//! x86_64 任务上下文切换。
//!
//! `TaskContext` 布局（`arch::task::TaskContext.buf`，16 个 u64）：
//!   [0] r15
//!   [1] r14
//!   [2] r13
//!   [3] r12
//!   [4] rbx
//!   [5] rbp
//!   [6] rsp   （切换后恢复的栈指针）
//!   [7] rip   （任务入口 / 恢复点）
//!   其余保留。
//!
//! `switch_to(prev, next)`：保存当前 callee-saved 寄存器 + 栈指针 + **恢复点**
//! 到 `prev.buf`，从 `next.buf` 恢复这些寄存器，然后跳转到 `next.rip`。
//!
//! 恢复点语义：保存时把"汇编恢复点 `2:` 之后"（即 `ret`）的地址存为 rip；
//! 恢复时 `jmp` 到该地址执行 `ret`，从而返回到之前调用 `switch_to` 的下一条指令
//! （等价于 `switch_to` 正常返回）。首次运行的任务 rip 为入口地址（`init_context`
//! 设置），直接跳转执行。

use arch::task::TaskContext;

// 常量索引（与 buf 布局对应）
const I_R15: usize = 0;
const I_R14: usize = 1;
const I_R13: usize = 2;
const I_R12: usize = 3;
const I_RBX: usize = 4;
const I_RBP: usize = 5;
const I_RSP: usize = 6;
const I_RIP: usize = 7;

/// 初始化一个新任务的上下文，使其首次运行时从 `entry` 开始，使用 `stack_top`。
///
/// `stack_top` 是该任务独立内核栈的栈顶（高地址端，栈向下增长）。
/// 首次 `switch_to` 到该任务时，会设置 RSP=stack_top 并跳转执行 `entry`。
pub fn init_context(ctx: &mut TaskContext, entry: extern "C" fn(), stack_top: u64) {
    let buf = ctx.as_buf_mut();
    for slot in buf.iter_mut() {
        *slot = 0;
    }
    buf[I_RIP] = entry as usize as u64;
    buf[I_RSP] = stack_top;
}

/// x86_64 上下文切换实现（naked 汇编，无编译器 prologue）。
///
/// 使用 `#[naked]` 避免编译器生成的栈帧，确保 `[rsp]` 就是调用者的返回地址，
/// 使 `switch_to` 的"保存/恢复返回地址"语义可靠。
///
/// ABI：`prev` 在 rdi，`next` 在 rsi（extern "C"）。
///
/// 保存：callee-saved 寄存器 + rsp + 返回地址（`[rsp]`）写入 `prev.buf`。
/// 恢复：从 `next.buf` 恢复寄存器 + rsp，然后 `jmp` 到 `next.rip`
/// （已保存过的任务 = 返回地址，等价于 ret 回其调用者；首次 = 任务入口）。
///
/// # Safety
/// 由 `arch::switch_to` 调用；`prev`/`next` 必须是有效的 `TaskContext`。
#[unsafe(naked)]
pub extern "C" fn x86_switch_to(prev: &mut TaskContext, next: &mut TaskContext) {
    // naked 函数：参数在 rdi（prev）与 rsi（next）
    core::arch::naked_asm!(
        // ---- 保存当前状态到 prev（rdi）----
        "mov [rdi + {o15}], r15",
        "mov [rdi + {o14}], r14",
        "mov [rdi + {o13}], r13",
        "mov [rdi + {o12}], r12",
        "mov [rdi + {obx}], rbx",
        "mov [rdi + {obp}], rbp",
        // 弹出返回地址（call 压入）作为恢复点；rsp 上移到调用者栈帧顶
        "pop rax",
        // 保存当前 rsp（此时指向调用者栈帧顶，恢复后 ret 能弹出其返回地址）
        "mov [rdi + {osp}], rsp",
        "mov [rdi + {oip}], rax",
        // ---- 恢复 next（rsi）----
        "3:",
        "mov r15, [rsi + {o15}]",
        "mov r14, [rsi + {o14}]",
        "mov r13, [rsi + {o13}]",
        "mov r12, [rsi + {o12}]",
        "mov rbx, [rsi + {obx}]",
        "mov rbp, [rsi + {obp}]",
        "mov rsp, [rsi + {osp}]",
        // 跳到 next.rip（返回地址 → 相当于 ret 回其调用者；首次 → 任务入口）
        "jmp [rsi + {oip}]",
        // 恢复点：ret 返回到之前调用 switch_to 的下一条指令
        "4:",
        "ret",
        o15 = const I_R15 * 8,
        o14 = const I_R14 * 8,
        o13 = const I_R13 * 8,
        o12 = const I_R12 * 8,
        obx = const I_RBX * 8,
        obp = const I_RBP * 8,
        osp = const I_RSP * 8,
        oip = const I_RIP * 8,
    );
}

/// x86_64 进入用户态（Ring 3）实现。
///
/// 给定 `arch::task::TrapFrame`（RIP/CS/RFLAGS/RSP/SS/CR3），先装载 `cr3`
/// （切到进程页表，若非 0），再把 iretq 帧按序压入当前内核栈，然后 `iretq`
/// 切换到 Ring 3 执行用户代码。
///
/// iretq 帧布局（栈顶到低地址）：RIP, CS, RFLAGS, RSP, SS。
/// `TrapFrame` 字段顺序恰为 rip/cs/rflags/rsp/ss/cr3，故按偏移读。
///
/// ABI：`frame` 在 rdi。返回后必然进入用户态，本函数不返回（末尾 `iretq`）。
///
/// ## `swapgs` 协议的另一半（SYSCALL-FAST-4 实核补上）
///
/// per-CPU 地基（FAST-1）建立的不变式是**成对**的：
///   - 内核态：`GS.base` = per-CPU 结构，`IA32_KERNEL_GS_BASE` = 用户值；
///   - 用户态：`GS.base` = 用户值，`IA32_KERNEL_GS_BASE` = per-CPU 结构。
///
/// 进入内核的 `swapgs`（`syscall_entry_stub` 第一步）只实现了「换进来」这一半。
/// **必须还有「换出去」这一半**：在切到用户态**之前** `swapgs`，否则用户态运行时
/// `GS.base` 仍是 per-CPU 地址、`KERNEL_GS_BASE` 是 0；此时用户执行 `syscall`，
/// 入口的 `swapgs` 会把 `GS.base` 换成 **0**，紧接着的 `gs:[...]` 访问立即 #GP。
///
/// 这正是 FAST-4 端到端测试暴露的问题：内核单测全绿（因为不涉及用户态 GS 状态），
/// 真跑用户态 `syscall` 才暴露。
///
/// `int 0x80` 路径**不需要**在此之外额外处理：它同样经本函数出去（换出一次），
/// 入口 stub 里由 CPL 门控决定是否换回（见 `interrupt_common_stub` 的说明）。
///
/// # Safety
/// 由 `arch::task::enter_usermode` 调用；`frame` 必须指向有效的 `TrapFrame`，
/// 其 cs/ss 须为 Ring 3 段选择子，rflags 须含 IF=1；`cr3` 若非 0 须为有效页表基址。
/// 且**调用前必须已建立 GS 地基**（否则 `swapgs` 会把垃圾换进 `GS.base`）。
#[unsafe(naked)]
pub extern "C" fn x86_64_enter_usermode(frame: &arch::task::TrapFrame) {
    core::arch::naked_asm!(
        // rdi = frame；把 iretq 帧的五个字段 push（先压 SS 最后压 RIP）
        // frame 偏移（repr(C)）：rip=0, cs=8, rflags=16, rsp=24, ss=32, cr3=40
        // 先装载 CR3（若 cr3 != 0 则写 CR3 切到进程页表）
        "mov rax, [rdi + 40]", // cr3
        "test rax, rax",
        "jz 0f",        // cr3 == 0 → 不切换页表
        "mov cr3, rax", // 写 CR3（切到进程用户页表）
        "0:",
        "mov rax, [rdi + 32]", // ss
        "push rax",
        "mov rax, [rdi + 24]", // rsp
        "push rax",
        "mov rax, [rdi + 16]", // rflags
        "push rax",
        "mov rax, [rdi + 8]", // cs
        "push rax",
        "mov rax, [rdi + 0]", // rip
        "push rax",
        // ---- swapgs：把 per-CPU 地址换到 KERNEL_GS_BASE，把用户值换进 GS.base ----
        // 必须在 iretq **之前**：此后 GS.base 是用户值，用户态执行 syscall 时入口
        // 的 swapgs 才能把 per-CPU 地址正确换回来（与 FAST-1 的不变式配对）。
        //
        // **无条件** swapgs：本函数的唯一用途就是进入用户态，故必然要把用户 GS 值
        // 换进 GS.base。首版加了「地基是否就绪」的条件判断（读一个静态标志），但
        // 那样引入了额外依赖且实测未能生效——进入用户态本就要求地基已建立，
        // 该前提由 `scheduler::start` 的上游保证，无需在裸汇编里再判一次。
        "swapgs",
        "iretq", // 弹出 RIP/CS/RFLAGS/RSP/SS → 切到 Ring 3
    );
}

/// 在架构初始化时注入 switch_to / enter_usermode 实现。
pub fn init() {
    arch::task::set_switch_to(x86_switch_to);
    arch::task::set_enter_usermode(x86_64_enter_usermode);
}
