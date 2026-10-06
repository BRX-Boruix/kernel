//! 中断描述符表（IDT）与异常/中断处理。
//!
//! - 覆盖 CPU 异常 0~31（除 16 号 FPU 错误外的通用兜底），以及外部中断 32~47。
//! - 通过手写汇编入口将 CPU 压栈的寄存器保存为 `InterruptFrame`，
//!   交给 Rust 端的 `dispatch` 分发。
//! - 支持注册外部中断处理函数（当前提供定时器 PIT 的中断）。

use core::arch::global_asm;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

/// 内核代码段选择子（加载 IDT 描述符时使用）。
use crate::gdt::{IST_DF, KCODE};

// ---------- IDT 结构 ----------

/// 一个 IDT 条目（16 字节）。
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct IdtEntry {
    offset_low: u16,  // 处理函数偏移 0..15
    selector: u16,    // 代码段选择子
    ist: u8,          // IST（未用，填 0）
    flags: u8,        // 类型与属性（present, DPL, interrupt gate）
    offset_mid: u16,  // 偏移 16..31
    offset_high: u32, // 偏移 32..63
    reserved: u32,    // 保留（必须为 0），使条目总大小为 16 字节
}

impl IdtEntry {
    const fn new() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            flags: 0,
            offset_mid: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    fn set_handler(&mut self, handler: u64, flags: u8, ist: u8) {
        self.offset_low = (handler & 0xFFFF) as u16;
        self.offset_mid = ((handler >> 16) & 0xFFFF) as u16;
        self.offset_high = (handler >> 32) as u32;
        self.selector = KCODE;
        self.flags = flags;
        self.ist = ist;
    }
}

/// 中断门（从用户态不可访问）
const IDT_FLAG_INTERRUPT: u8 = 0x8E;
/// 陷阱门（从用户态不可访问）
const IDT_FLAG_TRAP: u8 = 0x8F;
/// 陷阱门（DPL=3，用户态可触发；供软中断/系统调用使用）
const IDT_FLAG_TRAP_USER: u8 = 0xEF;

/// IDT（256 个条目）。
#[repr(C, packed)]
pub struct Idt {
    entries: [IdtEntry; 256],
}

impl Idt {
    const fn new() -> Self {
        Self {
            entries: [IdtEntry::new(); 256],
        }
    }
}

/// IDTR 结构。
#[repr(C, packed)]
struct Idtr {
    limit: u16,
    base: u64,
}

static mut IDT: Idt = Idt::new();

// ---------- 中断入口（汇编） ----------

// 生成 32 个异常入口 + 16 个外部中断入口，共 48 个。
// 每个入口把中断号压栈，然后跳到公共处理 `common_stub`。
// 有错误码的异常（8,10,11,12,13,14,17）CPU 会自动压栈错误码，
// 这里统一在入口补压一个占位 0，保证帧布局一致。

global_asm!(
    r#"
    .section .text

    // 公共中断处理入口。
    // 栈布局（由低到高）：
    //   rsp -> [压栈的通用寄存器区]
    //          中断号
    //          (错误码，若无则 0)
    //          RIP, CS, RFLAGS, RSP, SS
    .global interrupt_common_stub
    interrupt_common_stub:
        push rax
        push rbx
        push rcx
        push rdx
        push rsi
        push rdi
        push rbp
        push r8
        push r9
        push r10
        push r11
        push r12
        push r13
        push r14
        push r15

        // SYSCALL-FAST-4：GS 进入判定——**只看本帧 CS 的 CPL，不看向量**。
        //
        // 任何来自 Ring3 的进入（int 0x80、时钟、异常……）都发生在「用户态 GS
        // 状态」下（`GS.base` = 用户值，`KERNEL_GS_BASE` = per-CPU），内核必须先
        // `swapgs` 换回 per-CPU 地址；内核态进入（CPL0，含嵌套中断）则**不得**换。
        //
        // 为什么不用 Rust 钩子 + 全局标志：嵌套中断时内层会把外层置的标志清掉，
        // 外层返回用户态时漏掉 swapgs——GS 状态翻转，偶发 #GP，极难复现。
        // 每次进出都从**自己的帧**读 CPL，天然嵌套安全（无共享状态）。
        // 偏移 144 = CS 在 InterruptFrame 中的位置（FAST-2 实测钉死）。
        // `test mem, imm` 不破坏任何寄存器——此刻 15 个 GPR 都已是待保存的现场。
        test byte ptr [rsp + 144], 3
        jz 7f
        swapgs
        7:
        mov rdi, rsp
        call interrupt_dispatch

        // 恢复寄存器（interrupt_dispatch 返回后）
        pop r15
        pop r14
        pop r13
        pop r12
        pop r11
        pop r10
        pop r9
        pop r8
        pop rbp
        pop rdi
        pop rsi
        pop rdx
        pop rcx
        pop rbx
        pop rax

        // 跳过中断号 + 错误码（各 8 字节）
        add rsp, 16
        // SYSCALL-FAST-4：GS 退出判定——与进入判定配对，但**读的是即将 iretq 的
        // 那一帧的 CS**（[rsp+8]）。调度器可能在分发期间把帧整体替换成另一进程的
        // 保存帧：若那也是用户帧（cs&3==3），照样要 swapgs；若替换成了内核帧则不换。
        // 判据跟着「要回哪」走，而不是跟着「从哪来」走，这才是配对不变式：
        //   **CPL3 ⟺ GS.base 是用户值**。
        // 同样只用 `test mem, imm`——此刻用户 GPR 已全部恢复，多碰一个都是破坏现场。
        test byte ptr [rsp + 8], 3
        jz 8f
        swapgs
        8:
        iretq

    // 生成异常入口（无错误码）：先压占位错误码 0，再压中断号。
    // 用 .byte 手工编码 `push imm8`（0x6A）以绕开模板对 `$` 的解析。
    .macro isr_noerr num
        .global isr_\num
        .type isr_\num, @function
    isr_\num:
        .byte 0x6a, 0              // push 0  (错误码占位)
        .byte 0x68, \num, 0, 0, 0   // push 中断号 (imm32)
        jmp interrupt_common_stub
    .endm

    // 生成异常入口（有错误码）：CPU 已压错误码，只需压中断号。
    .macro isr_err num
        .global isr_\num
        .type isr_\num, @function
    isr_\num:
        .byte 0x68, \num, 0, 0, 0   // push 中断号 (imm32)
        jmp interrupt_common_stub
    .endm

    isr_noerr 0
    isr_noerr 1
    isr_noerr 2
    isr_noerr 3
    isr_noerr 4
    isr_noerr 5
    isr_noerr 6
    isr_noerr 7
    isr_err   8
    isr_noerr 9
    isr_err   10
    isr_err   11
    isr_err   12
    isr_err   13
    isr_err   14
    isr_noerr 15
    isr_noerr 16
    isr_err   17
    isr_noerr 18
    isr_noerr 19
    isr_noerr 20
    isr_noerr 21
    isr_noerr 22
    isr_noerr 23
    isr_noerr 24
    isr_noerr 25
    isr_noerr 26
    isr_noerr 27
    isr_noerr 28
    isr_noerr 29
    isr_noerr 30
    isr_noerr 31

    // 外部中断 32..47（无错误码）
    isr_noerr 32
    isr_noerr 33
    isr_noerr 34
    isr_noerr 35
    isr_noerr 36
    isr_noerr 37
    isr_noerr 38
    isr_noerr 39
    isr_noerr 40
    isr_noerr 41
    isr_noerr 42
    isr_noerr 43
    isr_noerr 44
    isr_noerr 45
    isr_noerr 46
    isr_noerr 47

    // MA1b：IPI 邮箱向量（0x40）。跨核 per-CPU 缓存排空的投递通道。
    isr_noerr 64

    // KA1：跨核停机向量（0x41）。panic 现场广播给其它 CPU，收到即永久停机。
    isr_noerr 65

    // phase2-M5 resched stub
    isr_noerr 66

    // S1：TLB shootdown 会合向量（0x43）。发起者广播 → 各核 invlpg → 各自 ack。
    isr_noerr 67

    // 软件中断 0x80（无错误码）：用户态软中断/系统调用入口（M2.5.4 / M3）。
    //
    // SYSCALL-FAST-4：**不再**用 `isr_noerr`（它直连 `interrupt_common_stub`，
    // 而该 stub 不处理 `swapgs`）。改用专用入口 `isr_128`，理由：
    //   - `enter_usermode` 在切到用户态前 `swapgs`，故用户态 `GS.base` = 用户值；
    //   - 从用户态进入内核（无论 `int 0x80` 还是 `syscall`）都必须 `swapgs` 换回
    //     per-CPU 地址，返回用户态前再换回去；
    //   - 只有 CPL3 → CPL0 的进入才该换。内核态自己 `int 0x80` 时**不得**换
    //     （否则把 GS 换成用户值），故用 CS 低两位做门控。
    //
    // 实现方式：`int 0x80` 仍走 `interrupt_common_stub`（不改公共 stub 的帧逻辑），
    // 但公共 stub 在**调用分发之前**与**执行 iretq 之前**各调用一个 Rust 侧钩子，
    // 由钩子按帧里的 CS 决定是否 `swapgs`。这样：
    //   - GS 协议集中在一处（Rust），无需在多处汇编里重复 CPL 门控；
    //   - 公共 stub 的寄存器/帧布局**完全不变**（ST_2 的硬约束）；
    //   - 只有向量 0x80 的钩子会真正动作（其它向量钩子立即返回）。
    //
    // 注意：钩子由**公共 stub** 调用，故向量 0x80 这里仍用普通 `isr_noerr`。
    // （曾一度改为专用入口，但那会删掉 `isr_128` 符号，导致链接失败的连锁问题。）
    isr_noerr 128

    // LAPIC 伪中断向量 255（0xFF，无错误码）：SVR 使能后伪中断会以此向量
    // 送达 CPU，IDT 必须存在对应表项——否则查表越界触发 #GP → #DF 级联停机
    // （arch1.md AA3）。处理策略在 Rust 分发端：按规范不发送 EOI、静默返回。
    isr_noerr 255

    .global x86_64_load_idt
    x86_64_load_idt:
        lidt [rdi]
        ret
    "#
);

/// 中断号 0~31 的异常名称。
fn exception_name(vector: u8) -> &'static str {
    const NAMES: [&str; 32] = [
        "Divide-by-zero",
        "Debug",
        "Non-maskable Interrupt",
        "Breakpoint",
        "Overflow",
        "Bound Range Exceeded",
        "Invalid Opcode",
        "Device Not Available",
        "Double Fault",
        "Coprocessor Segment Overrun",
        "Invalid TSS",
        "Segment Not Present",
        "Stack-Segment Fault",
        "General Protection Fault",
        "Page Fault",
        "Reserved",
        "x87 Floating-Point Exception",
        "Alignment Check",
        "Machine Check",
        "SIMD Floating-Point Exception",
        "Virtualization Exception",
        "Control Protection Exception",
        "Reserved",
        "Reserved",
        "Reserved",
        "Reserved",
        "Reserved",
        "Reserved",
        "Hypervisor Injection Exception",
        "VMM Communication Exception",
        "Security Exception",
        "Reserved",
    ];
    NAMES[vector as usize]
}

/// CPU 压栈形成的帧（保存的寄存器 + 中断号 + 错误码 + 处理器状态）。
///
/// `Copy`：全部字段为 u64，调度器（M4.2）需整体拷贝以在进程间迁移中断帧。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct InterruptFrame {
    /// 15 个通用寄存器（由公共 stub 压栈）
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    /// 中断号
    pub vector: u64,
    /// 错误码（若该异常有错误码）
    pub error_code: u64,
    /// 处理器压栈的上下文
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

// ---------- SYSCALL-FAST-2：帧布局自省（供契约测试对拍裸汇编偏移） ----------

/// `InterruptFrame` 各字段的**实测**偏移与大小。
///
/// 这些值由 `offset_of!` 从**真实结构**算出，不是抄来的常量。
/// 意义：`resume_interrupt_frame` 用裸汇编硬编码偏移寻址，二者若漂移则静默错乱；
/// 本结构让测试能直接断言「结构布局 == 汇编假设」。
pub struct InterruptFrameOffsets {
    pub size: usize,
    pub r15: usize,
    pub rdi: usize,
    pub rax: usize,
    pub vector: usize,
    pub error_code: usize,
    pub rip: usize,
    pub cs: usize,
    pub rflags: usize,
    pub rsp: usize,
    pub ss: usize,
}

/// 实测 `InterruptFrame` 布局。
pub fn debug_interrupt_frame_offsets() -> InterruptFrameOffsets {
    InterruptFrameOffsets {
        size: core::mem::size_of::<InterruptFrame>(),
        r15: core::mem::offset_of!(InterruptFrame, r15),
        rdi: core::mem::offset_of!(InterruptFrame, rdi),
        rax: core::mem::offset_of!(InterruptFrame, rax),
        vector: core::mem::offset_of!(InterruptFrame, vector),
        error_code: core::mem::offset_of!(InterruptFrame, error_code),
        rip: core::mem::offset_of!(InterruptFrame, rip),
        cs: core::mem::offset_of!(InterruptFrame, cs),
        rflags: core::mem::offset_of!(InterruptFrame, rflags),
        rsp: core::mem::offset_of!(InterruptFrame, rsp),
        ss: core::mem::offset_of!(InterruptFrame, ss),
    }
}
// ---------- A2: 从任意内存中恢复一个完整 InterruptFrame 并 iretq 回用户态 ----------

/// 从内存中的 InterruptFrame 恢复全部通用寄存器并 iretq 进入该帧描述的用户态上下文。
///
/// 为什么需要：对象式切换 (对 interrupt_common_stub 的帧) 通常由外层 stub 在该帧所在的当前栈上 pop+iretq。
/// 但 A2 空闲停车路径在把物理 RSP 切到本核 idle 栈后，被放弃的进程栈上不再有可用的外层 stub；
/// 此时若要恢复下一个就绪进程 (其 saved 是一个在内存 PCB 里的 InterruptFrame)，
/// 就需要从内存帧直接恢复各寄存器并 iretq，而非依赖弃栈上的 stub。
/// 帧布局：[0..112] = r15..rax 各 u64，[120]=vector, [128]=error_code,
/// [136..168] = rip/cs/rflags/rsp/ss (用户 iretq 帧)。
#[unsafe(naked)]
pub extern "C" fn resume_interrupt_frame(frame: *const InterruptFrame) -> ! {
    // naked: rdi = frame。先在当前 (idle) 栈顶剪出空间放 iretq 帧 + rdi 候用值储存。
    core::arch::naked_asm!(
        "sub rsp, 48",                       // [0..32]=iretq帧, [40]=rdi候用
        "mov rax, [rdi + 168]",
        "mov [rsp + 32], rax",              // ss
        "mov rax, [rdi + 160]",
        "mov [rsp + 24], rax",              // 用户 rsp
        "mov rax, [rdi + 152]",
        "mov [rsp + 16], rax",              // rflags
        "mov rax, [rdi + 144]",
        "mov [rsp + 8], rax",               // cs
        "mov rax, [rdi + 136]",
        "mov [rsp], rax",                   // rip
        // SYSCALL-FAST-4：若目标是**用户帧**，在 iretq 前 swapgs（把用户 GS 值换进
        // GS.base），与用户态 `syscall`/`int 0x80` 入口的 swapgs 配对。
        //
        // 判据用帧里的 CS 低两位。内核帧（cs&3==0）不换——内核态本就该持有 perCPU。
        // 注意：此判据必须在所有寄存器被覆盖**之前**求值，且只用 rdi（帧基址）。
        "test byte ptr [rdi + 144], 3",      // [rdi+144] = cs 的低字节
        "jz 9f",
        "swapgs",
        "9:",
        "mov rax, [rdi + 72]",              // rdi 恢复值先储到 [rsp+40]（rdi 仍为帧基址）
        "mov [rsp + 40], rax",
        "mov r15, [rdi + 0]",
        "mov r14, [rdi + 8]",
        "mov r13, [rdi + 16]",
        "mov r12, [rdi + 24]",
        "mov r11, [rdi + 32]",
        "mov r10, [rdi + 40]",
        "mov r9, [rdi + 48]",
        "mov r8, [rdi + 56]",
        "mov rbp, [rdi + 64]",
        "mov rsi, [rdi + 80]",
        "mov rdx, [rdi + 88]",
        "mov rcx, [rdi + 96]",
        "mov rbx, [rdi + 104]",
        "mov rax, [rdi + 112]",
        "mov rdi, [rsp + 40]",
        "iretq"
    );
}

// ---------- 外部中断处理函数表（共享中断） ----------

/// 外部中断处理函数（IRQ）。返回 `true` 表示已处理。
pub type IrqHandler = extern "C" fn(u8) -> bool;

/// 每个 IRQ 最多可注册的处理函数数（共享中断）。
///
/// 同一 IRQ 线上的多个设备（如两个网卡共享一根 IRQ）各自注册一个 handler，
/// 分发时依次调用，任一返回 `true` 即视为已处理。4 个槽位对典型 PC 足够。
pub const MAX_HANDLERS_PER_IRQ: usize = 4;

/// 外部中断处理函数表（IRQ0~15，每 IRQ 多个共享槽位）。
///
/// 采用无锁的原子函数指针表，而非 `spin::Mutex`：因为 `interrupt_dispatch`
/// 运行于**中断上下文**，若某 IRQ 打断同 CPU 正在持有该锁的代码，非可重入的
/// 自旋锁会永远自旋 → 死锁。原子表以 `load(Acquire)` 读、`compare_exchange`
/// 写，处理函数均为 `'static` 且只在中断使能前注册，故安全无锁。
///
/// 取值为 0 表示空槽；合法函数地址不可能为 0，因此可兼作"空"标记。
static IRQ_HANDLERS: [[AtomicUsize; MAX_HANDLERS_PER_IRQ]; 16] =
    [const { [const { AtomicUsize::new(0) }; MAX_HANDLERS_PER_IRQ] }; 16];

/// 注册外部中断（IRQ0~15）的处理函数（支持共享：同一 IRQ 可注册多个）。
///
/// - 处理函数须为 `'static`（当前为 `extern "C"` 静态函数），且永不注销，
///   以保证中断上下文无锁读取时指针始终有效；
/// - 重复注册同一 handler 返回 `false`（幂等，不产生重复分发）；
/// - 该 IRQ 槽位已满返回 `false`。
///
/// 返回 `true` 表示注册成功。
pub fn register_irq(irq: u8, handler: IrqHandler) -> bool {
    if irq >= 16 {
        return false;
    }
    let slot = &IRQ_HANDLERS[irq as usize];
    let ptr = handler as usize; // x86_64 下函数指针与 usize 等宽
    for entry in slot {
        let cur = entry.load(Ordering::Acquire);
        if cur == ptr {
            return false; // 已注册，去重
        }
        if cur == 0 {
            // 竞争写入：仅当槽仍为空时占位。
            if entry
                .compare_exchange(0, ptr, Ordering::Release, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
            // 竞争失败：换下一个槽重试。
        }
    }
    false // 槽满
}

/// 注销外部中断处理函数（共享中断下移除一个 handler）。
///
/// 返回 `true` 表示确实存在并已移除。中断上下文中该 handler 可能正在执行，
/// 调用方须保证注销后不再依赖它（当前无动态卸载场景，仅供完整性提供）。
pub fn unregister_irq(irq: u8, handler: IrqHandler) -> bool {
    if irq >= 16 {
        return false;
    }
    let slot = &IRQ_HANDLERS[irq as usize];
    let ptr = handler as usize;
    for entry in slot {
        if entry.load(Ordering::Acquire) == ptr {
            entry.store(0, Ordering::Release);
            return true;
        }
    }
    false
}

/// 查询某 IRQ 已注册的 handler 数。
pub fn irq_handler_count(irq: u8) -> usize {
    if irq >= 16 {
        return 0;
    }
    IRQ_HANDLERS[irq as usize]
        .iter()
        .filter(|e| e.load(Ordering::Relaxed) != 0)
        .count()
}

// ---------- 嵌套控制与优先级（T7） ----------

/// IRQ 优先级范围：0（最低）~ 15（最高）。
pub const IRQ_PRIO_MIN: u8 = 0;
pub const IRQ_PRIO_MAX: u8 = 15;
/// 不在任何中断上下文时 `current_irq_priority()` 的返回值。
pub const IRQ_PRIO_NONE: u8 = 0xFF;

/// 每 IRQ 的软件优先级（默认 0 最低）。
///
/// 优先级决定嵌套关系：嵌套开启时，**更高优先级**的中断可以打断当前正在
/// 处理的中断；同优先级或更低优先级不可。中断上下文外读取安全（原子）。
static IRQ_PRIORITIES: [AtomicU8; 16] = [const { AtomicU8::new(IRQ_PRIO_MIN) }; 16];

/// 全局嵌套开关。默认关闭（与历史行为一致：中断门已自动关中断，处理期间
/// 不可被打断）；开启后高优先级中断可打断低优先级处理。
static NESTED_IRQ: AtomicBool = AtomicBool::new(false);

/// 当前正在处理的中断优先级（`IRQ_PRIO_NONE` = 不在中断上下文）。
///
/// 进入外部中断分发时原子替换为自身优先级，返回前恢复旧值。仅软件语义，
/// 用于嵌套判断（`prio > prev`）；单核下无需 per-CPU 数组。
static CURRENT_IRQ_PRIO: AtomicU8 = AtomicU8::new(IRQ_PRIO_NONE);

/// 设置某 IRQ 的优先级（0~15）。越界返回 `false`。
pub fn set_irq_priority(irq: u8, prio: u8) -> bool {
    if irq >= 16 || prio > IRQ_PRIO_MAX {
        return false;
    }
    IRQ_PRIORITIES[irq as usize].store(prio, Ordering::Relaxed);
    true
}

/// 查询某 IRQ 的优先级。越界返回 `IRQ_PRIO_MIN`。
pub fn irq_priority(irq: u8) -> u8 {
    if irq >= 16 {
        return IRQ_PRIO_MIN;
    }
    IRQ_PRIORITIES[irq as usize].load(Ordering::Relaxed)
}

/// 开启/关闭中断嵌套（默认关闭）。
///
/// 开启后，外部中断分发时若自身优先级高于当前处理中的中断优先级，会临时
/// 使能中断（`sti`）允许更高优先级打断，返回前恢复。优先级抑制仍然生效：
/// 更低/同级优先级的中断即使硬件到达，也不会在当前处理中嵌套（进入时中断
/// 门保持关中断）。
pub fn set_nested_irq(enabled: bool) {
    NESTED_IRQ.store(enabled, Ordering::Relaxed);
}

/// 当前嵌套开关状态。
pub fn nested_irq_enabled() -> bool {
    NESTED_IRQ.load(Ordering::Relaxed)
}

/// 当前正在处理的中断优先级；不在中断上下文返回 `IRQ_PRIO_NONE`（0xFF）。
pub fn current_irq_priority() -> u8 {
    CURRENT_IRQ_PRIO.load(Ordering::Relaxed)
}

/// 当前中断是否使能（读 RFLAGS.IF）。
pub fn interrupts_enabled() -> bool {
    let flags: u64;
    unsafe {
        core::arch::asm!(
            "pushfq",
            "pop {}",
            out(reg) flags,
            options(nomem, nostack, preserves_flags),
        );
    }
    flags & (1 << 9) != 0
}

/// 页错误（#PF, 14 号异常）回调。
///
/// 参数为 (CR2 线性地址, 错误码)。返回 `true` 表示已处理（如按需补页后），
/// 继续执行；返回 `false` 表示未处理（内核态缺页/非法访问），保持原停机行为。
///
/// 由虚拟内存/进程子系统注册（M1.3 按需分页）。`arch` 层只提供钩子，
/// 不实现具体策略（ADR-007）。
pub type PageFaultHandler = extern "C" fn(u64, u64) -> bool;
static PAGE_FAULT_HANDLER: spin::Once<PageFaultHandler> = spin::Once::new();

/// 注册页错误处理回调。
pub fn register_page_fault_handler(h: PageFaultHandler) {
    let _ = PAGE_FAULT_HANDLER.call_once(|| h);
}

/// 软中断（vector 0x80）处理函数。
///
/// 由 `int 0x80`（用户态或内核态）触发进入。参数为进入时的中断帧
/// （含用户/内核的 RIP/CS/RFLAGS/RSP/SS）。返回 `true` 表示已处理并继续
/// （`iretq` 返回触发点）；`false` 表示未处理（保留停机行为）。
pub type SoftInterruptHandler = extern "C" fn(&mut InterruptFrame) -> bool;
static SOFT_INT_HANDLER: spin::Once<SoftInterruptHandler> = spin::Once::new();

/// 注册软中断（vector 0x80）处理回调。
pub fn register_soft_interrupt_handler(h: SoftInterruptHandler) {
    let _ = SOFT_INT_HANDLER.call_once(|| h);
}

/// 用户态异常（#PF/#GP/#UD 等，CPL=3）处理器。
///
/// 由进程层注册（M3.3 / ADR-034 PRE-2/S1-11）：当用户态进程触发异常时，不再当作
/// 内核崩溃停机，而是终止/回收该进程（或投递信号进用户 handler）。
///
/// 回调携带 `cr2`（#PF 出错线性地址，ADR-034 §2.8 供 siginfo.fault_addr；
/// 非 #PF 异常为 0）。返回 `true` 表示已处置且应 **iretq 回用户态**（如已把
/// 现场改写为 handler 入口）；返回 `false` 表示未恢复（已终止/停机）。
pub type UserExceptionHandler = extern "C" fn(cr2: u64, frame: &mut InterruptFrame) -> bool;
static USER_EXCEPTION_HANDLER: spin::Once<UserExceptionHandler> = spin::Once::new();

/// 注册用户态异常处理器（M3.3）。
pub fn register_user_exception_handler(h: UserExceptionHandler) {
    let _ = USER_EXCEPTION_HANDLER.call_once(|| h);
}

/// 内核态 #PF 检查器（KA3）：内核态缺页进入通用"CPU EXCEPTION 停机"路径
/// **之前**调用。返回 `true` 表示检查器已完全处置（如识别为内核栈守护页
/// 命中并停机报告），分发端直接返回；`false` 落入通用致命路径。
/// 架构层不认识内核符号布局，故经函数指针注入。
pub type KernelFaultInspector = fn(cr2: u64) -> bool;
static KERNEL_FAULT_INSPECTOR: spin::Once<KernelFaultInspector> = spin::Once::new();

/// 注册内核态 #PF 检查器（kernel 层启动早期调用一次）。
pub fn register_kernel_fault_inspector(f: KernelFaultInspector) {
    let _ = KERNEL_FAULT_INSPECTOR.call_once(|| f);
}

/// 调度器 tick 回调（M4.2）：每次 LAPIC 定时器中断（IRQ0）后调用。
///
/// 由调度器注册（kernel 层）。回调持有 `&mut InterruptFrame`，可**整体改写**
/// 中断帧（寄存器 + iretq 帧）为另一进程的保存帧，并切换 CR3/TSS.RSP0；
// ---------- SYSCALL-FAST-2：`syscall` 指令入口 stub ----------

/// `syscall` 指令的硬件行为（与中断门的本质差异）：
///   - 走 `IA32_LSTAR` 直接跳转，**不经过 IDT**；
///   - **不压栈**：RIP→`rcx`、RFLAGS→`r11`，其余寄存器原样；
///   - **不切栈**：RSP 仍是**用户栈**；
///   - 按 `IA32_FMASK` 清 RFLAGS 位（我们掩了 IF/TF，故进入时中断已关）。
///
/// 本 stub 的职责：把这种「没有任何栈帧」的进入状态，**人工构造成与
/// `interrupt_common_stub` 完全一致**的 `InterruptFrame`，然后复用同一个
/// `interrupt_dispatch`。
///
/// ## 为什么必须逐字节一致
///
/// 因为下游全部依赖该布局：`resume_interrupt_frame` 用**裸汇编硬编码偏移**寻址；
/// 调度器 `pop_and_commit_switch` **整体改写**该帧；阻塞类 syscall 靠整帧替换
/// 语义在进程间迁移现场。布局偏一个字段就静默错乱。
///
/// ## 栈切换的安全性（顺序不可调换）
///
/// 进入时 RSP 是**用户栈**，此时若发生中断就会在用户栈上压内核帧——用户态可借此
/// 控制内核栈（提权面）。故顺序严格为：
///   1. `swapgs`（拿到 per-CPU 结构；此刻 CS 已是 Ring0）；
///   2. 从 per-CPU 取**内核栈顶**并切栈（`mov rsp, ...`）；
///   3. 在**内核栈**上压帧。
/// FMASK 已保证 IF=0，故 1→2 之间不存在中断窗口。
///
/// ## 与 `int 0x80` 的语义差异（刻意保留在帧里）
///
/// 软中断路径的帧由**硬件**压入 RIP/CS/RFLAGS/RSP/SS；本 stub 必须**手工**压入
/// 等价内容：
///   - RIP 来自 `rcx`（syscall 硬件存入）；
///   - RFLAGS 来自 `r11`；
///   - CS = 用户代码段（因为这是从用户态进来的）；
///   - RSP = 进入时的用户 RSP（须在任何切栈**之前**保存）；
///   - SS = 用户数据段。
global_asm!(
    r#"
    .section .text

    .global syscall_entry_stub
    .type syscall_entry_stub, @function
    syscall_entry_stub:
        // ---- 阶段 1：换 GS 到内核 per-CPU（CS 此刻已是 Ring0）----
        // 前提：用户态运行时 `GS.base` = 用户值、`IA32_KERNEL_GS_BASE` = per-CPU 地址。
        // 该前提由 `x86_64_enter_usermode` 在 `iretq` 前 `swapgs` 建立（配对的一半）。
        swapgs

        // ---- 阶段 2：保存用户 RSP，切到本核内核栈 ----
        // per-CPU 结构偏移：self_ptr=0, slot=8, kernel_stack_top=16（见 percpu.rs）。
        // 用户 RSP 先存到 GS:24 的暂存位（本核私有，无需跨核同步）。
        // 注意：此时 RSP 仍是用户栈，任何 push 都会踩用户栈——故先只用 mov。
        mov qword ptr gs:[24], rsp
        // 切换到**本核专用 syscall 栈**（gs:[48]），而**不是** gs:[16]。
        //
        // gs:[16] 是「借来的当前内核栈」（引导期由 RSP 向上对齐推出）。若 syscall
        // 发自内核正在使用该栈的时刻，压入 176 字节的帧会直接覆盖内核的活动栈帧，
        // 而 `sysretq` 不弹帧 —— 内核随后带着被破坏的栈继续跑。
        // 实测症状：`sys_write` 第二次进入时在堆分配器内部异常（标记 `1 1 a A`
        // 之后不再前进），以及更早版本的整体静默停机。
        //
        // gs:[48] 指向 `SYSCALL_STACKS[slot]`（16 KiB，`.bss`），与任何内核栈无关。
        mov rsp, qword ptr gs:[48]

        // ---- 阶段 3：在内核栈上构造 InterruptFrame ----
        // 布局（低->高）与 interrupt_common_stub 完全一致：
        //   15 个通用寄存器, vector, error_code, RIP, CS, RFLAGS, RSP, SS
        //
        // 先压硬件上下文（栈顶->底）：SS, RSP, RFLAGS, CS, RIP
        // 用户 SS/CS 常量：SS=0x30, CS=0x28（与 GDT 一致；sysret 回程用 0x38，见 syscall.rs）。
        // **寄存器保全铁律**：`rax` 装的是用户传的系统调用号，绝不能当暂存用。
        // 首版误用 `mov rax, gs:[24]` 取用户 RSP，把**系统调用号冲掉**，
        // 导致帧里 rax 是垃圾（实测 `nr=0x30`，且 a3 泄漏了 stub 用过的 rdx=0x3f8）。
        // 这里改用 `r11` 暂存——`r11` 是 `syscall` 硬件写入的 RFLAGS，
        // 我们要的值已在下面 `push r11` 前读到栈上了吗？没有——故同样不能碰。
        // 正确做法：**直接用内存操作数**把 gs:[24] 压栈，不经过任何通用寄存器。
        // **RPL=3 不可省略（GPF 修复）**：此处曾写 `push 0x30` / `push 0x28`——
        // 那是 UDATA/UCODE 的**索引值**，低 2 位 RPL=0。本 stub 自己走 `sysretq`
        // 回程（段选择子由 STAR 推算，**不读这两个槽**），故在单纯 syscall 路径上
        // 这两个值从不被校验，RPL=0 一直「看起来正常」。
        //
        // 但该帧会被**存进进程的 saved 现场**（阻塞类 syscall / yield 经
        // `slot.saved = *frame`），此后由**另一条路径**恢复：时钟中断（IRQ0）的
        // `commit_next` 做 `*frame = slot.saved`，再经 `interrupt_common_stub` 的
        // **`iretq`** 返回。`iretq` 的返回来特权级取 **CS.RPL**：RPL=0 表示「回到
        // Ring0」，而 0x28 对应描述符的 DPL=3 —— RPL 与 DPL 不符，硬件 #GP，
        // 错误码即该选择子（实测 `error=0x28`，`rip` 落在 `iretq`）。
        //
        // 实测症状：用户态一跑起来（真正发生 syscall）就随机 #GP 停机，raw 转储里
        // `iretq` 帧「看起来完全合法」（RIP/CS/RSP/SS 都是合理值），唯有 RPL 位缺失——
        // 这正是它极难定位的原因：帧里每个字段单独看都对。
        //
        // 修复：与 task::process 的单点构造 `user_code_selector` / `user_data_selector`
        // 保持一致（`UCODE|3` / `UDATA|3`）。sysretq 回程不受影响——
        // 它本就不读这两个槽。
        push 0x33                  // SS  = 用户数据段 | RPL3
        push qword ptr gs:[24]     // RSP = 用户 RSP（阶段 2 暂存；不占用任何 GPR）
        push r11                   // RFLAGS（syscall 硬件存入 r11）
        push 0x2b                  // CS  = 用户代码段 | RPL3
        push rcx                   // RIP（syscall 硬件存入 rcx）
        // 错误码占位 + 中断号（与 isr_noerr 宏一致）
        .byte 0x6a, 0              // push 0 (错误码占位)
        push 0x80                  // vector = 0x80（复用软中断分发路径）
        // 15 个通用寄存器，顺序与 interrupt_common_stub 完全相同
        push rax
        push rbx
        push rcx
        push rdx
        push rsi
        push rdi
        push rbp
        push r8
        push r9
        push r10
        push r11
        push r12
        push r13
        push r14
        push r15

        // ---- 阶段 4：复用同一分发入口（帧语义与软中断路径完全一致）----
        mov rdi, rsp
        call interrupt_dispatch

        // ---- 阶段 5：恢复寄存器 ----
        pop r15
        pop r14
        pop r13
        pop r12
        pop r11
        pop r10
        pop r9
        pop r8
        pop rbp
        pop rdi
        pop rsi
        pop rdx
        pop rcx
        pop rbx
        pop rax

        // ---- 阶段 6：跳过中断号 + 错误码 ----
        add rsp, 16

        // ---- 阶段 7：换回 GS 并按 iretq 返回 ----
        //
        // # 为什么这里**不能**用 sysretq（3P6-1 根因五，实测修复）
        //
        // 本 stub 的返回路径会被调度器用来进入**任意**进程：当某进程在本 stub 里
        // 阻塞时，syscall 内部的 `commit_next` 会 `*frame = slot.saved` 把**目标
        // 进程的帧**整体写进本 stub 的帧位置，随后由本 stub 的尾部负责进入它。
        // 而目标进程的帧可能是**中断路径**（`interrupt_common_stub` 的时钟 / #PF）
        // 保存的——那种帧的 `rcx` 槽与 `r11` 槽装的是**用户当时真正的 rcx/r11**，
        // 不是 syscall 约定值。
        //
        // `sysretq` 把 `rcx` 当目标 RIP、`r11` 当目标 RFLAGS，且**不修改**它们。
        // 于是用户拿回的 `rcx` 变成「被打断处的 RIP」、`r11` 变成 RFLAGS。对「把
        // 循环计数器放在 rcx」的代码（libsys 的 `memset`、tcc 的 `load_data`）这是
        // 致命的：计数器被换成代码地址，循环冲出缓冲区 → SIGSEGV。
        //
        // 实测（`tcc-on-boruix/boruix/probe_pf_rcx.c`，4 MiB 写循环被时钟抢占后
        // 再由"另一个进程的阻塞 syscall"切回）：`rcx` 变成 **0x40008b**（正是该循环
        // 存储指令的地址）、`r11` 变成 **0x10203**（RFLAGS|RF）——两者恰好就是
        // sysretq 的两个输入。同一次运行里未触发 #PF 的对照组（预触碰全部页）完好。
        //
        // `iretq` 从帧里弹 RIP/CS/RFLAGS/RSP/SS，并把 15 个 GPR（含 rcx/r11）按帧
        // 恢复，因此对「syscall 帧」与「中断帧」**都**正确——与
        // `interrupt_common_stub` 的尾部完全一致（两者必须能互换地消费对方保存的
        // 帧，这是本节修复后必须维持的不变式）。
        //
        // syscall ABI 不受影响：syscall 帧的 rcx/r11 槽本就是本 stub 压入的
        // 「返回 RIP / RFLAGS」，用户拿到的值不变。
        //
        // 代价：`sysretq` 回程（SYSCALL-FAST-4）由此废除；入口仍是 `syscall`
        // （LSTAR），快路径的主要收益（免 `int 0x80` 的门开销）保留。
        // GS 退出判定：读**即将 iretq 的那一帧**的 CS（偏移 8 = CS）。
        // 与阶段 1 的 `swapgs` 配对——不变式：**CPL3 ⟺ GS.base 是用户值**。
        // 调度器可能已把帧整体换成另一进程的帧，故判据跟着「要回哪」走。
        test byte ptr [rsp + 8], 3
        jz 6f
        swapgs
        6:
        iretq
    "#
);

/// `syscall` 入口 stub 的地址（供 LSTAR 使用）。
pub fn syscall_entry_addr() -> u64 {
    unsafe extern "C" {
        fn syscall_entry_stub();
    }
    syscall_entry_stub as *const () as usize as u64
}
/// `interrupt_common_stub` 返回后 iretq 即进入目标进程用户态。返回 void，
/// 若调度器未切换（无其他就绪进程），帧保持不变，原进程继续执行。
///
/// 每个核自己的 IRQ0 后都会调用（对称多处理：每个 AP 用自己的 LAPIC 定时器
/// 驱动调度 tick）。
pub type SchedulerTickHandler = extern "C" fn(&mut InterruptFrame);
static SCHEDULER_TICK: AtomicUsize = AtomicUsize::new(0);

/// 注册调度器 tick 回调（M4.2）。用原子槽单次注册（与软中断 handler 同模式）。
pub fn register_scheduler_tick(h: SchedulerTickHandler) {
    SCHEDULER_TICK.store(h as usize, Ordering::SeqCst);
}

/// 中断返回边界的「待决信号投递」回调（S1-8 触发点 4）。
///
/// `arch` 不认识 `task`/信号语义（保持分层），故与 tick、软中断 handler 同模式：
/// 由内核层注入 `task::deliver_pending_on_return`。返回 `false` 表示当前进程已被
/// 默认终止、`*frame` 已由调度接管，调用方不得再触碰该帧。
///
/// ABI 用 Rust `fn`（非 `extern "C"`）与 [`SchedulerTickHandler`] 的既有约定保持
/// 一致，避免内核侧注册点出现 ABI 不匹配。
pub type PendingDeliverHandler = fn(&mut InterruptFrame) -> bool;
static PENDING_DELIVER: AtomicUsize = AtomicUsize::new(0);

/// 注册待决信号投递回调（内核引导期调用一次）。
pub fn register_pending_deliver(h: PendingDeliverHandler) {
    PENDING_DELIVER.store(h as usize, Ordering::SeqCst);
}

/// IPI 邮箱向量（MA1b）：跨核请求的投递通道（当前唯一用途 = per-CPU 缓存
/// 排空请求）。避开 32..47（8259 IRQ 重映射区）与 0x80（syscall）。
pub const IPI_VECTOR: u8 = 0x40;

/// 跨核停机向量（KA1）：panic 现场广播给其它 CPU，收到即永久停机。
/// 与 IPI_VECTOR 同避让纪律。
pub const IPI_HALT_VECTOR: u8 = 0x41;

/// 跨核重调度向量（阶段2 M5）：目标核处于调度空闲 halt 时收到即醒来、立刻重查
/// 自己的就绪队列（把跨核唤醒的时延从"等下一 IRQ0 tick (~16ms)"压到即时）。
/// 目标核若在运行则静默无副作用（处理函数仅 EOI 后返回）。与其它 IPI 向量同避让。
pub const IPI_RESCHED_VECTOR: u8 = 0x42;

/// TLB shootdown 会合向量（SMP 审计 S1）。
///
/// 发起核改完页表后广播本向量，目标核在中断门内执行 `invlpg`（或整表重载 CR3）
/// 并递增 ack 计数；发起核自旋等待全部在线核（除自己）确认后，才**允许归还
/// 物理帧**。缺了「等确认」这一步，帧可能在本核还没失效 TLB 时就被复用，
/// 陈旧翻译指向新数据 → 静默内存破坏。
pub const IPI_TLB_VECTOR: u8 = 0x43;

/// x86-64 异常向量号（SDM Vol.3 §6.3.1）：页错误（#PF，有错误码 + CR2）。
/// 分发路径按此号路由补页回调 / 内核故障检查器 / CR2 打印。
pub const VECTOR_PAGE_FAULT: u64 = 14;

/// x86-64 异常向量号（SDM Vol.3 §6.3.1）：双重错误（#DF，有错误码，
/// IST 切换）。打印时附带内核栈溢出提示。
pub const VECTOR_DOUBLE_FAULT: u64 = 8;

/// x86-64 异常向量号（SDM Vol.3 §6.3.1）：通用保护故障（#GP，有错误码）。
///
/// 与 #PF 的关键差别：#GP **没有 CR2**，出错地址不会由硬件记录。定位只能靠
/// 「出错 rip + 当时寄存器值」，故分发路径对本向量额外转储全部通用寄存器
/// （见致命路径的寄存器转储段）。
pub const VECTOR_GENERAL_PROTECTION: u64 = 13;

/// IPI 到达回调（MA1b）：目标 CPU 在中断上下文执行（中断门，IF 已关）。
/// 回调须短小、不睡眠、只触碰本 CPU 私有数据。
pub type IpiHandler = fn();
static IPI_HANDLER: AtomicUsize = AtomicUsize::new(0);

/// 注册 IPI 到达回调（kernel 层把 mm 的"排空本核缓存"接进来）。
pub fn register_ipi_handler(h: IpiHandler) {
    IPI_HANDLER.store(h as usize, Ordering::SeqCst);
}

/// 读取当前已注册的 IPI 到达回调（供 kernel-tests 保存/恢复现场用）。
/// 无回调返回 None。IPI 分发是单一槽位，自测临时换装后必须恢复原位，
/// 否则 mm 的跨核排空在测试期间失效。
pub fn current_ipi_handler() -> Option<IpiHandler> {
    let f = IPI_HANDLER.load(Ordering::Acquire);
    if f == 0 {
        None
    } else {
        // 指针来自 register_ipi_handler 写入的合法 'static 函数地址。
        Some(unsafe { core::mem::transmute::<usize, IpiHandler>(f) })
    }
}

fn dispatch_ipi() {
    let f = IPI_HANDLER.load(Ordering::Acquire);
    if f != 0 {
        // 指针来自 register_ipi_handler 写入的合法 'static 函数地址。
        let h = unsafe { core::mem::transmute::<usize, IpiHandler>(f) };
        h();
    }
    // Fixed IPI 置位 ISR，必须 EOI，否则后续同向量中断被 LAPIC 挂起。
    crate::lapic::end_of_interrupt();
}

/// 跨核重调度请求处理（阶段2 M5）：Fixed IPI 置位 ISR，必须 EOI。中断本身已
/// 把目标核从调度空闲 halt 唤醒；此处仅清挂起位，无其它副作用。
fn dispatch_resched() {
    crate::lapic::end_of_interrupt();
}

/// 向指定 CPU 槽位发送跨核重调度 IPI（阶段2 M5）。用于某核跨核唤醒了一个驻留
/// 在别核（且该核空闲 halt）的进程后，即时促其醒来重查就绪队列。返回是否成功
/// 投递（目标槽位失联/尚未上线则 false，调用方可静默忽略——被唤醒核自身 IRQ0
/// 兜底会在 ~16ms 内重查，IPI 只是即时优化）。
/// 已投递的重调度 IPI 计数（S4 可观测性）。
///
/// 存在的理由：跨核唤醒**必须**投递 IPI 这一不变式此前无任何观测手段——
/// `let _ = send_resched_ipi_to_slot(..)` 把结果丢弃，投递与否、投给谁，
/// 全都不可见。计数本身也是真实的运行期指标（可据此判断 IPI 风暴）。
static RESCHED_IPI_SENDS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// 读取已投递的重调度 IPI 总数。
pub fn resched_ipi_send_count() -> u64 {
    RESCHED_IPI_SENDS.load(core::sync::atomic::Ordering::Relaxed)
}

/// 投递失败计数（目标槽位失联）。与成功计数分开，避免"看起来发了"。
static RESCHED_IPI_FAILS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// 读取重调度 IPI 投递失败总数。
pub fn resched_ipi_send_fail_count() -> u64 {
    RESCHED_IPI_FAILS.load(core::sync::atomic::Ordering::Relaxed)
}

pub fn send_resched_ipi_to_slot(slot: usize) -> bool {
    match crate::smp::lapic_id_of_slot(slot) {
        Some(lapic_id) => {
            let ok = crate::lapic::send_fixed_ipi(lapic_id, IPI_RESCHED_VECTOR);
            if ok {
                RESCHED_IPI_SENDS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            } else {
                RESCHED_IPI_FAILS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
            ok
        }
        None => {
            RESCHED_IPI_FAILS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            false
        }
    }
}

/// 给指定槽位发送 TLB shootdown 会合 IPI（S1）。
///
/// 返回是否**成功投递**（槽位未登记 = false，不静默当作成功）。
pub fn send_tlb_ipi_to_slot(slot: usize) -> bool {
    match crate::smp::lapic_id_of_slot(slot) {
        Some(lapic_id) => crate::lapic::send_fixed_ipi(lapic_id, IPI_TLB_VECTOR),
        None => false,
    }
}

/// TLB shootdown 会合的中断侧处理：失效本核 TLB 并 ack，然后 EOI。
///
/// 在中断门内运行（IF 已关），**只做寄存器操作与原子递增，不取任何锁**
/// ——这是发起核能安全地持页表锁等待 ack 的前提。
fn dispatch_tlb_shootdown() {
    crate::smp::tlb_shootdown_ack();
    crate::lapic::end_of_interrupt();
}

/// 跨核停机处理（KA1）：中断门下 IF 已关，hlt 永久睡眠——本核不再参与任何
/// 执行，直到下一次 CPU Reset。不 EOI：无恢复路径，挂起位无意义。
fn dispatch_ipi_halt() -> ! {
    loop {
        // SAFETY: 特权指令停机；中断已被中断门关闭，hlt 永久阻塞。
        unsafe { core::arch::asm!("hlt") }
    }
}

/// LAPIC 伪中断向量（SVR 低 8 位）。
///
/// 伪中断到达时 ISR 位**不置位**，按 Intel SDM §10.9 不需要 EOI；处理器只
/// 要求 IDT 存在该向量的表项。分发到此向量时静默返回即可。
pub const SPURIOUS_VECTOR: u16 = 0xFF;

/// 裸串口格式化输出（AM7）：绕过 klib console sink 链与全部锁，供致命异常
/// 诊断使用。栈上 128B 缓冲、零堆分配；截断优于死锁/丢诊断。
fn raw_serial_fmt(args: core::fmt::Arguments) {
    use core::fmt::Write as _;
    /// 单行诊断缓冲上限：异常字段（名称/十六进制值）最长不超过此值。
    const RAW_DIAG_CAP: usize = 128;
    struct RawWriter<'a> {
        buf: &'a mut [u8],
        len: usize,
    }
    impl core::fmt::Write for RawWriter<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let bytes = s.as_bytes();
            let room = self.buf.len() - self.len;
            let mut n = bytes.len().min(room);
            // 审计 B23：截断必须落在 UTF-8 字符边界——多字节序列被拦腰截断
            // 后，下方 from_utf8_unchecked 即 UB。UTF-8 续字节特征 (b & 0xC0)
            // == 0x80：n 回退到首字节为止。当前全部实参为 ASCII 十六进制/
            // 字段名（边界天然成立），此处回退是契约的机器强制而非信任。
            // 仅在确实发生截断（n < bytes.len()）时才需回退；全量容纳
            // （n == bytes.len()）时无切点，`bytes[n]` 越界读（S19 回归：
            // 旧实现无条件读 bytes[n]，n==len 时 OOB panic）。
            while n > 0 && n < bytes.len() && bytes[n] & 0xC0 == 0x80 {
                n -= 1;
            }
            self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
            self.len += n;
            Ok(())
        }
    }
    let mut buf = [0u8; RAW_DIAG_CAP];
    let len = {
        let mut w = RawWriter {
            buf: &mut buf,
            len: 0,
        };
        let _ = w.write_fmt(args);
        w.len
    };
    // 截断回退可能把 len 停在缓冲内已有内容的字符中间？不会——每次
    // write_str 只追加完整 &str 或其字符边界前缀，len 永远停在边界。
    let s = unsafe { core::str::from_utf8_unchecked(&buf[..len]) };
    crate::serial::write_str(s);
}

// ---------- SYSCALL-FAST-4：GS 进出判定（已内联进 interrupt_common_stub）----------
//
// 历史备注：本节原是 `gs_entry_hook`/`gs_exit_hook` 两个 Rust 钩子 + 一个全局
// `GS_UNSWAP_PENDING` 标志。实测发现该设计有**嵌套中断缺陷**：内层中断会把外层
// 置位的标志清掉，外层返回用户态时漏掉 swapgs，GS 状态整体翻转，此后偶发 #GP。
// 已改为 stub 内联 CPL 判定（`test [rsp+144], 3` / `test [rsp+8], 3`），每次进出
// 都读**自己那一帧**，无共享状态，天然嵌套安全。钩子已删除（单一来源）。

/// 分发入口（由汇编 `interrupt_common_stub` 调用）。
///
/// `frame` 指向保存的寄存器区。
#[unsafe(no_mangle)]
pub extern "C" fn interrupt_dispatch(frame: *mut InterruptFrame) {
    let frame = unsafe { &mut *frame };
    let vector = frame.vector;

    if vector == SPURIOUS_VECTOR as u64 {
        // LAPIC 伪中断：无 ISR 位、无需 EOI，静默吞掉（arch1.md AA3）。
        // 不走外部中断路径：该路径按 (vector-32) 索引 16 项 IRQ 表并给 8259
        // 发 EOI，对 0xFF 全部不适用。
        return;
    }

    if vector == IPI_VECTOR as u64 {
        // MA1b：IPI 邮箱——回调处理本核请求后向 LAPIC EOI。
        dispatch_ipi();
        return;
    }

    if vector == IPI_HALT_VECTOR as u64 {
        // KA1：跨核停机请求——永久停住本核（不返回）。
        dispatch_ipi_halt();
    }

    if vector == IPI_RESCHED_VECTOR as u64 {
        // 阶段2（M5）：跨核重调度请求——本核若在调度空闲 halt 则被此中断唤醒，
        // 返回后重查自己就绪队列；若在运行则仅 EOI 无副作用。无需回调。
        dispatch_resched();
        return;
    }

    if vector == IPI_TLB_VECTOR as u64 {
        // S1：TLB shootdown 会合——在中断门内立即失效，然后 ack。
        dispatch_tlb_shootdown();
        return;
    }

    if vector < 32 {
        // CPU 异常：先关中断，避免嵌套
        disable();

        if vector == VECTOR_PAGE_FAULT {
            // 页错误：仅**用户态**缺页交给已注册的 #PF 回调（按需分页 / COW）。
            // 内核态 #PF（含 SMAP/SMEP 违规、访问未映射内核地址）一律视为致命
            // 错误，不交给用户态补页处理器——否则可能被 `cow_pages` 记账误命中
            // 或掩盖真实的防护触发（严格隔离下内核不应访问用户页 / 执行用户代码）。
            // 回调约定：`fn(cr2, error_code) -> bool`（虚拟地址在前，错误码在后）。
            let cr2 = crate::mmio::cr2();
            if frame.cs & 3 == 3 {
                if let Some(h) = PAGE_FAULT_HANDLER.get() {
                    if h(cr2, frame.error_code) {
                        return; // 已处理（如补页成功），返回用户态继续
                    }
                }
            }
        }

        // M3.3 / ADR-034 PRE-2：若异常来自用户态（CS.RPL==3），交给进程层终止
        // 该进程或投递信号，而非当作内核崩溃。读取 CR2（#PF 出错地址）传给回调
        // （非 #PF 异常也读——值为陈旧 CR2，回调按 vector 决定是否采信）。
        // 处理器应不返回（停机/恢复调度）；返回则兜底停机。
        if frame.cs & 3 == 3 {
            if let Some(h) = USER_EXCEPTION_HANDLER.get() {
                let cr2 = crate::mmio::cr2();
                // 返回 true：已处置（如投递到 handler），iretq 回用户态继续；
                // 返回 false：未恢复（已终止/停机），兜底停机。
                if h(cr2, frame) {
                    return;
                }
                crate::halt_forever();
            }
        }

        // KA3：内核态 #PF 先过注册的检查器（如内核栈守护页识别）。检查器
        // 处置完毕（返回 true）则不再落入下方通用致命路径。
        if frame.cs & 3 == 0 && vector == VECTOR_PAGE_FAULT {
            let cr2 = crate::mmio::cr2();
            if let Some(insp) = KERNEL_FAULT_INSPECTOR.get() {
                if insp(cr2) {
                    return;
                }
            }
        }

        // 内核态异常（或未注册用户态处理器）：打印并停机。
        // AM7：诊断走**裸串口**而非 klib::info!——后者经 console sink 注册链
        // 与各 sink 锁；若崩溃根源正是 console/锁/堆，这条链可能死锁或丢字，
        // 违背"停机前必有诊断"的自我承诺。裸串口是同 crate 内最短依赖路径，
        // 不经过任何锁与堆。
        raw_serial_fmt(format_args!("\n========== CPU EXCEPTION ==========\n"));
        raw_serial_fmt(format_args!("exception: {}\n", exception_name(vector as u8)));
        raw_serial_fmt(format_args!("  vector: {:#x}\n", vector));
        raw_serial_fmt(format_args!("  rip:    {:#x}\n", frame.rip));
        if vector == VECTOR_PAGE_FAULT {
            let cr2 = crate::mmio::cr2();
            // 未注册/未处理/内核态：打印 CR2 并停机
            raw_serial_fmt(format_args!("  cr2:    {:#x}\n", cr2));
            raw_serial_fmt(format_args!("  error:  P={:#x}\n", frame.error_code));
        }
        if vector == VECTOR_DOUBLE_FAULT {
            // Double Fault：打印错误码（0 表示外部中断/软件引起的 DF）
            raw_serial_fmt(format_args!("  error:  {:#x}\n", frame.error_code));
            raw_serial_fmt(format_args!("  (Double Fault - possible kernel stack overflow)\n"));
        }
        // GPF 的定位依赖**完整寄存器现场**，故单独转储（本节为此存在）。
        //
        // 为何 GPF 特别需要它：#PF 有 CR2 直接指出出错地址，GPF 没有——出错信息
        // 只存在于「哪条指令 + 当时寄存器值」里。而 GPF 在内核态最常见的两个成因
        // 都表现为「寄存器里是一个非规范地址」（bit 47..63 未按要求符号扩展）或
        // 「段/对齐违规」，两者都只能从寄存器里读出来。只打印 rip 会让定位停在
        // 「知道在哪条指令、不知道它在算什么」，这是本轮实测踩到的实际困难。
        //
        // 转储成本只发生在本就致命的路径上（随后 halt_forever），且走裸串口
        // （不经 console sink/锁/堆，理由同上方 AM7），故不引入新的失败模式。
        if vector == VECTOR_GENERAL_PROTECTION {
            // 帧里的 ss/cs/vector 与 GPR 同等重要：本向量的错误码**就是段选择子**
            // （GDT 索引 <<3 | TI | 外部事件位），要判「哪个选择子非法」必须同时
            // 看到 ss/cs 当前值；vector 则回答「是哪条进入路径进来的」。
            raw_serial_fmt(format_args!("  ss:     {:#x}\n", frame.ss));
            raw_serial_fmt(format_args!("  rsp:    {:#x}\n", frame.rsp));
            raw_serial_fmt(format_args!("  cs:     {:#x}\n", frame.cs));
            raw_serial_fmt(format_args!("  rflags: {:#x}\n", frame.rflags));
            raw_serial_fmt(format_args!("  error:  {:#x}\n", frame.error_code));
            raw_serial_fmt(format_args!("  vector: {:#x} ({})\n", frame.vector, exception_name(frame.vector as u8)));
            // iretq 帧转储：#GP 若由 `iretq` 触发，出错信息**不在**上面这些字段里，
            // 而在 iretq 正要弹出、位于 frame.rsp 处的那个 5 槽帧里
            // （RIP/CS/RFLAGS/RSP/SS）。上面 15 个 GPR 是 iretq **执行时**的寄存器，
            // 与「iretq 想装载什么」是两件事——本向量最容易在这里被误读。
            // 裸读 rsp 处 6 个 qword（多读 1 个以便判别帧边界）。
            // SAFETY：仅在内核已致命停机前诊断路径上读；frame.rsp 是内核栈地址，
            // 该栈在本次异常发生前一直有效，读操作不改变任何状态，也不解引用其内容。
            unsafe {
                let p = frame.rsp as *const u64;
                raw_serial_fmt(format_args!("  [rsp+0]  {:#018x}  (iretq RIP )\n", core::ptr::read_volatile(p)));
                raw_serial_fmt(format_args!("  [rsp+8]  {:#018x}  (iretq CS  )\n", core::ptr::read_volatile(p.add(1))));
                raw_serial_fmt(format_args!("  [rsp+16] {:#018x}  (iretq FLAG)\n", core::ptr::read_volatile(p.add(2))));
                raw_serial_fmt(format_args!("  [rsp+24] {:#018x}  (iretq RSP )\n", core::ptr::read_volatile(p.add(3))));
                raw_serial_fmt(format_args!("  [rsp+32] {:#018x}  (iretq SS  )\n", core::ptr::read_volatile(p.add(4))));
                raw_serial_fmt(format_args!("  [rsp+40] {:#018x}  (beyond    )\n", core::ptr::read_volatile(p.add(5))));
            }
            raw_serial_fmt(format_args!("  rax:    {:#x}\n", frame.rax));
            raw_serial_fmt(format_args!("  rbx:    {:#x}\n", frame.rbx));
            raw_serial_fmt(format_args!("  rcx:    {:#x}\n", frame.rcx));
            raw_serial_fmt(format_args!("  rdx:    {:#x}\n", frame.rdx));
            raw_serial_fmt(format_args!("  rsi:    {:#x}\n", frame.rsi));
            raw_serial_fmt(format_args!("  rdi:    {:#x}\n", frame.rdi));
            raw_serial_fmt(format_args!("  rbp:    {:#x}\n", frame.rbp));
            raw_serial_fmt(format_args!("  r8:     {:#x}\n", frame.r8));
            raw_serial_fmt(format_args!("  r9:     {:#x}\n", frame.r9));
            raw_serial_fmt(format_args!("  r10:    {:#x}\n", frame.r10));
            raw_serial_fmt(format_args!("  r11:    {:#x}\n", frame.r11));
            raw_serial_fmt(format_args!("  r12:    {:#x}\n", frame.r12));
            raw_serial_fmt(format_args!("  r13:    {:#x}\n", frame.r13));
            raw_serial_fmt(format_args!("  r14:    {:#x}\n", frame.r14));
            raw_serial_fmt(format_args!("  r15:    {:#x}\n", frame.r15));
        }
        raw_serial_fmt(format_args!("==================================\n"));
        crate::halt_forever();
    } else if vector == 0x80 {
        // 软中断：交给已注册的 handler（M2.5.4 进入用户态冒烟 / M3 syscall 雏形）。
        if let Some(h) = SOFT_INT_HANDLER.get() {
            if h(frame) {
                return; // 已处理，iretq 返回触发点
            }
        }
        // AM7：致命诊断走裸串口（理由见上方 CPU EXCEPTION 分支注释）。
        raw_serial_fmt(format_args!("========== UNHANDLED SOFT INTERRUPT (0x80) ==========\n"));
        crate::halt_forever();
    } else {
        // 外部中断（32..47 → IRQ0..15）。共享中断：依次调用该 IRQ 的全部
        // handler，任一返回 `true` 即视为已处理并停止；全部未处理则 EOI。
        //
        // 嵌套与优先级（T7）：每 IRQ 一个软件优先级（0 最低 ~ 15 最高）。
        // - 嵌套关闭（默认）：中断门已自动关中断，处理期间不可被打断；
        // - 嵌套开启：若本 IRQ 优先级高于"当前正在处理的中断"优先级，则
        //   临时 `sti` 允许更高优先级中断打断（返回前 `cli` 并恢复状态）。
        //   否则保持关中断——更低/同级优先级的中断无法打断当前处理。
        // `CURRENT_IRQ_PRIO` 进入时原子替换、返回前恢复，供嵌套判断与
        // handler 内查询（`current_irq_priority`）。
        let irq = (vector - 32) as u8;
        let prio = irq_priority(irq);
        let prev = CURRENT_IRQ_PRIO.swap(prio, Ordering::Relaxed);
        let nested = NESTED_IRQ.load(Ordering::Relaxed) && prio > prev;
        if nested {
            enable();
        }
        let slot = &IRQ_HANDLERS[irq as usize];
        for entry in slot {
            let handler_ptr = entry.load(Ordering::Acquire);
            if handler_ptr == 0 {
                continue;
            }
            // 指针来自 register_irq 写入的合法 'static 函数地址，读回安全。
            let h = unsafe { core::mem::transmute::<usize, IrqHandler>(handler_ptr) };
            if h(irq) {
                break;
            }
        }
        if nested {
            disable();
        }
        CURRENT_IRQ_PRIO.store(prev, Ordering::Relaxed);
        // 外部中断统一向 8259 发送 EOI，清除其 ISR 服务位——否则 8259 会持续
        // 屏蔽同 IRQ 的后续中断（键盘等只收到第一个字符）。LAPIC EOI 由各
        // handler 自行发送（见 `irq1_handler` 等）。无条件发送对走 LAPIC 自身
        // 定时器（irq0）等路径亦无害。
        crate::pic::end_of_interrupt(irq);
        // M4.2：IRQ0（LAPIC 定时器）之后调用调度器 tick，允许在中断帧上做
        // 进程切换（改写 frame → 返回时 iretq 到目标进程）。仅 BSP 调度。
        if irq == 0 {
            let f = SCHEDULER_TICK.load(Ordering::Acquire);
            if f != 0 {
                let h: SchedulerTickHandler =
                    unsafe { core::mem::transmute::<usize, SchedulerTickHandler>(f) };
                h(frame);
            }
            // S1-8 触发点 4：tick 可能已把 `*frame` 整体改写为**被切入进程**的
            // 用户现场（`commit_same_lock` 的 `*frame = slot.saved`）。那条路径
            // 不经过任何投递检查——本处补上：投递该进程的待决信号。
            //
            // 为何必须在这里而不能只在 tick 内部：`tick` 顶部的投递以「被中断的
            // 上下文属于要投递的进程」为前提，切点之后这个前提就换了人；且
            // `commit_same_lock` 持着 RUN 与 per-pid 桶锁，不得在其临界区内投递
            // （默认终止路径会经 `exit_current` 取同一批锁）。此处所有调度锁均已
            // 释放，正是投递的安全点。
            let dh = PENDING_DELIVER.load(Ordering::Acquire);
            if dh != 0 {
                let d: PendingDeliverHandler = unsafe { core::mem::transmute::<usize, PendingDeliverHandler>(dh) };
                // 返回 false = 进程已终止且 `*frame` 已交调度接管，不得再触碰。
                let _ = d(frame);
            }
        }
    }
}

// 加载 IDT。
unsafe extern "C" {
    fn x86_64_load_idt(idtr: *const Idtr);
}

/// 启用 FPU/SSE：清 CR0.TS、置 MP/NE，并置 CR4.OSFXSR。
///
/// bootloader（Limine）可能以 lazy-FPU 方式启动，CR0.TS=1。此时任何 x87/MMX/SSE
/// 指令都会触发 #NM（Device Not Available）异常。这里直接清除 TS，让浮点指令
/// 始终可用；同时置 MP（monitor coprocessor）与 NE（native error），规范 FPU
/// 行为；CR4.OSFXSR（bit9）声明 OS 保存 SSE 状态——未置位时任何 SSE 指令 #UD。
///
/// 跨任务 FPU 状态语义（task1 K2 落地后的设计事实，取代旧的"偶然安全"记录）：
/// **eager 全量保存**——每次任务切出/切入由 task 调度器经 [`crate::fpu`] 的
/// fxsave64/fxrstor64 完成，每进程持独立 [`crate::fpu::FpuArea`]。本函数只负责
/// 一次性建立硬件前提（TS=0、EM=0、OSFXSR=1）且此后不得再置 TS；若未来改动
/// 引入 TS 惰性方案，必须同步废弃 task 侧 eager 接线，两者不可并存。
pub fn enable_fpu() {
    unsafe {
        let cr0: u64;
        core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack));
        // 清 TS(bit3)，置 MP(bit1) 与 NE(bit5)
        let new = (cr0 & !(1 << 3)) | (1 << 1) | (1 << 5);
        core::arch::asm!("mov cr0, {}", in(reg) new, options(nomem, nostack));

        // CR4.OSFXSR(bit9)：向 CPU 声明 OS 在任务切换时保存 SSE 现场。
        // 未置位时 SSE 指令一律 #UD——FXSAVE/FXRSTOR 与用户 SSE 代码的共同前提。
        let mut cr4 = crate::mmio::read_cr4();
        cr4 |= 1 << 9;
        crate::mmio::write_cr4(cr4);
    }
}

/// 保存当前 RFLAGS（含 IF）并关中断，返回保存的旧 RFLAGS。
///
/// 注入给 [`klib::sync::irq::set_irq_guard`]，供中断安全锁保存/恢复中断状态。
#[inline]
pub fn irq_save() -> usize {
    let flags: u64;
    unsafe {
        core::arch::asm!(
            "pushfq",
            "pop {}",
            out(reg) flags,
            options(nomem, nostack, preserves_flags),
        );
    }
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
    }
    flags as usize
}

/// 恢复此前保存的 RFLAGS（还原 IF 状态，可能重新打开中断）。
#[inline]
pub fn irq_restore(flags: usize) {
    unsafe {
        core::arch::asm!(
            "push {}",
            "popfq",
            in(reg) flags as u64,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// 初始化 IDT：填充 0~47 号向量，然后加载。
pub fn init() {
    // 启用 FPU/SSE（清 CR0.TS），避免用户态/内核执行浮点指令时触发 #NM → 级联 #DF。
    enable_fpu();

    unsafe {
        let idt_ptr = &raw mut IDT as *mut Idt;

        // 0~31：异常，陷阱门。vector 8（Double Fault）使用独立 IST 栈，
        // 避免异常处理中再次异常导致 Triple Fault 重启。其余不用 IST（0）。
        for vector in 0..32u16 {
            let handler = get_isr_addr(vector);
            let ist = if vector == VECTOR_DOUBLE_FAULT as u16 { IST_DF as u8 } else { 0 };
            (*idt_ptr).entries[vector as usize].set_handler(handler, IDT_FLAG_TRAP, ist);
        }
        // 32~47：外部中断，中断门（不用 IST）
        for vector in 32..48u16 {
            let handler = get_isr_addr(vector);
            (*idt_ptr).entries[vector as usize].set_handler(handler, IDT_FLAG_INTERRUPT, 0);
        }
        // 0x80：用户态软中断（M2.5.4 / M3 syscall 入口），DPL=3 陷阱门，
        // 用户态 `int 0x80` 可触发进入内核。
        let handler = get_isr_addr(0x80);
        (*idt_ptr).entries[0x80].set_handler(handler, IDT_FLAG_TRAP_USER, 0);
        // 0xFF：LAPIC 伪中断向量（arch1.md AA3）。SVR 使能该向量后，伪中断
        // 到达时 CPU 照常查 IDT；缺表项 = #GP → #DF 级联停机。中断门 + 分发端
        // 静默返回（无需 EOI）。
        let handler = get_isr_addr(SPURIOUS_VECTOR);
        (*idt_ptr).entries[SPURIOUS_VECTOR as usize].set_handler(handler, IDT_FLAG_INTERRUPT, 0);
        // MA1b：IPI 邮箱向量 0x40。中断门；分发端调用注册回调后向 LAPIC EOI。
        let handler = get_isr_addr(IPI_VECTOR as u16);
        (*idt_ptr).entries[IPI_VECTOR as usize].set_handler(handler, IDT_FLAG_INTERRUPT, 0);
        // KA1：跨核停机向量 0x41。中断门；收到即永久停机（无需 EOI——本核
        // 不再恢复执行）。
        let handler = get_isr_addr(IPI_HALT_VECTOR as u16);
        (*idt_ptr).entries[IPI_HALT_VECTOR as usize].set_handler(handler, IDT_FLAG_INTERRUPT, 0);
        // 阶段2（M5）：跨核重调度向量 0x42。中断门；收到即唤醒调度空闲 halt。
        let handler = get_isr_addr(IPI_RESCHED_VECTOR as u16);
        (*idt_ptr).entries[IPI_RESCHED_VECTOR as usize].set_handler(handler, IDT_FLAG_INTERRUPT, 0);
        // S1：TLB shootdown 会合向量 0x43。中断门；目标核在门内失效 TLB 并 ack。
        let handler = get_isr_addr(IPI_TLB_VECTOR as u16);
        (*idt_ptr).entries[IPI_TLB_VECTOR as usize].set_handler(handler, IDT_FLAG_INTERRUPT, 0);

        let idtr = build_idtr();
        x86_64_load_idt(&idtr as *const Idtr);
    }
}

/// MA1b：在**当前 CPU** 上重新加载全局 IDT。
///
/// IDT 内存是全体 CPU 共享的静态表，但 IDTR 是 per-CPU 寄存器——AP 在
/// `ap_entry` 中必须自行 `lidt`，否则该核上任何中断（含 IPI）都查不到
/// 向量表直落三重故障。须在开中断之前调用。
pub fn reload_idt_current_cpu() {
    unsafe {
        let idtr = build_idtr();
        x86_64_load_idt(&idtr as *const Idtr);
    }
}

/// 构造指向共享静态 IDT 的 IDTR。
fn build_idtr() -> Idtr {
    Idtr {
        limit: (core::mem::size_of::<Idt>() - 1) as u16,
        base: &raw const IDT as u64,
    }
}

/// 获取第 `vector` 号中断入口的地址。
/// 汇编生成的符号名形如 `isr_0`、`isr_14`。
fn get_isr_addr(vector: u16) -> u64 {
    // 通过构建符号名无法在稳定 Rust 中反射，改用固定符号表。
    // 这里用 extern 声明并查表。
    unsafe extern "C" {
        fn isr_0();
        fn isr_1();
        fn isr_128();
        fn isr_2();
        fn isr_3();
        fn isr_4();
        fn isr_5();
        fn isr_6();
        fn isr_7();
        fn isr_8();
        fn isr_9();
        fn isr_10();
        fn isr_11();
        fn isr_12();
        fn isr_13();
        fn isr_14();
        fn isr_15();
        fn isr_16();
        fn isr_17();
        fn isr_18();
        fn isr_19();
        fn isr_20();
        fn isr_21();
        fn isr_22();
        fn isr_23();
        fn isr_24();
        fn isr_25();
        fn isr_26();
        fn isr_27();
        fn isr_28();
        fn isr_29();
        fn isr_30();
        fn isr_31();
        fn isr_32();
        fn isr_33();
        fn isr_34();
        fn isr_35();
        fn isr_36();
        fn isr_37();
        fn isr_38();
        fn isr_39();
        fn isr_40();
        fn isr_41();
        fn isr_42();
        fn isr_43();
        fn isr_44();
        fn isr_45();
        fn isr_46();
        fn isr_47();
        fn isr_64();
        fn isr_65();
        fn isr_66();
fn isr_67();
        fn isr_255();
    }

    const HANDLERS: [unsafe extern "C" fn(); 48] = [
        isr_0, isr_1, isr_2, isr_3, isr_4, isr_5, isr_6, isr_7, isr_8, isr_9, isr_10, isr_11,
        isr_12, isr_13, isr_14, isr_15, isr_16, isr_17, isr_18, isr_19, isr_20, isr_21, isr_22,
        isr_23, isr_24, isr_25, isr_26, isr_27, isr_28, isr_29, isr_30, isr_31, isr_32, isr_33,
        isr_34, isr_35, isr_36, isr_37, isr_38, isr_39, isr_40, isr_41, isr_42, isr_43, isr_44,
        isr_45, isr_46, isr_47,
    ];

    // 软中断向量 0x80 使用独立的 isr_128 入口。
    if vector == 0x80 {
        return isr_128 as *const () as usize as u64;
    }
    // MA1b：IPI 邮箱向量 0x40（isr_64）。
    if vector == IPI_VECTOR as u16 {
        return isr_64 as *const () as usize as u64;
    }
    // KA1：跨核停机向量 0x41（isr_65）。
    if vector == IPI_HALT_VECTOR as u16 {
        return isr_65 as *const () as usize as u64;
    }
    // 阶段2（M5）：跨核重调度向量 0x42（isr_66）。
    if vector == IPI_RESCHED_VECTOR as u16 {
        return isr_66 as *const () as usize as u64;
    }
    // S1：TLB shootdown 会合向量 0x43（isr_67）。
    if vector == IPI_TLB_VECTOR as u16 {
        return isr_67 as *const () as usize as u64;
    }
    // 伪中断向量 0xFF 同样在固定表之外（isr_255）。
    if vector == SPURIOUS_VECTOR {
        return isr_255 as *const () as usize as u64;
    }
    HANDLERS[vector as usize] as *const () as usize as u64
}

/// 使能中断。
pub fn enable() {
    unsafe { core::arch::asm!("sti") };
}

/// 禁用中断。
pub fn disable() {
    unsafe { core::arch::asm!("cli") };
}

/// CPU 停机（执行一条 `hlt`）。
#[inline]
pub fn halt() {
    unsafe { core::arch::asm!("hlt", options(nomem, nostack)) };
}

/// 永久停机：关中断后空转，永不返回。
///
/// 原实现是 `cli; hlt` 死循环。`hlt` 在关中断时会让 CPU 永久停在 HLT 状态，
/// QEMU 不再推进指令，导致 gdb 单步/continue 永远等待（死锁）。
/// 这里改为 `pause`（spin_loop）空转：占满 CPU 但持续执行，gdb 可随时打断，
/// 且此前由 `interrupt_dispatch` 打印的异常信息仍会先输出到串口。
pub fn halt_forever() -> ! {
    loop {
        disable();
        core::hint::spin_loop(); // pause
    }
}
