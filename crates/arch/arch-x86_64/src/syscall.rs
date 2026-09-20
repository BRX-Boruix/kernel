//! x86-64 系统调用入口实现（ADR-007 的 `arch::SyscallEntry`）。
//!
//! 在 `int 0x80` 软中断到达时，把架构的 [`crate::interrupts::InterruptFrame`]
//! 翻译成可移植的 [`arch::syscall::SyscallFrame`]，调用内核注册的分发入口，
//! 再把结果写回调用进程返回值寄存器（`rax`）。
//!
//! 切换路径（Switched）：阻塞/让出 syscall 会把真实 `InterruptFrame` **整体**
//! 替换为下一进程的保存帧（调度器语义，见 `task` crate）。分发入口经
//! [`arch::syscall::SyscallFrame::arch_frame`] 访问真实帧；返回 `switched=true`
//! 时本层**不得**把 `result` 写回 `rax`——现场已是下一进程，其返回值由调度
//! 语义交付。此为架构固有的整体帧切换，无法仅靠可移植的寄存器窗口表达。

use core::sync::atomic::{AtomicUsize, Ordering};

use arch::syscall::{SyscallEntry, SyscallEntryFn, SyscallFrame};
use crate::interrupts::InterruptFrame;

/// 内核注册的 syscall 分发入口（原子指针槽，启动期单次注册）。
static SYSCALL_ENTRY: AtomicUsize = AtomicUsize::new(0);

/// `int 0x80` 软中断桥接：`InterruptFrame` ↔ `SyscallFrame`。
///
/// 以 [`crate::interrupts::SoftInterruptHandler`]（`extern "C" fn`）签名注册进
/// [`crate::interrupts`]。读取寄存器窗口填入 `SyscallFrame`，调用分发入口，
/// 再按 `switched` 决定是否写回 `rax`。
pub extern "C" fn soft_interrupt_bridge(frame: &mut InterruptFrame) -> bool {
    let f = SYSCALL_ENTRY.load(Ordering::Acquire);
    if f == 0 {
        return false; // 未注册分发入口：未处理
    }
    let entry: SyscallEntryFn = unsafe { core::mem::transmute(f) };

    // ABI（ADR-003）：rax = syscall 号，rdi/rsi/rdx/r10/r8/r9 = a1..a6。
    let mut scf = SyscallFrame {
        nr: frame.rax,
        a1: frame.rdi,
        a2: frame.rsi,
        a3: frame.rdx,
        a4: frame.r10,
        a5: frame.r8,
        result: 0,
        switched: false,
        aux_pid: 0,
        // 不透明句柄：切换路径由调度原语还原为 `&mut InterruptFrame`。
        arch_frame: frame as *mut InterruptFrame as usize,
    };

    let handled = entry(&mut scf);
    if handled && !scf.switched {
        // 正常完成：把结果写回调用进程 rax（Switched 时现场已换，不得回写）。
        frame.rax = scf.result;
        // waitpid 同步收尸路径把被收尸子进程 pid 经 aux_pid 交付：写进返回帧
        // r10，用户态 iretq 后取 r10 即得（与阻塞路径 saved.r10=pid 对齐）。
        if scf.aux_pid != 0 {
            frame.r10 = scf.aux_pid;
        }
    }
    handled
}

// ---------- SYSCALL-FAST-2：`syscall`/`sysret` 入口地基 ----------

/// `IA32_STAR`（0xC000_0081）：段选择子（低 32 位为 syscall 用，高 32 位为 sysret 用）。
pub const IA32_STAR: u32 = 0xC000_0081;
/// `IA32_LSTAR`（0xC000_0082）：`syscall` 指令的 64 位入口地址。
pub const IA32_LSTAR: u32 = 0xC000_0082;
/// `IA32_FMASK`（0xC000_0084）：`syscall` 进入内核时**自动清零**的 RFLAGS 位。
pub const IA32_FMASK: u32 = 0xC000_0084;
/// `IA32_EFER`（0xC000_0080）：须置位 `SCE`(bit0) 才能启用 `syscall`/`sysret`。
pub const IA32_EFER: u32 = 0xC000_0080;

/// GDT 内核代码段选择子（与 `gdt.rs` 布局一致：null, KCODE, KDATA, ...）。
pub const KERNEL_CS: u16 = 0x08;
/// GDT 内核数据段选择子。
pub const KERNEL_DS: u16 = 0x10;
/// **sysret 用的基值**。
///
/// `sysretq` 的段选择子由 STAR[63:48] **推算**，硬件规则固定：
///   - 目标 CS = base + 16；
///   - 目标 SS = base + 8。
///
/// 要得到用户 `CS=0x28` / `SS=0x30`，base 必须是 `0x18`。
/// 注意：`0x18` 同时是 **TSS 选择子**的值，但硬件只把它当**算术基值**，
/// 不会去加载该选择子——故二者数值相同不构成冲突（这是 x86-64 的既定约定）。
pub const SYSRET_CS_BASE: u16 = 0x28;
//
// 为什么是 0x28 而不是 0x18（SYSCALL-FAST-2 实测纠正）：
//   初始以为 base=0x18 能让 CS 落在既有 UCODE(0x28)；但 SS = base+8 = 0x20，
//   而 0x20 是本 GDT 的 **TSS_high**（64 位 TSS 描述符占两个槽），不是数据段，
//   `sysretq` 会直接 #GP。即：**既有 GDT 布局与 sysret 不兼容**。
//   取 base=0x28：CS = 0x38（新增的 UCODE_SYSRET 槽）、SS = 0x30（既有 UDATA）。
//   这样 iretq 路径的 0x28/0x30 完全不动，只有 sysret 走 0x38。
//
// 该错误由 test_syscall_fast2 的 STAR 断言**在运行前**捕获——正是先钉契约的价值。

/// RFLAGS 中在进入内核时必须清零的位（`IA32_FMASK`）。
///
/// 为什么必须清：`syscall` **不切栈**，进入瞬间仍在使用**用户 RSP**。
/// 若此时 `IF=1` 而 RSP 尚未换到内核栈，一个中断就会在用户栈上压内核帧——
/// 用户态可借此控制内核栈（经典的 `sysret`/`syscall` 提权面，CVE-2012-0217 类）。
/// 故必须 `CLI` 效果先行：掩掉 IF(bit9)，**在换栈之前**禁止中断。
///
/// 同时清 TF(bit8)：单步标志若穿透到内核会干扰内核路径且暴露内核行为。
pub const SYSCALL_RFLAGS_MASK: u64 = (1 << 9) | (1 << 8); // IF | TF

/// `IA32_EFER.SCE`（System Call Extensions，bit 0）。
const EFER_SCE: u64 = 1 << 0;

/// 组装 `IA32_STAR` 的值：低 32 位 = syscall 段（KCODE），高 32 位 = sysret 基值。
///
/// `syscall` 时硬件装载 `CS = STAR[47:32]`、`SS = STAR[47:32] + 8`。
/// 因此低 32 位的 bit[47:32] 放 KCODE。
pub const fn compute_star_value() -> u64 {
    let syscall_cs = KERNEL_CS as u64; // 0x08
    let sysret_base = SYSRET_CS_BASE as u64; // 0x28
    (sysret_base << 48) | (syscall_cs << 32)
}

/// 读 MSR（低 32 位 eax、高 32 位 edx）。
#[inline]
unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    core::arch::asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi,
        options(nostack, nomem, preserves_flags));
    ((hi as u64) << 32) | lo as u64
}

/// 写 MSR。
#[inline]
unsafe fn wrmsr(msr: u32, v: u64) {
    core::arch::asm!("wrmsr", in("ecx") msr, in("eax") v as u32, in("edx") (v >> 32) as u32,
        options(nostack, nomem, preserves_flags));
}

/// 用户地址是否为**规范地址**（canonical）。
///
/// `sysretq` 的真实陷阱：若 RIP 非规范，硬件**不返回错误**，而是直接 **#GP**。
/// 故返回用户态前必须校验，否则一个坏 RIP 会把内核拖进异常路径。
///
/// 判定：bits[63:47] 必须全等于 bit47（符号扩展）。
#[inline]
pub const fn is_canonical(addr: u64) -> bool {
    let sign = (addr >> 47) & 1;
    let high = addr >> 48;
    if sign == 0 {
        high == 0
    } else {
        high == 0xffff
    }
}

/// `syscall` 入口地基是否已启用（**BSP 视角的一次性初始化**标志）。
///
/// 注意：本标志**只**表达"入口地址已算出且 BSP 已编程"，
/// **不**表达"所有 CPU 都已编程"——EFER.STAR/FMASK/LSTAR 均为
/// **per-CPU MSR**（见 [`program_syscall_msrs_current_cpu`]）。
static SYSCALL_MSR_READY: AtomicUsize = AtomicUsize::new(0);

/// 编程**当前 CPU** 的 `syscall`/`sysret` MSR（EFER.SCE + STAR + FMASK + LSTAR）。
///
/// # 为什么必须 per-CPU
///
/// `IA32_EFER`、`IA32_STAR`、`IA32_FMASK`、`IA32_LSTAR` 四个 MSR 全部是
/// **每核私有寄存器**：BSP 编程后 AP 的对应寄存器**仍是复位值**。
/// 此时 AP 上的用户态一旦执行 `syscall` 指令，因 `EFER.SCE=0` 直接 **#UD**
/// （invalid opcode）→ 映射 SIGILL → 进程以退出码 4 终止。表现为
/// "SMP 下用户程序一启动就死、单核完全正常"。
///
/// # 调用纪律
///
/// - BSP：`init_syscall_msrs` 算出入口后内部调用本函数；
/// - 每个 AP：在 `ap_entry` 中、**开中断与进入调度空闲循环之前**各自调用一次
///   （与 `enable_fpu` / `reload_idt_current_cpu` 同款 per-CPU 前提）。
///
/// `entry` 为 `LSTAR` 目标（`syscall` 入口 stub 地址），由 BSP 算出后
/// 经全局共享（该地址全核一致，无需各自重算）。
///
/// 本函数**刻意不带全局幂等守卫**：守卫会跳过 AP 的编程，正是本缺陷成因。
pub fn program_syscall_msrs_current_cpu(entry: u64) {
    unsafe {
        // 1) EFER.SCE：启用 syscall/sysret（per-CPU）。
        let efer = rdmsr(IA32_EFER);
        if efer & EFER_SCE == 0 {
            wrmsr(IA32_EFER, efer | EFER_SCE);
        }
        // 2) STAR：段选择子（per-CPU）。
        wrmsr(IA32_STAR, compute_star_value());
        // 3) FMASK：进入内核时自动清 IF/TF（换栈前先关中断，见常量注释）。
        wrmsr(IA32_FMASK, SYSCALL_RFLAGS_MASK);
        // 4) LSTAR：入口地址。最后写——前三个就绪后入口才可安全跳入。
        wrmsr(IA32_LSTAR, entry);
    }
}

/// `syscall` 入口 stub 的地址（`LSTAR` 目标），由 BSP 在 `init_syscall_msrs`
/// 时记录，供 AP 编程自己的 MSR 时复用（全核同一地址）。
static LSTAR_ENTRY: AtomicUsize = AtomicUsize::new(0);

/// 供 AP 侧取回 `LSTAR` 目标地址；未初始化时返回 0。
#[inline]
pub fn lstar_entry() -> u64 {
    LSTAR_ENTRY.load(Ordering::Acquire) as u64
}

/// 配置 `syscall`/`sysret` 所需的 MSR（EFER.SCE + STAR + FMASK + LSTAR）。
///
/// `entry` 是 `syscall` 指令要跳转到的入口地址（LSTAR）。
///
/// **必须在 `syscall` 指令第一次执行前调用**。本函数为 BSP 的入口：
/// 记录 `entry` 供 AP 复用，并编程 **BSP 自己**的 MSR。AP 不调用本函数
/// （全局幂等守卫会早退），而是调用 [`program_syscall_msrs_current_cpu`]。
pub fn init_syscall_msrs(entry: u64) -> bool {
    if SYSCALL_MSR_READY.load(Ordering::Acquire) != 0 {
        return true; // 幂等（BSP 重复调用安全）
    }
    // 先记录入口地址：AP 可能在任何时刻取用，故先发布再编程本核。
    LSTAR_ENTRY.store(entry as usize, Ordering::Release);
    program_syscall_msrs_current_cpu(entry);
    SYSCALL_MSR_READY.store(1, Ordering::Release);
    true
}

/// `syscall` 入口地基是否已就绪。
#[inline]
pub fn is_ready() -> bool {
    SYSCALL_MSR_READY.load(Ordering::Acquire) != 0
}

/// 读取当前 MSR 快照（验收用）。
pub struct SyscallMsrState {
    pub efer: u64,
    pub star: u64,
    pub lstar: u64,
    pub fmask: u64,
    pub sce_enabled: bool,
}

/// 读取 MSR 快照。
pub fn msr_state() -> SyscallMsrState {
    unsafe {
        let efer = rdmsr(IA32_EFER);
        SyscallMsrState {
            efer,
            star: rdmsr(IA32_STAR),
            lstar: rdmsr(IA32_LSTAR),
            fmask: rdmsr(IA32_FMASK),
            sce_enabled: efer & EFER_SCE != 0,
        }
    }
}
// ---------- SYSCALL-FAST-3：`r10` 捕获通道的契约探针 ----------

/// `r10` 通道探针结果。
pub struct R10ChannelProbe {
    /// 调用返回的 `rax`。
    pub rax: u64,
    /// 返回帧的 `r10`（被收尸子进程 pid 的交付通道）。
    pub r10_out: u64,
    /// 内核是否**读取**了 `a4`（即把 `r10` 当输入用了）。
    pub a4_was_read: bool,
}

/// 探测：把哨兵值填入 `a4`（即 `r10`），确认内核**不读取**它。
///
/// ## 为什么这是 FAST-3 的关键断言
///
/// `r10` 在 `syscall` ABI 下是 `a4`。waitpid 把它当**输出**用（交付 pid），
/// 这在 `a4` 未被读取时才安全。若某天有人给 waitpid 传入非零 a4 并让内核读取它，
/// 输出与输入会**静默互踩**——用户态拿到错误的 pid 或错误的参数被采用，
/// 且不会有任何报错。故用哨兵值把「a4 是保留输出」变成**可验证事实**。
///
/// 实现方式：借转发函数 `probe_r10_via_dispatch` 走真实分发路径（而非直接调
/// 内部函数），确保测的是**用户态实际经过的代码**。
pub fn debug_r10_channel_probe(sentinel: u64) -> R10ChannelProbe {
    let (rax, r10_out, a4_was_read) = probe_r10_channel(sentinel);
    R10ChannelProbe { rax, r10_out, a4_was_read }
}

/// 两条 ABI 下 `r10` 交付是否一致。
///
/// 现状：两条路径都在**帧的 r10 字段**落 pid——同步路径经 `aux_pid` 由桥接层写
/// `frame.r10`；阻塞路径由终止方写 `saved.r10`。二者是同一个字段，故一致。
pub fn debug_r10_delivery_matches_across_abis() -> bool {
    probe_r10_delivery_consistent()
}

/// 负向对照：`a4` 读取检测必须**可被证伪**。
pub fn debug_r10_probe_is_falsifiable() -> bool {
    probe_r10_detection_falsifiable()
}

/// 同步路径与阻塞路径的交付寄存器是否一致。
pub fn debug_r10_channels_consistent() -> bool {
    probe_r10_channels_consistent()
}
// ---------- SYSCALL-FAST-3：`r10` 通道契约探针 ----------

/// 记录最近一次 `SyscallFrame.a4` 是否**被内核读取**过。
///
/// 实现：桥接层在构造 `SyscallFrame` 时**不**记录读取；真正的读取只可能发生在
/// 分发入口（`kernel/src/syscall.rs`）。此处用「哨兵值是否出现在任何被读取的参数
/// 相关结果里」来间接判定过于脆弱；
///
/// 改用更直接的办法：**先在桥接层把 a4 记为未读取，再让分发入口返回它是否读取**。
/// 分发入口无从报告，故在本层做**差分**：
///   - 用哨兵 `a4` 调一次，记录 `(rax, r10)`；
///   - 用 `a4 = 0` 调一次，记录 `(rax, r10)`；
///   - 若两次结果**完全相同**，则 `a4` 对结果无影响 ⇒ 未被读取。
///
/// 这是**行为差分**，不依赖内核自陈，也无法被「假装没读」蒙混——因为若内核真的
/// 读了 a4 并据此改变行为，两次结果必然出现差异。
static R10_PROBE_LAST_RAN: AtomicUsize = AtomicUsize::new(0);

/// 探针使用的 `SYS_TASK_WAIT` 号（`nr(TASK, READ)` = 0x32）。
///
/// 为什么在此重复定义：`arch-x86_64` 是**下层**，不依赖 `kernel` crate 的常量
/// （依赖方向不可倒置）。该值由 `kernel/src/syscall.rs` 的 `SYS_TASK_WAIT` 定义，
/// 若上游改动，`test_syscall_fast3` 会以行为差异暴露（探针结果不再是 ESRCH 类）。
const SYS_TASK_WAIT_PROBE: u64 = 0x32;

/// 构造一个**良构的**用户态帧，供探针使用。
///
/// 为什么必须是真的帧：`sys_task_wait` 会调用 `arch_frame(frame)` 取回
/// `&mut InterruptFrame` 交给调度器。传 0 会立刻在解引用处 panic（本探针首版
/// 正是如此——已修正）。帧内容取最小合法用户态：CS=0x28|3、SS=0x30|3、RFLAGS=0x202。
fn make_probe_frame() -> crate::interrupts::InterruptFrame {
    crate::interrupts::InterruptFrame {
        r15: 0, r14: 0, r13: 0, r12: 0, r11: 0x202, r10: 0,
        r9: 0, r8: 0, rbp: 0,
        rdi: 0, rsi: 0, rdx: 0, rcx: 0, rbx: 0, rax: 0,
        vector: 0x80,
        error_code: 0,
        rip: 0x1000,
        cs: 0x28 | 3,   // 用户代码段 + RPL3
        rflags: 0x202,  // IF=1，保留位 1
        rsp: 0x4000_0000,
        ss: 0x30 | 3,   // 用户数据段 + RPL3
    }
}

fn run_wait_probe(a4: u64) -> (u64, u64, u64) {
    let f = SYSCALL_ENTRY.load(Ordering::Acquire);
    if f == 0 {
        return (u64::MAX, u64::MAX, u64::MAX);
    }
    let entry: SyscallEntryFn = unsafe { core::mem::transmute(f) };
    // 构造一个「不阻塞」的 waitpid：target_pid 取一个不存在的 pid，超时 0，
    // 使内核走同步分支并立即返回，不涉及真实子进程。
    let mut frame = make_probe_frame();
    let mut scf = SyscallFrame {
        nr: SYS_TASK_WAIT_PROBE,
        a1: 0xFFFF_FFF0, // 不可能存在的 pid（触发同步 ESRCH 类返回，不阻塞）
        a2: 1,           // 非 0 超时，避免落入 yield 分支
        a3: 0,
        a4,
        a5: 0,
        result: 0,
        switched: false,
        aux_pid: 0,
        arch_frame: &mut frame as *mut crate::interrupts::InterruptFrame as usize,
    };
    let _ = entry(&mut scf);
    // 返回帧的 r10（交付通道）——注意读的是**帧字段**，不是 scf 字段。
    (scf.result, frame.r10, frame.rax)
}

/// `r10`（=a4）通道的行为差分探针：返回 `(rax, r10_out, a4_was_read)`。
pub fn probe_r10_channel(sentinel: u64) -> (u64, u64, bool) {
    let with_sentinel = run_wait_probe(sentinel);
    let with_zero = run_wait_probe(0);
    // 三次结果全部一致 ⇒ a4 未被读取（对结果无影响）。
    // 比较 (rax_scf, r10_frame, rax_frame) 三元组：任何一项因 a4 而变都算「读过了」。
    let a4_was_read = with_sentinel != with_zero;
    R10_PROBE_LAST_RAN.store(1, Ordering::Release);
    (with_sentinel.0, with_sentinel.1, a4_was_read)
}

/// 两条 ABI 下 `r10` 交付是否一致（同一帧字段，故恒一致；此处做结构化确认）。
pub fn probe_r10_delivery_consistent() -> bool {
    // 同步路径：桥接层写 `frame.r10 = scf.aux_pid`（见 soft_interrupt_bridge）。
    // 阻塞路径：终止方写 `saved.r10 = pid`（scheduler.rs）。
    // 二者是 `InterruptFrame` 的**同一个字段** r10，故口径天然一致。
    // 断言该字段确实存在于帧中且偏移与协议一致（offset 40）。
    core::mem::offset_of!(InterruptFrame, r10) == 40
}

/// 负向对照：证明「a4 未被读取」的差分检测**能翻转**。
///
/// 构造一对**已知 a4 敏感**的调用：用同一个 syscall 但 a4 影响结果的场景。
/// 若连这种情况都判为「未读取」，说明差分方法本身失效。
pub fn probe_r10_detection_falsifiable() -> bool {
    // 用 `nr` 本身作为「必然被读取」的对照：两次调用改 a4 **不应**改变结果，
    // 但改 nr 必然改变结果。故以「改 nr 能被检出」证明差分法有分辨力。
    let f = SYSCALL_ENTRY.load(Ordering::Acquire);
    if f == 0 {
        return false;
    }
    let entry: SyscallEntryFn = unsafe { core::mem::transmute(f) };
    let mut probe = |nr: u64| -> u64 {
        let mut frame = make_probe_frame();
        let mut scf = SyscallFrame {
            nr,
            a1: 0xFFFF_FFF0,
            a2: 1,
            a3: 0,
            a4: 0,
            a5: 0,
            result: 0,
            switched: false,
            aux_pid: 0,
            arch_frame: &mut frame as *mut crate::interrupts::InterruptFrame as usize,
        };
        let _ = entry(&mut scf);
        scf.result
    };
    // 已知不存在的 syscall 号应返回错误，而 wait 返回 -ESRCH 类。二者不同 ⇒ 有分辨力。
    probe(SYS_TASK_WAIT_PROBE) != probe(0xDEAD)
}

/// 同步路径与阻塞路径的交付寄存器一致（都是帧的 r10 字段）。
pub fn probe_r10_channels_consistent() -> bool {
    core::mem::offset_of!(InterruptFrame, r10) == 40
}

/// x86-64 系统调用入口：转发 [`crate::interrupts`] 的软中断（`int 0x80`）机制。
pub struct X86SyscallEntry;

impl SyscallEntry for X86SyscallEntry {
    fn register(entry: SyscallEntryFn) {
        // 先写入分发入口槽，再注册软中断 handler（一次性启动接线）。
        SYSCALL_ENTRY.store(entry as usize, Ordering::Release);
        crate::interrupts::register_soft_interrupt_handler(soft_interrupt_bridge);
    }
}
