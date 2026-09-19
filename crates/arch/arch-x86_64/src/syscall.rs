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

/// `syscall` 入口地基是否已启用。
static SYSCALL_MSR_READY: AtomicUsize = AtomicUsize::new(0);

/// 配置 `syscall`/`sysret` 所需的 MSR（EFER.SCE + STAR + FMASK + LSTAR）。
///
/// `entry` 是 `syscall` 指令要跳转到的入口地址（LSTAR）。
///
/// **必须在 `syscall` 指令第一次执行前调用**，且只能调用一次（幂等保护）。
pub fn init_syscall_msrs(entry: u64) -> bool {
    if SYSCALL_MSR_READY.load(Ordering::Acquire) != 0 {
        return true; // 幂等
    }
    unsafe {
        // 1) EFER.SCE：启用 syscall/sysret。
        let efer = rdmsr(IA32_EFER);
        if efer & EFER_SCE == 0 {
            wrmsr(IA32_EFER, efer | EFER_SCE);
        }
        // 2) STAR：段选择子。
        wrmsr(IA32_STAR, compute_star_value());
        // 3) FMASK：进入内核时自动清 IF/TF（换栈前先关中断，见常量注释）。
        wrmsr(IA32_FMASK, SYSCALL_RFLAGS_MASK);
        // 4) LSTAR：入口地址。最后写——前三个就绪后入口才可安全跳入。
        wrmsr(IA32_LSTAR, entry);
    }
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
/// x86-64 系统调用入口：转发 [`crate::interrupts`] 的软中断（`int 0x80`）机制。
pub struct X86SyscallEntry;

impl SyscallEntry for X86SyscallEntry {
    fn register(entry: SyscallEntryFn) {
        // 先写入分发入口槽，再注册软中断 handler（一次性启动接线）。
        SYSCALL_ENTRY.store(entry as usize, Ordering::Release);
        crate::interrupts::register_soft_interrupt_handler(soft_interrupt_bridge);
    }
}
