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
        // 不透明句柄：切换路径由调度原语还原为 `&mut InterruptFrame`。
        arch_frame: frame as *mut InterruptFrame as usize,
    };

    let handled = entry(&mut scf);
    if handled && !scf.switched {
        // 正常完成：把结果写回调用进程 rax（Switched 时现场已换，不得回写）。
        frame.rax = scf.result;
    }
    handled
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
