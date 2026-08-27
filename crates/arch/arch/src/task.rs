//! 任务上下文与上下文切换（平台无关抽象）。
//!
//! `TaskContext` 保存一次 `switch_to` 所需的 CPU 状态（架构相关布局）。
//! 架构 crate 提供 `switch_to` 的实际实现（汇编保存/恢复寄存器），
//! 通用代码通过 `switch_to` 函数在不同任务之间切换。
//!
//! 设计（ADR-007）：通用代码不依赖具体架构寄存器布局；
//! 架构 crate 负责填充/解释 `TaskContext` 的字节布局，并通过
//! `set_switch_to` 注入切换函数。

use core::sync::atomic::{AtomicUsize, Ordering};

/// 任务上下文：架构相关的 CPU 状态快照。
///
/// 布局由架构 crate 定义。为保持 `arch` 层不依赖具体架构，
/// 这里用一个固定大小的字节缓冲表示，由架构实现填充。
/// 当前大小容纳 x86_64 的上下文（16 个 u64：callee-saved 寄存器 +
/// 栈指针 + 恢复点，见 arch-x86_64/src/task.rs）。
pub struct TaskContext {
    buf: [u64; 16],
}

impl TaskContext {
    /// 创建一个零初始化的上下文（须由架构实现填充）。
    pub const fn empty() -> Self {
        Self { buf: [0; 16] }
    }

    /// 访问内部缓冲（供架构 crate 填充/读取）。
    pub fn as_buf_mut(&mut self) -> &mut [u64] {
        &mut self.buf
    }

    /// 访问内部缓冲（只读）。
    pub fn as_buf(&self) -> &[u64] {
        &self.buf
    }
}

/// 架构切换函数：`fn(prev: &mut TaskContext, next: &mut TaskContext)`。
/// 由架构 crate 在早期注入（汇编实现）。
type SwitchFn = extern "C" fn(&mut TaskContext, &mut TaskContext);
static SWITCH_FN: AtomicUsize = AtomicUsize::new(0);

/// 注入架构的上下文切换实现（架构 crate 在初始化时调用）。
///
/// S21 invariant：`f` 必须是合法 `SwitchFn`（汇编实现的 `extern "C"` 函数，
/// 且其契约要求 `prev`/`next` 为有效 `TaskContext`）、`'static`、由**单线程
/// BSP 启动阶段**一次性注入；此后在任意 CPU/中断上下文读取并 transmute 回
/// 调用。错误注入非 SwitchFn 指针或并发重复注入会产生悬垂调用，未定义行为。
pub fn set_switch_to(f: SwitchFn) {
    SWITCH_FN.store(f as usize, Ordering::SeqCst);
}

/// 进入用户态（Ring 3）所需的完整陷阱帧。
///
/// 含 `iretq` 弹出的全部字段（RIP/CS/RFLAGS/RSP/SS），外加进程用户页表基址 `cr3`。
/// 平台无关抽象（ADR-007）；架构 crate 负责用这些字段构造真实的 iretq 帧，
/// 并在 `iretq` 前装载 `cr3`（切到进程页表）。
///
/// - `rflags`：须含 `IF=1`（开中断）且 `IOPL=0`（禁 I/O 指令）。
/// - `cs`/`ss`：Ring 3 段选择子（如 x86_64 的 `UCODE`/`UDATA`）。
/// - `cr3`：用户进程页表物理基址（`PageTable::paddr()`）。非 0 时架构实现
///   在 `iretq` 前写 CR3；0 表示沿用当前页表（不切换）。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TrapFrame {
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
    /// 用户进程页表物理基址（CR3 值）；0 = 不切换页表。
    pub cr3: u64,
}

/// 进入用户态函数：`fn(&TrapFrame)`。由架构 crate 在早期注入（汇编实现）。
type EnterUserFn = extern "C" fn(&TrapFrame);
static ENTER_USER_FN: AtomicUsize = AtomicUsize::new(0);

/// 注入架构的"进入用户态"实现（架构 crate 在初始化时调用）。
pub fn set_enter_usermode(f: EnterUserFn) {
    ENTER_USER_FN.store(f as usize, Ordering::SeqCst);
}

/// 通过 `iretq` 进入用户态执行 `frame` 描述的程序。
///
/// 永不返回（用户态退出时通过中断/异常回到内核）。若未注入实现则 panic。
#[inline(never)]
pub fn enter_usermode(frame: &TrapFrame) -> ! {
    let f = ENTER_USER_FN.load(Ordering::SeqCst);
    if f == 0 {
        panic!("arch::enter_usermode not injected");
    }
    let f: EnterUserFn = unsafe { core::mem::transmute(f) };
    f(frame);
    unreachable!("enter_usermode returned")
}

/// 在两个任务上下文之间切换。
///
/// 保存当前 CPU 状态到 `prev`，恢复 `next` 的状态并继续执行。
/// 若未注入实现（未初始化）则 panic。
///
/// `#[inline(never)]`：保证稳定的调用栈帧（`x86_switch_to` 的裸汇编
/// 依赖 `[rsp]` 返回地址，内联会破坏该语义）。
///
/// S21 invariant：`SWITCH_FN` 值必须由 [`set_switch_to`] 注入的合法
/// `SwitchFn` 地址；`prev`/`next` 必须是有效的、已由架构上下文保存的
/// `TaskContext`（不可为悬垂/重复借用）。`unsafe` transmute 在此成立的前提
/// 是上述注入不变式（见 [`set_switch_to`]）。
#[inline(never)]
pub fn switch_to(prev: &mut TaskContext, next: &mut TaskContext) {
    let f = SWITCH_FN.load(Ordering::SeqCst);
    if f == 0 {
        panic!("arch::switch_to not injected");
    }
    let f: SwitchFn = unsafe { core::mem::transmute(f) };
    f(prev, next)
}
