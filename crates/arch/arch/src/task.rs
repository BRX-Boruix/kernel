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
/// 当前大小容纳 x86_64 的 callee-saved 寄存器集（15 个 u64）。
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
pub fn set_switch_to(f: SwitchFn) {
    SWITCH_FN.store(f as usize, Ordering::SeqCst);
}

/// 在两个任务上下文之间切换。
///
/// 保存当前 CPU 状态到 `prev`，恢复 `next` 的状态并继续执行。
/// 若未注入实现（未初始化）则 panic。
///
/// `#[inline(never)]`：保证稳定的调用栈帧（`x86_switch_to` 的裸汇编
/// 依赖 `[rsp]` 返回地址，内联会破坏该语义）。
#[inline(never)]
pub fn switch_to(prev: &mut TaskContext, next: &mut TaskContext) {
    let f = SWITCH_FN.load(Ordering::SeqCst);
    if f == 0 {
        panic!("arch::switch_to not injected");
    }
    let f: SwitchFn = unsafe { core::mem::transmute(f) };
    f(prev, next)
}
