//! 每进程信号处置——ADR-034 §2.2。
//!
//! 承载每信号的处置（`SigDisposition`）与"默认处置查表"（`default_disposition`）。
//! - `SigDisposition`：Default / Ignore / Handler(fn)。`SIGKILL`/`SIGSTOP`
//!   处置**恒为 Default**（`sigaction` 拒绝对其设 handler/ignore，映射 klib
//!   `InvalidParam`）。
//! - `default_disposition(sig)`：Default 处置落到哪个默认动作（Terminate /
//!   Ignore / Stop / Cont），查表。
//!
//! 本模块只承载处置类型与默认表；信号集位图见 [`crate::signal_set`]，
//! 信号号常量见 [`crate::signals`]。
//!
//! 本模块为纯逻辑（无内核硬件依赖），其数学正确性由 kernel crate 的
//! `test_signal_foundation`（kernel-tests，QEMU 实机）覆盖——任务 crate
//! 因依赖含 x86_64 内联汇编的 arch-x86_64 无法宿主 `cargo test`，故按
//! ADR-033 先例把纯逻辑验收放到 QEMU kernel-tests（S06：不留宿主导向的
//! `#[cfg(test)]` 死代码）。

use crate::signals::{SIGCHLD, SIGCONT, SIGKILL, SIGSTOP};

/// 一个信号的处置方式（ADR-034 §2.2）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigDisposition {
    /// 默认处置（终止/忽略/停止/继续，查 [`default_disposition`]）。
    Default,
    /// 忽略该信号。
    Ignore,
    /// 用户态 handler 函数指针。
    Handler(u64),
}

/// "Default" 处置对应的默认动作（ADR-034 §2.2）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefaultAction {
    /// 终止进程。
    Terminate,
    /// 忽略（不投递、不动作）。
    Ignore,
    /// 暂停进程（SIGSTOP，首期以 NotSupported 诚实拒绝，§4.4）。
    Stop,
    /// 恢复暂停的进程（SIGCONT）。
    Cont,
}

/// 默认处置查表：`sig` 的 Default 动作。
///
/// 取值对齐 POSIX 默认语义（signal(7)）与 ADR-034 §2.2。未知信号号（`>= NSIG`
/// 或未列举）如实返回 Terminate（兜底终止，S09 不伪造）。
pub const fn default_disposition(sig: u32) -> DefaultAction {
    match sig {
        SIGCHLD => DefaultAction::Ignore,
        SIGCONT => DefaultAction::Cont,
        SIGSTOP => DefaultAction::Stop,
        // 其余（含 SIGKILL/SIGINT/SIGILL/SIGBUS/SIGFPE/SIGUSR1/SIGSEGV/
        // SIGUSR2/SIGPIPE/SIGALRM/SIGTERM 及未知号）默认终止。
        _ => DefaultAction::Terminate,
    }
}

/// 该信号是否"硬信号"（处置恒 Default、不可设 handler/ignore）。
///
/// 目前为 `SIGKILL` 与 `SIGSTOP`（ADR-034 §2.2/§2.6）。
pub const fn is_hard_signal(sig: u32) -> bool {
    sig == SIGKILL || sig == SIGSTOP
}

/// 校验 `sigaction` 设置的处置：硬信号不可设 Handler/Ignore（恒 Default），
/// 越界信号号拒绝。
///
/// - `sig >= NSIG`：越界信号号（`OutOfRange`，ERANGE）——不允许对其设处置
///   （与 `default_disposition`/`SignalSet::of` 对越界的处理不同：处置设置是
///   真实的状态写入，越界必须如实拒绝而非静默忽略，S09）；
/// - 硬信号（SIGKILL/SIGSTOP）设 Handler/Ignore：`InvalidParam`（EINVAL，ADR-034 §2.2）；
/// - 否则 `Ok(())`。
pub fn validate_disposition(sig: u32, disp: SigDisposition) -> Result<(), klib::error::Error> {
    use crate::signal_set::NSIG;
    if sig >= NSIG {
        return Err(klib::error::Error::OutOfRange);
    }
    if is_hard_signal(sig) && !matches!(disp, SigDisposition::Default) {
        return Err(klib::error::Error::InvalidParam);
    }
    Ok(())
}
