//! 进程管理与调度系统（Task & Scheduler Subsystem，独立 Crate）。
//!
//! 包含：
//! - `process`：进程控制块（PCB/Process）、进程表与地址空间绑定；
//! - `scheduler`：多进程就绪队列、时间片轮转（Round-Robin）、阻塞与唤醒调度器；
//! - `signals`：POSIX / BORUIX 进程信号分发模型。

#![no_std]

extern crate alloc;

pub mod process;
pub mod sched_eevdf;
pub mod scheduler;
pub mod signal;
pub mod signal_set;
pub mod signals;

pub use process::{
    Caps, Groups, Process, ProcessIdentity, ProcessTable, TaskState, clear_current_proc,
    current_proc_mut, process_page_fault_handler, set_current_proc,
};
/// 测试夹具钩子仅在 `kernel-tests` 构建存在（与 `scheduler::test_hooks` 同门禁）。
#[cfg(feature = "kernel-tests")]
pub use scheduler::test_hooks::spawn_child_with_identity;
pub use scheduler::{
    SwitchOutcome, Waited, block_current, block_current_with, block_for_event,
    active_user_snapshots, exit_current, get_process_snapshot, init_pid, kill_pid,
    process_snapshots, ps_snapshot,
    set_init_pid, set_unit_fs_base, spawn, spawn_derived, spawn_thread_with,
    // S1-8 触发点 4：中断返回边界对「刚被切入的进程」投递待决信号
    // （修复「睡眠型前台子进程的 ^C 永久失效」，详见该函数文档）。
    deliver_pending_on_return,
    spawn_with_ppid, spawn_with_ppid_fds,
    start, tick,
    group_members, group_live_count, group_all_exited, is_group_leader,
    waitpid, waitpid_timeout, wake, wake_event, wake_event_timeout, wake_with_value,
    wake_waitpid_timeout, set_event_timeout_timer,
    clear_event_timeout_timer, clear_event_waiter_if, yield_now, set_distribute_across_cpus,
    block_for_irq, wake_irq_timeout,
    // A2：音频等待者（plan_audio_vfs.md 批次二）。
    block_for_audio, wake_audio, wake_audio_timeout, set_audio_timeout_timer,
    clear_audio_timeout_timer, clear_audio_waiter_if,
    // I-EVENTS 阶段 2：键盘事件记录等待者（ADR-047）。
    InputEventBlock, block_for_input_event, wake_input_event, clear_input_event_waiter_if,
    // I-EVENTS 阶段 3 P2（§6.15）：console 字节流等待者（第 4 个等待者，
    // 甲-a 架构的阻塞原语——consoled 写入唤醒 fd 0 读者）。
    ConsoleBlock, block_for_console, wake_console, clear_console_waiter_if,
};
#[cfg(feature = "kernel-tests")]
pub use scheduler::test_hooks;
pub use signal::{
    DefaultAction, DeliveryOutcome, SigDisposition, SigInfo, SignalFrame, SignalState,
    SIGNAL_FRAME_MAGIC, MAX_SIGNAL_NESTING, default_disposition, deliver_on_return,
    is_hard_signal, sigreturn, validate_disposition,
};
pub use signal_set::{NSIG, SignalSet};
pub use signals::{
    SIGALRM, SIGBUS, SIGCHLD, SIGCONT, SIGFPE, SIGILL, SIGINT, SIGKILL, SIGPIPE, SIGSEGV,
    SIGSTOP, SIGTERM, SIGUSR1, SIGUSR2, signal_for_exception, signal_name,
};
