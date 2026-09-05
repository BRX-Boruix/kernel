//! 进程管理与调度系统（Task & Scheduler Subsystem，独立 Crate）。
//!
//! 包含：
//! - `process`：进程控制块（PCB/Process）、进程表与地址空间绑定；
//! - `scheduler`：多进程就绪队列、时间片轮转（Round-Robin）、阻塞与唤醒调度器；
//! - `signals`：POSIX / BORUIX 进程信号分发模型。

#![no_std]

extern crate alloc;

pub mod process;
pub mod scheduler;
pub mod signal;
pub mod signal_set;
pub mod signals;

pub use process::{
    Privilege, Process, ProcessIdentity, ProcessTable, TaskState, clear_current_proc,
    current_proc_mut, process_page_fault_handler, set_current_proc,
};
pub use scheduler::{
    SwitchOutcome, Waited, block_current, block_current_with, block_for_event, block_for_kbd,
    exit_current, get_process_snapshot, init_pid, kill_pid, process_snapshots, ps_snapshot,
    set_init_pid, spawn, spawn_thread_with, spawn_with_ppid, spawn_with_ppid_fds, start, tick,
    waitpid, wake, wake_event, wake_event_timeout, wake_kbd, wake_with_value, set_event_timeout_timer,
    clear_event_timeout_timer, clear_event_waiter_if, yield_now, set_distribute_across_cpus,
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
