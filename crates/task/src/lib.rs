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
pub mod signals;

pub use process::{
    Process, ProcessTable, TaskState, clear_current_proc, current_proc_mut,
    process_page_fault_handler, set_current_proc,
};
pub use scheduler::{
    SwitchOutcome, Waited, block_current, block_current_with, block_for_event, block_for_kbd,
    exit_current, get_process_snapshot, init_pid, kill_pid, process_snapshots, ps_snapshot,
    set_init_pid, spawn, spawn_with_ppid, spawn_with_ppid_fds, start, tick, waitpid, wake, wake_event,
    wake_event_timeout, wake_kbd, set_event_timeout_timer, clear_event_timeout_timer,
    clear_event_waiter_if, yield_now,
};
#[cfg(feature = "kernel-tests")]
pub use scheduler::test_hooks;
pub use signals::{
    SIGBUS, SIGFPE, SIGILL, SIGKILL, SIGSEGV, SIGTERM, signal_for_exception, signal_name,
};
