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
    block_current, block_for_kbd, exit_current, get_process_snapshot, kill_pid, process_snapshots,
    ps_snapshot, spawn, start, tick, wake, wake_kbd, yield_now,
};
pub use signals::{SIGBUS, SIGFPE, SIGILL, SIGSEGV, SIGTERM, signal_for_exception, signal_name};
