//! x86-64 定时器/时钟实现（ADR-007 的 `arch::Timer`）。
//!
//! 转发到 `klib::time`（时钟源注入 + 定时器队列核心）。时钟源由
//! [`crate::lapic::init`] 注入（LAPIC 100Hz 周期定时器 tick），
//! 软件定时器队列由 LAPIC tick 中断调用 [`klib::time::poll_timeouts`] 驱动。

use arch::timer::{Timer, TimerCallback};

/// x86-64 定时器：LAPIC 周期定时器作为硬件时钟源 + klib 软件定时器队列。
pub struct X8664Timer;

impl Timer for X8664Timer {
    fn now_nanos() -> Option<u64> {
        klib::time::now_nanos()
    }

    fn now_micros() -> Option<u64> {
        klib::time::now_micros()
    }

    fn now_millis() -> Option<u64> {
        klib::time::now_millis()
    }

    fn sleep_us(us: u64) {
        klib::time::sleep_us(us);
    }

    fn set_timeout(delay_ns: u64, callback: TimerCallback, arg: usize) -> Option<u64> {
        klib::time::set_timeout(delay_ns, callback, arg)
    }

    fn poll_timeouts() {
        klib::time::poll_timeouts();
    }
}
