//! 定时器/时钟架构抽象（ADR-007）。
//!
//! 通用内核代码只依赖本 trait，由各具体架构实现：
//! - `now_nanos`：单调时钟（自时钟启动以来的纳秒数）；
//! - `sleep_us`：忙等/挂起当前执行；
//! - `set_timeout`：注册一次性软件定时器（`delay_ns` 后调用回调）；
//! - `poll_timeouts`：驱动软件定时器队列（由硬件 tick 中断周期调用）。
//!
//! 具体架构实现（如 `arch-x86_64` 的 LAPIC 定时器）通常把本 trait
//! 转发给 `klib::time`（时钟源注入 + 定时器队列核心），trait 本身
//! 保证"业务代码一套、多架构可移植"。

/// 定时器回调：`fn(arg: usize)`（`'static`，由注册方保证生命周期）。
pub type TimerCallback = fn(arg: usize);

/// 定时器/时钟抽象接口（全静态方法，风格与 [`crate::Platform`] 一致）。
pub trait Timer {
    /// 当前单调时间（自时钟启动以来的纳秒数）。时钟未就绪时返回 0。
    fn now_nanos() -> u64;

    /// 当前单调时间（微秒）。
    fn now_micros() -> u64 {
        Self::now_nanos() / 1_000
    }

    /// 当前单调时间（毫秒）。
    fn now_millis() -> u64 {
        Self::now_nanos() / 1_000_000
    }

    /// 睡眠 `us` 微秒（时钟未就绪时立即返回）。
    fn sleep_us(us: u64);

    /// 注册一次性定时器：`delay_ns` 纳秒后调用 `callback(arg)`。
    /// 返回定时器 id；表满或时钟未就绪时返回 `None`。
    fn set_timeout(delay_ns: u64, callback: TimerCallback, arg: usize) -> Option<u64>;

    /// 驱动软件定时器队列（硬件 tick 中断里调用）。到期回调在锁外执行。
    fn poll_timeouts();
}
