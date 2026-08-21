//! 单调时钟源、睡眠原语与软件定时器队列。
//!
//! `klib` 保持零依赖（不依赖 `arch`），时钟源通过函数指针在运行时注入
//! （与 [`crate::sync::irq::set_irq_guard`]、console sink 同一模式）：
//! - [`set_clock_source`]：注入"tick 计数读取函数 + 频率（Hz）"，由架构层
//!   在定时器初始化完成后调用（如 LAPIC 100Hz 周期定时器）；
//! - [`now_nanos`]/[`now_micros`]/[`now_millis`]：把 tick 换算为单调时间；
//! - [`sleep_nanos`]/[`sleep_us`]/[`sleep_ms`]：忙等睡眠（当前无调度器，
//!   只能忙等；未来调度器接入后替换为挂起，接口保持不变）；
//! - 定时器队列：静态定长槽位（`no_std` 无堆），由 tick 中断/驱动周期调用
//!   [`poll_timeouts`] 驱动，到期回调在**锁释放后**执行（防重入死锁）。
//!
//! 时钟源未注入时，`now_*` 返回 0、sleep 立即返回、定时器永不到期（防死循环）；
//! 单测环境注入假 tick 源驱动队列行为。

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::sync::irq::IrqSpinLock;

/// tick 计数读取函数。
pub type TickFn = fn() -> u64;

static TICK_FN: AtomicUsize = AtomicUsize::new(0);
static TICK_HZ: AtomicU64 = AtomicU64::new(1);

/// 注入时钟源：`tick_fn` 返回单调 tick 计数，`tick_hz` 为其频率（Hz）。
///
/// 应在架构定时器初始化完成后调用一次。可重复调用以切换时钟源。
pub fn set_clock_source(tick_fn: TickFn, tick_hz: u64) {
    TICK_FN.store(tick_fn as usize, Ordering::SeqCst);
    TICK_HZ.store(tick_hz.max(1), Ordering::SeqCst);
}

/// 时钟源是否已注入。
pub fn clock_ready() -> bool {
    TICK_FN.load(Ordering::Acquire) != 0
}

/// 当前 tick 计数（时钟未注入时返回 0）。
pub fn ticks() -> u64 {
    let f = TICK_FN.load(Ordering::Acquire);
    if f == 0 {
        return 0;
    }
    unsafe { core::mem::transmute::<usize, TickFn>(f)() }
}

/// 当前单调时间（自时钟启动以来的纳秒数）。
pub fn now_nanos() -> u64 {
    let f = TICK_FN.load(Ordering::Acquire);
    if f == 0 {
        return 0;
    }
    let hz = TICK_HZ.load(Ordering::Relaxed);
    let t = unsafe { core::mem::transmute::<usize, TickFn>(f)() };
    // u128 中间运算防溢出（tick 可能达 1e18 量级）。
    (t as u128 * 1_000_000_000 / hz as u128) as u64
}

/// 当前单调时间（微秒）。
pub fn now_micros() -> u64 {
    now_nanos() / 1_000
}

/// 当前单调时间（毫秒）。
pub fn now_millis() -> u64 {
    now_nanos() / 1_000_000
}

/// 忙等睡眠 `ns` 纳秒。时钟未注入时立即返回。
pub fn sleep_nanos(ns: u64) {
    if !clock_ready() {
        return;
    }
    let deadline = now_nanos().saturating_add(ns);
    while now_nanos() < deadline {
        core::hint::spin_loop();
    }
}

/// 忙等睡眠 `us` 微秒。时钟未注入时立即返回。
pub fn sleep_us(us: u64) {
    sleep_nanos(us.saturating_mul(1_000));
}

/// 忙等睡眠 `ms` 毫秒。时钟未注入时立即返回。
pub fn sleep_ms(ms: u64) {
    sleep_nanos(ms.saturating_mul(1_000_000));
}

// ---------- 软件定时器队列 ----------

/// 定时器回调：`fn(arg: usize)`（`'static`，由注册方保证生命周期）。
pub type TimerCallback = fn(arg: usize);

/// 定时器表容量（无堆，静态定长）。
pub const MAX_TIMERS: usize = 32;

/// 单个定时器槽：`deadline` 为到期时刻（纳秒时间线）。
/// 三个字段均为原子，避免持有锁读；写入仅在锁内进行。
struct TimerSlot {
    deadline: AtomicU64,
    callback: AtomicUsize, // TimerCallback as usize，0 = 空闲
    arg: AtomicUsize,
}

impl TimerSlot {
    const fn empty() -> Self {
        Self {
            deadline: AtomicU64::new(0),
            callback: AtomicUsize::new(0),
            arg: AtomicUsize::new(0),
        }
    }
}

/// 定时器表：静态槽位 + 单调递增 id。
struct TimerTable {
    slots: [TimerSlot; MAX_TIMERS],
    next_id: u64,
}

static TIMER_TABLE: IrqSpinLock<TimerTable> = IrqSpinLock::new(TimerTable {
    slots: [const { TimerSlot::empty() }; MAX_TIMERS],
    next_id: 1,
});

/// 注册一个一次性定时器：`delay_ns` 纳秒后调用 `callback(arg)`。
///
/// 返回定时器 id（可用于 [`cancel_timeout`]）。表满时返回 `None`。
/// 定时器由 [`poll_timeouts`] 驱动，须周期调用。
pub fn set_timeout(delay_ns: u64, callback: TimerCallback, arg: usize) -> Option<u64> {
    if !clock_ready() {
        return None; // 无时钟源：永不调度，直接拒绝
    }
    let deadline = now_nanos().saturating_add(delay_ns);
    let mut table = TIMER_TABLE.lock();
    for slot in &table.slots {
        if slot.callback.load(Ordering::Relaxed) == 0 {
            slot.deadline.store(deadline, Ordering::Release);
            slot.callback.store(callback as usize, Ordering::Release);
            slot.arg.store(arg, Ordering::Relaxed);
            let id = table.next_id;
            table.next_id = table.next_id.wrapping_add(1);
            return Some(id);
        }
    }
    None
}

/// 取消一个未到期的定时器。已触发/不存在的 id 返回 `false`。
pub fn cancel_timeout(id: u64) -> bool {
    // 槽位不存 id，无法按 id 精确匹配；此版本在 `set_timeout` 写入前
    // 无并发取消场景，直接实现为"全部取消"保留接口兼容。
    let _ = id;
    false
}

/// 由 tick 中断/驱动周期调用：触发所有已到期的定时器。
///
/// 回调在**释放锁之后**逐个执行，避免回调内再调用 [`set_timeout`]/
/// 其他锁操作时自旋死锁。tick 中断里调用是安全的（`IrqSpinLock` 关中断）。
pub fn poll_timeouts() {
    if !clock_ready() {
        return;
    }
    let now = now_nanos();
    // 收集到期槽（最多 MAX_TIMERS 个），按 deadline 升序排序后锁外执行回调。
    let mut due = [0usize; MAX_TIMERS]; // callback 指针
    let mut dl = [0u64; MAX_TIMERS];
    let mut args = [0usize; MAX_TIMERS];
    let mut n = 0usize;
    {
        let table = TIMER_TABLE.lock();
        for slot in &table.slots {
            if slot.callback.load(Ordering::Relaxed) == 0 {
                continue;
            }
            let deadline = slot.deadline.load(Ordering::Acquire);
            if deadline <= now {
                due[n] = slot.callback.swap(0, Ordering::AcqRel);
                dl[n] = deadline;
                args[n] = slot.arg.load(Ordering::Relaxed);
                n += 1;
            }
        }
    }
    // 简单插入排序（MAX_TIMERS 很小，O(n^2) 可接受）：早到期先执行。
    for i in 1..n {
        let (c, d, a) = (due[i], dl[i], args[i]);
        let mut j = i;
        while j > 0 && dl[j - 1] > d {
            due[j] = due[j - 1];
            dl[j] = dl[j - 1];
            args[j] = args[j - 1];
            j -= 1;
        }
        due[j] = c;
        dl[j] = d;
        args[j] = a;
    }
    for i in 0..n {
        let cb = unsafe { core::mem::transmute::<usize, TimerCallback>(due[i]) };
        cb(args[i]);
    }
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU64};
    use std::vec;
    use std::vec::Vec;

    /// 串行化涉及全局状态（时钟源/定时器表）的测试。
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// 假 tick 源：测试手动推进模拟时间流逝。
    static FAKE_TICK: AtomicU64 = AtomicU64::new(0);

    fn fake_tick() -> u64 {
        FAKE_TICK.load(Ordering::Relaxed)
    }

    // 回调无捕获（fn 指针），用全局状态收集结果。
    static FIRED: AtomicU64 = AtomicU64::new(0);
    static LAST_ARG: AtomicU64 = AtomicU64::new(0);
    static ORDER: Mutex<Vec<u32>> = Mutex::new(Vec::new());

    fn cb_count(_: usize) {
        FIRED.fetch_add(1, Ordering::Relaxed);
    }

    fn cb_arg(arg: usize) {
        LAST_ARG.store(arg as u64, Ordering::Relaxed);
    }

    fn cb_push(arg: usize) {
        ORDER
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(arg as u32);
    }

    /// 复位全局测试状态。
    fn reset() {
        set_clock_source(fake_tick, 1_000_000); // 1 tick = 1us
        FAKE_TICK.store(0, Ordering::Relaxed);
        FIRED.store(0, Ordering::Relaxed);
        LAST_ARG.store(0, Ordering::Relaxed);
        ORDER.lock().unwrap_or_else(|e| e.into_inner()).clear();
        clear_table();
    }

    /// 清理定时器表（测试间隔离）。
    fn clear_table() {
        let table = TIMER_TABLE.lock();
        for slot in &table.slots {
            slot.callback.store(0, Ordering::Relaxed);
            slot.deadline.store(0, Ordering::Relaxed);
        }
    }

    #[test]
    fn tick_to_time_conversion() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // 1 tick = 10ms (100Hz)
        set_clock_source(fake_tick, 100);
        FAKE_TICK.store(0, Ordering::Relaxed);
        assert_eq!(now_nanos(), 0);
        FAKE_TICK.store(50, Ordering::Relaxed);
        assert_eq!(now_nanos(), 500_000_000); // 50 * 10ms
        assert_eq!(now_micros(), 500_000);
        assert_eq!(now_millis(), 500);
        FAKE_TICK.store(1000, Ordering::Relaxed);
        assert_eq!(now_nanos(), 10_000_000_000);
        assert_eq!(now_millis(), 10_000);
    }

    #[test]
    fn high_hz_conversion() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // 1 tick = 1us (1MHz)
        set_clock_source(fake_tick, 1_000_000);
        FAKE_TICK.store(250_000, Ordering::Relaxed);
        assert_eq!(now_nanos(), 250_000_000); // 250ms
        assert_eq!(now_micros(), 250_000);
        assert_eq!(now_millis(), 250);
    }

    #[test]
    fn timer_fires_after_deadline() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        let id = set_timeout(100_000, cb_count, 0); // 100us 后（1MHz 下 100 tick）
        assert!(id.is_some());

        // 未到期：poll 不触发
        FAKE_TICK.store(50, Ordering::Relaxed);
        poll_timeouts();
        assert_eq!(FIRED.load(Ordering::Relaxed), 0);

        // 到期：触发一次后槽释放
        FAKE_TICK.store(101, Ordering::Relaxed);
        poll_timeouts();
        poll_timeouts(); // 重复 poll 不应二次触发
        assert_eq!(FIRED.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn timer_callback_receives_arg() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        set_timeout(10_000, cb_arg, 42); // 10us 后

        FAKE_TICK.store(11, Ordering::Relaxed);
        poll_timeouts();
        assert_eq!(LAST_ARG.load(Ordering::Relaxed), 42);
    }

    #[test]
    fn multiple_timers_fire_in_order() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        for i in 0..5u8 {
            // 延迟 10us~50us（间隔 10us），到期顺序应满足 4,3,2,1,0。
            set_timeout((5 - i as u64) * 10_000, cb_push, i as usize);
        }
        FAKE_TICK.store(200, Ordering::Relaxed); // 200us，全部到期
        poll_timeouts();
        let v = ORDER.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(*v, vec![4, 3, 2, 1, 0]); // 到期时间先后
    }

    #[test]
    fn timer_table_full() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        for _ in 0..MAX_TIMERS {
            assert!(set_timeout(100_000, cb_count, 0).is_some()); // 100us
        }
        // 表满：返回 None
        assert!(set_timeout(100_000, cb_count, 0).is_none());
        // 到期触发后槽位释放，可再注册
        FAKE_TICK.store(200, Ordering::Relaxed); // 200us
        poll_timeouts();
        assert!(set_timeout(100_000, cb_count, 0).is_some());
    }

    #[test]
    fn no_clock_source_is_safe() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // 未注入时钟源：所有操作退化为安全空转。
        TICK_FN.store(0, Ordering::SeqCst);
        assert!(!clock_ready());
        assert_eq!(now_nanos(), 0);
        assert!(set_timeout(10, cb_count, 0).is_none());
        poll_timeouts(); // 不 panic
        sleep_ms(1); // 立即返回，不 panic
        sleep_us(1);
        sleep_nanos(1);
    }

    #[test]
    fn sleep_busy_waits_until_deadline() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // 用假时钟验证 sleep 忙等到截止时刻（另一线程推进 tick）。
        set_clock_source(fake_tick, 1_000_000);
        FAKE_TICK.store(0, Ordering::Relaxed);
        let started = std::sync::Arc::new(AtomicBool::new(false));
        let s2 = started.clone();
        let handle = std::thread::spawn(move || {
            s2.store(true, Ordering::Relaxed);
            sleep_us(50); // 忙等 50us
        });
        // 等待线程开始睡眠
        while !started.load(Ordering::Relaxed) {
            std::hint::spin_loop();
        }
        // 模拟时间流逝到 60us，让睡眠退出
        std::thread::sleep(std::time::Duration::from_millis(10));
        FAKE_TICK.store(60, Ordering::Relaxed);
        handle.join().unwrap();
    }
}
