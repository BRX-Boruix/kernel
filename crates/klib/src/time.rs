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

/// wall clock（真实纪元秒）读取函数。
///
/// 返回 Unix epoch 秒（1970-01-01T00:00:00Z 起的秒数）。与单调时钟正交——
/// 单调时钟回答"开机至今多久"，墙钟回答"现在是哪个真实时刻"。来源为
/// 架构层 RTC/CMOS（`arch_x86_64::rtc`）。注入机制与 `set_clock_source`
/// 同模式（函数指针运行时注入，保持 klib 零依赖）。
pub type WallFn = fn() -> Option<u64>;

static TICK_FN: AtomicUsize = AtomicUsize::new(0);
static TICK_HZ: AtomicU64 = AtomicU64::new(1);
static WALL_FN: AtomicUsize = AtomicUsize::new(0);

/// 注入时钟源：`tick_fn` 返回单调 tick 计数，`tick_hz` 为其频率（Hz）。
///
/// 应在架构定时器初始化完成后调用一次。可重复调用以切换时钟源。
///
/// S21 前提（成文）：TICK_FN→TICK_HZ 双 store 无发布同步；读者 Acquire 读 fn
/// 后 Relaxed 读 hz，切换时钟源期间理论上可读到"新 fn + 旧 hz"错配。前提是
/// **时钟源只在启动早期单线程阶段注入/切换一次**，此后 TICK_FN/TICK_HZ 不再
/// 被写，错配窗口不可达。多核热切换时钟源须引入版本号/同一原子双字段。
pub fn set_clock_source(tick_fn: TickFn, tick_hz: u64) {
    TICK_FN.store(tick_fn as usize, Ordering::SeqCst);
    TICK_HZ.store(tick_hz.max(1), Ordering::SeqCst);
}

/// 注入 wall clock 源：`wall_fn` 返回 Unix epoch 秒。
///
/// 应在架构层 RTC 初始化完成（能读到真实年月日时分秒）后调用一次。可重复
/// 调用以切换来源（如后续接入 NTP/网络时钟）。
pub fn set_wall_clock_source(wall_fn: WallFn) {
    WALL_FN.store(wall_fn as usize, Ordering::SeqCst);
}

/// 当前 wall clock（Unix epoch 秒）。未注入来源时返回 `None`。
///
/// **S09**：墙钟未就绪（[`set_wall_clock_source`] 未调用、或底层 RTC 不可
/// 读）返回 `None`——用 `Option` 显式表达"不可用"，绝不把 0（1970-01-01）
/// 伪装成"真实时间恰好是纪元起点"的哨兵值。
pub fn wall_clock_secs() -> Option<u64> {
    let f = WALL_FN.load(Ordering::Acquire);
    if f == 0 {
        return None;
    }
    unsafe { core::mem::transmute::<usize, WallFn>(f)() }
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
///
/// **S09**：时钟源未注入（[`clock_ready`] == false）时返回 `None`——用
/// `Option` 显式表达"未就绪"，而不是伪装成"真实时间恰好为 0"的哨兵值。
/// 内核在 LAPIC 定时器初始化（架构层 `lapic::init`）后注入时钟源，此路径
/// 在生产启动中仅在极早期可达；调用方应把 `None` 当作"时钟不可用"处理。
pub fn now_nanos() -> Option<u64> {
    let f = TICK_FN.load(Ordering::Acquire);
    if f == 0 {
        return None;
    }
    let hz = TICK_HZ.load(Ordering::Relaxed);
    let t = unsafe { core::mem::transmute::<usize, TickFn>(f)() };
    // u128 中间运算防乘法溢出（tick 可能达 1e18 量级）。
    // S19：最终 u128→u64 若超位宽（hz 极小且 tick 极大时商可超 u64）不应静默
    // 回绕，饱和到 u64::MAX 而非截断。真实 LAPIC 频率下不可达，但做饱和更诚实。
    let ns = (t as u128 * 1_000_000_000 / hz as u128) as u128;
    Some(if ns > u64::MAX as u128 { u64::MAX } else { ns as u64 })
}

/// 当前单调时间（微秒）。时钟未就绪返回 `None`。
pub fn now_micros() -> Option<u64> {
    now_nanos().map(|n| n / 1_000)
}

/// 当前单调时间（毫秒）。时钟未就绪返回 `None`。
pub fn now_millis() -> Option<u64> {
    now_nanos().map(|n| n / 1_000_000)
}

/// 忙等睡眠 `ns` 纳秒。时钟未注入时立即返回（防早期死循环）。
///
/// **S09**：未就绪即返回会把"未就绪"伪装成"睡眠已完成"。调用方必须
/// 保证时钟就绪（[`clock_ready`]）后才调用；本 no-op 仅作早期防死循环
/// 兜底，不作为正常睡眠语义。
pub fn sleep_nanos(ns: u64) {
    if !clock_ready() {
        return;
    }
    // clock_ready() 已保证注入时钟源，now_nanos() 必为 Some。
    let deadline = now_nanos().expect("clock_ready checked").saturating_add(ns);
    while now_nanos().expect("clock_ready checked") < deadline {
        core::hint::spin_loop();
    }
}

/// 忙等睡眠 `us` 微秒。时钟未注入时立即返回（防早期死循环）。
pub fn sleep_us(us: u64) {
    sleep_nanos(us.saturating_mul(1_000));
}

/// 忙等睡眠 `ms` 毫秒。时钟未注入时立即返回（防早期死循环）。
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
    /// 注册时分配的非零 identity；0 表示槽位空闲。
    id: AtomicU64,
    deadline: AtomicU64,
    callback: AtomicUsize, // TimerCallback as usize，0 = 空闲
    arg: AtomicUsize,
}

impl TimerSlot {
    const fn empty() -> Self {
        Self {
            id: AtomicU64::new(0),
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
#[must_use] // S18：忽略返回值会失去取消句柄。
pub fn set_timeout(delay_ns: u64, callback: TimerCallback, arg: usize) -> Option<u64> {
    if !clock_ready() {
        return None; // 无时钟源：永不调度，直接拒绝
    }
    // clock_ready() 已保证注入时钟源。
    let deadline = now_nanos().expect("clock_ready checked").saturating_add(delay_ns);
    let mut table = TIMER_TABLE.lock();
    let slot_index = table
        .slots
        .iter()
        .position(|slot| slot.callback.load(Ordering::Relaxed) == 0)?;

    // 0 始终表示“无 ID”；绕回时跳过它，确保 live ID 永不与空槽混淆。
    let id = table.next_id;
    table.next_id = table.next_id.wrapping_add(1);
    if table.next_id == 0 {
        table.next_id = 1;
    }

    let slot = &table.slots[slot_index];
    // 发布顺序：先完整初始化 payload，最后写 callback 作为槽位 live 标志。
    // 所有查看 live 槽位的路径均在 TIMER_TABLE 锁内，仍保留 Release 以
    // 明确 callback 的发布语义。
    slot.id.store(id, Ordering::Relaxed);
    slot.deadline.store(deadline, Ordering::Relaxed);
    slot.arg.store(arg, Ordering::Relaxed);
    slot.callback.store(callback as usize, Ordering::Release);
    Some(id)
}

/// 取消一个未到期的定时器。已触发/不存在的 id 返回 `false`。
///
/// 调用与 `poll_timeouts` 均持有同一把 IRQ-safe 锁，因此二者线性化：若取消先
/// 取得锁，回调绝不会进入锁外执行队列；若 poll 先取得锁并摘除槽位，则取消如实
/// 返回 false，回调会按既有语义执行。
pub fn cancel_timeout(id: u64) -> bool {
    if id == 0 {
        return false;
    }
    let table = TIMER_TABLE.lock();
    for slot in &table.slots {
        if slot.id.load(Ordering::Relaxed) == id && slot.callback.load(Ordering::Acquire) != 0 {
            // callback 是槽位的 live 标志；先清它使 poll 无法再认领，再清理余下
            // 元数据，确保该 id 永远不会在重用槽里再次匹配。
            slot.callback.store(0, Ordering::Release);
            slot.id.store(0, Ordering::Relaxed);
            slot.deadline.store(0, Ordering::Relaxed);
            slot.arg.store(0, Ordering::Relaxed);
            return true;
        }
    }
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
    // clock_ready() 已保证注入时钟源。
    let now = now_nanos().expect("clock_ready checked");
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
                // poll 已认领回调；该 ID 从此不再可取消，也不会与后续重用槽位
                // 的新定时器相混淆。
                slot.id.store(0, Ordering::Relaxed);
                slot.deadline.store(0, Ordering::Relaxed);
                slot.arg.store(0, Ordering::Relaxed);
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

    /// 假 wall 源：测试控制返回的 epoch 秒。
    static FAKE_EPOCH: AtomicU64 = AtomicU64::new(0);
    static FAKE_WALL_ENABLED: AtomicBool = AtomicBool::new(false);

    fn fake_wall() -> Option<u64> {
        if FAKE_WALL_ENABLED.load(Ordering::Relaxed) {
            Some(FAKE_EPOCH.load(Ordering::Relaxed))
        } else {
            None
        }
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
        // 隔离 wall clock 全局状态：默认关（未注入）。
        set_wall_clock_source(fake_wall);
        FAKE_WALL_ENABLED.store(false, Ordering::Relaxed);
        FAKE_EPOCH.store(0, Ordering::Relaxed);
        FIRED.store(0, Ordering::Relaxed);
        LAST_ARG.store(0, Ordering::Relaxed);
        ORDER.lock().unwrap_or_else(|e| e.into_inner()).clear();
        clear_table();
    }

    /// 清理定时器表（测试间隔离）。
    fn clear_table() {
        let table = TIMER_TABLE.lock();
        for slot in &table.slots {
            slot.id.store(0, Ordering::Relaxed);
            slot.callback.store(0, Ordering::Relaxed);
            slot.deadline.store(0, Ordering::Relaxed);
            slot.arg.store(0, Ordering::Relaxed);
        }
    }

    #[test]
    fn tick_to_time_conversion() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // 1 tick = 10ms (100Hz)
        set_clock_source(fake_tick, 100);
        FAKE_TICK.store(0, Ordering::Relaxed);
        assert_eq!(now_nanos(), Some(0));
        FAKE_TICK.store(50, Ordering::Relaxed);
        assert_eq!(now_nanos(), Some(500_000_000)); // 50 * 10ms
        assert_eq!(now_micros(), Some(500_000));
        assert_eq!(now_millis(), Some(500));
        FAKE_TICK.store(1000, Ordering::Relaxed);
        assert_eq!(now_nanos(), Some(10_000_000_000));
        assert_eq!(now_millis(), Some(10_000));
    }

    #[test]
    fn high_hz_conversion() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // 1 tick = 1us (1MHz)
        set_clock_source(fake_tick, 1_000_000);
        FAKE_TICK.store(250_000, Ordering::Relaxed);
        assert_eq!(now_nanos(), Some(250_000_000)); // 250ms
        assert_eq!(now_micros(), Some(250_000));
        assert_eq!(now_millis(), Some(250));
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
        let _ = set_timeout(10_000, cb_arg, 42); // 10us 后

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
            let _ = set_timeout((5 - i as u64) * 10_000, cb_push, i as usize);
        }
        FAKE_TICK.store(200, Ordering::Relaxed); // 200us，全部到期
        poll_timeouts();
        let v = ORDER.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(*v, vec![4, 3, 2, 1, 0]); // 到期时间先后
    }

    #[test]
    fn cancel_timeout_removes_only_its_exact_timer() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();

        let first = set_timeout(10_000, cb_push, 1).expect("first timer id");
        let middle = set_timeout(20_000, cb_push, 2).expect("middle timer id");
        let last = set_timeout(30_000, cb_push, 3).expect("last timer id");
        assert_ne!(first, 0, "timer id zero is reserved as no-id");
        assert_ne!(first, middle, "live timers need distinct ids");
        assert_ne!(middle, last, "live timers need distinct ids");

        assert!(cancel_timeout(middle), "cancel must find the requested id");
        assert!(
            !cancel_timeout(middle),
            "repeated cancellation must truthfully report no live timer"
        );
        assert!(
            !cancel_timeout(u64::MAX),
            "unknown ids must not claim cancellation success"
        );

        // All original deadlines have elapsed. Only the non-cancelled callbacks may run.
        FAKE_TICK.store(100, Ordering::Relaxed);
        poll_timeouts();
        assert_eq!(
            *ORDER.lock().unwrap_or_else(|e| e.into_inner()),
            vec![1, 3],
            "cancelling one timer must not suppress or reorder other due timers"
        );
        assert!(
            !cancel_timeout(first),
            "a timer already claimed by poll_timeouts is no longer cancellable"
        );
        assert!(
            !cancel_timeout(last),
            "an executed timer id must not remain live"
        );
    }

    #[test]
    fn cancellation_releases_capacity_immediately() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();

        let mut ids = [0u64; MAX_TIMERS];
        for id in &mut ids {
            *id = set_timeout(1_000_000, cb_count, 0).expect("timer table slot");
        }
        assert!(
            set_timeout(1_000_000, cb_count, 0).is_none(),
            "table must be full"
        );

        let released = ids[MAX_TIMERS / 2];
        assert!(
            cancel_timeout(released),
            "cancelling a live timer frees its slot"
        );
        let replacement = set_timeout(1_000_000, cb_count, 0)
            .expect("cancelled slot must be reusable without waiting for deadline");
        assert_ne!(
            replacement, released,
            "reused slot must receive a new identity"
        );

        // Clean up every still-live timer so this global-state test cannot leak into another.
        for id in ids {
            if id != released {
                assert!(cancel_timeout(id));
            }
        }
        assert!(cancel_timeout(replacement));
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
        // 未注入时钟源：所有操作退化为安全空转，now_* 如实返回 None。
        TICK_FN.store(0, Ordering::SeqCst);
        WALL_FN.store(0, Ordering::SeqCst); // wall 也未注入
        assert!(!clock_ready());
        assert_eq!(now_nanos(), None);
        assert_eq!(now_micros(), None);
        assert_eq!(now_millis(), None);
        // wall clock 未注入：如实 None，绝不伪装成 1970 epoch 的 0。
        assert_eq!(wall_clock_secs(), None);
        assert!(set_timeout(10, cb_count, 0).is_none());
        poll_timeouts(); // 不 panic
        sleep_ms(1); // 立即返回，不 panic
        sleep_us(1);
        sleep_nanos(1);
        reset(); // 恢复全局状态，隔离后续测试
    }

    #[test]
    fn wall_clock_injection_and_values() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset(); // 注入 fake_wall 但默认关闭
        assert_eq!(wall_clock_secs(), None, "wall disabled -> None");
        // 启用假 wall：返回注入的 epoch 秒。
        FAKE_EPOCH.store(946_684_800, Ordering::Relaxed); // 2000-01-01T00:00:00Z
        FAKE_WALL_ENABLED.store(true, Ordering::Relaxed);
        assert_eq!(wall_clock_secs(), Some(946_684_800));
        // 来源可换：换一个 epoch（后续 NTP/网络时钟接入的替换点）。
        set_wall_clock_source(|| Some(1_700_000_000));
        assert_eq!(wall_clock_secs(), Some(1_700_000_000));
        reset();
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
