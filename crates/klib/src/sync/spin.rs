//! 自旋互斥锁（`SpinMutex`）。
//!
//! 纯忙等互斥：不关中断、不依赖任何架构特性，是其余锁原语的地基。
//! 中断安全（关中断）变体见 [`super::irq::IrqSpinLock`]。
//!
//! 锁语义：
//! - `lock()`：忙等直到拿到锁；
//! - `try_lock()`：拿不到立即返回 `None`（供死锁检测/非阻塞路径使用）；
//! - guard 析构自动释放。
//!
//! 注意：临界区内严禁睡眠/调度切换。若未来引入可抢占调度，需要升级为
//! 调度器感知锁（持有者+睡眠队列），当前阶段自旋足够。

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// 本执行流的身份标识（供同核重入检测）。
///
/// **绝不返回 0**——`0` 是 `SpinMutex::owner` 的「未持有」哨兵；两者重合会把
/// 空闲锁误判为重入。
///
/// 两条路径：
/// - **已注入架构回调**（真实内核）：返回 CPU 槽位 + 1。检测目标正是「同一
///   CPU 上中断上下文重入主线程持有的锁」。
/// - **未注入**（宿主单测）：返回线程身份 + 1。**不能简单地恒返回 1**——
///   宿主测试是真正多线程的，恒返回 1 会把「另一个线程持有」误报为重入
///   （初版即如此，`stress_contention` 等并发用例当场大面积误 panic）。
///   宿主测试要检出的「重入」恰是**同一线程**二次加锁，线程身份才是正确判据。
#[inline]
pub(crate) fn cpu_slot_id() -> usize {
    let s = super::irq::cpu_slot_for_lock();
    if s != usize::MAX {
        return s.wrapping_add(1);
    }
    // 未注入：退化为线程身份（宿主测试）。
    #[cfg(test)]
    {
        thread_id_hash().wrapping_add(1)
    }
    #[cfg(not(test))]
    {
        1
    }
}

/// 宿主测试用：当前线程的身份（按可复用的线程局部标量取值）。
#[cfg(test)]
fn thread_id_hash() -> usize {
    use core::cell::Cell;
    use std::thread_local;
    thread_local! {
        static ID: Cell<usize> = const { Cell::new(0) };
    }
    static NEXT: AtomicUsize = AtomicUsize::new(1);
    ID.with(|c| {
        if c.get() == 0 {
            c.set(NEXT.fetch_add(1, Ordering::Relaxed));
        }
        c.get()
    })
}

/// 自旋互斥锁。
pub struct SpinMutex<T> {
    locked: AtomicBool,
    /// 持有者 CPU 槽位 + 1（0 = 未持有）。用于 [`SpinMutex::lock`] 的同核重入
    /// 检测：`u64::MAX` 兼作「未知身份」哨兵（见 [`cpu_slot_id`]）。
    owner: AtomicUsize,
    data: UnsafeCell<T>,
}

// `T: Send` 时整个锁可跨线程转移/共享。
unsafe impl<T: Send> Sync for SpinMutex<T> {}
unsafe impl<T: Send> Send for SpinMutex<T> {}

impl<T> SpinMutex<T> {
    /// 常量构造（可用于 `static`）。
    pub const fn new(data: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            owner: AtomicUsize::new(0),
            data: UnsafeCell::new(data),
        }
    }

    /// 锁的当前状态（用于调试/断言）。
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }

    /// 忙等获取锁。
    ///
    /// # 同核重入检测（§6.12.6）
    ///
    /// 忙等前先查 `owner`：若本 CPU 已持有本锁，则**立即 panic** 而不是自旋。
    ///
    /// 为什么必须这样做：纯自旋锁无法区分「别的 CPU 持有、稍后会释放」与
    /// 「本 CPU 自己持有、永远等不到」。后者是**永久静默停机**——实测中它表现
    /// 为 BSP 的 IRQ0 handler 永不返回、EOI 永不发出、周期性中断永久停止，
    /// 第 3 个超时定时器起永不触发，shell 永久卡死且 `^C` 完全无效。
    /// 整整一轮排查才定位到它，正是因为它**不报错、只是安静地停住**。
    ///
    /// 故此处把「静默停机」换成「当场 panic + 明确指出重入」：同类缺陷今后
    /// 第一次发生即暴露，附 CPU 槽位可直接定位调用栈（S21：失败必须可定位）。
    pub fn lock(&self) -> SpinMutexGuard<'_, T> {
        let me = self::cpu_slot_id();
        let owner = self.owner.load(Ordering::Acquire);
        if owner == me {
            // cpu_slot_id() 返回「槽位 + 1」（0 是 owner 的未持有哨兵），
            // 报告时还原为槽位号，避免误导排查方向。
            panic!(
                "SpinMutex 同核重入死锁：本 CPU (slot {}) 已持有本锁；\
                 纯自旋锁在此必然永久自旋。请检查中断上下文中是否重入了同一把锁",
                me.wrapping_sub(1)
            );
        }
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        // 拿到锁后记录持有者（必须在 CAS 成功之后写，避免把等待者误记为持有者）。
        self.owner.store(me, Ordering::Release);
        SpinMutexGuard { mutex: self }
    }

    /// 非阻塞尝试获取锁；失败返回 `None`。
    pub fn try_lock(&self) -> Option<SpinMutexGuard<'_, T>> {
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(SpinMutexGuard { mutex: self })
        } else {
            None
        }
    }

    /// 借出不可变引用（仅在确实没有并发访问时使用，否则用 `lock()`）。
    pub fn get_mut(&mut self) -> &mut T {
        unsafe { &mut *self.data.get() }
    }
}

/// 释放锁时执行的额外动作（可扩展，当前仅用于原子解锁）。
#[must_use = "if unused the lock will immediately unlock"]
pub struct SpinMutexGuard<'a, T> {
    mutex: &'a SpinMutex<T>,
}

impl<T> core::ops::Deref for SpinMutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.mutex.data.get() }
    }
}

impl<T> core::ops::DerefMut for SpinMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<T> Drop for SpinMutexGuard<'_, T> {
    fn drop(&mut self) {
        // 先清持有者再放锁：任何观察者只要看到 `locked == false`，就必然也
        // 看到 `owner == 0`，不会把「已释放的锁」误判为「被自己持有」。
        self.mutex.owner.store(0, Ordering::Release);
        self.mutex.locked.store(false, Ordering::Release);
    }
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::vec::Vec;

    #[test]
    fn lock_unlock_basic() {
        let m = SpinMutex::new(0u32);
        {
            let mut g = m.lock();
            *g += 1;
        }
        assert_eq!(*m.lock(), 1);
    }

    #[test]
    fn try_lock_contended() {
        let m = SpinMutex::new(0u32);
        let g = m.try_lock().expect("first lock succeeds");
        assert!(m.try_lock().is_none(), "second lock must fail");
        drop(g);
        assert!(m.try_lock().is_some(), "lock free again after drop");
    }

    #[test]
    fn stress_contention() {
        // 多线程争抢同一把锁，累计计数必须精确。
        let m = Arc::new(SpinMutex::new(0u64));
        let c = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let m_ref = m.clone();
            let c_ref = c.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..5000 {
                    let mut g = m_ref.lock();
                    *g += 1;
                    drop(g);
                    c_ref.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(c.load(Ordering::Relaxed), 8 * 5000);
        assert_eq!(*m.lock(), 8 * 5000);
    }

    /// §6.12.6（丙）：**同一执行流二次加锁必须当场 panic**，而非永久自旋。
    ///
    /// 这是本检测存在的全部理由：纯自旋锁遇到自有锁会安静地停住，实测中
    /// 表现为不可诊断的静默停机。此处把它换成可定位的 panic。
    #[test]
    #[should_panic(expected = "同核重入死锁")]
    fn same_thread_reentry_panics() {
        let m = SpinMutex::new(0u32);
        let _g = m.lock();
        let _again = m.lock(); // 必须 panic，绝不能挂死
    }

    /// 对照：**不同**执行流先后加锁不得误报（锁正常工作时不得 panic）。
    ///
    /// # 原实现断言了一个不存在的不变量（flaky，实测复现）
    ///
    /// 原断言 `assert_eq!(*g, i)` 假定 4 个线程按 `i` 递增的顺序依次取得锁。
    /// 而 `std::thread::spawn` 的调度顺序**无任何保证**——线程 1 完全可能先于
    /// 线程 0 拿到锁，于是读到 `*g == 0` 而 `i == 1`。实测失败输出：
    ///
    /// ```text
    /// thread '<unnamed>' panicked at spin.rs:248:
    ///   assertion `left == right` failed
    ///     left: 0
    ///    right: 1
    /// ```
    ///
    /// 它是**间歇性**的（取决于调度，多次运行才复现一次），故更危险：
    /// 会被当作"偶发"忽略，而实际上门禁每一次都可能是红的。
    ///
    /// 这是测试自身的错误，与锁无关：锁要保证的是**互斥**，不是**按创建顺序
    /// 排队**。把一个调度顺序假设写进断言，等于让测试依赖它不拥有的保证。
    ///
    /// # 修正
    ///
    /// 断言改为**与顺序无关**的互斥性：每个线程只做"读-改-写"各一次，无论
    /// 谁先谁后，互斥成立则总和必为 4；若锁失效导致两个线程同时进入临界区，
    /// 丢失更新会让结果小于 4。对照目的（不产生误报 panic）完整保留，
    /// 但不再依赖调度顺序。
    ///
    /// 断言一律留在主线程：线程内 panic 会被 `join` 包装成 `Any { .. }`，
    /// 掩盖真实原因（原实现的报错正是如此——只看到 "no thread may panic"）。
    #[test]
    fn sequential_across_threads_no_false_positive() {
        let m = Arc::new(SpinMutex::new(0u32));
        let mut handles = Vec::new();
        for _ in 0..4u32 {
            let m_ref = m.clone();
            handles.push(std::thread::spawn(move || {
                // 读-改-写：互斥成立则每线程各贡献 +1，与顺序无关。
                let mut g = m_ref.lock();
                *g += 1;
            }));
        }
        for h in handles {
            h.join().expect("no thread may panic (no false reentry report)");
        }
        // 4 个线程各 +1。锁失效导致丢失更新时此处会小于 4。
        assert_eq!(*m.lock(), 4);
    }

    /// 对照：锁释放后同一执行流再次加锁**不得**被判为重入。
    /// （若 `Drop` 未清 `owner`，这条会误 panic——钉死该不变量。）
    #[test]
    fn reacquire_after_drop_allowed() {
        let m = SpinMutex::new(0u32);
        drop(m.lock());
        let mut g = m.lock();
        *g = 5;
        drop(g);
        assert_eq!(*m.lock(), 5);
    }
}