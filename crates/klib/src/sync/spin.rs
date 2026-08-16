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
use core::sync::atomic::{AtomicBool, Ordering};

/// 自旋互斥锁。
pub struct SpinMutex<T> {
    locked: AtomicBool,
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
            data: UnsafeCell::new(data),
        }
    }

    /// 锁的当前状态（用于调试/断言）。
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }

    /// 忙等获取锁。
    pub fn lock(&self) -> SpinMutexGuard<'_, T> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
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
}
