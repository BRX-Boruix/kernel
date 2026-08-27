//! 计数信号量（`Semaphore`）。
//!
//! 自旋忙等版：当前内核还没有调度器，`acquire` 时资源不足就自旋等待。
//! 未来接入调度器后，可将等待路径替换为"挂起当前线程"（阻塞语义不变，
//! 调用点零改动）。
//!
//! - `acquire()`：资源减一，不足则忙等；
//! - `try_acquire()`：不足立即返回 `false`；
//! - `release()`：资源加一（可超过初值，用于手动归还）。
//!
//! 初始值 `0` 即为二元信号量/互斥（互斥场景优先用 `SpinMutex`，省一个计数）。

use core::sync::atomic::{AtomicUsize, Ordering};

/// 计数信号量。
pub struct Semaphore {
    count: AtomicUsize,
}

impl Semaphore {
    /// 以 `initial` 个资源创建。
    pub const fn new(initial: usize) -> Self {
        Self {
            count: AtomicUsize::new(initial),
        }
    }

    /// 当前可用资源数。
    pub fn available(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }

    /// 获取一个资源；不足则忙等。
    pub fn acquire(&self) {
        loop {
            let c = self.count.load(Ordering::Acquire);
            if c == 0 {
                core::hint::spin_loop();
                continue;
            }
            if self
                .count
                .compare_exchange(c, c - 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
        }
    }

    /// 非阻塞获取；资源不足立即返回 `false`。
    pub fn try_acquire(&self) -> bool {
        loop {
            let c = self.count.load(Ordering::Acquire);
            if c == 0 {
                return false;
            }
            if self
                .count
                .compare_exchange(c, c - 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// 释放一个资源。
    pub fn release(&self) {
        // S19：release 无上限，count 无限累加会在 usize::MAX 溢出。用
        // try_update（原 fetch_update）饱和到 usize::MAX，杜绝回绕成小计数。
        let _ = self.count.try_update(Ordering::Release, Ordering::Relaxed, |c| {
            Some(c.saturating_add(1))
        });
    }
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_release_roundtrip() {
        let s = Semaphore::new(2);
        assert_eq!(s.available(), 2);
        s.acquire();
        s.acquire();
        assert_eq!(s.available(), 0);
        assert!(!s.try_acquire(), "exhausted");
        s.release();
        assert_eq!(s.available(), 1);
        assert!(s.try_acquire());
    }

    #[test]
    fn binary_semaphore_as_mutex() {
        let s = Semaphore::new(1);
        s.acquire();
        assert!(!s.try_acquire());
        s.release();
        assert!(s.try_acquire());
    }

    #[test]
    fn stress_producer_consumer() {
        use std::sync::Arc;
        use std::vec::Vec;
        let sem = Arc::new(Semaphore::new(0));
        let done = Arc::new(core::sync::atomic::AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let s = sem.clone();
            let d = done.clone();
            handles.push(std::thread::spawn(move || {
                // 每个消费者等 1000 次 release。
                for _ in 0..1000 {
                    s.acquire();
                    d.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                }
            }));
        }
        for _ in 0..4 * 1000 {
            sem.release();
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(done.load(core::sync::atomic::Ordering::Relaxed), 4 * 1000);
    }
}
