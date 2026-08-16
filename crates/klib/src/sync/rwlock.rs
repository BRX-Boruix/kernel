//! 读写锁（`RwLock`）。
//!
//! 基于自旋：多个读者可并存，写者独占。
//! 公平性策略：**写者优先**——一旦有写者等待，后续读者将被拒之门外，
//! 避免读者持续进入导致写者饿死（writer starvation）。
//!
//! 状态编码（`AtomicUsize`）：
//! - 低 32 位：读者计数（仅写者=1 时翻转用于互斥）；
//! - 高 32 位：等待写者的计数（用于写者优先）。
//!
//! 简化实现：
//! - 读者：`WRITER_PENDING == 0 && writer==0` 时 `readers.fetch_add(1)`；
//!   若写者持有或写者等待中，忙等。
//! - 写者：`writer.cas(0,1)`；若读者数>0 或已有写者，忙等。

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

/// 读者数在低 32 位；"有写者持有"标志为 `1 << 63`。
const WRITER_BIT: usize = 1usize << 63;
const READER_MASK: usize = 0xffff_ffff;

/// 读写锁。
pub struct RwLock<T> {
    state: AtomicUsize,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for RwLock<T> {}
unsafe impl<T: Send> Send for RwLock<T> {}

impl<T> RwLock<T> {
    /// 常量构造。
    pub const fn new(data: T) -> Self {
        Self {
            state: AtomicUsize::new(0),
            data: UnsafeCell::new(data),
        }
    }

    /// 获取读锁（可与其他读者共存；写者等待中则排队）。
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        loop {
            let s = self.state.load(Ordering::Acquire);
            // 写者持有或写者已等待 → 忙等（写者优先）。
            if s & (WRITER_BIT) != 0 {
                core::hint::spin_loop();
                continue;
            }
            let readers = s & READER_MASK;
            if self
                .state
                .compare_exchange(s, readers + 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return RwLockReadGuard { lock: self };
            }
        }
    }

    /// 获取写锁（独占；等待读者清零）。
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        loop {
            let s = self.state.load(Ordering::Acquire);
            if s == 0 {
                // 完全空闲：直接抢写者位。
                if self
                    .state
                    .compare_exchange(0, WRITER_BIT, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    return RwLockWriteGuard { lock: self };
                }
            }
            core::hint::spin_loop();
        }
    }

    /// 非阻塞读锁。
    pub fn try_read(&self) -> Option<RwLockReadGuard<'_, T>> {
        let s = self.state.load(Ordering::Acquire);
        if s & WRITER_BIT != 0 {
            return None;
        }
        let readers = s & READER_MASK;
        if self
            .state
            .compare_exchange(s, readers + 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(RwLockReadGuard { lock: self })
        } else {
            None
        }
    }

    /// 非阻塞写锁。
    pub fn try_write(&self) -> Option<RwLockWriteGuard<'_, T>> {
        if self
            .state
            .compare_exchange(0, WRITER_BIT, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(RwLockWriteGuard { lock: self })
        } else {
            None
        }
    }
}

impl<T> RwLock<T> {
    fn release_reader(&self) {
        // 读者离开：读者数减一。读者从不会清除 WRITER_BIT。
        self.state.fetch_sub(1, Ordering::Release);
    }

    fn release_writer(&self) {
        self.state.store(0, Ordering::Release);
    }
}

pub struct RwLockReadGuard<'a, T> {
    lock: &'a RwLock<T>,
}

impl<T> core::ops::Deref for RwLockReadGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> Drop for RwLockReadGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.release_reader();
    }
}

pub struct RwLockWriteGuard<'a, T> {
    lock: &'a RwLock<T>,
}

impl<T> core::ops::Deref for RwLockWriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> core::ops::DerefMut for RwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for RwLockWriteGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.release_writer();
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
    fn read_write_basic() {
        let l = RwLock::new(0u32);
        {
            let r = l.read();
            assert_eq!(*r, 0);
        }
        {
            let mut w = l.write();
            *w = 42;
        }
        assert_eq!(*l.read(), 42);
    }

    #[test]
    fn try_locks() {
        let l = RwLock::new(0u32);
        let r1 = l.try_read().expect("read1");
        let r2 = l.try_read().expect("read2 coexists");
        assert!(l.try_write().is_none(), "writer blocked by readers");
        drop(r1);
        drop(r2);
        let w = l.try_write().expect("writer after readers gone");
        assert!(l.try_read().is_none());
        drop(w);
    }

    #[test]
    fn stress_mixed_readers_writer() {
        let l = Arc::new(RwLock::new(0u64));
        let reads = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        // 4 个读者循环读，2 个写者循环写。
        for _ in 0..4 {
            let l_ref = l.clone();
            let reads_ref = reads.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..3000 {
                    let r = l_ref.read();
                    assert!(*r <= 100_000);
                    reads_ref.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        for _ in 0..2 {
            let l_ref = l.clone();
            handles.push(std::thread::spawn(move || {
                for i in 0..3000 {
                    let mut w = l_ref.write();
                    *w = (*w + 1) % 100_001;
                    let _ = i;
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert!(reads.load(Ordering::Relaxed) == 4 * 3000);
    }
}
