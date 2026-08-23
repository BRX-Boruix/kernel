//! 读写锁（`RwLock`）。
//!
//! 基于自旋：多个读者可并存，写者独占。
//! 公平性策略：**写者优先**——写者在入口先登记等待（pending 计数），
//! 此后新读者一律被拒之门外，直到该写者取得锁并释放。等待写者不可能
//! 被新读者插队饿死（KA1：此前实现只有持有位、无等待追踪，模块头
//! 宣称的写者优先不成立——已按真语义重实现并有确定性回归测试钉住）。
//!
//! 对称取舍（成文）：写者优先意味着**持续写流下读者可饿死**——这是与
//! "读侧无门槛"之间的显式选择；读侧插队无限推迟状态翻转对内核不变量
//! 的破坏更直接，故牺牲读者即时性换写者有界等待。
//!
//! 状态编码（`AtomicUsize`）：
//! - 低 32 位：读者计数；
//! - 位 32–62：**等待写者的计数**（每个等待者是一个自旋线程，物理线程
//!   数远小于 2^31，字段耗尽不可达；debug 构建仍有溢出断言）；
//! - 位 63：写者持有位。
//!
//! 简化实现：
//! - 写者：入口 `pending += 1` → 自旋等「持有位空 + 读者数零」→ CAS 取
//!   持有位 → 注销自己的 pending；释放时只清持有位、保留其余 pending；
//! - 读者：高 32 位全零（无持有者、无等待写者）才允许进入，否则忙等；
//! - try_read / try_write 不登记 pending——非阻塞路径不得留下队列副作用。
//!
//! 锁序注意（S21）：本改造改变的是准入时序而非锁语义；持读再请写、或
//! 违反全局锁序嵌套，依旧死锁（与改造前一致），调用方纪律不变。

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

/// 读者数在低 32 位；"有写者持有"标志为 `1 << 63`。
const WRITER_BIT: usize = 1usize << 63;
const READER_MASK: usize = 0xffff_ffff;
/// 等待写者计数的位偏移（位 32–62，共 31 位）与步进。
const PENDING_SHIFT: u32 = 32;
const PENDING_ONE: usize = 1usize << PENDING_SHIFT;
/// pending 字段满值（溢出断言的比对基准）。
const PENDING_FULL: usize = 0x7fff_ffff_usize << PENDING_SHIFT;

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

    /// 获取读锁（可与其他读者共存；写者持有或**等待中**则忙等）。
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        loop {
            let s = self.state.load(Ordering::Acquire);
            // 高 32 位非零（写者持有位或等待写者计数）→ 忙等（写者优先）。
            if s & !READER_MASK != 0 {
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

    /// 获取写锁（独占；入口登记等待，既有读者清零后取得）。
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        // 入口登记等待：自此新读者被拒之门外（写者优先的核心动作）。
        let s = self.state.fetch_add(PENDING_ONE, Ordering::AcqRel);
        debug_assert!(s & PENDING_FULL != PENDING_FULL, "pending overflow");
        loop {
            let s = self.state.load(Ordering::Acquire);
            if s & WRITER_BIT == 0 && s & READER_MASK == 0 {
                // 完全空闲：抢持有位。CAS 目标保留 pending 位（含自己的，
                // 取得后立即注销），失败即重读重试。
                if self
                    .state
                    .compare_exchange(
                        s,
                        s | WRITER_BIT,
                        Ordering::Acquire,
                        Ordering::Relaxed,
                    )
                    .is_ok()
                {
                    self.state.fetch_sub(PENDING_ONE, Ordering::Release);
                    return RwLockWriteGuard { lock: self };
                }
            }
            core::hint::spin_loop();
        }
    }

    /// 非阻塞读锁（等待写者在场同样拒绝——与 [`Self::read`] 同一门控）。
    pub fn try_read(&self) -> Option<RwLockReadGuard<'_, T>> {
        let s = self.state.load(Ordering::Acquire);
        if s & !READER_MASK != 0 {
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

    /// 非阻塞写锁：仅在完全空闲时直接取得。不登记 pending——非阻塞
    /// 路径不得留下队列副作用（否则一次失败的 try_write 会错误地挡住
    /// 后续读者）。等待中的其他写者因此不被 try_write 插队。
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
        // 读者离开：读者数减一。读者从不会触碰高 32 位。
        self.state.fetch_sub(1, Ordering::Release);
    }

    fn release_writer(&self) {
        // 只清持有位、保留 pending 位：其余等待写者继续优先于新读者。
        self.state.fetch_and(!WRITER_BIT, Ordering::Release);
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

    /// KA1（确定性红证）：写者**等待中**必须把新读者拒之门外。
    ///
    /// 持有读锁 → 后台写者阻塞在 write()（成为等待者）→ 主线程反复尝试
    /// try_read。正确实现里等待写者一经登记，try_read 立即返回 None；
    /// 虚构"写者优先"的旧实现永远返回 Some——有限次轮询后断言失败，
    /// 不依赖任何时序假设。轮询上限只是防死循环的护栏，正常路径几次
    /// 迭代内即可观察到门控。
    #[test]
    fn waiting_writer_gates_new_readers() {
        let l = Arc::new(RwLock::new(0u32));
        let gate = l.read(); // 持有读锁：写者只能等待
        let l2 = Arc::clone(&l);
        let writer = std::thread::spawn(move || {
            let _w = l2.write(); // 阻塞直至主线程放行
        });
        let mut gated = false;
        for _ in 0..100_000 {
            if l.try_read().is_none() {
                gated = true;
                break;
            }
            core::hint::spin_loop();
        }
        assert!(
            gated,
            "waiting writer did not gate new readers: write-priority is fiction"
        );
        drop(gate);
        writer.join().unwrap();
    }

    /// KA1 补充：等待写者在既有读者全部离开后必须能取得锁，且第二个
    /// 等待写者在其之后串行取得；全部结束后状态字归零（pending 计数
    /// 无残留——残留会让读者被永久拒之门外）。
    #[test]
    fn pending_writers_drain_and_state_returns_to_idle() {
        let l = Arc::new(RwLock::new(0u32));
        let gate = l.read();
        let w1 = Arc::clone(&l);
        let w2 = Arc::clone(&l);
        let h1 = std::thread::spawn(move || {
            let mut g = w1.write();
            *g += 1;
        });
        let h2 = std::thread::spawn(move || {
            let mut g = w2.write();
            *g += 10;
        });
        // 等 pending 登记生效（try_read 被 门控 = 至少一个写者在等待）
        let mut gated = false;
        for _ in 0..100_000 {
            if l.try_read().is_none() {
                gated = true;
                break;
            }
            core::hint::spin_loop();
        }
        assert!(gated, "writers failed to register as pending");
        drop(gate);
        h1.join().unwrap();
        h2.join().unwrap();
        // 两个写者各成功累加一次
        let r = l.read();
        assert_eq!(*r, 11);
        drop(r);
        // 状态完全空闲：try_write 必须成功（若有 pending/持有位残留则失败）
        let w = l.try_write().expect("state must return to fully idle");
        drop(w);
    }
}
