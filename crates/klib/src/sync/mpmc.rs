//! 无锁有界多生产者多消费者队列（`MpmcQueue`）。
//!
//! Vyukov 有界 MPMC 环形队列：任意数量生产/消费者并发安全，全程无锁
//! （仅原子操作 + 自旋等待），因此同时覆盖 SPSC / MPSC / MPMC 场景。
//!
//! 容量固定（`const N`），必须为 2 的幂（内部用位与取模）。
//! 元素要求 `Copy`：并发取出无法安全转移所有权。
//!
//! API：
//! - [`MpmcQueue::push`]：满则忙等（有界阻塞写）；
//! - [`MpmcQueue::try_push`]：满立即返回 `false`；
//! - [`MpmcQueue::pop`]：空则忙等；
//! - [`MpmcQueue::try_pop`]：空立即返回 `None`。
//!
//! 典型用途：串口/键盘输入缓冲、任务队列、消息传递（T1.3 的 `RingBuffer`
//! 若需多消费者语义可改用本类型）。

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};

/// 无锁有界 MPMC 环形队列。
pub struct MpmcQueue<T: Copy, const N: usize> {
    /// 数据槽（`N` 必须是 2 的幂）。
    buf: [UnsafeCell<MaybeUninit<T>>; N],
    /// 每个槽的序号（Vyukov 算法核心：随入队/出队轮次递增）。
    seq: [AtomicUsize; N],
    /// 下一次入队位置（绝对序号，按 usize 位宽回绕；与 `seq` 槽位的
    /// `pos..pos+N` 区间判别配合，回绕安全——见 [`MpmcQueue::pop`]）。
    enqueue_pos: AtomicUsize,
    /// 下一次出队位置（同入队，回绕设计）。
    dequeue_pos: AtomicUsize,
}

// `T: Copy + Send` 时队列可共享。
unsafe impl<T: Copy + Send, const N: usize> Sync for MpmcQueue<T, N> {}

impl<T: Copy, const N: usize> MpmcQueue<T, N> {
    /// 常量构造。
    ///
    /// `N` 必须为 2 的幂且大于 0，否则 `assert` 触发（const 上下文可静态验证）。
    pub const fn new() -> Self {
        assert!(N.is_power_of_two(), "MpmcQueue size must be a power of two");
        // seq 初始化为槽位下标：让"空槽"周期从 `0,1,...,N-1` 开始。
        let mut seq = [const { AtomicUsize::new(0) }; N];
        let mut i = 0;
        while i < N {
            seq[i] = AtomicUsize::new(i);
            i += 1;
        }
        Self {
            buf: [const { UnsafeCell::new(MaybeUninit::uninit()) }; N],
            seq,
            enqueue_pos: AtomicUsize::new(0),
            dequeue_pos: AtomicUsize::new(0),
        }
    }

    /// 入队；满则忙等。返回前元素已对消费者可见。
    ///
    /// Vyukov 标准算法（绝对序号）：
    /// - 生产者预留 `pos`，等 `seq[idx] == pos`（该轮槽位空闲）后写入，发布为 `pos+1`；
    /// - 消费者读到 `seq[idx] == pos+1` 后取走，将槽位释放为 `pos+N`（跨过整个环，
    ///   使序号与下一轮 `pos+N` 的生产者对齐）。
    pub fn push(&self, value: T) {
        let mask = N - 1;
        let pos = self.enqueue_pos.fetch_add(1, Ordering::Acquire);
        let idx = pos & mask;
        while self.seq[idx].load(Ordering::Acquire) != pos {
            core::hint::spin_loop();
        }
        unsafe {
            (*self.buf[idx].get()).write(value);
        }
        self.seq[idx].store(pos.wrapping_add(1), Ordering::Release);
    }

    /// 非阻塞入队；满立即返回 `false`。
    ///
    /// 乐观 CAS：先读 `enqueue_pos`，槽位不就绪（满）直接返回 `false` 且不预留位置，
    /// 避免多生产者"预留-退还"导致的 ABA 死锁。
    pub fn try_push(&self, value: T) -> bool {
        let mask = N - 1;
        loop {
            let pos = self.enqueue_pos.load(Ordering::Acquire);
            let idx = pos & mask;
            if self.seq[idx].load(Ordering::Acquire) != pos {
                return false; // 该槽位本轮的写者尚未就绪（队列满）
            }
            if self
                .enqueue_pos
                .compare_exchange(pos, pos.wrapping_add(1), Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                unsafe {
                    (*self.buf[idx].get()).write(value);
                }
                self.seq[idx].store(pos.wrapping_add(1), Ordering::Release);
                return true;
            }
            // CAS 失败：其他生产者抢先，重试。
        }
    }

    /// 出队；空则忙等。
    pub fn pop(&self) -> T {
        let mask = N - 1;
        let pos = self.dequeue_pos.fetch_add(1, Ordering::Acquire);
        let idx = pos & mask;
        while self.seq[idx].load(Ordering::Acquire) != pos.wrapping_add(1) {
            core::hint::spin_loop();
        }
        let value = unsafe { (*self.buf[idx].get()).assume_init_read() };
        self.seq[idx].store(pos.wrapping_add(N), Ordering::Release);
        value
    }

    /// 非阻塞出队；空返回 `None`。
    ///
    /// 乐观 CAS（不预留-退还），多消费者安全。
    pub fn try_pop(&self) -> Option<T> {
        let mask = N - 1;
        loop {
            let pos = self.dequeue_pos.load(Ordering::Acquire);
            let idx = pos & mask;
            if self.seq[idx].load(Ordering::Acquire) != pos.wrapping_add(1) {
                return None; // 该轮数据尚未发布（空）
            }
            if self
                .dequeue_pos
                .compare_exchange(pos, pos.wrapping_add(1), Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                let value = unsafe { (*self.buf[idx].get()).assume_init_read() };
                self.seq[idx].store(pos.wrapping_add(N), Ordering::Release);
                return Some(value);
            }
            // CAS 失败：其他消费者抢先，重试。
        }
    }
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::vec::Vec;

    #[test]
    fn spsc_roundtrip() {
        let q = MpmcQueue::<u32, 8>::new();
        q.push(1);
        q.push(2);
        assert_eq!(q.pop(), 1);
        assert_eq!(q.try_pop(), Some(2));
        assert_eq!(q.try_pop(), None);
    }

    #[test]
    fn spsc_full_empty() {
        let q = MpmcQueue::<u32, 4>::new();
        assert!(q.try_push(1));
        assert!(q.try_push(2));
        assert!(q.try_push(3));
        assert!(q.try_push(4));
        assert!(!q.try_push(5), "full");
        assert_eq!(q.pop(), 1);
        assert!(q.try_push(5), "slot reused after pop");
        assert_eq!(q.pop(), 2);
        assert_eq!(q.pop(), 3);
        assert_eq!(q.pop(), 4);
        assert_eq!(q.pop(), 5);
    }

    #[test]
    fn spsc_wraparound_many() {
        // 容量 8，流水式 push/pop 循环 1000 次，确保序号回绕与槽位复用正确。
        // 注意：忙等 `push` 在满时自旋，单线程不能先塞满，必须边推边取。
        let q = MpmcQueue::<u32, 8>::new();
        for i in 0..1000u32 {
            // 先 pop 释放槽位，再 push：保证队列始终 ≤ 容量 8，忙等 `push` 不会自陷。
            if i >= 8 {
                assert_eq!(q.pop(), i - 8);
            }
            q.push(i);
        }
        // 收尾：队列中残留最后 8 个（992..=999）。
        for i in 0..8u32 {
            assert_eq!(q.pop(), 992 + i);
        }
        assert_eq!(q.try_pop(), None);
    }

    #[test]
    fn mpsc_stress() {
        const CAP: usize = 64;
        const PRODUCERS: usize = 4;
        const PER: usize = 2000;
        let q = Arc::new(MpmcQueue::<u32, CAP>::new());
        let mut handles = Vec::new();
        for p in 0..PRODUCERS {
            let q_ref = q.clone();
            handles.push(std::thread::spawn(move || {
                for i in 0..PER {
                    let v = (p * PER + i) as u32;
                    // 随机偶发忙等也允许；push 本身会等。
                    while !q_ref.try_push(v) {
                        core::hint::spin_loop();
                    }
                }
            }));
        }
        // 消费端统计，用校验和验证无丢失/无重复。
        let mut seen = std::collections::HashSet::new();
        let expected_total = PRODUCERS * PER;
        while seen.len() < expected_total {
            if let Some(v) = q.try_pop() {
                assert!(seen.insert(v), "duplicate {}", v);
            } else {
                core::hint::spin_loop();
            }
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(seen.len(), expected_total);
    }
}
