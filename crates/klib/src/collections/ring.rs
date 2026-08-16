//! 无锁 SPSC 环形缓冲区（`RingBuffer`）。
//!
//! 单一生产者 + 单一消费者模型：一个线程（或中断处理器）写、另一个线程读，
//! 无锁、无需关中断，适合串口 RX 缓冲、键盘输入缓冲等场景。
//!
//! 容量 `N` 必须是 2 的幂（`new` 中编译期断言），索引用掩码取模。
//! 槽位用 `MaybeUninit` 延迟初始化，不要求 `T: Default/Copy`。
//!
//! 多生产者 / 多消费者场景请用 [`crate::sync::mpmc::MpmcQueue`]，
//! 或外部加锁保护后复用本类型。
//!
//! 注意：`clear()` 时槽内未读元素不会被 drop（无锁语义下无法安全回收），
//! 适用于 `u8`/`u32` 等无析构类型；需要 drop 语义时先 `pop` 清空。

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};

/// 无锁 SPSC 环形缓冲区。
pub struct RingBuffer<T, const N: usize> {
    /// 数据槽（下标 = `pos & (N-1)`）。
    buf: [UnsafeCell<MaybeUninit<T>>; N],
    /// 下一个写入槽（生产者独占维护）。
    head: AtomicUsize,
    /// 下一个读取槽（消费者独占维护）。
    tail: AtomicUsize,
}

// 生产者（push）与消费者（pop）经 `&self` 并发调用是设计前提，故 `Sync`。
// 数据所有权经槽位转移，`T` 本身无需 `Send`。
unsafe impl<T, const N: usize> Sync for RingBuffer<T, N> {}
unsafe impl<T, const N: usize> Send for RingBuffer<T, N> {}

impl<T, const N: usize> RingBuffer<T, N> {
    /// 常量构造（容量须为 2 的幂，编译期断言）。
    pub const fn new() -> Self {
        assert!(
            N.is_power_of_two(),
            "RingBuffer capacity must be a power of two"
        );
        Self {
            buf: [const { UnsafeCell::new(MaybeUninit::uninit()) }; N],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    /// 容量。
    pub const fn capacity(&self) -> usize {
        N
    }

    /// 已缓冲元素数（接近满时可能略不精确，仅作参考）。
    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        head.wrapping_sub(tail)
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 是否已满。
    pub fn is_full(&self) -> bool {
        self.len() == N
    }

    /// 生产者写入；满时返回 `Err(value)`。
    pub fn push(&self, value: T) -> Result<(), T> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if head.wrapping_sub(tail) == N {
            return Err(value); // 满
        }
        let slot: *mut MaybeUninit<T> =
            unsafe { self.buf.get_unchecked(head & (N - 1)).get() };
        unsafe {
            (*slot).write(value);
        }
        self.head.store(head + 1, Ordering::Release);
        Ok(())
    }

    /// 消费者读取；空时返回 `None`。
    pub fn pop(&self) -> Option<T> {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        if tail == head {
            return None; // 空
        }
        let slot: *const MaybeUninit<T> =
            unsafe { self.buf.get_unchecked(tail & (N - 1)).get() };
        let v = unsafe { (*slot).assume_init_read() };
        self.tail.store(tail + 1, Ordering::Release);
        Some(v)
    }

    /// 清空缓冲（`&mut self` 独占；未读元素不 drop，见模块文档）。
    pub fn clear(&mut self) {
        *self = Self::new();
    }
}

impl<T, const N: usize> Default for RingBuffer<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn basic_push_pop() {
        let rb = RingBuffer::<u32, 8>::new();
        assert!(rb.is_empty());
        assert_eq!(rb.capacity(), 8);
        for i in 0..8 {
            rb.push(i).unwrap();
        }
        assert!(rb.is_full());
        assert_eq!(rb.push(99), Err(99)); // 满：原值返回
        for i in 0..8 {
            assert_eq!(rb.pop(), Some(i));
        }
        assert!(rb.is_empty());
        assert_eq!(rb.pop(), None);
    }

    #[test]
    fn wrap_around() {
        let rb = RingBuffer::<u32, 4>::new();
        for i in 0..4 {
            rb.push(i).unwrap();
        }
        assert_eq!(rb.pop(), Some(0));
        assert_eq!(rb.pop(), Some(1));
        rb.push(10).unwrap();
        rb.push(11).unwrap();
        assert_eq!(rb.pop(), Some(2));
        assert_eq!(rb.pop(), Some(3));
        assert_eq!(rb.pop(), Some(10));
        assert_eq!(rb.pop(), Some(11));
        assert!(rb.is_empty());
    }

    #[test]
    fn partial_fill_and_len() {
        let rb = RingBuffer::<u32, 8>::new();
        rb.push(1).unwrap();
        rb.push(2).unwrap();
        rb.push(3).unwrap();
        assert_eq!(rb.len(), 3);
        assert!(!rb.is_full());
        rb.pop();
        rb.pop();
        assert_eq!(rb.len(), 1);
    }

    #[test]
    fn clear_resets() {
        let mut rb = RingBuffer::<u32, 4>::new();
        for i in 0..4 {
            rb.push(i).unwrap();
        }
        rb.clear();
        assert!(rb.is_empty());
        rb.push(7).unwrap();
        assert_eq!(rb.pop(), Some(7));
    }

    #[test]
    fn spsc_producer_consumer() {
        // 压力：生产者写 total 项，消费者校验和（跨多轮环绕）。
        const N: usize = 16;
        let total: u64 = 200_000;
        let rb = Arc::new(RingBuffer::<u64, N>::new());
        let pr = rb.clone();
        let prod = std::thread::spawn(move || {
            for i in 0..total {
                while pr.push(i).is_err() {
                    std::hint::spin_loop();
                }
            }
        });
        let cr = rb.clone();
        let cons = std::thread::spawn(move || {
            let mut got = 0u64;
            let mut sum = 0u64;
            while got < total {
                if let Some(v) = cr.pop() {
                    sum += v;
                    got += 1;
                } else {
                    std::hint::spin_loop();
                }
            }
            sum
        });
        prod.join().unwrap();
        let sum = cons.join().unwrap();
        assert_eq!(sum, total * (total - 1) / 2);
    }

    #[test]
    fn shared_between_threads() {
        // 编译期验证 Send/Sync 可用（Arc 跨线程传递）。
        let rb = Arc::new(RingBuffer::<u8, 4>::new());
        let r = rb.clone();
        std::thread::spawn(move || {
            r.push(1).unwrap();
        })
        .join()
        .unwrap();
        assert_eq!(rb.pop(), Some(1));
    }
}
