//! 屏障（`Barrier`）。
//!
//! `n` 个线程必须**全部到达**后才能一起放行（会合点）。常用于阶段并行：
//! 所有参与者完成第 k 轮工作后，一起进入第 k+1 轮。
//!
//! 实现为自旋版：未到齐的线程忙等。每轮（`generation`）重置计数，
//! 因此同一 `Barrier` 可反复使用（等待多轮）。
//!
//! 注意：`n` 个线程必须各自调用一次 `wait()` 才算到齐，不允许同一线程
//! 调用多次充数。

use core::sync::atomic::{AtomicUsize, Ordering};

/// 屏障。
pub struct Barrier {
    /// 需要到达的线程总数。
    total: usize,
    /// 当前代际已到达计数。
    arrived: AtomicUsize,
    /// 代际号（每放行一轮 +1）。
    generation: AtomicUsize,
}

impl Barrier {
    /// 创建需要 `n` 个线程到齐的屏障。
    pub const fn new(n: usize) -> Self {
        // `n.max(1)` 不能 const（Ord 尚未稳定为 const trait），用手写分支。
        let total = if n == 0 { 1 } else { n };
        Self {
            total,
            arrived: AtomicUsize::new(0),
            generation: AtomicUsize::new(0),
        }
    }

    /// 等待所有线程到达；全部到齐后返回，之后一起放行。
    pub fn wait(&self) {
        let g = self.generation.load(Ordering::Acquire);
        // 抵达：计数加一，取的是加一前的旧值。
        let prev = self.arrived.fetch_add(1, Ordering::AcqRel);
        if prev + 1 == self.total {
            // 最后一个到达者：重置计数并进入下一代，唤醒所有人。
            self.arrived.store(0, Ordering::Release);
            self.generation.fetch_add(1, Ordering::AcqRel);
        } else {
            // 其余线程忙等，直到代际前进。
            while self.generation.load(Ordering::Acquire) == g {
                core::hint::spin_loop();
            }
        }
    }

    /// 当前代际已到达数（调试用）。
    pub fn arrived_count(&self) -> usize {
        self.arrived.load(Ordering::Relaxed)
    }
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::vec::Vec;

    #[test]
    fn single_thread_passes() {
        let b = Barrier::new(1);
        b.wait(); // 一个线程也立即放行（total.max(1)）
    }

    #[test]
    fn all_arrive_then_release() {
        const N: usize = 8;
        let barrier = Arc::new(Barrier::new(N));
        let mut handles = Vec::new();
        for i in 0..N {
            let b = barrier.clone();
            handles.push(std::thread::spawn(move || {
                // 模拟：第 i 个线程到达前做一点"工作"。
                for _ in 0..(i * 1000) {
                    core::hint::spin_loop();
                }
                b.wait();
                // 放行后（应已到齐）可继续。
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // 一轮结束后计数已重置。
        assert_eq!(barrier.arrived_count(), 0);
    }

    #[test]
    fn reusable_multi_round() {
        const N: usize = 4;
        const ROUNDS: usize = 3;
        let barrier = Arc::new(Barrier::new(N));
        let mut handles = Vec::new();
        for _ in 0..N {
            let b = barrier.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..ROUNDS {
                    b.wait();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(barrier.arrived_count(), 0);
    }
}
