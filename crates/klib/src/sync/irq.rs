//! 中断安全锁（`IrqSpinLock`）。
//!
//! 在 [`super::spin::SpinMutex`] 之上加"关中断 + 保存/恢复 FLAGS"：
//! - 加锁：保存当前中断状态 → `cli` → 自旋获取锁；
//! - 解锁：释放自旋锁 → 恢复保存的中断状态（若原来中断是开的则重新打开）。
//!
//! 这避免了多核/中断嵌套死锁：
//! - 中断处理程序与本 CPU 主线程竞争同一把锁时，主线程已关中断，
//!   不会被中断打断、从而永远不释放锁（经典的"死锁"场景）；
//! - 不同 CPU 之间仍靠自旋互斥。
//!
//! `klib` 保持零依赖（不依赖 `arch`/`x86`），因此"保存/恢复 FLAGS"通过
//! 函数指针在运行时由架构层注入（与 console 的 sink 注入同理）。
//! 未注入时退化为普通自旋锁（单 CPU / 测试环境足够）。

use super::spin::{SpinMutex, SpinMutexGuard};
use core::sync::atomic::{AtomicUsize, Ordering};

/// 保存当前中断状态并关中断，返回保存的旧状态（不透明 token）。
pub type IrqSaveFn = fn() -> usize;
/// 恢复此前保存的中断状态。
pub type IrqRestoreFn = fn(usize);

static IRQ_SAVE: AtomicUsize = AtomicUsize::new(0);
static IRQ_RESTORE: AtomicUsize = AtomicUsize::new(0);

/// 由架构层注入"保存/关中断"与"恢复"函数。
///
/// 例：x86_64 下 `save = pushfq & cli 返回旧 FLAGS`，`restore = popfq`。
pub fn set_irq_guard(save: IrqSaveFn, restore: IrqRestoreFn) {
    IRQ_SAVE.store(save as usize, Ordering::SeqCst);
    IRQ_RESTORE.store(restore as usize, Ordering::SeqCst);
}

fn irq_save() -> usize {
    let v = IRQ_SAVE.load(Ordering::Acquire);
    if v != 0 {
        unsafe { core::mem::transmute::<usize, IrqSaveFn>(v)() }
    } else {
        0 // 未注入：退化为普通自旋锁
    }
}

fn irq_restore(saved: usize) {
    if IRQ_SAVE.load(Ordering::Acquire) != 0 {
        let v = IRQ_RESTORE.load(Ordering::Acquire);
        unsafe { core::mem::transmute::<usize, IrqRestoreFn>(v)(saved) };
    }
}

/// 中断安全自旋锁。
pub struct IrqSpinLock<T> {
    inner: SpinMutex<T>,
}

unsafe impl<T: Send> Sync for IrqSpinLock<T> {}
unsafe impl<T: Send> Send for IrqSpinLock<T> {}

impl<T> IrqSpinLock<T> {
    /// 常量构造（可用于 `static`）。
    pub const fn new(data: T) -> Self {
        Self {
            inner: SpinMutex::new(data),
        }
    }

    /// 保存中断状态 → 关中断 → 忙等获取锁。
    pub fn lock(&self) -> IrqSpinLockGuard<'_, T> {
        let saved = irq_save();
        let guard = self.inner.lock();
        IrqSpinLockGuard {
            guard: Some(guard),
            saved,
        }
    }

    /// 非阻塞尝试；失败返回 `None`（已恢复中断状态）。
    pub fn try_lock(&self) -> Option<IrqSpinLockGuard<'_, T>> {
        let saved = irq_save();
        match self.inner.try_lock() {
            Some(guard) => Some(IrqSpinLockGuard {
                guard: Some(guard),
                saved,
            }),
            None => {
                irq_restore(saved);
                None
            }
        }
    }
}

/// 中断安全锁的 guard：析构时先释放自旋锁，再恢复中断状态。
///
/// `guard` 用 `Option` 包装：`Drop` 中 `take()` 显式释放内部锁（guard 字段
/// 赋值 `None` 即触发其析构），保证在恢复中断**之前**锁已可被其他 CPU 抢占。
pub struct IrqSpinLockGuard<'a, T> {
    guard: Option<SpinMutexGuard<'a, T>>,
    saved: usize,
}

impl<T> core::ops::Deref for IrqSpinLockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.guard.as_ref().unwrap().deref()
    }
}

impl<T> core::ops::DerefMut for IrqSpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.guard.as_mut().unwrap().deref_mut()
    }
}

impl<T> Drop for IrqSpinLockGuard<'_, T> {
    fn drop(&mut self) {
        // 先放锁再恢复中断：保证在重新打开中断前，锁已可被其他 CPU 抢占。
        self.guard = None;
        irq_restore(self.saved);
    }
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::vec::Vec;

    /// 测试环境不注入真实架构函数 → 退化为普通自旋锁，行为仍必须正确。
    #[test]
    fn unguarded_fallback_works() {
        let l = IrqSpinLock::new(0u32);
        {
            let mut g = l.lock();
            *g = 7;
        }
        assert_eq!(*l.lock(), 7);
    }

    #[test]
    fn try_lock_contended() {
        let l = IrqSpinLock::new(0u32);
        let g = l.try_lock().expect("first succeeds");
        assert!(l.try_lock().is_none(), "second must fail");
        drop(g);
        assert!(l.try_lock().is_some());
    }

    #[test]
    fn stress_contention() {
        let l = Arc::new(IrqSpinLock::new(0u64));
        let c = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let l_ref = l.clone();
            let c_ref = c.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..5000 {
                    let mut g = l_ref.lock();
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
        assert_eq!(*l.lock(), 8 * 5000);
    }
}
