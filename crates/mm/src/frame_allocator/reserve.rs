//! 预留(reserve)页管理。
//!
//! 维护一个小的紧急预留池，用于在全局分配完全失败时兜底。

use core::sync::atomic::Ordering;

use klib::{info, warn};

use super::LazyBuddyAllocator;
use super::allocator_core::{FrameState, ORDER_4K};

impl LazyBuddyAllocator {
    pub(crate) fn reserve_pop(&self) -> Option<usize> {
        let mut list = self.reserve_list.lock();
        if let Some(head) = list.head {
            unsafe {
                let frame = self.frame_ptr(head);
                list.head = (*frame).next;
                self.reset_frame_with(frame, ORDER_4K as u8);
            }
            self.reserve_count.fetch_sub(1, Ordering::Relaxed);
            return Some(head);
        }
        None
    }

    /// 紧急预留池容量上限（单位：4K 页）。
    ///
    /// 固定上限保证 reserve 池只保留少量兜底页，不会随反复 churn 无限增长。
    const RESERVE_CAP: usize = 32;

    pub(crate) fn reserve_push(&self, pfn: usize) {
        let mut list = self.reserve_list.lock();
        // 把"容量判断"与"入池"收敛到同一临界区内：多 CPU 并发释放时，
        // 不会出现都通过 `< RESERVE_CAP` 检查、从而令 reserve_count 超出上限的情况。
        if self.reserve_count.load(Ordering::Relaxed) >= Self::RESERVE_CAP {
            // 池已满：先释放 reserve 锁，再回收到全局 buddy（可参与后续合并），
            // 避免这些 4K 帧被 reserve 池独占、永不合并而加剧碎片化。
            drop(list);
            self.free_and_merge(pfn, ORDER_4K);
            return;
        }
        unsafe {
            self.link_frame_as(pfn, ORDER_4K as u8, FrameState::Allocated, list.head);
        }
        list.head = Some(pfn);
        self.reserve_count.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn init_reserve(&self, pages: usize) {
        let mut added = 0usize;
        let mut first_pfn = 0usize;
        let mut last_pfn = 0usize;
        while added < pages {
            if let Some(pfn) = self.alloc_global(ORDER_4K, 0) {
                if added == 0 {
                    first_pfn = pfn;
                }
                last_pfn = pfn;
                self.reserve_push(pfn);
                added += 1;
            } else {
                break;
            }
        }
        if added > 0 {
            info!(
                "PMM: Reserved {} emergency pages (pfn {}..{} = phys 0x{:x}-0x{:x})",
                added,
                first_pfn,
                last_pfn,
                first_pfn * 4096,
                last_pfn * 4096
            );
        } else {
            warn!("PMM: Failed to reserve emergency pages");
        }
    }
}
