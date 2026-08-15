//! 预留(reserve)页管理。
//!
//! 维护一个小的紧急预留池，用于在全局分配完全失败时兜底。

use core::sync::atomic::Ordering;

use klib::logln;

use super::allocator_core::{FrameState, ORDER_4K};
use super::LazyBuddyAllocator;

impl LazyBuddyAllocator {
    pub(crate) fn reserve_pop(&self) -> Option<usize> {
        let mut list = self.reserve_list.lock();
        if let Some(head) = list.head {
            unsafe {
                let frame = self.get_frame(head);
                list.head = frame.next;
                self.reset_frame_with(frame, ORDER_4K as u8);
            }
            self.reserve_count.fetch_sub(1, Ordering::Relaxed);
            return Some(head);
        }
        None
    }

    pub(crate) fn reserve_push(&self, pfn: usize) {
        let mut list = self.reserve_list.lock();
        unsafe {
            self.link_frame_as(pfn, ORDER_4K as u8, FrameState::Allocated, list.head);
        }
        list.head = Some(pfn);
        self.reserve_count.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn init_reserve(&self, pages: usize) {
        let mut added = 0usize;
        while added < pages {
            if let Some(frame) = self.alloc_global(ORDER_4K, 0) {
                self.reserve_push(frame);
                added += 1;
            } else {
                break;
            }
        }
        if added > 0 {
            logln!("PMM: Reserved {} emergency pages", added);
        } else {
            logln!("PMM: WARNING Failed to reserve emergency pages");
        }
    }
}
