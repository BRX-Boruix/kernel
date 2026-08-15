//! 全局 buddy 链表操作。
//!
//! 负责全局空闲链表的分片(pop/push)、双向链表摘除、高阶块分裂、
//! 相邻块合并，以及从未初始化(uninit)区域惰性切块。

use core::sync::atomic::Ordering;

use super::allocator_core::{FrameState, MetadataCache, MAX_ORDER, SHARD_COUNT};
use super::percpu_cache::FreeList;
use super::LazyBuddyAllocator;

impl LazyBuddyAllocator {
    fn shard_for_pfn(pfn: usize) -> usize {
        pfn % SHARD_COUNT
    }

    fn shard_for_cpu(cpu: usize) -> usize {
        cpu % SHARD_COUNT
    }

    fn pop_from_global(&self, order: usize, cpu: usize) -> Option<usize> {
        let start = Self::shard_for_cpu(cpu);
        for offset in 0..SHARD_COUNT {
            let shard = (start + offset) % SHARD_COUNT;
            let mut list = self.lock_global_list(order, shard);
            if let Some(idx) = list.head {
                unsafe {
                    self.remove_from_list_with_list(idx, order, &mut *list);
                    self.reset_frame(idx, order as u8);
                }
                return Some(idx);
            }
        }
        None
    }

    fn push_to_global(&self, pfn: usize, order: usize) {
        let shard = Self::shard_for_pfn(pfn);
        let mut list = self.lock_global_list(order, shard);
        unsafe {
            self.link_frame_as(pfn, order as u8, FrameState::FreeGlobal, list.head);
        }
        if let Some(head_idx) = list.head {
            unsafe {
                let head_frame = self.get_frame(head_idx);
                head_frame.prev = Some(pfn);
            }
        }
        list.head = Some(pfn);
    }

    unsafe fn remove_from_list_with_list(&self, pfn: usize, order: usize, list: &mut FreeList) { unsafe {
        let (prev_idx, next_idx) = {
            let frame = self.get_frame(pfn);
            let prev = frame.prev;
            let next = frame.next;
            frame.next = None;
            frame.prev = None;
            (prev, next)
        };

        if let Some(prev) = prev_idx {
            let prev_frame = self.get_frame(prev);
            prev_frame.next = next_idx;
        } else {
            list.head = next_idx;
        }

        if let Some(next) = next_idx {
            let next_frame = self.get_frame(next);
            next_frame.prev = prev_idx;
        }

        let _ = order; // keep signature parity
    }}

    pub(crate) fn alloc_from_list(&self, order: usize, cpu: usize) -> Option<usize> {
        if let Some(idx) = self.pop_from_global(order, cpu) {
            self.alloc_hit_global.fetch_add(1, Ordering::Relaxed);
            return Some(idx);
        }

        for higher in (order + 1)..MAX_ORDER {
            if let Some(idx) = self.pop_from_global(higher, cpu) {
                self.alloc_hit_global.fetch_add(1, Ordering::Relaxed);
                unsafe {
                    for j in (order..higher).rev() {
                        let buddy_idx = idx + (1 << j);
                        self.reset_frame(buddy_idx, j as u8);
                        self.push_to_global(buddy_idx, j);
                    }
                    self.reset_frame(idx, order as u8);
                }
                return Some(idx);
            }
        }

        None
    }

    pub(crate) fn alloc_from_uninit(&self, order: usize) -> Option<usize> {
        let size = 1 << order;

        let mut uninit = self.uninit.lock();
        let len = uninit.regions.len();
        if len == 0 {
            return None;
        }

        for offset in 0..len {
            let i = (uninit.last_uninit_idx + offset) % len;
            if let Some(mut region) = uninit.regions[i] {
                let aligned_start = (region.start_pfn + size - 1) & !(size - 1);

                if aligned_start + size <= region.end_pfn {
                    // Handle alignment gap by freeing small blocks to buddy system
                    if aligned_start > region.start_pfn {
                        let mut cursor = region.start_pfn;
                        while cursor < aligned_start {
                            let remaining = aligned_start - cursor;
                            let max_fit =
                                (usize::BITS as usize - 1 - remaining.leading_zeros() as usize)
                                    .min(MAX_ORDER - 1);
                            let align_limit = cursor.trailing_zeros() as usize;
                            let order_gap = core::cmp::min(max_fit, align_limit);

                            unsafe {
                                let mut cache = MetadataCache::new();
                                let frame = self.get_frame_with_cache(cursor, &mut cache);
                                self.reset_frame_with(frame, order_gap as u8);
                            }
                            self.free_and_merge(cursor, order_gap);

                            cursor += 1 << order_gap;
                        }
                    }

                    let alloc_start = aligned_start;

                    if alloc_start + size == region.end_pfn {
                        uninit.regions[i] = None;
                    } else {
                        region.start_pfn = alloc_start + size;
                        uninit.regions[i] = Some(region);
                    }
                    uninit.last_uninit_idx = i;

                    return Some(alloc_start);
                }
            }
        }
        None
    }

    pub(crate) fn free_and_merge(&self, mut pfn: usize, mut order: usize) {
        let cfg = self.config();

        while order < MAX_ORDER - 1 {
            let buddy_pfn = pfn ^ (1 << order);
            if buddy_pfn >= cfg.total_frames {
                break;
            }

            let shard = Self::shard_for_pfn(buddy_pfn);
            let mut list = self.lock_global_list(order, shard);
            unsafe {
                let buddy = self.get_frame(buddy_pfn);
                if buddy.state != FrameState::FreeGlobal || buddy.order != order as u8 {
                    break;
                }
                self.remove_from_list_with_list(buddy_pfn, order, &mut *list);
                self.reset_frame_with(buddy, order as u8);
            }
            drop(list);

            if buddy_pfn < pfn {
                pfn = buddy_pfn;
            }
            order += 1;
        }

        self.push_to_global(pfn, order);
    }
}
