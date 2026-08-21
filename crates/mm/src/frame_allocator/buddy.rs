//! 全局 buddy 链表操作。
//!
//! 负责全局空闲链表的分片(pop/push)、双向链表摘除、高阶块分裂、
//! 相邻块合并，以及从未初始化(uninit)区域惰性切块。

use core::sync::atomic::Ordering;

use super::LazyBuddyAllocator;
use super::allocator_core::{FrameState, MAX_ORDER, MetadataCache, SHARD_COUNT};
use super::percpu_cache::FreeList;

impl LazyBuddyAllocator {
    /// 帧 → shard 的"分组粒度"：同一 (pfn>>SHARD_PFN_SHIFT) 区间内的帧共享同一 shard。
    ///
    /// 关键不变量：buddy 对 (pfn, pfn ^ (1<<order)) 仅在 bit `order` 上相异。
    /// 当 `order < SHARD_PFN_SHIFT` 时，翻转该低位不改变高位 `pfn >> SHARD_PFN_SHIFT`，
    /// 因此一对 buddy **必然落在同一 shard**。这使 `free_and_merge` 的
    /// "检查 buddy 状态 → 从链表摘除 → 合并后挂回"能在同一把 shard 锁内原子完成，
    /// 从根本上消除跨 shard 合并的 TOCTOU 竞态（否则相邻 4K 帧几乎总跨 shard，
    /// 既引发并发竞态窗口，又令大量 order-0 合并跨锁串行）。
    ///
    /// 取 12 覆盖 order 0..11（最高 8MiB 块）的合并始终同 shard；
    /// order ≥ 12 的超大块理论上仍可跨 shard，但其合并本就安全（仅靠 Freeing 态守卫，
    /// 不会损坏链表），且极少触发，故无需特殊处理。
    const SHARD_PFN_SHIFT: usize = 12;

    fn shard_for_pfn(pfn: usize) -> usize {
        (pfn >> Self::SHARD_PFN_SHIFT) % SHARD_COUNT
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
                let head_frame = self.frame_ptr(head_idx);
                (*head_frame).prev = Some(pfn);
            }
        }
        list.head = Some(pfn);
    }

    unsafe fn remove_from_list_with_list(&self, pfn: usize, order: usize, list: &mut FreeList) {
        unsafe {
            let (prev_idx, next_idx) = {
                let frame = self.frame_ptr(pfn);
                let prev = (*frame).prev;
                let next = (*frame).next;
                (*frame).next = None;
                (*frame).prev = None;
                (prev, next)
            };

            if let Some(prev) = prev_idx {
                let prev_frame = self.frame_ptr(prev);
                (*prev_frame).next = next_idx;
            } else {
                list.head = next_idx;
            }

            if let Some(next) = next_idx {
                let next_frame = self.frame_ptr(next);
                (*next_frame).prev = prev_idx;
            }

            let _ = order; // keep signature parity
        }
    }

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
                                let frame = self.frame_ptr_with_cache(cursor, &mut cache);
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

            let pfn_shard = Self::shard_for_pfn(pfn);
            let buddy_shard = Self::shard_for_pfn(buddy_pfn);

            // 守卫：仅当 buddy 与当前被释放块处于**同一 shard** 时才尝试合并。
            // 这样本轮摘除（`lock_global_list(order, buddy_shard)`）与末尾的
            // `push_to_global(pfn, order)`（锁 `shard_for_pfn(pfn)`）必然落在同一把
            // shard 锁内，整个合并对其它 CPU 原子可见，彻底消除跨 shard 合并的
            // TOCTOU / 双重摘链竞态。
            //
            // `shard_for_pfn` 已保证 `order < SHARD_PFN_SHIFT` 时 buddy 必与 pfn 同 shard，
            // 故 order 0..11 的合并（最常见）永不触发此 break；仅 order 12..14 且恰好跨
            // shard 边界时放弃合并（最多损失一个 8/16/32 MiB 块的合并，属良性碎片，极罕见）。
            if pfn_shard != buddy_shard {
                break;
            }

            let mut list = self.lock_global_list(order, buddy_shard);
            unsafe {
                let buddy = self.frame_ptr(buddy_pfn);
                if (*buddy).state != FrameState::FreeGlobal || (*buddy).order != order as u8 {
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

    /// 在持有帧所属 shard 的 order-0 元数据锁期间完成状态校验与 order 读取，
    /// 并把帧状态置为瞬态 `Freeing`，从而消除 `deallocate` 无锁读取元数据带来的
    /// TOCTOU 数据竞争（double-free / order 漂移）。
    ///
    /// 返回该帧被释放时的 order；若帧非 `Allocated`（double-free 或无效释放）
    /// 返回 `None`。调用方随后应通过 `reserve_push` / `percpu_push` 把状态改写为
    /// `Allocated` / `FreePerCpu`，最终由合并路径置为 `FreeGlobal`。
    ///
    /// 锁序说明：此处仅短暂持有 `orders[0].shards[shard]`，校验并标记后立即释放，
    /// 不会与 `free_and_merge` 内部持有的 order>0 链表锁形成嵌套，故无死锁/自死锁。
    pub(crate) fn deallocate_checked(&self, pfn: usize) -> Option<usize> {
        let shard = Self::shard_for_pfn(pfn);
        // 以该 shard 的 order-0 链表锁作为该 shard 内所有帧元数据的保护锁。
        let meta_guard = self.lock_global_list(0, shard);
        let order = unsafe {
            let frame_meta = self.frame_ptr(pfn);
            if (*frame_meta).state != FrameState::Allocated {
                // 双重释放或无效释放：元数据锁保护下判定，杜绝并发重复释放。
                return None;
            }
            // 认领该帧：置为瞬态 Freeing，防止元数据锁释放后、状态被改写前的
            // 窗口中被另一个 CPU 重复释放。
            (*frame_meta).state = FrameState::Freeing;
            (*frame_meta).order as usize
        };
        drop(meta_guard);
        Some(order)
    }
}
