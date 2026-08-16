//! 面向外部的页帧分配/释放 API。

use core::sync::atomic::Ordering;

use klib::logln;

use arch::PhysFrame;

use super::allocator_core::{MAX_ORDER, ORDER_4K};
use super::{current_cpu_id, LazyBuddyAllocator};

impl LazyBuddyAllocator {
    /// Allocate a frame of order N
    pub fn allocate(&self, order: usize) -> Option<PhysFrame> {
        if order >= MAX_ORDER {
            return None;
        }

        self.alloc_calls.fetch_add(1, Ordering::Relaxed);
        let cpu = current_cpu_id();

        if let Some(idx) = self
            .percpu_pop(cpu, order)
            .or_else(|| self.percpu_refill(cpu, order))
            .or_else(|| self.alloc_global(order, cpu))
            .or_else(|| {
                if order == ORDER_4K {
                    self.reserve_pop()
                } else {
                    None
                }
            })
        {
            self.allocated_frames
                .fetch_add(1 << order, Ordering::Relaxed);
            return Some(PhysFrame::from_paddr_raw((idx * 4096) as u64));
        }

        // Auto-compact on higher-order failure with throttling.
        if order > ORDER_4K {
            let now = self.alloc_calls.load(Ordering::Relaxed);
            let last = self.compact_last_alloc_call.load(Ordering::Relaxed);
            let min_interval = 1024;
            if now.saturating_sub(last) >= min_interval {
                let max_order = self.max_free_order();
                if max_order < order {
                    self.compact_last_alloc_call.store(now, Ordering::Relaxed);
                    self.compact();
                    if let Some(idx) = self.alloc_global(order, cpu) {
                        self.allocated_frames
                            .fetch_add(1 << order, Ordering::Relaxed);
                        return Some(PhysFrame::from_paddr_raw((idx * 4096) as u64));
                    }
                }
            }
        }

        self.alloc_fail.fetch_add(1, Ordering::Relaxed);
        self.alloc_fail_by_order[order].fetch_add(1, Ordering::Relaxed);
        None
    }

    pub fn deallocate(&self, frame: PhysFrame) {
        self.dealloc_calls.fetch_add(1, Ordering::Relaxed);
        let pfn = frame.start_paddr() as usize / 4096;
        let cfg = self.config();

        if pfn >= cfg.total_frames {
            logln!("PMM: WARNING Deallocate out of bounds pfn {}", pfn);
            return;
        }

        // 无元数据（孔洞）检查：必须在读取帧元数据前完成，避免空指针解引用。
        let block_idx = pfn / cfg.frames_per_block;
        if unsafe { self.block_ptr(block_idx) }.is_null() {
            logln!("PMM: WARNING Deallocate frame with no metadata (hole?): pfn {}", pfn);
            return;
        }

        // 在元数据锁保护下校验状态并读取 order（消除无锁读取的 TOCTOU 数据竞争）：
        // 同时把帧标记为瞬态 Freeing，防止释放完成前被并发重复释放。
        let order = match self.deallocate_checked(pfn) {
            Some(order) => order,
            None => {
                logln!(
                    "PMM: WARNING Double free or invalid free at pfn {}",
                    pfn
                );
                return;
            }
        };

        if order == ORDER_4K && self.reserve_count.load(Ordering::Relaxed) < 32 {
            // reserve_push 会把状态改写回 Allocated 并挂入预留池。
            self.reserve_push(pfn);
        } else {
            let cpu = current_cpu_id();
            // percpu_push 把状态改写为 FreePerCpu，溢出后再由合并路径置为 FreeGlobal。
            self.percpu_push(cpu, pfn, order);
        }

        self.allocated_frames
            .fetch_sub(1 << order, Ordering::Relaxed);
    }
}
