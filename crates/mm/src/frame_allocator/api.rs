//! 面向外部的页帧分配/释放 API。

use core::sync::atomic::Ordering;

use klib::logln;

use arch::PhysFrame;

use super::allocator_core::{FrameState, MAX_ORDER, ORDER_4K};
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

        let order = unsafe {
            let block_idx = pfn / cfg.frames_per_block;
            if (*cfg.metadata_map.add(block_idx)).is_null() {
                logln!("PMM: WARNING Deallocate frame with no metadata (hole?): pfn {}", pfn);
                return;
            }

            let frame_meta = self.get_frame(pfn);
            if frame_meta.state != FrameState::Allocated {
                logln!(
                    "PMM: WARNING Double free or invalid free at pfn {} state {:?}",
                    pfn, frame_meta.state
                );
                return;
            }
            frame_meta.order as usize
        };

        if order == ORDER_4K && self.reserve_count.load(Ordering::Relaxed) < 32 {
            self.reserve_push(pfn);
        } else {
            let cpu = current_cpu_id();
            self.percpu_push(cpu, pfn, order);
        }

        self.allocated_frames
            .fetch_sub(1 << order, Ordering::Relaxed);
    }
}
