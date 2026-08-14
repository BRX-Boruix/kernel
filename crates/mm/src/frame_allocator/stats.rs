use core::sync::atomic::Ordering;

use super::allocator_core::{MAX_CPUS, MAX_ORDER, SHARD_COUNT};
use super::{ALLOCATOR, FREE_LISTS, PER_CPU};

#[derive(Debug, Clone, Copy)]
pub struct FrameAllocatorStats {
    pub allocated_frames: usize,
    pub alloc_calls: usize,
    pub alloc_hit_percpu: usize,
    pub alloc_refill: usize,
    pub alloc_hit_global: usize,
    pub alloc_hit_uninit: usize,
    pub alloc_fail: usize,
    pub alloc_fail_by_order: [usize; MAX_ORDER],
    pub dealloc_calls: usize,
    pub global_list_ops: usize,
    pub reserve_count: usize,
    pub compact_calls: usize,
    pub compact_drained: usize,
    pub compact_success: usize,
    pub compact_last_before: usize,
    pub compact_last_after: usize,
}

#[derive(Debug, Clone)]
pub struct PmmFragStats {
    pub max_order: usize,
    pub free_global_by_order: [usize; MAX_ORDER],
    pub free_percpu_by_order: [usize; MAX_ORDER],
    pub uninit_frames: usize,
}

pub fn stats() -> FrameAllocatorStats {
    FrameAllocatorStats {
        allocated_frames: ALLOCATOR.allocated_frames.load(Ordering::Relaxed),
        alloc_calls: ALLOCATOR.alloc_calls.load(Ordering::Relaxed),
        alloc_hit_percpu: ALLOCATOR.alloc_hit_percpu.load(Ordering::Relaxed),
        alloc_refill: ALLOCATOR.alloc_refill.load(Ordering::Relaxed),
        alloc_hit_global: ALLOCATOR.alloc_hit_global.load(Ordering::Relaxed),
        alloc_hit_uninit: ALLOCATOR.alloc_hit_uninit.load(Ordering::Relaxed),
        alloc_fail: ALLOCATOR.alloc_fail.load(Ordering::Relaxed),
        alloc_fail_by_order: core::array::from_fn(|i| {
            ALLOCATOR.alloc_fail_by_order[i].load(Ordering::Relaxed)
        }),
        dealloc_calls: ALLOCATOR.dealloc_calls.load(Ordering::Relaxed),
        global_list_ops: ALLOCATOR.global_list_ops.load(Ordering::Relaxed),
        reserve_count: ALLOCATOR.reserve_count.load(Ordering::Relaxed),
        compact_calls: ALLOCATOR.compact_calls.load(Ordering::Relaxed),
        compact_drained: ALLOCATOR.compact_drained.load(Ordering::Relaxed),
        compact_success: ALLOCATOR.compact_success.load(Ordering::Relaxed),
        compact_last_before: ALLOCATOR.compact_last_before.load(Ordering::Relaxed),
        compact_last_after: ALLOCATOR.compact_last_after.load(Ordering::Relaxed),
    }
}

pub fn frag_stats() -> PmmFragStats {
    let mut free_global = [0usize; MAX_ORDER];
    let mut free_percpu = [0usize; MAX_ORDER];

    if let Some(lists) = FREE_LISTS.get() {
        for order in 0..MAX_ORDER {
            for shard in 0..SHARD_COUNT {
                let list = lists.orders[order].shards[shard].lock();
                let mut cur = list.head;
                while let Some(pfn) = cur {
                    free_global[order] += 1;
                    unsafe {
                        let frame = ALLOCATOR.get_frame(pfn);
                        cur = frame.next;
                    }
                }
            }
        }
    }

    for cpu in 0..MAX_CPUS {
        PER_CPU.with_cache(cpu, |cache| {
            for order in 0..MAX_ORDER {
                free_percpu[order] += cache.counts[order] as usize;
            }
        });
    }

    let mut uninit_frames = 0usize;
    {
        let uninit = ALLOCATOR.uninit.lock();
        for region in uninit.regions.iter().flatten() {
            uninit_frames = uninit_frames.saturating_add(region.end_pfn - region.start_pfn);
        }
    }

    let mut max_order = 0usize;
    for order in (0..MAX_ORDER).rev() {
        if free_global[order] + free_percpu[order] > 0 {
            max_order = order;
            break;
        }
    }

    PmmFragStats {
        max_order,
        free_global_by_order: free_global,
        free_percpu_by_order: free_percpu,
        uninit_frames,
    }
}

pub fn reset_stats() {
    ALLOCATOR.alloc_calls.store(0, Ordering::Relaxed);
    ALLOCATOR.alloc_hit_percpu.store(0, Ordering::Relaxed);
    ALLOCATOR.alloc_refill.store(0, Ordering::Relaxed);
    ALLOCATOR.alloc_hit_global.store(0, Ordering::Relaxed);
    ALLOCATOR.alloc_hit_uninit.store(0, Ordering::Relaxed);
    ALLOCATOR.alloc_fail.store(0, Ordering::Relaxed);
    for i in 0..MAX_ORDER {
        ALLOCATOR.alloc_fail_by_order[i].store(0, Ordering::Relaxed);
    }
    ALLOCATOR.dealloc_calls.store(0, Ordering::Relaxed);
    ALLOCATOR.global_list_ops.store(0, Ordering::Relaxed);
}
