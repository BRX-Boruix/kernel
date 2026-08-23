use core::sync::atomic::Ordering;

use super::allocator_core::{MAX_ORDER, for_each_global_list};
use super::{ALLOCATOR, PER_CPU};

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

/// 集中式装载/清零全部原子计数器。
/// `counter_stats!(load)` 构造 `FrameAllocatorStats`；`counter_stats!(reset)` 把可清零计数器写回 0。
macro_rules! counter_stats {
    (load) => {{
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
    }};
    (reset) => {{
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
    }};
}

/// 物理分配器碎片统计。
///
/// `free_percpu_by_order` 仅覆盖**当前 CPU** 缓存（所有权不变量，mm1.md MA1）；
/// 其它 CPU 缓存中的空闲页不在此列，消费方不得把该字段当作全系统 per-CPU 总和。
///
/// 审计 B8 投影裁决：SysFS `memory_json`（vfs_init.rs）**只**消费全局
/// `allocated_frames` 派生值，不投影本字段——percpu 语义（当前核私有视图）
/// 与 sysfs"全系统状态文件"的读者预期不符，宁缺勿谎。未来若要暴露 per-CPU
/// 视图，必须以显式 `per_cpu_free_bytes` 字段名 + 文档标注采样语义，不得
/// 混入 capacity/allocated/free 全局三元组。
#[derive(Debug, Clone)]
pub struct PmmFragStats {
    pub max_order: usize,
    pub free_global_by_order: [usize; MAX_ORDER],
    pub free_percpu_by_order: [usize; MAX_ORDER],
    pub uninit_frames: usize,
}

pub fn stats() -> FrameAllocatorStats {
    counter_stats!(load)
}

pub fn frag_stats() -> PmmFragStats {
    let mut free_global = [0usize; MAX_ORDER];
    let mut free_percpu = [0usize; MAX_ORDER];

    for_each_global_list(|order, _shard, list| {
        let mut cur = list.head;
        while let Some(pfn) = cur {
            free_global[order] += 1;
            unsafe {
                let frame = ALLOCATOR.frame_ptr(pfn);
                cur = (*frame).next;
            }
        }
    });

    // per-CPU 部分只读**当前 CPU** 槽的计数（所有权不变量，mm1.md MA1：
    // with_cache 是无锁裸指针转发，跨槽读取在多核下是数据竞争）。诊断统计
    // 宁可少报其它 CPU 的缓存页，也不破坏属主排他性。
    let current_cpu = super::current_cpu_id();
    debug_assert!(current_cpu < PER_CPU.cpu_count(), "cpu slot out of range");
    if current_cpu < PER_CPU.cpu_count() {
        PER_CPU.with_cache(current_cpu, |cache| {
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
    counter_stats!(reset);
}
