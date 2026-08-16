//! LazyBuddy 物理页帧分配器核心类型与元数据访问。
//!
//! 惰性初始化的 buddy allocator：启动时不初始化整片内存，只记录
//! `uninit_regions`，分配时按需切块并惰性建立 buddy 元数据。
//!
//! 本文件仅保留核心数据结构、常量与元数据访问/链表辅助方法。
//! 初始化、分配/释放、per-CPU、预留、压缩逻辑分别拆到
//! `init` / `buddy` / `percpu` / `reserve` / `compact` / `api` 子模块。

use core::sync::atomic::{AtomicUsize, Ordering};

use spin::{Mutex, Once};

use super::percpu_cache::{FreeList, ReserveList};
use super::FREE_LISTS;

/// Buddy 系统的 order 数（order 0..MAX_ORDER-1 有效）。
///
/// 最大可用 order = MAX_ORDER-1，单次最大连续分配 = 2^(MAX_ORDER-1) × 4KB。
/// 取 41 使 order 0..40 覆盖到 x86-64 物理地址空间理论上限 4PB
/// （2^40 × 4KB = 4PB），从而不再限制大内存机器上的大连续块分配/合并。
/// （原值 19 把单次分配上限限制在 order 18 = 1GB，仅为容纳 1GB 大页。）
pub(crate) const MAX_ORDER: usize = 41;
/// Lock sharding count for each order
pub(crate) const SHARD_COUNT: usize = 8;

/// Standard page size order
pub const ORDER_4K: usize = 0;
/// Huge page size (2MB) order
pub const ORDER_2M: usize = 9;
/// Huge page size (1GB) order
pub const ORDER_1G: usize = 18;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum FrameState {
    Allocated = 0,
    FreeGlobal = 1,
    FreePerCpu = 2,
}

/// Metadata for a physical frame
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub(crate) struct BuddyFrame {
    pub(crate) order: u8,
    pub(crate) state: FrameState,
    pub(crate) flags: u8,
    // Using index for next pointer to avoid pointer complexity in static array
    pub(crate) next: Option<usize>,
    pub(crate) prev: Option<usize>,
}

pub(crate) const BF_MIGRATABLE: u8 = 1 << 0;

impl BuddyFrame {
    pub(crate) const fn new() -> Self {
        Self {
            order: 0,
            state: FrameState::Allocated,
            flags: BF_MIGRATABLE,
            next: None,
            prev: None,
        }
    }
}

#[inline]
fn set_flag(flags: &mut u8, mask: u8, on: bool) {
    if on {
        *flags |= mask;
    } else {
        *flags &= !mask;
    }
}

/// 向上对齐到 4KB 边界。
#[inline]
pub(crate) const fn align_4k(v: usize) -> usize {
    (v + 4095) & !4095
}

/// 遍历所有全局空闲链表（每个 order/shard），对已加锁的 `FreeList` 调用 `f(order, shard, &mut list)`。
pub(crate) fn for_each_global_list(mut f: impl FnMut(usize, usize, &mut FreeList)) {
    if let Some(lists) = FREE_LISTS.get() {
        for order in 0..MAX_ORDER {
            for shard in 0..SHARD_COUNT {
                let mut list = lists.orders[order].shards[shard].lock();
                f(order, shard, &mut list);
            }
        }
    }
}

/// Represents a region of physical memory that hasn't been initialized into the buddy system yet
#[derive(Debug, Clone, Copy)]
pub(crate) struct UninitRegion {
    pub(crate) start_pfn: usize,
    pub(crate) end_pfn: usize,
}

pub(crate) struct AllocatorConfig {
    pub(crate) total_frames: usize,
    pub(crate) metadata_map: *mut *mut BuddyFrame,
    pub(crate) metadata_map_len: usize,
    pub(crate) frames_per_block: usize,
}

pub(crate) struct UninitState {
    pub(crate) regions: &'static mut [Option<UninitRegion>],
    pub(crate) last_uninit_idx: usize,
}

impl UninitState {
    const fn empty() -> Self {
        Self {
            regions: &mut [],
            last_uninit_idx: 0,
        }
    }
}

/// 元数据块分配池：从预留的一段连续物理内存中逐块切出 `BuddyFrame` 数组。
pub(crate) struct MetadataPool {
    pub(crate) base: *mut u8,
    pub(crate) blocks: usize,
    pub(crate) next: usize,
    pub(crate) block_size: usize,
}

impl MetadataPool {
    pub(crate) fn alloc_block(&mut self) -> *mut BuddyFrame {
        if self.next >= self.blocks {
            panic!("PMM: metadata pool exhausted");
        }
        let ptr = unsafe { self.base.add(self.next * self.block_size) } as *mut BuddyFrame;
        self.next += 1;
        ptr
    }
}

pub(crate) struct LazyBuddyAllocator {
    pub(crate) config: Once<AllocatorConfig>,
    pub(crate) uninit: Mutex<UninitState>,
    pub(crate) allocated_frames: AtomicUsize,
    pub(crate) alloc_calls: AtomicUsize,
    pub(crate) alloc_hit_percpu: AtomicUsize,
    pub(crate) alloc_refill: AtomicUsize,
    pub(crate) alloc_hit_global: AtomicUsize,
    pub(crate) alloc_hit_uninit: AtomicUsize,
    pub(crate) alloc_fail: AtomicUsize,
    pub(crate) alloc_fail_by_order: [AtomicUsize; MAX_ORDER],
    pub(crate) dealloc_calls: AtomicUsize,
    pub(crate) global_list_ops: AtomicUsize,
    pub(crate) reserve_list: Mutex<ReserveList>,
    pub(crate) reserve_count: AtomicUsize,
    pub(crate) compact_calls: AtomicUsize,
    pub(crate) compact_drained: AtomicUsize,
    pub(crate) compact_success: AtomicUsize,
    pub(crate) compact_last_before: AtomicUsize,
    pub(crate) compact_last_after: AtomicUsize,
    pub(crate) compact_last_alloc_call: AtomicUsize,
}

impl LazyBuddyAllocator {
    pub(crate) const fn new() -> Self {
        Self {
            config: Once::new(),
            uninit: Mutex::new(UninitState::empty()),
            allocated_frames: AtomicUsize::new(0),
            alloc_calls: AtomicUsize::new(0),
            alloc_hit_percpu: AtomicUsize::new(0),
            alloc_refill: AtomicUsize::new(0),
            alloc_hit_global: AtomicUsize::new(0),
            alloc_hit_uninit: AtomicUsize::new(0),
            alloc_fail: AtomicUsize::new(0),
            alloc_fail_by_order: [const { AtomicUsize::new(0) }; MAX_ORDER],
            dealloc_calls: AtomicUsize::new(0),
            global_list_ops: AtomicUsize::new(0),
            reserve_list: Mutex::new(ReserveList::new()),
            reserve_count: AtomicUsize::new(0),
            compact_calls: AtomicUsize::new(0),
            compact_drained: AtomicUsize::new(0),
            compact_success: AtomicUsize::new(0),
            compact_last_before: AtomicUsize::new(0),
            compact_last_after: AtomicUsize::new(0),
            compact_last_alloc_call: AtomicUsize::new(0),
        }
    }

    pub(crate) fn config(&self) -> &AllocatorConfig {
        self.config.get().expect("PMM not initialized")
    }

    // Helper to access frame metadata
    pub(crate) unsafe fn get_frame(&self, pfn: usize) -> &'static mut BuddyFrame { unsafe {
        let cfg = self.config();
        let block_idx = pfn / cfg.frames_per_block;
        let offset = pfn % cfg.frames_per_block;
        let block_ptr = *cfg.metadata_map.add(block_idx);
        &mut *block_ptr.add(offset)
    }}

    // Optimized helper with cache
    pub(crate) unsafe fn get_frame_with_cache(
        &self,
        pfn: usize,
        cache: &mut MetadataCache,
    ) -> &'static mut BuddyFrame { unsafe {
        let cfg = self.config();
        let block_idx = pfn / cfg.frames_per_block;
        let offset = pfn % cfg.frames_per_block;

        if block_idx != cache.block_idx {
            cache.block_ptr = *cfg.metadata_map.add(block_idx);
            cache.block_idx = block_idx;
        }

        &mut *cache.block_ptr.add(offset)
    }}

    /// 把一个帧标记为已分配，并脱离所有链表（复位 next/prev/order/migratable）。
    #[inline]
    pub(crate) unsafe fn reset_frame(&self, pfn: usize, order: u8) {
        unsafe {
            self.reset_frame_with(self.get_frame(pfn), order);
        }
    }

    /// 复位给定的 `frame` 元数据（调用方已持有帧引用）。
    #[inline]
    pub(crate) unsafe fn reset_frame_with(&self, frame: &'static mut BuddyFrame, order: u8) {
        frame.order = order;
        frame.state = FrameState::Allocated;
        set_flag(&mut frame.flags, BF_MIGRATABLE, true);
        frame.next = None;
        frame.prev = None;
    }

    /// 把一个帧标记为 `state` 状态并链入链表（`next` 为链头）。
    ///
    /// 供 `push_to_global`、`percpu_push_raw`、`reserve_push` 复用，
    /// 统一"写 order/state/migratable/next/prev"五连操作。
    #[inline]
    pub(crate) unsafe fn link_frame_as(&self, pfn: usize, order: u8, state: FrameState, next: Option<usize>) {
        unsafe {
            let frame = self.get_frame(pfn);
            frame.order = order;
            frame.state = state;
            set_flag(&mut frame.flags, BF_MIGRATABLE, true);
            frame.next = next;
            frame.prev = None;
        }
    }

    /// 取得某 order 下指定 shard 的全局链表锁，并计入一次全局链表操作。
    pub(crate) fn lock_global_list(&self, order: usize, shard: usize) -> spin::MutexGuard<'_, FreeList> {
        let lists = FREE_LISTS.get().expect("PMM free lists not initialized");
        self.global_list_ops.fetch_add(1, Ordering::Relaxed);
        lists.orders[order].shards[shard].lock()
    }
}

pub(crate) struct MetadataCache {
    block_idx: usize,
    block_ptr: *mut BuddyFrame,
}

impl MetadataCache {
    pub(crate) fn new() -> Self {
        Self {
            block_idx: usize::MAX,
            block_ptr: core::ptr::null_mut(),
        }
    }
}
