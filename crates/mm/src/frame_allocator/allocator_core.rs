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

use super::FREE_LISTS;
use super::percpu_cache::{FreeList, ReserveList};

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
    /// 已分配（也在未初始化内存的零值语义下成立，故必须为 0）。
    Allocated = 0,
    /// 空闲且挂在全局 buddy 链表上。
    FreeGlobal = 1,
    /// 空闲且挂在 per-CPU 缓存链表上。
    FreePerCpu = 2,
    /// 释放进行中的瞬态：已被 `deallocate` 认领（通过元数据锁校验），
    /// 但尚未来得及挂入空闲链表。既非 `Allocated`（防止并发重复释放），
    /// 也非 `FreeGlobal`（防止被分配/被误当作合并伙伴）。
    Freeing = 3,
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
    /// 两级稀疏页表（L1）。
    /// L1[block_idx >> L1_SHIFT] 指向一个二级表（`*mut BuddyFrame` 数组，长度 L2_ENTRIES），
    /// L2[block_idx & L2_MASK] 指向实际 `BuddyFrame` block。
    /// 二级表仅在 `process_range` 触及相应 L1 项时才按需分配，从而真正稀疏。
    pub(crate) metadata_l1: *mut *mut *mut BuddyFrame,
    pub(crate) metadata_map_len: usize, // 逻辑 block 数（上界），用于边界检查
    pub(crate) frames_per_block: usize,
}

/// 一级表每个条目覆盖的 block 数（2^L1_SHIFT）。
pub(crate) const L1_SHIFT: usize = 10;
/// 一级表条目数 = 2^L1_SHIFT = 1024。
pub(crate) const L1_ENTRIES: usize = 1 << L1_SHIFT;
/// 二级表条目数 = 2^L1_SHIFT = 1024。
pub(crate) const L2_ENTRIES: usize = 1 << L1_SHIFT;
/// 用于索引二级表的掩码。
pub(crate) const L2_MASK: usize = L2_ENTRIES - 1;

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

    /// 分配 `count` 个连续 block（供二级表等需要连续内存的结构使用）。
    /// 返回首 block 的裸字节指针（长度 = count * block_size）。
    pub(crate) fn alloc_blocks(&mut self, count: usize) -> *mut u8 {
        if self.next.saturating_add(count) > self.blocks {
            panic!("PMM: metadata pool exhausted");
        }
        let ptr = unsafe { self.base.add(self.next * self.block_size) };
        self.next += count;
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

    // 通过两级稀疏页表定位 block 指针（*mut BuddyFrame）。
    // 未建 block 的 L2 项为 null；调用方须保证 block 已由 process_range 建立。
    #[inline]
    pub(crate) unsafe fn block_ptr(&self, block_idx: usize) -> *mut BuddyFrame {
        unsafe {
            let cfg = self.config();
            let l1 = cfg.metadata_l1;
            let l1_idx = block_idx >> L1_SHIFT;
            let l2 = *l1.add(l1_idx);
            let l2_idx = block_idx & L2_MASK;
            *l2.add(l2_idx)
        }
    }

    // 返回帧元数据裸指针（**非** `&'static mut`）。
    //
    // 元数据由 shard 链表锁保护，调用方须在持锁临界区内通过裸指针访问。
    // 之所以不返回 `&'static mut`：多 CPU 并发对“同一底层内存”取 `&mut`
    // 即构成别名/noalias 未定义行为（LLVM 可借 noalias 做激进优化而对同一
    // 元数据字节产生交错写）；裸指针不携带独占所有权假设，可安全用于此场景。
    #[inline]
    pub(crate) unsafe fn frame_ptr(&self, pfn: usize) -> *mut BuddyFrame {
        unsafe {
            let cfg = self.config();
            let block_idx = pfn / cfg.frames_per_block;
            let offset = pfn % cfg.frames_per_block;
            let block_ptr = self.block_ptr(block_idx);
            block_ptr.add(offset)
        }
    }

    // 带缓存的等价版本（同一 block 内连续访问时复用 block 指针）。
    #[inline]
    pub(crate) unsafe fn frame_ptr_with_cache(
        &self,
        pfn: usize,
        cache: &mut MetadataCache,
    ) -> *mut BuddyFrame {
        unsafe {
            let cfg = self.config();
            let block_idx = pfn / cfg.frames_per_block;
            let offset = pfn % cfg.frames_per_block;

            if block_idx != cache.block_idx {
                cache.block_ptr = self.block_ptr(block_idx);
                cache.block_idx = block_idx;
            }

            cache.block_ptr.add(offset)
        }
    }

    /// 把一个帧标记为已分配，并脱离所有链表（复位 next/prev/order/migratable）。
    #[inline]
    pub(crate) unsafe fn reset_frame(&self, pfn: usize, order: u8) {
        unsafe {
            self.reset_frame_with(self.frame_ptr(pfn), order);
        }
    }

    /// 复位给定的 `frame` 元数据（调用方已持有帧裸指针，须在持锁临界区内）。
    #[inline]
    pub(crate) unsafe fn reset_frame_with(&self, frame: *mut BuddyFrame, order: u8) {
        unsafe {
            (*frame).order = order;
            (*frame).state = FrameState::Allocated;
            set_flag(&mut (*frame).flags, BF_MIGRATABLE, true);
            (*frame).next = None;
            (*frame).prev = None;
        }
    }

    /// 把一个帧标记为 `state` 状态并链入链表（`next` 为链头）。
    ///
    /// 供 `push_to_global`、`percpu_push_raw`、`reserve_push` 复用，
    /// 统一"写 order/state/migratable/next/prev"五连操作。
    #[inline]
    pub(crate) unsafe fn link_frame_as(
        &self,
        pfn: usize,
        order: u8,
        state: FrameState,
        next: Option<usize>,
    ) {
        let frame = unsafe { self.frame_ptr(pfn) };
        unsafe {
            (*frame).order = order;
            (*frame).state = state;
            set_flag(&mut (*frame).flags, BF_MIGRATABLE, true);
            (*frame).next = next;
            (*frame).prev = None;
        }
    }

    /// 取得某 order 下指定 shard 的全局链表锁，并计入一次全局链表操作。
    pub(crate) fn lock_global_list(
        &self,
        order: usize,
        shard: usize,
    ) -> spin::MutexGuard<'_, FreeList> {
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
