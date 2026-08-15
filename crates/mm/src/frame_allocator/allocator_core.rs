//! LazyBuddy 物理页帧分配器核心。
//!
//! 惰性初始化的 buddy allocator：启动时不初始化整片内存，只记录
//! `uninit_regions`，分配时按需切块并惰性建立 buddy 元数据。
//!
//! 精简自旧项目 `mm::frame_allocator`，去除了 x86 依赖、rmap/mapper
//! 相关的页面迁移逻辑，改为架构无关的类型与 `klib` 日志。

use core::mem::size_of;
use core::slice;
use core::sync::atomic::{AtomicUsize, Ordering};

use limine::{MemmapEntry, MemoryMapEntryType, NonNullPtr};
use klib::logln;
use spin::{Mutex, Once};

use crate::{PhysAddr, PhysFrame};

use super::percpu_cache::{FreeList, FreeListTable, ReserveList};
use super::{current_cpu_id, FREE_LISTS, PER_CPU};

/// Max order for buddy system (2^19 * 4KB = 2GB blocks covers 1GB huge pages)
pub(crate) const MAX_ORDER: usize = 19;
/// Lock sharding count for each order
pub(crate) const SHARD_COUNT: usize = 8;
/// Max CPUs for per-CPU caches
pub(crate) const MAX_CPUS: usize = 64;
/// Buffer for uninit regions count to handle fragmentation
const PADDING_REGIONS: usize = 16;

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
    const fn new() -> Self {
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

struct MetadataPool {
    base: *mut u8,
    blocks: usize,
    next: usize,
    block_size: usize,
}

impl MetadataPool {
    fn alloc_block(&mut self) -> *mut BuddyFrame {
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
    unsafe fn get_frame_with_cache(
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

    // Helper to find contiguous memory for metadata structures (O(N))
    fn find_metadata_storage(
        mmap: &[NonNullPtr<MemmapEntry>],
        metadata_map_size: usize,
        uninit_regions_size: usize,
        metadata_pool_size: usize,
        counts_size: usize,
    ) -> (usize, usize, usize, usize) {
        const MIN_METADATA_BASE: usize = 0x0010_0000; // 1MiB guard to avoid low memory/HHDM corner cases
        let entries = mmap.iter().map(|e| unsafe { &*e.as_ptr() });

        let align = |v: usize| (v + 4095) & !4095;
        let total_size = align(metadata_map_size)
            + align(uninit_regions_size)
            + align(counts_size)
            + align(metadata_pool_size);
        let map_uninit_size =
            align(metadata_map_size) + align(uninit_regions_size) + align(counts_size);

        let mut best_total: Option<(usize, usize)> = None;
        let mut best_pool: Option<(usize, usize)> = None;
        let mut best_map: Option<(usize, usize)> = None;

        for entry in entries.clone() {
            if entry.typ != MemoryMapEntryType::Usable {
                continue;
            }
            let base = entry.base as usize;
            let len = entry.len as usize;
            if base < MIN_METADATA_BASE {
                continue;
            }
            let aligned_base = align(base);
            let avail = len.saturating_sub(aligned_base.saturating_sub(base));

            if avail >= total_size {
                if best_total.map_or(true, |b| avail > b.1) {
                    best_total = Some((base, avail));
                }
            }
            if avail >= metadata_pool_size {
                if best_pool.map_or(true, |b| avail > b.1) {
                    best_pool = Some((base, avail));
                }
            }
            if avail >= map_uninit_size {
                if best_map.map_or(true, |b| avail > b.1) {
                    best_map = Some((base, avail));
                }
            }
        }

        if let Some((base, avail)) = best_total {
            let map_paddr = align(base);
            let uninit_paddr = align(map_paddr + metadata_map_size);
            let counts_paddr = align(uninit_paddr + uninit_regions_size);
            let pool_paddr = align(counts_paddr + counts_size);
            let end = pool_paddr + metadata_pool_size;
            if end > base + avail {
                panic!("PMM: metadata placement exceeds region bounds");
            }
            return (map_paddr, uninit_paddr, pool_paddr, counts_paddr);
        }

        let (pool_base, _pool_len) = best_pool.unwrap_or_else(|| {
            panic!("PMM: Not enough memory for metadata pool!");
        });

        let (mut map_base, mut map_avail) = best_map.unwrap_or_else(|| {
            panic!("PMM: Not enough memory for metadata map/uninit array!");
        });

        if map_base == pool_base {
            // Find an alternative map region
            let mut alt_map: Option<(usize, usize)> = None;
            for entry in entries {
                if entry.typ != MemoryMapEntryType::Usable {
                    continue;
                }
                let base = entry.base as usize;
                let len = entry.len as usize;
                let aligned_base = align(base);
                let avail = len.saturating_sub(aligned_base.saturating_sub(base));
                if base == pool_base || avail < map_uninit_size {
                    continue;
                }
                if alt_map.map_or(true, |b| avail > b.1) {
                    alt_map = Some((base, avail));
                }
            }
            let alt = alt_map.unwrap_or_else(|| {
                panic!("PMM: Not enough separate memory for metadata map/uninit array!");
            });
            map_base = alt.0;
            map_avail = alt.1;
        }

        let map_paddr = align(map_base);
        let uninit_paddr = align(map_paddr + metadata_map_size);
        let counts_paddr = align(uninit_paddr + uninit_regions_size);
        let map_end = counts_paddr + counts_size;
        if map_end > map_base + map_avail {
            panic!("PMM: metadata map/uninit placement exceeds region bounds");
        }
        let pool_paddr = align(pool_base);

        (map_paddr, uninit_paddr, pool_paddr, counts_paddr)
    }

    /// Initialize the allocator with Limine memory map
    ///
    /// # Safety
    /// This function must be called only once and with valid memory map.
    pub(crate) unsafe fn init(&self, mmap: &[NonNullPtr<MemmapEntry>]) { unsafe {
        FREE_LISTS.call_once(FreeListTable::new);

        let entries_iter = mmap.iter().map(|e| &*e.as_ptr());

        // 1. Calculate physical memory bounds and count usable regions
        let mut max_phys_addr = 0;
        let mut usable_regions_count = 0;

        for entry in entries_iter.clone() {
            if entry.typ == MemoryMapEntryType::Usable {
                let end = entry.base + entry.len;
                if end > max_phys_addr {
                    max_phys_addr = end;
                }
                usable_regions_count += 1;
            }
        }

        // Align to 4KB
        let total_frames = (max_phys_addr as usize + 4095) / 4096;

        // Calculate block parameters
        let frame_size = size_of::<BuddyFrame>();
        let frames_per_block = 4096 / frame_size;

        let metadata_map_len = (total_frames + frames_per_block - 1) / frames_per_block;

        // Calculate sizes for arrays
        let metadata_map_size = metadata_map_len * size_of::<usize>(); // pointer size
        let max_uninit_regions = usable_regions_count * 2 + PADDING_REGIONS;
        let uninit_regions_size = max_uninit_regions * size_of::<Option<UninitRegion>>();
        let metadata_pool_size = metadata_map_len * 4096; // one 4K block per metadata block
        let counts_size = total_frames * size_of::<core::sync::atomic::AtomicU16>();

        logln!(
            "PMM: Total RAM: {} MB, Frames: {}, Metadata Pool: {} KB",
            max_phys_addr / 1024 / 1024,
            total_frames,
            metadata_pool_size / 1024
        );

        // 2. Allocate metadata map array, uninit regions array, and metadata pool
        let (map_paddr, uninit_paddr, pool_paddr, counts_paddr) = Self::find_metadata_storage(
            mmap,
            metadata_map_size,
            uninit_regions_size,
            metadata_pool_size,
            counts_size,
        );
        if map_paddr == 0 {
            panic!("PMM: metadata map placed at paddr 0");
        }

        // Calculate reserved ranges for metadata structures
        let map_end = map_paddr + metadata_map_size;
        let uninit_end = uninit_paddr + uninit_regions_size;
        let counts_end = counts_paddr + counts_size;
        let pool_end = pool_paddr + metadata_pool_size;

        // Initialize pointers
        let phys_offset = match crate::PHYS_OFFSET.get() {
            Some(v) => *v,
            None => return,
        };
        let metadata_map = (phys_offset + map_paddr as u64) as *mut *mut BuddyFrame;
        // Initialize metadata map to null (handling sparse memory)
        core::ptr::write_bytes(metadata_map, 0, metadata_map_len);

        let uninit_regions_ptr = (phys_offset + uninit_paddr as u64) as *mut Option<UninitRegion>;
        let uninit_regions = slice::from_raw_parts_mut(uninit_regions_ptr, max_uninit_regions);
        let uninit_len = uninit_regions.len();

        // Initialize arrays
        for r in uninit_regions.iter_mut() {
            *r = None;
        }

        // Initialize counts array (保留占位，页面计数留到虚拟内存阶段)
        let counts_ptr = (phys_offset + counts_paddr as u64) as *mut core::sync::atomic::AtomicU16;
        core::ptr::write_bytes(counts_ptr, 0, total_frames);

        self.config.call_once(|| AllocatorConfig {
            total_frames,
            metadata_map,
            metadata_map_len,
            frames_per_block,
        });

        // 3. Allocate metadata blocks and record uninit regions
        let mut blocks_allocated = 0;
        let mut region_idx = 0;
        let mut metadata_pool = MetadataPool {
            base: (phys_offset + pool_paddr as u64) as *mut u8,
            blocks: metadata_map_len,
            next: 0,
            block_size: 4096,
        };

        // Simple array of reserved ranges, sorted
        let mut reserved = [
            (map_paddr, map_end),
            (uninit_paddr, uninit_end),
            (counts_paddr, counts_end),
            (pool_paddr, pool_end),
        ];
        reserved.sort_unstable_by_key(|r| r.0);

        for entry in entries_iter.clone() {
            if entry.typ == MemoryMapEntryType::Usable {
                let mut current = entry.base as usize;
                let region_end = (entry.base + entry.len) as usize;

                // Process gaps around reserved regions
                for (r_start, r_end) in reserved.iter() {
                    // If current region overlaps with reserved block
                    if current < *r_end && region_end > *r_start {
                        // Process gap before reserved block
                        if *r_start > current {
                            self.process_range(
                                current,
                                *r_start,
                                &mut blocks_allocated,
                                &mut region_idx,
                                uninit_regions,
                                &mut metadata_pool,
                            );
                        }
                        // Advance past reserved block
                        current = core::cmp::max(current, *r_end);
                        // Align
                        current = (current + 4095) & !4095;
                    }
                }

                // Process remaining part of the region
                if current < region_end {
                    self.process_range(
                        current,
                        region_end,
                        &mut blocks_allocated,
                        &mut region_idx,
                        uninit_regions,
                        &mut metadata_pool,
                    );
                }
            }
        }

        logln!(
            "PMM: Metadata blocks allocated: {} / {}",
            blocks_allocated,
            metadata_map_len
        );
        logln!("PMM: Initialized with {} regions (Capacity: {})", region_idx, uninit_len);

        {
            let mut uninit = self.uninit.lock();
            uninit.regions = uninit_regions;
            uninit.last_uninit_idx = 0;
        }

        self.init_reserve(32);
    }}

    // Helper to process a range of usable memory
    unsafe fn process_range(
        &self,
        start: usize,
        end: usize,
        blocks_allocated: &mut usize,
        region_idx: &mut usize,
        uninit_regions: &mut [Option<UninitRegion>],
        metadata_pool: &mut MetadataPool,
    ) { unsafe {
        let mut current = start;
        // Align start to 4KB
        current = (current + 4095) & !4095;

        let cfg = self.config();
        let block_size = cfg.frames_per_block * 4096;

        if current >= end {
            return;
        }

        let first_block = current / block_size;
        let last_block = (end - 1) / block_size;

        // Ensure metadata exists for all blocks covered by this range
        for block_idx in first_block..=last_block {
            if block_idx >= cfg.metadata_map_len {
                break;
            }

            let entry_ptr = cfg.metadata_map.add(block_idx);
            if (*entry_ptr).is_null() {
                let block_ptr = metadata_pool.alloc_block();
                *entry_ptr = block_ptr;

                // Initialize block memory
                for i in 0..cfg.frames_per_block {
                    block_ptr.add(i).write(BuddyFrame::new());
                }

                *blocks_allocated += 1;
            }
        }

        // The remaining memory can be used as uninit regions
        if current < end {
            let start_pfn = current / 4096;
            let end_pfn = end / 4096;

            if start_pfn < end_pfn {
                if *region_idx < uninit_regions.len() {
                    uninit_regions[*region_idx] = Some(UninitRegion { start_pfn, end_pfn });
                    *region_idx += 1;
                } else {
                    logln!("PMM: WARNING Dropping usable memory region (uninit regions full)");
                }
            }
        }
    }}

    fn shard_for_pfn(pfn: usize) -> usize {
        pfn % SHARD_COUNT
    }

    fn shard_for_cpu(cpu: usize) -> usize {
        cpu % SHARD_COUNT
    }

    fn per_cpu_limit(order: usize) -> u16 {
        match order {
            0..=1 => 64,
            2..=4 => 32,
            5..=8 => 16,
            9..=12 => 8,
            13..=16 => 4,
            _ => 2,
        }
    }

    fn per_cpu_batch(order: usize) -> u16 {
        let limit = Self::per_cpu_limit(order);
        if limit > 8 {
            8
        } else {
            limit
        }
    }

    fn pop_from_global(&self, order: usize, cpu: usize) -> Option<usize> {
        let lists = FREE_LISTS.get().expect("PMM free lists not initialized");
        let start = Self::shard_for_cpu(cpu);
        for offset in 0..SHARD_COUNT {
            let shard = (start + offset) % SHARD_COUNT;
            let mut list = lists.orders[order].shards[shard].lock();
            self.global_list_ops.fetch_add(1, Ordering::Relaxed);
            if let Some(idx) = list.head {
                unsafe {
                    self.remove_from_list_with_list(idx, order, &mut *list);
                    let frame = self.get_frame(idx);
                    frame.state = FrameState::Allocated;
                    set_flag(&mut frame.flags, BF_MIGRATABLE, true);
                    frame.next = None;
                    frame.prev = None;
                }
                return Some(idx);
            }
        }
        None
    }

    fn push_to_global(&self, pfn: usize, order: usize) {
        let lists = FREE_LISTS.get().expect("PMM free lists not initialized");
        let shard = Self::shard_for_pfn(pfn);
        let mut list = lists.orders[order].shards[shard].lock();
        self.global_list_ops.fetch_add(1, Ordering::Relaxed);
        unsafe {
            let frame = self.get_frame(pfn);
            frame.order = order as u8;
            frame.state = FrameState::FreeGlobal;
            set_flag(&mut frame.flags, BF_MIGRATABLE, true);
            frame.next = list.head;
            frame.prev = None;
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

    fn alloc_from_list(&self, order: usize, cpu: usize) -> Option<usize> {
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
                        let buddy = self.get_frame(buddy_idx);
                        buddy.order = j as u8;
                        buddy.state = FrameState::Allocated;
                        set_flag(&mut buddy.flags, BF_MIGRATABLE, true);
                        buddy.next = None;
                        buddy.prev = None;
                        self.push_to_global(buddy_idx, j);
                    }
                    let target = self.get_frame(idx);
                    target.order = order as u8;
                    target.state = FrameState::Allocated;
                    set_flag(&mut target.flags, BF_MIGRATABLE, true);
                    target.next = None;
                    target.prev = None;
                }
                return Some(idx);
            }
        }

        None
    }

    fn alloc_from_uninit(&self, order: usize) -> Option<usize> {
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
                                frame.order = order_gap as u8;
                                frame.state = FrameState::Allocated;
                                set_flag(&mut frame.flags, BF_MIGRATABLE, true);
                                frame.next = None;
                                frame.prev = None;
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

    fn free_and_merge(&self, mut pfn: usize, mut order: usize) {
        let cfg = self.config();

        while order < MAX_ORDER - 1 {
            let buddy_pfn = pfn ^ (1 << order);
            if buddy_pfn >= cfg.total_frames {
                break;
            }

            let lists = FREE_LISTS.get().expect("PMM free lists not initialized");
            let shard = Self::shard_for_pfn(buddy_pfn);
            let mut list = lists.orders[order].shards[shard].lock();
            self.global_list_ops.fetch_add(1, Ordering::Relaxed);
            unsafe {
                let buddy = self.get_frame(buddy_pfn);
                if buddy.state != FrameState::FreeGlobal || buddy.order != order as u8 {
                    break;
                }
                self.remove_from_list_with_list(buddy_pfn, order, &mut *list);
                buddy.state = FrameState::Allocated;
                set_flag(&mut buddy.flags, BF_MIGRATABLE, true);
                buddy.next = None;
                buddy.prev = None;
            }
            drop(list);

            if buddy_pfn < pfn {
                pfn = buddy_pfn;
            }
            order += 1;
        }

        self.push_to_global(pfn, order);
    }

    fn percpu_pop_raw(&self, cpu: usize, order: usize) -> Option<usize> {
        PER_CPU.with_cache(cpu, |cache| {
            if let Some(head) = cache.heads[order] {
                unsafe {
                    let frame = self.get_frame(head);
                    cache.heads[order] = frame.next;
                    cache.counts[order] = cache.counts[order].saturating_sub(1);
                    frame.next = None;
                    frame.prev = None;
                    frame.state = FrameState::Allocated;
                    set_flag(&mut frame.flags, BF_MIGRATABLE, true);
                }
                return Some(head);
            }
            None
        })
    }

    fn percpu_pop(&self, cpu: usize, order: usize) -> Option<usize> {
        let res = self.percpu_pop_raw(cpu, order);
        if res.is_some() {
            self.alloc_hit_percpu.fetch_add(1, Ordering::Relaxed);
        }
        res
    }

    fn percpu_push_raw(&self, cpu: usize, pfn: usize, order: usize) {
        PER_CPU.with_cache(cpu, |cache| {
            unsafe {
                let frame = self.get_frame(pfn);
                frame.order = order as u8;
                frame.state = FrameState::FreePerCpu;
                set_flag(&mut frame.flags, BF_MIGRATABLE, true);
                frame.next = cache.heads[order];
                frame.prev = None;
            }
            cache.heads[order] = Some(pfn);
            cache.counts[order] = cache.counts[order].saturating_add(1);
        });
    }

    fn percpu_push(&self, cpu: usize, pfn: usize, order: usize) {
        self.percpu_push_raw(cpu, pfn, order);
        let limit = Self::per_cpu_limit(order);
        let mut to_drain: u16 = 0;
        PER_CPU.with_cache(cpu, |cache| {
            if cache.counts[order] > limit {
                to_drain = cache.counts[order] - limit;
            }
        });
        while to_drain > 0 {
            if let Some(drained) = self.percpu_pop_raw(cpu, order) {
                self.free_and_merge(drained, order);
            } else {
                break;
            }
            to_drain -= 1;
        }
    }

    pub(crate) fn drain_percpu_all(&self) -> usize {
        let mut drained = 0usize;
        for cpu in 0..MAX_CPUS {
            for order in 0..MAX_ORDER {
                loop {
                    let pfn = self.percpu_pop_raw(cpu, order);
                    if let Some(pfn) = pfn {
                        self.free_and_merge(pfn, order);
                        drained = drained.saturating_add(1);
                    } else {
                        break;
                    }
                }
            }
        }
        drained
    }

    pub(crate) fn max_free_order(&self) -> usize {
        let mut free_global = [0usize; MAX_ORDER];
        if let Some(lists) = FREE_LISTS.get() {
            for order in 0..MAX_ORDER {
                for shard in 0..SHARD_COUNT {
                    let list = lists.orders[order].shards[shard].lock();
                    let mut cur = list.head;
                    while let Some(pfn) = cur {
                        free_global[order] += 1;
                        unsafe {
                            let frame = self.get_frame(pfn);
                            cur = frame.next;
                        }
                    }
                }
            }
        }
        let mut free_percpu = [0usize; MAX_ORDER];
        for cpu in 0..MAX_CPUS {
            PER_CPU.with_cache(cpu, |cache| {
                for order in 0..MAX_ORDER {
                    free_percpu[order] += cache.counts[order] as usize;
                }
            });
        }
        for order in (0..MAX_ORDER).rev() {
            if free_global[order] + free_percpu[order] > 0 {
                return order;
            }
        }
        0
    }

    pub(crate) fn compact(&self) {
        let before = self.max_free_order();
        self.compact_calls.fetch_add(1, Ordering::Relaxed);
        let drained = self.drain_percpu_all();
        self.compact_drained.fetch_add(drained, Ordering::Relaxed);
        let after = self.max_free_order();
        self.compact_last_before.store(before, Ordering::Relaxed);
        self.compact_last_after.store(after, Ordering::Relaxed);
        if after > before {
            self.compact_success.fetch_add(1, Ordering::Relaxed);
        }
        logln!("PMM: WARNING compact triggered drained={}", drained);
    }

    fn percpu_refill(&self, cpu: usize, order: usize) -> Option<usize> {
        let batch = Self::per_cpu_batch(order);
        let mut first: Option<usize> = None;
        for _ in 0..batch {
            if let Some(pfn) = self.alloc_global(order, cpu) {
                if first.is_none() {
                    first = Some(pfn);
                } else {
                    self.percpu_push_raw(cpu, pfn, order);
                }
            } else {
                break;
            }
        }
        if first.is_some() {
            self.alloc_refill.fetch_add(1, Ordering::Relaxed);
        }
        first
    }

    fn alloc_global(&self, order: usize, cpu: usize) -> Option<usize> {
        if let Some(idx) = self.alloc_from_list(order, cpu) {
            return Some(idx);
        }
        if let Some(idx) = self.alloc_from_uninit(order) {
            self.alloc_hit_uninit.fetch_add(1, Ordering::Relaxed);
            unsafe {
                let frame = self.get_frame(idx);
                frame.state = FrameState::Allocated;
                frame.order = order as u8;
                set_flag(&mut frame.flags, BF_MIGRATABLE, true);
                frame.next = None;
                frame.prev = None;
            }
            return Some(idx);
        }
        None
    }

    fn reserve_pop(&self) -> Option<usize> {
        let mut list = self.reserve_list.lock();
        if let Some(head) = list.head {
            unsafe {
                let frame = self.get_frame(head);
                list.head = frame.next;
                frame.next = None;
                frame.prev = None;
                frame.state = FrameState::Allocated;
                set_flag(&mut frame.flags, BF_MIGRATABLE, true);
            }
            self.reserve_count.fetch_sub(1, Ordering::Relaxed);
            return Some(head);
        }
        None
    }

    fn reserve_push(&self, pfn: usize) {
        let mut list = self.reserve_list.lock();
        unsafe {
            let frame = self.get_frame(pfn);
            frame.order = ORDER_4K as u8;
            frame.state = FrameState::Allocated;
            set_flag(&mut frame.flags, BF_MIGRATABLE, true);
            frame.next = list.head;
            frame.prev = None;
        }
        list.head = Some(pfn);
        self.reserve_count.fetch_add(1, Ordering::Relaxed);
    }

    fn init_reserve(&self, pages: usize) {
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
            return Some(PhysFrame::containing_address(PhysAddr::new(
                (idx * 4096) as u64,
            )));
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
                        return Some(PhysFrame::containing_address(PhysAddr::new(
                            (idx * 4096) as u64,
                        )));
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
        let pfn = frame.start_address().as_u64() as usize / 4096;
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

struct MetadataCache {
    block_idx: usize,
    block_ptr: *mut BuddyFrame,
}

impl MetadataCache {
    fn new() -> Self {
        Self {
            block_idx: usize::MAX,
            block_ptr: core::ptr::null_mut(),
        }
    }
}
