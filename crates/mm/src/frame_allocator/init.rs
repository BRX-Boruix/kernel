//! LazyBuddy 分配器初始化。
//!
//! 根据 Limine 内存映射计算物理内存边界、预留元数据存储位置，
//! 建立 frame 元数据块，并登记未初始化(uninit)区域。

use core::mem::size_of;
use core::slice;

use limine::{MemmapEntry, MemoryMapEntryType, NonNullPtr};
use klib::logln;

use super::allocator_core::{
    align_4k, AllocatorConfig, BuddyFrame, MetadataPool, UninitRegion, L1_ENTRIES, L1_SHIFT,
    L2_ENTRIES, L2_MASK,
};
use super::percpu_cache::FreeListTable;
use super::{LazyBuddyAllocator, FREE_LISTS};

/// Buffer for uninit regions count to handle fragmentation
const PADDING_REGIONS: usize = 16;

impl LazyBuddyAllocator {
    // Helper to find contiguous memory for metadata structures (O(N))
    //
    // 返回 (map_paddr, uninit_paddr, pool_paddr)。
    // 不再分配 `counts`（每帧 2 字节、按全物理地址跨度预留的数组）——它从未被
    // 运行时代码读取，纯属预留占位，且在高地址机器上是元数据爆炸的主因之一。
    fn find_metadata_storage(
        mmap: &[NonNullPtr<MemmapEntry>],
        metadata_map_size: usize,
        uninit_regions_size: usize,
        metadata_pool_size: usize,
    ) -> (usize, usize, usize) {
        const MIN_METADATA_BASE: usize = 0x0010_0000; // 1MiB guard to avoid low memory/HHDM corner cases
        let entries = mmap.iter().map(|e| unsafe { &*e.as_ptr() });

        let total_size = align_4k(metadata_map_size)
            .saturating_add(align_4k(uninit_regions_size))
            .saturating_add(align_4k(metadata_pool_size));
        let map_uninit_size =
            align_4k(metadata_map_size).saturating_add(align_4k(uninit_regions_size));

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
            let aligned_base = align_4k(base);
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
            let map_paddr = align_4k(base);
            let uninit_paddr = align_4k(map_paddr.saturating_add(metadata_map_size));
            let pool_paddr = align_4k(uninit_paddr.saturating_add(uninit_regions_size));
            let end = pool_paddr.saturating_add(metadata_pool_size);
            if end > base + avail {
                panic!("PMM: metadata placement exceeds region bounds");
            }
            return (map_paddr, uninit_paddr, pool_paddr);
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
                let aligned_base = align_4k(base);
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

        let map_paddr = align_4k(map_base);
        let uninit_paddr = align_4k(map_paddr.saturating_add(metadata_map_size));
        let map_end = uninit_paddr.saturating_add(uninit_regions_size);
        if map_end > map_base + map_avail {
            panic!("PMM: metadata map/uninit placement exceeds region bounds");
        }
        let pool_paddr = align_4k(pool_base);

        (map_paddr, uninit_paddr, pool_paddr)
    }

    /// Initialize the allocator with Limine memory map
    ///
    /// # Safety
    /// This function must be called only once and with valid memory map.
    pub(crate) unsafe fn init(&self, mmap: &[NonNullPtr<MemmapEntry>]) { unsafe {
        FREE_LISTS.call_once(FreeListTable::new);

        let entries_iter = mmap.iter().map(|e| &*e.as_ptr());

        // 1. Calculate physical memory bounds and count usable regions
        let mut max_phys_addr: u64 = 0;
        let mut usable_regions_count: usize = 0;

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
        // total_frames 覆盖整个地址跨度（含空洞），因为 buddy 索引以 pfn 计，
        // 任意可分配帧的元数据都必须可寻址。但 metadata 池只需覆盖实际 usable 内存。
        let total_frames = (max_phys_addr as usize + 4095) / 4096;

        // Calculate block parameters
        let frame_size = size_of::<BuddyFrame>();
        let frames_per_block = 4096 / frame_size;

        let metadata_map_len = (total_frames + frames_per_block - 1) / frames_per_block;

        // 计算实际需要分配的 metadata block 数：遍历每个 usable 区域，
        // 统计其覆盖的 block 范围。这样在稀疏内存布局下，metadata 池只按
        // 真实内存量增长，而不是按最大物理地址跨度，避免大内存/空洞机器
        // 上元数据过大导致放不进单个 usable 区域而 panic。
        let block_size = frames_per_block * 4096; // 每个 metadata block 覆盖的字节数
        let mut needed_blocks = 0usize;
        for entry in entries_iter.clone() {
            if entry.typ != MemoryMapEntryType::Usable {
                continue;
            }
            let start = entry.base as usize;
            let end = (entry.base + entry.len) as usize;
            if end <= start {
                continue;
            }
            let first = start / block_size;
            let last = (end - 1) / block_size;
            // 累加该区域覆盖的 block 数（cap 到 metadata_map_len 上界）
            needed_blocks = needed_blocks
                .saturating_add((last - first + 1).min(metadata_map_len.saturating_sub(first)));
        }

        // Calculate sizes for arrays.
        // 用 saturating 运算防御极端内存映射下的 usize 溢出。
        // 注意：不再分配 `counts` 数组（见 find_metadata_storage 注释）。
        //
        // metadata_map 改为两级稀疏页表：只分配固定大小的一级表（L1），
        // 每个条目覆盖 L1_ENTRIES 个 block。二级表（每块覆盖 L1_ENTRIES 个 block
        // 的 `*mut BuddyFrame` 数组）仅在 process_range 触及相应 L1 项时按需分配。
        // 这样 L1 体积恒定（8KB），不再随最高物理地址跨度膨胀。
        let l1_len = (metadata_map_len.saturating_add(L1_ENTRIES - 1)) / L1_ENTRIES;
        let metadata_map_size = l1_len.saturating_mul(size_of::<usize>()); // L1 表（指针数组）
        let max_uninit_regions = usable_regions_count.saturating_mul(2) + PADDING_REGIONS;
        let uninit_regions_size = max_uninit_regions.saturating_mul(size_of::<Option<UninitRegion>>());
        // metadata 池只按实际 usable 内存覆盖的 block 数分配（含少量上浮余量）。
        // 此外需预留两级页表的二级表空间：每个被触及的 L1 区间需要
        // L2_BLOCKS 个 block（L2_ENTRIES 个指针 / 每 block 指针数）。
        let l2_blocks_per_l1 = (L2_ENTRIES * size_of::<*mut BuddyFrame>()).div_ceil(4096);
        // 最多触及的 L1 区间数不超过 metadata_map 的 L1 项数（l1_len）
        let l1_len_for_pool = (metadata_map_len.saturating_add(L1_ENTRIES - 1)) / L1_ENTRIES;
        let metadata_pool_blocks = needed_blocks
            .saturating_add(PADDING_REGIONS)
            .saturating_add(l1_len_for_pool.saturating_mul(l2_blocks_per_l1));
        let metadata_pool_size = metadata_pool_blocks.saturating_mul(4096); // one 4K block per metadata block

        logln!(
            "PMM: Total RAM: {} MB, Frames: {}, Metadata Pool: {} KB",
            max_phys_addr / 1024 / 1024,
            total_frames,
            metadata_pool_size / 1024
        );

        // 2. Allocate metadata map array, uninit regions array, and metadata pool
        let (map_paddr, uninit_paddr, pool_paddr) = Self::find_metadata_storage(
            mmap,
            metadata_map_size,
            uninit_regions_size,
            metadata_pool_size,
        );
        if map_paddr == 0 {
            panic!("PMM: metadata map placed at paddr 0");
        }

        // Calculate reserved ranges for metadata structures
        let map_end = map_paddr + metadata_map_size;
        let uninit_end = uninit_paddr + uninit_regions_size;
        let pool_end = pool_paddr + metadata_pool_size;

        // Initialize pointers
        let phys_offset = match arch::PHYS_OFFSET.get() {
            Some(v) => *v,
            None => return,
        };
        // 一级表（L1）：`*mut *mut BuddyFrame` 数组，初始全 null。
        // 二级表在 process_range 触及对应 L1 项时按需分配。
        let metadata_l1 = (phys_offset + map_paddr as u64) as *mut *mut *mut BuddyFrame;
        // write_bytes 的第三个参数是字节数：l1_len 个 8 字节指针。
        core::ptr::write_bytes(metadata_l1, 0, l1_len * size_of::<*mut *mut BuddyFrame>());

        let uninit_regions_ptr = (phys_offset + uninit_paddr as u64) as *mut Option<UninitRegion>;
        let uninit_regions = slice::from_raw_parts_mut(uninit_regions_ptr, max_uninit_regions);
        let uninit_len = uninit_regions.len();

        // Initialize arrays
        for r in uninit_regions.iter_mut() {
            *r = None;
        }

        self.config.call_once(|| AllocatorConfig {
            total_frames,
            metadata_l1,
            metadata_map_len,
            frames_per_block,
        });

        // 3. Allocate metadata blocks and record uninit regions
        let mut blocks_allocated = 0;
        let mut region_idx = 0;
        let mut metadata_pool = MetadataPool {
            base: (phys_offset + pool_paddr as u64) as *mut u8,
            blocks: metadata_pool_blocks,
            next: 0,
            block_size: 4096,
        };

        // Simple array of reserved ranges, sorted
        let mut reserved = [
            (map_paddr, map_end),
            (uninit_paddr, uninit_end),
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
                        current = align_4k(current);
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
        current = align_4k(current);

        let cfg = self.config();
        let block_size = cfg.frames_per_block * 4096;

        if current >= end {
            return;
        }

        let first_block = current / block_size;
        let last_block = (end - 1) / block_size;

        // Ensure metadata exists for all blocks covered by this range.
        // 通过两级稀疏页表定位：L1[block_idx >> L1_SHIFT] 指向一个二级表，
        // 二级表按需分配（仅在触及该 L1 区间时），从而让索引随真实内存按需生长。
        for block_idx in first_block..=last_block {
            if block_idx >= cfg.metadata_map_len {
                break;
            }

            let l1_idx = block_idx >> L1_SHIFT;
            let l2_idx = block_idx & L2_MASK;

            // 若该 L1 区间尚无二级表，则分配并清零（L2_ENTRIES 个指针 = L2_BLOCKS 个 block）
            let l1 = cfg.metadata_l1;
            if (*l1.add(l1_idx)).is_null() {
                let l2_bytes = L2_ENTRIES * size_of::<*mut BuddyFrame>();
                let l2_blocks = l2_bytes.div_ceil(metadata_pool.block_size);
                let l2_base = metadata_pool.alloc_blocks(l2_blocks);
                core::ptr::write_bytes(l2_base, 0, l2_blocks * metadata_pool.block_size);
                *l1.add(l1_idx) = l2_base as *mut *mut BuddyFrame;
            }
            let l2 = *l1.add(l1_idx);

            let entry_ptr = l2.add(l2_idx);
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
}
