//! LazyBuddy 分配器初始化。
//!
//! 根据 Limine 内存映射计算物理内存边界、预留元数据存储位置，
//! 建立 frame 元数据块，并登记未初始化(uninit)区域。

use core::mem::size_of;
use core::slice;

use limine::{MemmapEntry, MemoryMapEntryType, NonNullPtr};
use klib::logln;

use super::allocator_core::{align_4k, AllocatorConfig, BuddyFrame, MetadataPool, UninitRegion};
use super::percpu_cache::FreeListTable;
use super::{LazyBuddyAllocator, FREE_LISTS};

/// Buffer for uninit regions count to handle fragmentation
const PADDING_REGIONS: usize = 16;

impl LazyBuddyAllocator {
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

        let total_size = align_4k(metadata_map_size)
            + align_4k(uninit_regions_size)
            + align_4k(counts_size)
            + align_4k(metadata_pool_size);
        let map_uninit_size =
            align_4k(metadata_map_size) + align_4k(uninit_regions_size) + align_4k(counts_size);

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
            let uninit_paddr = align_4k(map_paddr + metadata_map_size);
            let counts_paddr = align_4k(uninit_paddr + uninit_regions_size);
            let pool_paddr = align_4k(counts_paddr + counts_size);
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
        let uninit_paddr = align_4k(map_paddr + metadata_map_size);
        let counts_paddr = align_4k(uninit_paddr + uninit_regions_size);
        let map_end = counts_paddr + counts_size;
        if map_end > map_base + map_avail {
            panic!("PMM: metadata map/uninit placement exceeds region bounds");
        }
        let pool_paddr = align_4k(pool_base);

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
        let phys_offset = match arch::PHYS_OFFSET.get() {
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
}
