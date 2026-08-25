//! LazyBuddy 分配器初始化。
//!
//! 根据 Limine 内存映射计算物理内存边界、预留元数据存储位置，
//! 建立 frame 元数据块，并登记未初始化(uninit)区域。
//!
//! 初始化日志（`[pmm]`）覆盖每个阶段的**统计数据与过程**：
//! - usable 区域总数、物理内存边界、总帧数；
//! - metadata block / 两级稀疏表 / pool 尺寸计算；
//! - metadata 存储位置选择结果；
//! - 逐 usable 区域的 process_range：block 覆盖、L1/L2 表按需分配、uninit 登记；
//! - 收尾：metadata block 用量、uninit region 数、紧急预留。
//!
//! 耗时说明：`mm::init()` 发生在时钟源（HPET/LAPIC）注入之前，`klib::time`
//! 尚不可用，故用 **RDTSC** 计时。通过 CPUID leaf 0x15 探测 TSC 频率，把每个
//! 阶段的耗时换算成毫秒/秒；探测失败（TCG 下 ECX=0）则退化为只报 cycles。

use core::mem::size_of;
use core::slice;
use core::sync::atomic::{AtomicUsize, Ordering};

use klib::info;
use limine::{MemmapEntry, MemoryMapEntryType, NonNullPtr};

use super::allocator_core::{
    AllocatorConfig, BuddyFrame, FRAME_SIZE_BYTES, L1_ENTRIES, L1_SHIFT, L2_ENTRIES, L2_MASK,
    MetadataPool, UninitRegion, align_4k,
};
use super::percpu_cache::FreeListTable;
use super::reserve::{CRITICAL_RESERVE_CAP_PAGES, RESERVE_CAP_PAGES};
use super::{FREE_LISTS, LazyBuddyAllocator};

/// Buffer for uninit regions count to handle fragmentation
const PADDING_REGIONS: usize = 16;

/// MM4 可观测性：uninit 槽位彻底耗尽时（分裂登记后仍放不下）被丢弃的物理
/// 帧计数。正常布局下该值为 0；非 0 即容量公式被真实布局击穿的证据。
///
/// 审计 B7 观测通道如实说明：唯一自增点（:672）紧邻容量 panic——计数非零
/// 的系统**必然已响亮失败**，本出口的消费者是崩溃现场/事后内核镜像检查，
/// 而非存活系统的运行时指标（那类"恒 0 的活体观测口"才是 S25 禁止的死
/// 出口）。若未来把丢弃改为非致命降级，必须同步把本计数接入 sysfs 投影。
static DROPPED_UNINIT_FRAMES: AtomicUsize = AtomicUsize::new(0);

/// 读取初始化期被丢弃的可用帧计数（MM4 可观测性出口）。
pub fn dropped_uninit_frames() -> usize {
    DROPPED_UNINIT_FRAMES.load(Ordering::Relaxed)
}

/// 读 TSC（相对耗时用；时钟源注入前的早期计时）。
///
/// 用编译器内建 `_rdtsc()`（比手写 inline asm 更稳，避免寄存器约束问题）。
#[inline]
fn rdtsc() -> u64 {
    // SAFETY: rdtsc 是单条无副作用的指令，可安全内联。
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// 探测 TSC 频率，返回 `(频率, 来源)`。
///
/// 优先 CPUID leaf 0x15（`ECX`=参考频率 Hz，`EBX:EAX`=TSC 倍频比，
/// `tsc_hz = ECX*EBX/EAX`）；失败则尝试 leaf 0x16（EAX=处理器基频 MHz，近似）。
/// 用 `core::arch::__cpuid` intrinsic（内联汇编不能用 rbx，LLVM 保留）。
/// QEMU TCG 下 0x15/0x16 通常都不提供，此时返回 None（退化为纯 cycles）。
fn tsc_hz() -> Option<(u64, &'static str)> {
    // 0x15：精确 TSC 频率。
    let r = core::arch::x86_64::__cpuid(0x15);
    let (den, num, ref_hz) = (r.eax as u64, r.ebx as u64, r.ecx as u64);
    if ref_hz != 0 && den != 0 {
        let hz = ref_hz.saturating_mul(num) / den;
        if hz != 0 {
            return Some((hz, "cpuid 0x15"));
        }
    }
    // 0x16：处理器基频（MHz），作为近似兜底。
    let r = core::arch::x86_64::__cpuid(0x16);
    let base_mhz = r.eax as u64;
    if base_mhz != 0 {
        return Some((base_mhz * 1_000_000, "cpuid 0x16 (approx)"));
    }
    None
}

/// 阶段耗时记录：在初始化各关键点调用 `mark` 打印该阶段耗时。
///
/// 用 RDTSC 测相对 cycles；若能探测到 TSC 频率，额外换算成 ns/ms/s。
struct InitTimer {
    start: u64,
    last: u64,
    hz: Option<u64>,
}

impl InitTimer {
    fn new() -> Self {
        let t = rdtsc();
        let hz = match tsc_hz() {
            Some((h, s)) => {
                info!("[pmm] TSC freq detected: {} Hz ({})", h, s);
                Some(h)
            }
            None => {
                info!(
                    "[pmm] TSC freq unknown (CPUID 0x15/0x16 unsupported); timing in cycles only"
                );
                None
            }
        };
        Self {
            start: t,
            last: t,
            hz,
        }
    }

    /// 把 cycles 换算成 `(seconds, millis, nanos)`；无法换算（无频率）则返回 None。
    fn elapsed(&self, cyc: u64) -> Option<(u64, u64, u64)> {
        self.hz.map(|hz| {
            let ns = cyc.saturating_mul(1_000_000_000) / hz;
            (ns / 1_000_000_000, ns / 1_000_000, ns)
        })
    }

    /// 记录自 `last` 以来的耗时，并更新 `last`；返回该阶段 cycles。
    fn mark(&mut self, label: &str) -> u64 {
        let now = rdtsc();
        let cyc = now.wrapping_sub(self.last);
        self.last = now;
        match self.elapsed(cyc) {
            Some((s, ms, ns)) => info!(
                "[pmm]   -- {}: {} s / {} ms / {} ns ({} cycles)",
                label, s, ms, ns, cyc
            ),
            None => info!("[pmm]   -- {}: {} cycles", label, cyc),
        }
        cyc
    }

    /// 初始化总耗时（cycles）。
    fn total(&self) -> u64 {
        rdtsc().wrapping_sub(self.start)
    }
}

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
    pub(crate) unsafe fn init(&self, mmap: &[NonNullPtr<MemmapEntry>]) {
        unsafe {
            FREE_LISTS.call_once(FreeListTable::new);
            let mut timer = InitTimer::new();

            let entries_iter = mmap.iter().map(|e| &*e.as_ptr());

            // 1. Calculate physical memory bounds and count usable regions
            let mut max_phys_addr: u64 = 0;
            let mut usable_regions_count: usize = 0;

            // 内存映射入口清单
            info!(
                "[pmm] === LazyBuddy init: {} memory-map entries ===",
                mmap.len()
            );

            for entry in entries_iter.clone() {
                if entry.typ == MemoryMapEntryType::Usable {
                    let end = entry.base + entry.len;
                    if end > max_phys_addr {
                        max_phys_addr = end;
                    }
                    usable_regions_count += 1;
                }
            }

            info!(
                "[pmm] usable regions: {} (Usable), max phys addr: 0x{:x} ({} MB)",
                usable_regions_count,
                max_phys_addr as usize,
                max_phys_addr / 1024 / 1024
            );

            // Align to 4KB
            // total_frames 覆盖整个地址跨度（含空洞），因为 buddy 索引以 pfn 计，
            // 任意可分配帧的元数据都必须可寻址。但 metadata 池只需覆盖实际 usable 内存。
            let total_frames = (max_phys_addr as usize + 4095) / 4096;
            info!(
                "[pmm] total_frames (max span incl. holes): {}",
                total_frames
            );

            // Calculate block parameters
            let frame_size = size_of::<BuddyFrame>();
            let frames_per_block = 4096 / frame_size;
            let block_size = frames_per_block * 4096; // 每个 metadata block 覆盖的字节数
            info!(
                "[pmm] BuddyFrame size: {} B, frames_per_block: {}, block covers {} B ({} KB)",
                frame_size,
                frames_per_block,
                block_size,
                block_size / 1024
            );

            let metadata_map_len = (total_frames + frames_per_block - 1) / frames_per_block;

            // 计算实际需要分配的 metadata block 数：遍历每个 usable 区域，
            // 统计其覆盖的 block 范围。这样在稀疏内存布局下，metadata 池只按
            // 真实内存量增长，而不是按最大物理地址跨度，避免大内存/空洞机器
            // 上元数据过大导致放不进单个 usable 区域而 panic。
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
            info!(
                "[pmm] metadata_map_len (logical blocks): {}, needed metadata blocks across usable: {}",
                metadata_map_len, needed_blocks
            );

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
            let uninit_regions_size =
                max_uninit_regions.saturating_mul(size_of::<Option<UninitRegion>>());
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

            info!(
                "[pmm] L1 table: entries={} size={} B ({}) | L2: entries={}, blocks_per_l1={}",
                l1_len, metadata_map_size, l1_len, L2_ENTRIES, l2_blocks_per_l1
            );
            info!(
                "[pmm] uninit: max_regions={}, array_size={} B",
                max_uninit_regions, uninit_regions_size
            );
            info!(
                "[pmm] metadata pool: blocks={}, size={} KB (needed={} + pad={} + l2 for {} L1)",
                metadata_pool_blocks,
                metadata_pool_size / 1024,
                needed_blocks,
                PADDING_REGIONS,
                l1_len_for_pool
            );

            timer.mark("memory map & sizing");

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

            info!(
                "[pmm] metadata storage: map=0x{:x} ({} B) uninit=0x{:x} ({} B) pool=0x{:x} ({} KB)",
                map_paddr,
                metadata_map_size,
                uninit_paddr,
                uninit_regions_size,
                pool_paddr,
                metadata_pool_size / 1024
            );

            // Calculate reserved ranges for metadata structures
            let map_end = map_paddr + metadata_map_size;
            let uninit_end = uninit_paddr + uninit_regions_size;
            let pool_end = pool_paddr + metadata_pool_size;

            // Initialize pointers
            // MD1：PHYS_OFFSET 未设置与其余初始化失败同哲学——显式 panic。
            // 原实现的静默 `return` 会留下 FREE_LISTS 已建、config 未建的
            // 半成品状态，后续分配路径以更难诊断的方式爆炸。
            let phys_offset = match arch::PHYS_OFFSET.get() {
                Some(v) => *v,
                None => panic!(
                    "PMM: PHYS_OFFSET not initialized (HHDM response missing); \
                     frame allocator cannot map metadata structures"
                ),
            };
            // 一级表（L1）：`*mut *mut BuddyFrame` 数组，初始全 null。
            // 二级表在 process_range 触及对应 L1 项时按需分配。
            let metadata_l1 = (phys_offset + map_paddr as u64) as *mut *mut *mut BuddyFrame;
            // write_bytes 的第三个参数是字节数：l1_len 个 8 字节指针。
            core::ptr::write_bytes(metadata_l1, 0, l1_len * size_of::<*mut *mut BuddyFrame>());

            let uninit_regions_ptr =
                (phys_offset + uninit_paddr as u64) as *mut Option<UninitRegion>;
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

            info!(
                "[pmm] HHDM offset: 0x{:x}, metadata L1 @virt 0x{:x}, uninit array @virt 0x{:x}, pool @virt 0x{:x}",
                phys_offset,
                metadata_l1 as usize,
                uninit_regions_ptr as usize,
                (phys_offset + pool_paddr as u64) as usize
            );
            timer.mark("metadata arrays zeroed");

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
            info!(
                "[pmm] reserved metadata ranges: map(0x{:x}-0x{:x}) uninit(0x{:x}-0x{:x}) pool(0x{:x}-0x{:x})",
                reserved[0].0,
                reserved[0].1,
                reserved[1].0,
                reserved[1].1,
                reserved[2].0,
                reserved[2].1
            );

            for entry in entries_iter.clone() {
                if entry.typ == MemoryMapEntryType::Usable {
                    let mut current = entry.base as usize;
                    let region_end = (entry.base + entry.len) as usize;
                    info!(
                        "[pmm] == process usable region: phys 0x{:x}-0x{:x} ({} MB, {} frames) ==",
                        current,
                        region_end,
                        (region_end - current) / 1024 / 1024,
                        (region_end - current) / 4096
                    );

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

            {
                let now = rdtsc();
                let cyc = now.wrapping_sub(timer.last);
                timer.last = now;
                match timer.elapsed(cyc) {
                    Some((s, ms, ns)) => info!(
                        "[pmm]   -- process usable regions ({} s / {} ms / {} ns / {} cycles): blocks_allocated={} / {} uninit_regions={}",
                        s, ms, ns, cyc, blocks_allocated, metadata_map_len, region_idx
                    ),
                    None => info!(
                        "[pmm]   -- process usable regions ({} cycles): blocks_allocated={} / {} uninit_regions={}",
                        cyc, blocks_allocated, metadata_map_len, region_idx
                    ),
                }
            }

            info!(
                "[pmm] Metadata blocks allocated: {} / {}",
                blocks_allocated, metadata_map_len
            );
            info!(
                "[pmm] Initialized with {} regions (Capacity: {})",
                region_idx, uninit_len
            );

            {
                let mut uninit = self.uninit.lock();
                uninit.regions = uninit_regions;
                uninit.last_uninit_idx = 0;
            }

            self.init_reserve(RESERVE_CAP_PAGES);
            self.init_reserve_critical(CRITICAL_RESERVE_CAP_PAGES);

            {
                let total = timer.total();
                match timer.elapsed(total) {
                    Some((s, ms, ns)) => info!(
                        "[pmm] === LazyBuddy init done (total {} s / {} ms / {} ns / {} cycles) ===",
                        s, ms, ns, total
                    ),
                    None => info!("[pmm] === LazyBuddy init done (total {} cycles) ===", total),
                }
            }
        }
    }

    // Helper to process a range of usable memory
    unsafe fn process_range(
        &self,
        start: usize,
        end: usize,
        blocks_allocated: &mut usize,
        region_idx: &mut usize,
        uninit_regions: &mut [Option<UninitRegion>],
        metadata_pool: &mut MetadataPool,
    ) {
        unsafe {
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

            info!(
                "[pmm]   process_range 0x{:x}-0x{:x} -> blocks [{}, {}] ({} blocks)",
                current,
                end,
                first_block,
                last_block,
                last_block.saturating_sub(first_block) + 1
            );

            // Ensure metadata exists for all blocks covered by this range.
            // 通过两级稀疏页表定位：L1[block_idx >> L1_SHIFT] 指向一个二级表，
            // 二级表按需分配（仅在触及该 L1 区间时），从而让索引随真实内存按需生长。
            let mut l2_tables_allocated = 0usize;
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
                    l2_tables_allocated += 1;
                    info!(
                        "[pmm]     allocated L2 table for L1[{}] @virt 0x{:x} ({} blocks)",
                        l1_idx, l2_base as usize, l2_blocks
                    );
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

            if l2_tables_allocated > 0 {
                info!(
                    "[pmm]     built {} L2 tables, cumulative metadata blocks: {}",
                    l2_tables_allocated, *blocks_allocated
                );
            }

            // The remaining memory can be used as uninit regions
            if current < end {
                let start_pfn = current / 4096;
                let end_pfn = end / 4096;

                if start_pfn < end_pfn {
                    if *region_idx < uninit_regions.len() {
                        uninit_regions[*region_idx] = Some(UninitRegion { start_pfn, end_pfn });
                        info!(
                            "[pmm]     uninit region #{}: pfn {}..{} -> phys 0x{:x}-0x{:x} ({} frames, {} MB)",
                            *region_idx,
                            start_pfn,
                            end_pfn,
                            start_pfn * 4096,
                            end_pfn * 4096,
                            end_pfn - start_pfn,
                            (end_pfn - start_pfn) * 4096 / 1024 / 1024
                        );
                        *region_idx += 1;
                    } else {
                        // MM4：槽位彻底耗尽。容量公式 usable×2+PADDING 被真实
                        // 布局击穿属于异常：显式计数并 panic，绝不带着"少了
                        // 一块可用内存"的账本静默继续启动（旧实现只 warn 后
                        // 把该段 RAM 永久出局，所有后续统计随之失真）。
                        DROPPED_UNINIT_FRAMES.fetch_add(
                            (end_pfn - start_pfn) as usize,
                            Ordering::Relaxed,
                        );
                        panic!(
                            "PMM: uninit region array exhausted; dropping {} frames \
                             (pfn {}..{} phys 0x{:x}-0x{:x}). Memory layout exceeds \
                             capacity formula (usable_regions*2+padding); sizing must be fixed.",
                            end_pfn - start_pfn,
                            start_pfn,
                            end_pfn,
                            start_pfn * FRAME_SIZE_BYTES as usize,
                            end_pfn * FRAME_SIZE_BYTES as usize
                        );
                    }
                }
            }
        }
    }
}
