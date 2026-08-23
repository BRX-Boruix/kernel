mod allocator_core;
mod api;
mod buddy;
mod compact;
mod init;
mod percpu;
mod percpu_cache;
mod refcount;
mod reserve;
mod stats;

use core::mem::size_of;

use arch::{PhysFrame, phys_to_virt};
use limine::{MemmapEntry, NonNullPtr};
use spin::Once;

use allocator_core::{LazyBuddyAllocator, MAX_ORDER, ORDER_4K};
use percpu_cache::{FreeListTable, PerCpuCache, PerCpuCacheSet};

pub use allocator_core::{FRAME_SIZE_BYTES, HUGE_FRAME_SIZE_BYTES, ORDER_1G, ORDER_2M};
pub use compact::{compact_now, ipi_drain_current_cpu, set_remote_drain};
pub use init::dropped_uninit_frames;
pub use refcount::{count as frame_refcount, decref as frame_decref, incref as frame_incref};
pub use stats::reset_stats as reset_frame_stats;
pub use stats::{FrameAllocatorStats, PmmFragStats, frag_stats, reset_stats, stats};

/// 获取物理页帧总数。
pub fn total_frames() -> usize {
    ALLOCATOR.config().total_frames
}

// Global allocator instance
static ALLOCATOR: LazyBuddyAllocator = LazyBuddyAllocator::new();
static FREE_LISTS: Once<FreeListTable> = Once::new();
static PER_CPU: PerCpuCacheSet = PerCpuCacheSet::new();

/// 当前 CPU id 的读取器（函数指针，返回当前 LAPIC/CPU id）。
/// 由 arch 层在 SMP 初始化时注入。单核时默认为 0。
static CPU_ID_READER: spin::Once<fn() -> usize> = spin::Once::new();

/// 注入当前 CPU id 的读取函数（由 SMP 子系统调用）。
pub fn set_cpu_id_reader(f: fn() -> usize) {
    let _ = CPU_ID_READER.call_once(|| f);
}

/// 获取当前 CPU id。
pub(crate) fn current_cpu_id() -> usize {
    match CPU_ID_READER.get() {
        Some(f) => f(),
        None => 0,
    }
}

/// 依据实际 CPU 数初始化 per-CPU 页帧缓存（自适应核数）。
///
/// 缓存数组从**物理帧分配器**分配连续帧，经 HHDM 映射为 `&'static mut [PerCpuCache]`，
/// 而非从有限的内核堆分配，从而不占用 4MB 堆、也不受核数导致的堆容量限制。
/// 须在任何 AP 使用帧分配前调用（内核在 SMP 启动前按 Limine 响应注入 CPU 数）。
pub fn init_percpu_caches(cpu_count: usize) {
    let count = cpu_count.max(1);

    // 计算所需连续帧数与可容纳的最小 order（2^order 个 4KB 帧）。
    // order 上限 MAX_ORDER-1：buddy 能分配的最大块（2^(MAX_ORDER-1) 帧）。
    let bytes = count * size_of::<PerCpuCache>();
    let need_frames = bytes.div_ceil(4096);
    let order = if need_frames <= 1 {
        0
    } else {
        let bits = usize::BITS as usize; // 64
        (bits - 1 - (need_frames - 1).leading_zeros() as usize).min(MAX_ORDER - 1)
    };

    // 注意：这里不能走公共 `allocate_frames`（会先查 per-CPU 缓存，而缓存此时
    // 尚未初始化 → panic）。直接走全局空闲列表分配缓存数组本身的物理帧。
    let idx = ALLOCATOR
        .alloc_global(order, 0)
        .expect("failed to allocate per-CPU cache frames");
    let start = PhysFrame::from_paddr_raw((idx * 4096) as u64);
    let base = phys_to_virt(start.start_paddr()) as *mut u8;

    // 清零整个分配区
    unsafe { core::ptr::write_bytes(base, 0, (1 << order) * 4096) };

    // 映射为可写 slice（每个槽位一个 PerCpuCache）
    let caches: &'static mut [PerCpuCache] =
        unsafe { core::slice::from_raw_parts_mut(base as *mut PerCpuCache, count) };
    for c in caches.iter_mut() {
        *c = PerCpuCache::new();
    }

    PER_CPU.init(caches);
}

unsafe impl Send for LazyBuddyAllocator {}
unsafe impl Sync for LazyBuddyAllocator {}

/// Initialize the global allocator
pub unsafe fn init(mmap: &[NonNullPtr<MemmapEntry>]) {
    unsafe {
        ALLOCATOR.init(mmap);
    }
}

/// Allocate a physical frame
pub fn allocate_frame() -> Option<PhysFrame> {
    allocate_frames(ORDER_4K)
}

/// Allocate physical frames with specific order
pub fn allocate_frames(order: usize) -> Option<PhysFrame> {
    let f = ALLOCATOR.allocate(order)?;
    // 登记该块内每帧的引用计数为 1（COW 共享会在此基础上 incref）。
    // 仅登记 4K 帧粒度；块内未单独释放的残留登记由下次 init 覆盖，无碍。
    let n = 1usize << order;
    for i in 0..n {
        refcount::init(f.start_paddr() + (i * 4096) as u64);
    }
    Some(f)
}

/// Deallocate a physical frame
///
/// **先校验后变更**（审计 #7）：pfn 越界/孔洞检查必须发生在任何帧元数据
/// 解引用（含 refcount 的 refs_cell）之前——孔洞地址流入引用计数即对
/// null+offset 野指针 RMW。校验通过后先递减引用计数；仅当引用降到 0 才
/// 真正归还物理帧分配器（COW 安全）。
pub fn deallocate_frame(frame: PhysFrame) {
    let pfn = frame.start_paddr() as usize / 4096;
    if !ALLOCATOR.pfn_managed(pfn) {
        return;
    }
    if refcount::decref(frame.start_paddr()) {
        ALLOCATOR.deallocate(frame);
    }
}
