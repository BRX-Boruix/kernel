mod allocator_core;
mod api;
mod buddy;
mod compact;
mod init;
mod percpu;
mod percpu_cache;
mod reserve;
mod stats;

use core::mem::size_of;

use arch::{phys_to_virt, PhysFrame};
use limine::{MemmapEntry, NonNullPtr};
use spin::Once;

use allocator_core::{LazyBuddyAllocator, MAX_ORDER, ORDER_4K};
use percpu_cache::{FreeListTable, PerCpuCache, PerCpuCacheSet};

pub use allocator_core::{ORDER_1G, ORDER_2M};
pub use compact::compact_now;
pub use stats::reset_stats as reset_frame_stats;
pub use stats::{frag_stats, reset_stats, stats, FrameAllocatorStats, PmmFragStats};


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

    let start = allocate_frames(order).expect("failed to allocate per-CPU cache frames");
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
pub unsafe fn init(mmap: &[NonNullPtr<MemmapEntry>]) { unsafe {
    ALLOCATOR.init(mmap);
}}

/// Allocate a physical frame
pub fn allocate_frame() -> Option<PhysFrame> {
    allocate_frames(ORDER_4K)
}

/// Allocate physical frames with specific order
pub fn allocate_frames(order: usize) -> Option<PhysFrame> {
    ALLOCATOR.allocate(order)
}

/// Deallocate a physical frame
pub fn deallocate_frame(frame: PhysFrame) {
    ALLOCATOR.deallocate(frame);
}
