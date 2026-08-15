mod allocator_core;
mod api;
mod buddy;
mod compact;
mod init;
mod percpu;
mod percpu_cache;
mod reserve;
mod stats;

use arch::PhysFrame;
use limine::{MemmapEntry, NonNullPtr};
use spin::Once;

use allocator_core::{LazyBuddyAllocator, ORDER_4K};
use percpu_cache::{FreeListTable, PerCpuCacheSet};

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
