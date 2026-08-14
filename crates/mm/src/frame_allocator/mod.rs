mod allocator_core;
mod compact;
mod percpu_cache;
mod stats;

use limine::{MemmapEntry, NonNullPtr};
use spin::Once;

use crate::addr::PhysFrame;

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

/// 获取当前 CPU id。
///
/// M0 阶段为单核，暂返回 0。多核/中断管理实现后再接入真实 CPU id。
fn current_cpu_id() -> usize {
    0
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
