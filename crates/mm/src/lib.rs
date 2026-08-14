//! BORUIX 内存管理子系统。
//!
//! 精简自旧项目 `mm`，当前包含：
//! - 物理页帧分配器（LazyBuddy，惰性初始化 buddy allocator）
//!
//! 后续阶段逐步加入：虚拟内存/页表、堆分配器、地址空间等。

#![no_std]

pub mod addr;
pub mod frame_allocator;

pub use addr::{PhysAddr, PhysFrame, VirtAddr};
pub use frame_allocator::{
    allocate_frame, allocate_frames, compact_now, deallocate_frame, frag_stats, init as init_frame,
    stats as frame_stats, reset_frame_stats, FrameAllocatorStats, PmmFragStats,
};

use limine::{HhdmRequest, MemmapRequest};
use spin::Once;

// Limine 请求。用 limine_tag 放入 .limine_reqs 段，确保 Limine 完整识别。
#[limine::limine_tag]
static HHDM_REQUEST: HhdmRequest = HhdmRequest::new(0);
#[limine::limine_tag]
static MEMMAP_REQUEST: MemmapRequest = MemmapRequest::new(0);

/// HHDM 偏移（物理地址 → 虚拟地址的偏移），由 Limine 提供。
pub static PHYS_OFFSET: Once<u64> = Once::new();

/// 初始化内存管理子系统。
///
/// 从 Limine 获取 HHDM 偏移和内存映射，然后初始化物理页帧分配器。
pub fn init() {
    // 1. Get HHDM offset
    let phys_offset = if let Some(hhdm_resp) = HHDM_REQUEST.get_response().get() {
        *PHYS_OFFSET.call_once(|| hhdm_resp.offset)
    } else {
        panic!("Failed to get HHDM response from Limine");
    };
    klib::logln!("[mm] HHDM offset: {:#x}", phys_offset);

    // 2. Initialize Frame Allocator
    if let Some(memmap_resp) = MEMMAP_REQUEST.get_response().get() {
        unsafe {
            // Limine provides an array of NonNullPtr<MemmapEntry>.
            let entries = core::slice::from_raw_parts(
                memmap_resp.entries.as_ptr(),
                memmap_resp.entry_count as usize,
            );
            frame_allocator::init(entries);
        }
    } else {
        panic!("Failed to get Memory Map from Limine");
    }
    klib::logln!("[mm] memory manager initialized");
}
