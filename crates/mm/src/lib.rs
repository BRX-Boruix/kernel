//! BORUIX 内存管理子系统。
//!
//! 精简自旧项目 `mm`，当前包含：
//! - 物理页帧分配器（LazyBuddy，惰性初始化 buddy allocator）
//! - 虚拟内存：页表抽象（经 arch 层）与地址空间
//!
//! 地址类型（`PhysAddr`/`VirtAddr`/`PhysFrame`）定义在 `arch` 抽象层，
//! 使用方请从 `arch` 直接引入。

#![no_std]

extern crate alloc;

pub mod frame_allocator;
pub mod mapper;
pub mod memory_set;
pub mod user_space;

pub use frame_allocator::{
    allocate_frame, allocate_frames, compact_now, deallocate_frame, frag_stats, frame_decref,
    frame_incref, frame_refcount, init as init_frame, stats as frame_stats, reset_frame_stats,
    total_frames, FrameAllocatorStats, PmmFragStats,
};

use core::sync::atomic::{AtomicUsize, Ordering};

use limine::{HhdmRequest, MemmapRequest};

// Limine 请求。用 limine_tag 放入 .limine_reqs 段，确保 Limine 完整识别。
#[limine::limine_tag]
static HHDM_REQUEST: HhdmRequest = HhdmRequest::new(0);
#[limine::limine_tag]
static MEMMAP_REQUEST: MemmapRequest = MemmapRequest::new(0);

/// CPU 数读取器（函数指针注入，避免 `mm` 重复声明 Limine SMP 请求）。
///
/// 由内核在 `mm::init()` 前注入 `arch_x86_64::smp::requested_cpu_count`，
/// 返回系统总 CPU 数。默认 1（未注入时单核）。
static CPU_COUNT_READER: AtomicUsize = AtomicUsize::new(0);

/// 注入系统总 CPU 数读取器（内核在 `mm::init()` 前调用）。
pub fn set_cpu_count_reader(f: fn() -> usize) {
    CPU_COUNT_READER.store(f as usize, Ordering::SeqCst);
}

/// 读取系统总 CPU 数（未注入时默认 1）。
pub fn cpu_count() -> usize {
    let f = CPU_COUNT_READER.load(Ordering::SeqCst);
    if f == 0 {
        1
    } else {
        let f: fn() -> usize = unsafe { core::mem::transmute(f) };
        f()
    }
}

/// 初始化内存管理子系统。
///
/// 从 Limine 获取 HHDM 偏移和内存映射，然后初始化物理页帧分配器。
pub fn init() {
    // 1. Get HHDM offset
    let phys_offset = if let Some(hhdm_resp) = HHDM_REQUEST.get_response().get() {
        *arch::PHYS_OFFSET.call_once(|| hhdm_resp.offset)
    } else {
        panic!("Failed to get HHDM response from Limine");
    };
    klib::info!("[mm] HHDM offset: {:#x}", phys_offset);

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

    // 3. 初始化 per-CPU 页帧缓存（自适应核数）。
    //    必须在 frame_allocator::init 之后、任何 per-CPU 分配发生之前，
    //    否则 `allocate_frame` 会因缓存未初始化而 panic。
    frame_allocator::init_percpu_caches(cpu_count());

    klib::info!("[mm] memory manager initialized");
}
