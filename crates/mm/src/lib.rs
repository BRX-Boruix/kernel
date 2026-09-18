//! BORUIX 内存管理子系统。
//!
//! 精简自旧项目 `mm`，当前包含：
//! - 物理页帧分配器（LazyBuddy，惰性初始化 buddy allocator）
//! - 虚拟内存：页表抽象（经 arch 层）与地址空间
//!
//! 地址类型（`PhysAddr`/`VirtAddr`/`PhysFrame`）定义在 `arch` 抽象层，
//! `mm` 经 re-export 供外部使用（ADR-009-11）。

#![no_std]

extern crate alloc;

pub mod dma;
pub mod frame_allocator;
pub mod mapper;
pub mod user_space;

pub use arch::{PhysAddr, PhysFrame, VirtAddr};

pub use frame_allocator::{
    CRITICAL_RESERVE_CAP_PAGES, FRAME_SIZE_BYTES, HUGE_FRAME_SIZE_BYTES, FrameAllocatorStats,
    PmmFragStats, ReserveLevel, allocate_frame, allocate_frame_critical, allocate_frames,
    allocate_frames_critical, compact_now, deallocate_frame, frag_stats, frame_decref,
    frame_incref, frame_refcount, init as init_frame, ipi_drain_current_cpu, reset_frame_stats,
    set_remote_drain, stats as frame_stats, total_frames,
};

use core::sync::atomic::{AtomicUsize, Ordering};

use limine::{HhdmRequest, MemmapRequest};

// Limine 请求。用 limine_tag 放入 .limine_reqs 段，确保 Limine 完整识别。
#[limine::limine_tag]
static HHDM_REQUEST: HhdmRequest = HhdmRequest::new(0);
#[limine::limine_tag]
static MEMMAP_REQUEST: MemmapRequest = MemmapRequest::new(0);

/// Limine kernel-address 请求：给出内核镜像的物理/虚拟基址，用于把镜像自身的
/// 物理区间从帧分配器的可用内存中排除（见 `kernel_image_range`）。
static KERNEL_ADDRESS_REQUEST: limine::KernelAddressRequest = limine::KernelAddressRequest::new(0);

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

/// 计算内核镜像在**物理地址空间**中的占用区间，供帧分配器保留。
///
/// 为什么必须有这个函数：帧分配器的 usable 区域来自 Limine 内存映射，而内核镜像
/// 所在的物理页在映射里仍标记为 Usable。若不显式排除，`allocate_frames` 会把
/// 正在运行的内核代码页当作 DMA 缓冲发出去——设备从该物理地址读到的不是驱动写的
/// 数据，而是 x86 机器码。这正是 HDA 驱动 DMA 一切异常的根因。
///
/// 镜像跨度取 "首个 4K 对齐的 physical_base" 起的 `KERNEL_IMAGE_RESERVE_BYTES`。
/// 该值按实际内核链接产物保守上界取定（见 kernel/.cargo 与 kernel.ld 的布局），
/// 宁可多保留、不可少保留：多保留只损失少量物理内存，少保留会让内核代码被当
/// 空闲帧分发出去。
fn kernel_image_range(phys_offset: u64) -> (usize, usize) {
    /// 内核镜像物理占用的保守上界（含 .text/.rodata/.data/.bss 与嵌入模块）。
    /// 实测内核产物 + 内嵌 initrd/modules 远小于此；取 64 MiB 上界。
    const KERNEL_IMAGE_RESERVE_BYTES: u64 = 64 * 1024 * 1024;

    let base = KERNEL_ADDRESS_REQUEST
        .get_response()
        .get()
        .map(|r| r.physical_base)
        .unwrap_or(0);
    if base == 0 {
        // 拿不到镜像基址时如实报告并退化为"不额外保留"，由调用方日志暴露。
        klib::error!("[mm] Limine kernel address response missing; kernel image NOT reserved");
        return (0, 0);
    }
    let start = base & !0xfff;
    let end = (base + KERNEL_IMAGE_RESERVE_BYTES + 0xfff) & !0xfff;
    klib::info!(
        "[mm] kernel image phys base {:#x} (virt {:#x}) -> reserving {:#x}-{:#x} ({} MiB), HHDM {:#x}",
        base,
        KERNEL_ADDRESS_REQUEST.get_response().get().map(|r| r.virtual_base).unwrap_or(0),
        start,
        end,
        KERNEL_IMAGE_RESERVE_BYTES / 1024 / 1024,
        phys_offset
    );
    (start as usize, end as usize)
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
            frame_allocator::init(entries, kernel_image_range(phys_offset));
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
