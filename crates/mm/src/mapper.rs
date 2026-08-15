//! 虚拟内存高层接口。
//!
//! 提供：
//! - 物理帧分配器的 FFI 适配（供 `arch-x86_64` 的页表页分配注入）
//! - 物理地址 → 虚拟地址（HHDM）转换
//! - 内核启动早期建立的初始页表（Limine 已为内核建好），用于验证分页

use crate::frame_allocator;
use crate::PHYS_OFFSET;

/// 分配一个物理帧，返回其物理地址（0 表示失败）。FFI 安全。
#[unsafe(no_mangle)]
pub extern "C" fn mm_alloc_frame() -> u64 {
    match frame_allocator::allocate_frame() {
        Some(f) => f.start_address().as_u64(),
        None => 0,
    }
}

/// 释放一个物理帧。FFI 安全。
#[unsafe(no_mangle)]
pub extern "C" fn mm_dealloc_frame(paddr: u64) {
    frame_allocator::deallocate_frame(crate::PhysFrame::containing_address(crate::PhysAddr::new(paddr)));
}

/// 物理地址 → 可访问虚拟地址（HHDM 高半区直接映射）。
///
/// 注意：HHDM 只覆盖物理 RAM，不含 MMIO 设备区。
#[inline]
pub fn phys_to_virt(paddr: u64) -> u64 {
    PHYS_OFFSET.get().copied().unwrap_or(0) + paddr
}

/// 虚拟地址 → 物理地址（仅当 vaddr 在 HHDM 直接映射区内）。
#[inline]
pub fn virt_to_phys(vaddr: u64) -> Option<u64> {
    let offset = PHYS_OFFSET.get().copied()?;
    if vaddr >= offset {
        Some(vaddr - offset)
    } else {
        None
    }
}
