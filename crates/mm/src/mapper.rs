//! 虚拟内存高层接口。
//!
//! 提供：
//! - 物理帧分配器的 FFI 适配（供 `arch-x86_64` 的页表页分配注入）
//! - 物理地址 → 虚拟地址（HHDM）转换
//! - 内核启动早期建立的初始页表（Limine 已为内核建好），用于验证分页

use crate::frame_allocator;

/// 分配一个物理帧，返回其物理地址（0 表示失败）。FFI 安全。
#[unsafe(no_mangle)]
pub extern "C" fn mm_alloc_frame() -> u64 {
    match frame_allocator::allocate_frame() {
        Some(f) => f.start_paddr(),
        None => 0,
    }
}

/// 释放一个物理帧。FFI 安全。
#[unsafe(no_mangle)]
pub extern "C" fn mm_dealloc_frame(paddr: u64) {
    frame_allocator::deallocate_frame(arch::PhysFrame::from_paddr_raw(paddr));
}
