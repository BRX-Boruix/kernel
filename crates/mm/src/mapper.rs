//! 虚拟内存高层接口。
//!
//! 提供：
//! - 物理帧分配器的 FFI 适配（供 `arch-x86_64` 的页表页分配注入）
//! - 物理地址 → 虚拟地址（HHDM）转换
//! - 内核启动早期建立的初始页表（Limine 已为内核建好），用于验证分页

use crate::frame_allocator;

/// 分配一个物理帧，返回其物理地址（0 表示失败）。FFI 安全。
///
/// MD3：删除原 `#[unsafe(no_mangle)]`——本函数从不经符号名引用（唯一调用点
/// 以函数指针注入 `paging::init`），导出符号名只会制造"存在稳定内核 ABI"的
/// 假象。extern "C" ABI 保留以匹配注入签名。
pub extern "C" fn mm_alloc_frame() -> u64 {
    match frame_allocator::allocate_frame() {
        Some(f) => f.start_paddr(),
        None => 0,
    }
}

/// 释放一个物理帧。FFI 安全。
///
/// 同 [`mm_alloc_frame`]（MD3）：不再导出符号名。
pub extern "C" fn mm_dealloc_frame(paddr: u64) {
    frame_allocator::deallocate_frame(arch::PhysFrame::from_paddr_raw(paddr));
}
