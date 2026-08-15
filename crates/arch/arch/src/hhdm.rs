//! HHDM（高半区直接映射）偏移与地址换算。
//!
//! 物理地址 → 虚拟地址的偏移由 Limine 在启动时提供。此模块在 `arch` 抽象层
//! 统一持有该偏移，供 `mm`（直接映射换算）与 `arch-x86_64`（访问物理页表页）
//! 等 crate 共享，避免各自维护重复的 `PHYS_OFFSET` 与换算逻辑。

use spin::Once;

/// HHDM 偏移（物理地址 → 虚拟地址的偏移），由 Limine 提供。
pub static PHYS_OFFSET: Once<u64> = Once::new();

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
