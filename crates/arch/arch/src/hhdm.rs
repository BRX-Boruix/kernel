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
///
/// 前置条件：`PHYS_OFFSET` 必须已由启动期（Limine HHDM 响应）初始化。
/// 未初始化时**立即 panic**（S09：宁可报错，绝不返回伪数据）——此前实现
/// 静默 `unwrap_or(0)` 退化为恒等映射，把物理地址当虚拟地址返回，解引用
/// 会 triple fault 或读到错误内存。调用方在偏移就绪前调用是编程错误，
/// 必须以显式 panic 暴露，而非伪装成有效地址。
#[inline]
pub fn phys_to_virt(paddr: u64) -> u64 {
    let offset = PHYS_OFFSET
        .get()
        .copied()
        .expect("PHYS_OFFSET not initialized: phys_to_virt called before HHDM offset setup");
    offset + paddr
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 偏移未初始化时 `phys_to_virt` 必须**报错**（panic），而非静默返回
    /// 恒等映射（S09 回归：旧实现 `unwrap_or(0)` 把物理地址当虚拟地址，
    /// 解引用即 triple fault / 读错内存）。
    ///
    /// 依赖：本 crate 无任何测试初始化 `PHYS_OFFSET`，故该全局 `Once` 在
    /// 测试进程内保持未初始化，`expect` 必然触发——确定性。
    #[test]
    #[should_panic(expected = "PHYS_OFFSET not initialized")]
    fn phys_to_virt_before_init_panics_instead_of_identity() {
        let _ = phys_to_virt(0x1000);
    }
}
