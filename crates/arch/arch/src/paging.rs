//! 页表抽象（架构无关）。
//!
//! 统一成"把某物理页映射到某虚拟地址"的抽象，不绑定 x86 的 PML4 层级数
//! （ADR-007）。各架构实现本 trait，`mm` 等上层只依赖此接口。

use crate::addr::{PhysAddr, VirtAddr};

/// 页大小。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PageSize {
    /// 4KB 页。
    Size4K,
    /// 2MB 页。
    Size2M,
    /// 1GB 页。
    Size1G,
}

/// 页权限标志。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PageFlags(u64);

impl PageFlags {
    /// 空标志。
    pub const fn empty() -> Self {
        Self(0)
    }

    /// 是否可写。
    pub const fn writable(mut self) -> Self {
        self.0 |= 1 << 1;
        self
    }

    /// 是否用户态可访问。
    pub const fn user(mut self) -> Self {
        self.0 |= 1 << 2;
        self
    }

    /// 是否可执行（内核页通常需要）。
    pub const fn executable(self) -> Self {
        // 若开了 NX，需要在条目里清 bit63；默认实现保持可执行。
        self
    }

    /// 取出裸 u64 标志位（架构实现可据此构造条目）。
    pub const fn bits(self) -> u64 {
        self.0
    }
}

/// 页表操作抽象。
///
/// 实现方操作真实硬件页表（如 x86 的 CR3/PML4）。
pub trait PageTable {
    /// 错误类型（架构相关，如"页表层级已满"）。
    type Error: core::fmt::Debug;

    /// 把物理页 `paddr` 以 `size` 大小映射到虚拟地址 `vaddr`。
    fn map(&mut self, vaddr: VirtAddr, paddr: PhysAddr, size: PageSize, flags: PageFlags) -> Result<(), Self::Error>;

    /// 解除 `vaddr` 处的映射，返回被解映射的物理地址。
    fn unmap(&mut self, vaddr: VirtAddr) -> Result<PhysAddr, Self::Error>;

    /// 翻译虚拟地址 → 物理地址。
    fn translate(&self, vaddr: VirtAddr) -> Option<PhysAddr>;
}

/// 当前活动的页表（活动地址空间）。
///
/// 由具体架构在启动时装载到 CR3 等寄存器。
pub trait ActivePageTable {
    /// 获取当前活动页表的句柄。
    fn current() -> Self;

    /// 切换活动页表（装入 CR3）。
    fn activate(&self);
}
