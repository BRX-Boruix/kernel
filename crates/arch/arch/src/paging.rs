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

impl PageSize {
    /// 该页大小对应的字节数。
    pub const fn bytes(self) -> u64 {
        match self {
            PageSize::Size4K => 0x1000,
            PageSize::Size2M => 0x20_0000,
            PageSize::Size1G => 0x4000_0000,
        }
    }
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
    ///
    /// 默认页**不可执行**（架构实现据此置 NX=bit63）；仅当调用此方法显式授予
    /// 执行权限时才可执行，从而强制 W^X 保护。
    pub const fn executable(mut self) -> Self {
        self.0 |= 1 << 63;
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
    /// 须可从 `klib::error::Error` 构造，保证上层（`mm`/`kernel`）经统一错误码
    /// 传递（ADR-010），架构差异不泄漏成不同错误类型（ADR-007）。
    type Error: core::fmt::Debug + From<klib::error::Error>;

    /// 新建一个独立的页表：**继承当前内核半区映射**（所有进程共享内核映射），
    /// **用户半区为空**（每个进程独立的用户地址空间）。
    ///
    /// 用于进程地址空间：`spawn`（ADR-003）时从内核页表派生出新进程页表，
    /// 但不复制父进程的用户区。
    fn new() -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// 把物理页 `paddr` 以 `size` 大小映射到虚拟地址 `vaddr`。
    fn map(&mut self, vaddr: VirtAddr, paddr: PhysAddr, size: PageSize, flags: PageFlags) -> Result<(), Self::Error>;

    /// 解除 `vaddr` 处的映射，返回被解映射的物理地址。
    fn unmap(&mut self, vaddr: VirtAddr) -> Result<PhysAddr, Self::Error>;

    /// 翻译虚拟地址 → 物理地址。
    fn translate(&self, vaddr: VirtAddr) -> Option<PhysAddr>;

    /// 顶层页表物理基址（= 装载到 CR3 等页表寄存器的值）。
    ///
    /// 用于进程进入用户态/调度切换时装载进程自己的页表（M2.1 扩展 TrapFrame
    /// 的 `cr3` 字段）。默认返回 0；架构实现应返回真实页表物理基址。
    fn paddr(&self) -> u64 {
        0
    }
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
