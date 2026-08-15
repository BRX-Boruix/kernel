//! 物理/虚拟地址类型（架构无关）。
//!
//! 这些类型作为 `PageTable` 等抽象接口的参数，放在 `arch` 抽象层，
//! 使 `mm` 等上层业务逻辑不绑定具体架构（ADR-007）。

use core::fmt;

/// 物理地址。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PhysAddr(u64);

/// 虚拟地址。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct VirtAddr(u64);

impl PhysAddr {
    /// 从 u64 构造物理地址。
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    /// 取出裸 u64 值。
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// 以该地址为起始、恰好含一个 4KB 物理页。
    pub const fn containing_page(self) -> Self {
        Self(self.0 & !0xFFF)
    }

    /// 是否 4KB 对齐。
    pub const fn is_aligned_4k(self) -> bool {
        self.0 & 0xFFF == 0
    }
}

impl VirtAddr {
    /// 从 u64 构造虚拟地址。
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    /// 取出裸 u64 值。
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// 以该地址为起始、恰好含一个 4KB 虚拟页。
    pub const fn containing_page(self) -> Self {
        Self(self.0 & !0xFFF)
    }

    /// 是否 4KB 对齐。
    pub const fn is_aligned_4k(self) -> bool {
        self.0 & 0xFFF == 0
    }
}

impl fmt::Debug for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PhysAddr({:#x})", self.0)
    }
}

impl fmt::Debug for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VirtAddr({:#x})", self.0)
    }
}

/// 一个 4KB 物理页帧。
///
/// 内部是一个物理地址，始终按 4KB 对齐。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PhysFrame {
    start: PhysAddr,
}

impl PhysFrame {
    /// 从物理地址构造页帧（自动对齐到 4KB 页起始）。
    pub const fn containing_address(addr: PhysAddr) -> Self {
        Self {
            start: addr.containing_page(),
        }
    }

    /// 返回页帧的起始物理地址。
    pub const fn start_address(self) -> PhysAddr {
        self.start
    }

    /// 从物理地址构造页帧，要求已按 4KB 对齐（否则 panic）。
    pub const fn from_aligned(addr: PhysAddr) -> Self {
        Self { start: addr }
    }
}

impl fmt::Debug for PhysFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PhysFrame({:?})", self.start)
    }
}
