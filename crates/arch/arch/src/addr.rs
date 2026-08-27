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

/// 为对称的新类型地址（如 `PhysAddr`/`VirtAddr`）生成公共方法。
macro_rules! impl_newtype_addr {
    ($ty:ident, $debug_name:literal) => {
        impl $ty {
            /// 从 u64 构造该地址。
            pub const fn new(addr: u64) -> Self {
                Self(addr)
            }

            /// 取出裸 u64 值。
            pub const fn as_u64(self) -> u64 {
                self.0
            }

            /// 以该地址为起始、恰好含一个 4KB 页。
            pub const fn containing_page(self) -> Self {
                Self(self.0 & !0xFFF)
            }

            /// 是否 4KB 对齐。
            pub const fn is_aligned_4k(self) -> bool {
                self.0 & 0xFFF == 0
            }
        }

        impl core::fmt::Debug for $ty {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, concat!($debug_name, "({:#x})"), self.0)
            }
        }
    };
}

impl_newtype_addr!(PhysAddr, "PhysAddr");
impl_newtype_addr!(VirtAddr, "VirtAddr");

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

    /// 从裸 `u64` 物理地址构造页帧（自动对齐到 4KB 页起始）。
    pub const fn from_paddr_raw(paddr: u64) -> Self {
        Self {
            start: PhysAddr::new(paddr).containing_page(),
        }
    }

    /// 返回页帧的起始物理地址。
    pub const fn start_address(self) -> PhysAddr {
        self.start
    }

    /// 返回页帧起始物理地址的裸 `u64` 值。
    pub const fn start_paddr(self) -> u64 {
        self.start.as_u64()
    }

    /// 从物理地址构造页帧，要求已按 4KB 对齐（否则 panic）。
    ///
    /// S07 成文：doc 声称"否则 panic"，但实现不校验即破坏核心不变式
    /// '始终 4KB 对齐'。加入 `debug_assert` 使未对齐构造在调试构建中
    /// 被拦截，确保不变式不被静默违反。
    pub const fn from_aligned(addr: PhysAddr) -> Self {
        debug_assert!(
            addr.as_u64() & 0xFFF == 0,
            "PhysFrame::from_aligned requires 4KB-aligned address"
        );
        Self { start: addr }
    }
}

impl fmt::Debug for PhysFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PhysFrame({:?})", self.start)
    }
}
