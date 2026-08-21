//! 地址空间抽象（MemorySet）。
//!
//! 管理一段虚拟地址空间：记录已映射区域，通过泛型 `PT: PageTable` 操作
//! 具体架构页表（ADR-007：业务逻辑依赖 trait，不绑定具体架构）。

use alloc::vec::Vec;
use core::fmt;

use arch::{PageFlags, PageSize, PageTable, PhysAddr, VirtAddr};

/// 一次映射的段记录。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Area {
    /// 起始虚拟地址（页对齐）。
    pub start: VirtAddr,
    /// 结束虚拟地址（不含，页对齐）。
    pub end: VirtAddr,
    /// 页大小。
    pub size: PageSize,
    /// 权限标志。
    pub flags: PageFlags,
}

impl Area {
    /// 新建一段区域。
    pub const fn new(start: VirtAddr, end: VirtAddr, size: PageSize, flags: PageFlags) -> Self {
        Self {
            start,
            end,
            size,
            flags,
        }
    }
}

impl fmt::Debug for Area {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Area[{:#x}..{:#x} size={:?}]",
            self.start.as_u64(),
            self.end.as_u64(),
            self.size
        )
    }
}

/// 地址空间。持有已声明区域列表，实际页表由 `PT` 承载。
pub struct MemorySet<PT: PageTable> {
    areas: spin::Mutex<Vec<Area>>,
    _pt: core::marker::PhantomData<PT>,
}

impl<PT: PageTable> MemorySet<PT> {
    /// 创建地址空间。
    pub fn new() -> Self {
        Self {
            areas: spin::Mutex::new(Vec::new()),
            _pt: core::marker::PhantomData,
        }
    }

    /// 在 `start..end` 区间建立映射。`phys_frames` 提供每页的物理地址
    /// （长度需等于页数；分配由调用方保证成功）。
    ///
    /// `pt` 为活动页表（需已包含内核等映射）。
    pub fn map_range(
        &self,
        pt: &mut PT,
        start: VirtAddr,
        end: VirtAddr,
        size: PageSize,
        flags: PageFlags,
        phys_frames: &[u64],
    ) -> Result<(), PT::Error> {
        let page = size.bytes();
        let count = ((end.as_u64() - start.as_u64()) + page - 1) / page;
        debug_assert!(phys_frames.len() as u64 >= count, "not enough frames");
        let mut vaddr = start.as_u64();
        for &phys in phys_frames.iter().take(count as usize) {
            pt.map(VirtAddr::new(vaddr), PhysAddr::new(phys), size, flags)?;
            vaddr += page;
        }
        // 记录区域
        self.areas.lock().push(Area::new(start, end, size, flags));
        Ok(())
    }

    /// 当前已注册的区域（用于诊断）。
    pub fn areas(&self) -> usize {
        self.areas.lock().len()
    }
}
