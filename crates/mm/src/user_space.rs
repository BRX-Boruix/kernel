//! 用户地址空间（每进程独立虚拟地址空间）。
//!
//! M1 里程碑：为进程提供独立的用户地址空间。
//! - 通过 `PT::new()` 从当前内核页表派生（继承内核映射，用户半区为空）——ADR-007/ADR-003。
//! - 提供用户区映射/解映射/翻译 API，区分用户映射（带 `user` 标志）。
//! - 记录已声明的用户区域（Area），为 M1.3 按需分页提供基础。
//!
//! 泛型 `PT: PageTable` 使其不绑定具体架构（ADR-007）。
//! `PT::Error` 需可从 `&'static str` 构造（x86 实现 `Error = &'static str` 满足）。

use alloc::vec::Vec;

use arch::{ActivePageTable, PageFlags, PageSize, PhysAddr, PageTable, VirtAddr};

/// 用户地址空间默认边界。x86-64 低半区为 bit63=0 的 128TiB。
pub const USER_BASE: u64 = 0x0000_0000_0000_0000;
pub const USER_TOP: u64 = 0x0000_8000_0000_0000; // 128TiB，x86-64 低半区边界

/// 用户区映射记录（按需分页 / 统计用）。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UserArea {
    /// 起始虚拟地址（页对齐）。
    pub start: VirtAddr,
    /// 结束虚拟地址（不含，页对齐）。
    pub end: VirtAddr,
    /// 页大小。
    pub size: PageSize,
    /// 权限标志。
    pub flags: PageFlags,
}

/// 用户地址空间：持有独立页表 `PT`，管理用户区。
pub struct UserAddressSpace<PT: PageTable> {
    /// 独立页表（继承内核映射 + 独立用户区）。
    pt: PT,
    /// 已声明的用户区域。
    areas: spin::Mutex<Vec<UserArea>>,
}

impl<PT> UserAddressSpace<PT>
where
    PT: PageTable,
    PT::Error: From<&'static str>,
{
    /// 新建一个用户地址空间：从当前内核页表派生独立页表（ADR-003 纯 spawn）。
    pub fn new() -> Result<Self, PT::Error> {
        let pt = PT::new()?;
        Ok(Self {
            pt,
            areas: spin::Mutex::new(Vec::new()),
        })
    }

    /// 在用户空间映射一段物理页。
    ///
    /// `start`/`end` 必须在用户半区（`USER_BASE..USER_TOP`），否则返回错误。
    /// `phys_frames` 提供每页物理地址，长度需覆盖 `end-start` 的页数。
    pub fn map_user(
        &mut self,
        start: VirtAddr,
        end: VirtAddr,
        size: PageSize,
        flags: PageFlags,
        phys_frames: &[u64],
    ) -> Result<(), PT::Error> {
        let s = start.as_u64();
        let e = end.as_u64();
        if s < USER_BASE || e > USER_TOP || e <= s {
            return Err("user region out of range".into());
        }
        // 强制带 user 标志，保证用户态可访问
        let uflags = flags.user();
        let page = size.bytes();
        let count = ((e - s) + page - 1) / page;
        if (phys_frames.len() as u64) < count {
            return Err("not enough phys frames".into());
        }
        let mut vaddr = s;
        for &phys in phys_frames.iter().take(count as usize) {
            self.pt.map(VirtAddr::new(vaddr), PhysAddr::new(phys), size, uflags)?;
            vaddr += page;
        }
        self.areas.lock().push(UserArea { start, end, size, flags: uflags });
        Ok(())
    }

    /// 解除用户空间某虚拟地址的映射，返回被解映射的物理地址。
    pub fn unmap_user(&mut self, vaddr: VirtAddr) -> Result<PhysAddr, PT::Error> {
        self.pt.unmap(vaddr)
    }

    /// 翻译用户空间虚拟地址 → 物理地址。
    pub fn translate(&self, vaddr: VirtAddr) -> Option<PhysAddr> {
        self.pt.translate(vaddr)
    }

    /// 把本用户地址空间切换为活动页表（装入 CR3）。需 `PT: ActivePageTable`。
    pub fn activate(&self)
    where
        PT: ActivePageTable,
    {
        self.pt.activate();
    }

    /// 已声明的用户区域数（诊断用）。
    pub fn area_count(&self) -> usize {
        self.areas.lock().len()
    }
}
