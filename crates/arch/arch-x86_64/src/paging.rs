//! x86-64 页表实现（基于 CR3 的多级分页）。
//!
//! 实现 `arch::paging::PageTable`。x86-64 使用 4 级页表：
//! PML4 → PDPT → PD → PT。支持 4KB / 2MB / 1GB 页。
//!
//! 由于 `arch-x86_64` 不依赖 `mm`（避免循环），页表页的分配通过
//! 启动时注入的函数指针完成。

use arch::{phys_to_virt, PageFlags, PageSize, PhysAddr, VirtAddr};
use spin::Once;

use crate::mmio;

// ---- 页表页分配注入 ----

/// 分配一个物理页帧作为页表页，返回其物理地址（4KB 对齐）。
/// 返回 0 表示分配失败。由内核在早期注入（实际调用 `mm::allocate_frame`）。
static FRAME_ALLOC: Once<extern "C" fn() -> u64> = Once::new();

/// 注入页表页分配。HHDM 偏移由 `arch::hhdm::PHYS_OFFSET` 统一持有。
pub fn init(alloc: extern "C" fn() -> u64, phys_offset: u64) {
    let _ = FRAME_ALLOC.call_once(|| alloc);
    let _ = arch::PHYS_OFFSET.call_once(|| phys_offset);
}

/// 分配一个物理帧并返回其物理地址（0 表示失败）。
fn alloc_frame() -> Option<u64> {
    let p = FRAME_ALLOC.get().map(|f| f())?;
    if p == 0 {
        None
    } else {
        Some(p)
    }
}

// ---- 页表标志 ----

pub(crate) const FLAG_PRESENT: u64 = 1 << 0;
pub(crate) const FLAG_WRITABLE: u64 = 1 << 1;
pub(crate) const FLAG_USER: u64 = 1 << 2;
pub(crate) const FLAG_LARGE: u64 = 1 << 7;
pub(crate) const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// 由 `PageFlags` 与页大小构造 4KB 页表条目。
fn entry_from_flags(flags: PageFlags, large: bool) -> u64 {
    let mut e = 0u64;
    e |= FLAG_PRESENT;
    if flags.bits() & (1 << 1) != 0 {
        e |= FLAG_WRITABLE;
    }
    if flags.bits() & (1 << 2) != 0 {
        e |= FLAG_USER;
    }
    if large {
        e |= FLAG_LARGE;
    }
    e
}

/// x86-64 活动页表（持有 CR3 物理地址）。
pub struct X86PageTable {
    /// PML4 的物理地址。
    pml4: u64,
}

impl X86PageTable {
    /// 创建一个空的页表：分配一个 PML4 页并清零。
    pub fn new_empty() -> Option<Self> {
        let pml4 = alloc_frame()?;
        let pml4_virt = phys_to_virt(pml4) as *mut u64;
        // 清零 512 项
        unsafe { core::ptr::write_bytes(pml4_virt, 0, 512) };
        Some(Self { pml4 })
    }

    /// 从 PML4 物理地址构造（用于包装当前活动页表）。
    pub fn from_pml4(pml4: u64) -> Self {
        Self { pml4 }
    }

    /// 获取 PML4 物理地址（= CR3 值）。
    pub fn pml4_paddr(&self) -> u64 {
        self.pml4
    }

    /// 把本页表切换为活动页表（写 CR3）。
    pub fn activate(&self) {
        mmio::write_cr3(self.pml4);
    }

    /// 直接读一个虚拟地址处的 u64（物理页表页通过 HHDM 访问）。
    unsafe fn table_at(&self, phys: u64, index: usize) -> u64 {
        unsafe { mmio::read_u64(phys_to_virt(phys) as u64 + index as u64 * 8) }
    }

    /// 直接写一个虚拟地址处的 u64。
    unsafe fn table_set(&self, phys: u64, index: usize, val: u64) {
        unsafe { mmio::write_u64(phys_to_virt(phys) as u64 + index as u64 * 8, val) }
    }

    /// 沿虚地址从 PML4 逐级下降，返回路径上每层的表项与叶层索引。
    ///
    /// 叶层索引 `leaf`：`0..=2` 表示在对应层命中了 2MB/1GB 大页，`3` 表示 4KB 页。
    /// 若某层表项不存在（present=0）返回 `None`。
    unsafe fn walk(&self, vaddr: u64) -> Option<([u64; 4], usize)> {
        let indices = level_indices(vaddr);
        let mut table_phys = self.pml4;
        let mut entries = [0u64; 4];
        for lvl in 0..4 {
            let entry = unsafe { self.table_at(table_phys, indices[lvl]) };
            if entry & FLAG_PRESENT == 0 {
                return None;
            }
            entries[lvl] = entry;
            if lvl < 3 && entry & FLAG_LARGE != 0 {
                return Some((entries, lvl));
            }
            table_phys = entry & ADDR_MASK;
        }
        Some((entries, 3))
    }
}

/// 从叶层表项解析物理地址（区分 1GB/2MB 大页与 4KB 页）。
#[inline]
fn entry_paddr(entry: u64, leaf: usize) -> u64 {
    match leaf {
        1 => entry & !0x3F_FFFF_FFFF, // 1GB
        2 => entry & !0x1F_FFFF,      // 2MB
        _ => entry & ADDR_MASK,       // 4KB
    }
}

impl arch::PageTable for X86PageTable {
    type Error = &'static str;

    fn map(&mut self, vaddr: VirtAddr, paddr: PhysAddr, size: PageSize, flags: PageFlags) -> Result<(), Self::Error> {
        let v = vaddr.as_u64();
        let p = paddr.as_u64();
        let indices = level_indices(v);

        // 逐级下降，必要时创建中间页表页。
        let mut table_phys = self.pml4;
        // 页大小决定叶层：
        //   4K -> 叶层索引 = 3（PT）；需要 3 个中间层（PML4/PDPT/PD）
        //   2M -> 叶层索引 = 2（PD 大页）；需要 2 个中间层（PML4/PDPT）
        //   1G -> 叶层索引 = 1（PDPT 大页）；需要 1 个中间层（PML4）
        let leaf_level = match size {
            PageSize::Size4K => 3,
            PageSize::Size2M => 2,
            PageSize::Size1G => 1,
        };

        // 创建中间层（lvl 0 .. leaf_level），每层分配子表并连接
        for lvl in 0..leaf_level {
            let idx = indices[lvl];
            let entry = unsafe { self.table_at(table_phys, idx) };
            if entry & FLAG_PRESENT == 0 {
                let new_child = alloc_frame().ok_or("no frame for page table")?;
                // 清零子表
                unsafe { core::ptr::write_bytes(phys_to_virt(new_child) as *mut u64, 0, 512) };
                // 连接：present | writable（子表本身）
                let child_entry = new_child & ADDR_MASK | FLAG_PRESENT | FLAG_WRITABLE;
                unsafe { self.table_set(table_phys, idx, child_entry) };
                table_phys = new_child;
            } else {
                table_phys = entry & ADDR_MASK;
            }
        }

        // 在叶层写条目
        let leaf_idx = indices[leaf_level];
        let large = leaf_level < 3;
        let base = if large {
            // 大页：低 21/30 位为页内偏移，需保留对齐
            match size {
                PageSize::Size1G => p & !0x3F_FFFF_FFFF,
                _ => p & !0x1F_FFFF,
            }
        } else {
            p & !0xFFF
        };
        let entry_val = base | entry_from_flags(flags, large);
        unsafe { self.table_set(table_phys, leaf_idx, entry_val) };
        Ok(())
    }

    fn unmap(&mut self, vaddr: VirtAddr) -> Result<PhysAddr, Self::Error> {
        let v = vaddr.as_u64();
        let indices = level_indices(v);
        let (entries, leaf) = unsafe { self.walk(v) }.ok_or("not mapped")?;
        // 清掉叶层条目：父表 = 上一层的下一级表（PML4 层时为自身）
        let parent_phys = if leaf == 0 {
            self.pml4
        } else {
            entries[leaf - 1] & ADDR_MASK
        };
        unsafe { self.table_set(parent_phys, indices[leaf], 0) };
        flush_tlb(v);
        Ok(PhysAddr::new(entry_paddr(entries[leaf], leaf)))
    }

    fn translate(&self, vaddr: VirtAddr) -> Option<PhysAddr> {
        let (entries, leaf) = unsafe { self.walk(vaddr.as_u64()) }?;
        Some(PhysAddr::new(entry_paddr(entries[leaf], leaf)))
    }
}

/// 计算 4 级页表索引。
#[inline]
pub(crate) fn level_indices(vaddr: u64) -> [usize; 4] {
    [
        ((vaddr >> 39) & 0x1FF) as usize, // PML4
        ((vaddr >> 30) & 0x1FF) as usize, // PDPT
        ((vaddr >> 21) & 0x1FF) as usize, // PD
        ((vaddr >> 12) & 0x1FF) as usize, // PT
    ]
}

/// 刷新 TLB 中一个虚拟地址。
#[inline]
pub(crate) fn flush_tlb(vaddr: u64) {
    unsafe { core::arch::asm!("invlpg [{}]", in(reg) vaddr, options(nostack, preserves_flags)) };
}
