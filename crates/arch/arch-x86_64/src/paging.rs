//! x86-64 页表实现（基于 CR3 的多级分页）。
//!
//! 实现 `arch::paging::PageTable`。x86-64 使用 4 级页表：
//! PML4 → PDPT → PD → PT。支持 4KB / 2MB / 1GB 页。
//!
//! 支持 LA57（5 级分页）：启动时检测 `CR4.LA57` 位，动态选择 4 级或 5 级
//! 页表，避免在 LA57 机器上把 CR3 指向的 PML5 误当 PML4 使用导致地址错位。
//!
//! 由于 `arch-x86_64` 不依赖 `mm`（避免循环），页表页的分配通过
//! 启动时注入的函数指针完成。

use arch::{phys_to_virt, PageFlags, PageSize, PhysAddr, VirtAddr};
use spin::Once;

use crate::mmio;

// ---- 页表页分配 / 释放注入 ----

/// 分配一个物理页帧作为页表页，返回其物理地址（4KB 对齐）。
/// 返回 0 表示分配失败。由内核在早期注入（实际调用 `mm::allocate_frame`）。
static FRAME_ALLOC: Once<extern "C" fn() -> u64> = Once::new();

/// 释放一个物理页帧（用于回收不再使用的中间页表页）。
/// 由内核注入（实际调用 `mm` 的释放接口）。
static FRAME_DEALLOC: Once<extern "C" fn(u64)> = Once::new();

/// 注入页表页分配与释放。HHDM 偏移由 `arch::hhdm::PHYS_OFFSET` 统一持有。
pub fn init(alloc: extern "C" fn() -> u64, dealloc: extern "C" fn(u64), phys_offset: u64) {
    let _ = FRAME_ALLOC.call_once(|| alloc);
    let _ = FRAME_DEALLOC.call_once(|| dealloc);
    let _ = arch::PHYS_OFFSET.call_once(|| phys_offset);
}

/// 分配一个物理帧并返回其物理地址（0 表示失败）。
///
/// `pub(crate)` 供 `mmio::map_lapic` 在中间页表页缺失时主动分配。
pub(crate) fn alloc_frame() -> Option<u64> {
    let p = FRAME_ALLOC.get().map(|f| f())?;
    if p == 0 {
        None
    } else {
        Some(p)
    }
}

/// 释放一个物理页帧（页表页回收用）。
pub(crate) fn dealloc_frame(paddr: u64) {
    if let Some(f) = FRAME_DEALLOC.get() {
        f(paddr);
    }
}

// ---- 页表标志 ----

pub(crate) const FLAG_PRESENT: u64 = 1 << 0;
pub(crate) const FLAG_WRITABLE: u64 = 1 << 1;
pub(crate) const FLAG_USER: u64 = 1 << 2;
pub(crate) const FLAG_LARGE: u64 = 1 << 7;
pub(crate) const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// 顶层页表条目 256..512 为内核高半区（线性地址最高位 bit47/bit56 决定，与层级数无关）。
///
/// 内核高半区页表页**跨地址空间共享**（每个进程 `new()` 时复制这些顶层条目），
/// 因此这些页表页不能由单个用户地址空间回收/释放——否则会破坏其它进程的内核映射。
pub const KERNEL_HALF_START: usize = 256;

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
    // NX：未显式授予执行权限（PageFlags::executable，bit 63）的页一律不可执行
    if flags.bits() & (1 << 63) == 0 {
        e |= 1 << 63;
    }
    if large {
        e |= FLAG_LARGE;
    }
    e
}

// ---- LA57 / 页表层级数 ----

/// 检测当前是否处于 LA57（5 级分页）模式。
///
/// 读 CR4 的 LA57 位（bit 12）。
#[inline]
fn la57_enabled() -> bool {
    let cr4: u64;
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack));
    }
    cr4 & (1 << 12) != 0
}

/// 当前页表层级数（4 = LA48，5 = LA57）。
///
/// 整个系统在同一时刻只会有一种分页模式，故用运行时函数即可，
/// 无需在 `X86PageTable` 里存字段。
#[inline]
pub(crate) fn page_levels() -> usize {
    if la57_enabled() {
        5
    } else {
        4
    }
}

/// 计算虚地址在 `levels` 级页表中第 `level` 层的索引。
///
/// `level` 从 0（最顶层，PML4 或 PML5）开始计数，最低层是 PT。
///
/// 各层占位域（LA48 为例）：
/// - 顶层 PML4：位 39..48
/// - PDPT：位 30..39
/// - PD：位 21..30
/// - PT：位 12..21
///
/// 通用公式：第 `level` 层的起始位 = `12 + (levels - 1 - level) * 9`。
#[inline]
pub(crate) fn index_at(level: usize, levels: usize, vaddr: u64) -> usize {
    let bit = 12 + (levels - 1 - level) * 9;
    ((vaddr >> bit) & 0x1FF) as usize
}

/// 从叶层表项解析物理地址（区分大页与 4KB 页）。
///
/// `leaf` 是该叶子所处的层级（从顶层 0 数起），`levels` 为页表层级数。
/// 大页大小 = 2^(12 + (levels - 1 - leaf) * 9)。
///
/// 必须与 `ADDR_MASK` 相与以排除 NX（bit63）等高位标志位——否则启用 NX 后
/// `translate`/`unmap` 会把 NX 位误当作物理地址的一部分返回（见回归修复）。
#[inline]
fn entry_paddr(entry: u64, leaf: usize, levels: usize) -> u64 {
    let shift = 12 + (levels - 1 - leaf) * 9;
    // ADDR_MASK 排除 bit63/NX 及其它标志位；再按页大小对齐掩掉低位。
    entry & ADDR_MASK & !((1u64 << shift) - 1)
}

// ---- 页表 ----

/// x86-64 活动页表（持有 CR3 物理地址）。
///
/// 注意：`pml4` 字段在 LA57 下实际是最顶层（PML5），名字沿用以便兼容。
pub struct X86PageTable {
    /// 最顶层页表的物理地址（LA48 为 PML4，LA57 为 PML5）。
    pml4: u64,
}

impl X86PageTable {
    /// 创建一个空的页表：分配一个顶层页并清零。
    pub fn new_empty() -> Option<Self> {
        let top = alloc_frame()?;
        let top_virt = phys_to_virt(top) as *mut u64;
        // 清零 512 项
        unsafe { core::ptr::write_bytes(top_virt, 0, 512) };
        Some(Self { pml4: top })
    }

    /// 从顶层页表物理地址构造（用于包装当前活动页表）。
    pub fn from_pml4(pml4: u64) -> Self {
        Self { pml4 }
    }

    /// 获取顶层页表物理地址（= CR3 值）。
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

    /// 沿虚地址从顶层逐级下降，返回路径上每层的表项、叶层索引与层级数。
    ///
    /// `leaf` 是命中叶子所在的层（`0..=levels-1`）：非最低层命中代表大页。
    /// 若某层表项不存在（present=0）返回 `None`。
    /// 检查一个页表页（512 项）是否全空（present=0）。
    unsafe fn is_table_empty(&self, phys: u64) -> bool {
        let virt = phys_to_virt(phys) as *const u64;
        for i in 0..512 {
            if unsafe { *virt.add(i) } & FLAG_PRESENT != 0 {
                return false;
            }
        }
        true
    }

    unsafe fn walk(&self, vaddr: u64) -> Option<([u64; 5], usize, usize)> {
        let levels = page_levels();
        let mut entries = [0u64; 5];
        let mut table_phys = self.pml4;
        for lvl in 0..levels {
            let entry = unsafe { self.table_at(table_phys, index_at(lvl, levels, vaddr)) };
            if entry & FLAG_PRESENT == 0 {
                return None;
            }
            entries[lvl] = entry;
            // 除最低层外，命中大页即为叶子
            if lvl + 1 < levels && entry & FLAG_LARGE != 0 {
                return Some((entries, lvl, levels));
            }
            table_phys = entry & ADDR_MASK;
        }
        Some((entries, levels - 1, levels))
    }

}

impl arch::ActivePageTable for X86PageTable {
    /// 获取当前活动页表（包装当前 CR3）。
    fn current() -> Self {
        Self {
            pml4: mmio::cr3() & !0xFFF,
        }
    }

    /// 切换活动页表（写 CR3）。
    fn activate(&self) {
        mmio::write_cr3(self.pml4);
    }
}

impl arch::PageTable for X86PageTable {
    type Error = klib::error::Error;

    fn new() -> Result<Self, Self::Error> {
        // 1. 分配新顶层页表页并清零
        let top = alloc_frame().ok_or(klib::error::Error::OutOfMemory)?;
        let top_virt = phys_to_virt(top) as *mut u64;
        unsafe { core::ptr::write_bytes(top_virt, 0, 512) };

        // 2. 复制当前内核页表的高半区顶层条目（所有进程共享内核映射）。
        //    用户/内核分界在顶层条目 256 处（线性地址的最高位，bit47/bit56 决定，
        //    对应顶层 9 位索引的最高位），与页表层级数（LA48/LA57）无关。
        //    用户半区（顶层条目 0..255）保持为空，实现"独立用户地址空间"。
        //    CR3 返回的是 PML4 的物理地址，须经 HHDM 映射为虚拟地址才能解引用。
        let cur_top = phys_to_virt(mmio::cr3() & !0xFFF) as *const u64;
        for i in KERNEL_HALF_START..512 {
            let entry = unsafe { *cur_top.add(i) };
            if entry != 0 {
                unsafe { *top_virt.add(i) = entry };
            }
        }

        Ok(Self { pml4: top })
    }

    fn map(&mut self, vaddr: VirtAddr, paddr: PhysAddr, size: PageSize, flags: PageFlags) -> Result<(), Self::Error> {
        let levels = page_levels();
        let v = vaddr.as_u64();
        let p = paddr.as_u64();

        // 页大小决定叶层（从顶层 0 数起）：
        //   4K -> 最低层 (levels-1)
        //   2M -> 低二层 (levels-2)
        //   1G -> 低三层 (levels-3)
        let leaf_level = match size {
            PageSize::Size4K => levels - 1,
            PageSize::Size2M => levels - 2,
            PageSize::Size1G => levels - 3,
        };

        // 逐级下降，必要时创建中间页表页。
        let mut table_phys = self.pml4;
        for lvl in 0..leaf_level {
            let idx = index_at(lvl, levels, v);
            let entry = unsafe { self.table_at(table_phys, idx) };
            if entry & FLAG_PRESENT == 0 {
                let new_child = alloc_frame().ok_or(klib::error::Error::OutOfMemory)?;
                // 清零子表
                unsafe { core::ptr::write_bytes(phys_to_virt(new_child) as *mut u64, 0, 512) };
                // 连接：present | writable |（若叶层映射是用户页，则中间层也须置 USER 位）
                // 关键：用户态（Ring3）访问时，CPU 会检查每一级条目的 U/S 位。若中间层
                // 条目没有 USER 位，即使叶层有 USER 位，用户态访问也会 #PF（present 但
                // 权限不足，错误码 P=1,U/S=1）。故中间层必须继承叶层的 USER 位。
                let user_bit = flags.bits() & FLAG_USER;
                let child_entry = new_child & ADDR_MASK | FLAG_PRESENT | FLAG_WRITABLE | user_bit;
                unsafe { self.table_set(table_phys, idx, child_entry) };
                table_phys = new_child;
            } else {
                table_phys = entry & ADDR_MASK;
            }
        }

        // 在叶层写条目
        let leaf_idx = index_at(leaf_level, levels, v);
        let large = leaf_level + 1 < levels; // 非最低层即大页
        let base = if large {
            // 大页：按页大小对齐物理地址
            let shift = 12 + (levels - 1 - leaf_level) * 9;
            p & !((1u64 << shift) - 1)
        } else {
            p & !0xFFF
        };
        let entry_val = base | entry_from_flags(flags, large);
        unsafe { self.table_set(table_phys, leaf_idx, entry_val) };
        Ok(())
    }

    fn unmap(&mut self, vaddr: VirtAddr) -> Result<PhysAddr, Self::Error> {
        let v = vaddr.as_u64();
        let (entries, leaf, levels) = unsafe { self.walk(v) }.ok_or(klib::error::Error::NotFound)?;
        // 清掉叶层条目：父表 = 上一层的下一级表（顶层时为自身）
        let parent_phys = if leaf == 0 {
            self.pml4
        } else {
            entries[leaf - 1] & ADDR_MASK
        };
        let leaf_idx = index_at(leaf, levels, v);
        unsafe { self.table_set(parent_phys, leaf_idx, 0) };
        flush_tlb(v);

        // 回收中间页表页：仅当映射的是 4KB 页（leaf == levels-1）时才存在
        // 其下方的页表页链。逐级向上检查，若某级页表页全空则释放该页并清掉
        // 父层对应条目，直到某级不空或到达顶层（顶层/大页永不释放）。
        //
        // 地址空间隔离（ADR-007）：`new()` 派生页表时复制了内核高半区顶层条目，
        // 其指向的中间页表页**跨地址空间共享**。因此只有**用户半区**的页表页是
        // 本地址空间私有的、可回收；内核半区页表页绝不能在此释放（否则破坏其它
        // 进程的内核映射）。用户地址空间也不应解映射内核半区，这里一并拒绝。
        let top_idx = index_at(0, levels, v);
        if top_idx >= KERNEL_HALF_START {
            return Err(klib::error::Error::InvalidParam);
        }
        if leaf == levels - 1 && levels >= 3 {
            // 从 PT 的父层（leaf-1）开始，逐级向上回收已空的中间页表页；
            // 一直收到 level 1（PDPT），但**不回收顶层页表页**（level 0 / PML4）——
            // 顶层由 `UserAddressSpace::destroy` 统一释放，此处若释放会破坏同地址
            // 空间内仍存在的其它映射。用 `isize` 以便 `cur_level` 递减到 -1 自然退出。
            let mut cur_level = leaf as isize - 1;
            while cur_level >= 0 {
                let cl = cur_level as usize;
                // 当前层指向的（下一级）空页表页物理地址 = entries[cl] & ADDR_MASK。
                let table_phys = entries[cl] & ADDR_MASK;
                if table_phys == 0 || table_phys == self.pml4 {
                    break; // 空表或顶层页表页本身（顶层由 destroy 回收），停止
                }
                if !unsafe { self.is_table_empty(table_phys) } {
                    break; // 该层还有其它映射，停止回收
                }
                // 清掉父层指向该空表的条目：父表为上一层（cl-1）的表，
                // 当 cl==0 时父表即顶层表自身。
                let parent_phys = if cl == 0 {
                    self.pml4
                } else {
                    entries[cl - 1] & ADDR_MASK
                };
                unsafe { self.table_set(parent_phys, index_at(cl, levels, v), 0) };
                flush_tlb(v);
                dealloc_frame(table_phys);
                // 继续向上（直到 PDPT / 顶层边界）
                cur_level -= 1;
            }
        }

        Ok(PhysAddr::new(entry_paddr(entries[leaf], leaf, levels)))
    }

    fn translate(&self, vaddr: VirtAddr) -> Option<PhysAddr> {
        let (entries, leaf, levels) = unsafe { self.walk(vaddr.as_u64()) }?;
        Some(PhysAddr::new(entry_paddr(entries[leaf], leaf, levels)))
    }

    fn paddr(&self) -> u64 {
        self.pml4
    }

    /// 当前活动页表的顶层物理基址（= CR3 & ~0xFFF）。
    fn current_paddr() -> u64 {
        mmio::cr3() & !0xFFF
    }
}

/// 刷新 TLB 中一个虚拟地址。
#[inline]
pub(crate) fn flush_tlb(vaddr: u64) {
    unsafe { core::arch::asm!("invlpg [{}]", in(reg) vaddr, options(nostack, preserves_flags)) };
}
