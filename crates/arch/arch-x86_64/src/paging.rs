//! x86-64 页表实现（基于 CR3 的多级分页）。
//!
//! 实现 `arch::paging::PageTable`。x86-64 使用 4 级页表：
//! PML4 → PDPT → PD → PT。支持 4KB / 2MB / 1GB 页。
//!
//! 由于 `arch-x86_64` 不依赖 `mm`（避免循环），页表页的分配通过
//! 启动时注入的函数指针完成。

use arch::{PageFlags, PageSize, PhysAddr, VirtAddr};
use spin::Once;

// ---- 页表页分配注入 ----

/// 分配一个物理页帧作为页表页，返回其物理地址（4KB 对齐）。
/// 返回 0 表示分配失败。由内核在早期注入（实际调用 `mm::allocate_frame`）。
static FRAME_ALLOC: Once<extern "C" fn() -> u64> = Once::new();

/// HHDM 偏移（物理 → 虚拟），用于访问物理页表页。
static PHYS_OFFSET: Once<u64> = Once::new();

/// 注入页表页分配与 HHDM 偏移。
pub fn init(alloc: extern "C" fn() -> u64, phys_offset: u64) {
    let _ = FRAME_ALLOC.call_once(|| alloc);
    let _ = PHYS_OFFSET.call_once(|| phys_offset);
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

/// 物理地址 → 可访问的虚拟地址（HHDM）。
#[inline]
fn phys_to_virt(paddr: u64) -> u64 {
    PHYS_OFFSET.get().copied().unwrap_or(0) + paddr
}

// ---- 页表标志 ----

const FLAG_PRESENT: u64 = 1 << 0;
const FLAG_WRITABLE: u64 = 1 << 1;
const FLAG_USER: u64 = 1 << 2;
const FLAG_LARGE: u64 = 1 << 7;
const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

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
        unsafe {
            core::arch::asm!("mov cr3, {}", in(reg) self.pml4, options(nostack));
        }
    }

    /// 直接读一个虚拟地址处的 u64（物理页表页通过 HHDM 访问）。
    unsafe fn table_at(&self, phys: u64, index: usize) -> u64 {
        unsafe { *((phys_to_virt(phys) as *mut u64).add(index)) }
    }

    /// 直接写一个虚拟地址处的 u64。
    unsafe fn table_set(&self, phys: u64, index: usize, val: u64) {
        unsafe {
            core::ptr::write_volatile((phys_to_virt(phys) as *mut u64).add(index), val);
        }
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
        let mut table_phys = self.pml4;

        // 逐级走到叶层
        for lvl in 0..3 {
            let entry = unsafe { self.table_at(table_phys, indices[lvl]) };
            if entry & FLAG_PRESENT == 0 {
                return Err("not mapped");
            }
            if entry & FLAG_LARGE != 0 {
                // 大页：直接解映射
                let paddr = entry & !0x1F_FFFF;
                unsafe { self.table_set(table_phys, indices[lvl], 0) };
                flush_tlb(v);
                return Ok(PhysAddr::new(paddr));
            }
            table_phys = entry & ADDR_MASK;
        }
        // PT 层（第 3 层）
        let entry = unsafe { self.table_at(table_phys, indices[3]) };
        if entry & FLAG_PRESENT == 0 {
            return Err("not mapped");
        }
        let paddr = entry & ADDR_MASK;
        unsafe { self.table_set(table_phys, indices[3], 0) };
        flush_tlb(v);
        Ok(PhysAddr::new(paddr))
    }

    fn translate(&self, vaddr: VirtAddr) -> Option<PhysAddr> {
        let v = vaddr.as_u64();
        let indices = level_indices(v);
        let mut table_phys = self.pml4;

        // 逐级下降（PML4/PDPT/PD），遇大页直接返回
        for lvl in 0..3 {
            let entry = unsafe { self.table_at(table_phys, indices[lvl]) };
            if entry & FLAG_PRESENT == 0 {
                return None;
            }
            if entry & FLAG_LARGE != 0 {
                let base = match lvl {
                    1 => entry & !0x3F_FFFF_FFFF, // 1GB
                    _ => entry & !0x1F_FFFF,      // 2MB
                };
                return Some(PhysAddr::new(base));
            }
            table_phys = entry & ADDR_MASK;
        }
        // PT 层（4KB 页）
        let entry = unsafe { self.table_at(table_phys, indices[3]) };
        if entry & FLAG_PRESENT == 0 {
            return None;
        }
        Some(PhysAddr::new(entry & ADDR_MASK))
    }
}

/// 计算 4 级页表索引。
#[inline]
fn level_indices(vaddr: u64) -> [usize; 4] {
    [
        ((vaddr >> 39) & 0x1FF) as usize, // PML4
        ((vaddr >> 30) & 0x1FF) as usize, // PDPT
        ((vaddr >> 21) & 0x1FF) as usize, // PD
        ((vaddr >> 12) & 0x1FF) as usize, // PT
    ]
}

/// 刷新 TLB 中一个虚拟地址。
#[inline]
fn flush_tlb(vaddr: u64) {
    unsafe { core::arch::asm!("invlpg [{}]", in(reg) vaddr, options(nostack, preserves_flags)) };
}
