//! 极简 MMIO 映射。
//!
//! Limine 引导后内核运行在 4 级分页下，其 HHDM 偏移映射的是物理 RAM，
//! 并不覆盖 LAPIC 等 MMIO 设备区域（如 0xFEE00000）。
//! 本模块在启动早期、虚拟内存子系统（地基二）就绪前，直接操作当前
//! CR3 页表，把指定物理地址以 2MB 大页映射到高半区虚拟地址，供访问
//! LAPIC 等设备寄存器使用。

use crate::diag;
use crate::paging::level_indices;
use crate::serial;

/// 2MB 页大小。
const PAGE_2M: u64 = 0x20_0000;

/// 页表标志（与 `paging` 模块保持一致）。
const FLAG_PRESENT: u64 = 1 << 0;
const FLAG_WRITABLE: u64 = 1 << 1;
const FLAG_LARGE: u64 = 1 << 7;

/// 获取 CR3（PML4 物理地址）。
#[inline]
fn cr3() -> u64 {
    let val: u64;
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) val, options(nomem, nostack)) };
    val
}

/// 刷新 TLB 中指定虚拟地址的条目。
#[inline]
fn invlpg(virt: u64) {
    unsafe { core::arch::asm!("invlpg [{}]", in(reg) virt, options(nostack, preserves_flags)) };
}

/// 把物理地址 `phys`（须 2MB 对齐）映射到虚拟地址 `virt`（须 2MB 对齐），
/// 使用当前 CR3 页表，建立 2MB 大页。
///
/// `phys_offset` 为 HHDM 偏移，用于把页表所在的物理页映射为可访问虚拟地址。
/// 若中间页表页不存在，会复用已存在的（假定 Limine 已建立 0xffff800000000000 处的
/// PML4[510]/PDPT，映射正好落到同一 PDPT 下即可；LAPIC 虚拟地址选在 0xffff8000fee00000，
/// 与 HHDM 同属 PML4 索引 510 的 PDPT，无需新分配 PDPT）。
pub fn map_lapic(phys_offset: u64, phys: u64, virt: u64) -> bool {
    // 物理地址须 2MB 对齐
    if phys & (PAGE_2M - 1) != 0 || virt & (PAGE_2M - 1) != 0 {
        serial::write_str("[mmio] unaligned map\r\n");
        return false;
    }

    // x86-64 4 级分页索引（复用 `paging` 模块的统一计算）
    let [pml4_idx, pdpt_idx, pd_idx, _] = level_indices(virt);

    // PML4 物理地址
    let pml4_phys = cr3() & !0xFFF;
    // 通过 HHDM 访问物理页表
    let pml4 = (phys_offset + pml4_phys) as *mut u64;
    let pml4_entry = unsafe { *pml4.add(pml4_idx) };

    // 若 PDPT 不存在，返回失败（本实现假定已存在）
    if pml4_entry & FLAG_PRESENT == 0 {
        serial::write_str("[mmio] pml4[");
        diag::write_dec(pml4_idx as u128);
        serial::write_str("] not present\r\n");
        return false;
    }
    let pdpt_phys = pml4_entry & 0x000F_FFFF_FFFF_F000;
    let pdpt = (phys_offset + pdpt_phys) as *mut u64;
    let pdpt_entry = unsafe { *pdpt.add(pdpt_idx) };

    if pdpt_entry & FLAG_PRESENT == 0 {
        serial::write_str("[mmio] pdpt[");
        diag::write_dec(pdpt_idx as u128);
        serial::write_str("] not present\r\n");
        return false;
    }
    let pd_phys = pdpt_entry & 0x000F_FFFF_FFFF_F000;
    let pd = (phys_offset + pd_phys) as *mut u64;

    // 设置 2MB 大页条目：物理地址 + present + writable + large
    let entry = (phys & !0x1F_FFFF) | FLAG_PRESENT | FLAG_WRITABLE | FLAG_LARGE;
    unsafe {
        core::ptr::write_volatile(pd.add(pd_idx), entry);
    }
    invlpg(virt);
    true
}
