//! 极简 MMIO 映射。
//!
//! Limine 引导后内核运行在 4 级分页下，其 HHDM 偏移映射的是物理 RAM，
//! 并不覆盖 LAPIC 等 MMIO 设备区域（如 0xFEE00000）。
//! 本模块在启动早期、虚拟内存子系统（地基二）就绪前，直接操作当前
//! CR3 页表，把指定物理地址以 2MB 大页映射到高半区虚拟地址，供访问
//! LAPIC 等设备寄存器使用。

use arch::phys_to_virt;
use crate::paging::{
    flush_tlb, index_at, page_levels, ADDR_MASK, FLAG_LARGE, FLAG_PRESENT, FLAG_WRITABLE,
};

/// 2MB 页大小。
const PAGE_2M: u64 = 0x20_0000;

// ---- MMIO volatile 访问原语（供 lapic、paging 等复用）----

/// 从 `addr` 读取一个 u32（volatile）。
#[inline]
pub unsafe fn read_u32(addr: u64) -> u32 {
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// 向 `addr` 写一个 u32（volatile）。
#[inline]
pub unsafe fn write_u32(addr: u64, val: u32) {
    unsafe { core::ptr::write_volatile(addr as *mut u32, val) };
}

/// 从 `addr` 读取一个 u64（volatile）。
#[inline]
pub unsafe fn read_u64(addr: u64) -> u64 {
    unsafe { core::ptr::read_volatile(addr as *const u64) }
}

/// 向 `addr` 写一个 u64（volatile）。
#[inline]
pub unsafe fn write_u64(addr: u64, val: u64) {
    unsafe { core::ptr::write_volatile(addr as *mut u64, val) };
}

/// 读取 CR3（PML4 物理地址）。
#[inline]
pub fn cr3() -> u64 {
    let val: u64;
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) val, options(nomem, nostack)) };
    val
}

/// 读取 CR2（页错误线性地址）。
#[inline]
pub fn cr2() -> u64 {
    let val: u64;
    unsafe { core::arch::asm!("mov {}, cr2", out(reg) val, options(nomem, nostack)) };
    val
}

/// 写入 CR3（切换页表）。
#[inline]
pub fn write_cr3(val: u64) {
    unsafe { core::arch::asm!("mov cr3, {}", in(reg) val, options(nostack)) };
}

/// 把物理地址 `phys`（须 2MB 对齐）映射到虚拟地址 `virt`（须 2MB 对齐），
/// 使用当前 CR3 页表，建立 2MB 大页。
///
/// 通过 `arch::phys_to_virt` 把页表所在的物理页换算为可访问虚拟地址。
/// 逐级下降时若某中间页表页缺失，会**主动分配**并清零，而不是假定 Limine
/// 已建立对应层级——因此不依赖特定内存布局（修复原"复用已存在页表页"的假设）。
///
/// 支持 LA57：层数由 `page_levels()` 动态决定，2MB 大页落在 PD 层
/// （其层序号 = `levels - 2`）。
pub fn map_lapic(phys: u64, virt: u64) -> bool {
    // 物理地址须 2MB 对齐
    if phys & (PAGE_2M - 1) != 0 || virt & (PAGE_2M - 1) != 0 {
        klib::info!("[mmio] unaligned map");
        return false;
    }

    let levels = page_levels();
    // 2MB 大页所在层 = PD = 最低层往上一级 = levels - 2
    let pd_level = levels - 2;

    // 从当前 CR3 的顶层逐级下降至 PD 层。中间层缺失时主动分配。
    let mut table_phys = cr3() & !0xFFF;
    for lvl in 0..pd_level {
        let idx = index_at(lvl, levels, virt);
        let entry = unsafe { read_u64(phys_to_virt(table_phys) + idx as u64 * 8) };
        let next = if entry & FLAG_PRESENT != 0 {
            entry & ADDR_MASK
        } else {
            // 分配新页表页并清零
            let Some(new) = crate::paging::alloc_frame() else {
                klib::info!("[mmio] level {} no frame for page table", lvl);
                return false;
            };
            unsafe {
                // 清零 512 项
                core::ptr::write_bytes(phys_to_virt(new) as *mut u8, 0, 4096);
                // 连接：present | writable（子表本身）
                write_u64(
                    phys_to_virt(table_phys) + idx as u64 * 8,
                    (new & ADDR_MASK) | FLAG_PRESENT | FLAG_WRITABLE,
                );
            }
            new
        };
        table_phys = next;
    }

    // 设置 2MB 大页条目：物理地址 + present + writable + large
    let pd_idx = index_at(pd_level, levels, virt);
    let entry = (phys & !0x1F_FFFF) | FLAG_PRESENT | FLAG_WRITABLE | FLAG_LARGE;
    unsafe { write_u64(phys_to_virt(table_phys) + pd_idx as u64 * 8, entry) };
    flush_tlb(virt);
    true
}
