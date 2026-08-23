//! 极简 MMIO 映射。
//!
//! Limine 引导后内核运行在 4 级分页下，其 HHDM 偏移映射的是物理 RAM，
//! 并不覆盖 LAPIC 等 MMIO 设备区域（如 0xFEE00000）。
//! 本模块在启动早期、虚拟内存子系统（地基二）就绪前，直接操作当前
//! CR3 页表，把指定物理地址映射到高半区虚拟地址，供访问 LAPIC、
//! HPET、PCI BAR 等设备寄存器使用。
//!
//! 支持两种页大小：
//! - 2MB 大页（[`map_phys`] 传 `PageSize::Size2M`，或 [`map_lapic`] 便捷入口）：
//!   适合 LAPIC（0xFEE00000）等 2MB 对齐的大块设备区域；
//! - **4KB 页**（[`map_phys`] 传 `PageSize::Size4K`，或 [`map_phys_4k`] 便捷入口）：
//!   适合 PCI BAR 等任意对齐、小块设备寄存器。

use crate::paging::{
    ADDR_MASK, FLAG_LARGE, FLAG_PCD, FLAG_PRESENT, FLAG_WRITABLE, flush_tlb, index_at,
    page_levels,
};
use arch::PageSize;
use arch::phys_to_virt;
use core::sync::atomic::{AtomicBool, Ordering};

/// 2MB 页大小。
const PAGE_2M: u64 = 0x20_0000;
/// 4KB 页大小。
const PAGE_4K: u64 = 0x1000;

/// 设备 MMIO 映射统一虚拟基址（内核高半区）。
///
/// LAPIC/HPET 等 MMIO 区域不在 Limine HHDM 内（HHDM 只覆盖 RAM），由本模块
/// 经 `map_phys*` 自行建立页表映射。所有设备映射的虚拟地址都必须落在同一
/// 高半区基址上——此前 lapic/hpet 各自硬编码该常量（arch1.md AA2），偏移一变
/// 两处同时静默错映射。取值 = bit47 置位的高半区起点，与
/// [`crate::paging::KERNEL_HALF_START`]（顶层条目 256..512）的分界一致，
/// 保证这些映射随内核半区在所有地址空间共享。
pub const DEVICE_MMIO_VIRT_BASE: u64 = 0xffff_8000_0000_0000;

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

/// 把物理地址 `phys` 映射到虚拟地址 `virt`（按 `size` 对齐），使用当前
/// CR3 页表，建立大页（2MB）或 4KB 页映射。
///
/// 通过 `arch::phys_to_virt` 把页表所在的物理页换算为可访问虚拟地址。
/// 逐级下降时若某中间页表页缺失，会**主动分配**并清零，而不是假定 Limine
/// 已建立对应层级——因此不依赖特定内存布局。
///
/// 支持 LA57：层数由 `page_levels()` 动态决定。2MB 大页落在 PD 层
/// （层序号 = `levels - 2`），4KB 页落在 PT 层（层序号 = `levels - 1`）。
///
/// 返回 `false` 表示参数非法（未对齐）或页表页分配失败。
pub fn map_phys(phys: u64, virt: u64, size: PageSize) -> bool {
    let (leaf_level, mask) = match size {
        PageSize::Size2M => {
            if phys & (PAGE_2M - 1) != 0 || virt & (PAGE_2M - 1) != 0 {
                klib::info!("[mmio] unaligned 2M map");
                return false;
            }
            (page_levels() - 2, PAGE_2M - 1)
        }
        PageSize::Size4K => {
            if phys & (PAGE_4K - 1) != 0 || virt & (PAGE_4K - 1) != 0 {
                klib::info!("[mmio] unaligned 4K map");
                return false;
            }
            (page_levels() - 1, PAGE_4K - 1)
        }
        PageSize::Size1G => {
            klib::info!("[mmio] 1G map not supported");
            return false;
        }
    };
    let levels = page_levels();
    let large = leaf_level + 1 < levels; // 非最低层即大页

    // 从当前 CR3 的顶层逐级下降至叶层。中间层缺失时主动分配。
    let mut table_phys = cr3() & !0xFFF;
    for lvl in 0..leaf_level {
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

    // 设置叶层条目：物理地址 + present + writable（+ large 若大页）。
    //
    // 审计 B24：设备内存必须 **PCD（bit4，不可缓存）**——本函数的全部调用方
    // （LAPIC、HPET、早期 MMIO）映射的都是寄存器窗口，读有副作用，缓存/
    // 投机语义不可接受。此前未置 PCD 时正确性靠 MTRR 默认 UC 巧合兜底；
    // 现在属性由映射点显式声明，与 paging.rs entry_from_flags 的
    // device_memory 语义同源（SDM Vol.3 §11.5）。
    let leaf_idx = index_at(leaf_level, levels, virt);
    let mut entry =
        (phys & !mask) | FLAG_PRESENT | FLAG_WRITABLE | FLAG_PCD;
    if large {
        entry |= FLAG_LARGE;
    }
    unsafe { write_u64(phys_to_virt(table_phys) + leaf_idx as u64 * 8, entry) };
    flush_tlb(virt);
    true
}

/// 4KB 页级 MMIO 映射便捷入口（PCI BAR 等任意对齐小块设备寄存器）。
///
/// `phys`/`virt` 须 4KB 对齐。返回 `false` 表示失败。
pub fn map_phys_4k(phys: u64, virt: u64) -> bool {
    map_phys(phys, virt, PageSize::Size4K)
}

/// 2MB 大页 MMIO 映射便捷入口（LAPIC 等 2MB 对齐大块设备区域）。
///
/// 向后兼容入口，等价于 `map_phys(phys, virt, PageSize::Size2M)`。
pub fn map_lapic(phys: u64, virt: u64) -> bool {
    map_phys(phys, virt, PageSize::Size2M)
}

/// 4KB 页级 MMIO 映射自检（启动早期由内核调用）。
///
/// 映射**物理 RAM**（实模式 BIOS 数据区，物理 0x0 起的首个 4KB 页，始终
/// 可读可写）到高半区虚拟地址，写读回环确认 4KB 映射路径可用。
/// 用 RAM 而非设备区域（如 VGA），避免 `-display none` 等环境下设备寄存器
/// 读回全 0xFF 造成误判。
///
/// 依赖页表页分配器（`paging::init` 注入），须在其后调用。
pub fn test_map_phys_4k() {
    // 物理 RAM 首 4KB 页（BIOS 数据区，4KB 对齐）。
    const RAM_PHYS: u64 = 0x0;
    // 映射到高半区固定槽位（不与内核既有映射冲突）。
    const RAM_VIRT: u64 = 0xFFFF_FFFF_0100_0000;

    if !map_phys_4k(RAM_PHYS, RAM_VIRT) {
        klib::warn!("[mmio] 4K map failed");
        return;
    }
    // 写 0x5A 到该页末字节（避开实模式 IVT 起始区域）并读回验证。
    const MARK_ADDR: u64 = RAM_VIRT + 0xFF0;
    unsafe {
        write_u32(MARK_ADDR, 0x5A);
        let v = read_u32(MARK_ADDR);
        if v == 0x5A {
            klib::info!(
                "[mmio] 4K map verified: phys {:#x} -> virt {:#x}",
                RAM_PHYS,
                RAM_VIRT
            );
        } else {
            klib::warn!("[mmio] 4K map readback mismatch: {:#x}", v);
        }
    }
}

// ---- CR4 / SMEP / SMAP 支持 ----

/// 读取 CR4。
#[inline]
pub fn read_cr4() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) val, options(nomem, nostack));
    }
    val
}

/// 写入 CR4（仅在分页已启用、长模式下调用）。
#[inline]
pub fn write_cr4(val: u64) {
    unsafe {
        core::arch::asm!("mov cr4, {}", in(reg) val, options(nostack));
    }
}

/// 是否已在当前 CPU 上开启 SMAP（CR4.SMAP=1）。
///
/// 门控 [`stac`]/[`clac`]：SMAP 未开启（或 CPU 不支持）时这两个指令本质是
/// no-op——既避免在不支持 SMAP 的 CPU 上执行 `stac`/`clac` 触发 #UD，又保证
/// 语义自洽（无 SMAP 时内核本就可直接访问用户页，无需放行）。
static SMAP_ACTIVE: AtomicBool = AtomicBool::new(false);

/// 标记 SMAP 是否已启用（由 `cpu::enable_smep_smap` 在成功写 CR4 后调用）。
pub fn set_smap_active(on: bool) {
    SMAP_ACTIVE.store(on, Ordering::Relaxed);
}

/// 置 EFLAGS.AC 位：允许内核态（CPL=0）临时访问用户页（SMAP 的"白名单"放行）。
///
/// 开启 SMAP 后内核态默认禁止读写带 USER 权限的页；对来自用户的缓冲区做合法
/// 拷贝时，在访问前后用 `stac`/`clac` 临时放行。SMAP 未开启时本函数为 no-op。
#[inline]
pub unsafe fn stac() {
    if SMAP_ACTIVE.load(Ordering::Relaxed) {
        core::arch::asm!("stac", options(nomem, nostack, preserves_flags));
    }
}

/// 清 EFLAGS.AC 位：恢复 SMAP 默认禁止内核访问用户页。SMAP 未开启时 no-op。
#[inline]
pub unsafe fn clac() {
    if SMAP_ACTIVE.load(Ordering::Relaxed) {
        core::arch::asm!("clac", options(nomem, nostack, preserves_flags));
    }
}

/// 从用户虚拟地址 `src` 拷贝 `len` 字节到内核 `dst`（SMAP 安全）。
///
/// 内部 STAC 放行，并以编译器屏障防止访问被移出 STAC/CLAC 区间，CLAC 恢复。
pub unsafe fn copy_from_user(dst: *mut u8, src: u64, len: usize) {
    if len == 0 {
        return;
    }
    stac();
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    core::ptr::copy_nonoverlapping(src as *const u8, dst, len);
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    clac();
}

/// 从内核 `src` 拷贝 `len` 字节到用户虚拟地址 `dst`（SMAP 安全）。
pub unsafe fn copy_to_user(dst: u64, src: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    stac();
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    core::ptr::copy_nonoverlapping(src, dst as *mut u8, len);
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    clac();
}
