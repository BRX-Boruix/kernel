//! HPET（High Precision Event Timer）高精度事件定时器驱动。
//!
//! HPET 是 ACPI 提供的独立高精度定时器硬件（典型频率 14.31818MHz），
//! 计数器单调递增，适合作为高精度时间戳源。当前架构的**主时钟源仍为
//! LAPIC 100Hz 周期定时器**（驱动软件定时器队列/睡眠），HPET 作为
//! 高精度补充：提供微秒级 `now_nanos()`，并用于验证/校准。
//!
//! 初始化流程（由 `arch_x86_64::acpi::init` 解析 HPET 表获得基址/周期后
//! 调用本模块）：
//! 1. 用 4KB 页级 MMIO 映射（`mmio::map_phys_4k`）把 HPET 寄存器区
//!    （如物理 0xFED00000）映射到高半区虚拟地址（与 LAPIC 同模式）；
//! 2. 置 General Configuration（offset 0x10）的 ENABLE_CNF（bit0）启动
//!    主计数器；
//! 3. 读取 Main Counter（offset 0xF0，64 位），按计数器时钟周期
//!    （飞秒）换算纳秒。

use core::sync::atomic::{AtomicU64, Ordering};

use crate::mmio;

/// General Capabilities and ID Register 偏移（bit 32-63 为 COUNTER_CLK_PERIOD，
/// 单位飞秒；bit 0-7 为修订号）。
const REG_CAP_ID: u64 = 0x00;
/// General Configuration 寄存器偏移。
const REG_GC: u64 = 0x10;
/// Main Counter 寄存器偏移。
const REG_COUNTER: u64 = 0xF0;
/// GC 的 ENABLE_CNF 位：置 1 启动计数器。
const GC_ENABLE_CNF: u32 = 1;

/// HPET 寄存器区映射到的虚拟地址（0 = 未初始化）。
static HPET_VIRT: AtomicU64 = AtomicU64::new(0);
/// 计数器时钟周期（飞秒）。0 = 未初始化。
static HPET_PERIOD_FS: AtomicU64 = AtomicU64::new(0);

/// 从硬件 `General Capabilities and ID Register` 读取计数器时钟周期（飞秒）。
///
/// 时钟周期存在 bit 32-63（低 4 位为有效周期，高位多为厂商信息），
/// 以飞秒为单位（14.31818MHz → 约 69_841_192）。读回 0 表示硬件未提供，
/// 由调用方回退。
fn read_period_fs(virt: u64) -> u64 {
    // SAFETY: virt 已映射到真实 HPET 寄存器区，volatile 读 64 位。
    unsafe { mmio::read_u64(virt + REG_CAP_ID) >> 32 }
}

/// 初始化 HPET：映射寄存器区并启动主计数器。
///
/// `base_phys`：ACPI HPET 表的硬件寄存器基址（如 0xFED00000）；
/// `acpi_period_fs`：ACPI 表中的计数器时钟周期（飞秒）。QEMU 的 HPET 表
/// 常为 0（不填此字段），此时从**硬件寄存器** `General Capabilities and
/// ID Register`（bit 32-63）读取；两者皆 0 则失败。
///
/// 依赖页表页分配器（`paging::init`），须在其后调用。
pub fn init(base_phys: u64, acpi_period_fs: u64) -> bool {
    if base_phys == 0 {
        klib::info!("[hpet] no HPET (base=0)");
        return false;
    }
    if base_phys & 0xFFF != 0 {
        klib::warn!("[hpet] base {:#x} not 4K aligned", base_phys);
        return false;
    }

    // 与 LAPIC 相同的模式：统一设备映射基址（mmio::DEVICE_MMIO_VIRT_BASE）。
    let virt = base_phys | mmio::DEVICE_MMIO_VIRT_BASE;
    if !mmio::map_phys_4k(base_phys, virt) {
        klib::warn!("[hpet] map {:#x} failed", base_phys);
        return false;
    }

    // 时钟周期优先取硬件寄存器（QEMU 的真实值），ACPI 值作回退。
    let mut period_fs = read_period_fs(virt);
    if period_fs == 0 {
        period_fs = acpi_period_fs;
    }
    if period_fs == 0 {
        klib::warn!(
            "[hpet] clock period unavailable (hw={} acpi={})",
            read_period_fs(virt),
            acpi_period_fs
        );
        return false;
    }

    // 使能主计数器（置 GC.ENABLE_CNF），读回确认。
    // SAFETY: virt 已映射到真实 HPET 寄存器区，且寄存器为 volatile 访问。
    unsafe {
        let gc = mmio::read_u32(virt + REG_GC);
        mmio::write_u32(virt + REG_GC, gc | GC_ENABLE_CNF);
    }
    let gc_after = unsafe { mmio::read_u32(virt + REG_GC) };
    if gc_after & GC_ENABLE_CNF == 0 {
        klib::warn!("[hpet] enable counter failed (GC={:#x})", gc_after);
        return false;
    }

    HPET_VIRT.store(virt, Ordering::Relaxed);
    HPET_PERIOD_FS.store(period_fs, Ordering::Relaxed);
    klib::info!(
        "[hpet] enabled: base={:#x} period={}fs counter={}",
        base_phys,
        period_fs,
        counter()
    );
    true
}

/// HPET 是否已初始化可用。
pub fn is_ready() -> bool {
    HPET_VIRT.load(Ordering::Relaxed) != 0
}

/// 读取主计数器当前值（64 位，单调递增）。
///
/// 未初始化时返回 0。
pub fn counter() -> u64 {
    let virt = HPET_VIRT.load(Ordering::Relaxed);
    if virt == 0 {
        return 0;
    }
    unsafe { mmio::read_u64(virt + REG_COUNTER) }
}

/// 当前高精度单调时间（纳秒，微秒级分辨率）。
///
/// 换算：纳秒 = counter × period_fs / 1_000_000（period_fs 为飞秒）。
/// 未初始化时返回 0。
pub fn now_nanos() -> u64 {
    let period = HPET_PERIOD_FS.load(Ordering::Relaxed);
    if period == 0 {
        return 0;
    }
    let c = counter();
    // u128 中间运算防溢出（counter 可能达 1e15 量级）。
    (c as u128 * period as u128 / 1_000_000) as u64
}

/// 高精度忙等睡眠 `ns` 纳秒（基于 HPET 计数器）。
///
/// HPET 未初始化时立即返回。
pub fn sleep_nanos(ns: u64) {
    if !is_ready() {
        return;
    }
    let deadline = now_nanos().saturating_add(ns);
    while now_nanos() < deadline {
        core::hint::spin_loop();
    }
}
