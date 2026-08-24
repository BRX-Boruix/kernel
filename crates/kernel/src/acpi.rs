//! ACPI 表解析接线（T6）：把 ACPI 子系统登记到设备/驱动框架 DriverHub。

use core::sync::atomic::{AtomicU8, AtomicU16, AtomicU64, Ordering};
use drv::{BusType, DeviceInfo, DeviceKind, DriverHub};
use klib::info;

/// RSDP 版本（0 = 未初始化）。
static RSDP_REVISION: AtomicU8 = AtomicU8::new(0);
/// FADT 物理地址（0 = 未找到）。
static FADT_ADDR: AtomicU64 = AtomicU64::new(0);
/// DSDT 物理地址（0 = 未找到）。
static DSDT_ADDR: AtomicU64 = AtomicU64::new(0);
/// PM1a 控制块端口。
static PM1A_CNT: AtomicU16 = AtomicU16::new(0);
/// PM1b 控制块端口。
static PM1B_CNT: AtomicU16 = AtomicU16::new(0);

/// HPET 寄存器基址（0 = 无 HPET）。
static HPET_BASE: AtomicU64 = AtomicU64::new(0);
/// HPET 计数器时钟周期（飞秒，0 = 无 HPET）。
static HPET_PERIOD_FS: AtomicU64 = AtomicU64::new(0);

/// 初始化 ACPI：解析表 + 登记设备至 DriverHub。
pub fn init() {
    match arch_x86_64::acpi::init() {
        Some(info) => {
            RSDP_REVISION.store(info.rsdp_revision, Ordering::Release);
            FADT_ADDR.store(info.fadt_addr, Ordering::Release);
            DSDT_ADDR.store(info.dsdt_addr, Ordering::Release);
            PM1A_CNT.store(info.pm1a_cnt, Ordering::Release);
            PM1B_CNT.store(info.pm1b_cnt, Ordering::Release);

            if let Err(e) = DriverHub::register_device_info(
                DeviceInfo {
                    name: "acpi-fadt",
                    kind: DeviceKind::Misc,
                    bus: BusType::Platform,
                    location: 0,
                    vendor_id: 0,
                    device_id: 0,
                    class_code: 0,
                    subclass: 0,
                    prog_if: 0,
                    // C15.1：固件表登记属控制面，不承载数据持久语义，保守披露。
                    volatile: true,
                },
                None,
                Some("acpi"),
            ) {
                klib::error!("[acpi] fadt device registration failed: {:?}", e);
            }

            info!("[acpi] initialized (rev={})", info.rsdp_revision);

            // HPET 表（可选）：保存基址/周期供 hpet 驱动使用，并登记设备。
            if let Some(h) = info.hpet {
                HPET_BASE.store(h.base_addr, Ordering::Release);
                HPET_PERIOD_FS.store(h.counter_clock_period_fs as u64, Ordering::Release);
                if let Err(e) = DriverHub::register_device_info(
                    DeviceInfo {
                        name: "hpet",
                        kind: DeviceKind::Misc,
                        bus: BusType::Platform,
                        location: 0,
                        vendor_id: 0,
                        device_id: 0,
                        class_code: 0,
                        subclass: 0,
                        prog_if: 0,
                        // C15.1：HPET 计数器重启归零，状态不持久。
                        volatile: true,
                    },
                    None,
                    Some("hpet"),
                ) {
                    klib::error!("[acpi] hpet device registration failed: {:?}", e);
                }
            } else {
                klib::info!("[acpi] no HPET table");
            }
        }
        None => {
            klib::warn!("[acpi] init failed (no RSDP/tables)");
        }
    }
}

/// 返回 HPET 物理基址与时钟周期（飞秒）；无 HPET 表时为 `None`。
///
/// KM11：原 `(0, 0)` 元组哨兵改为 `Option`——"没有"是独立于取值域的状态，
/// 用魔法零值表达会把合法基址 0（理论可映射）与缺失混为一谈。
pub fn hpet_info() -> Option<(u64, u64)> {
    let base = HPET_BASE.load(Ordering::Acquire);
    let period = HPET_PERIOD_FS.load(Ordering::Acquire);
    if base == 0 || period == 0 {
        None
    } else {
        Some((base, period))
    }
}

/// FADT 解析产物观测出口（审计 B25：短表分级解析此前零测试佐证）。
/// 返回 `(fadt_phys, dsdt_phys, pm1a_port)`；未初始化/解析失败时为全 0。
///
/// 仅 `kernel-tests` 构建存在：唯一调用方是 tests::test_acpi_parse_tables
/// （QEMU 裸机自检，经 kmain feature 门进入）。非测试构建中该出口无生产
/// 读者，不设门即报死码——按零死代码纪律随调用方同门，而非压制警告。
#[cfg(feature = "kernel-tests")]
pub fn fadt_summary() -> (u64, u64, u16) {
    (
        FADT_ADDR.load(Ordering::Acquire),
        DSDT_ADDR.load(Ordering::Acquire),
        PM1A_CNT.load(Ordering::Acquire),
    )
}
