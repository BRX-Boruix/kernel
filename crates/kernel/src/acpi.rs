//! ACPI 表解析接线（T6）：把 ACPI 子系统登记到设备/驱动框架 DriverHub。

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU64, Ordering};
use drv::{BusType, DeviceInfo, DeviceKind, DriverHub};
use klib::info;

/// 是否已成功初始化。
static INITIALIZED: AtomicBool = AtomicBool::new(false);

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
            INITIALIZED.store(true, Ordering::Release);

            DriverHub::register_device_info(
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
                },
                None,
                Some("acpi"),
            );

            info!("[acpi] initialized (rev={})", info.rsdp_revision);

            // HPET 表（可选）：保存基址/周期供 hpet 驱动使用，并登记设备。
            if let Some(h) = info.hpet {
                HPET_BASE.store(h.base_addr, Ordering::Release);
                HPET_PERIOD_FS.store(h.counter_clock_period_fs as u64, Ordering::Release);
                DriverHub::register_device_info(
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
                    },
                    None,
                    Some("hpet"),
                );
            } else {
                klib::info!("[acpi] no HPET table");
            }
        }
        None => {
            klib::warn!("[acpi] init failed (no RSDP/tables)");
        }
    }
}

/// 返回 HPET 物理基址与时钟周期（飞秒）。
pub fn hpet_info() -> (u64, u64) {
    (
        HPET_BASE.load(Ordering::Acquire),
        HPET_PERIOD_FS.load(Ordering::Acquire),
    )
}
