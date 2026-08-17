//! ACPI 表解析接线（T6）：把 ACPI 子系统登记到设备/驱动框架。
//!
//! - 启动早期调用 `acpi::init()`：经 `arch_x86_64::acpi::init()` 解析
//!   RSDP → RSDT/XSDT → FADT；
//! - 把 ACPI 设备（FADT）登记到 drv 注册表（`DeviceId::acpi(*b"FACP")`），
//!   供未来的电源管理驱动（shutdown/reboot）匹配；
//! - 解析出的关键信息（DSDT、PM1 控制块、reset 寄存器）暴露为只读接口，
//!   供电源管理实现使用。

use core::sync::atomic::{AtomicU64, AtomicU16, Ordering};

use drv::{Device, DeviceId};
use klib::info;

/// ACPI 设备（FADT 表）。
struct AcpiDevice;
impl Device for AcpiDevice {
    fn name(&self) -> &'static str {
        "acpi-fadt"
    }
    fn id(&self) -> DeviceId {
        DeviceId::acpi(*b"FACP")
    }
}
static ACPI_DEVICE: AcpiDevice = AcpiDevice;

/// HPET 设备（高精度事件定时器表）。
struct HpetDevice;
impl Device for HpetDevice {
    fn name(&self) -> &'static str {
        "hpet"
    }
    fn id(&self) -> DeviceId {
        DeviceId::acpi(*b"HPET")
    }
}
static HPET_DEVICE: HpetDevice = HpetDevice;

/// 是否已成功初始化。
static INITIALIZED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// RSDP 版本（0 = 未初始化）。
static RSDP_REVISION: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
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

/// 初始化 ACPI：解析表 + 登记设备。
pub fn init() {
    match arch_x86_64::acpi::init() {
        Some(info) => {
            RSDP_REVISION.store(info.rsdp_revision, Ordering::Release);
            FADT_ADDR.store(info.fadt_addr, Ordering::Release);
            DSDT_ADDR.store(info.dsdt_addr, Ordering::Release);
            PM1A_CNT.store(info.pm1a_cnt, Ordering::Release);
            PM1B_CNT.store(info.pm1b_cnt, Ordering::Release);
            INITIALIZED.store(true, Ordering::Release);

            drv::register_device(&ACPI_DEVICE);
            drv::probe_all();

            info!("[acpi] initialized (rev={})", info.rsdp_revision);

            // HPET 表（可选）：保存基址/周期供 hpet 驱动使用，并登记设备。
            if let Some(h) = info.hpet {
                HPET_BASE.store(h.base_addr, Ordering::Release);
                HPET_PERIOD_FS.store(h.counter_clock_period_fs as u64, Ordering::Release);
                drv::register_device(&HPET_DEVICE);
                drv::probe_all();
            } else {
                klib::info!("[acpi] no HPET table");
            }
        }
        None => {
            klib::warn!("[acpi] init failed (no RSDP/tables)");
        }
    }
}

/// HPET 探测结果：(寄存器基址, 计数器时钟周期飞秒)，无 HPET 为 `(0, 0)`。
pub fn hpet_info() -> (u64, u64) {
    (
        HPET_BASE.load(Ordering::Acquire),
        HPET_PERIOD_FS.load(Ordering::Acquire),
    )
}

/// 是否已成功解析 ACPI 表。
#[allow(dead_code)] // 供未来电源管理（shutdown/reboot）使用。
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

/// FADT 物理地址（0 = 不可用）。
#[allow(dead_code)] // 供未来电源管理（shutdown/reboot）使用。
pub fn fadt_addr() -> u64 {
    FADT_ADDR.load(Ordering::Acquire)
}

/// DSDT 物理地址（0 = 不可用）。
#[allow(dead_code)] // 供未来电源管理（shutdown/reboot）使用。
pub fn dsdt_addr() -> u64 {
    DSDT_ADDR.load(Ordering::Acquire)
}

/// PM1a 控制块端口（0 = 不可用）。
#[allow(dead_code)] // 供未来电源管理（shutdown/reboot）使用。
pub fn pm1a_cnt() -> u16 {
    PM1A_CNT.load(Ordering::Acquire)
}

/// PM1b 控制块端口（0 = 不可用）。
#[allow(dead_code)] // 供未来电源管理（shutdown/reboot）使用。
pub fn pm1b_cnt() -> u16 {
    PM1B_CNT.load(Ordering::Acquire)
}
