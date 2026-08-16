//! PCI 总线枚举 + 设备登记（T6.1）。
//!
//! 启动早期枚举 PCI 总线（bus 0），把发现的每个设备登记到设备/驱动框架
//! （`drv` 注册表），供后续 PCI 驱动（网卡/磁盘/键盘控制器等）匹配绑定。
//!
//! 实现要点：
//! - 枚举逻辑走 `arch::pci::enumerate_bus`（ADR-007 抽象，x86 用 0xCF8/0xCFC）；
//! - PCI 设备是**运行时发现**的，不能像静态设备那样用 `static` 常量：
//!   用定长槽位池（`PciDevice` 数组）存储，枚举后把槽位引用以 `'static`
//!   身份注册进 drv 注册表（槽位池生命周期与内核相同，安全）。

use core::sync::atomic::{AtomicUsize, Ordering};

use drv::{Device, DeviceId};
use klib::info;

use arch::pci::PciDeviceInfo;

/// PCI 设备槽位池容量（QEMU/常见 PC 几十个设备足够；未来可扩容）。
pub const MAX_PCI_DEVICES: usize = 64;

/// 可注册的 PCI 设备（实现 `drv::Device`，id 用 vendor/device/class 约定）。
struct PciDevice {
    info: PciDeviceInfo,
}

impl Device for PciDevice {
    fn name(&self) -> &'static str {
        "pci-device"
    }
    fn id(&self) -> DeviceId {
        DeviceId::pci(self.info.vendor_id, self.info.device_id, self.info.class_code())
    }
}

impl PciDevice {
    /// 空槽位（常量构造，仅供槽位池初始化）。
    const fn empty() -> Self {
        Self {
            info: PciDeviceInfo {
                bus: 0,
                device: 0,
                function: 0,
                vendor_id: 0,
                device_id: 0,
                class: 0,
                subclass: 0,
                prog_if: 0,
                header_type: 0,
            },
        }
    }
}

/// 设备槽位池：枚举后填入，此后只读（`'static` 借用合法）。
static mut PCI_DEVICES: [PciDevice; MAX_PCI_DEVICES] = [const { PciDevice::empty() }; MAX_PCI_DEVICES];

/// 已填写的槽位数。
static PCI_COUNT: AtomicUsize = AtomicUsize::new(0);

/// 枚举 PCI 总线（bus 0）并把发现的设备注册进 drv 注册表。
///
/// 返回注册成功的设备数。可在启动早期（drv 框架就绪后）调用一次。
pub fn enumerate() -> usize {
    let mut registered = 0;
    arch::pci::enumerate_bus::<arch_x86_64::pci::X8664Pci>(0, |info| {
        // 打印设备信息（厂商/设备号 + class）。
        info!(
            "[pci] {:02x}:{:02x}.{} vendor={:04x} device={:04x} class={:06x}",
            info.bus,
            info.device,
            info.function,
            info.vendor_id,
            info.device_id,
            info.class_code()
        );

        let idx = PCI_COUNT.fetch_add(1, Ordering::SeqCst);
        if idx >= MAX_PCI_DEVICES {
            klib::warn!("[pci] device slot pool exhausted, dropping device");
            return;
        }
        // SAFETY: 槽位 `idx` 只被本函数写一次（计数保证），且 `'static` 有效。
        unsafe {
            PCI_DEVICES[idx].info = info;
        }
        // 注册进 drv 注册表。
        // SAFETY: 槽位池与内核同生命周期，且填入后不再变动。
        let dev: &'static PciDevice = unsafe { &*core::ptr::addr_of!(PCI_DEVICES[idx]) };
        if drv::register_device(dev) {
            registered += 1;
        }
    });
    info!(
        "[pci] enumerated {} devices, {} registered",
        PCI_COUNT.load(Ordering::SeqCst),
        registered
    );
    registered
}
