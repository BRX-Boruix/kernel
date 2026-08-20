//! PCI 总线枚举 + 设备登记（T6.1）。
//!
//! 启动早期枚举 PCI 总线（bus 0），把发现的每个设备登记到 DriverHub 驱动中枢。

use core::sync::atomic::{AtomicUsize, Ordering};
use drv::{BusType, DeviceInfo, DeviceKind, DriverHub};
use klib::info;

/// PCI 设备槽位池容量。
pub const MAX_PCI_DEVICES: usize = 64;

/// 已填写的槽位数。
static PCI_COUNT: AtomicUsize = AtomicUsize::new(0);

/// 枚举 PCI 总线（bus 0）并把发现的设备注册进 DriverHub。
pub fn enumerate() -> usize {
    let mut registered = 0;
    arch::pci::enumerate_bus::<arch_x86_64::pci::X8664Pci>(0, |info| {
        info!(
            "[pci] {:02x}:{:02x}.{} vendor={:04x} device={:04x} class={:06x}",
            info.bus,
            info.device,
            info.function,
            info.vendor_id,
            info.device_id,
            info.class_code()
        );

        let loc = ((info.bus as u32) << 16) | ((info.device as u32) << 8) | (info.function as u32);
        let kind = match info.class {
            0x01 => DeviceKind::Block,
            0x02 => DeviceKind::Net,
            0x03 => DeviceKind::Display,
            0x07 => DeviceKind::Char,
            _ => DeviceKind::Misc,
        };

        DriverHub::register_device_info(
            DeviceInfo {
                name: "pci-device",
                kind,
                bus: BusType::Pci,
                location: loc,
                vendor_id: info.vendor_id,
                device_id: info.device_id,
                class_code: info.class,
                subclass: info.subclass,
                prog_if: info.prog_if,
            },
            None,
            None,
        );
        PCI_COUNT.fetch_add(1, Ordering::SeqCst);
        registered += 1;
    });
    info!(
        "[pci] enumerated {} devices, {} registered to DriverHub",
        PCI_COUNT.load(Ordering::SeqCst),
        registered
    );
    registered
}
