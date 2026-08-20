//! PCI 硬件驱动匹配与自动 Attach（PciDriver / Probe / Generic Bindings）。

use crate::device::{BusType, DeviceInfo, DeviceKind};
use crate::driver::DriverStage;
use crate::hub::DriverHub;
use klib::info;

/// 探测 PCI 块存储设备（IDE / SATA / NVMe，Class 0x01）。
pub fn probe_pci_block(_hub: &DriverHub, dev: &DeviceInfo) -> bool {
    dev.bus == BusType::Pci && dev.class_code == 0x01
}

/// 绑定 PCI 块存储设备。
pub fn attach_pci_block(_hub: &DriverHub, dev: &DeviceInfo) {
    info!(
        "[pci_driver] attached block driver to {:04x}:{:04x} location={:#x}",
        dev.vendor_id, dev.device_id, dev.location
    );
}

/// 探测 PCI 网络设备（以太网控制器，Class 0x02）。
pub fn probe_pci_net(_hub: &DriverHub, dev: &DeviceInfo) -> bool {
    dev.bus == BusType::Pci && dev.class_code == 0x02
}

/// 绑定 PCI 网络设备。
pub fn attach_pci_net(_hub: &DriverHub, dev: &DeviceInfo) {
    info!(
        "[pci_driver] attached net driver to {:04x}:{:04x} location={:#x}",
        dev.vendor_id, dev.device_id, dev.location
    );
}

/// 探测 PCI 显示控制器（VGA / GPU，Class 0x03）。
pub fn probe_pci_display(_hub: &DriverHub, dev: &DeviceInfo) -> bool {
    dev.bus == BusType::Pci && dev.class_code == 0x03
}

/// 绑定 PCI 显示控制器。
pub fn attach_pci_display(_hub: &DriverHub, dev: &DeviceInfo) {
    info!(
        "[pci_driver] attached display driver to {:04x}:{:04x} location={:#x}",
        dev.vendor_id, dev.device_id, dev.location
    );
}

/// 注册所有标准 PCI Class 驱动。
pub fn register_pci_class_drivers() {
    DriverHub::register_driver_ops(
        "pci-block",
        DriverStage::Devices,
        |_| {},
        Some(probe_pci_block),
        Some(attach_pci_block),
    );

    DriverHub::register_driver_ops(
        "pci-net",
        DriverStage::Devices,
        |_| {},
        Some(probe_pci_net),
        Some(attach_pci_net),
    );

    DriverHub::register_driver_ops(
        "pci-display",
        DriverStage::Devices,
        |_| {},
        Some(probe_pci_display),
        Some(attach_pci_display),
    );
}
