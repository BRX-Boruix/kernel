//! PCI 硬件驱动匹配与智能竞标绑定（PciDriver / Bidding / Fallback）。

use crate::device::{BusType, DeviceInfo};
use crate::driver::DriverStage;
use crate::hub::DriverHub;
use klib::info;

// 1. PCI 块存储设备（IDE / SATA / NVMe，Class 0x01）
pub fn score_pci_block(_hub: &DriverHub, dev: &DeviceInfo) -> u8 {
    if dev.bus == BusType::Pci && dev.class_code == 0x01 {
        if dev.vendor_id == 0x8086 && dev.device_id == 0x7010 {
            // Intel PIIX4 IDE 优化专用驱动打分 90
            90
        } else {
            // 通用 PCI 块设备标准驱动打分 60
            60
        }
    } else {
        0
    }
}

pub fn attach_pci_block(_hub: &DriverHub, dev: &DeviceInfo) -> Result<(), ()> {
    info!(
        "[pci_driver] attached block driver to {:04x}:{:04x} location={:#x}",
        dev.vendor_id, dev.device_id, dev.location
    );
    Ok(())
}

// 2. PCI 网络设备（以太网控制器，Class 0x02）
pub fn score_pci_net(_hub: &DriverHub, dev: &DeviceInfo) -> u8 {
    if dev.bus == BusType::Pci && dev.class_code == 0x02 {
        if dev.vendor_id == 0x8086 && dev.device_id == 0x100E {
            // Intel 82540EM (e1000) 专用网卡优化驱动打分 95
            95
        } else {
            // 通用以太网标准驱动打分 65
            65
        }
    } else {
        0
    }
}

pub fn attach_pci_net(_hub: &DriverHub, dev: &DeviceInfo) -> Result<(), ()> {
    info!(
        "[pci_driver] attached net driver to {:04x}:{:04x} location={:#x}",
        dev.vendor_id, dev.device_id, dev.location
    );
    Ok(())
}

// 3. PCI 显示控制器（VGA / GPU，Class 0x03）
pub fn score_pci_display(_hub: &DriverHub, dev: &DeviceInfo) -> u8 {
    if dev.bus == BusType::Pci && dev.class_code == 0x03 {
        if dev.vendor_id == 0x1234 && dev.device_id == 0x1111 {
            // QEMU Standard VGA 专用驱动打分 85
            85
        } else {
            // 通用 VESA/VGA 显示驱动打分 50
            50
        }
    } else {
        0
    }
}

pub fn attach_pci_display(_hub: &DriverHub, dev: &DeviceInfo) -> Result<(), ()> {
    info!(
        "[pci_driver] attached display driver to {:04x}:{:04x} location={:#x}",
        dev.vendor_id, dev.device_id, dev.location
    );
    Ok(())
}

/// 注册所有标准 PCI 智能竞标驱动。
pub fn register_pci_class_drivers() {
    DriverHub::register_driver_bidding(
        "pci-block",
        DriverStage::Devices,
        |_| {},
        Some(score_pci_block),
        Some(attach_pci_block),
    );

    DriverHub::register_driver_bidding(
        "pci-net",
        DriverStage::Devices,
        |_| {},
        Some(score_pci_net),
        Some(attach_pci_net),
    );

    DriverHub::register_driver_bidding(
        "pci-display",
        DriverStage::Devices,
        |_| {},
        Some(score_pci_display),
        Some(attach_pci_display),
    );
}
