//! PCI 类匹配候选驱动（candidate-only，ADR-022 §1 / drv1 DR1）。
//!
//! **如实定位**：本文件三个驱动是"类匹配候选登记器"，不是已实现的硬件
//! 驱动——它们按 PCI 类代码/厂商 ID 给设备打分参与仲裁，胜出后在注册表
//! 留名记分，但 **attach 不触碰任何硬件、不创建任何设备状态、不映射任何
//! BAR**。DevFS 对其绑定呈现 `candidate:{name}(unimplemented)`。
//!
//! e1000 最小收包路径（vendor 0x8086 device 0x100E 的真驱动）属新功能
//! 立项（中断/DMA/MMIO 接线均不存在，ADR-022 §11 欠账登记），在落地前
//! 本模块保持候选语义，绝不以日志伪装"已挂接"。

use crate::device::{BusType, DeviceInfo};
use crate::driver::DriverStage;
use crate::hub::DriverHub;
use klib::error::Error;
use klib::info;

// ===== S13：竞标优先级分数与 PCI 标识常量的单一来源 =====
//
// 竞标分是候选驱动对同总线设备的**相对优先级**（分数高者胜出，ADR-022
// §2 仲裁）。这里把散落的字面量收拢为带语义注释的命名常量，避免三处
// 同类分数漂移/笔误。默认分基准见 hub 的 `EXPLICIT_BIND_SCORE`。
//
// 分数语义（越高越优先）：
// - 特定厂商+型号的真候选（虽未实现硬件控制，仍是"精确命中"）优先级最高；
// - 通用类候选（类代码命中但无精确厂商匹配）居中；
// - 通用显示候选兜底最低（VGA 设备多，避免抢占更精确匹配）。
mod score {
    /// Intel PIIX4 IDE（vendor 0x8086, device 0x7010）精确命中。
    pub const PIIX4_IDE: u8 = 90;
    /// 通用 PCI 块存储候选（Class 0x01）。
    pub const GENERIC_BLOCK: u8 = 60;
    /// Intel 82540EM e1000（vendor 0x8086, device 0x100E）精确命中。
    pub const E1000: u8 = 95;
    /// 通用以太网候选（Class 0x02）。
    pub const GENERIC_NET: u8 = 65;
    /// QEMU Standard VGA（vendor 0x1234, device 0x1111）精确命中。
    pub const QEMU_VGA: u8 = 85;
    /// 通用 VESA/VGA 显示候选（Class 0x03）兜底。
    pub const GENERIC_DISPLAY: u8 = 50;
}

mod ids {
    pub const INTEL_VENDOR: u16 = 0x8086;
    pub const PIIX4_IDE_DEVICE: u16 = 0x7010;
    pub const E1000_DEVICE: u16 = 0x100E;
    pub const QEMU_VGA_VENDOR: u16 = 0x1234;
    pub const QEMU_VGA_DEVICE: u16 = 0x1111;
    pub const CLASS_BLOCK: u8 = 0x01;
    pub const CLASS_NET: u8 = 0x02;
    pub const CLASS_DISPLAY: u8 = 0x03;
}

// 1. PCI 块存储候选（IDE / SATA / NVMe，Class 0x01）
pub fn score_pci_block(_hub: &DriverHub, dev: &DeviceInfo) -> u8 {
    if dev.bus == BusType::Pci && dev.class_code == ids::CLASS_BLOCK {
        if dev.vendor_id == ids::INTEL_VENDOR && dev.device_id == ids::PIIX4_IDE_DEVICE {
            // Intel PIIX4 IDE 候选优先级（精确命中）
            score::PIIX4_IDE
        } else {
            // 通用 PCI 块设备候选优先级
            score::GENERIC_BLOCK
        }
    } else {
        0
    }
}

pub fn attach_pci_block(_hub: &DriverHub, dev: &DeviceInfo) -> Result<(), ()> {
    info!(
        "[pci-candidate] candidacy recorded for block class on {:04x}:{:04x} location={:#x} (no hardware control implemented)",
        dev.vendor_id, dev.device_id, dev.location
    );
    Ok(())
}

pub fn detach_pci_block(_hub: &DriverHub, dev: &DeviceInfo) -> Result<(), ()> {
    info!(
        "[pci-candidate] candidacy released for block class on {:04x}:{:04x} location={:#x}",
        dev.vendor_id, dev.device_id, dev.location
    );
    Ok(())
}

// 2. PCI 网络候选（以太网控制器，Class 0x02）
pub fn score_pci_net(_hub: &DriverHub, dev: &DeviceInfo) -> u8 {
    if dev.bus == BusType::Pci && dev.class_code == ids::CLASS_NET {
        if dev.vendor_id == ids::INTEL_VENDOR && dev.device_id == ids::E1000_DEVICE {
            // Intel 82540EM (e1000) 候选优先级——注意：这只是候选优先级，
            // e1000 真驱动尚未立项落地，不存在任何专用数据路径。
            score::E1000
        } else {
            // 通用以太网候选优先级
            score::GENERIC_NET
        }
    } else {
        0
    }
}

pub fn attach_pci_net(_hub: &DriverHub, dev: &DeviceInfo) -> Result<(), ()> {
    info!(
        "[pci-candidate] candidacy recorded for net class on {:04x}:{:04x} location={:#x} (no hardware control implemented)",
        dev.vendor_id, dev.device_id, dev.location
    );
    Ok(())
}

pub fn detach_pci_net(_hub: &DriverHub, dev: &DeviceInfo) -> Result<(), ()> {
    info!(
        "[pci-candidate] candidacy released for net class on {:04x}:{:04x} location={:#x}",
        dev.vendor_id, dev.device_id, dev.location
    );
    Ok(())
}

// 3. PCI 显示控制器候选（VGA / GPU，Class 0x03）
pub fn score_pci_display(_hub: &DriverHub, dev: &DeviceInfo) -> u8 {
    if dev.bus == BusType::Pci && dev.class_code == ids::CLASS_DISPLAY {
        if dev.vendor_id == ids::QEMU_VGA_VENDOR && dev.device_id == ids::QEMU_VGA_DEVICE {
            // QEMU Standard VGA 候选优先级（精确命中）
            score::QEMU_VGA
        } else {
            // 通用 VESA/VGA 显示候选优先级（兜底）
            score::GENERIC_DISPLAY
        }
    } else {
        0
    }
}

pub fn attach_pci_display(_hub: &DriverHub, dev: &DeviceInfo) -> Result<(), ()> {
    info!(
        "[pci-candidate] candidacy recorded for display class on {:04x}:{:04x} location={:#x} (no hardware control implemented)",
        dev.vendor_id, dev.device_id, dev.location
    );
    Ok(())
}

pub fn detach_pci_display(_hub: &DriverHub, dev: &DeviceInfo) -> Result<(), ()> {
    info!(
        "[pci-candidate] candidacy released for display class on {:04x}:{:04x} location={:#x}",
        dev.vendor_id, dev.device_id, dev.location
    );
    Ok(())
}

/// 注册全部标准 PCI 类匹配候选驱动（controls_hardware=false，M9.2 解绑支持）。
///
/// DM1：注册结果上抛给 ensure_registered 统一留痕，表满不静默丢弃。
pub fn register_pci_class_drivers() -> Result<(), Error> {
    DriverHub::register_driver_full(
        "pci-block",
        DriverStage::Devices,
        |_| {},
        Some(score_pci_block),
        None,
        Some(attach_pci_block),
        Some(detach_pci_block),
        false,
    )?;

    DriverHub::register_driver_full(
        "pci-net",
        DriverStage::Devices,
        |_| {},
        Some(score_pci_net),
        None,
        Some(attach_pci_net),
        Some(detach_pci_net),
        false,
    )?;

    DriverHub::register_driver_full(
        "pci-display",
        DriverStage::Devices,
        |_| {},
        Some(score_pci_display),
        None,
        Some(attach_pci_display),
        Some(detach_pci_display),
        false,
    )
}
