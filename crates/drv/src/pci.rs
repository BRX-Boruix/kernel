//! PCI 总线枚举与设备控制模块（BusType::Pci）。
//!
//! 支持通过 I/O 端口 0xCF8 / 0xCFC 进行 Legacy PCI 配置空间扫描与读写。

use crate::device::{BusType, DeviceInfo, DeviceKind};
use crate::driver::DriverStage;
use crate::hub::DriverHub;
use arch_x86_64::port::{inl, outl};
use klib::info;

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;
const ENABLE_BIT: u32 = 0x8000_0000;

pub fn read_config_u32(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let address = ENABLE_BIT
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset as u32) & 0xFC);
    outl(CONFIG_ADDRESS, address);
    inl(CONFIG_DATA)
}

pub fn read_config_u16(bus: u8, device: u8, function: u8, offset: u8) -> u16 {
    let value = read_config_u32(bus, device, function, offset);
    let shift = (offset & 0x3) * 8;
    ((value >> shift) & 0xFFFF) as u16
}

pub fn read_config_u8(bus: u8, device: u8, function: u8, offset: u8) -> u8 {
    let value = read_config_u32(bus, device, function, offset);
    let shift = (offset & 0x3) * 8;
    ((value >> shift) & 0xFF) as u8
}

pub fn write_config_u32(bus: u8, device: u8, function: u8, offset: u8, value: u32) {
    let address = ENABLE_BIT
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset as u32) & 0xFC);
    outl(CONFIG_ADDRESS, address);
    outl(CONFIG_DATA, value);
}

pub fn write_config_u16(bus: u8, device: u8, function: u8, offset: u8, value: u16) {
    let mut reg = read_config_u32(bus, device, function, offset);
    let shift = (offset & 0x3) * 8;
    reg &= !(0xFFFFu32 << shift);
    reg |= (value as u32) << shift;
    write_config_u32(bus, device, function, offset, reg);
}

pub fn enable_bus_master(bus: u8, device: u8, function: u8) {
    let cmd = read_config_u16(bus, device, function, 0x04);
    let new_cmd = cmd | (1 << 2) | (1 << 1); // Bus Master + Memory Space
    if new_cmd != cmd {
        write_config_u16(bus, device, function, 0x04, new_cmd);
    }
}

fn kind_for_class(class_code: u8) -> DeviceKind {
    match class_code {
        0x01 => DeviceKind::Block,
        0x02 => DeviceKind::Net,
        0x03 => DeviceKind::Display,
        0x07 => DeviceKind::Char,
        _ => DeviceKind::Misc,
    }
}

pub fn name_for_device(class_code: u8, subclass: u8) -> &'static str {
    match (class_code, subclass) {
        (0x01, 0x01) => "pci-ide-storage",
        (0x01, 0x06) => "pci-sata-ahci",
        (0x01, _) => "pci-mass-storage",
        (0x02, 0x00) => "pci-ethernet",
        (0x02, _) => "pci-network",
        (0x03, 0x00) => "pci-vga-display",
        (0x03, _) => "pci-display",
        (0x06, 0x00) => "pci-host-bridge",
        (0x06, 0x01) => "pci-isa-bridge",
        (0x06, _) => "pci-bridge",
        _ => "pci-device",
    }
}

/// 扫描 PCI 总线并注册到 DriverHub
pub fn scan_pci_bus() -> usize {
    let mut count = 0;
    for bus in 0..=8 {
        for device in 0..32 {
            let vendor = read_config_u16(bus, device, 0, 0x00);
            if vendor == 0xFFFF {
                continue;
            }
            let header_type = read_config_u8(bus, device, 0, 0x0E);
            let functions = if header_type & 0x80 != 0 { 8 } else { 1 };
            for function in 0..functions {
                let vendor_id = read_config_u16(bus, device, function, 0x00);
                if vendor_id == 0xFFFF {
                    continue;
                }
                let device_id = read_config_u16(bus, device, function, 0x02);
                let prog_if = read_config_u8(bus, device, function, 0x09);
                let subclass = read_config_u8(bus, device, function, 0x0A);
                let class_code = read_config_u8(bus, device, function, 0x0B);

                let location = ((bus as u32) << 16) | ((device as u32) << 8) | (function as u32);
                let kind = kind_for_class(class_code);
                let name = name_for_device(class_code, subclass);

                DriverHub::register_device_info(
                    DeviceInfo {
                        name,
                        kind,
                        bus: BusType::Pci,
                        location,
                        vendor_id,
                        device_id,
                        class_code,
                        subclass,
                        prog_if,
                    },
                    None,
                    None,
                );

                info!(
                    "[pci] {:02x}:{:02x}.{} vendor={:04x} device={:04x} class={:02x}:{:02x} ({})",
                    bus, device, function, vendor_id, device_id, class_code, subclass, name
                );
                count += 1;
            }
        }
    }
    info!("[pci] scan complete: found and registered {} devices", count);
    count
}

pub fn init_pci_bus(_hub: &DriverHub) {
    scan_pci_bus();
}

pub fn register_pci_bus_driver() {
    DriverHub::register_driver("pci-bus", DriverStage::Devices, init_pci_bus);
}
