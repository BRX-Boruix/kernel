//! PCI 总线枚举与设备控制模块（BusType::Pci，BAR 自省与遥测支持，M10.1）。
//!
//! 支持通过 I/O 端口 0xCF8 / 0xCFC 进行 Legacy PCI 配置空间扫描、BARs 解析与读写。

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

/// PCI Base Address Register (BAR) 深度自省模型（M10.1）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PciBar {
    IoPort {
        port: u16,
        size: u32,
    },
    Mmio32 {
        addr: u32,
        size: u32,
        prefetchable: bool,
    },
    Mmio64 {
        addr: u64,
        size: u64,
        prefetchable: bool,
    },
    None,
}

/// 解析指定 PCI 设备的 6 个 BAR 配置空间。
pub fn inspect_pci_bars(bus: u8, device: u8, function: u8) -> [PciBar; 6] {
    let mut bars = [PciBar::None; 6];
    let mut i = 0;

    while i < 6 {
        let offset = 0x10 + (i as u8) * 4;
        let orig_val = read_config_u32(bus, device, function, offset);

        if orig_val == 0 || orig_val == 0xFFFF_FFFF {
            bars[i] = PciBar::None;
            i += 1;
            continue;
        }

        // 写入全 1 获取 BAR 请求大小
        write_config_u32(bus, device, function, offset, 0xFFFF_FFFF);
        let size_mask = read_config_u32(bus, device, function, offset);
        // 恢复原始配置
        write_config_u32(bus, device, function, offset, orig_val);

        if orig_val & 1 == 1 {
            // I/O Port BAR
            let port = (orig_val & 0xFFFC) as u16;
            let size = !(size_mask & 0xFFFC) + 1;
            bars[i] = PciBar::IoPort { port, size };
            i += 1;
        } else {
            // MMIO BAR
            let bar_type = (orig_val >> 1) & 0x03;
            let prefetchable = (orig_val & (1 << 3)) != 0;

            if bar_type == 2 && i + 1 < 6 {
                // 64-bit MMIO
                let next_offset = 0x10 + ((i + 1) as u8) * 4;
                let orig_high = read_config_u32(bus, device, function, next_offset);
                write_config_u32(bus, device, function, next_offset, 0xFFFF_FFFF);
                let high_mask = read_config_u32(bus, device, function, next_offset);
                write_config_u32(bus, device, function, next_offset, orig_high);

                let full_addr = ((orig_high as u64) << 32) | ((orig_val & 0xFFFF_FFF0) as u64);
                let full_mask = ((high_mask as u64) << 32) | ((size_mask & 0xFFFF_FFF0) as u64);
                let size = !full_mask + 1;

                bars[i] = PciBar::Mmio64 {
                    addr: full_addr,
                    size,
                    prefetchable,
                };
                bars[i + 1] = PciBar::None;
                i += 2;
            } else {
                // 32-bit MMIO
                let addr = orig_val & 0xFFFF_FFF0;
                let size = !(size_mask & 0xFFFF_FFF0) + 1;
                bars[i] = PciBar::Mmio32 {
                    addr,
                    size,
                    prefetchable,
                };
                i += 1;
            }
        }
    }

    bars
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
                // C15.1：只有海量存储类（PCI class 0x01）硬件背后存在可持久化
                // 介质；其余类别的设备一律保守披露为易失，禁止伪装持久存储。
                let is_mass_storage = class_code == 0x01;

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
                        volatile: !is_mass_storage,
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
    info!(
        "[pci] scan complete: found and registered {} devices",
        count
    );
    count
}

pub fn init_pci_bus(_hub: &DriverHub) {
    scan_pci_bus();
}

pub fn register_pci_bus_driver() {
    DriverHub::register_driver("pci-bus", DriverStage::Devices, init_pci_bus);
}
