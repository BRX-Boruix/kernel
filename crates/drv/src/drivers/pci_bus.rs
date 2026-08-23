//! PCI 总线枚举与设备控制模块（BusType::Pci，BAR 自省与遥测支持，M10.1）。
//!
//! 支持通过 I/O 端口 0xCF8 / 0xCFC 进行 Legacy PCI 配置空间扫描、BARs 解析与读写。
//!
//! KM6：设备注册名唯一化——旧实现按类别命名（两台同类别设备重名），而
//! DriverHub 的 name-based 查找（`pci_location_of`、UIO claim、DevFS 投影）
//! 以名字区分设备，重名使查找永远命中第一台。现注册名为
//! `<类别描述>-<bus>-<device>-<function>`（经 `Box::leak` 常驻；注册表条目
//! 本就终生存在，数量受扫描空间上界约束）。

use crate::device::{BusType, DeviceInfo, DeviceKind};
use crate::driver::DriverStage;
use crate::hub::DriverHub;
use arch_x86_64::port::{inl, outl};
use klib::info;

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;
const ENABLE_BIT: u32 = 0x8000_0000;

/// PCI 配置空间类代码（offset 0x0B）：海量存储（IDE/AHCI/NVMe 等）。
const PCI_CLASS_MASS_STORAGE: u8 = 0x01;
/// PCI 配置空间类代码：网络控制器。
const PCI_CLASS_NETWORK: u8 = 0x02;
/// PCI 配置空间类代码：显示控制器。
const PCI_CLASS_DISPLAY: u8 = 0x03;
/// PCI 配置空间类代码：桥接设备（host/ISA/PCI-to-PCI 桥）。
const PCI_CLASS_BRIDGE: u8 = 0x06;
/// PCI 配置空间类代码：简单通信控制器（串口等）。
const PCI_CLASS_SIMPLE_COMM: u8 = 0x07;

/// 海量存储子类（offset 0x0A）：IDE 控制器。
const PCI_SUBCLASS_IDE: u8 = 0x01;
/// 海量存储子类：SATA（AHCI 模式）。
const PCI_SUBCLASS_SATA: u8 = 0x06;
/// 网络子类：以太网控制器。
const PCI_SUBCLASS_ETHERNET: u8 = 0x00;
/// 显示子类：VGA 兼容控制器。
const PCI_SUBCLASS_VGA: u8 = 0x00;
/// 桥接子类：Host bridge。
const PCI_SUBCLASS_HOST_BRIDGE: u8 = 0x00;
/// 桥接子类：ISA bridge。
const PCI_SUBCLASS_ISA_BRIDGE: u8 = 0x01;

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
        PCI_CLASS_MASS_STORAGE => DeviceKind::Block,
        PCI_CLASS_NETWORK => DeviceKind::Net,
        PCI_CLASS_DISPLAY => DeviceKind::Display,
        PCI_CLASS_SIMPLE_COMM => DeviceKind::Char,
        _ => DeviceKind::Misc,
    }
}

/// 按类别给出设备描述性基础名（KM6：仅作唯一注册名的前缀，不再单独充当
/// 注册名——同类别多设备重名会破坏 name-based 查找）。
pub fn name_for_device(class_code: u8, subclass: u8) -> &'static str {
    match (class_code, subclass) {
        (PCI_CLASS_MASS_STORAGE, PCI_SUBCLASS_IDE) => "pci-ide-storage",
        (PCI_CLASS_MASS_STORAGE, PCI_SUBCLASS_SATA) => "pci-sata-ahci",
        (PCI_CLASS_MASS_STORAGE, _) => "pci-mass-storage",
        (PCI_CLASS_NETWORK, PCI_SUBCLASS_ETHERNET) => "pci-ethernet",
        (PCI_CLASS_NETWORK, _) => "pci-network",
        (PCI_CLASS_DISPLAY, PCI_SUBCLASS_VGA) => "pci-vga-display",
        (PCI_CLASS_DISPLAY, _) => "pci-display",
        (PCI_CLASS_BRIDGE, PCI_SUBCLASS_HOST_BRIDGE) => "pci-host-bridge",
        (PCI_CLASS_BRIDGE, PCI_SUBCLASS_ISA_BRIDGE) => "pci-isa-bridge",
        (PCI_CLASS_BRIDGE, _) => "pci-bridge",
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
                // KM6：唯一注册名 = 类别描述 + PCI 位置（泄漏为 'static，
                // 注册表条目本就终生存在）。
                let base = name_for_device(class_code, subclass);
                let name: &'static str = alloc::boxed::Box::leak(
                    alloc::format!("{base}-{bus:02x}-{device:02x}-{function}").into_boxed_str(),
                );
                // C15.1：只有海量存储类硬件背后存在可持久化介质；其余类别
                // 的设备一律保守披露为易失，禁止伪装持久存储。
                let is_mass_storage = class_code == PCI_CLASS_MASS_STORAGE;

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

                // K2：把该设备的第一个 MMIO BAR 发布为 UIO 可认领的物理窗口
                // （设备物理资源是内核登记事实，用户 claim 只能映射这里登记
                // 过的窗口）。发布失败不阻断设备注册，但必须留痕。
                let bars = inspect_pci_bars(bus, device, function);
                let window = bars.iter().find_map(|bar| match *bar {
                    PciBar::Mmio32 { addr, size, .. } => Some((addr as u64, size as u64)),
                    PciBar::Mmio64 { addr, size, .. } => Some((addr, size)),
                    _ => None,
                });
                if let Some((phys, size)) = window {
                    if let Err(e) = crate::publish_device_window(name, phys, size) {
                        info!(
                            "[pci] device window publish skipped for {}: {:?}",
                            name, e
                        );
                    }
                }

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
