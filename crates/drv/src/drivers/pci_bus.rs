//! PCI 总线枚举与设备控制模块（BusType::Pci，BAR 自省与遥测支持，M10.1）。
//!
//! 支持通过 I/O 端口 0xCF8 / 0xCFC 进行 Legacy PCI 配置空间扫描、BARs 解析与读写。
//!
//! KM6：设备注册名唯一化——旧实现按类别命名（两台同类别设备重名），而
//! DriverHub 的 name-based 查找（`pci_location_of`、UIO claim、DevFS 投影）
//! 以名字区分设备，重名使查找永远命中第一台。现注册名为
//! `<类别描述>-<bus>-<device>-<function>`（经 `Box::leak` 常驻；注册表条目
//! 本就终生存在，数量受扫描空间上界约束）。
//!
//! BAR 探测一次性纪律（ADR-022 §4 / DA3）：BAR 尺寸测量采用"写全 1 读回"
//! 的规范手法，对活动设备是**破坏性配置空间写**。本模块只在扫描枚举期对
//! 每设备执行一次探测并把结果存入 [`cached_pci_bars`] 只读缓存；DevFS 等
//! 消费方一律读缓存——"读一个属性文件"永远不再触碰设备配置空间。

use crate::device::{BusType, DeviceInfo, DeviceKind};
use crate::driver::DriverStage;
use crate::hub::DriverHub;
use arch_x86_64::port::{inl, outl};
use klib::{error::Error, info, warn};
use spin::Mutex;

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

/// 解析指定 PCI 设备的 6 个 BAR 配置空间（**破坏性探测，仅限扫描期调用**）。
///
/// 采用"写全 1 读回"规范手法测量 BAR 尺寸——对已由驱动接管的设备执行会
/// 瞬时破坏其配置空间。本函数私有化（ADR-022 §4），唯一调用方是
/// [`scan_pci_bus`] 的枚举路径；运行期消费一律走 [`cached_pci_bars`]。
fn inspect_pci_bars(bus: u8, device: u8, function: u8) -> [PciBar; 6] {
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

            if bar_type == 2 && i + 1 >= 6 {
                // DD4b：末槽（slot 5）64-bit BAR 没有配对的高位槽，按规范属
                // 畸形配置。如实拒绝解析并留痕——静默按 32 位误读会把高位
                // 基址/尺寸整个读错。
                warn!(
                    "[pci] malformed config: 64-bit BAR in final slot {:02x}:{:02x}.{} (no paired high dword); skipped",
                    bus, device, function
                );
                bars[i] = PciBar::None;
                i += 1;
            } else if bar_type == 2 {
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

/// BAR 探测缓存条目：扫描期一次性探测的结果（ADR-022 §4）。
struct BarCacheEntry {
    name: &'static str,
    bars: [PciBar; 6],
}

/// 缓存容量与 DriverHub 设备表一致：每个成功注册的 PCI 设备至多一条，
/// 不存在溢出路径；越界即内核缺陷信号，warn 留痕后放弃缓存该条目。
const MAX_BAR_CACHE: usize = 64;
static BAR_CACHE: Mutex<[Option<BarCacheEntry>; MAX_BAR_CACHE]> =
    Mutex::new([const { None }; MAX_BAR_CACHE]);

/// 查询设备扫描期缓存的 BAR 解析结果（只读，零配置空间访问）。
///
/// 仅 [`scan_pci_bus`] 注册过的 PCI 设备有条目；非扫描路径注册的 PCI 设备
/// 返回 `None`——调用方必须显式处理缺席（DevFS 报 `no_bar_probe` 错误），
/// 禁止现场补探测或编造空结果。
pub fn cached_pci_bars(dev_name: &str) -> Option<[PciBar; 6]> {
    let cache = BAR_CACHE.lock();
    cache.iter().find_map(|slot| {
        slot.as_ref()
            .filter(|e| e.name == dev_name)
            .map(|e| e.bars)
    })
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

                if DriverHub::register_device_info(
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
                )
                .is_err()
                {
                    // DM1：设备表满等注册失败必须留痕；未注册的设备不进入
                    // BAR 缓存，避免产生任何查不到属主的探测记录。
                    warn!(
                        "[pci] device {} registration rejected (device table full); skipping",
                        name
                    );
                    continue;
                }

                // K2 + DA3：对该设备执行唯一一次 BAR 探测，结果入只读缓存；
                // 第一个 MMIO 窗口发布为 UIO 可认领的物理窗口（设备物理资源
                // 是内核登记事实）。发布失败不阻断设备注册，但必须留痕。
                let bars = inspect_pci_bars(bus, device, function);
                {
                    let mut cache = BAR_CACHE.lock();
                    match cache.iter_mut().find(|s| s.is_none()) {
                        Some(slot) => *slot = Some(BarCacheEntry { name, bars }),
                        None => warn!(
                            "[pci] BAR cache full; probe result for {} not cached (kernel defect signal)",
                            name
                        ),
                    }
                }
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

pub fn register_pci_bus_driver() -> Result<(), Error> {
    DriverHub::register_driver("pci-bus", DriverStage::Devices, init_pci_bus)
}
