//! 具体硬件与外设驱动集合（统一收拢管理）。
//!
//! 包含：
//! - `serial`：Early 阶段 COM1 串口字符设备驱动；
//! - `keyboard`：Core 阶段 PS/2 键盘控制器驱动（键盘队列唯一消费点）；
//! - `cmos`：Core 阶段 CMOS RTC 实时时钟驱动；
//! - `pseudo`：Core 阶段 null / zero 伪设备驱动；
//! - `ata_pio`：Devices 阶段 ATA/IDE PIO **LBA28** 块存储驱动；
//! - `ramdisk`：Late 阶段虚拟内存磁盘块设备驱动；
//! - `pci_bus`：Devices 阶段 PCI 总线探测与 BAR 一次性自省缓存；
//! - `pci_classes`：Devices 阶段 PCI 类匹配**候选登记器**（candidate-only，
//!   ADR-022 §1——无真实硬件控制，绑定以 candidate 前缀呈现）。

pub mod ata_pio;
pub mod cmos;
pub mod keyboard;
pub mod pci_bus;
pub mod pci_classes;
pub mod pseudo;
pub mod ramdisk;
pub mod serial;
