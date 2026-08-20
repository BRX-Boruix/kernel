//! 具体硬件与外设驱动集合（统一收拢管理）。
//!
//! 包含：
//! - `serial`：Early 阶段 COM1 串口字符设备驱动；
//! - `keyboard`：Core 阶段 PS/2 键盘控制器驱动；
//! - `cmos`：Core 阶段 CMOS RTC 实时时钟驱动；
//! - `pseudo`：Core 阶段 null / zero 伪设备驱动；
//! - `ata_pio`：Devices 阶段 ATA / IDE PIO 块存储驱动；
//! - `ramdisk`：Late 阶段虚拟内存磁盘块设备驱动；
//! - `pci_bus`：Devices 阶段 PCI 总线探测与 BAR 自省驱动；
//! - `pci_classes`：Devices 阶段 PCI 类目竞标驱动（以太网卡、VGA 显示、存储）。

pub mod ata_pio;
pub mod cmos;
pub mod keyboard;
pub mod pci_bus;
pub mod pci_classes;
pub mod pseudo;
pub mod ramdisk;
pub mod serial;
