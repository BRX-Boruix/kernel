//! Platform 平台基础设备驱动（Early/Core/Devices/Late 阶段）。
//!
//! 包含：
//! - `serial`：Early 阶段 COM1 串口字符设备；
//! - `keyboard`：Core 阶段 PS/2 键盘输入设备；
//! - `cmos`：Core 阶段 CMOS RTC 硬件实时时钟；
//! - `pseudo`：Core 阶段伪设备（null, zero）；
//! - `ata_pio`：Devices 阶段 ATA/IDE 硬盘块设备；
//! - `ramdisk`：Late 阶段虚拟内存磁盘块设备。

pub mod serial;
pub mod keyboard;
pub mod cmos;
pub mod pseudo;
pub mod ata_pio;
pub mod ramdisk;
