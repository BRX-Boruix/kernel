//! Platform 平台基础设备驱动（Early/Core 阶段）。
//!
//! 包含：
//! - `serial`：Early 阶段 COM1 串口字符设备；
//! - `keyboard`：Core 阶段 PS/2 键盘输入设备；
//! - `cmos`：Core 阶段 CMOS RTC 硬件实时时钟；
//! - `pseudo`：Core/Late 阶段伪设备（null, zero, tty）。

pub mod serial;
pub mod keyboard;
pub mod cmos;
pub mod pseudo;
