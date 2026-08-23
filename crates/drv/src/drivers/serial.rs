//! Early 阶段：COM1 串口控制台驱动（Platform CharDevice）。

use crate::device::{BusType, CharDevice, Device, DeviceInfo, DeviceKind, DeviceOps, IoDevice};
use crate::driver::DriverStage;
use crate::hub::DriverHub;

/// COM1 串口设备在 DriverHub / DevFS 中的唯一注册名。
///
/// KM8：字面量曾散布在驱动注册、DevFS 投影与内核 serial_read/write 查找三处，
/// 任一处漂移都会让 name-based 查找静默失配、悄悄落到直连硬件回退路径。
/// 所有引用点统一 import 本常量。
pub const COM1_DEVICE_NAME: &str = "serial-com1";

pub struct SerialDevice;

impl Device for SerialDevice {
    fn name(&self) -> &'static str {
        COM1_DEVICE_NAME
    }

    fn kind(&self) -> DeviceKind {
        DeviceKind::Char
    }

    fn as_io(&self) -> Option<&dyn IoDevice> {
        Some(self)
    }
}

impl IoDevice for SerialDevice {
    fn write(&self, data: &[u8]) -> usize {
        if let Ok(s) = core::str::from_utf8(data) {
            arch_x86_64::serial::write_str(s);
        } else {
            for &b in data {
                arch_x86_64::serial::write_byte(b);
            }
        }
        data.len()
    }

    fn write_at(&self, _offset: u64, data: &[u8]) -> usize {
        self.write(data)
    }
}

pub static SERIAL_DEV: SerialDevice = SerialDevice;

pub fn init_serial(hub: &DriverHub) {
    arch_x86_64::serial::init();
    DriverHub::register_device_info(
        DeviceInfo {
            name: COM1_DEVICE_NAME,
            kind: DeviceKind::Char,
            bus: BusType::Platform,
            location: 0x3F8,
            vendor_id: 0,
            device_id: 0,
            class_code: 0x07, // Simple Communications Controller
            subclass: 0x00,   // Generic 16550 UART
            prog_if: 0x02,
            // C15.1：串口是流式通道，不持久化任何数据。
            volatile: true,
        },
        Some(&SERIAL_DEV),
        Some("serial"),
    );
}

pub fn register_serial_driver() {
    DriverHub::register_driver("serial", DriverStage::Early, init_serial);
}
