//! Core/Late 阶段：伪设备实现（/devices/null, /devices/zero）。

use crate::device::{BusType, CharDevice, Device, DeviceInfo, DeviceKind, DeviceOps, IoDevice};
use crate::driver::DriverStage;
use crate::hub::DriverHub;

pub struct NullDevice;

impl Device for NullDevice {
    fn name(&self) -> &'static str {
        "null"
    }

    fn kind(&self) -> DeviceKind {
        DeviceKind::Char
    }

    fn as_io(&self) -> Option<&dyn IoDevice> {
        Some(self)
    }
}

impl IoDevice for NullDevice {
    fn read(&self, _out: &mut [u8]) -> usize {
        0
    }

    fn write(&self, data: &[u8]) -> usize {
        data.len()
    }
}

pub struct ZeroDevice;

impl Device for ZeroDevice {
    fn name(&self) -> &'static str {
        "zero"
    }

    fn kind(&self) -> DeviceKind {
        DeviceKind::Char
    }

    fn as_io(&self) -> Option<&dyn IoDevice> {
        Some(self)
    }
}

impl IoDevice for ZeroDevice {
    fn read(&self, out: &mut [u8]) -> usize {
        for b in out.iter_mut() {
            *b = 0;
        }
        out.len()
    }

    fn write(&self, data: &[u8]) -> usize {
        data.len()
    }
}

pub static NULL_DEV: NullDevice = NullDevice;
pub static ZERO_DEV: ZeroDevice = ZeroDevice;

pub fn init_pseudo(_hub: &DriverHub) {
    DriverHub::register_device_info(
        DeviceInfo {
            name: "null",
            kind: DeviceKind::Char,
            bus: BusType::Virtual,
            location: 0,
            vendor_id: 0,
            device_id: 0,
            class_code: 0,
            subclass: 0,
            prog_if: 0,
            // C15.1：纯虚拟黑洞设备，写入即弃。
            volatile: true,
        },
        Some(&NULL_DEV),
        Some("pseudo"),
    );

    DriverHub::register_device_info(
        DeviceInfo {
            name: "zero",
            kind: DeviceKind::Char,
            bus: BusType::Virtual,
            location: 0,
            vendor_id: 0,
            device_id: 0,
            class_code: 0,
            subclass: 0,
            prog_if: 0,
            // C15.1：纯虚拟零流设备，不承载可持久数据。
            volatile: true,
        },
        Some(&ZERO_DEV),
        Some("pseudo"),
    );
}

pub fn register_pseudo_driver() {
    DriverHub::register_driver("pseudo", DriverStage::Core, init_pseudo);
}
