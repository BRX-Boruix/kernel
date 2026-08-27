//! Core/Late 阶段：伪设备实现（/devices/null, /devices/zero）。

use crate::device::{BusType, CharDevice, Device, DeviceInfo, DeviceKind, IoDevice};
use crate::driver::DriverStage;
use crate::hub::DriverHub;
use klib::error::Error;

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

// S15：显式 opt-in——/devices/null 是字符设备。
impl CharDevice for NullDevice {}

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

// S15：显式 opt-in——/devices/zero 是字符设备。
impl CharDevice for ZeroDevice {}

pub static NULL_DEV: NullDevice = NullDevice;
pub static ZERO_DEV: ZeroDevice = ZeroDevice;

pub fn init_pseudo(_hub: &DriverHub) {
    // DM1：两个注册结果逐一显式处理，失败留痕不静默。
    if let Err(e) = DriverHub::register_device_info(
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
    ) {
        klib::error!("[pseudo] null device registration failed: {:?}", e);
    }

    if let Err(e) = DriverHub::register_device_info(
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
    ) {
        klib::error!("[pseudo] zero device registration failed: {:?}", e);
    }
}

pub fn register_pseudo_driver() -> Result<(), Error> {
    DriverHub::register_driver("pseudo", DriverStage::Core, init_pseudo)
}
