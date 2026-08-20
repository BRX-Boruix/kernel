//! Core 阶段：PS/2 键盘控制器驱动（Platform InputDevice）。

use crate::device::{BusType, CharDevice, Device, DeviceInfo, DeviceKind, DeviceOps, InputDevice, IoDevice};
use crate::driver::DriverStage;
use crate::hub::DriverHub;

pub struct KeyboardDevice;

impl Device for KeyboardDevice {
    fn name(&self) -> &'static str {
        "ps2-keyboard"
    }

    fn kind(&self) -> DeviceKind {
        DeviceKind::Char
    }

    fn as_io(&self) -> Option<&dyn IoDevice> {
        Some(self)
    }
}

impl IoDevice for KeyboardDevice {
    fn read(&self, out: &mut [u8]) -> usize {
        let mut got = 0usize;
        while got < out.len() {
            match arch_x86_64::keyboard::pop() {
                Some(ch) => {
                    out[got] = ch;
                    got += 1;
                }
                None => break,
            }
        }
        got
    }

    fn poll(&self) -> bool {
        // 如果有按键缓存则返回 true
        false
    }
}

pub static KEYBOARD_DEV: KeyboardDevice = KeyboardDevice;

pub fn init_keyboard(_hub: &DriverHub) {
    DriverHub::register_device_info(
        DeviceInfo {
            name: "ps2-keyboard",
            kind: DeviceKind::Char,
            bus: BusType::Platform,
            location: 0x60,
            vendor_id: 0,
            device_id: 0,
            class_code: 0x09, // Input Device Controller
            subclass: 0x00,   // Keyboard Controller
            prog_if: 0x00,
        },
        Some(&KEYBOARD_DEV),
        Some("keyboard"),
    );
}

pub fn register_keyboard_driver() {
    DriverHub::register_driver("keyboard", DriverStage::Core, init_keyboard);
}
