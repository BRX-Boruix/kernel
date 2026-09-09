//! Core 阶段：PS/2 键盘控制器驱动（Platform InputDevice）。
//!
//! 单一消费点纪律（ADR-022 §8 / DM5）：键盘队列是独占资源，字节唯一 pop
//! 点是本设备的 [`IoDevice::read`]。kernel 侧 stdin 源与 DevFS 直读都经
//! DriverHub 转发到同一扇门——多读者竞争自此是字符设备的标准语义，内核
//! 内部不存在第二条绕过设备的隐藏通道。

use crate::device::{BusType, CharDevice, Device, DeviceInfo, DeviceKind, InputDevice, IoDevice};
use crate::driver::DriverStage;
use crate::hub::DriverHub;
use klib::error::Error;

/// PS/2 键盘设备在 DriverHub / DevFS / kernel stdin 接线中的唯一注册名。
///
/// KM8 同款纪律：字面量散布在驱动注册、kernel stdin 转发查找等多处，
/// 任一处漂移都会让 name-based 查找静默失配、悄悄落到直连硬件回退路径。
pub const PS2_KEYBOARD_DEVICE_NAME: &str = "ps2-keyboard";

pub struct KeyboardDevice;

impl Device for KeyboardDevice {
    fn name(&self) -> &'static str {
        PS2_KEYBOARD_DEVICE_NAME
    }

    fn kind(&self) -> DeviceKind {
        DeviceKind::Char
    }

    fn as_io(&self) -> Option<&dyn IoDevice> {
        Some(self)
    }
}

impl IoDevice for KeyboardDevice {
    /// 从键盘队列取走至多 `out.len()` 个字节。
    ///
    /// 这是全内核唯一合法的键盘队列消费点；无数据时返回 0（非阻塞语义，
    /// 与 stdin 源的 WouldBlock 契约衔接）。
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

    // ADR-022 §6（DM2）：原恒 false 的 poll() 覆写已随 IoDevice::poll
    // trait 槽位一并删除——零消费方的说谎接口不留存；首个轮询型消费者
    // （stdio 非阻塞读）立项时按需重建并附带消费方。
}

pub static KEYBOARD_DEV: KeyboardDevice = KeyboardDevice;

// S15：显式 opt-in——PS/2 键盘是字符/输入设备（InputDevice: CharDevice）。
impl CharDevice for KeyboardDevice {}
impl InputDevice for KeyboardDevice {}

pub fn init_keyboard(_hub: &DriverHub) {
    if let Err(e) = DriverHub::register_device_info(
        DeviceInfo {
            name: PS2_KEYBOARD_DEVICE_NAME,
            kind: DeviceKind::Char,
            bus: BusType::Platform,
            location: 0x60,
            vendor_id: 0,
            device_id: 0,
            class_code: 0x09, // Input Device Controller
            subclass: 0x00,   // Keyboard Controller
            prog_if: 0x00,
            // C15.1：按键是瞬时输入事件，不持久化任何数据。
            volatile: true,
            // 键盘为 IRQ1 平台设备；PCI 中断线字段置 0（不参与设备中断投递）。
            irq_line: 0,
        },
        Some(&KEYBOARD_DEV),
        Some("keyboard"),
    ) {
        // DM1：注册失败必须可见（表满等），静默丢设备不复存在。
        klib::error!(
            "[keyboard] device registration failed: {:?} (stdin will fall back to direct UART path)",
            e
        );
    }
}

pub fn register_keyboard_driver() -> Result<(), Error> {
    DriverHub::register_driver("keyboard", DriverStage::Core, init_keyboard)
}
