//! Core 阶段：PS/2 键盘控制器驱动（Platform InputDevice）。
//!
//! **I-EVENTS P5 轨道 A 退役（§6.15.5）**：本设备曾是「键盘字节队列的唯一
//! 消费点」（ADR-022 §8 / DM5 的 stdin 扇门）。P4 单径切换后 stdin 不再
//! 经 DriverHub 取键盘字节（等待源唯一是 console 环），P5 移除内核字节环
//! 后本设备无字节可读——`IoDevice::read` 如实恒返 0（设备枚举与 DriverHub
//! 登记保留：PS/2 控制器真实存在，设备清单的「有此硬件」仍是真话；「有
//! 字节流」不再是）。键事件经 `/devices/input/events`（原始键码）+ 用户态
//! consoled 转换供给终端。

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
    /// **恒返 0**（P5 轨道 A 退役）：字节环已随内核 KEYMAP 一起移除，本设备
    /// 不再有数据源。保留 trait 槽位与 0 返回（「此刻无数据」的诚实形态）
    /// 而非删除 impl——DriverHub 设备枚举/列举契约仍要求 IoDevice 存在；
    /// 任何经此 read 的调用方得到的是「无数据」，不是伪造的字节。
    fn read(&self, _out: &mut [u8]) -> usize {
        0
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
