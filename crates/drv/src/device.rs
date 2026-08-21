//! 设备分类定义与统一设备操作抽象（DeviceOps / IoDevice）。
//!
//! 统一抽象字符设备、块设备、输入设备与网络设备，支持零 ioctl 纯属性读写。

use klib::error::Error;

/// 基础 IO 设备 Trait（只包含标准 read/write/poll/size 等操作，彻底抛弃 ioctl）。
pub trait IoDevice: Send + Sync {
    fn read(&self, _out: &mut [u8]) -> usize {
        0
    }
    fn write(&self, _data: &[u8]) -> usize {
        0
    }
    fn read_at(&self, _offset: u64, out: &mut [u8]) -> usize {
        self.read(out)
    }
    fn write_at(&self, _offset: u64, data: &[u8]) -> usize {
        self.write(data)
    }
    /// 带错误码的定位写接口。
    ///
    /// `write_at` 是遗留的短写风格接口，无法区分 0 字节写、设备繁忙与参数越界；
    /// 新调用方应使用本接口获得可程序化的失败原因。默认实现保留旧设备兼容性，
    /// 将短写归类为设备 I/O 错误。
    fn write_at_checked(&self, offset: u64, data: &[u8]) -> Result<usize, Error> {
        let written = self.write_at(offset, data);
        if written == data.len() {
            Ok(written)
        } else {
            Err(Error::Io)
        }
    }
    fn poll(&self) -> bool {
        false
    }
    fn size(&self) -> Option<u64> {
        None
    }
}

/// 字符设备（如串口、终端、控制台）。
pub trait CharDevice: IoDevice {}
impl<T: IoDevice + ?Sized> CharDevice for T {}

/// 输入设备（如键盘、鼠标）。
pub trait InputDevice: CharDevice {}
impl<T: CharDevice + ?Sized> InputDevice for T {}

/// 块存储设备（如 ATA/IDE 硬盘、VirtIO-Blk、Ramdisk）。
pub trait BlockDevice: IoDevice {
    fn block_size(&self) -> usize {
        512
    }
    fn block_count(&self) -> u64 {
        self.size().unwrap_or(0) / self.block_size() as u64
    }
}

/// 网络设备（如 e1000 以太网卡）。
pub trait NetDevice: IoDevice {
    fn mac_address(&self) -> [u8; 6] {
        [0u8; 6]
    }
    fn transmit(&self, _packet: &[u8]) -> bool {
        false
    }
    fn receive(&self, _out_packet: &mut [u8]) -> usize {
        0
    }
}

/// 设备种类分类。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceKind {
    Char,
    Block,
    Net,
    Display,
    Misc,
}

/// 物理/虚拟总线分类。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusType {
    Platform,
    Pci,
    Virtual,
    Unknown,
}

/// 统一设备描述符元数据。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    pub name: &'static str,
    pub kind: DeviceKind,
    pub bus: BusType,
    pub location: u32,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u8,
    pub subclass: u8,
    pub prog_if: u8,
}

impl DeviceInfo {
    pub const fn empty() -> Self {
        Self {
            name: "",
            kind: DeviceKind::Misc,
            bus: BusType::Unknown,
            location: 0,
            vendor_id: 0,
            device_id: 0,
            class_code: 0,
            subclass: 0,
            prog_if: 0,
        }
    }
}

/// 统一设备操作抽象：所有可被 DriverHub 发现与控制的设备实例均实现此接口。
pub trait Device: Send + Sync {
    fn name(&self) -> &'static str;
    fn kind(&self) -> DeviceKind;
    fn as_io(&self) -> Option<&dyn IoDevice> {
        None
    }
    fn as_block(&self) -> Option<&dyn BlockDevice> {
        None
    }
}

pub trait DeviceOps: Device + IoDevice + Send + Sync {}
impl<T: Device + IoDevice + Send + Sync> DeviceOps for T {}
