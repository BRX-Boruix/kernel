//! 设备分类定义与统一设备操作抽象（DeviceOps / IoDevice）。
//!
//! 统一抽象字符设备、块设备、输入设备与网络设备，支持零 ioctl 纯属性读写。

use core::sync::atomic::{AtomicU64, Ordering};
use klib::error::Error;

/// 计算字节区间 `[offset, offset+len)` 触碰的 512B 扇区块数（去重）。
///
/// `len == 0` 恒为 0；跨界部分扇区按实际触碰的去重块数计。
/// 该公式是内存型后端（ramdisk / ATA 回退盘）扇区计数的唯一口径。
///
/// 溢出纪律（drv1 DD1）：区间末端经 `saturating_add` 截断在地址域末端
/// （`u64::MAX`），任何 `(offset, len)` 组合都不溢出、不回绕——大 `len`
/// 的语义是"区间延伸到地址空间尽头为止"，与越界写回退到介质尾的行为一致。
pub fn sectors_touched(offset: u64, len: u64) -> u64 {
    if len == 0 {
        return 0;
    }
    let first_block = offset / 512;
    // len >= 1 ⇒ len - 1 无下溢；末端饱和截断，见上。
    let last_byte = offset.saturating_add(len - 1);
    last_byte / 512 - first_block + 1
}

/// 块设备真实 I/O 计数（DMYGH C16.1）。
///
/// 语义：计数与介质实际发生的 512B 扇区传输一一对应——
/// - 硬件 ATA：每条**成功**的扇区读/写命令各计 1；
/// - 内存型后端（ramdisk / ATA 回退盘）：按传输区间触碰的去重扇区块数
///   （[`sectors_touched`]）累计，其"扇区"为逻辑单位，设备自身的
///   `volatile=true` 披露已表明无物理介质。
///
/// 只有成功路径计数；失败、越界、被拒绝的操作一律不计。
/// 字段私有 + 只读访问器：外部只能观测，无法凭空写入。
#[derive(Debug)]
pub struct IoStats {
    sectors_read: AtomicU64,
    sectors_written: AtomicU64,
}

impl IoStats {
    pub const fn new() -> Self {
        Self {
            sectors_read: AtomicU64::new(0),
            sectors_written: AtomicU64::new(0),
        }
    }

    /// 记录一次成功传输涉及的扇区数。内部使用 wrapping 语义防溢出 panic：
    /// u64 扇区数在可预见寿命内不可能绕回，绕回本身即统计失真前兆。
    pub fn record_read(&self, sectors: u64) {
        self.sectors_read.fetch_add(sectors, Ordering::Relaxed);
    }

    pub fn record_write(&self, sectors: u64) {
        self.sectors_written.fetch_add(sectors, Ordering::Relaxed);
    }

    pub fn sectors_read(&self) -> u64 {
        self.sectors_read.load(Ordering::Relaxed)
    }

    pub fn sectors_written(&self) -> u64 {
        self.sectors_written.load(Ordering::Relaxed)
    }
}

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
    fn size(&self) -> Option<u64> {
        None
    }
    /// 返回该设备的真实 I/O 计数；无计数能力的设备返回 `None`。
    /// 缺失必须可见（JSON 输出 null/error），禁止用零值冒充"从未发生 I/O"。
    fn io_stats(&self) -> Option<&IoStats> {
        None
    }
}

/// 字符设备（如串口、终端、控制台）。
///
/// S15：**显式 opt-in marker**——不允许 blanket impl。只有具体字符设备
/// 才 `impl CharDevice`，否则一切 IoDevice（含块/网络）都被标记为字符，
/// DeviceKind 分类语义被架空。各设备依据自身 `kind()` 归属，不依赖本 trait。
pub trait CharDevice: IoDevice {}

/// 输入设备（如键盘、鼠标）。
///
/// S15：显式 opt-in marker（同 [`CharDevice`]）。仅真实输入设备实现。
pub trait InputDevice: CharDevice {}

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
    /// 数据易失性披露（DMYGH C15.1）：`true` 表示该设备承载的数据在断电或
    /// 重启后不持久（内存模拟盘、流式设备、纯虚拟设备等）。只有可证明
    /// 持久化的真实硬件介质（如 ATA 硬盘、电池供电 CMOS）才允许 `false`。
    /// 无法证明持久化的设备必须保守上报 `true`，禁止默认伪装为持久存储。
    pub volatile: bool,
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
            // 空描述符不承载任何持久性证据，按易失披露（保守方向）。
            volatile: true,
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
