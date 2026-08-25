//! Ramdisk 虚拟内存块设备驱动（BlockDevice）。
//!
//! 在内存中开辟连续空间模拟块存储，直接作为 VFS 挂载点或数据卷。

use crate::device::{
    sectors_touched, BlockDevice, BusType, Device, DeviceInfo, DeviceKind, IoDevice, IoStats,
};
use crate::driver::DriverStage;
use crate::hub::DriverHub;
use klib::error::Error;
use spin::Mutex;

/// Ramdisk 的实际可写容量。静态后端占用 BSS；该常量同时决定存储数组、
/// `size()` 与 `block_count()`，防止容量上报与真实存储再次分叉（DMYGH #14）。
const RAMDISK_CAPACITY: usize = 64 * 1024;
static RAMDISK_STORAGE: Mutex<[u8; RAMDISK_CAPACITY]> = Mutex::new([0u8; RAMDISK_CAPACITY]);

pub struct RamdiskDevice {
    pub name: &'static str,
    /// 真实 I/O 计数（C16.1）：按成功传输区间触碰的去重扇区块数累计。
    pub stats: IoStats,
}

impl Device for RamdiskDevice {
    fn name(&self) -> &'static str {
        self.name
    }

    fn kind(&self) -> DeviceKind {
        DeviceKind::Block
    }

    fn as_io(&self) -> Option<&dyn IoDevice> {
        Some(self)
    }

    fn as_block(&self) -> Option<&dyn BlockDevice> {
        Some(self)
    }
}

impl IoDevice for RamdiskDevice {
    fn read_at(&self, offset: u64, out: &mut [u8]) -> usize {
        let storage = RAMDISK_STORAGE.lock();
        let Ok(off) = usize::try_from(offset) else {
            return 0;
        };
        if off >= storage.len() {
            return 0;
        }
        let n = core::cmp::min(out.len(), storage.len() - off);
        out[..n].copy_from_slice(&storage[off..off + n]);
        self.stats.record_read(sectors_touched(offset, n as u64));
        n
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> usize {
        // 成文契约（drv1 DD4a）：本方法是遗留短写风格接口的兼容适配——
        // 签名本身无法承载错误类型，`Err -> 0` 的映射是该签名的固有损失，
        // 不是吞错缺陷。实现原语是 [`Self::write_at_checked`]；**新调用方
        // 一律使用 checked 接口**获得可程序化的失败原因（OutOfRange 等）。
        self.write_at_checked(offset, data).unwrap_or(0)
    }

    fn write_at_checked(&self, offset: u64, data: &[u8]) -> Result<usize, klib::error::Error> {
        let mut storage = RAMDISK_STORAGE.lock();
        let off = usize::try_from(offset).map_err(|_| klib::error::Error::OutOfRange)?;
        let end = off
            .checked_add(data.len())
            .ok_or(klib::error::Error::OutOfRange)?;
        if end > storage.len() {
            return Err(klib::error::Error::OutOfRange);
        }
        storage[off..end].copy_from_slice(data);
        // C16.1：只有完整成功的写入才计数；上面的越界/溢出错误路径不经过此处。
        self.stats
            .record_write(sectors_touched(offset, data.len() as u64));
        Ok(data.len())
    }

    fn size(&self) -> Option<u64> {
        Some(RAMDISK_CAPACITY as u64)
    }

    fn io_stats(&self) -> Option<&IoStats> {
        Some(&self.stats)
    }
}

impl BlockDevice for RamdiskDevice {
    fn block_size(&self) -> usize {
        512
    }

    fn block_count(&self) -> u64 {
        (RAMDISK_CAPACITY / 512) as u64
    }
}

pub static RAMDISK_DEV: RamdiskDevice = RamdiskDevice {
    name: "ramdisk0",
    stats: IoStats::new(),
};

pub fn init_ramdisk(_hub: &DriverHub) {
    if let Err(e) = DriverHub::register_device_info(
        DeviceInfo {
            name: "ramdisk0",
            kind: DeviceKind::Block,
            bus: BusType::Virtual,
            location: 0,
            vendor_id: 0,
            device_id: 0,
            class_code: 0x01,
            subclass: 0x80,
            prog_if: 0,
            // DMYGH C15.1：Ramdisk 后端是进程地址空间外的静态内存，重启即失。
            volatile: true,
        },
        Some(&RAMDISK_DEV),
        Some("ramdisk"),
    ) {
        klib::error!("[ramdisk] device registration failed: {:?}", e);
    }
}

pub fn register_ramdisk_driver() -> Result<(), Error> {
    DriverHub::register_driver("ramdisk", DriverStage::Late, init_ramdisk)
}
