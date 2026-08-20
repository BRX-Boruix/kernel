//! Ramdisk 虚拟内存块设备驱动（BlockDevice）。
//!
//! 在内存中开辟连续空间模拟块存储，直接作为 VFS 挂载点或数据卷。

use crate::device::{BlockDevice, BusType, Device, DeviceInfo, DeviceKind, IoDevice};
use crate::driver::DriverStage;
use crate::hub::DriverHub;
use spin::Mutex;

const RAMDISK_CAPACITY: usize = 16 * 1024 * 1024; // 16 MB 内存盘
static RAMDISK_STORAGE: Mutex<[u8; 1024 * 64]> = Mutex::new([0u8; 1024 * 64]); // 64KB 内核紧凑缓冲区

pub struct RamdiskDevice {
    pub name: &'static str,
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
        let off = offset as usize;
        if off >= storage.len() {
            return 0;
        }
        let n = core::cmp::min(out.len(), storage.len() - off);
        out[..n].copy_from_slice(&storage[off..off + n]);
        n
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> usize {
        let mut storage = RAMDISK_STORAGE.lock();
        let off = offset as usize;
        if off >= storage.len() {
            return 0;
        }
        let n = core::cmp::min(data.len(), storage.len() - off);
        storage[off..off + n].copy_from_slice(&data[..n]);
        n
    }

    fn size(&self) -> Option<u64> {
        Some(RAMDISK_CAPACITY as u64)
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

pub static RAMDISK_DEV: RamdiskDevice = RamdiskDevice { name: "ramdisk0" };

pub fn init_ramdisk(_hub: &DriverHub) {
    DriverHub::register_device_info(
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
        },
        Some(&RAMDISK_DEV),
        Some("ramdisk"),
    );
}

pub fn register_ramdisk_driver() {
    DriverHub::register_driver("ramdisk", DriverStage::Late, init_ramdisk);
}
