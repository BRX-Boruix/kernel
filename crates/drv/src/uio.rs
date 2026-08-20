//! 用户态驱动沙箱（Userspace I/O & Driver Sandbox Subsystem，M11）。
//!
//! 提供用户态驱动注册、设备硬件认领（Claim）、MMIO 物理地址安全映射及异常隔离守护。

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Mutex;
use klib::error::Error;
use klib::info;

pub const MAX_UIO_DRIVERS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UioDriverEntry {
    pub pid: usize,
    pub claimed_device: [u8; 32],
    pub claimed_len: usize,
    pub mmio_phys_base: u64,
    pub mmio_size: u64,
    pub is_alive: bool,
}

impl UioDriverEntry {
    pub const EMPTY: Self = Self {
        pid: 0,
        claimed_device: [0u8; 32],
        claimed_len: 0,
        mmio_phys_base: 0,
        mmio_size: 0,
        is_alive: false,
    };
}

static UIO_COUNT: AtomicUsize = AtomicUsize::new(0);
static UIO_DRIVERS: Mutex<[UioDriverEntry; MAX_UIO_DRIVERS]> = Mutex::new([UioDriverEntry::EMPTY; MAX_UIO_DRIVERS]);

/// 用户态进程注册为驱动实例（UIO Register，M11.1）。
pub fn uio_register_driver(pid: usize, dev_name: &str, mmio_base: u64, mmio_size: u64) -> Result<usize, Error> {
    let mut list = UIO_DRIVERS.lock();
    for (i, entry) in list.iter_mut().enumerate() {
        if !entry.is_alive {
            let mut name_buf = [0u8; 32];
            let copy_len = dev_name.len().min(31);
            name_buf[..copy_len].copy_from_slice(&dev_name.as_bytes()[..copy_len]);

            *entry = UioDriverEntry {
                pid,
                claimed_device: name_buf,
                claimed_len: copy_len,
                mmio_phys_base: mmio_base,
                mmio_size,
                is_alive: true,
            };
            UIO_COUNT.fetch_add(1, Ordering::Relaxed);
            info!("[uio] driver registered: pid={} claiming dev={} mmio={:#x} (size={})", pid, dev_name, mmio_base, mmio_size);
            return Ok(i);
        }
    }
    Err(Error::OutOfMemory)
}

/// 进程退出或异常终止时，自动隔离并释放其认领的硬件资源（M11.2 Fault Isolation）。
pub fn uio_on_process_exit(pid: usize) -> bool {
    let mut list = UIO_DRIVERS.lock();
    let mut found = false;
    for entry in list.iter_mut() {
        if entry.is_alive && entry.pid == pid {
            entry.is_alive = false;
            found = true;
            let dev_str = core::str::from_utf8(&entry.claimed_device[..entry.claimed_len]).unwrap_or("unknown");
            info!("[uio] isolated crashed driver: pid={} claimed_dev={} (kernel protected, 0 Panic)", pid, dev_str);
        }
    }
    found
}

/// 查询指定设备是否被活跃的用户态驱动认领。
pub fn uio_is_device_claimed(dev_name: &str) -> bool {
    let list = UIO_DRIVERS.lock();
    for entry in list.iter() {
        if entry.is_alive {
            if let Ok(name) = core::str::from_utf8(&entry.claimed_device[..entry.claimed_len]) {
                if name == dev_name {
                    return true;
                }
            }
        }
    }
    false
}
