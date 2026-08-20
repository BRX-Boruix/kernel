//! 统一驱动中枢引擎（DriverHub Central Registry & Lifecycle Engine）。
//!
//! 提供线程安全的驱动与设备集中注册表、4 阶段严格生命周期触发以及自动多驱动竞标与降级机制（M8.1 & M8.2）。

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Mutex;
use klib::{info, warn};

use crate::device::{BusType, DeviceInfo, DeviceOps};
use crate::driver::{Driver, DriverEntry, DriverStage};

pub const MAX_DRIVERS: usize = 32;
pub const MAX_DEVICES: usize = 64;

#[derive(Clone, Copy)]
pub struct DeviceEntry {
    pub info: DeviceInfo,
    pub dev: Option<&'static dyn DeviceOps>,
    pub driver_name: Option<&'static str>,
    pub driver_score: u8,
}

static DRIVER_COUNT: AtomicUsize = AtomicUsize::new(0);
static DRIVERS: Mutex<[DriverEntry; MAX_DRIVERS]> = Mutex::new([DriverEntry::EMPTY; MAX_DRIVERS]);

static DEVICE_COUNT: AtomicUsize = AtomicUsize::new(0);
static DEVICES: Mutex<[Option<DeviceEntry>; MAX_DEVICES]> = Mutex::new([None; MAX_DEVICES]);

static REGISTERED: AtomicBool = AtomicBool::new(false);

/// 驱动中枢全局控制柄。
pub struct DriverHub;

impl DriverHub {
    /// 注册一个基础阶段驱动。
    pub fn register_driver(name: &'static str, stage: DriverStage, init: fn(&DriverHub)) {
        let idx = DRIVER_COUNT.fetch_add(1, Ordering::Relaxed);
        if idx >= MAX_DRIVERS {
            return;
        }
        let mut list = DRIVERS.lock();
        list[idx] = DriverEntry {
            name,
            stage,
            init,
            probe: None,
            score_probe: None,
            attach: None,
        };
    }

    /// 注册一个带 probe/attach 动态设备匹配能力的驱动。
    pub fn register_driver_ops(
        name: &'static str,
        stage: DriverStage,
        init: fn(&DriverHub),
        probe: Option<fn(&DriverHub, &DeviceInfo) -> bool>,
        attach: Option<fn(&DriverHub, &DeviceInfo) -> Result<(), ()>>,
    ) {
        let idx = DRIVER_COUNT.fetch_add(1, Ordering::Relaxed);
        if idx >= MAX_DRIVERS {
            return;
        }
        let mut list = DRIVERS.lock();
        list[idx] = DriverEntry {
            name,
            stage,
            init,
            probe,
            score_probe: None,
            attach,
        };
    }

    /// 注册一个带显式竞标打分（score_probe）的智能驱动（M8.1）。
    pub fn register_driver_bidding(
        name: &'static str,
        stage: DriverStage,
        init: fn(&DriverHub),
        score_probe: Option<fn(&DriverHub, &DeviceInfo) -> u8>,
        attach: Option<fn(&DriverHub, &DeviceInfo) -> Result<(), ()>>,
    ) {
        let idx = DRIVER_COUNT.fetch_add(1, Ordering::Relaxed);
        if idx >= MAX_DRIVERS {
            return;
        }
        let mut list = DRIVERS.lock();
        list[idx] = DriverEntry {
            name,
            stage,
            init,
            probe: None,
            score_probe,
            attach,
        };
    }

    /// 向中枢注册一个已发现的硬件设备实例。
    pub fn register_device_info(
        info: DeviceInfo,
        dev: Option<&'static dyn DeviceOps>,
        driver_name: Option<&'static str>,
    ) {
        let idx = DEVICE_COUNT.fetch_add(1, Ordering::Relaxed);
        if idx >= MAX_DEVICES {
            return;
        }
        let mut list = DEVICES.lock();
        list[idx] = Some(DeviceEntry {
            info,
            dev,
            driver_name,
            driver_score: if driver_name.is_some() { 50 } else { 0 },
        });
    }

    /// 注册一个现成的 DeviceOps 实例。
    pub fn register_device(dev: &'static dyn DeviceOps) {
        Self::register_device_info(
            DeviceInfo {
                name: dev.name(),
                kind: dev.kind(),
                bus: BusType::Unknown,
                location: 0,
                vendor_id: 0,
                device_id: 0,
                class_code: 0,
                subclass: 0,
                prog_if: 0,
            },
            Some(dev),
            None,
        );
    }

    /// 注册指定总线类型的 DeviceOps 实例。
    pub fn register_device_bus(dev: &'static dyn DeviceOps, bus: BusType) {
        Self::register_device_info(
            DeviceInfo {
                name: dev.name(),
                kind: dev.kind(),
                bus,
                location: 0,
                vendor_id: 0,
                device_id: 0,
                class_code: 0,
                subclass: 0,
                prog_if: 0,
            },
            Some(dev),
            None,
        );
    }

    /// 返回当前已注册的设备总数。
    pub fn device_count() -> usize {
        DEVICE_COUNT.load(Ordering::Relaxed)
    }

    /// 返回当前已注册的驱动总数。
    pub fn driver_count() -> usize {
        DRIVER_COUNT.load(Ordering::Relaxed)
    }

    /// 获取指定索引的设备信息。
    pub fn device_info_at(index: usize) -> Option<DeviceInfo> {
        if index >= DEVICE_COUNT.load(Ordering::Relaxed) {
            return None;
        }
        let list = DEVICES.lock();
        list.get(index).and_then(|e| e.map(|entry| entry.info))
    }

    /// 获取指定索引的设备操作集。
    pub fn device_at(index: usize) -> Option<&'static dyn DeviceOps> {
        if index >= DEVICE_COUNT.load(Ordering::Relaxed) {
            return None;
        }
        let list = DEVICES.lock();
        list.get(index).and_then(|e| e.and_then(|entry| entry.dev))
    }

    /// 获取指定索引设备绑定的驱动名称。
    pub fn device_driver_at(index: usize) -> Option<&'static str> {
        if index >= DEVICE_COUNT.load(Ordering::Relaxed) {
            return None;
        }
        let list = DEVICES.lock();
        list.get(index)
            .and_then(|e| e.as_ref())
            .and_then(|entry| entry.driver_name)
    }

    /// 获取指定索引设备当前绑定驱动的竞标得分。
    pub fn device_driver_score_at(index: usize) -> u8 {
        if index >= DEVICE_COUNT.load(Ordering::Relaxed) {
            return 0;
        }
        let list = DEVICES.lock();
        list.get(index)
            .and_then(|e| e.as_ref())
            .map(|entry| entry.driver_score)
            .unwrap_or(0)
    }

    fn ensure_registered() {
        if REGISTERED.swap(true, Ordering::Relaxed) {
            return;
        }
        crate::platform::serial::register_serial_driver();
        crate::platform::keyboard::register_keyboard_driver();
        crate::platform::cmos::register_cmos_driver();
        crate::platform::pseudo::register_pseudo_driver();
        crate::platform::ata_pio::register_ata_driver();
        crate::platform::ramdisk::register_ramdisk_driver();
        crate::pci::register_pci_bus_driver();
        crate::pci_drivers::register_pci_class_drivers();
    }

    /// 触发指定生命周期阶段的所有驱动初始化。
    pub fn init_stage(stage: DriverStage) {
        Self::ensure_registered();
        let count = DRIVER_COUNT.load(Ordering::Relaxed);
        let list = DRIVERS.lock();
        let hub = DriverHub;
        for entry in list.iter().take(count) {
            if entry.stage == stage {
                entry.init(&hub);
                info!("[driver_hub] init stage={:?} driver={}", stage, entry.name());
            }
        }
    }

    /// 执行多驱动竞标打分与最高分择优绑定，支持故障自动降级回退（M8.1 & M8.2 核心仲裁引擎）。
    pub fn arbitrate_and_attach_device(dev_idx: usize) -> bool {
        let info = {
            let devices = DEVICES.lock();
            match devices.get(dev_idx).and_then(|e| e.as_ref()) {
                Some(entry) => entry.info,
                None => return false,
            }
        };

        let drv_count = DRIVER_COUNT.load(Ordering::Relaxed);
        let hub = DriverHub;

        // 1. 收集所有驱动对该设备的竞标打分 (score, driver_entry)
        let mut bids: [Option<(u8, DriverEntry)>; MAX_DRIVERS] = [None; MAX_DRIVERS];
        let mut bid_len = 0usize;

        {
            let drivers = DRIVERS.lock();
            for drv in drivers.iter().take(drv_count) {
                let score = drv.score_probe(&hub, &info);
                if score > 0 {
                    bids[bid_len] = Some((score, *drv));
                    bid_len += 1;
                }
            }
        }

        if bid_len == 0 {
            return false;
        }

        // 2. 按竞标分数从高到低排序 (降序)
        for i in 0..bid_len {
            for j in (i + 1)..bid_len {
                let score_i = bids[i].map(|b| b.0).unwrap_or(0);
                let score_j = bids[j].map(|b| b.0).unwrap_or(0);
                if score_j > score_i {
                    bids.swap(i, j);
                }
            }
        }

        // 3. 从最高分驱动开始尝试 attach，若失败则原地降级回退到次高分驱动（M8.2 故障隔离与 Fallback）
        for (score, drv) in bids.iter().take(bid_len).flatten() {
            info!(
                "[driver_hub] bidding: device={} evaluating candidate driver={} (score={})",
                info.name, drv.name, score
            );
            match drv.attach(&hub, &info) {
                Ok(()) => {
                    info!(
                        "[driver_hub] arbitrated winner: attached driver={} (score={}) to device={}",
                        drv.name, score, info.name
                    );
                    let mut devices = DEVICES.lock();
                    if let Some(entry) = devices.get_mut(dev_idx).and_then(|e| e.as_mut()) {
                        entry.driver_name = Some(drv.name);
                        entry.driver_score = *score;
                    }
                    return true;
                }
                Err(()) => {
                    warn!(
                        "[driver_hub] fallback triggered: driver={} failed attach to device={}, falling back to next bidder",
                        drv.name, info.name
                    );
                }
            }
        }

        false
    }

    /// 遍历所有未绑定的设备，自动运行智能竞标仲裁与绑定。
    pub fn attach_all() {
        let dev_count = DEVICE_COUNT.load(Ordering::Relaxed);
        for idx in 0..dev_count {
            let is_unbound = {
                let devices = DEVICES.lock();
                devices.get(idx).and_then(|e| e.as_ref()).map(|e| e.driver_name.is_none()).unwrap_or(false)
            };
            if is_unbound {
                Self::arbitrate_and_attach_device(idx);
            }
        }
    }

    /// 极早阶段初始化（Early Serial & Timer）。
    pub fn init_early() {
        Self::init_stage(DriverStage::Early);
    }

    /// 核心阶段初始化（Keyboard, CMOS RTC, Pseudo）。
    pub fn init_core() {
        Self::init_stage(DriverStage::Core);
    }

    /// 外设探测与自动绑定阶段（PCI Scan, ATA, PCI Drivers）。
    pub fn init_devices() {
        Self::init_stage(DriverStage::Devices);
        Self::attach_all();
    }

    /// 后置阶段初始化（Ramdisk, Services）。
    pub fn init_late() {
        Self::init_stage(DriverStage::Late);
        Self::attach_all();
    }
}
