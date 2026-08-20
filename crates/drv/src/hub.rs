//! 统一驱动中枢引擎（DriverHub Central Registry & Lifecycle Engine）。
//!
//! 提供线程安全的驱动与设备集中注册表、4 阶段严格生命周期触发以及自动 `attach_all` 探测机制。

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Mutex;
use klib::info;

use crate::device::{BusType, DeviceInfo, DeviceOps};
use crate::driver::{Driver, DriverEntry, DriverStage};

pub const MAX_DRIVERS: usize = 32;
pub const MAX_DEVICES: usize = 64;

#[derive(Clone, Copy)]
pub struct DeviceEntry {
    pub info: DeviceInfo,
    pub dev: Option<&'static dyn DeviceOps>,
    pub driver_name: Option<&'static str>,
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
            attach: None,
        };
    }

    /// 注册一个带 probe/attach 动态设备匹配能力的驱动。
    pub fn register_driver_ops(
        name: &'static str,
        stage: DriverStage,
        init: fn(&DriverHub),
        probe: Option<fn(&DriverHub, &DeviceInfo) -> bool>,
        attach: Option<fn(&DriverHub, &DeviceInfo)>,
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

    /// 触发指定生命周期阶段的所有驱动初始化。
    pub fn init_stage(stage: DriverStage) {
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

    /// 遍历所有未绑定的设备，自动运行所有注册驱动的 `probe` 并执行 `attach` 绑定。
    pub fn attach_all() {
        let dev_count = DEVICE_COUNT.load(Ordering::Relaxed);
        let drv_count = DRIVER_COUNT.load(Ordering::Relaxed);
        let hub = DriverHub;
        for idx in 0..dev_count {
            let info = {
                let devices = DEVICES.lock();
                match devices.get(idx).and_then(|e| e.as_ref()) {
                    Some(entry) => entry.info,
                    None => continue,
                }
            };

            let mut attached: Option<&'static str> = None;
            let drivers = DRIVERS.lock();
            for drv in drivers.iter().take(drv_count) {
                if drv.probe(&hub, &info) {
                    if drv.attach.is_some() {
                        drv.attach(&hub, &info);
                        attached = Some(drv.name);
                        info!(
                            "[driver_hub] attached driver={} to device={}",
                            drv.name, info.name
                        );
                    }
                    break;
                }
            }
            drop(drivers);

            if let Some(name) = attached {
                let mut devices = DEVICES.lock();
                if let Some(entry) = devices.get_mut(idx).and_then(|e| e.as_mut()) {
                    entry.driver_name = Some(name);
                }
            }
        }
    }

    /// 极早阶段初始化（Early Serial & Timer）。
    pub fn init_early() {
        Self::init_stage(DriverStage::Early);
    }

    /// 核心阶段初始化（Keyboard & Platform Controllers）。
    pub fn init_core() {
        Self::init_stage(DriverStage::Core);
    }

    /// 外设探测阶段初始化（PCI Bus Scan & attach_all）。
    pub fn init_devices() {
        Self::init_stage(DriverStage::Devices);
        Self::attach_all();
    }

    /// 后置阶段初始化（Ramdisk & Virtual Devices）。
    pub fn init_late() {
        Self::init_stage(DriverStage::Late);
    }

    /// 全阶段按序执行（测试与宿主运行用）。
    pub fn init_all() {
        Self::init_early();
        Self::init_core();
        Self::init_devices();
        Self::init_late();
    }
}
