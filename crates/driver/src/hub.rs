//! 统一驱动中枢引擎（DriverHub Central Registry & Lifecycle Engine）。
//!
//! 提供线程安全的驱动与设备集中注册表、4 阶段严格生命周期触发、类匹配候选
//! 仲裁与热插拔/热重载支持（M8 ~ M9）。
//!
//! 契约要点（ADR-022 + 本改造：driver crate 的动态表重构）：
//! - 稠密不变量（DA4）：设备表 [0..len) 全稠密，拔除走 swap-remove 压缩；
//!   0..device_count() 枚举永远完整覆盖全部设备。
//! - 动态容量（去掉编译期硬顶）：驱动表/设备表由定长静态数组改为 Vec，
//!   注册时按需 try_reserve 扩容，不再有 MAX_DRIVERS=32 / MAX_DEVICES=64
//!   的上限；可随可用内核堆持续增长。
//! - 诚实边界（延续 DM1 精神）：唯一可能的失败是堆分配失败（try_reserve
//!   不成功 -> Error::OutOfMemory），len() 即真值——拒绝可见、计数无谎言。
//! - 候选语义（DR1a）：竞标胜出 != 硬件接管。是否真实控制硬件由
//!   DriverEntry::controls_hardware 声明，DevFS 按 candidate 前缀呈现。

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering::{AcqRel}};
use klib::error::Error;
use klib::{info, warn};
use spin::Mutex;

use crate::device::{BusType, Device, DeviceInfo};
use crate::driver::{Driver, DriverEntry, DriverStage};
use crate::event::{DeviceEvent, publish_event};

/// 对块设备做缓存穿透探测读的结果（DriverHub::probe_io_device）。
///
/// - Alive：探测读成功，设备可服务。
/// - Gone：探测读失败（真实设备拔除/后端移除），驱动已在内部触发 DeviceDeparted。
/// - NotFound：设备表无此名或实例为 None。
/// - NotIo：设备存在但不是 IO 设备，无可探测。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeStatus {
    Alive,
    Gone,
    NotFound,
    NotIo,
}

/// 显式带驱动名注册设备时的绑定分。
///
/// 该路径的驱动在注册前已在自己的 init 中完成真实初始化与接管
/// （ata_pio identify、键盘控制器就绪等），绑定关系先于竞标存在；
/// 分数取标准类驱动档位（ADR-022 分数语义），不是仲裁产物。
/// S13：单一来源——driver.rs 的 score_probe 默认通用探测分也引用此值。
pub(crate) const EXPLICIT_BIND_SCORE: u8 = 50;

#[derive(Clone, Copy)]
pub struct DeviceEntry {
    pub info: DeviceInfo,
    pub dev: Option<&'static dyn Device>,
    pub driver_name: Option<&'static str>,
    pub driver_score: u8,
    pub driver_controls_hardware: bool,
}

// 动态表：Vec（无编译期上限）。len() 即各自计数。
// 与旧 Mutex<[T; N]> 不同，元素稠密存储、无 Option 包装——Vec 天生稠密，
// swap_remove 天然压缩，去掉旧实现稠密前缀 + 尾条前移补位的手工编排。
static DRIVERS: Mutex<Vec<DriverEntry>> = Mutex::new(Vec::new());
static DEVICES: Mutex<Vec<DeviceEntry>> = Mutex::new(Vec::new());

static REGISTERED: AtomicBool = AtomicBool::new(false);

/// 驱动中枢全局控制柄。
pub struct DriverHub;

impl DriverHub {
    /// 注册一个基础阶段驱动。
    ///
    /// 动态表：push 前按需扩容；堆分配失败返回 Error::OutOfMemory
    /// （诚实边界，绝不 panic 于可预见的资源耗尽）。
    pub fn register_driver(name: &'static str, stage: DriverStage, init: fn(&DriverHub)) -> Result<(), Error> {
        let mut list = DRIVERS.lock();
        if list.try_reserve(1).is_err() {
            drop(list);
            warn!("[driver_hub] OOM: driver table cannot grow for '{}'", name);
            return Err(Error::OutOfMemory);
        }
        list.push(DriverEntry {
            name,
            stage,
            init,
            probe: None,
            score_probe: None,
            attach: None,
            detach: None,
            controls_hardware: true,
        });
        Ok(())
    }

    /// 注册一个带 probe/attach 动态设备匹配能力的驱动。
    ///
    /// ADR-008 哲学五点名的未来 LKM 注册入口：静态链接阶段驱动同样经此
    /// 注册，动态模块加载落地时接口保持不变。堆分配失败返回
    /// Error::OutOfMemory。
    pub fn register_driver_ops(
        name: &'static str,
        stage: DriverStage,
        init: fn(&DriverHub),
        probe: Option<fn(&DriverHub, &DeviceInfo) -> bool>,
        attach: Option<fn(&DriverHub, &DeviceInfo) -> Result<(), ()>>,
    ) -> Result<(), Error> {
        Self::register_driver_full(name, stage, init, None, probe, attach, None, true)
    }

    /// 注册一个全功能生命周期驱动（含候选打分、Attach 与 Detach 热插拔支持，M9.2）。
    ///
    /// controls_hardware 必须如实声明（ADR-022）：attach 完成真实硬件接管
    /// 传 true；仅作候选登记（无 BAR 映射/中断/状态创建）传 false，DevFS 将
    /// 以 candidate:{name}(unimplemented) 呈现其绑定。
    #[allow(clippy::too_many_arguments)]
    pub fn register_driver_full(
        name: &'static str,
        stage: DriverStage,
        init: fn(&DriverHub),
        score_probe: Option<fn(&DriverHub, &DeviceInfo) -> u8>,
        probe: Option<fn(&DriverHub, &DeviceInfo) -> bool>,
        attach: Option<fn(&DriverHub, &DeviceInfo) -> Result<(), ()>>,
        detach: Option<fn(&DriverHub, &DeviceInfo) -> Result<(), ()>>,
        controls_hardware: bool,
    ) -> Result<(), Error> {
        let mut list = DRIVERS.lock();
        if list.try_reserve(1).is_err() {
            drop(list);
            warn!("[driver_hub] OOM: driver table cannot grow for '{}'", name);
            return Err(Error::OutOfMemory);
        }
        list.push(DriverEntry {
            name,
            stage,
            init,
            probe,
            score_probe,
            attach,
            detach,
            controls_hardware,
        });
        Ok(())
    }

    /// 向中枢注册一个已发现的硬件设备实例，并向拓扑事件日志发布
    /// DeviceArrived 事件（M9.1）。
    ///
    /// driver_name 为 Some 时表示该设备由具名驱动在自身 init 中完成真实初始化
    /// 后登记（无法证明持久化的设备填 volatile: true 保守披露）。
    /// 动态表：堆分配失败返回 Error::OutOfMemory（DM1 精神）。
    pub fn register_device_info(
        info: DeviceInfo,
        dev: Option<&'static dyn Device>,
        driver_name: Option<&'static str>,
    ) -> Result<(), Error> {
        let mut list = DEVICES.lock();
        if list.try_reserve(1).is_err() {
            drop(list);
            warn!("[driver_hub] OOM: device table cannot grow for '{}'", info.name);
            return Err(Error::OutOfMemory);
        }
        list.push(DeviceEntry {
            info,
            dev,
            driver_name,
            driver_score: if driver_name.is_some() {
                EXPLICIT_BIND_SCORE
            } else {
                0
            },
            driver_controls_hardware: driver_name.is_some(),
        });
        drop(list);
        // 发布拓扑接入事件
        publish_event(DeviceEvent::DeviceArrived(info));
        Ok(())
    }

    /// 动态拔除/下线一个硬件设备（Hotplug Out），安全解绑并发布
    /// DeviceDeparted 事件（M9.1 & M9.2）。
    ///
    /// 移除采用 swap-remove 索引压缩（ADR-022 §5 / DA4）：被移除条目由末位
    /// 条目补位，[0..len) 保持全稠密——0..device_count() 枚举在中部拔除后
    /// 依然完整，尾部设备不再被静默跳过。
    pub fn unregister_device_by_name(name: &str) -> bool {
        let hub = DriverHub;

        // 1. 定位待移除设备；拿到元数据后，先在锁外调用其绑定驱动的 detach
        //    （detach 可能回调 hub，持锁执行即重入死锁）。
        let matched_info: Option<DeviceInfo> = {
            let devices = DEVICES.lock();
            devices.iter().find(|e| e.info.name == name).map(|e| e.info)
        };
        let Some(info) = matched_info else {
            return false;
        };

        // 2. 如果已绑定驱动，先调用驱动的 detach 进行安全解绑（锁外）。
        let matched_drv_name: Option<&'static str> = {
            let devices = DEVICES.lock();
            devices
                .iter()
                .find(|e| e.info.name == name)
                .and_then(|e| e.driver_name)
        };
        if let Some(drv_name) = matched_drv_name {
            let drv = {
                let drivers = DRIVERS.lock();
                drivers.iter().find(|d| d.name == drv_name).copied()
            };
            if let Some(drv) = drv {
                if let Err(()) = drv.detach(&hub, &info) {
                    warn!(
                        "[driver_hub] detach driver={} failed on device={}",
                        drv_name, info.name
                    );
                }
                if drv.controls_hardware {
                    info!("[driver_hub] detached driver={} from device={}", drv_name, info.name);
                } else {
                    info!(
                        "[driver_hub] candidacy released: driver={} record removed from device={} (candidate-only)",
                        drv_name, info.name
                    );
                }
            }
        }

        // 3. 锁内按名字复核并 swap-remove 压缩（S21 TOCTOU 防护：detach 在锁外
        //    执行期间其它线程可能已并发注册/拔除设备，故移除前在锁内复核名字
        //    仍存在——并发竞争下名字匹配失败即放弃，不误删他设备）。
        {
            let mut devices = DEVICES.lock();
            let Some(idx) = devices.iter().position(|e| e.info.name == name) else {
                // 已被并发路径移除：非失败，他人已完成。
                return true;
            };
            devices.swap_remove(idx);
        }

        // 4. 向事件日志广播拔除事件
        publish_event(DeviceEvent::DeviceDeparted(info));
        info!("[driver_hub] hotplug: device={} departed safely", name);
        true
    }

    /// 对指定块设备做一次轻量存活探测（经 IoDevice::probe_alive，非阻塞、
    /// 只读状态不触发完整 I/O）。设备已消失时，驱动在 probe_alive 内部经
    /// is_device_gone + notify_device_gone 主动发布 DeviceDeparted
    /// （ADR-030 热插拔闭环）。用于 volumed 低频对账。
    pub fn probe_io_device(name: &str) -> ProbeStatus {
        // 拿设备实例做探测（保持短临界区：只读快照，探测在锁外执行）。
        let dev = {
            let devices = DEVICES.lock();
            devices.iter().find(|e| e.info.name == name).and_then(|e| e.dev)
        };
        let Some(dev) = dev else {
            return ProbeStatus::NotFound;
        };
        let Some(io) = dev.as_io() else {
            return ProbeStatus::NotIo;
        };
        match io.probe_alive() {
            Some(true) => ProbeStatus::Alive,
            Some(false) => ProbeStatus::Gone,
            None => {
                let mut buf = [0u8; 512];
                if io.read_at(0, &mut buf) > 0 {
                    ProbeStatus::Alive
                } else {
                    ProbeStatus::Gone
                }
            }
        }
    }

    /// 驱动在线热重载（Live Reloading）：安全解绑当前绑定 -> 重新执行候选
    /// 仲裁并记录胜者（M9.2）。
    pub fn reload_device_driver(name: &str) -> bool {
        let hub = DriverHub;

        let target_info: Option<DeviceInfo> = {
            let devices = DEVICES.lock();
            devices.iter().find(|e| e.info.name == name).map(|e| e.info)
        };
        let Some(info) = target_info else {
            return false;
        };

        // 1. Detach 解绑（候选条目的 detach 是纯记录操作，恒 Ok）
        {
            let drv_name = {
                let devices = DEVICES.lock();
                devices.iter().find(|e| e.info.name == name).and_then(|e| e.driver_name)
            };
            if let Some(drv_name) = drv_name {
                let drv = {
                    let drivers = DRIVERS.lock();
                    drivers.iter().find(|d| d.name == drv_name).copied()
                };
                if let Some(drv) = drv {
                    let _ = drv.detach(&hub, &info);
                }
            }
        }

        // 2. 复位绑定状态（锁内复核，S21 TOCTOU）
        {
            let mut devices = DEVICES.lock();
            if let Some(entry) = devices.iter_mut().find(|e| e.info.name == name) {
                entry.driver_name = None;
                entry.driver_score = 0;
                entry.driver_controls_hardware = false;
            }
        }

        // 3. 重新候选仲裁与记录
        let attached = Self::arbitrate_and_attach_device(info.name);
        info!("[driver_hub] hot-reload device={} result={}", name, attached);
        attached
    }

    /// 按设备名反查 PCI 位置（bus, device, function）。
    ///
    /// 遍历已注册设备，找到名称匹配且 bus == BusType::Pci 的条目，从 location
    /// 字段解码出 (bus, device, function)。非 PCI 设备或未知名称返回 None。
    pub fn pci_location_of(name: &str) -> Option<(u8, u8, u8)> {
        let devices = DEVICES.lock();
        for entry in devices.iter() {
            if entry.info.bus == BusType::Pci && entry.info.name == name {
                let loc = entry.info.location;
                let bus = ((loc >> 16) & 0xFF) as u8;
                let device = ((loc >> 8) & 0xFF) as u8;
                let function = (loc & 0xFF) as u8;
                return Some((bus, device, function));
            }
        }
        None
    }

    /// 当前已注册的有效设备总数（= 注册表稠密前缀长度）。
    pub fn device_count() -> usize {
        DEVICES.lock().len()
    }

    /// 指定名称的设备是否已注册（S08：供 UIO 认领等 name-based 入口校验）。
    pub fn device_exists(name: &str) -> bool {
        DEVICES.lock().iter().any(|e| e.info.name == name)
    }

    /// 按设备名取其中断线（PCI 配置空间 0x3C 的 Interrupt Line）。
    ///
    /// 供设备中断投递（IRQ → 认领该设备的用户态驱动）归属判定使用。
    /// 无中断线/平台/虚拟设备返回 0（0 语义 = 无 PCI 中断，不参与投递）。
    pub fn device_irq_of(name: &str) -> u8 {
        DEVICES.lock()
            .iter()
            .find(|e| e.info.name == name)
            .map(|e| e.info.irq_line)
            .unwrap_or(0)
    }

    /// 返回当前已注册的驱动总数（驱动表无移除通道）。
    pub fn driver_count() -> usize {
        DRIVERS.lock().len()
    }

    /// 获取指定索引的设备信息。
    pub fn device_info_at(index: usize) -> Option<DeviceInfo> {
        DEVICES.lock().get(index).map(|e| e.info)
    }

    /// 测试诊断：检查索引槽位是否仍被设备占用。
    ///
    /// 动态表全稠密无洞，等价于 index < device_count()；越界（含被移除后）
    /// 返回 false。仅供测试核对计数回落/不越界。
    #[cfg(feature = "kernel-tests")]
    pub fn device_slot_occupied_raw(index: usize) -> bool {
        DEVICES.lock().get(index).is_some()
    }

    /// 获取指定索引的设备实例。
    pub fn device_at(index: usize) -> Option<&'static dyn Device> {
        DEVICES.lock().get(index).and_then(|e| e.dev)
    }

    /// 获取指定索引设备绑定的驱动名称。
    pub fn device_driver_at(index: usize) -> Option<&'static str> {
        DEVICES.lock().get(index).and_then(|e| e.driver_name)
    }

    /// 获取指定索引设备当前绑定驱动的竞标得分。
    pub fn device_driver_score_at(index: usize) -> u8 {
        DEVICES.lock().get(index).map(|e| e.driver_score).unwrap_or(0)
    }

    /// 指定索引设备的绑定是否为候选登记（ADR-022）。
    pub fn device_driver_is_candidate(index: usize) -> bool {
        DEVICES.lock()
            .get(index)
            .map(|e| e.driver_name.is_some() && !e.driver_controls_hardware)
            .unwrap_or(false)
    }

    fn ensure_registered() {
        if REGISTERED.swap(true, AcqRel) {
            return;
        }
        // DM1：内建驱动注册结果逐一显式处理——堆分配失败等必须留痕。
        let registrations = [
            ("serial", crate::drivers::serial::register_serial_driver()),
            ("keyboard", crate::drivers::keyboard::register_keyboard_driver()),
            ("cmos", crate::drivers::cmos::register_cmos_driver()),
            ("pseudo", crate::drivers::pseudo::register_pseudo_driver()),
            ("ata_pio", crate::drivers::ata_pio::register_ata_driver()),
            ("ramdisk", crate::drivers::ramdisk::register_ramdisk_driver()),
            ("pci-bus", crate::drivers::pci_bus::register_pci_bus_driver()),
            (
                "pci-class-candidates",
                crate::drivers::pci_classes::register_pci_class_drivers(),
            ),
        ];
        for (name, outcome) in registrations {
            if let Err(e) = outcome {
                warn!("[driver_hub] builtin driver '{}' registration failed: {:?}", name, e);
            }
        }
    }

    /// 触发指定生命周期阶段的所有驱动初始化。
    pub fn init_stage(stage: DriverStage) {
        Self::ensure_registered();
        let hub = DriverHub;
        // S21：不得持 DRIVERS 锁调用 driver.init——driver 的 init 可能回调 hub
        // （注册设备/仲裁，取 DEVICES 甚至 DRIVERS 锁），持锁遍历时回调即重入
        // 死锁。改为锁内收集到期的 init 函数与名字，锁外逐一调用。
        let inits: alloc::vec::Vec<(fn(&DriverHub), &'static str)> = {
            let list = DRIVERS.lock();
            list.iter().filter(|e| e.stage == stage).map(|e| (e.init, e.name())).collect()
        };
        for (init_fn, name) in inits {
            init_fn(&hub);
            info!("[driver_hub] init stage={:?} driver={}", stage, name);
        }
    }

    /// 执行类匹配候选仲裁：收集全部非零打分候选，按分数降序择优记录，
    /// attach 失败自动降级回退次优（M8.1 & M8.2 仲裁引擎）。
    ///
    /// 胜出只意味着绑定记录成立；是否真实接管硬件由候选的 controls_hardware
    /// 声明决定（ADR-022），日志按此分支措辞。
    ///
    /// 入参为被仲裁设备的注册名（设备身份）。动态表 + 并发下索引可因
    /// swap-remove 位移，故仲裁以名字定位，不再以裸索引定位。
    pub fn arbitrate_and_attach_device(dev_name: &str) -> bool {
        let info = {
            let devices = DEVICES.lock();
            match devices.iter().find(|e| e.info.name == dev_name) {
                Some(entry) => entry.info,
                None => return false,
            }
        };

        let hub = DriverHub;

        // 1. 收集所有驱动对该设备的竞标打分 (score, driver_entry)
        let mut bids: alloc::vec::Vec<(u8, DriverEntry)> = alloc::vec::Vec::new();
        {
            let drivers = DRIVERS.lock();
            for drv in drivers.iter() {
                let score = drv.score_probe(&hub, &info);
                if score > 0 {
                    bids.push((score, *drv));
                }
            }
        }

        if bids.is_empty() {
            return false;
        }

        // 2. 按竞标分数从高到低排序 (降序)
        bids.sort_by(|a, b| b.0.cmp(&a.0));

        // 3. 从最高分候选开始尝试 attach，失败则降级回退次优（M8.2）
        for (score, drv) in bids.iter() {
            info!(
                "[driver_hub] bidding: device={} evaluating candidate driver={} (score={})",
                info.name, drv.name, score
            );
            match drv.attach(&hub, &info) {
                Ok(()) => {
                    if drv.controls_hardware {
                        info!(
                            "[driver_hub] arbitrated winner: attached driver={} (score={}) to device={}",
                            drv.name, score, info.name
                        );
                    } else {
                        info!(
                            "[driver_hub] candidate selected: driver={} (score={}) recorded for device={} (no hardware control implemented)",
                            drv.name, score, info.name
                        );
                    }
                    let mut devices = DEVICES.lock();
                    if let Some(entry) = devices.iter_mut().find(|e| e.info.name == info.name) {
                        entry.driver_name = Some(drv.name);
                        entry.driver_score = *score;
                        entry.driver_controls_hardware = drv.controls_hardware;
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

    /// 遍历所有未绑定的设备，自动运行候选仲裁并记录胜者。
    pub fn attach_all() {
        // 快照未绑定设备名（仲裁以名字定位；避免持锁遍历 + 锁外 attach 重入）。
        let names: alloc::vec::Vec<&'static str> = {
            let devices = DEVICES.lock();
            devices.iter().filter(|e| e.driver_name.is_none()).map(|e| e.info.name).collect()
        };
        for name in names {
            Self::arbitrate_and_attach_device(name);
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

    /// 外设探测与候选仲裁阶段（PCI Scan, ATA, PCI Class Candidates）。
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
