//! 统一驱动中枢引擎（DriverHub Central Registry & Lifecycle Engine）。
//!
//! 提供线程安全的驱动与设备集中注册表、4 阶段严格生命周期触发、类匹配候选
//! 仲裁与热插拔/热重载支持（M8 ~ M9）。
//!
//! 契约要点（ADR-022）：
//! - **稠密不变量**（DA4）：设备表 `[0..DEVICE_COUNT)` 全稠密，拔除走
//!   swap-remove 压缩；`0..device_count()` 枚举永远完整覆盖全部设备。
//! - **诚实容量边界**（DM1）：注册族返回 `Result`，表满报 `NoSpace`，
//!   计数器只在条目写入成功后推进——计数即真值。
//! - **候选语义**（DR1a）：竞标胜出 ≠ 硬件接管。是否真实控制硬件由
//!   [`DriverEntry::controls_hardware`] 声明，DevFS 按 candidate 前缀呈现。

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering::{Acquire, AcqRel, Release}};
use klib::error::Error;
use klib::{info, warn};
use spin::Mutex;

use crate::device::{BusType, Device, DeviceInfo};
use crate::driver::{Driver, DriverEntry, DriverStage};
use crate::event::{DeviceEvent, publish_event};

pub const MAX_DRIVERS: usize = 32;
pub const MAX_DEVICES: usize = 64;

/// 对块设备做缓存穿透探测读的结果（`DriverHub::probe_io_device`）。
///
/// - [`Alive`](ProbeStatus::Alive)：探测读成功，设备可服务。
/// - [`Gone`](ProbeStatus::Gone)：探测读失败（真实设备拔除/后端移除），
///   驱动已在 `read_at` 内部触发 `DeviceDeparted`。
/// - [`NotFound`](ProbeStatus::NotFound)：设备表无此名或实例为 None。
/// - [`NotIo`](ProbeStatus::NotIo)：设备存在但不是 IO 设备，无可探测。
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
/// 分数取标准类驱动档位（ADR-022 §1 的分数语义），不是仲裁产物。
/// S13：单一来源——`driver.rs` 的 `score_probe` 默认通用探测分也引用此值，
/// 避免两处散落的 50 漂移。
pub(crate) const EXPLICIT_BIND_SCORE: u8 = 50;

#[derive(Clone, Copy)]
pub struct DeviceEntry {
    pub info: DeviceInfo,
    /// 设备实例。`&'static dyn Device` 容纳所有分类：IO 设备实现
    /// `DeviceOps`（=Device+IoDevice），显示等非 IO 设备仅实现 [`Device`]
    /// 并经 [`Device::as_display`] 观测。
    pub dev: Option<&'static dyn Device>,
    /// 绑定记录：竞标胜出的候选名，或注册时显式声明的接管驱动名。
    pub driver_name: Option<&'static str>,
    pub driver_score: u8,
    /// 绑定是否代表**真实硬件接管**（ADR-022 §1）。`false` = 候选登记
    /// （candidate-only），DevFS 以 `candidate:` 前缀呈现。
    pub driver_controls_hardware: bool,
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
    ///
    /// 表满返回 [`Error::NoSpace`]（DM1：拒绝必须可见，计数器不虚增）。
    /// 本入口无 attach 司槽，条目的 `controls_hardware` 恒为 true（init 即
    /// 全部工作），该值不参与任何决策路径。
    pub fn register_driver(name: &'static str, stage: DriverStage, init: fn(&DriverHub)) -> Result<(), Error> {
        let mut list = DRIVERS.lock();
        let idx = DRIVER_COUNT.load(Acquire);
        if idx >= MAX_DRIVERS {
            drop(list);
            warn!(
                "[driver_hub] driver table full ({}); registration of '{}' rejected",
                MAX_DRIVERS, name
            );
            return Err(Error::NoSpace);
        }
        list[idx] = DriverEntry {
            name,
            stage,
            init,
            probe: None,
            score_probe: None,
            attach: None,
            detach: None,
            controls_hardware: true,
        };
        DRIVER_COUNT.store(idx + 1, Release);
        Ok(())
    }

    /// 注册一个带 probe/attach 动态设备匹配能力的驱动。
    ///
    /// ADR-008 哲学五点名的未来 LKM 注册入口：静态链接阶段驱动同样经此
    /// 注册，动态模块加载落地时接口保持不变。表满返回 [`Error::NoSpace`]。
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
    /// `controls_hardware` 必须如实声明（ADR-022 §1）：attach 完成真实硬件
    /// 接管传 `true`；仅作候选登记（无 BAR 映射/中断/状态创建）传 `false`，
    /// DevFS 将以 `candidate:{name}(unimplemented)` 呈现其绑定。
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
        let idx = DRIVER_COUNT.load(Acquire);
        if idx >= MAX_DRIVERS {
            drop(list);
            warn!(
                "[driver_hub] driver table full ({}); registration of '{}' rejected",
                MAX_DRIVERS, name
            );
            return Err(Error::NoSpace);
        }
        list[idx] = DriverEntry {
            name,
            stage,
            init,
            probe,
            score_probe,
            attach,
            detach,
            controls_hardware,
        };
        DRIVER_COUNT.store(idx + 1, Release);
        Ok(())
    }

    /// 向中枢注册一个已发现的硬件设备实例，并向拓扑事件日志发布
    /// `DeviceArrived` 事件（M9.1）。
    ///
    /// `driver_name` 为 `Some` 时表示该设备由具名驱动在自身 init 中完成
    /// 真实初始化后登记（C15.1 论述原泛型入口 `register_device`/
    /// `register_device_bus` 已并入此处：持久化证据必须由携带完整元数据的
    /// 本入口显式声明，无法证明持久化的设备填 `volatile: true` 保守披露）。
    /// 表满返回 [`Error::NoSpace`]（DM1）。
    pub fn register_device_info(
        info: DeviceInfo,
        dev: Option<&'static dyn Device>,
        driver_name: Option<&'static str>,
    ) -> Result<(), Error> {
        let mut list = DEVICES.lock();
        let idx = DEVICE_COUNT.load(Acquire);
        if idx >= MAX_DEVICES {
            drop(list);
            warn!(
                "[driver_hub] device table full ({}); registration of '{}' rejected",
                MAX_DEVICES, info.name
            );
            return Err(Error::NoSpace);
        }
        list[idx] = Some(DeviceEntry {
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
        DEVICE_COUNT.store(idx + 1, Release);
        drop(list);
        // 发布拓扑接入事件
        publish_event(DeviceEvent::DeviceArrived(info));
        Ok(())
    }

    /// 动态拔除/下线一个硬件设备（Hotplug Out），安全解绑并发布
    /// `DeviceDeparted` 事件（M9.1 & M9.2）。
    ///
    /// 移除采用 **swap-remove 索引压缩**（ADR-022 §5 / DA4）：尾条目前移
    /// 补位，`[0..DEVICE_COUNT)` 保持全稠密——`0..device_count()` 枚举在
    /// 中部拔除后依然完整，尾部设备不再被静默跳过。
    pub fn unregister_device_by_name(name: &str) -> bool {
        let dev_count = DEVICE_COUNT.load(Acquire);
        let hub = DriverHub;

        for idx in 0..dev_count {
            let mut matched_info: Option<DeviceInfo> = None;
            let mut matched_drv_name: Option<&'static str> = None;
            let mut matched_controls_hw = false;

            {
                let devices = DEVICES.lock();
                if let Some(entry) = devices.get(idx).and_then(|e| e.as_ref()) {
                    if entry.info.name == name {
                        matched_info = Some(entry.info);
                        matched_drv_name = entry.driver_name;
                        matched_controls_hw = entry.driver_controls_hardware;
                    }
                }
            }

            if let Some(info) = matched_info {
                // 1. 如果已绑定驱动，先调用驱动的 detach 进行安全解绑
                if let Some(drv_name) = matched_drv_name {
                    let drv_count = DRIVER_COUNT.load(Acquire);
                    let drivers = DRIVERS.lock();
                    for drv in drivers.iter().take(drv_count) {
                        if drv.name == drv_name {
                            if let Err(()) = drv.detach(&hub, &info) {
                                warn!(
                                    "[driver_hub] detach driver={} failed on device={}",
                                    drv_name, info.name
                                );
                            }
                            if matched_controls_hw {
                                info!(
                                    "[driver_hub] detached driver={} from device={}",
                                    drv_name, info.name
                                );
                            } else {
                                info!(
                                    "[driver_hub] candidacy released: driver={} record removed from device={} (candidate-only)",
                                    drv_name, info.name
                                );
                            }
                            break;
                        }
                    }
                }

                // 2. 索引压缩移除（swap-remove，稠密不变量）
                {
                    let mut devices = DEVICES.lock();
                    // S21：TOCTOU 防护——detach 在锁外执行期间，其它线程可能
                    // 已并发注册/拔除设备，`idx` 与快照计数可能已失效。移除前
                    // 在锁内**复核**：idx 仍在计数范围内，且该槽位仍绑定同一
                    // 名字（并发竞争时名字匹配失败即放弃，不误删他设备）。
                    let last = DEVICE_COUNT.load(Acquire) - 1;
                    let still_ours = idx <= last
                        && devices
                            .get(idx)
                            .and_then(|e| e.as_ref())
                            .map(|e| e.info.name == name)
                            .unwrap_or(false);
                    if !still_ours {
                        continue;
                    }
                    if idx != last {
                        // 仅当被移除设备不是末位时才需尾条前移补位。若 idx == last，
                        // `devices[idx] = devices[last].take()` 是**自赋值**：先
                        // take() 取走末条目置 None，又写回同一槽位——设备实际未
                        // 被移除，计数却递减，谎报成功（S26/S09 回归：旧实现
                        // 当待移除设备恰为最后一个时设备残留、计数脱钩）。
                        devices[idx] = devices[last].take();
                    } else {
                        devices[idx] = None;
                    }
                    DEVICE_COUNT.store(last, Release);
                }

                // 3. 向事件日志广播拔除事件
                publish_event(DeviceEvent::DeviceDeparted(info));
                info!("[driver_hub] hotplug: device={} departed safely", name);
                return true;
            }
        }

        false
    }

    /// 对指定块设备做一次**轻量存活探测**（经 `IoDevice::probe_alive`，非阻塞、
    /// 只读状态不触发完整 I/O）。设备已消失时，驱动在 `probe_alive` 内部经
    /// `is_device_gone` + `notify_device_gone` 主动发布 `DeviceDeparted`
    /// （ADR-030 热插拔闭环）。用于 `volumed` 低频对账：对已挂卷做探测，把
    /// "拔除但无事件"的空闲卷兜底发现出来。
    ///
    /// **轻量性关键**：不使用 `read_at`（其同步 PIO 忙等最多轮询 20 万次
    /// `inb`，QEMU 下每次是一次 VM-exit，长时间内核态自旋会阻塞调度与键盘
    /// IRQ——本会话实测对账时输入积压）。`probe_alive` 只读几次 status，代价
    /// 可忽略，专供对账/心跳等低频存活性检查。
    pub fn probe_io_device(name: &str) -> ProbeStatus {
        let dev_count = DEVICE_COUNT.load(Acquire);
        // 拿设备实例做探测（保持短临界区：只读快照，探测在锁外执行）。
        let dev = {
            let devices = DEVICES.lock();
            let mut found: Option<&'static dyn Device> = None;
            for idx in 0..dev_count {
                if let Some(entry) = devices.get(idx).and_then(|e| e.as_ref()) {
                    if entry.info.name == name {
                        found = entry.dev;
                        break;
                    }
                }
            }
            found
        };
        let Some(dev) = dev else {
            // 无设备实例（纯元数据登记）或未找到：无从探测。
            return ProbeStatus::NotFound;
        };
        let Some(io) = dev.as_io() else {
            // 非 IO 设备（如显示/网络纯元数据）：不探测。
            return ProbeStatus::NotIo;
        };
        // 轻量存活探测：设备支持 probe_alive 则用之；否则回退到一次 read_at
        // （仅当设备无 probe 能力，如非块 IO 设备，此时 read_at 也快）。
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
        let dev_count = DEVICE_COUNT.load(Acquire);
        let hub = DriverHub;

        for idx in 0..dev_count {
            let mut target_info: Option<DeviceInfo> = None;
            let mut current_drv: Option<&'static str> = None;

            {
                let devices = DEVICES.lock();
                if let Some(entry) = devices.get(idx).and_then(|e| e.as_ref()) {
                    if entry.info.name == name {
                        target_info = Some(entry.info);
                        current_drv = entry.driver_name;
                    }
                }
            }

            if let Some(info) = target_info {
                // 1. Detach 解绑（候选条目的 detach 是纯记录操作，恒 Ok）
                if let Some(drv_name) = current_drv {
                    let drv_count = DRIVER_COUNT.load(Acquire);
                    let drivers = DRIVERS.lock();
                    for drv in drivers.iter().take(drv_count) {
                        if drv.name == drv_name {
                            let _ = drv.detach(&hub, &info);
                            break;
                        }
                    }
                }

                // 2. 重置绑定状态
                {
                    let mut devices = DEVICES.lock();
                    // S21：TOCTOU 防护——detach 在锁外执行后，复核该槽位仍
                    // 绑定同一设备再重置，避免并发竞争下误改他设备条目。
                    let still_ours = idx <= DEVICE_COUNT.load(Acquire)
                        && devices
                            .get(idx)
                            .and_then(|e| e.as_ref())
                            .map(|e| e.info.name == name)
                            .unwrap_or(false);
                    if !still_ours {
                        continue;
                    }
                    if let Some(entry) = devices.get_mut(idx).and_then(|e| e.as_mut()) {
                        entry.driver_name = None;
                        entry.driver_score = 0;
                        entry.driver_controls_hardware = false;
                    }
                }

                // 3. 重新候选仲裁与记录
                let attached = Self::arbitrate_and_attach_device(idx);
                info!(
                    "[driver_hub] hot-reload device={} result={}",
                    name, attached
                );
                return attached;
            }
        }

        false
    }

    /// 按设备名反查 PCI 位置（bus, device, function）。
    ///
    /// 遍历已注册设备，找到名称匹配且 `bus == BusType::Pci` 的条目，
    /// 从 `location` 字段解码出 `(bus, device, function)`。非 PCI 设备或
    /// 未知名称返回 `None`，绝不回退到固定设备。
    pub fn pci_location_of(name: &str) -> Option<(u8, u8, u8)> {
        let dev_count = DEVICE_COUNT.load(Acquire);
        let devices = DEVICES.lock();
        for entry in devices.iter().take(dev_count).flatten() {
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
    ///
    /// 不变量（ADR-022 §5）：拔除经 swap-remove 压缩，表中无洞；
    /// `0..device_count()` 与各 `*_at(index)` 访问器构成同一枚举契约。
    pub fn device_count() -> usize {
        DEVICE_COUNT.load(Acquire)
    }

    /// 指定名称的设备是否已注册（S08：供 UIO 认领等 name-based 入口校验
    /// 设备真实存在，杜绝注册"幽灵设备名"）。
    pub fn device_exists(name: &str) -> bool {
        let list = DEVICES.lock();
        list.iter()
            .take(DEVICE_COUNT.load(Acquire))
            .any(|e| e.as_ref().map(|entry| entry.info.name == name).unwrap_or(false))
    }

    /// 返回当前已注册的驱动总数（驱动表无移除通道，恒等于稠密长度）。
    pub fn driver_count() -> usize {
        DRIVER_COUNT.load(Acquire)
    }

    /// 获取指定索引的设备信息。
    pub fn device_info_at(index: usize) -> Option<DeviceInfo> {
        if index >= DEVICE_COUNT.load(Acquire) {
            return None;
        }
        let list = DEVICES.lock();
        list.get(index).and_then(|e| e.map(|entry| entry.info))
    }

    /// 测试诊断：直接检查原始槽位是否仍被设备占用（**不过滤** `DEVICE_COUNT`
    /// 稠密前缀）。
    ///
    /// 用途：验证 swap-remove 后**无残留**——移除末位设备后，槽位必须真正
    /// 清空（S26/S09 回归：旧实现在 `idx == last` 时自赋值，设备残留在
    /// 计数之后成为幽灵条目）。生产构建不编译本访问器（`kernel-tests` feature）。
    #[cfg(feature = "kernel-tests")]
    pub fn device_slot_occupied_raw(index: usize) -> bool {
        let list = DEVICES.lock();
        list.get(index).and_then(|e| e.as_ref()).is_some()
    }

    /// 获取指定索引的设备实例。
    pub fn device_at(index: usize) -> Option<&'static dyn Device> {
        if index >= DEVICE_COUNT.load(Acquire) {
            return None;
        }
        let list = DEVICES.lock();
        list.get(index).and_then(|e| e.and_then(|entry| entry.dev))
    }

    /// 获取指定索引设备绑定的驱动名称。
    pub fn device_driver_at(index: usize) -> Option<&'static str> {
        if index >= DEVICE_COUNT.load(Acquire) {
            return None;
        }
        let list = DEVICES.lock();
        list.get(index)
            .and_then(|e| e.as_ref())
            .and_then(|entry| entry.driver_name)
    }

    /// 获取指定索引设备当前绑定驱动的竞标得分。
    pub fn device_driver_score_at(index: usize) -> u8 {
        if index >= DEVICE_COUNT.load(Acquire) {
            return 0;
        }
        let list = DEVICES.lock();
        list.get(index)
            .and_then(|e| e.as_ref())
            .map(|entry| entry.driver_score)
            .unwrap_or(0)
    }

    /// 指定索引设备的绑定是否为**候选登记**（竞标胜出但驱动未实现硬件
    /// 接管，ADR-022 §1）。未绑定或越界返回 `false`——`false` 不代表
    /// 真实接管，呈现方必须先确认 [`Self::device_driver_at`] 非 None。
    pub fn device_driver_is_candidate(index: usize) -> bool {
        if index >= DEVICE_COUNT.load(Acquire) {
            return false;
        }
        let list = DEVICES.lock();
        list.get(index)
            .and_then(|e| e.as_ref())
            .map(|entry| entry.driver_name.is_some() && !entry.driver_controls_hardware)
            .unwrap_or(false)
    }

    fn ensure_registered() {
        if REGISTERED.swap(true, AcqRel) {
            return;
        }
        // DM1：内建驱动注册结果逐一显式处理——表满等失败必须留痕，
        // 静默丢弃不复存在。
        let registrations = [
            (
                "serial",
                crate::drivers::serial::register_serial_driver(),
            ),
            (
                "keyboard",
                crate::drivers::keyboard::register_keyboard_driver(),
            ),
            ("cmos", crate::drivers::cmos::register_cmos_driver()),
            ("pseudo", crate::drivers::pseudo::register_pseudo_driver()),
            ("ata_pio", crate::drivers::ata_pio::register_ata_driver()),
            (
                "ramdisk",
                crate::drivers::ramdisk::register_ramdisk_driver(),
            ),
            ("pci-bus", crate::drivers::pci_bus::register_pci_bus_driver()),
            (
                "pci-class-candidates",
                crate::drivers::pci_classes::register_pci_class_drivers(),
            ),
        ];
        for (name, outcome) in registrations {
            if let Err(e) = outcome {
                warn!(
                    "[driver_hub] builtin driver '{}' registration failed: {:?}",
                    name, e
                );
            }
        }
    }

    /// 触发指定生命周期阶段的所有驱动初始化。
    pub fn init_stage(stage: DriverStage) {
        Self::ensure_registered();
        let hub = DriverHub;
        // S21：不得持 DRIVERS 锁调用 driver.init——driver 的 init 可能回调
        // hub（注册设备/仲裁，取 DEVICES 甚至 DRIVERS 锁），持锁遍历时回调
        // 即重入死锁。改为**锁内收集**到期的 init 函数与名字，**锁外**逐一调用。
        let inits: alloc::vec::Vec<(fn(&DriverHub), &'static str)> = {
            let count = DRIVER_COUNT.load(Acquire);
            let list = DRIVERS.lock();
            list.iter()
                .take(count)
                .filter(|e| e.stage == stage)
                .map(|e| (e.init, e.name()))
                .collect()
        };
        for (init_fn, name) in inits {
            init_fn(&hub);
            info!(
                "[driver_hub] init stage={:?} driver={}",
                stage,
                name
            );
        }
    }

    /// 执行类匹配候选仲裁：收集全部非零打分候选，按分数降序择优记录，
    /// attach 失败自动降级回退次优（M8.1 & M8.2 仲裁引擎）。
    ///
    /// 胜出只意味着**绑定记录成立**；是否真实接管硬件由候选的
    /// `controls_hardware` 声明决定（ADR-022 §1），日志按此分支措辞。
    pub fn arbitrate_and_attach_device(dev_idx: usize) -> bool {
        let info = {
            let devices = DEVICES.lock();
            match devices.get(dev_idx).and_then(|e| e.as_ref()) {
                Some(entry) => entry.info,
                None => return false,
            }
        };

        let drv_count = DRIVER_COUNT.load(Acquire);
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

        // 3. 从最高分候选开始尝试 attach，若失败则原地降级回退到次高分候选（M8.2 故障隔离与 Fallback）
        for (score, drv) in bids.iter().take(bid_len).flatten() {
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
                    if let Some(entry) = devices.get_mut(dev_idx).and_then(|e| e.as_mut()) {
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
        let dev_count = DEVICE_COUNT.load(Acquire);
        for idx in 0..dev_count {
            let is_unbound = {
                let devices = DEVICES.lock();
                devices
                    .get(idx)
                    .and_then(|e| e.as_ref())
                    .map(|e| e.driver_name.is_none())
                    .unwrap_or(false)
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
