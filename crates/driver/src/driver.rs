//! 统一驱动生命周期抽象与四阶段调度定义（Driver / DriverStage / Bidding / Hotplug Detach）。

use crate::device::DeviceInfo;
use crate::hub::{DriverHub, EXPLICIT_BIND_SCORE};

/// 驱动四阶段确定性启动时序（ADR-008 核心哲学）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DriverStage {
    /// 极早阶段（无堆内存、无中断）：Early 串口与基础计时器
    Early = 0,
    /// 核心阶段（堆已就绪、中断已启用）：PS/2 键盘控制器、CMOS RTC 时钟、伪设备
    Core = 1,
    /// 外设探测阶段：PCI 总线扫描、自动 probe/attach 绑定块设备与网卡
    Devices = 2,
    /// 后置阶段：系统服务就绪、终端虚拟设备、Ramdisk 与交互通道
    Late = 3,
}

/// 统一驱动抽象：声明阶段、初始化钩子与多驱动竞标/仲裁/绑定与热解绑机制（M9.2）。
pub trait Driver: Send + Sync {
    /// 驱动名（调试与 DevFS 挂载用）。
    fn name(&self) -> &'static str;

    /// 所属的启动生命周期阶段。
    fn stage(&self) -> DriverStage;

    /// 阶段驱动初始化钩子。
    fn init(&self, hub: &DriverHub);

    /// 设备匹配探测（返回 true 表示该驱动支持并能够接管该硬件）。
    fn probe(&self, _hub: &DriverHub, _dev: &DeviceInfo) -> bool {
        false
    }

    /// 驱动竞标打分（0~100 分制，M8.1）。
    ///
    /// 分数语义（ADR-022 §1，DM6 现实描述）：分数是**类匹配优先级常量**——
    /// 0 表示不支持；非零表示该驱动能作为该设备的候选参与仲裁。当前生态
    /// 每个设备类恰有一个投标者（`drivers/pci_classes.rs`），厂商专用行
    /// （如 0x8086:0x100E）仅作预留区分度，不代表存在另一条已实现的优化
    /// 路径；多候选降级回退目前只有测试构造场景。文档不得暗示生产环境
    /// 存在多档竞争生态。
    fn score_probe(&self, hub: &DriverHub, dev: &DeviceInfo) -> u8 {
        // S13：默认通用探测分单一来源，与 hub 显式绑定档位共用同一常量。
        if self.probe(hub, dev) { EXPLICIT_BIND_SCORE } else { 0 }
    }

    /// 候选胜出后的绑定确认。
    ///
    /// 返回 `Ok(())` 表示接受绑定记录。注意（ADR-022 §1）：Ok 只代表
    /// **候选登记成功**，是否真实接管硬件由 [`DriverEntry::controls_hardware`]
    /// 声明——未实现硬件控制的驱动（如 pci_classes 三候选）在此只完成
    /// 登记，不做任何硬件触碰，DevFS 以 candidate 前缀如实呈现。
    /// Err(()) 触发仲裁降级回退到次高分候选。
    fn attach(&self, _hub: &DriverHub, _dev: &DeviceInfo) -> Result<(), ()> {
        Ok(())
    }

    /// 硬件拔除或热重载时安全解绑释放驱动资源（M9.2）。
    fn detach(&self, _hub: &DriverHub, _dev: &DeviceInfo) -> Result<(), ()> {
        Ok(())
    }
}

/// 注册表内部紧凑驱动条目。
#[derive(Clone, Copy)]
pub struct DriverEntry {
    pub name: &'static str,
    pub stage: DriverStage,
    pub init: fn(&DriverHub),
    pub probe: Option<fn(&DriverHub, &DeviceInfo) -> bool>,
    pub score_probe: Option<fn(&DriverHub, &DeviceInfo) -> u8>,
    pub attach: Option<fn(&DriverHub, &DeviceInfo) -> Result<(), ()>>,
    pub detach: Option<fn(&DriverHub, &DeviceInfo) -> Result<(), ()>>,
    /// 该驱动 attach 成功后是否**真实接管硬件**（BAR 映射/中断注册/设备
    /// 状态创建，ADR-022 §1）。`false` = 候选登记专用（candidate-only）：
    /// 仲裁可胜出、注册表留名记分，但 DevFS 以 `candidate:` 前缀如实呈现，
    /// 日志不使用 "attached" 措辞。未实现硬件控制的驱动必须如实声明 false。
    pub controls_hardware: bool,
}

fn noop(_hub: &DriverHub) {}

impl DriverEntry {
    pub const EMPTY: DriverEntry = DriverEntry {
        name: "",
        stage: DriverStage::Late,
        init: noop,
        probe: None,
        score_probe: None,
        attach: None,
        detach: None,
        controls_hardware: false,
    };
}

impl Driver for DriverEntry {
    fn name(&self) -> &'static str {
        self.name
    }

    fn stage(&self) -> DriverStage {
        self.stage
    }

    fn init(&self, hub: &DriverHub) {
        (self.init)(hub);
    }

    fn probe(&self, hub: &DriverHub, dev: &DeviceInfo) -> bool {
        if let Some(score_fn) = self.score_probe {
            score_fn(hub, dev) > 0
        } else if let Some(probe_fn) = self.probe {
            probe_fn(hub, dev)
        } else {
            false
        }
    }

    fn score_probe(&self, hub: &DriverHub, dev: &DeviceInfo) -> u8 {
        if let Some(score_fn) = self.score_probe {
            score_fn(hub, dev)
        } else if let Some(probe_fn) = self.probe {
            if probe_fn(hub, dev) { 50 } else { 0 }
        } else {
            0
        }
    }

    fn attach(&self, hub: &DriverHub, dev: &DeviceInfo) -> Result<(), ()> {
        if let Some(attach_fn) = self.attach {
            attach_fn(hub, dev)
        } else {
            Ok(())
        }
    }

    fn detach(&self, hub: &DriverHub, dev: &DeviceInfo) -> Result<(), ()> {
        if let Some(detach_fn) = self.detach {
            detach_fn(hub, dev)
        } else {
            Ok(())
        }
    }
}
