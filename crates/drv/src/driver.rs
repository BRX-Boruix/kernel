//! 驱动生命周期抽象（`Driver` trait）。

use crate::device::Device;
use crate::id::DeviceId;

/// 驱动操作结果的错误类型（统一错误码，ADR-010）。
pub type DrvResult = Result<(), klib::error::Error>;

/// 设备驱动：声明支持哪些设备，并实现其生命周期。
///
/// 生命周期阶段（由框架/总线探测驱动）：
/// 1. [`Driver::matches`]：id 匹配（注册表遍历用，快路径）；
/// 2. [`Driver::probe`]：探测——确认设备确实存在/可访问（可跳过/留空）；
/// 3. [`Driver::init`]：初始化——分配资源、注册中断等；成功即绑定；
/// 4. [`Driver::idle`]：周期轮询（可选，如轮询式设备、后台维护）；
/// 5. [`Driver::shutdown`]：关闭/卸载（预留动态卸载）。
///
/// 静态驱动通常是零大小结构体 + 内部原子状态，因此方法均取 `&self`
/// （与 `klib::console::Console` 风格一致），保证注册表可安全共享。
pub trait Driver: Send + Sync {
    /// 驱动名（调试/日志用）。
    fn name(&self) -> &'static str;

    /// 该驱动是否支持指定设备（id 匹配）。
    fn matches(&self, id: &DeviceId) -> bool;

    /// 探测设备是否真实存在/可用。默认认为匹配即存在（静态注册的设备
    /// 通常已经确认存在）；需要读硬件确认的驱动可覆盖此方法。
    fn probe(&self, _dev: &dyn Device) -> DrvResult {
        Ok(())
    }

    /// 初始化并绑定设备。返回错误表示绑定失败（驱动继续尝试下一个匹配）。
    fn init(&self, dev: &dyn Device) -> DrvResult;

    /// 周期轮询（默认空操作；由 [`crate::probe::idle_all`] 周期调用）。
    fn idle(&self, _dev: &dyn Device) {}

    /// 关闭/卸载设备（预留动态卸载；默认空操作）。
    fn shutdown(&self, _dev: &dyn Device) {}
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::Device;
    use crate::id::{BusType, DeviceClass, DeviceId};

    struct DummyDevice;

    impl Device for DummyDevice {
        fn name(&self) -> &'static str {
            "dummy"
        }
        fn id(&self) -> DeviceId {
            DeviceId::system(DeviceClass::Generic, 0)
        }
    }

    struct DummyDriver;

    impl Driver for DummyDriver {
        fn name(&self) -> &'static str {
            "dummy"
        }
        fn matches(&self, id: &DeviceId) -> bool {
            id.bus == BusType::System
        }
        fn init(&self, _dev: &dyn Device) -> DrvResult {
            Ok(())
        }
    }

    #[test]
    fn driver_defaults() {
        let d = DummyDriver;
        let dev = DummyDevice;
        // probe/idle/shutdown 有默认实现，不 panic 即可。
        assert_eq!(d.probe(&dev), Ok(()));
        d.idle(&dev);
        d.shutdown(&dev);
    }

    #[test]
    fn driver_matches() {
        let d = DummyDriver;
        let dev = DummyDevice;
        assert!(d.matches(&dev.id()));
        assert!(!d.matches(&DeviceId::pci(0x8086, 0x1234, 0)));
    }
}
