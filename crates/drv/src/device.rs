//! 通用设备抽象（`Device` trait）。

use crate::id::DeviceId;

/// 通用设备：框架中一个"被发现、可被驱动绑定"的硬件实例。
///
/// 设备通常是**静态注册**的（静态链接阶段就存在），也可以是未来模块
/// 动态发现后注册（`register_device` 接受 `&'static`，模块须保证生命周期）。
pub trait Device: Send + Sync {
    /// 设备名（调试/日志用）。
    fn name(&self) -> &'static str;

    /// 设备 id（驱动匹配用）。
    fn id(&self) -> DeviceId;
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{BusType, DeviceClass};

    struct DummyDevice;

    impl Device for DummyDevice {
        fn name(&self) -> &'static str {
            "dummy"
        }
        fn id(&self) -> DeviceId {
            DeviceId::system(DeviceClass::Generic, 0)
        }
    }

    #[test]
    fn device_trait_basic() {
        let d = DummyDevice;
        assert_eq!(d.name(), "dummy");
        assert_eq!(d.id().bus, BusType::System);
    }
}
