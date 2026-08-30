//! 设备与驱动框架统一中枢（ADR-008 核心）。
//!
//! 提供基于 ADR-008 驱动中枢哲学的四阶段生命周期、自动总线探测与统一设备分类标准。
//!
//! 测试载体事实（ADR-022 §9 / drv1 DDX1）：本 crate 依赖 arch-x86_64，其
//! 中断桩内联汇编无法在宿主 COFF 目标汇编，`cargo test -p drv` 结构性不可
//! 行——本 crate 的行为断言全部由 kernel 自检（真机 QEMU，`kernel-tests`
//! feature）承载；原文件内 `#[cfg(test)]` 模块自诞生起从未在任何环境编译，
//! 已按死代码移除，有效意图（sectors_touched 边界矩阵、pci_location_of
//! 对抗分支）迁移至 `kernel/src/tests.rs`。

#![no_std]

extern crate alloc;

pub mod bus;
pub mod device;
pub mod driver;
pub mod drivers;
pub mod event;
pub mod hub;
pub mod uio;

// 向上提供对 PCI 深度自省等功能的导出
pub use drivers::pci_bus as pci;
pub use drivers::pci_classes as pci_drivers;

pub use device::{
    BlockDevice, BusType, CharDevice, Device, DeviceInfo, DeviceKind, DeviceOps, DisplayDevice,
    InputDevice, IoDevice, IoStats, NetDevice, sectors_touched,
};
pub use driver::{Driver, DriverEntry, DriverStage};
pub use event::{
    DeviceEvent, dropped_event_count, peek_event, pending_event_count, pop_event, publish_event,
    set_event_wake_callback,
};
pub use hub::{DriverHub, ProbeStatus};
pub use uio::{
    UioDriverEntry, device_mmio_window, publish_device_window, uio_claim_device,
    uio_device_window_of, uio_is_device_claimed, uio_on_process_exit, uio_register_driver,
    uio_unregister_driver,
};
