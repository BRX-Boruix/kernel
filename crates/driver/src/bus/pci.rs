//! PCI 总线配置空间枚举与 BAR 缓存（ADR-008 §4 总线层）。
//!
//! 当前实现位于 `super::drivers::pci_bus`，本模块提供 ADR-008 规范路径的
//! 重导出，使用方可通过 `driver::bus::pci::*` 访问 PCI 相关接口。

pub use super::drivers::pci_bus::{
    PciBar, cached_pci_bars, inspect_pci_bars, pci_location_of, scan_pci_bus,
};
pub use super::drivers::pci_classes::register_pci_class_drivers;