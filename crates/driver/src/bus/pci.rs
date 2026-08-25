//! PCI 总线配置空间枚举与 BAR 缓存（ADR-008 §4 总线层）。
//!
//! 当前实现位于 `super::drivers::pci_bus`，本模块提供 ADR-008 规范路径的
//! 重导出，使用方可通过 `driver::bus::pci::*` 访问 PCI 相关接口。

//! PCI 总线配置空间枚举与 BAR 缓存（ADR-008 §4 总线层）。
//!
//! 当前实现位于 `super::drivers::pci_bus`，本模块提供 ADR-008 规范路径的
//! 重导出。使用方可通过 `driver::bus::pci::*` 访问 PCI 相关接口。

pub use crate::drivers::pci_bus::{cached_pci_bars, init_pci_bus, register_pci_bus_driver, scan_pci_bus};
pub use crate::drivers::pci_classes::register_pci_class_drivers;