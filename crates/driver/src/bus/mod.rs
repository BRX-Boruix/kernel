//! 总线探测层（ADR-008 §4 总线-设备-驱动正交解耦）。
//!
//! 各总线类型（PCI、Platform、Virtual）的枚举与探测逻辑。

pub mod pci;
pub mod platform;