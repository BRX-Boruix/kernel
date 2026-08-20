//! 设备/驱动框架（ADR-008 核心）。
//!
//! 提供统一 `Driver` trait / 设备注册表 / probe 机制：
//! - [`DeviceId`]：跨总线设备 id 约定（总线 + vendor/device/class）；
//! - [`Device`]：通用设备抽象；
//! - [`Driver`]：驱动生命周期（`probe`/`init`/`idle`/`shutdown`）；
//! - [`Registry`]：驱动 + 设备注册表（静态链接，`IrqSpinLock` 保护）；
//! - [`probe_all`]：总线探测（对每个设备找匹配驱动 → probe → init → 绑定）；
//! - [`ModuleLoader`]：预留"加载 ELF 模块"接口（动态化时只加加载机制）。
//!
//! 设计要点（ADR-008）：
//! - 驱动静态起步，但接口按"可加载模块"设计；未来动态化只需实现
//!   [`ModuleLoader`] 并让模块镜像注册驱动，注册表接口不变。
//! - 框架本身零硬件依赖（不依赖 arch），具体驱动实现方负责访问硬件。

#![no_std]

#[cfg(test)]
extern crate std;

pub mod device;
pub mod driver;
pub mod id;
pub mod module;
pub mod probe;
pub mod registry;

pub use device::Device;
pub use driver::{Driver, DrvResult};
pub use id::{BusType, DeviceId};
pub use module::{ModuleLoader, load_module, set_module_loader};
pub use probe::{idle_all, probe_all, shutdown_all};
pub use registry::{
    Binding, Registry, binding_count, device_count, driver_count, register_device, register_driver,
    with_registry,
};
