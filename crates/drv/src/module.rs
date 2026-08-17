//! 模块加载预留接口（ADR-008：动态化只加"加载 ELF 模块"机制）。
//!
//! 当前内核静态链接驱动，本模块提供统一的模块加载抽象：
//! - [`ModuleLoader`]：加载器 trait（未来由 ELF 模块加载器实现）；
//! - [`set_module_loader`]：注册加载器（启动早期由内核调用）；
//! - [`load_module`]：按名加载并执行一个模块（动态化入口）。
//!
//! 模块加载后，其内部驱动通过 [`crate::registry::register_driver`] 注册，
//! 注册表与 probe 接口完全不变（本框架的核心承诺）。

use klib::sync::irq::IrqSpinLock;

/// 模块加载器接口。
///
/// 未来实现方：解析 ELF 模块镜像，重定位并调用其入口函数；
/// 模块入口内部执行驱动注册（`register_driver`）等初始化动作。
pub trait ModuleLoader: Sync {
    /// 加载并初始化一个模块。
    ///
    /// `name`：模块名（诊断用）；`data`：模块镜像字节。
    /// 返回 `Ok` 表示加载成功（驱动已注册）。
    fn load(&self, name: &str, data: &[u8]) -> Result<(), klib::error::Error>;
}

/// 全局加载器槽（静态链接阶段为空；动态化时由内核注册）。
static LOADER: IrqSpinLock<Option<&'static dyn ModuleLoader>> = IrqSpinLock::new(None);

/// 注册模块加载器（启动早期调用一次）。
pub fn set_module_loader(loader: &'static dyn ModuleLoader) {
    *LOADER.lock() = Some(loader);
}

/// 当前是否已有模块加载器。
pub fn loader_registered() -> bool {
    LOADER.lock().is_some()
}

/// 加载并初始化一个模块（动态化入口；未注册加载器时返回错误）。
pub fn load_module(name: &str, data: &[u8]) -> Result<(), klib::error::Error> {
    let l = LOADER.lock();
    match *l {
        Some(loader) => loader.load(name, data),
        None => Err(klib::error::Error::NotFound),
    }
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyLoader;
    impl ModuleLoader for DummyLoader {
        fn load(&self, _name: &str, _data: &[u8]) -> Result<(), klib::error::Error> {
            Ok(())
        }
    }

    #[test]
    fn no_loader_by_default() {
        assert!(!loader_registered());
        assert!(load_module("x", b"").is_err());
    }

    #[test]
    fn set_loader_registers() {
        static L: DummyLoader = DummyLoader;
        set_module_loader(&L);
        assert!(loader_registered());
        assert!(load_module("x", b"data").is_ok());
    }
}
