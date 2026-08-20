//! 驱动 + 设备注册表。
//!
//! 静态链接阶段的内核，驱动与设备对象都是 `&'static` 常量；注册表把它们
//! 存入定长数组（上限 [`MAX_DRIVERS`]/[`MAX_DEVICES`]）。未来动态加载
//! 模块后，模块内驱动同样调用 [`register_driver`] 注册（接口不变）。
//!
//! 线程安全：整个注册表由 `IrqSpinLock` 保护（关中断 + 自旋），
//! 探测/绑定发生在 BSP 单线程早期，之后 idle 轮询跨核安全。

use core::mem::MaybeUninit;

use klib::sync::irq::IrqSpinLock;

use crate::device::Device;
use crate::driver::Driver;

/// 驱动注册上限（静态链接阶段足够；动态模块加载时可另行扩容）。
pub const MAX_DRIVERS: usize = 32;
/// 设备注册上限。
pub const MAX_DEVICES: usize = 32;
/// 绑定关系上限（每个设备最多绑定一个驱动，故通常 ≤ MAX_DEVICES）。
pub const MAX_BINDINGS: usize = 32;

/// 一条"设备 ↔ 驱动"绑定关系。
#[derive(Clone, Copy)]
pub struct Binding {
    pub driver: &'static dyn Driver,
    pub device: &'static dyn Device,
}

/// 注册表：驱动表 + 设备表 + 绑定表（定长数组 + 计数）。
pub struct Registry {
    drivers: [Option<&'static dyn Driver>; MAX_DRIVERS],
    devices: [Option<&'static dyn Device>; MAX_DEVICES],
    bindings: [MaybeUninit<Binding>; MAX_BINDINGS],
    n_drivers: usize,
    n_devices: usize,
    n_bindings: usize,
}

impl Registry {
    /// 空注册表（常量构造）。
    pub const fn new() -> Self {
        Self {
            drivers: [None; MAX_DRIVERS],
            devices: [None; MAX_DEVICES],
            bindings: [const { MaybeUninit::uninit() }; MAX_BINDINGS],
            n_drivers: 0,
            n_devices: 0,
            n_bindings: 0,
        }
    }

    /// 注册驱动（重复注册返回 `false`）。表满返回 `false`。
    pub fn register_driver(&mut self, d: &'static dyn Driver) -> bool {
        if self.drivers.iter().any(|&x| x.is_some() && ptr_eq_driver(x.unwrap(), d)) {
            return false;
        }
        if self.n_drivers >= MAX_DRIVERS {
            return false;
        }
        self.drivers[self.n_drivers] = Some(d);
        self.n_drivers += 1;
        true
    }

    /// 注册设备（重复注册返回 `false`）。表满返回 `false`。
    pub fn register_device(&mut self, dev: &'static dyn Device) -> bool {
        if self.devices.iter().any(|&x| x.is_some() && ptr_eq_device(x.unwrap(), dev)) {
            return false;
        }
        if self.n_devices >= MAX_DEVICES {
            return false;
        }
        self.devices[self.n_devices] = Some(dev);
        self.n_devices += 1;
        true
    }

    /// 已注册驱动数。
    pub fn driver_count(&self) -> usize {
        self.n_drivers
    }

    /// 已注册设备数。
    pub fn device_count(&self) -> usize {
        self.n_devices
    }

    /// 已绑定关系数。
    pub fn binding_count(&self) -> usize {
        self.n_bindings
    }

    /// 遍历驱动（只读）。
    pub fn for_each_driver(&self, mut f: impl FnMut(&'static dyn Driver)) {
        for i in 0..self.n_drivers {
            if let Some(d) = self.drivers[i] {
                f(d);
            }
        }
    }

    /// 遍历设备（只读）。
    pub fn for_each_device(&self, mut f: impl FnMut(&'static dyn Device)) {
        for i in 0..self.n_devices {
            if let Some(d) = self.devices[i] {
                f(d);
            }
        }
    }

    /// 遍历绑定关系（只读）。
    pub fn for_each_binding(&self, mut f: impl FnMut(&Binding)) {
        for i in 0..self.n_bindings {
            // SAFETY: `n_bindings` 之前的槽位均已写入（见 `bind`）。
            let b = unsafe { self.bindings[i].assume_init_ref() };
            f(b);
        }
    }

    /// 添加一条绑定（内部用于 probe 成功后）。
    pub(crate) fn bind(&mut self, driver: &'static dyn Driver, device: &'static dyn Device) -> bool {
        if self.n_bindings >= MAX_BINDINGS {
            return false;
        }
        self.bindings[self.n_bindings] = MaybeUninit::new(Binding { driver, device });
        self.n_bindings += 1;
        true
    }

    /// 设备是否已绑定驱动。
    pub fn is_bound(&self, device: &'static dyn Device) -> bool {
        for i in 0..self.n_bindings {
            let b = unsafe { self.bindings[i].assume_init_ref() };
            if ptr_eq_device(b.device, device) {
                return true;
            }
        }
        false
    }

    /// 收集所有匹配设备 id 的驱动（按注册顺序），写入 `out`。
    /// 返回写入数量。
    pub fn collect_matching_drivers(
        &self,
        dev: &'static dyn Device,
        out: &mut [Option<&'static dyn Driver>],
    ) -> usize {
        let id = dev.id();
        let mut n = 0;
        for i in 0..self.n_drivers {
            if n >= out.len() {
                break;
            }
            if let Some(d) = self.drivers[i] {
                if d.matches(&id) {
                    out[n] = Some(d);
                    n += 1;
                }
            }
        }
        n
    }
}

fn ptr_eq_driver(a: &'static dyn Driver, b: &'static dyn Driver) -> bool {
    core::ptr::eq(a, b)
}
fn ptr_eq_device(a: &'static dyn Device, b: &'static dyn Device) -> bool {
    core::ptr::eq(a, b)
}

/// 全局注册表（中断安全锁保护）。
pub static REGISTRY: IrqSpinLock<Registry> = IrqSpinLock::new(Registry::new());

/// 注册驱动（静态链接阶段由各驱动模块调用）。
pub fn register_driver(d: &'static dyn Driver) -> bool {
    REGISTRY.lock().register_driver(d)
}

/// 注册设备（静态链接阶段由启动代码/总线枚举调用）。
pub fn register_device(dev: &'static dyn Device) -> bool {
    REGISTRY.lock().register_device(dev)
}

/// 已注册驱动数。
pub fn driver_count() -> usize {
    REGISTRY.lock().driver_count()
}

/// 已注册设备数。
pub fn device_count() -> usize {
    REGISTRY.lock().device_count()
}

/// 访问全局注册表并执行闭包。
pub fn with_registry<R, F: FnOnce(&Registry) -> R>(f: F) -> R {
    let reg = REGISTRY.lock();
    f(&reg)
}

/// 已绑定关系数。
pub fn binding_count() -> usize {
    REGISTRY.lock().binding_count()
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{DeviceClass, DeviceId};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// 注册表是全局单例，测试间需复位 → 用测试锁串行化 + 手动清空。
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static INIT_CALLS: AtomicUsize = AtomicUsize::new(0);

    struct TestDevice(&'static str);

    impl Device for TestDevice {
        fn name(&self) -> &'static str {
            self.0
        }
        fn id(&self) -> DeviceId {
            DeviceId::system(DeviceClass::Generic, 1)
        }
    }

    struct TestDriver;

    impl Driver for TestDriver {
        fn name(&self) -> &'static str {
            "test"
        }
        fn matches(&self, id: &DeviceId) -> bool {
            id.class == DeviceClass::Generic as u32
        }
        fn init(&self, _dev: &dyn Device) -> crate::driver::DrvResult {
            INIT_CALLS.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    static DEV: TestDevice = TestDevice("dev0");
    static DRV: TestDriver = TestDriver;

    fn reset_registry() {
        // 直接重建全局注册表（测试环境无中断语义，锁内替换安全）。
        *REGISTRY.lock() = Registry::new();
        INIT_CALLS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn register_and_count() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_registry();
        assert!(register_driver(&DRV));
        assert!(register_device(&DEV));
        assert_eq!(driver_count(), 1);
        assert_eq!(device_count(), 1);
        assert_eq!(binding_count(), 0);
    }

    #[test]
    fn duplicate_register_rejected() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_registry();
        assert!(register_driver(&DRV));
        assert!(!register_driver(&DRV), "duplicate driver rejected");
        assert!(register_device(&DEV));
        assert!(!register_device(&DEV), "duplicate device rejected");
        assert_eq!(driver_count(), 1);
        assert_eq!(device_count(), 1);
    }

    #[test]
    fn collect_matching_drivers() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_registry();
        register_driver(&DRV);
        let mut out = [None; 4];
        let n = REGISTRY.lock().collect_matching_drivers(&DEV, &mut out);
        assert_eq!(n, 1);
        assert_eq!(out[0].unwrap().name(), "test");
    }

    #[test]
    fn bind_then_bound() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_registry();
        register_driver(&DRV);
        register_device(&DEV);
        assert!(REGISTRY.lock().bind(&DRV, &DEV));
        assert_eq!(binding_count(), 1);
        assert!(REGISTRY.lock().is_bound(&DEV));
    }
}
