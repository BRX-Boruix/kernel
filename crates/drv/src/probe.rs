//! 总线探测机制（probe 框架）。
//!
//! 对每个已注册设备：找第一个匹配驱动 → `probe` 确认 → `init` 绑定。
//! 当前为静态链接：设备/驱动在启动早期注册后一次性探测。未来动态模块
//! 加载后，新模块只需重新调用 [`probe_all`]（或逐个 [`probe_device`]）。
//!
//! 实现约束：**不使用堆分配**（定长快照），保证探测可在早期（堆未就绪、
//! 单测环境 klib 全局分配器未初始化）安全运行。

use klib::{info, warn};

use crate::device::Device;
use crate::registry::{Binding, MAX_BINDINGS, MAX_DEVICES, MAX_DRIVERS, REGISTRY};

/// 对全部已注册设备执行探测：为每个未绑定设备匹配并绑定驱动。
///
/// 返回新绑定数量。
pub fn probe_all() -> usize {
    // 快照未绑定设备（避免遍历时持锁 + 调 probe 死锁）。
    let mut pending: [Option<&'static dyn Device>; MAX_DEVICES] = [None; MAX_DEVICES];
    let mut n = 0;
    {
        let reg = REGISTRY.lock();
        reg.for_each_device(|dev| {
            if !reg.is_bound(dev) && n < MAX_DEVICES {
                pending[n] = Some(dev);
                n += 1;
            }
        });
    }

    let mut bound = 0;
    for i in 0..n {
        if let Some(dev) = pending[i] {
            if probe_device(dev) {
                bound += 1;
            }
        }
    }
    bound
}

/// 探测单个设备：按注册顺序尝试每个匹配驱动 probe → init → 绑定。
///
/// 一个驱动 probe 失败（如硬件不存在）时，继续尝试下一个匹配驱动；
/// 全部失败则设备保持未绑定。返回是否成功绑定。
pub fn probe_device(dev: &'static dyn Device) -> bool {
    // 收集匹配驱动（快照，避免持锁调 probe）。
    let mut drivers: [Option<&'static dyn crate::driver::Driver>; MAX_DRIVERS] = [None; MAX_DRIVERS];
    let n_drivers = {
        let reg = REGISTRY.lock();
        if reg.is_bound(dev) {
            return true; // 已绑定
        }
        reg.collect_matching_drivers(dev, &mut drivers)
    };
    if n_drivers == 0 {
        info!(
            "[drv] probe {}: no matching driver (bus={})",
            dev.name(),
            dev.id().bus.name()
        );
        return false;
    }

    for i in 0..n_drivers {
        let drv = drivers[i].unwrap();

        // probe：确认设备可用。
        if let Err(e) = drv.probe(dev) {
            warn!(
                "[drv] probe {}: driver '{}' probe failed: {}",
                dev.name(),
                drv.name(),
                e
            );
            continue;
        }

        // init：初始化并绑定。
        if let Err(e) = drv.init(dev) {
            warn!(
                "[drv] init {}: driver '{}' init failed: {}",
                dev.name(),
                drv.name(),
                e
            );
            continue;
        }

        let ok = REGISTRY.lock().bind(drv, dev);
        if ok {
            info!(
                "[drv] bound '{}' to '{}' (bus={})",
                dev.name(),
                drv.name(),
                dev.id().bus.name()
            );
        }
        return ok;
    }
    false
}

/// 周期轮询：调用所有已绑定驱动的 `idle`（供轮询式设备与后台维护）。
///
/// 注意：在注册表锁**外**调用（避免驱动内部再取锁死锁）。
pub fn idle_all() {
    let mut snapshot: [Option<Binding>; MAX_BINDINGS] = [None; MAX_BINDINGS];
    let mut n = 0;
    {
        let reg = REGISTRY.lock();
        reg.for_each_binding(|b| {
            if n < MAX_BINDINGS {
                snapshot[n] = Some(*b);
                n += 1;
            }
        });
    }
    for i in 0..n {
        if let Some(b) = snapshot[i] {
            b.driver.idle(b.device);
        }
    }
}

/// 关闭全部已绑定设备（预留动态卸载路径）。
pub fn shutdown_all() {
    let mut snapshot: [Option<Binding>; MAX_BINDINGS] = [None; MAX_BINDINGS];
    let mut n = 0;
    {
        let reg = REGISTRY.lock();
        reg.for_each_binding(|b| {
            if n < MAX_BINDINGS {
                snapshot[n] = Some(*b);
                n += 1;
            }
        });
    }
    for i in 0..n {
        if let Some(b) = snapshot[i] {
            b.driver.shutdown(b.device);
        }
    }
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::{Driver, DrvResult};
    use crate::id::{DeviceClass, DeviceId};
    use crate::registry::{Registry, binding_count, register_device, register_driver};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    static INIT_CALLS: AtomicUsize = AtomicUsize::new(0);
    static IDLE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static SHUTDOWN_CALLS: AtomicUsize = AtomicUsize::new(0);
    static PROBE_FAIL: AtomicUsize = AtomicUsize::new(0);

    struct ProbeDevice;

    impl Device for ProbeDevice {
        fn name(&self) -> &'static str {
            "probe-dev"
        }
        fn id(&self) -> DeviceId {
            DeviceId::system(DeviceClass::Generic, 7)
        }
    }

    static DEV: ProbeDevice = ProbeDevice;

    struct OkDriver;

    impl Driver for OkDriver {
        fn name(&self) -> &'static str {
            "ok"
        }
        fn matches(&self, id: &DeviceId) -> bool {
            id.class == DeviceClass::Generic as u32
        }
        fn init(&self, _dev: &dyn Device) -> DrvResult {
            INIT_CALLS.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn idle(&self, _dev: &dyn Device) {
            IDLE_CALLS.fetch_add(1, Ordering::SeqCst);
        }
        fn shutdown(&self, _dev: &dyn Device) {
            SHUTDOWN_CALLS.fetch_add(1, Ordering::SeqCst);
        }
    }

    static OK_DRV: OkDriver = OkDriver;

    struct FailDriver;

    impl Driver for FailDriver {
        fn name(&self) -> &'static str {
            "fail"
        }
        fn matches(&self, id: &DeviceId) -> bool {
            id.class == DeviceClass::Generic as u32
        }
        fn probe(&self, _dev: &dyn Device) -> DrvResult {
            PROBE_FAIL.fetch_add(1, Ordering::SeqCst);
            Err("hw absent")
        }
        fn init(&self, _dev: &dyn Device) -> DrvResult {
            Ok(())
        }
    }

    static FAIL_DRV: FailDriver = FailDriver;

    fn reset() {
        *REGISTRY.lock() = Registry::new();
        INIT_CALLS.store(0, Ordering::SeqCst);
        IDLE_CALLS.store(0, Ordering::SeqCst);
        SHUTDOWN_CALLS.store(0, Ordering::SeqCst);
        PROBE_FAIL.store(0, Ordering::SeqCst);
    }

    #[test]
    fn probe_binds_and_counts() {
        let _g = TEST_LOCK.lock().unwrap();
        reset();
        register_driver(&OK_DRV);
        register_device(&DEV);
        let n = probe_all();
        assert_eq!(n, 1);
        assert_eq!(INIT_CALLS.load(Ordering::SeqCst), 1);
        assert!(REGISTRY.lock().is_bound(&DEV));
        assert_eq!(binding_count(), 1);
    }

    #[test]
    fn probe_skips_already_bound() {
        let _g = TEST_LOCK.lock().unwrap();
        reset();
        register_driver(&OK_DRV);
        register_device(&DEV);
        assert_eq!(probe_all(), 1);
        // 再次探测：已绑定，不再重复 init。
        assert_eq!(probe_all(), 0);
        assert_eq!(INIT_CALLS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn probe_failure_not_bound() {
        let _g = TEST_LOCK.lock().unwrap();
        reset();
        // fail 驱动先注册（会被先匹配），probe 失败 → 不绑定。
        register_driver(&FAIL_DRV);
        register_driver(&OK_DRV);
        register_device(&DEV);
        let n = probe_all();
        assert_eq!(n, 1); // fail 失败后，ok 驱动兜底绑定
        assert_eq!(PROBE_FAIL.load(Ordering::SeqCst), 1);
        assert_eq!(INIT_CALLS.load(Ordering::SeqCst), 1);
        assert!(REGISTRY.lock().is_bound(&DEV));
    }

    #[test]
    fn no_matching_driver() {
        let _g = TEST_LOCK.lock().unwrap();
        reset();
        // 不注册任何驱动。
        register_device(&DEV);
        let n = probe_all();
        assert_eq!(n, 0);
        assert!(!REGISTRY.lock().is_bound(&DEV));
    }

    #[test]
    fn idle_and_shutdown_called() {
        let _g = TEST_LOCK.lock().unwrap();
        reset();
        register_driver(&OK_DRV);
        register_device(&DEV);
        probe_all();
        idle_all();
        assert_eq!(IDLE_CALLS.load(Ordering::SeqCst), 1);
        shutdown_all();
        assert_eq!(SHUTDOWN_CALLS.load(Ordering::SeqCst), 1);
    }
}
