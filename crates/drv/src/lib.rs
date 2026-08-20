//! 设备与驱动框架统一中枢（ADR-008 核心）。
//!
//! 提供基于 ADR-008 驱动中枢哲学的四阶段生命周期、自动总线探测与统一设备分类标准。

#![no_std]

#[cfg(test)]
extern crate std;

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
    BlockDevice, BusType, CharDevice, Device, DeviceInfo, DeviceKind, DeviceOps, InputDevice,
    IoDevice, NetDevice,
};
pub use driver::{Driver, DriverEntry, DriverStage};
pub use event::{publish_event, pop_event, pending_event_count, subscribe_events, DeviceEvent, EventSubscriber};
pub use hub::DriverHub;
pub use uio::{uio_register_driver, uio_on_process_exit, uio_is_device_claimed, UioDriverEntry};

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};

    struct MockSerialDev;
    impl Device for MockSerialDev {
        fn name(&self) -> &'static str {
            "serial-com1"
        }
        fn kind(&self) -> DeviceKind {
            DeviceKind::Char
        }
        fn as_io(&self) -> Option<&dyn IoDevice> {
            Some(self)
        }
    }
    impl IoDevice for MockSerialDev {
        fn write(&self, data: &[u8]) -> usize {
            data.len()
        }
    }

    static DRV_EARLY_INITED: AtomicBool = AtomicBool::new(false);
    static DRV_PROBED: AtomicBool = AtomicBool::new(false);
    static DRV_ATTACHED: AtomicBool = AtomicBool::new(false);

    fn early_init(_hub: &DriverHub) {
        DRV_EARLY_INITED.store(true, Ordering::Relaxed);
    }

    fn probe_block(_hub: &DriverHub, dev: &DeviceInfo) -> bool {
        dev.bus == BusType::Pci && dev.class_code == 0x01
    }

    fn attach_block(_hub: &DriverHub, _dev: &DeviceInfo) -> Result<(), ()> {
        DRV_ATTACHED.store(true, Ordering::Relaxed);
        Ok(())
    }

    #[test]
    fn test_driver_hub_lifecycle_and_bidding() {
        // 1. 注册 Early 阶段驱动
        DriverHub::register_driver("early-serial", DriverStage::Early, early_init);

        // 2. 注册 Devices 阶段带竞标的块设备驱动
        DriverHub::register_driver_ops(
            "pci-block-driver",
            DriverStage::Devices,
            |_| {},
            Some(probe_block),
            Some(attach_block),
        );

        // 3. 注册一个 Platform 字符设备和一个 PCI 块设备
        DriverHub::register_device(&MockSerialDev);
        DriverHub::register_device_info(
            DeviceInfo {
                name: "pci-ata-disk",
                kind: DeviceKind::Block,
                bus: BusType::Pci,
                location: 0x00010000,
                vendor_id: 0x8086,
                device_id: 0x7010,
                class_code: 0x01,
                subclass: 0x01,
                prog_if: 0x80,
            },
            None,
            None,
        );

        assert!(DriverHub::device_count() >= 2);
        assert!(DriverHub::driver_count() >= 2);

        // 4. 触发 Early 阶段
        DriverHub::init_early();
        assert!(DRV_EARLY_INITED.load(Ordering::Relaxed));
        assert!(!DRV_ATTACHED.load(Ordering::Relaxed));

        // 5. 触发 Devices 阶段（自动 probe / attach）
        DriverHub::init_devices();
        assert!(DRV_ATTACHED.load(Ordering::Relaxed));
    }
}
