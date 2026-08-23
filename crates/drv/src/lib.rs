//! 设备与驱动框架统一中枢（ADR-008 核心）。
//!
//! 提供基于 ADR-008 驱动中枢哲学的四阶段生命周期、自动总线探测与统一设备分类标准。

#![no_std]

extern crate alloc;

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
    IoDevice, IoStats, NetDevice, sectors_touched,
};
pub use driver::{Driver, DriverEntry, DriverStage};
pub use event::{
    DeviceEvent, EventSubscriber, pending_event_count, pop_event, publish_event, subscribe_events,
};
pub use hub::DriverHub;
pub use uio::{
    UioDriverEntry, device_mmio_window, publish_device_window, uio_claim_device,
    uio_device_window_of, uio_is_device_claimed, uio_on_process_exit, uio_register_driver,
};

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
                volatile: false,
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

    #[test]
    fn test_pci_location_reverse_lookup() {
        // C5.1：注册 → 反查回环。location 编码 = (bus<<16)|(device<<8)|function。
        DriverHub::register_device_info(
            DeviceInfo {
                name: "pci-ethernet",
                kind: DeviceKind::Net,
                bus: BusType::Pci,
                location: 0x00030000, // bus=0, device=3, function=0
                vendor_id: 0x8086,
                device_id: 0x100E,
                class_code: 0x02,
                subclass: 0x00,
                prog_if: 0x00,
                volatile: true,
            },
            None,
            None,
        );

        // 正向反查
        assert_eq!(
            DriverHub::pci_location_of("pci-ethernet"),
            Some((0, 3, 0)),
            "registered PCI device must be reverse-locatable"
        );

        // 对抗：未知名称
        assert_eq!(
            DriverHub::pci_location_of("nonexistent-device"),
            None,
            "unknown device name must not yield a location"
        );

        // 对抗：非 PCI 设备（MockSerialDev 是 Platform/Unknown bus）
        assert_eq!(
            DriverHub::pci_location_of("serial-com1"),
            None,
            "non-PCI device must not return a PCI location"
        );

        // 多设备区分：注册第二个不同位置的 PCI 设备
        DriverHub::register_device_info(
            DeviceInfo {
                name: "pci-bridge",
                kind: DeviceKind::Misc,
                bus: BusType::Pci,
                location: 0x01040001, // bus=1, device=4, function=1
                vendor_id: 0x8086,
                device_id: 0x244E,
                class_code: 0x06,
                subclass: 0x04,
                prog_if: 0x00,
                volatile: true,
            },
            None,
            None,
        );
        assert_eq!(
            DriverHub::pci_location_of("pci-bridge"),
            Some((1, 4, 1)),
            "second PCI device at different BDF must be locatable"
        );
        assert_eq!(
            DriverHub::pci_location_of("pci-ethernet"),
            Some((0, 3, 0)),
            "first device must still be locatable after second registration"
        );
    }

    /// C15.1：DeviceInfo.volatile 必须经注册表原样往返，且泛型注册入口
    /// （register_device / register_device_bus）在无持久化证据时保守披露 true。
    #[test]
    fn test_volatile_disclosure() {
        // 持久硬件声明：false 必须原样保留
        DriverHub::register_device_info(
            DeviceInfo {
                name: "volatile-hw-disk",
                kind: DeviceKind::Block,
                bus: BusType::Pci,
                location: 0x00050000,
                vendor_id: 0x8086,
                device_id: 0x7010,
                class_code: 0x01,
                subclass: 0x01,
                prog_if: 0x80,
                volatile: false,
            },
            None,
            None,
        );

        // 易失设备声明：true 必须原样保留
        DriverHub::register_device_info(
            DeviceInfo {
                name: "volatile-ram-disk",
                kind: DeviceKind::Block,
                bus: BusType::Virtual,
                location: 0,
                vendor_id: 0,
                device_id: 0,
                class_code: 0x01,
                subclass: 0x80,
                prog_if: 0,
                volatile: true,
            },
            None,
            None,
        );

        let find_info = |name: &str| {
            (0..DriverHub::device_count()).find_map(|i| {
                DriverHub::device_info_at(i).filter(|info| info.name == name)
            })
        };

        let hw = find_info("volatile-hw-disk").expect("hw disk registered");
        assert!(
            !hw.volatile,
            "persistent hardware declaration must round-trip as volatile=false"
        );
        let ram = find_info("volatile-ram-disk").expect("ram disk registered");
        assert!(
            ram.volatile,
            "volatile declaration must round-trip as volatile=true"
        );

        // 泛型入口（仅知 name/kind）：无持久化证据必须保守上报 true
        let generic = find_info("serial-com1").expect("generic-registered device present");
        assert!(
            generic.volatile,
            "generic registration without persistence evidence must disclose volatile=true"
        );
    }

    /// C16.1：触碰扇区公式边界矩阵与计数器读写语义。
    /// 公式是 ramdisk / ATA 回退盘扇区计数的唯一口径，边界必须钉死。
    #[test]
    fn test_io_stats_and_sector_touch_math() {
        use crate::device::{IoStats, sectors_touched};

        // 空传输恒为 0
        assert_eq!(sectors_touched(0, 0), 0);
        assert_eq!(sectors_touched(512, 0), 0);
        // 单字节占一块
        assert_eq!(sectors_touched(0, 1), 1);
        // 恰好整块
        assert_eq!(sectors_touched(0, 512), 1);
        assert_eq!(sectors_touched(1024, 1024), 2);
        // 越过整块边界 1 字节 → 新增一块
        assert_eq!(sectors_touched(0, 513), 2);
        // 块内偏移 + 跨界
        assert_eq!(sectors_touched(511, 2), 2);
        assert_eq!(sectors_touched(511, 513), 3);
        // 大偏移不溢出（u64 全域）
        assert_eq!(sectors_touched(u64::MAX - 600, 100), 2);

        // 计数器：record 后只读访问器必须精确回读
        let st = IoStats::new();
        assert_eq!((st.sectors_read(), st.sectors_written()), (0, 0));
        st.record_read(3);
        st.record_write(5);
        st.record_read(1);
        assert_eq!(st.sectors_read(), 4);
        assert_eq!(st.sectors_written(), 5);
    }
}
