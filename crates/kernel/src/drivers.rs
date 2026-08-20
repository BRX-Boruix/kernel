//! 设备/驱动框架接线（升级为 M7 DriverHub 驱动中枢）。
//!
//! 提供基于 DriverStage 四阶段生命周期与 DriverHub 集中调度的核心硬件驱动注册。

use core::sync::atomic::{AtomicUsize, Ordering};
use drv::{BusType, Device, DeviceInfo, DeviceKind, DeviceOps, DriverHub, DriverStage, IoDevice};
use klib::info;

/// Framebuffer 设备对象。
struct FramebufferDevice;
impl Device for FramebufferDevice {
    fn name(&self) -> &'static str {
        "framebuffer"
    }
    fn kind(&self) -> DeviceKind {
        DeviceKind::Display
    }
    fn as_io(&self) -> Option<&dyn IoDevice> {
        Some(self)
    }
}
impl IoDevice for FramebufferDevice {}
static FRAMEBUFFER_DEV: FramebufferDevice = FramebufferDevice;

/// Limine framebuffer 指针。
static FRAMEBUFFER_PTR: AtomicUsize = AtomicUsize::new(0);

fn init_framebuffer(_hub: &DriverHub) {
    let p = FRAMEBUFFER_PTR.load(Ordering::Acquire);
    if p == 0 {
        return;
    }
    let fb: &limine::Framebuffer = unsafe { &*(p as *const limine::Framebuffer) };
    crate::terminal::init(fb);
    let _ = klib::console::register_console(&crate::terminal::TERMINAL_CONSOLE);
    DriverHub::register_device_info(
        DeviceInfo {
            name: "framebuffer",
            kind: DeviceKind::Display,
            bus: BusType::Virtual,
            location: 0,
            vendor_id: 0,
            device_id: 0,
            class_code: 0x03,
            subclass: 0x00,
            prog_if: 0x00,
        },
        Some(&FRAMEBUFFER_DEV),
        Some("framebuffer"),
    );
    info!("[driver_hub] framebuffer terminal & display registered");
}

/// 初始化 DriverHub 驱动框架（Early & Core 阶段）。
pub fn init() {
    // 注册 Framebuffer 驱动
    DriverHub::register_driver("framebuffer", DriverStage::Core, init_framebuffer);

    // 触发 Early 阶段（串口控制台）
    DriverHub::init_early();

    // 注册统一 console 的串口 sink
    let _ = klib::console::register_console(&arch_x86_64::serial::SERIAL_CONSOLE);

    // 触发 Core 阶段（PS/2 键盘、CMOS RTC 时钟、伪设备、Framebuffer）
    DriverHub::init_core();

    // 触发 Devices 阶段（PCI 总线枚举、自动 probe / attach）
    DriverHub::init_devices();

    info!(
        "[driver_hub] framework inited: drivers={} devices={}",
        DriverHub::driver_count(),
        DriverHub::device_count()
    );
}

/// 注册 Framebuffer 指针供 Core 阶段或即时终端使用。
pub fn register_framebuffer(fb: &limine::Framebuffer) {
    FRAMEBUFFER_PTR.store(fb as *const limine::Framebuffer as usize, Ordering::Release);
}
