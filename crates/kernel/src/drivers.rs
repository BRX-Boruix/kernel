//! 设备/驱动框架的静态接线（T5）。
//!
//! 把当前**硬编码接线**的硬件（串口、framebuffer）登记为框架设备，并
//! 提供对应驱动，验证 ADR-008 的 `Driver` trait / 注册表 / probe 机制。
//! T6 将把具体设备下沉为正式驱动（本文件即其落点）。

use drv::{BusType, Device, DeviceId, Driver, DrvResult};
use klib::{info, warn};

// ---------- 设备对象（静态实例） ----------

/// COM1 串口设备。
struct SerialPortDevice;
impl Device for SerialPortDevice {
    fn name(&self) -> &'static str {
        "serial-com1"
    }
    fn id(&self) -> DeviceId {
        DeviceId::serial_port(1)
    }
}
static SERIAL_PORT_DEVICE: SerialPortDevice = SerialPortDevice;

/// Framebuffer 设备。
struct FramebufferDevice;
impl Device for FramebufferDevice {
    fn name(&self) -> &'static str {
        "framebuffer"
    }
    fn id(&self) -> DeviceId {
        DeviceId::framebuffer()
    }
}
static FRAMEBUFFER_DEVICE: FramebufferDevice = FramebufferDevice;

// ---------- 驱动（静态实例） ----------

/// 串口 UART 驱动：probe 读 LSR 确认端口可访问；init 登记。
///
/// 当前仅"探测 + 绑定"（输出仍走既有串口接线）；T6 下沉为正式驱动时
/// 在此接管收发。
struct SerialUartDriver;
impl Driver for SerialUartDriver {
    fn name(&self) -> &'static str {
        "serial-uart"
    }
    fn matches(&self, id: &DeviceId) -> bool {
        id.bus == BusType::Serial
    }
    fn probe(&self, dev: &dyn Device) -> DrvResult {
        // 读 LSR（0x3F8+5）确认端口存在（任何读数均视为可访问）。
        let _lsr = port_for(dev).map(arch_x86_64::port::inb);
        match _lsr {
            Some(_) => Ok(()),
            None => Err("unsupported com port"),
        }
    }
    fn init(&self, dev: &dyn Device) -> DrvResult {
        let base = port_for(dev).unwrap_or(0x3F8);
        info!("[drv] serial-uart init: COM{} base={:#x}", dev.id().device, base);
        Ok(())
    }
    fn idle(&self, _dev: &dyn Device) {
        // 轮询入口：T6 接管时在此读输入缓冲。
    }
    fn shutdown(&self, _dev: &dyn Device) {
        info!("[drv] serial-uart shutdown");
    }
}
static SERIAL_UART_DRIVER: SerialUartDriver = SerialUartDriver;

/// Framebuffer 驱动：绑定 framebuffer 设备并登记尺寸。
struct FramebufferDriver;
impl Driver for FramebufferDriver {
    fn name(&self) -> &'static str {
        "framebuffer"
    }
    fn matches(&self, id: &DeviceId) -> bool {
        id.bus == BusType::Framebuffer
    }
    fn init(&self, dev: &dyn Device) -> DrvResult {
        info!("[drv] framebuffer init: '{}'", dev.name());
        Ok(())
    }
}
static FRAMEBUFFER_DRIVER: FramebufferDriver = FramebufferDriver;

/// 从设备 id 映射 COM 端口基址（COM1=0x3F8 起，间隔 0x100）。
fn port_for(dev: &dyn Device) -> Option<u16> {
    let n = dev.id().device;
    if (1..=4).contains(&n) {
        Some(0x3F8 + ((n - 1) * 0x100) as u16)
    } else {
        None
    }
}

// ---------- 初始化入口 ----------

/// 注册串口设备 + 驱动并执行探测（启动早期，serial::init 之后调用）。
pub fn init() {
    drv::register_driver(&SERIAL_UART_DRIVER);
    drv::register_device(&SERIAL_PORT_DEVICE);
    drv::probe_all();

    info!(
        "[drv] framework: drivers={} devices={} bound={}",
        drv::driver_count(),
        drv::device_count(),
        drv::binding_count()
    );
}

/// 注册 framebuffer 设备（framebuffer 终端初始化成功后调用）。
pub fn register_framebuffer() {
    drv::register_driver(&FRAMEBUFFER_DRIVER);
    if drv::register_device(&FRAMEBUFFER_DEVICE) {
        drv::probe_all();
    } else {
        warn!("[drv] framebuffer device already registered");
    }
}
