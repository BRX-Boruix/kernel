//! 设备/驱动框架的静态接线（T5 框架 + T6 驱动下沉）。
//!
//! 串口与 framebuffer 的**驱动化**：
//! - 架构层（`arch-x86_64::serial`）仍负责最早期的硬件初始化（早期日志
//!   输出需要），但 **console sink 注册、framebuffer 终端初始化**由驱动
//!   `init` 阶段接管（`Driver` 生命周期），启动代码不再硬编码接线。
//! - 设备对象携带运行期信息（framebuffer 指针），probe/init 按框架流程走。

use core::sync::atomic::{AtomicUsize, Ordering};

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

/// Framebuffer 设备。运行期由 `register_framebuffer` 填充 fb 指针。
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

/// Limine framebuffer 指针（`register_framebuffer` 写入，驱动 init 读取）。
static FRAMEBUFFER_PTR: AtomicUsize = AtomicUsize::new(0);

// ---------- 驱动（静态实例） ----------

/// 串口 UART 驱动（正式驱动）。
///
/// - `probe`：读 LSR 确认端口可访问；
/// - `init`：注册统一 console 的串口 sink（接管输出）；
/// - `idle`：轮询读输入（当前无消费者，读取即丢弃避免缓冲堆积）。
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
        let lsr = port_for(dev).map(arch_x86_64::port::inb);
        match lsr {
            Some(_) => Ok(()),
            None => Err("unsupported com port"),
        }
    }
    fn init(&self, dev: &dyn Device) -> DrvResult {
        let base = port_for(dev).unwrap_or(0x3F8);
        // 正式接管输出：注册统一 console 的串口 sink。
        if !klib::console::register_console(&arch_x86_64::serial::SERIAL_CONSOLE) {
            return Err("console table full");
        }
        info!("[drv] serial-uart init: COM{} base={:#x} (sink registered)", dev.id().device, base);
        Ok(())
    }
    fn idle(&self, _dev: &dyn Device) {
        // 轮询读输入：无消费者，读取即丢弃（保持 FIFO 不堆积）。
        while arch_x86_64::serial::read_byte().is_some() {}
    }
    fn shutdown(&self, _dev: &dyn Device) {
        info!("[drv] serial-uart shutdown");
    }
}
static SERIAL_UART_DRIVER: SerialUartDriver = SerialUartDriver;

/// Framebuffer 驱动（正式驱动）：init 初始化终端并注册屏幕 sink。
struct FramebufferDriver;
impl Driver for FramebufferDriver {
    fn name(&self) -> &'static str {
        "framebuffer"
    }
    fn matches(&self, id: &DeviceId) -> bool {
        id.bus == BusType::Framebuffer
    }
    fn init(&self, dev: &dyn Device) -> DrvResult {
        let p = FRAMEBUFFER_PTR.load(Ordering::Acquire);
        if p == 0 {
            return Err("framebuffer not provided by bootloader");
        }
        // SAFETY: `register_framebuffer` 写入的是合法 `&limine::Framebuffer` 指针，
        // 生命周期与 bootloader 提供的一致（内核运行期有效）。
        let fb: &limine::Framebuffer = unsafe { &*(p as *const limine::Framebuffer) };
        crate::terminal::init(fb);
        if !klib::console::register_console(&crate::terminal::TERMINAL_CONSOLE) {
            return Err("console table full");
        }
        info!("[drv] framebuffer init: '{}' (sink registered)", dev.name());
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

/// 注册串口设备 + 驱动并执行探测（启动早期，架构串口硬件就绪后调用）。
///
/// 驱动 `init` 在此完成串口 console sink 注册，启动代码不再手动接线。
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

/// 注册 framebuffer 设备并触发探测（bootloader 提供 framebuffer 后调用）。
///
/// 驱动 `init` 在此完成 framebuffer 终端初始化与屏幕 sink 注册。
pub fn register_framebuffer(fb: &limine::Framebuffer) {
    FRAMEBUFFER_PTR.store(fb as *const limine::Framebuffer as usize, Ordering::Release);
    drv::register_driver(&FRAMEBUFFER_DRIVER);
    if drv::register_device(&FRAMEBUFFER_DEVICE) {
        drv::probe_all();
    } else {
        warn!("[drv] framebuffer device already registered");
    }
}
