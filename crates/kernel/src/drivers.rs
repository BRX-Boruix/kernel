//! 设备/驱动框架接线（升级为 M7 DriverHub 驱动中枢）。
//!
//! 提供基于 DriverStage 四阶段生命周期与 DriverHub 集中调度的核心硬件驱动注册。

use core::sync::atomic::{AtomicUsize, Ordering};
use driver::{BusType, DeviceInfo, DeviceKind, DriverHub, DriverStage};
use klib::{error, info};

/// Limine framebuffer 指针。
static FRAMEBUFFER_PTR: AtomicUsize = AtomicUsize::new(0);

fn init_framebuffer(_hub: &DriverHub) {
    let p = FRAMEBUFFER_PTR.load(Ordering::Acquire);
    if p == 0 {
        return;
    }
    let fb: &limine::Framebuffer = unsafe { &*(p as *const limine::Framebuffer) };
    // term1 T9：协议类型 → 表现层值结构的转换收敛在内核侧（S14），
    // term 不认识 limine 类型。
    let Some(addr) = fb.address.as_ptr() else {
        error!("[driver_hub] framebuffer address is null; terminal not initialized");
        return;
    };
    let info = term::FbInfo {
        addr: addr as usize,
        width: fb.width,
        height: fb.height,
        pitch: fb.pitch,
        bpp: fb.bpp,
        memory_model: fb.memory_model,
        red_mask_size: fb.red_mask_size,
        red_mask_shift: fb.red_mask_shift,
        green_mask_size: fb.green_mask_size,
        green_mask_shift: fb.green_mask_shift,
        blue_mask_size: fb.blue_mask_size,
        blue_mask_shift: fb.blue_mask_shift,
    };
    // term1 T3：init 失败即诚实降级为纯串口，且不注册屏幕 sink——
    // 注册死 sink 等于向 console 层伪装屏幕可用。
    if term::init(&info).is_ok() {
        // S18：注册失败（console 表满）必须显式记录，不再静默吞返回值——
        // 否则屏幕 sink 悄悄不挂载，用户以为有屏幕实则无。
        if !klib::console::register_console(&term::TERMINAL_CONSOLE) {
            error!("[fb] console sink table full; framebuffer terminal not registered");
        }
    }
    if let Err(e) = DriverHub::register_device_info(
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
            // C15.1：帧缓冲是易失显示面，内容不持久。
            volatile: true,
        },
        // KM7：无 I/O 操作集 → dev=None。显示能力不冒充字节流通道；
        // 驱动名绑定保留（framebuffer 驱动负责终端初始化，与 IO 无关）。
        None,
        Some("framebuffer"),
    ) {
        // DM1（ADR-022 §5）：注册失败必须可见，静默丢设备不复存在。
        error!("[driver_hub] framebuffer device registration failed: {:?}", e);
    }
    info!("[driver_hub] framebuffer terminal & display registered");
}

/// 初始化 DriverHub 驱动框架（Early & Core 阶段）。
pub fn init() {
    // 注册 Framebuffer 驱动
    if let Err(e) = DriverHub::register_driver("framebuffer", DriverStage::Core, init_framebuffer)
    {
        // DM1（ADR-022 §5）：注册失败必须可见。
        error!("[driver_hub] framebuffer driver registration failed: {:?}", e);
    }

    // 触发 Early 阶段（串口控制台）
    DriverHub::init_early();

    // 注册统一 console 的串口 sink
    let _ = klib::console::register_console(&arch_x86_64::serial::SERIAL_CONSOLE);

    // 触发 Core 阶段（PS/2 键盘、CMOS RTC 时钟、伪设备、Framebuffer）
    DriverHub::init_core();

    // 触发 Devices 阶段（PCI 总线枚举、自动 probe / attach、ATA 硬盘）
    DriverHub::init_devices();

    // 触发 Late 阶段（Ramdisk 等后置虚拟设备）
    DriverHub::init_late();

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

/// 真实显示几何 `(width, height, bpp)`——直接读取 Limine 注册的 framebuffer
/// 描述符，是 `/devices/displays/primary/mode` 的唯一数据源。
/// 未注册（指针为 0）返回 None：调用方必须显式处理缺席，禁止编造缺省分辨率
/// （vfs1 R1 / kernel1 KM12：虚构 1024x768 已废除）。刷新率 Limine 不披露，
/// 不在任何投影中输出。
pub fn framebuffer_geometry() -> Option<(u64, u64, u64)> {
    let p = FRAMEBUFFER_PTR.load(Ordering::Acquire);
    if p == 0 {
        return None;
    }
    // SAFETY：指针来自 init_display 阶段注册的 Limine framebuffer 描述符，
    // bootloader 保证其生命周期覆盖整个内核运行期；此处只读前几个整型字段。
    let fb: &limine::Framebuffer = unsafe { &*(p as *const limine::Framebuffer) };
    Some((fb.width as u64, fb.height as u64, fb.bpp as u64))
}
