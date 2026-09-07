//! VFS 全局实例与系统骨架初始化。
//!
//! 遵循 ADR-005（RESTful 命名）、ADR-011（VFS 架构规范）、ADR-012（存储卷）
//! 与 ADR-013（JSON 第一公民）：
//! - `/`：根内存文件系统（RamFS）
//! - `/processes`：挂载 ProcFS（动态只读 JSON 状态节点）
//! - `/system`：真实可写 RamFS 域目录（ADR-012 swapfile 归属），`/system/info`
//!   挂载 SysFS（CPU、内存、内核信息 JSON）
//! - `/devices`：挂载 DevFS（串口主数据通道、属性子文件、设备列表 JSON）

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use arch::Platform;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;
use spin::Once;

use vfs::devfs::{DevFS, DeviceInfo, DeviceInfoProvider};
use vfs::inode::Permissions;
use vfs::mount::MountTable;
use vfs::procfs::{ProcFS, ProcessInfoProvider, ProcessSnapshot};
use vfs::ramfs::RamFS;
use vfs::sysfs::{SysFS, SystemInfoProvider};

static VFS_ROOT: Once<Arc<MountTable>> = Once::new();

/// 已挂载块设备登记：设备名 → 挂载路径（`try_mount_ext2_volumes` 启动期静态
/// 挂载与 `mount_device_volume` 设备挂载成功时登记，两处同源）。
///
/// 用途：
/// - **幂等（V5/R1）**：`mount_device_volume` 对**同一设备**重复调用返回
///   `AlreadyExists`（按设备名判定，`/volumes/{label}` 被占用不构成拒绝），
///   而非经 `mount_volume` 同名自增消解再挂到 `/volumes/{label}-2` 产生幽灵
///   重复卷。**不同设备同名卷仍走 `mount_volume` 的 -N 冲突消解**（挂到
///   `-2`）——本登记只按设备区分，注释语义与实现一致，不依赖脆弱的 `-N`
///   后缀启发式判断。
/// - **卸载反向**：`sys_volume_unmount` 据路径找回设备并注销登记，使设备可被
///   再次挂载（热插拔往返）。
///
/// **并发诚实**：本登记在启动期（单线程）与用户态 syscall 路径填充。每个
/// `lock()` 临界区（查询/登记/注销）自身都是原子的短操作、无嵌套锁序、无
/// 死锁面；但"查询未挂→挂载→登记"并非整体原子（两进程并发 `mount_device_volume`
/// 同一新设备可能都通过 `is_device_mounted` 检查而重复挂载）。此竞态在**当前
/// 唯一调用方 volumed 顺序驱动**下不可达（对账与事件循环单进程单线程）；若将来
/// 引入第二个并发挂载者，需在 `mount_device_volume` 内把"判幂等+挂载+登记"纳入
/// 同一把锁或引入 per-device 状态机，先成文锁序再编码。
static MOUNTED_DEVICES: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

/// 查询某块设备是否已挂载（`MOUNTED_DEVICES` 登记过）。
pub fn is_device_mounted(name: &str) -> bool {
    MOUNTED_DEVICES.lock().iter().any(|(d, _)| d == name)
}

/// 按挂载路径注销设备登记（`sys_volume_unmount` 调用），使设备可再次挂载。
pub fn unmark_device_by_path(path: &str) {
    MOUNTED_DEVICES.lock().retain(|(_, p)| p != path);
}

/// 获取全局 VFS 挂载表。
pub fn root() -> &'static Arc<MountTable> {
    VFS_ROOT.get().expect("VFS not initialized")
}

/// 内核 ProcFS Provider 实现。
struct KernelProcessProvider;

impl ProcessInfoProvider for KernelProcessProvider {
    fn list_processes(&self) -> Vec<ProcessSnapshot> {
        task::process_snapshots()
    }

    fn get_process(&self, pid: usize) -> Option<ProcessSnapshot> {
        task::get_process_snapshot(pid)
    }
}

/// 内核 SysFS Provider 实现。
struct KernelSystemProvider;

impl SystemInfoProvider for KernelSystemProvider {
    fn cpu_json(&self) -> String {
        use arch::cpu::Cpu as _;
        use arch_x86_64::cpu::X8664Cpu;

        // CPU 信息在 BSP 单线程阶段由 `arch_x86_64::cpu::init()` 经 CPUID 探测并
        // 缓存；SysFS 只投影该缓存，绝不编造厂商或功能位。
        let mut target = klib::json::VecTarget::new();
        let mut writer = klib::json::JsonWriter::new(&mut target);
        let mut object = writer
            .start_object()
            .expect("Vec-backed CPU JSON serialization cannot fail");
        object
            .field_str("arch", crate::CurrentArch::name())
            .expect("Vec-backed CPU JSON serialization cannot fail");
        object
            .field_u64("cores", mm::cpu_count() as u64)
            .expect("Vec-backed CPU JSON serialization cannot fail");
        object
            .field_str("vendor", X8664Cpu::vendor_id())
            .expect("Vec-backed CPU JSON serialization cannot fail");
        object
            .sub_array("features", |features| {
                for feature in arch::cpu::CpuFeature::ALL {
                    if X8664Cpu::has_feature(feature) {
                        features.push_str(feature.name())?;
                    }
                }
                Ok(())
            })
            .expect("Vec-backed CPU JSON serialization cannot fail");
        object
            .end()
            .expect("Vec-backed CPU JSON serialization cannot fail");
        target
            .into_string()
            .expect("CPU vendor and feature names are valid UTF-8")
    }

    fn memory_json(&self) -> String {
        // KM9：与 cpu_json 统一走 JsonWriter（旧 format! 手拼 JSON 是同文件
        // 双风格之一）；页帧字节数取 mm 常量，不再内联 4096/2097152 魔数。
        let total_f = mm::total_frames();
        let stats = mm::frame_stats();
        let total_bytes = total_f as u64 * mm::FRAME_SIZE_BYTES;
        let allocated_bytes = stats.allocated_frames as u64 * mm::FRAME_SIZE_BYTES;
        let free_bytes = total_bytes.saturating_sub(allocated_bytes);
        let mut target = klib::json::VecTarget::new();
        let mut writer = klib::json::JsonWriter::new(&mut target);
        writer
            .start_object()
            .and_then(|mut o| {
                o.field_u64("capacity_bytes", total_bytes)?;
                o.field_u64("allocated_bytes", allocated_bytes)?;
                o.field_u64("free_bytes", free_bytes)?;
                o.field_u64("page_size", mm::FRAME_SIZE_BYTES)?;
                o.field_u64("huge_page_size", mm::HUGE_FRAME_SIZE_BYTES)?;
                o.end()
            })
            .expect("Vec-backed memory JSON serialization cannot fail");
        target
            .into_string()
            .expect("memory JSON keys are ASCII")
    }

    fn kernel_json(&self) -> String {
        // KM9：JsonWriter 统一风格；env! 值经 field_str 自动转义。
        // 构建时间戳是 build.rs 注入的毫秒级十进制数——保持原 JSON 数值类型，
        // 以 const fn 在编译期解析为 u64（非数字输入会在编译期失败，而非
        // 运行时伪造 0）。
        /// 编译期解析十进制时间戳；非数字字节触发编译错误。
        const fn parse_ms(s: &str) -> u64 {
            let bytes = s.as_bytes();
            let mut v = 0u64;
            let mut i = 0;
            while i < bytes.len() {
                assert!(bytes[i].is_ascii_digit(), "non-decimal build timestamp");
                v = v * 10 + (bytes[i] - b'0') as u64;
                i += 1;
            }
            v
        }
        const BUILD_TIMESTAMP_MS: u64 = parse_ms(env!("BORUIX_BUILD_TIMESTAMP"));
        let version = env!("CARGO_PKG_VERSION");
        let commit = env!("BORUIX_GIT_COMMIT");
        let uptime_ms = klib::time::now_millis().unwrap_or(0);
        let mut target = klib::json::VecTarget::new();
        let mut writer = klib::json::JsonWriter::new(&mut target);
        writer
            .start_object()
            .and_then(|mut o| {
                o.field_str("name", "BORUIX")?;
                o.field_str("version", version)?;
                o.field_str("git_commit", commit)?;
                o.field_u64("build_timestamp", BUILD_TIMESTAMP_MS)?;
                o.field_u64("uptime_ms", uptime_ms)?;
                o.end()
            })
            .expect("Vec-backed kernel JSON serialization cannot fail");
        target
            .into_string()
            .expect("kernel JSON keys and env values are UTF-8")
    }

    fn time_json(&self) -> String {
        // 墙钟（真实年月日时分秒）直接来自 CMOS/BIOS 硬件时钟。
        // 唯一实现是 arch 层 `rtc::read_time`（双读一致性校验、UIP 轮询上界、
        // BCD/二进制与 12/24 小时制处理都在那一处，AA1）。本函数只做 JSON 投影。
        let t = arch_x86_64::rtc::read_time();
        let mut target = klib::json::VecTarget::new();
        let mut writer = klib::json::JsonWriter::new(&mut target);
        writer
            .start_object()
            .and_then(|mut o| {
                o.field_u64("year", t.year as u64)?;
                o.field_u64("month", t.month as u64)?;
                o.field_u64("day", t.day as u64)?;
                o.field_u64("hour", t.hour as u64)?;
                o.field_u64("minute", t.minute as u64)?;
                o.field_u64("second", t.second as u64)?;
                o.end()
            })
            .expect("Vec-backed time JSON serialization cannot fail");
        target
            .into_string()
            .expect("time JSON keys are ASCII")
    }
}

/// 内核 DevFS Provider 实现。
struct KernelDeviceProvider;


impl DeviceInfoProvider for KernelDeviceProvider {
    fn list_devices(&self) -> Vec<DeviceInfo> {
        let mut list = Vec::new();
        let count = driver::DriverHub::device_count();
        for i in 0..count {
            if let Some(info) = driver::DriverHub::device_info_at(i) {
                let bus_str = match info.bus {
                    driver::BusType::Pci => "PCI",
                    driver::BusType::Platform => "Platform",
                    driver::BusType::Virtual => "Virtual",
                    driver::BusType::Unknown => "Unknown",
                };
                // DR1a（ADR-022 §1）：绑定状态按注册表真值双态呈现——
                // 真实接管 = "driver:<name>"；竞标胜出但驱动未实现硬件控制
                // = "candidate:<name>(unimplemented)"。用户态可据此编程，
                // 绝不把候选登记伪装成已挂接的驱动。
                let bound = match driver::DriverHub::device_driver_at(i) {
                    Some(driver_name) => {
                        if driver::DriverHub::device_driver_is_candidate(i) {
                            Some(format!("candidate:{}(unimplemented)", driver_name))
                        } else {
                            Some(String::from(driver_name))
                        }
                    }
                    // K4：查不到绑定驱动时如实报 "unbound"，绝不伪造 "attached"
                    // ——绑定状态是用户可见的治理数据，必须来自注册表真值。
                    None => Some(String::from("unbound")),
                };
                let class_val = ((info.class_code as u32) << 16)
                    | ((info.subclass as u32) << 8)
                    | (info.prog_if as u32);
                list.push(DeviceInfo {
                    name: String::from(info.name),
                    bus: String::from(bus_str),
                    class: format!("{:#06x}", class_val),
                    bound_driver: bound,
                    // C15.1：易失性披露直通 DriverHub 注册值，无影子副本。
                    volatile: info.volatile,
                });
            }
        }
        // 设备注册表为空是合法状态；DevFS 必须如实返回空列表，不能伪造设备。
        list
    }

    fn serial_read(&self, buf: &mut [u8]) -> Result<usize, klib::error::Error> {
        use driver::drivers::serial::COM1_DEVICE_NAME;
        if buf.is_empty() {
            return Ok(0);
        }
        let count = driver::DriverHub::device_count();
        for i in 0..count {
            if let Some(info) = driver::DriverHub::device_info_at(i) {
                if info.name == COM1_DEVICE_NAME {
                    if let Some(ops) = driver::DriverHub::device_at(i) {
                        if let Some(io) = ops.as_io() {
                            return Ok(io.read(buf));
                        }
                    }
                }
            }
        }
        // KM8：框架设备缺席不是静默降级的理由——直连 UART 回退必须留下
        // 可见痕迹（首次触发 warn 一次，避免每次 read 刷屏）。
        static FALLBACK_WARNED: AtomicBool = AtomicBool::new(false);
        if !FALLBACK_WARNED.swap(true, Ordering::SeqCst) {
            klib::warn!(
                "[devfs] '{}' not found in DriverHub; falling back to direct UART path",
                COM1_DEVICE_NAME
            );
        }
        if let Some(b) = arch_x86_64::serial::read_byte() {
            buf[0] = b;
            Ok(1)
        } else {
            Ok(0)
        }
    }

    fn serial_write(&self, buf: &[u8]) -> Result<usize, klib::error::Error> {
        use driver::drivers::serial::COM1_DEVICE_NAME;
        let count = driver::DriverHub::device_count();
        for i in 0..count {
            if let Some(info) = driver::DriverHub::device_info_at(i) {
                if info.name == COM1_DEVICE_NAME {
                    if let Some(ops) = driver::DriverHub::device_at(i) {
                        if let Some(io) = ops.as_io() {
                            return Ok(io.write(buf));
                        }
                    }
                }
            }
        }
        // KM8：同 serial_read——回退可见。
        static FALLBACK_WARNED: AtomicBool = AtomicBool::new(false);
        if !FALLBACK_WARNED.swap(true, Ordering::SeqCst) {
            klib::warn!(
                "[devfs] '{}' not found in DriverHub; falling back to direct UART path",
                COM1_DEVICE_NAME
            );
        }
        for &b in buf {
            arch_x86_64::serial::write_byte(b);
        }
        Ok(buf.len())
    }

    fn get_serial_baudrate(&self) -> Result<u32, klib::error::Error> {
        arch_x86_64::serial::get_baudrate()
    }

    fn set_serial_baudrate(&self, baud: u32) -> Result<(), klib::error::Error> {
        arch_x86_64::serial::set_baudrate(baud)
    }

    fn telemetry_json(&self) -> String {
        // K3：本内核不存在设备健康检查子系统，"status":"healthy" 是凭空捏造。
        // 遵循同文件 storage/net 的诚实纪律（DMYGH #16）：只输出真实可得
        // 的事实（注册表计数、运行时长），不编造健康结论。待未来引入真实
        // 健康探测后，status 字段必须由该探测结果驱动。KM9：JsonWriter 风格。
        let count = driver::DriverHub::device_count();
        let drv_count = driver::DriverHub::driver_count();
        let mut target = klib::json::VecTarget::new();
        let mut writer = klib::json::JsonWriter::new(&mut target);
        writer
            .start_object()
            .and_then(|mut o| {
                o.field_u64("total_devices", count as u64)?;
                o.field_u64("total_drivers", drv_count as u64)?;
                o.field_u64("uptime_ms", klib::time::now_millis().unwrap_or(0))?;
                o.end()
            })
            .expect("Vec-backed telemetry JSON serialization cannot fail");
        target
            .into_string()
            .expect("telemetry JSON keys are ASCII")
    }

    fn storage_status_json(&self) -> String {
        // DMYGH #16：主块设备 = 注册表中第一个 Block 类设备（天然兼容 #15
        // 双身份 ata0 / ata0-ramfallback）；计数直读驱动 IoStats，无影子副本。
        // 无设备、无 IO 操作集或无计数来源均输出显式错误，绝不编造健康值。
        // KM9：JsonWriter 统一风格（替代 format! 手拼 + JsonStr 转义）。
        let mut target = klib::json::VecTarget::new();
        let mut writer = klib::json::JsonWriter::new(&mut target);
        let count = driver::DriverHub::device_count();
        for i in 0..count {
            let Some(info) = driver::DriverHub::device_info_at(i) else {
                continue;
            };
            if info.kind != driver::DeviceKind::Block {
                continue;
            }
            let name = info.name;
            let outcome: Result<(), ()> = (|| {
                let Some(ops) = driver::DriverHub::device_at(i) else {
                    return error_object(&mut writer, "no_io_ops", name);
                };
                let Some(io) = ops.as_io() else {
                    return error_object(&mut writer, "no_io_ops", name);
                };
                match io.io_stats() {
                    Some(st) => {
                        let mut obj = writer.start_object()?;
                        obj.field_str("device", name)?;
                        obj.field_bool("volatile", info.volatile)?;
                        obj.field_u64("sectors_read", st.sectors_read())?;
                        obj.field_u64("sectors_written", st.sectors_written())?;
                        obj.end()
                    }
                    None => error_object(&mut writer, "no_counter", name),
                }
            })();
            outcome.expect("Vec-backed storage JSON serialization cannot fail");
            return target
                .into_string()
                .expect("storage JSON keys and device names are UTF-8");
        }
        writer
            .start_object()
            .and_then(|mut o| {
                o.field_str("error", "no_block_device")?;
                o.end()
            })
            .expect("Vec-backed storage JSON serialization cannot fail");
        return target
            .into_string()
            .expect("storage JSON keys are ASCII");

        /// 写入 `{"error":<code>,"device":<name>}` 错误对象（KM9 辅助）。
        fn error_object<T: klib::json::JsonTarget>(
            writer: &mut klib::json::JsonWriter<T>,
            code: &str,
            name: &str,
        ) -> Result<(), ()> {
            let mut obj = writer.start_object()?;
            obj.field_str("error", code)?;
            obj.field_str("device", name)?;
            obj.end()
        }
    }

    /// 真实显示几何直通：唯一数据源是 Limine 注册的 framebuffer 描述符
    /// （drivers::framebuffer_geometry）。缺席时显式报错；刷新率 Limine 不
    /// 披露，宁缺毋假不输出 refresh_hz（vfs1 R1 / KM12：编造的 1024x768@60 已废除）。
    fn display_mode_json(&self) -> String {
        let Some((w, h, bpp)) = crate::drivers::framebuffer_geometry() else {
            return alloc::string::String::from(r#"{"error":"no_display_info"}"#);
        };
        let mut target = klib::json::VecTarget::new();
        let mut writer = klib::json::JsonWriter::new(&mut target);
        writer
            .start_object()
            .and_then(|mut o| {
                o.field_u64("width", w)?;
                o.field_u64("height", h)?;
                o.field_u64("bpp", bpp)?;
                o.end()
            })
            .expect("Vec-backed display mode JSON serialization cannot fail");
        let s = target
            .into_string()
            .expect("display mode JSON keys are ASCII");
        // 行尾换行由 DevFS 读取闭包统一追加（单点契约，审计 #9）——
        // provider 返回裸 JSON，双侧追加即双换行。
        s
    }

    fn net_stats_json(&self) -> String {
        // DMYGH #16：尚无真实 NIC 数据路径。若存在 Net 类设备则如实报告其
        // 统计不受支持；一个都没有则报告 no_net_device。禁止编造收发统计。
        // KM9：JsonWriter 统一风格。
        let count = driver::DriverHub::device_count();
        for i in 0..count {
            if let Some(info) = driver::DriverHub::device_info_at(i) {
                if info.kind == driver::DeviceKind::Net {
                    let mut target = klib::json::VecTarget::new();
                    let mut writer = klib::json::JsonWriter::new(&mut target);
                    writer
                        .start_object()
                        .and_then(|mut o| {
                            o.field_str("error", "nic_stats_unsupported")?;
                            o.field_str("device", info.name)?;
                            o.end()
                        })
                        .expect("Vec-backed net JSON serialization cannot fail");
                    return target
                        .into_string()
                        .expect("net JSON keys and device names are UTF-8");
                }
            }
        }
        String::from(r#"{"error":"no_net_device"}"#)
    }

    fn pci_bars_json(&self, dev_name: &str) -> String {
        // C5.1/#5：经 DriverHub 反查设备名 → PCI 位置。
        // DA3（ADR-022 §4）：BAR 数据只读**扫描期缓存**——本属性文件每次
        // 读取都不再触碰配置空间（inspect_pci_bars 的写全 1 手法对活动
        // 设备是破坏性写，已私有化为扫描期单次执行）。缓存缺席（非扫描期
        // 注册的 PCI 设备）如实报 no_bar_probe，禁止现场补探测或编造空数组。
        let error_json = |code: &str| {
            let mut target = klib::json::VecTarget::new();
            let mut writer = klib::json::JsonWriter::new(&mut target);
            writer
                .start_object()
                .and_then(|mut o| {
                    o.field_str("error", code)?;
                    o.field_str("device", dev_name)?;
                    o.end()
                })
                .expect("Vec-backed pci bars JSON serialization cannot fail");
            target
                .into_string()
                .expect("pci bars JSON keys and device names are UTF-8")
        };
        if driver::DriverHub::pci_location_of(dev_name).is_none() {
            return error_json("not_found");
        }
        let Some(bars) = driver::pci::cached_pci_bars(dev_name) else {
            return error_json("no_bar_probe");
        };
        let mut target = klib::json::VecTarget::new();
        let mut writer = klib::json::JsonWriter::new(&mut target);
        if let Ok(mut arr) = writer.start_array() {
            for (i, bar) in bars.iter().enumerate() {
                match bar {
                    driver::pci::PciBar::IoPort { port, size } => {
                        let _ = arr.push_object(|obj| {
                            let _ = obj.field_u64("bar", i as u64);
                            let _ = obj.field_str("type", "io_port");
                            let _ = obj.field_u64("port", *port as u64);
                            let _ = obj.field_u64("size", *size as u64);
                            Ok(())
                        });
                    }
                    driver::pci::PciBar::Mmio32 {
                        addr,
                        size,
                        prefetchable,
                    } => {
                        let _ = arr.push_object(|obj| {
                            let _ = obj.field_u64("bar", i as u64);
                            let _ = obj.field_str("type", "mmio32");
                            let _ = obj.field_u64("addr", *addr as u64);
                            let _ = obj.field_u64("size", *size as u64);
                            let _ = obj.field_bool("prefetchable", *prefetchable);
                            Ok(())
                        });
                    }
                    driver::pci::PciBar::Mmio64 {
                        addr,
                        size,
                        prefetchable,
                    } => {
                        let _ = arr.push_object(|obj| {
                            let _ = obj.field_u64("bar", i as u64);
                            let _ = obj.field_str("type", "mmio64");
                            let _ = obj.field_u64("addr", *addr);
                            let _ = obj.field_u64("size", *size);
                            let _ = obj.field_bool("prefetchable", *prefetchable);
                            Ok(())
                        });
                    }
                    driver::pci::PciBar::None => {}
                }
            }
            let _ = arr.end();
        }
        // KM9：JsonWriter 只产出 ASCII + 转义串，UTF-8 转换不可能失败；
        // 旧 `unwrap_or("[]")` 会把内部错误静默伪装成空列表，已删除。
        target
            .into_string()
            .expect("pci bars JSON serialization is ASCII-safe")
    }

    // ---- ADR-005/012 /devices/disks 块设备子树 ----

    fn list_disk_names(&self) -> alloc::vec::Vec<alloc::string::String> {
        let mut names = alloc::vec::Vec::new();
        let count = driver::DriverHub::device_count();
        for i in 0..count {
            if let Some(info) = driver::DriverHub::device_info_at(i) {
                if info.kind == driver::DeviceKind::Block {
                    names.push(alloc::string::String::from(info.name));
                }
            }
        }
        names
    }

    fn disk_info_json(&self, name: &str) -> String {
        let count = driver::DriverHub::device_count();
        for i in 0..count {
            let Some(info) = driver::DriverHub::device_info_at(i) else {
                continue;
            };
            if info.name != name || info.kind != driver::DeviceKind::Block {
                continue;
            }
            // 容量必须来自真实 `as_io().size()`；无 IO 操作集或 size 缺席时
            // 显式报 no_capacity，绝不编造容量（S09 宁缺毋假）。
            let Some(ops) = driver::DriverHub::device_at(i) else {
                return disk_error_json("no_io_ops", name);
            };
            let Some(io) = ops.as_io() else {
                return disk_error_json("no_io_ops", name);
            };
            let capacity = io.size();
            let bus_str = match info.bus {
                driver::BusType::Pci => "PCI",
                driver::BusType::Platform => "Platform",
                driver::BusType::Virtual => "Virtual",
                driver::BusType::Unknown => "Unknown",
            };
            let driver = match driver::DriverHub::device_driver_at(i) {
                Some(d) => {
                    if driver::DriverHub::device_driver_is_candidate(i) {
                        alloc::format!("candidate:{}(unimplemented)", d)
                    } else {
                        alloc::string::String::from(d)
                    }
                }
                None => alloc::string::String::from("unbound"),
            };
            let mut target = klib::json::VecTarget::new();
            let mut writer = klib::json::JsonWriter::new(&mut target);
            writer
                .start_object()
                .and_then(|mut o| {
                    o.field_str("name", name)?;
                    o.field_str("bus", bus_str)?;
                    o.field_str("driver", &driver)?;
                    o.field_bool("volatile", info.volatile)?;
                    match capacity {
                        Some(c) => {
                            let _ = o.field_u64("capacity_bytes", c)?;
                        }
                        None => {
                            let _ = o.field_null("capacity_bytes")?;
                        }
                    }
                    o.end()
                })
                .expect("Vec-backed disk info JSON serialization cannot fail");
            return target
                .into_string()
                .expect("disk info JSON keys and device names are UTF-8");
        }
        disk_error_json("not_found", name)
    }

    fn disk_partitions_json(&self, name: &str) -> String {
        let mbr = match read_disk_mbr(name) {
            Ok(m) => m,
            Err(code) => return disk_error_json(code, name),
        };
        let mut target = klib::json::VecTarget::new();
        let mut writer = klib::json::JsonWriter::new(&mut target);
        if let Ok(mut arr) = writer.start_array() {
            for p in mbr.partitions.iter().copied() {
                if p.is_empty() {
                    continue;
                }
                let _ = arr.push_object(|obj| {
                    let _ = obj.field_u64("start_lba", p.start_lba as u64);
                    let _ = obj.field_u64("sector_count", p.sector_count as u64);
                    let _ = obj.field_str("type", &alloc::format!("{:#04x}", p.part_type));
                    let _ = obj.field_bool("bootable", p.boot_flag == 0x80);
                    Ok(())
                });
            }
            let _ = arr.end();
        }
        target
            .into_string()
            .expect("disk partitions JSON serialization is ASCII-safe")
    }

    fn list_disk_partition_ids(&self, name: &str) -> alloc::vec::Vec<alloc::string::String> {
        let mbr = match read_disk_mbr(name) {
            Ok(m) => m,
            Err(_) => return alloc::vec::Vec::new(),
        };
        // 1-based 真实 MBR 槽位序：`partition-1`、`partition-2`（ADR-012 §4）。
        mbr.partitions
            .iter()
            .enumerate()
            .filter(|(_, p)| !p.is_empty())
            .map(|(i, _)| alloc::format!("partition-{}", i + 1))
            .collect()
    }

    fn disk_partition_info_json(&self, name: &str, part_id: &str) -> String {
        let mbr = match read_disk_mbr(name) {
            Ok(m) => m,
            Err(code) => return disk_error_json(code, name),
        };
        // 解析 `partition-{n}`：1-based 真实槽位。
        let idx = match part_id.strip_prefix("partition-") {
            Some(rest) => match rest.parse::<usize>() {
                Ok(n) if n >= 1 && n <= mbr.partitions.len() => n - 1,
                _ => return disk_error_json("not_found", name),
            },
            None => return disk_error_json("not_found", name),
        };
        let p = match mbr.partitions.get(idx) {
            Some(p) if !p.is_empty() => *p,
            _ => return disk_error_json("not_found", name),
        };
        let mut target = klib::json::VecTarget::new();
        let mut writer = klib::json::JsonWriter::new(&mut target);
        writer
            .start_object()
            .and_then(|mut o| {
                o.field_str("device", name)?;
                o.field_str("part", part_id)?;
                o.field_u64("start_lba", p.start_lba as u64)?;
                o.field_u64("sector_count", p.sector_count as u64)?;
                o.field_str("type", &alloc::format!("{:#04x}", p.part_type))?;
                o.field_bool("bootable", p.boot_flag == 0x80)?;
                o.end()
            })
            .expect("Vec-backed partition info JSON serialization cannot fail");
        target
            .into_string()
            .expect("partition info JSON keys and device names are UTF-8")
    }

    fn random_bytes(&self, buf: &mut [u8]) -> Result<usize, klib::error::Error> {
        // 唯一数据源 = arch 熵池（rdseed→rdrand→时钟垫底，诚实披露 source）。
        // 字符流 read 每次返回新随机字节，忽略 offset（由 DevFS 节点保证）。
        arch_x86_64::random::fill_bytes(buf);
        Ok(buf.len())
    }

    fn random_status_json(&self) -> String {
        // S07/S09 宁缺毋假：如实披露熵源与是否密码学安全。时钟垫底是确定性
        // 扰动，不是真随机——绝不让用户态误以为拿到密码学安全熵。
        let src = arch_x86_64::random::source();
        let mut target = klib::json::VecTarget::new();
        let mut writer = klib::json::JsonWriter::new(&mut target);
        writer
            .start_object()
            .and_then(|mut o| {
                o.field_str("source", src.name())?;
                o.field_bool("crypto_safe", src.crypto_safe())?;
                o.end()
            })
            .expect("Vec-backed random status JSON serialization cannot fail");
        target
            .into_string()
            .expect("random status JSON keys are ASCII")
    }
}

/// 统一磁盘错误对象 `{"error":<code>,"device":<name>}`（ADR-012 §4 诚实化：
/// 任何无真实数据源的字段显式报错，绝不编造）。
fn disk_error_json(code: &str, name: &str) -> String {
    let mut target = klib::json::VecTarget::new();
    let mut writer = klib::json::JsonWriter::new(&mut target);
    writer
        .start_object()
        .and_then(|mut o| {
            o.field_str("error", code)?;
            o.field_str("device", name)?;
            o.end()
        })
        .expect("Vec-backed disk error JSON serialization cannot fail");
    target
        .into_string()
        .expect("disk error JSON keys and device names are UTF-8")
}

/// 读块设备 LBA0 并解析真实 MBR（ADR-012 §4 逐分区投影共享半）。
///
/// 出错时返回错误码字符串（`no_io_ops`/`lba0_short_read`/`no_mbr`/`not_found`），
/// 绝不回退到编造分区表（S09 宁缺毋假）。
fn read_disk_mbr(name: &str) -> Result<fs::mbr::Mbr, &'static str> {
    let count = driver::DriverHub::device_count();
    for i in 0..count {
        let Some(info) = driver::DriverHub::device_info_at(i) else {
            continue;
        };
        if info.name != name || info.kind != driver::DeviceKind::Block {
            continue;
        }
        let Some(ops) = driver::DriverHub::device_at(i) else {
            return Err("no_io_ops");
        };
        let Some(io) = ops.as_io() else {
            return Err("no_io_ops");
        };
        let mut sector = [0u8; 512];
        if io.read_at(0, &mut sector) < 512 {
            return Err("lba0_short_read");
        }
        return fs::mbr::parse_mbr(&sector).map_err(|_| "no_mbr");
    }
    Err("not_found")
}

/// 初始化根文件系统并构建默认 RESTful 目录骨架与特殊文件系统挂载（ADR-005 / ADR-011 / ADR-012 / ADR-013）。
pub fn init() {
    // ADR-029 M2.1：boot 来源驱动 root 选择——由启动来源决定根，而非盘里
    // 是否装了系统。ISO 启动 → liveCD（RAMFS 根）；磁盘启动 → 安装模式
    // （启动盘分区为根，/programs 是池内普通目录、无 payload 兜底）。
    let boot = crate::boot_source();
    match boot {
        crate::BootSource::LiveCd | crate::BootSource::Unknown => {
            klib::info!("[boot] liveCD mode (RAMFS root); block devices mount at /volumes/<label>");
            init_livecd();
        }
        crate::BootSource::Disk {
            mbr_disk_id,
            partition_index,
        } => {
            klib::info!(
                "[boot] install mode detected: boot disk mbr_disk_id={:#x} partition_index={}",
                mbr_disk_id,
                partition_index
            );
            // 安装模式：启动盘分区为系统池根。找不到匹配盘（损坏/签名缺失）
            // 如实退化回 liveCD 兜底，绝不伪造安装模式（S09）。
            if !init_install(mbr_disk_id, partition_index) {
                klib::error!(
                    "[boot] boot disk (id={:#x} part={}) not found; falling back to liveCD",
                    mbr_disk_id,
                    partition_index
                );
                init_livecd();
            }
        }
    }
}

/// liveCD 模式：RAMFS 根 + `/programs` 内置 payload + 所有块设备挂 `/volumes`。
fn init_livecd() {
    let ramfs = Arc::new(RamFS::new());
    let mount_table = Arc::new(MountTable::new(ramfs));
    build_skeleton(&mount_table);
    populate_builtin_programs(&mount_table);
    let volumes_mounted = try_mount_ext2_volumes(&mount_table, None);

    VFS_ROOT.call_once(|| mount_table);
    if volumes_mounted {
        klib::info!(
            "[vfs] root RamFS, ProcFS, SysFS, DevFS mounted, /programs = built-in liveCD payload, external disk mounted at /volumes/<label>"
        );
    } else {
        klib::info!(
            "[vfs] root RamFS, ProcFS, SysFS, DevFS mounted, /programs = built-in liveCD payload (no external disk)"
        );
    }
}

/// 安装模式：把启动盘分区（mbr_disk_id + partition_index）的 EXT2 挂为根，
/// `/programs` 是池内普通目录（**不**做内置 payload 兜底，ADR-029 §决策4）。
///
/// 返回 true 表示成功建立安装模式根；false 表示找不到匹配盘（调用方退化
/// liveCD）。骨架目录（/programs /config /system /volumes ...）直接在池上
/// 创建；其余块设备（非启动盘）挂 `/volumes/{label}`。
fn init_install(mbr_disk_id: u32, partition_index: u32) -> bool {
    // 扫描块设备，找 MBR 磁盘签名匹配且分区号匹配的盘。
    let count = driver::DriverHub::device_count();
    for i in 0..count {
        let Some(info) = driver::DriverHub::device_info_at(i) else {
            continue;
        };
        if info.kind != driver::DeviceKind::Block || info.volatile {
            continue;
        }
        let Some(ops) = driver::DriverHub::device_at(i) else {
            continue;
        };
        let bridge: Arc<dyn fs::ByteDevice> = Arc::new(DrvByteBridge(ops));
        let mut sector = [0u8; 512];
        if bridge.read_bytes(0, &mut sector) < 512 {
            continue;
        }
        let Ok(mbr) = fs::mbr::parse_mbr(&sector) else {
            continue;
        };
        // MBR 磁盘签名必须匹配（boot 来源比对，ADR-029 M2.2）。签名为 0 或
        // 不匹配都排除。
        if mbr.disk_signature != mbr_disk_id || mbr.disk_signature == 0 {
            continue;
        }
        // 定位 boot 分区：partition_index 为 0（未分区）时取首分区，否则取
        // 对应 1-based 槽位（本内核 MBR 最多 4 分区，超界即视为不匹配）。
        let part = if partition_index == 0 {
            mbr.first_partition()
        } else if (partition_index as usize) <= fs::mbr::PARTITION_ENTRY_COUNT {
            let p = mbr.partitions[partition_index as usize - 1];
            if p.is_empty() {
                None
            } else {
                Some(p)
            }
        } else {
            None
        };
        let Some(part) = part else {
            continue;
        };
        let part_start_byte = part.start_lba as u64 * 512;
        let Ok(ext2) = fs::ext2::Ext2Fs::open(bridge, part_start_byte) else {
            klib::warn!(
                "[boot] boot partition lba={} is not a valid EXT2; cannot use as root",
                part.start_lba
            );
            continue;
        };
        // 以启动盘 EXT2 为根建立安装模式根。
        let mount_table = Arc::new(MountTable::new(Arc::new(ext2)));
        build_skeleton(&mount_table);
        // ADR-029 §决策4：安装模式 /programs 是池内普通目录，不做内置
        // payload 兜底——盘里没有就是没有。
        klib::info!(
            "[boot] install mode root = '{}' partition lba={} (EXT2), /programs = pool directory (no built-in fallback)",
            info.name,
            part.start_lba
        );
        // 其余块设备（非启动盘）挂 /volumes/{label}；排除已作为 root 的启动盘
        // （按 MBR 磁盘签名，避免系统盘分区被二次挂载，S26/S29）。
        let _volumes = try_mount_ext2_volumes(&mount_table, Some(mbr_disk_id));
        VFS_ROOT.call_once(|| mount_table);
        return true;
    }
    false
}

/// 构建默认 RESTful 顶层目录骨架与特殊文件系统挂载（liveCD 与安装模式共用）。
fn build_skeleton(mount_table: &Arc<vfs::mount::MountTable>) {
    // 构建默认顶层骨架（词法规范 v2，ADR-005：集合目录用复数名词，
    // 域目录用单数物质名词，禁止形容词/缩写）。
    // 幂等语义：骨架目录首次安装/启动时创建并持久化到 root；已安装盘再次
    // 初始化时目录已存在属正常——不可把 AlreadyExists 当故障 panic，否则
    // SDK 预装的 /programs 等内容会在每次重启被重复创建而冲突。
    let ensure_dir = |path: &str| match mount_table.mkdir(path, Permissions::all()) {
        Ok(_) => {}
        Err(klib::error::Error::AlreadyExists) => {}
        Err(e) => panic!("mkdir {}: {:?}", path, e),
    };
    let ensure_link = || match mount_table.symlink("/scratch", "/tmp") {
        Ok(_) => {}
        Err(klib::error::Error::AlreadyExists) => {}
        Err(e) => panic!("symlink /tmp -> /scratch: {:?}", e),
    };
    ensure_dir("/programs");
    ensure_dir("/config");
    ensure_dir("/system");
    ensure_dir("/processes");
    ensure_dir("/devices");
    ensure_dir("/users");
    ensure_dir("/scratch");
    ensure_dir("/volumes");
    // 运行时安装的用户态驱动 ELF 集合目录（与 /programs 系统内置分离；
    // 词法规范 v2 登记于 test_vfs_lexicon LEXICON，ADR-038）。
    ensure_dir("/modules");

    // 词法规范 v2 热路径豁免：官方短别名 /tmp  → 正名 /scratch。
    // 符号链接长期稳定存在，但文档与代码主路径一律写正名。
    ensure_link();

    // 挂载特殊文件系统
    let procfs = Arc::new(ProcFS::new(Arc::new(KernelProcessProvider)));
    mount_table
        .mount("/processes", procfs)
        .expect("mount procfs");

    // `/system` 保持为真实可写 RamFS 域目录（ADR-012 §3 #3：可容纳 swapfile 等
    // 运行时文件）；SysFS 只读 JSON 视图挂载到子目录 `/system/info/`，避免
    // 虚视图遮蔽真实存储归属。
    ensure_dir("/system/info");
    let sysfs = Arc::new(SysFS::new(Arc::new(KernelSystemProvider)));
    mount_table
        .mount("/system/info", sysfs)
        .expect("mount sysfs at /system/info");

    let devfs = Arc::new(DevFS::new(Arc::new(KernelDeviceProvider)));
    mount_table.mount("/devices", devfs).expect("mount devfs");
}

/// liveCD 基线：把构建期嵌入的用户程序 payload（SDK 生成 `binaries_payload.rs`）
/// 写入 ramfs `/programs`——无外部盘时系统仍可启动（ADR-017）。外部盘不再
/// 遮蔽 `/programs`（ADR-028 单源：外部盘改挂 `/volumes/{label}`）。
/// 任一写入失败如实报错并继续（残留部分 payload 会使 init 加载失败可见，
/// 不静默伪装成功）。
fn populate_builtin_programs(mount_table: &Arc<vfs::mount::MountTable>) {
    for p in crate::binaries_payload::PAYLOADS {
        let path = alloc::format!("/programs/{}", p.name);
        let node = match mount_table.create_file(&path, Permissions::readonly()) {
            Ok(n) => n,
            Err(e) => {
                klib::error!("[vfs] built-in payload failed (create {}): {:?}", path, e);
                continue;
            }
        };
        if let Err(e) = node.write_at(0, p.data) {
            klib::error!(
                "[vfs] built-in payload failed (write {} {} bytes): {:?}",
                path,
                p.data.len(),
                e
            );
            continue;
        }
        // KM4 同款纪律：RamFS 写入要么全量要么 Err，但署名长度不符仍须显式
        // 报错——绝不静默把截断的 ELF 当作完整 payload 交给加载器。
        if node.metadata().map(|m| m.size).unwrap_or(0) != p.data.len() as u64 {
            klib::error!(
                "[vfs] built-in payload size mismatch on {}: expected {} got {}",
                path,
                p.data.len(),
                node.metadata().map(|m| m.size).unwrap_or(0)
            );
            continue;
        }
        klib::info!(
            "[vfs] built-in liveCD payload: {} ({} bytes, read-only)",
            p.name,
            p.data.len()
        );
    }
}

/// drv 块设备 → fs::ByteDevice 桥接（M0.2 起提供读写双向；EXT2 只读挂载
/// 阶段只用到读，写路径为 PRE-1 可写 EXT2 的地基）。
struct DrvByteBridge(&'static dyn driver::Device);

impl fs::ByteDevice for DrvByteBridge {
    fn read_bytes(&self, offset: u64, out: &mut [u8]) -> usize {
        self.0.as_io().map(|io| io.read_at(offset, out)).unwrap_or(0)
    }
    /// M0.2：透传 `IoDevice::write_at`。短写/越界如实返回实际写入字节数
    /// （可能 < 请求值或 0），与 [`ByteDevice::write_bytes`] 契约一致——
    /// 绝不把部分写伪装成全量成功。
    fn write_bytes(&self, offset: u64, data: &[u8]) -> usize {
        self.0.as_io().map(|io| io.write_at(offset, data)).unwrap_or(0)
    }
    fn byte_len(&self) -> Option<u64> {
        self.0.as_io().and_then(|io| io.size())
    }
}

/// 尝试从注册表的持久块设备挂载 EXT2 到 `/volumes/{label}`（ADR-028 §决策2）。
///
/// 链路：DriverHub → volatile 拒载（C13.2 前置条件）→ MBR 首分区 →
/// EXT2 超级块校验 → 读卷标（M0.1 `volume_name_str`）→ `mount_volume`。
/// 卷标命名：有卷标挂 `/volumes/{label}`；无卷标降级 `storage-{ShortUUID}`
/// （ShortUUID = FS UUID 前 4 hex，M0.1 `uuid`；UUID 全零则回退到
/// `mount_unnamed_volume` 的确定性 `storage-{seq}`）。
///
/// **单设备失败只淘汰该设备**（KM10 修复）：volatile/短读/MBR/非 EXT2 的
/// 盘被跳过并留下可见日志，全部候选耗尽才返回 false，绝不伪造挂载成功。
///
/// `exclude_boot_disk`：安装模式传入已作为 root 的启动盘 MBR 磁盘签名，遍历时
/// 跳过该盘（S26/S29：启动盘分区已挂为根，不得二次挂到 `/volumes/{label}`）。
/// liveCD 模式（RAMFS 根，无盘作根）传 `None`。
fn try_mount_ext2_volumes(
    mount_table: &Arc<vfs::mount::MountTable>,
    exclude_boot_disk: Option<u32>,
) -> bool {
    let mut any_mounted = false;
    let count = driver::DriverHub::device_count();
    for i in 0..count {
        let Some(info) = driver::DriverHub::device_info_at(i) else {
            continue;
        };
        if info.kind != driver::DeviceKind::Block {
            continue;
        }
        let name = info.name;
        // C13.2 前置条件（#15 评估结论）：易失载体禁止冒充持久文件系统；
        // 该设备不合格，继续考察下一候选。
        if info.volatile {
            klib::warn!(
                "[ext2] skip '{}': volatile=true (data would not survive reboot)",
                name
            );
            continue;
        }
        let Some(ops) = driver::DriverHub::device_at(i) else {
            continue;
        };
        let bridge: Arc<dyn fs::ByteDevice> = Arc::new(DrvByteBridge(ops));
        let mut sector = [0u8; 512];
        if bridge.read_bytes(0, &mut sector) < 512 {
            klib::warn!("[ext2] skip '{}': LBA0 short read, no MBR", name);
            continue;
        }
        let first = match fs::mbr::parse_mbr(&sector) {
            Ok(mbr) => {
                // 安装模式：跳过已作为 root 的启动盘（按 MBR 磁盘签名匹配）。
                // 启动盘签名 0 或与排除值不匹配则继续正常考察。
                if let Some(boot_id) = exclude_boot_disk {
                    if mbr.disk_signature == boot_id {
                        klib::info!(
                            "[ext2] skip '{}': is the boot/root disk (disk_sig={:08X}), not remounted as a volume",
                            name,
                            boot_id
                        );
                        continue;
                    }
                }
                mbr.first_partition()
            }
            Err(e) => {
                klib::warn!("[ext2] skip '{}': MBR parse failed: {:?}", name, e);
                continue;
            }
        };
        let Some(part) = first else {
            klib::warn!("[ext2] skip '{}': no MBR partition entries", name);
            continue;
        };
        let part_start_byte = part.start_lba as u64 * 512;
        let ext2 = match fs::ext2::Ext2Fs::open(bridge, part_start_byte) {
            Ok(f) => f,
            Err(e) => {
                klib::warn!(
                    "[ext2] skip '{}': partition lba={} is not a valid EXT2: {:?}",
                    name,
                    part.start_lba,
                    e
                );
                continue;
            }
        };
        // M0.1：卷标命名——有卷标挂 /volumes/{label}；无卷标降级
        // storage-{ShortUUID}（FS UUID 前 4 hex）。非 UTF-8 卷标按无卷标
        // 处理（S02：不 lossy 篡改，如实降级）。`Ext2Superblock` 为 Copy，
        // 取值副本后即可安全 move `ext2`。
        let sb = *ext2.superblock();
        let mount_result = match sb.volume_name_str() {
            Some(label) if !label.is_empty() => mount_table.mount_volume(label, Arc::new(ext2)),
            Some(_) | None => {
                // 无卷标（空串）或非 UTF-8：降级命名。
                if !sb.uuid_is_zero() {
                    let short = alloc::format!(
                        "storage-{:02x}{:02x}",
                        sb.uuid[0], sb.uuid[1]
                    );
                    mount_table.mount_volume(&short, Arc::new(ext2))
                } else {
                    // 无 UUID 源：确定性 storage-{seq}（不伪造硬件身份）。
                    mount_table.mount_unnamed_volume(None, Arc::new(ext2))
                }
            }
        };
        match mount_result {
            Ok(final_path) => {
                klib::info!(
                    "[ext2] mounted '{}' partition start_lba={} at {} (writable)",
                    name,
                    part.start_lba,
                    final_path
                );
                // 登记设备→挂载路径（与 mount_device_volume 同源），使后续
                // volumed 对同一设备幂等跳过、对"不同设备同名卷"走 -N 消解。
                MOUNTED_DEVICES.lock().push((String::from(name), final_path));
                any_mounted = true;
            }
            // mount 点被占等全局性失败与设备无关，记录后继续考察下一候选。
            Err(e) => {
                klib::error!("[ext2] mount volume for '{}' failed: {:?}", name, e);
            }
        }
    }
    if !any_mounted {
        klib::warn!("[ext2] no mountable persistent block device; /volumes remains empty");
    }
    any_mounted
}

/// 按块设备名把其首分区的 EXT2 挂载到 `/volumes/{label}`（M4.2 `VOLUME_MOUNT`）。
///
/// 与 [`try_mount_ext2_volumes`] 同链路（volatile 拒载 → MBR 首分区 → EXT2 校验
/// → 卷标命名 → `mount_volume`），但只针对**指定名字**的单块设备，并把失败
/// 如实映射为 `vfs::Error`（供 syscall `pack_err` 上抛），不吞错。
///
/// 找不到设备 → `NotFound`；MBR 缺失/损坏 → `Corrupt`；非 EXT2 → `NotSupported`；
/// 卷标命名冲突由 `mount_volume` 自增消解并返回最终路径。
pub fn mount_device_volume(name: &str) -> Result<String, klib::error::Error> {
    // 同一设备幂等（V5/R1）：若该设备已挂载（`MOUNTED_DEVICES` 登记，含启动期
    // 静态挂载与先前 volumed 挂载），**返回已有挂载路径**（而非报 AlreadyExists）——
    // 使 volumed 对账时能拿到 boot-time 静态挂载卷的真实路径并加入追踪，从而在
    // 设备拔除（`DeviceDeparted`）时能卸载对应卷（ADR-030 热插拔闭环 P2-2）。
    // 幂等性保持：同一设备不产生第二挂载点。
    if is_device_mounted(name) {
        if let Some((_, path)) = MOUNTED_DEVICES
            .lock()
            .iter()
            .find(|(d, _)| d == name)
            .cloned()
        {
            return Ok(path);
        }
        // 登记表有设备名但无路径（异常态）：如实报 AlreadyExists，不伪造路径。
        return Err(klib::error::Error::AlreadyExists);
    }
    let count = driver::DriverHub::device_count();
    for i in 0..count {
        let Some(info) = driver::DriverHub::device_info_at(i) else {
            continue;
        };
        if info.kind != driver::DeviceKind::Block || info.name != name {
            continue;
        }
        // C13.2 前置条件：易失载体禁止冒充持久文件系统。
        if info.volatile {
            return Err(klib::error::Error::ReadOnly);
        }
        let Some(ops) = driver::DriverHub::device_at(i) else {
            return Err(klib::error::Error::NotFound);
        };
        let bridge: Arc<dyn fs::ByteDevice> = Arc::new(DrvByteBridge(ops));
        let mut sector = [0u8; 512];
        if bridge.read_bytes(0, &mut sector) < 512 {
            return Err(klib::error::Error::Corrupt);
        }
        let first = fs::mbr::parse_mbr(&sector)
            .map_err(|_| klib::error::Error::Corrupt)?
            .first_partition()
            .ok_or(klib::error::Error::Corrupt)?;
        let part_start_byte = first.start_lba as u64 * 512;
        let ext2 = fs::ext2::Ext2Fs::open(bridge, part_start_byte)
            .map_err(|_| klib::error::Error::NotSupported)?;
        let sb = *ext2.superblock();
        let mount_table = root();
        let result = match sb.volume_name_str() {
            Some(label) if !label.is_empty() => {
                mount_table.mount_volume(label, Arc::new(ext2))
            }
            Some(_) | None => {
                if !sb.uuid_is_zero() {
                    let short = alloc::format!("storage-{:02x}{:02x}", sb.uuid[0], sb.uuid[1]);
                    mount_table.mount_volume(&short, Arc::new(ext2))
                } else {
                    mount_table.mount_unnamed_volume(None, Arc::new(ext2))
                }
            }
        };
        // 挂载成功才登记（设备名 → 真实路径），卸载据路径反向注销。
        if let Ok(final_path) = &result {
            MOUNTED_DEVICES
                .lock()
                .push((String::from(name), final_path.clone()));
        }
        return result;
    }
    Err(klib::error::Error::NotFound)
}
