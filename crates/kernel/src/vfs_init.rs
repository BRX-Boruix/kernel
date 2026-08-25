//! VFS 全局实例与系统骨架初始化。
//!
//! 遵循 ADR-005（RESTful 命名）、ADR-011（VFS 架构规范）、ADR-012（存储卷）
//! 与 ADR-013（JSON 第一公民）：
//! - `/`：根内存文件系统（RamFS）
//! - `/processes`：挂载 ProcFS（动态只读 JSON 状态节点）
//! - `/system`：挂载 SysFS（CPU、内存、内核信息 JSON）
//! - `/devices`：挂载 DevFS（串口主数据通道、属性子文件、设备列表 JSON）

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use arch::Platform;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Once;

use vfs::devfs::{DevFS, DeviceInfo, DeviceInfoProvider};
use vfs::inode::Permissions;
use vfs::mount::MountTable;
use vfs::procfs::{ProcFS, ProcessInfoProvider, ProcessSnapshot};
use vfs::ramfs::RamFS;
use vfs::sysfs::{SysFS, SystemInfoProvider};

static VFS_ROOT: Once<Arc<MountTable>> = Once::new();

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
        let uptime_ms = klib::time::now_millis();
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
}

/// 内核 DevFS Provider 实现。
struct KernelDeviceProvider;


impl DeviceInfoProvider for KernelDeviceProvider {
    fn list_devices(&self) -> Vec<DeviceInfo> {
        let mut list = Vec::new();
        let count = drv::DriverHub::device_count();
        for i in 0..count {
            if let Some(info) = drv::DriverHub::device_info_at(i) {
                let bus_str = match info.bus {
                    drv::BusType::Pci => "PCI",
                    drv::BusType::Platform => "Platform",
                    drv::BusType::Virtual => "Virtual",
                    drv::BusType::Unknown => "Unknown",
                };
                // DR1a（ADR-022 §1）：绑定状态按注册表真值双态呈现——
                // 真实接管 = "driver:<name>"；竞标胜出但驱动未实现硬件控制
                // = "candidate:<name>(unimplemented)"。用户态可据此编程，
                // 绝不把候选登记伪装成已挂接的驱动。
                let bound = match drv::DriverHub::device_driver_at(i) {
                    Some(driver_name) => {
                        if drv::DriverHub::device_driver_is_candidate(i) {
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
        use drv::drivers::serial::COM1_DEVICE_NAME;
        if buf.is_empty() {
            return Ok(0);
        }
        let count = drv::DriverHub::device_count();
        for i in 0..count {
            if let Some(info) = drv::DriverHub::device_info_at(i) {
                if info.name == COM1_DEVICE_NAME {
                    if let Some(ops) = drv::DriverHub::device_at(i) {
                        return Ok(ops.read(buf));
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
        use drv::drivers::serial::COM1_DEVICE_NAME;
        let count = drv::DriverHub::device_count();
        for i in 0..count {
            if let Some(info) = drv::DriverHub::device_info_at(i) {
                if info.name == COM1_DEVICE_NAME {
                    if let Some(ops) = drv::DriverHub::device_at(i) {
                        return Ok(ops.write(buf));
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
        let count = drv::DriverHub::device_count();
        let drv_count = drv::DriverHub::driver_count();
        let mut target = klib::json::VecTarget::new();
        let mut writer = klib::json::JsonWriter::new(&mut target);
        writer
            .start_object()
            .and_then(|mut o| {
                o.field_u64("total_devices", count as u64)?;
                o.field_u64("total_drivers", drv_count as u64)?;
                o.field_u64("uptime_ms", klib::time::now_millis())?;
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
        let count = drv::DriverHub::device_count();
        for i in 0..count {
            let Some(info) = drv::DriverHub::device_info_at(i) else {
                continue;
            };
            if info.kind != drv::DeviceKind::Block {
                continue;
            }
            let name = info.name;
            let outcome: Result<(), ()> = (|| {
                let Some(ops) = drv::DriverHub::device_at(i) else {
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
        let count = drv::DriverHub::device_count();
        for i in 0..count {
            if let Some(info) = drv::DriverHub::device_info_at(i) {
                if info.kind == drv::DeviceKind::Net {
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
        if drv::DriverHub::pci_location_of(dev_name).is_none() {
            return error_json("not_found");
        }
        let Some(bars) = drv::pci::cached_pci_bars(dev_name) else {
            return error_json("no_bar_probe");
        };
        let mut target = klib::json::VecTarget::new();
        let mut writer = klib::json::JsonWriter::new(&mut target);
        if let Ok(mut arr) = writer.start_array() {
            for (i, bar) in bars.iter().enumerate() {
                match bar {
                    drv::pci::PciBar::IoPort { port, size } => {
                        let _ = arr.push_object(|obj| {
                            let _ = obj.field_u64("bar", i as u64);
                            let _ = obj.field_str("type", "io_port");
                            let _ = obj.field_u64("port", *port as u64);
                            let _ = obj.field_u64("size", *size as u64);
                            Ok(())
                        });
                    }
                    drv::pci::PciBar::Mmio32 {
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
                    drv::pci::PciBar::Mmio64 {
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
                    drv::pci::PciBar::None => {}
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
}

/// 初始化根文件系统并构建默认 RESTful 目录骨架与特殊文件系统挂载（ADR-005 / ADR-011 / ADR-012 / ADR-013）。
pub fn init() {
    let ramfs = Arc::new(RamFS::new());
    let mount_table = Arc::new(MountTable::new(ramfs));

    // 构建默认顶层骨架（全称 RESTful 集合）
    mount_table
        .mkdir("/binaries", Permissions::all())
        .expect("mkdir /binaries");
    mount_table
        .mkdir("/config", Permissions::all())
        .expect("mkdir /config");
    mount_table
        .mkdir("/system", Permissions::all())
        .expect("mkdir /system");
    mount_table
        .mkdir("/processes", Permissions::all())
        .expect("mkdir /processes");
    mount_table
        .mkdir("/devices", Permissions::all())
        .expect("mkdir /devices");
    mount_table
        .mkdir("/users", Permissions::all())
        .expect("mkdir /users");
    mount_table
        .mkdir("/temporary", Permissions::all())
        .expect("mkdir /temporary");
    mount_table
        .mkdir("/volumes", Permissions::all())
        .expect("mkdir /volumes");

    // 挂载特殊文件系统
    let procfs = Arc::new(ProcFS::new(Arc::new(KernelProcessProvider)));
    mount_table
        .mount("/processes", procfs)
        .expect("mount procfs");

    let sysfs = Arc::new(SysFS::new(Arc::new(KernelSystemProvider)));
    mount_table.mount("/system", sysfs).expect("mount sysfs");

    let devfs = Arc::new(DevFS::new(Arc::new(KernelDeviceProvider)));
    mount_table.mount("/devices", devfs).expect("mount devfs");

    // ADR-017（liveCD 回归）：先以构建期内置 payload 填充 ramfs /binaries
    // （无外部盘也可启动），随后尝试挂载外部盘 EXT2 —— 挂载成功即整体覆盖
    // 内置（盘优先，U 盘上放新版/测试程序可生效）。两源皆缺时 /binaries
    // 保持空目录，init 加载将显式失败并可见，绝不伪造成功。
    populate_builtin_binaries(&mount_table);
    let disk_mounted = try_mount_ext2_binaries(&mount_table);

    VFS_ROOT.call_once(|| mount_table);
    if disk_mounted {
        klib::info!(
            "[vfs] root RamFS, ProcFS, SysFS, DevFS mounted, /binaries = EXT2 (external disk overrides built-in)"
        );
    } else {
        klib::info!(
            "[vfs] root RamFS, ProcFS, SysFS, DevFS mounted, /binaries = built-in liveCD payload (no external disk)"
        );
    }
}

/// liveCD 基线：把构建期嵌入的用户程序 payload（SDK 生成 `binaries_payload.rs`）
/// 写入 ramfs `/binaries`——无外部盘时系统仍可启动（ADR-017）。外部盘随后
/// 经 [`try_mount_ext2_binaries`] 挂载时以 mount 语义整体覆盖（盘优先）。
/// 任一写入失败如实报错并继续（残留部分 payload 会使 init 加载失败可见，
/// 不静默伪装成功）。
fn populate_builtin_binaries(mount_table: &Arc<vfs::mount::MountTable>) {
    for p in crate::binaries_payload::PAYLOADS {
        let path = alloc::format!("/binaries/{}", p.name);
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

/// drv 块设备 → fs::ByteDevice 桥接（只读路径足够；EXT2 驱动本身只读）。
struct DrvByteBridge(&'static dyn drv::DeviceOps);

impl fs::ByteDevice for DrvByteBridge {
    fn read_bytes(&self, offset: u64, out: &mut [u8]) -> usize {
        self.0.as_io().map(|io| io.read_at(offset, out)).unwrap_or(0)
    }
    fn byte_len(&self) -> Option<u64> {
        self.0.as_io().and_then(|io| io.size())
    }
}

/// 尝试从注册表的持久块设备挂载 EXT2 到 /binaries（C13.1+C13.2+#13）。
///
/// 链路：DriverHub → volatile 拒载（C13.2 前置条件）→ MBR 首分区 →
/// EXT2 超级块校验 → mount。**单设备失败只淘汰该设备**（KM10 修复：原实现
/// 在 volatile/短读/MBR 失败时直接 `return false`，放弃全部后续候选——一旦
/// 未来出现"第一块易失 + 第二块持久"的注册顺序，持久盘将被静默跳过），
/// 全部候选耗尽才返回 false 并留下可见日志，绝不伪造挂载成功。
fn try_mount_ext2_binaries(mount_table: &Arc<vfs::mount::MountTable>) -> bool {
    let count = drv::DriverHub::device_count();
    for i in 0..count {
        let Some(info) = drv::DriverHub::device_info_at(i) else {
            continue;
        };
        if info.kind != drv::DeviceKind::Block {
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
        let Some(ops) = drv::DriverHub::device_at(i) else {
            continue;
        };
        let bridge: Arc<dyn fs::ByteDevice> = Arc::new(DrvByteBridge(ops));
        let mut sector = [0u8; 512];
        if bridge.read_bytes(0, &mut sector) < 512 {
            klib::warn!("[ext2] skip '{}': LBA0 short read, no MBR", name);
            continue;
        }
        let first = match fs::mbr::parse_mbr(&sector) {
            Ok(mbr) => mbr.first_partition(),
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
        match mount_table.mount("/binaries", Arc::new(ext2)) {
            Ok(()) => {
                klib::info!(
                    "[ext2] mounted '{}' partition start_lba={} at /binaries (read-only)",
                    name,
                    part.start_lba
                );
                return true;
            }
            // mount 点被占等全局性失败与设备无关，直接终止。
            Err(e) => {
                klib::error!("[ext2] mount /binaries failed: {:?}", e);
                return false;
            }
        }
    }
    klib::warn!("[ext2] no mountable persistent block device; built-in liveCD payload remains active");
    false
}
