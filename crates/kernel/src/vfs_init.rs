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
        let total_f = mm::total_frames();
        let stats = mm::frame_stats();
        let total_bytes = total_f as u64 * 4096;
        let allocated_bytes = stats.allocated_frames as u64 * 4096;
        let free_bytes = total_bytes.saturating_sub(allocated_bytes);
        format!(
            r#"{{"capacity_bytes":{},"allocated_bytes":{},"free_bytes":{},"page_size":4096,"huge_page_size":2097152}}"#,
            total_bytes, allocated_bytes, free_bytes
        )
    }

    fn kernel_json(&self) -> String {
        let version = env!("CARGO_PKG_VERSION");
        let commit = env!("BORUIX_GIT_COMMIT");
        let timestamp = env!("BORUIX_BUILD_TIMESTAMP");
        let uptime_ms = klib::time::now_millis();
        format!(
            r#"{{"name":"BORUIX","version":"{}","git_commit":"{}","build_timestamp":{},"uptime_ms":{}}}"#,
            version, commit, timestamp, uptime_ms
        )
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
                let bound = drv::DriverHub::device_driver_at(i)
                    .map(|s| String::from(s))
                    .or(Some(String::from("attached")));
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
        if buf.is_empty() {
            return Ok(0);
        }
        let count = drv::DriverHub::device_count();
        for i in 0..count {
            if let Some(info) = drv::DriverHub::device_info_at(i) {
                if info.name == "serial-com1" {
                    if let Some(ops) = drv::DriverHub::device_at(i) {
                        return Ok(ops.read(buf));
                    }
                }
            }
        }
        if let Some(b) = arch_x86_64::serial::read_byte() {
            buf[0] = b;
            Ok(1)
        } else {
            Ok(0)
        }
    }

    fn serial_write(&self, buf: &[u8]) -> Result<usize, klib::error::Error> {
        let count = drv::DriverHub::device_count();
        for i in 0..count {
            if let Some(info) = drv::DriverHub::device_info_at(i) {
                if info.name == "serial-com1" {
                    if let Some(ops) = drv::DriverHub::device_at(i) {
                        return Ok(ops.write(buf));
                    }
                }
            }
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
        let count = drv::DriverHub::device_count();
        let drv_count = drv::DriverHub::driver_count();
        format!(
            r#"{{"status":"healthy","total_devices":{},"total_drivers":{},"uptime_ms":{}}}"#,
            count,
            drv_count,
            klib::time::now_millis()
        )
    }

    fn storage_status_json(&self) -> String {
        // DMYGH #16：主块设备 = 注册表中第一个 Block 类设备（天然兼容 #15
        // 双身份 ata0 / ata0-ramfallback）；计数直读驱动 IoStats，无影子副本。
        // 无设备、无 IO 操作集或无计数来源均输出显式错误，绝不编造健康值。
        let count = drv::DriverHub::device_count();
        for i in 0..count {
            let Some(info) = drv::DriverHub::device_info_at(i) else {
                continue;
            };
            if info.kind != drv::DeviceKind::Block {
                continue;
            }
            let name = info.name;
            let Some(ops) = drv::DriverHub::device_at(i) else {
                return format!(r#"{{"error":"no_io_ops","device":"{}"}}"#, name);
            };
            let Some(io) = ops.as_io() else {
                return format!(r#"{{"error":"no_io_ops","device":"{}"}}"#, name);
            };
            return match io.io_stats() {
                Some(st) => format!(
                    r#"{{"device":"{}","volatile":{},"sectors_read":{},"sectors_written":{}}}"#,
                    name,
                    info.volatile,
                    st.sectors_read(),
                    st.sectors_written()
                ),
                None => format!(r#"{{"error":"no_counter","device":"{}"}}"#, name),
            };
        }
        String::from(r#"{"error":"no_block_device"}"#)
    }

    fn net_stats_json(&self) -> String {
        // DMYGH #16：尚无真实 NIC 数据路径。若存在 Net 类设备则如实报告其
        // 统计不受支持；一个都没有则报告 no_net_device。禁止编造收发统计。
        let count = drv::DriverHub::device_count();
        for i in 0..count {
            if let Some(info) = drv::DriverHub::device_info_at(i) {
                if info.kind == drv::DeviceKind::Net {
                    return format!(
                        r#"{{"error":"nic_stats_unsupported","device":"{}"}}"#,
                        info.name
                    );
                }
            }
        }
        String::from(r#"{"error":"no_net_device"}"#)
    }

    fn pci_bars_json(&self, dev_name: &str) -> String {
        // C5.1/#5：经 DriverHub 反查设备名 → PCI 位置 → inspect_pci_bars。
        // 不存在或非 PCI 设备返回错误 JSON，禁止回退到固定设备。
        let (bus, device, function) = match drv::DriverHub::pci_location_of(dev_name) {
            Some(loc) => loc,
            None => {
                return format!(
                    r#"{{"error":"not_found","device":"{}"}}"#,
                    dev_name
                );
            }
        };
        let bars = drv::pci::inspect_pci_bars(bus, device, function);
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
        let bytes = target.into_bytes();
        let s = core::str::from_utf8(&bytes).unwrap_or("[]");
        String::from(s)
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

    // M13/#13：真实磁盘链路——EXT2 挂载到 /binaries。挂载失败时 /binaries
    // 保持空目录，init 加载将显式失败并可见；绝不回退到编译期嵌入副本。
    let disk_mounted = try_mount_ext2_binaries(&mount_table);

    VFS_ROOT.call_once(|| mount_table);
    if disk_mounted {
        klib::info!("[vfs] root RamFS, ProcFS, SysFS, DevFS mounted, /binaries = EXT2(ata0)");
    } else {
        klib::info!("[vfs] root RamFS, ProcFS, SysFS, DevFS mounted, /binaries EMPTY (no persistent disk)");
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

/// 尝试从注册表首个持久块设备挂载 EXT2 到 /binaries（C13.1+C13.2+#13）。
///
/// 链路：DriverHub → volatile 拒载（C13.2 前置条件）→ MBR 首分区 →
/// EXT2 超级块校验 → mount。任何一步失败都返回 false 并留下可见日志，
/// 绝不伪造挂载成功。
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
        // C13.2 前置条件（#15 评估结论）：易失载体禁止冒充持久文件系统。
        if info.volatile {
            klib::warn!(
                "[ext2] refuse to mount '{}' as EXT2 backing: volatile=true (data would not survive reboot)",
                name
            );
            return false;
        }
        let Some(ops) = drv::DriverHub::device_at(i) else {
            continue;
        };
        let bridge: Arc<dyn fs::ByteDevice> = Arc::new(DrvByteBridge(ops));
        let mut sector = [0u8; 512];
        if bridge.read_bytes(0, &mut sector) < 512 {
            klib::warn!("[ext2] '{}' LBA0 short read, no MBR", name);
            return false;
        }
        let first = match fs::mbr::parse_mbr(&sector) {
            Ok(mbr) => mbr.first_partition(),
            Err(e) => {
                klib::warn!("[ext2] '{}' MBR parse failed: {:?}", name, e);
                return false;
            }
        };
        let Some(part) = first else {
            klib::warn!("[ext2] '{}' has no MBR partition entries", name);
            return false;
        };
        let part_start_byte = part.start_lba as u64 * 512;
        let ext2 = match fs::ext2::Ext2Fs::open(bridge, part_start_byte) {
            Ok(f) => f,
            Err(e) => {
                klib::warn!(
                    "[ext2] '{}' partition lba={} is not a valid EXT2: {:?}",
                    name,
                    part.start_lba,
                    e
                );
                return false;
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
            Err(e) => {
                klib::error!("[ext2] mount /binaries failed: {:?}", e);
                return false;
            }
        }
    }
    klib::warn!("[ext2] no persistent block device registered; /binaries stays empty");
    false
}
