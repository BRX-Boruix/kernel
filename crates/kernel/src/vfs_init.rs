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
use vfs::procfs::{ProcessInfoProvider, ProcessSnapshot, ProcFS};
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
        crate::scheduler::process_snapshots()
    }

    fn get_process(&self, pid: usize) -> Option<ProcessSnapshot> {
        crate::scheduler::get_process_snapshot(pid)
    }
}

/// 内核 SysFS Provider 实现。
struct KernelSystemProvider;

impl SystemInfoProvider for KernelSystemProvider {
    fn cpu_json(&self) -> String {
        let arch_name = crate::CurrentArch::name();
        let cores = mm::cpu_count();
        format!(
            r#"{{"arch":"{}","cores":{},"vendor":"GenuineIntel","features":["smap","smep","syscall","xsave"]}}"#,
            arch_name, cores
        )
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
                let bound = drv::DriverHub::device_driver_at(i).map(|s| String::from(s)).or(Some(String::from("attached")));
                let class_val = ((info.class_code as u32) << 16) | ((info.subclass as u32) << 8) | (info.prog_if as u32);
                list.push(DeviceInfo {
                    name: String::from(info.name),
                    bus: String::from(bus_str),
                    class: format!("{:#06x}", class_val),
                    bound_driver: bound,
                });
            }
        }
        if list.is_empty() {
            list.push(DeviceInfo {
                name: String::from("serial-com1"),
                bus: String::from("Serial"),
                class: String::from("UART"),
                bound_driver: Some(String::from("attached")),
            });
        }
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

    fn get_serial_baudrate(&self) -> u32 {
        115200
    }

    fn set_serial_baudrate(&self, _baud: u32) -> Result<(), klib::error::Error> {
        Ok(())
    }

    fn telemetry_json(&self) -> String {
        let count = drv::DriverHub::device_count();
        let drv_count = drv::DriverHub::driver_count();
        format!(
            r#"{{"status":"healthy","total_devices":{},"total_drivers":{},"uptime_ms":{}}}"#,
            count, drv_count, klib::time::now_millis()
        )
    }

    fn pci_bars_json(&self, _dev_name: &str) -> String {
        let bars = drv::pci::inspect_pci_bars(0, 1, 1); // IDE controller at 00:01.1
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
                    drv::pci::PciBar::Mmio32 { addr, size, prefetchable } => {
                        let _ = arr.push_object(|obj| {
                            let _ = obj.field_u64("bar", i as u64);
                            let _ = obj.field_str("type", "mmio32");
                            let _ = obj.field_u64("addr", *addr as u64);
                            let _ = obj.field_u64("size", *size as u64);
                            let _ = obj.field_bool("prefetchable", *prefetchable);
                            Ok(())
                        });
                    }
                    drv::pci::PciBar::Mmio64 { addr, size, prefetchable } => {
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
    mount_table.mkdir("/binaries", Permissions::all()).expect("mkdir /binaries");
    mount_table.mkdir("/config", Permissions::all()).expect("mkdir /config");
    mount_table.mkdir("/system", Permissions::all()).expect("mkdir /system");
    mount_table.mkdir("/processes", Permissions::all()).expect("mkdir /processes");
    mount_table.mkdir("/devices", Permissions::all()).expect("mkdir /devices");
    mount_table.mkdir("/users", Permissions::all()).expect("mkdir /users");
    mount_table.mkdir("/temporary", Permissions::all()).expect("mkdir /temporary");
    mount_table.mkdir("/volumes", Permissions::all()).expect("mkdir /volumes");

    // 挂载特殊文件系统
    let procfs = Arc::new(ProcFS::new(Arc::new(KernelProcessProvider)));
    mount_table.mount("/processes", procfs).expect("mount procfs");

    let sysfs = Arc::new(SysFS::new(Arc::new(KernelSystemProvider)));
    mount_table.mount("/system", sysfs).expect("mount sysfs");

    let devfs = Arc::new(DevFS::new(Arc::new(KernelDeviceProvider)));
    mount_table.mount("/devices", devfs).expect("mount devfs");

    // M6.4：将内核可执行程序装入 /binaries 虚拟目录（VFS 直接加载支持）
    if let Ok(init_node) = mount_table.create_file("/binaries/init.elf", Permissions::read_exec()) {
        let _ = init_node.write_at(0, include_bytes!("../init.elf"));
    }
    if let Ok(shell_node) = mount_table.create_file("/binaries/shell.elf", Permissions::read_exec()) {
        let _ = shell_node.write_at(0, include_bytes!("../shell.elf"));
    }

    VFS_ROOT.call_once(|| mount_table);
    klib::info!("[vfs] root RamFS, ProcFS, SysFS, DevFS mounted, /binaries populated");
}
