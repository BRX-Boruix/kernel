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
        drv::with_registry(|reg| {
            reg.for_each_device(|dev| {
                let id = dev.id();
                let bus_str = match id.bus {
                    drv::BusType::Pci => "PCI",
                    drv::BusType::System => "System",
                    drv::BusType::Serial => "Serial",
                    drv::BusType::Ps2 => "PS2",
                    drv::BusType::Framebuffer => "Framebuffer",
                    drv::BusType::Acpi => "ACPI",
                };
                let bound = if reg.is_bound(dev) {
                    Some(String::from("attached"))
                } else {
                    None
                };
                list.push(DeviceInfo {
                    name: String::from(dev.name()),
                    bus: String::from(bus_str),
                    class: format!("{:#06x}", id.class),
                    bound_driver: bound,
                });
            });
        });
        if list.is_empty() {
            list.push(DeviceInfo {
                name: String::from("serial-com1"),
                bus: String::from("Serial"),
                class: String::from("UART"),
                bound_driver: Some(String::from("uart16550")),
            });
        }
        list
    }

    fn serial_read(&self, buf: &mut [u8]) -> Result<usize, klib::error::Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        if let Some(b) = arch_x86_64::serial::read_byte() {
            buf[0] = b;
            Ok(1)
        } else {
            Ok(0)
        }
    }

    fn serial_write(&self, buf: &[u8]) -> Result<usize, klib::error::Error> {
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

    VFS_ROOT.call_once(|| mount_table);
    klib::info!("[vfs] root RamFS, ProcFS, SysFS, DevFS mounted successfully");
}
