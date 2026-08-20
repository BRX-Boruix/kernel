//! BORUIX 虚拟文件系统（VFS）。
//!
//! 遵循 ADR-005（RESTful 命名）、ADR-011（VFS 架构规范）与 ADR-012（存储卷）。

#![no_std]

#[cfg(test)]
extern crate std;

extern crate alloc;

pub mod devfs;
pub mod dynamic;
pub mod file_handle;
pub mod inode;
pub mod mount;
pub mod path;
pub mod procfs;
pub mod ramfs;
pub mod sysfs;

pub use devfs::{DevFS, DeviceInfo, DeviceInfoProvider};
pub use dynamic::{DynamicDirNode, DynamicFileNode};
pub use file_handle::{FileHandle, OpenFlags};
pub use inode::{DirEntry, FileMetadata, FileSystem, INode, INodeType, Permissions};
pub use mount::MountTable;
pub use path::Path;
pub use procfs::{ProcessInfoProvider, ProcessSnapshot, ProcFS};
pub use sysfs::{SysFS, SystemInfoProvider};
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use crate::file_handle::{FileHandle, OpenFlags, SeekWhence};
    use crate::inode::{INodeType, Permissions};
    use crate::mount::MountTable;
    use crate::path::Path;
    use crate::ramfs::RamFS;
    use klib::error::Error;

    #[test]
    fn test_path_canonicalize() {
        assert_eq!(Path::canonicalize("/"), "/");
        assert_eq!(Path::canonicalize("/a/b/c"), "/a/b/c");
        assert_eq!(Path::canonicalize("/a/./b/../c/"), "/a/c");
        assert_eq!(Path::canonicalize("///a///b///"), "/a/b");
        assert_eq!(Path::canonicalize("/a/../../.."), "/");
    }

    #[test]
    fn test_ramfs_basic_file_ops() {
        let ramfs = Arc::new(RamFS::new());
        let mount_table = MountTable::new(ramfs);

        // 创建目录
        mount_table.mkdir("/config", Permissions::all()).expect("mkdir");
        mount_table.mkdir("/binaries", Permissions::all()).expect("mkdir");

        // 创建文件
        let file = mount_table.create_file("/config/system.toml", Permissions::read_write()).expect("create");
        assert_eq!(file.metadata().unwrap().node_type, INodeType::RegularFile);

        // 句柄写入与读取
        let handle = FileHandle::new(file.clone(), OpenFlags::READ_WRITE);
        assert_eq!(handle.write(b"hello boruix vfs").unwrap(), 16);
        assert_eq!(file.metadata().unwrap().size, 16);

        // Seek 重新读
        handle.seek(0, SeekWhence::Set).unwrap();
        let mut buf = [0u8; 32];
        let n = handle.read(&mut buf).unwrap();
        assert_eq!(n, 16);
        assert_eq!(&buf[..16], b"hello boruix vfs");

        // 显式 pread/pwrite
        let mut pbuf = [0u8; 6];
        assert_eq!(handle.pread(6, &mut pbuf).unwrap(), 6);
        assert_eq!(&pbuf, b"boruix");

        // 列出目录
        let config_dir = mount_table.resolve("/config", true).expect("resolve config");
        let entries = config_dir.list_dir().expect("list dir");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "system.toml");
        assert_eq!(entries[0].size, 16);
    }

    #[test]
    fn test_symlinks_and_mounts() {
        let ramfs_root = Arc::new(RamFS::new());
        let mount_table = MountTable::new(ramfs_root);

        mount_table.mkdir("/users", Permissions::all()).unwrap();
        mount_table.mkdir("/users/aixiaoji", Permissions::all()).unwrap();
        mount_table.create_file("/users/aixiaoji/notes.txt", Permissions::all()).unwrap();

        // 创建软链接
        mount_table.symlink("/users/aixiaoji/notes.txt", "/latest_notes").unwrap();

        // 经由软链接读取目标节点
        let resolved = mount_table.resolve("/latest_notes", true).unwrap();
        assert_eq!(resolved.metadata().unwrap().node_type, INodeType::RegularFile);

        // 挂载独立子文件系统到 /volumes/data
        mount_table.mkdir("/volumes", Permissions::all()).unwrap();
        let data_ramfs = Arc::new(RamFS::new());
        mount_table.mount("/volumes/data", data_ramfs).unwrap();

        // 在挂载的文件系统上创建文件
        mount_table.create_file("/volumes/data/project.rs", Permissions::all()).unwrap();
        let proj_file = mount_table.resolve("/volumes/data/project.rs", true).unwrap();
        assert_eq!(proj_file.metadata().unwrap().node_type, INodeType::RegularFile);
    }

    #[test]
    fn test_unlink_and_empty_dir_protection() {
        let ramfs = Arc::new(RamFS::new());
        let mount_table = MountTable::new(ramfs);

        mount_table.mkdir("/testdir", Permissions::all()).unwrap();
        mount_table.create_file("/testdir/file1", Permissions::all()).unwrap();

        // 试图删除非空目录应失败
        assert_eq!(mount_table.unlink("/testdir").unwrap_err(), Error::NotEmpty);

        // 删除文件后删除空目录
        mount_table.unlink("/testdir/file1").unwrap();
        mount_table.unlink("/testdir").unwrap();
        match mount_table.resolve("/testdir", true) {
            Err(Error::NotFound) => {}
            _ => panic!("expected NotFound after unlink"),
        }
    }

    struct MockProcessProvider;
    impl ProcessInfoProvider for MockProcessProvider {
        fn list_processes(&self) -> Vec<ProcessSnapshot> {
            alloc::vec![
                ProcessSnapshot {
                    pid: 1,
                    name: alloc::string::String::from("init"),
                    state: alloc::string::String::from("Running"),
                    memory_bytes: 65536,
                    threads: 1,
                },
                ProcessSnapshot {
                    pid: 2,
                    name: alloc::string::String::from("shell"),
                    state: alloc::string::String::from("Ready"),
                    memory_bytes: 131072,
                    threads: 1,
                },
            ]
        }

        fn get_process(&self, pid: usize) -> Option<ProcessSnapshot> {
            if pid == 1 {
                Some(ProcessSnapshot {
                    pid: 1,
                    name: alloc::string::String::from("init"),
                    state: alloc::string::String::from("Running"),
                    memory_bytes: 65536,
                    threads: 1,
                })
            } else {
                None
            }
        }
    }

    struct MockSystemProvider;
    impl SystemInfoProvider for MockSystemProvider {
        fn cpu_json(&self) -> alloc::string::String {
            alloc::string::String::from(r#"{"arch":"x86_64","cores":1,"vendor":"GenuineIntel"}"#)
        }
        fn memory_json(&self) -> alloc::string::String {
            alloc::string::String::from(r#"{"capacity_bytes":134217728,"allocated_bytes":4194304,"free_bytes":130023424}"#)
        }
        fn kernel_json(&self) -> alloc::string::String {
            alloc::string::String::from(r#"{"version":"0.1.0","git_commit":"abcdef"}"#)
        }
    }

    struct MockDeviceProvider {
        baud: core::sync::atomic::AtomicU32,
    }
    impl DeviceInfoProvider for MockDeviceProvider {
        fn list_devices(&self) -> Vec<DeviceInfo> {
            alloc::vec![
                DeviceInfo {
                    name: alloc::string::String::from("serial-com1"),
                    bus: alloc::string::String::from("ISA"),
                    class: alloc::string::String::from("UART"),
                    bound_driver: Some(alloc::string::String::from("uart16550")),
                }
            ]
        }
        fn serial_read(&self, buf: &mut [u8]) -> Result<usize, Error> {
            let data = b"OK";
            let l = core::cmp::min(buf.len(), data.len());
            buf[..l].copy_from_slice(&data[..l]);
            Ok(l)
        }
        fn serial_write(&self, buf: &[u8]) -> Result<usize, Error> {
            Ok(buf.len())
        }
        fn get_serial_baudrate(&self) -> u32 {
            self.baud.load(core::sync::atomic::Ordering::Relaxed)
        }
        fn set_serial_baudrate(&self, baud: u32) -> Result<(), Error> {
            self.baud.store(baud, core::sync::atomic::Ordering::Relaxed);
            Ok(())
        }
    }

    #[test]
    fn test_m63_special_filesystems() {
        let ramfs_root = Arc::new(RamFS::new());
        let mount_table = MountTable::new(ramfs_root);

        mount_table.mkdir("/processes", Permissions::all()).unwrap();
        mount_table.mkdir("/system", Permissions::all()).unwrap();
        mount_table.mkdir("/devices", Permissions::all()).unwrap();

        // 1. ProcFS 挂载与 JSON 读取
        let procfs = Arc::new(ProcFS::new(Arc::new(MockProcessProvider)));
        mount_table.mount("/processes", procfs).unwrap();

        let list_file = mount_table.resolve("/processes/list", true).unwrap();
        let mut buf = [0u8; 512];
        let n = list_file.read_at(0, &mut buf).unwrap();
        let s = core::str::from_utf8(&buf[..n]).unwrap();
        assert!(s.contains(r#""name":"init""#));
        assert!(s.contains(r#""name":"shell""#));

        let status_file = mount_table.resolve("/processes/1/status", true).unwrap();
        let n2 = status_file.read_at(0, &mut buf).unwrap();
        let s2 = core::str::from_utf8(&buf[..n2]).unwrap();
        assert!(s2.contains(r#""pid":1"#));
        assert!(s2.contains(r#""state":"Running""#));

        // 2. SysFS 挂载与 JSON 读取
        let sysfs = Arc::new(SysFS::new(Arc::new(MockSystemProvider)));
        mount_table.mount("/system", sysfs).unwrap();

        let cpu_file = mount_table.resolve("/system/cpu", true).unwrap();
        let n3 = cpu_file.read_at(0, &mut buf).unwrap();
        let s3 = core::str::from_utf8(&buf[..n3]).unwrap();
        assert!(s3.contains(r#""arch":"x86_64""#));

        let mem_file = mount_table.resolve("/system/memory", true).unwrap();
        let n4 = mem_file.read_at(0, &mut buf).unwrap();
        let s4 = core::str::from_utf8(&buf[..n4]).unwrap();
        assert!(s4.contains(r#""capacity_bytes":134217728"#));

        // 3. DevFS 挂载与属性子文件
        let devfs = Arc::new(DevFS::new(Arc::new(MockDeviceProvider {
            baud: core::sync::atomic::AtomicU32::new(115200),
        })));
        mount_table.mount("/devices", devfs).unwrap();

        // 读取设备列表 JSON
        let dev_list = mount_table.resolve("/devices/list", true).unwrap();
        let n5 = dev_list.read_at(0, &mut buf).unwrap();
        let s5 = core::str::from_utf8(&buf[..n5]).unwrap();
        assert!(s5.contains(r#""driver":"uart16550""#));

        // 串口属性子文件测试
        let baud_file = mount_table.resolve("/devices/serial-com1/baudrate", true).unwrap();
        let n6 = baud_file.read_at(0, &mut buf).unwrap();
        assert_eq!(core::str::from_utf8(&buf[..n6]).unwrap().trim(), "115200");

        // 写入调速
        baud_file.write_at(0, b"9600").unwrap();
        let n7 = baud_file.read_at(0, &mut buf).unwrap();
        assert_eq!(core::str::from_utf8(&buf[..n7]).unwrap().trim(), "9600");

        // 串口 config JSON
        let cfg_file = mount_table.resolve("/devices/serial-com1/config", true).unwrap();
        let n8 = cfg_file.read_at(0, &mut buf).unwrap();
        let s8 = core::str::from_utf8(&buf[..n8]).unwrap();
        assert!(s8.contains(r#""baudrate":9600"#));

        // 显示器分辨率 mode JSON
        let mode_file = mount_table.resolve("/devices/displays/primary/mode", true).unwrap();
        let n9 = mode_file.read_at(0, &mut buf).unwrap();
        let s9 = core::str::from_utf8(&buf[..n9]).unwrap();
        assert!(s9.contains(r#""width":1024"#));
    }
}
