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
pub mod page_cache;
pub mod path;
pub mod procfs;
pub mod ramfs;
pub mod sysfs;

pub use devfs::{DevFS, DeviceInfo, DeviceInfoProvider};
pub use dynamic::{DynamicDirNode, DynamicFileNode};
pub use file_handle::{FileHandle, OpenFlags};
pub use inode::{DirEntry, FileMetadata, FileSystem, INode, INodeType, Permissions};
pub use mount::MountTable;
pub use page_cache::{HUGE_PAGE_SIZE, PAGE_SIZE, PageCache, PageCacheStats};
pub use path::Path;
pub use procfs::{ProcFS, ProcessInfoProvider, ProcessSnapshot};
pub use sysfs::{SysFS, SystemInfoProvider};
#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_handle::{FileHandle, OpenFlags, SeekWhence};
    use crate::inode::{INodeType, Permissions};
    use crate::mount::MountTable;
    use crate::path::Path;
    use crate::ramfs::RamFS;
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
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
        mount_table
            .mkdir("/config", Permissions::all())
            .expect("mkdir");
        mount_table
            .mkdir("/binaries", Permissions::all())
            .expect("mkdir");

        // 创建文件
        let file = mount_table
            .create_file("/config/system.toml", Permissions::read_write())
            .expect("create");
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

        // DMYGH #12：offset=0 是定位 I/O 的文件起始位置，必须覆盖而非追加。
        assert_eq!(handle.pwrite(0, b"HELLO").unwrap(), 5);
        handle.seek(0, SeekWhence::Set).unwrap();
        let mut overwritten = [0u8; 16];
        assert_eq!(handle.read(&mut overwritten).unwrap(), 16);
        assert_eq!(&overwritten, b"HELLO boruix vfs");

        // 列出目录
        let config_dir = mount_table
            .resolve("/config", true)
            .expect("resolve config");
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
        mount_table
            .mkdir("/users/aixiaoji", Permissions::all())
            .unwrap();
        mount_table
            .create_file("/users/aixiaoji/notes.txt", Permissions::all())
            .unwrap();

        // 创建软链接
        mount_table
            .symlink("/users/aixiaoji/notes.txt", "/latest_notes")
            .unwrap();

        // 经由软链接读取目标节点
        let resolved = mount_table.resolve("/latest_notes", true).unwrap();
        assert_eq!(
            resolved.metadata().unwrap().node_type,
            INodeType::RegularFile
        );

        // 挂载独立子文件系统到 /volumes/data
        mount_table.mkdir("/volumes", Permissions::all()).unwrap();
        let data_ramfs = Arc::new(RamFS::new());
        mount_table.mount("/volumes/data", data_ramfs).unwrap();

        // 在挂载的文件系统上创建文件
        mount_table
            .create_file("/volumes/data/project.rs", Permissions::all())
            .unwrap();
        let proj_file = mount_table
            .resolve("/volumes/data/project.rs", true)
            .unwrap();
        assert_eq!(
            proj_file.metadata().unwrap().node_type,
            INodeType::RegularFile
        );
    }

    #[test]
    fn test_unlink_and_empty_dir_protection() {
        let ramfs = Arc::new(RamFS::new());
        let mount_table = MountTable::new(ramfs);

        mount_table.mkdir("/testdir", Permissions::all()).unwrap();
        mount_table
            .create_file("/testdir/file1", Permissions::all())
            .unwrap();

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
                    name: alloc::string::String::from("init.elf"),
                    state: alloc::string::String::from("Running"),
                    memory_bytes: 65536,
                },
                ProcessSnapshot {
                    pid: 2,
                    name: alloc::string::String::from("shell.elf"),
                    state: alloc::string::String::from("Ready"),
                    memory_bytes: 131072,
                },
            ]
        }

        fn get_process(&self, pid: usize) -> Option<ProcessSnapshot> {
            if pid == 1 {
                Some(ProcessSnapshot {
                    pid: 1,
                    name: alloc::string::String::from("init.elf"),
                    state: alloc::string::String::from("Running"),
                    memory_bytes: 65536,
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
            alloc::string::String::from(
                r#"{"capacity_bytes":134217728,"allocated_bytes":4194304,"free_bytes":130023424}"#,
            )
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
                    volatile: true,
                },
                DeviceInfo {
                    name: alloc::string::String::from("ata0"),
                    bus: alloc::string::String::from("ISA"),
                    class: alloc::string::String::from("IDE"),
                    bound_driver: Some(alloc::string::String::from("ata_pio")),
                    volatile: false,
                },
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
        fn get_serial_baudrate(&self) -> Result<u32, Error> {
            Ok(self.baud.load(core::sync::atomic::Ordering::Relaxed))
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
        assert!(s.contains(r#""name":"init.elf""#));
        assert!(s.contains(r#""name":"shell.elf""#));
        // #2：内核无线程概念，ProcFS 不得再对外报告 threads 字段。
        assert!(!s.contains("threads"));

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
        // C15.1：易失性披露字段必须逐设备出现在 /devices/list JSON 中。
        assert!(s5.contains(r#""volatile":true"#), "serial-com1 is a stream device and must disclose volatile=true");
        assert!(s5.contains(r#""volatile":false"#), "hardware ata0 must disclose volatile=false");
        // 披露字段必须与设备条目一一对应（两台设备各一个 volatile 标记）。
        assert_eq!(
            s5.matches(r#""volatile":"#).count(),
            2,
            "every listed device must carry its own volatile disclosure"
        );

        // 串口属性子文件测试
        let baud_file = mount_table
            .resolve("/devices/serial-com1/baudrate", true)
            .unwrap();
        let n6 = baud_file.read_at(0, &mut buf).unwrap();
        assert_eq!(core::str::from_utf8(&buf[..n6]).unwrap().trim(), "115200");

        // 写入调速
        baud_file.write_at(0, b"9600").unwrap();
        let n7 = baud_file.read_at(0, &mut buf).unwrap();
        assert_eq!(core::str::from_utf8(&buf[..n7]).unwrap().trim(), "9600");
        assert_eq!(
            baud_file.write_at(0, b"not-a-number"),
            Err(Error::InvalidParam)
        );
        assert_eq!(baud_file.write_at(0, b"4294967296"), Err(Error::InvalidParam));
        let n7b = baud_file.read_at(0, &mut buf).unwrap();
        assert_eq!(core::str::from_utf8(&buf[..n7b]).unwrap().trim(), "9600");

        // 串口 config JSON
        let cfg_file = mount_table
            .resolve("/devices/serial-com1/config", true)
            .unwrap();
        let n8 = cfg_file.read_at(0, &mut buf).unwrap();
        let s8 = core::str::from_utf8(&buf[..n8]).unwrap();
        assert!(s8.contains(r#""baudrate":9600"#));

        // 显示器分辨率 mode JSON
        let mode_file = mount_table
            .resolve("/devices/displays/primary/mode", true)
            .unwrap();
        let n9 = mode_file.read_at(0, &mut buf).unwrap();
        let s9 = core::str::from_utf8(&buf[..n9]).unwrap();
        assert!(s9.contains(r#""width":1024"#));
    }

    struct EmptyDeviceProvider;
    impl DeviceInfoProvider for EmptyDeviceProvider {
        fn list_devices(&self) -> Vec<DeviceInfo> {
            Vec::new()
        }

        fn serial_read(&self, _buf: &mut [u8]) -> Result<usize, Error> {
            Err(Error::NotFound)
        }

        fn serial_write(&self, _buf: &[u8]) -> Result<usize, Error> {
            Err(Error::NotFound)
        }

        fn get_serial_baudrate(&self) -> Result<u32, Error> {
            Err(Error::NotFound)
        }

        fn set_serial_baudrate(&self, _baud: u32) -> Result<(), Error> {
            Err(Error::NotFound)
        }
    }

    /// DMYGH #4：设备注册表为空是合法状态，DevFS 必须如实输出空数组。
    #[test]
    fn test_devfs_empty_device_registry_is_honest() {
        let devfs = DevFS::new(Arc::new(EmptyDeviceProvider));
        let list = devfs.root().lookup("list").expect("resolve device list");
        let mut buf = [0u8; 8];
        let n = list.read_at(0, &mut buf).expect("read empty device list");
        assert_eq!(&buf[..n], b"[]\n");
    }

    #[test]
    fn test_page_cache_2m_and_4k_eviction() {
        let ramfs = Arc::new(RamFS::new());
        let mount_table = Arc::new(MountTable::new(ramfs));
        mount_table.mkdir("/binaries", Permissions::all()).unwrap();

        let file = mount_table
            .create_file("/binaries/app.elf", Permissions::read_write())
            .unwrap();

        // 写入一段 2MB+ 的数据
        let pattern_len = 2 * 1024 * 1024 + 8192;
        let mut sample_data = alloc::vec![0u8; pattern_len];
        for (i, b) in sample_data.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        file.write_at(0, &sample_data).unwrap();

        let cache = PageCache::new();

        // 1. 4KB 页缓存读取（跨越 4096 边界，涉及 page 0 与 page 1）
        let mut read_buf_4k = [0u8; 100];
        let n1 = cache
            .read_cached(file.as_ref(), 4090, &mut read_buf_4k)
            .unwrap();
        assert_eq!(n1, 100);
        assert_eq!(&read_buf_4k, &sample_data[4090..4190]);
        let stats1 = cache.stats();
        assert_eq!(stats1.misses, 2); // 跨 2 个 4KB 页未命中
        assert_eq!(stats1.hits, 0);

        // 再次读取命中 4KB 缓存（2 个页皆已缓存）
        let mut read_buf_4k_hit = [0u8; 100];
        let n2 = cache
            .read_cached(file.as_ref(), 4090, &mut read_buf_4k_hit)
            .unwrap();
        assert_eq!(n2, 100);
        assert_eq!(&read_buf_4k_hit, &sample_data[4090..4190]);
        let stats2 = cache.stats();
        assert_eq!(stats2.hits, 2);

        // 2. 2MB 大页直通缓存读取
        let mut big_buf = alloc::vec![0u8; 256 * 1024];
        let n_big = cache.read_cached(file.as_ref(), 0, &mut big_buf).unwrap();
        assert_eq!(n_big, 256 * 1024);
        assert_eq!(&big_buf[..], &sample_data[..256 * 1024]);
        let stats3 = cache.stats();
        assert_eq!(stats3.huge_pages, 1);

        // 再次命中 2MB 大页缓存
        let mut big_buf2 = alloc::vec![0u8; 1024];
        let n_big2 = cache
            .read_cached(file.as_ref(), 65536, &mut big_buf2)
            .unwrap();
        assert_eq!(n_big2, 1024);
        assert_eq!(&big_buf2[..], &sample_data[65536..65536 + 1024]);
        let stats4 = cache.stats();
        assert_eq!(stats4.hits, 2);

        // 3. 淘汰机制测试（Eviction）
        let evicted = cache.evict_clean_pages(1);
        assert!(evicted >= 1);
        let stats5 = cache.stats();
        assert!(stats5.evictions >= 1);
    }
}
