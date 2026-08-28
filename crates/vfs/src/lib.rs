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
pub mod stdio;
pub mod sysfs;

pub use devfs::{DevFS, DeviceInfo, DeviceInfoProvider};
pub use dynamic::{DynamicDirNode, DynamicFileNode};
pub use file_handle::{
    FileHandle, OpenFlags,
};
// 匿名管道端（ADR-014 §4.1 FLAG_PIPE）也随根再导出，供 task/进程 fd 表与
// syscall 层拼写。
pub use file_handle::OpenHandle;
// M12（ADR-023 §5）：SeekWhence 是句柄 seek 契约的公共枚举，随 crate
// 根再导出——调用方不应被要求钻进 file_handle 模块路径才能拼写类型。
pub use file_handle::SeekWhence;
pub use inode::{DirEntry, FileMetadata, FileSystem, INode, INodeType, Permissions};
pub use mount::MountTable;
pub use page_cache::{
    set_global_page_cache, HUGE_PAGE_SIZE, PAGE_SIZE, PageCache, PageCacheStats,
    READ_BULK_THRESHOLD_BYTES,
};
pub use path::Path;
pub use procfs::{ProcFS, ProcessInfoProvider, ProcessSnapshot};
pub use ramfs::{set_ramfs_memory_tight_hook, RamFS};
pub use stdio::{set_stdin_source, set_stdout_sink, stderr_handle, stdin_handle, stdout_handle};
pub use sysfs::{SysFS, SystemInfoProvider};
#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_handle::{FileHandle, OpenFlags, SeekWhence};
    use crate::inode::{INodeType, Permissions};
    use crate::mount::MountTable;
    use crate::path::Path;
    use crate::ramfs::RamFS;
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
            .mkdir("/programs", Permissions::all())
            .expect("mkdir");

        // 创建文件
        let file = mount_table
            .create_file("/config/system.toml", Permissions::read_write())
            .expect("create");
        assert_eq!(file.metadata().unwrap().node_type, INodeType::RegularFile);

        // 句柄写入与读取
        let handle = FileHandle::new(file.clone(), OpenFlags::READ_WRITE).unwrap();
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

        // 挂载独立子文件系统到 /volumes/data（A6：挂载目标必须已存在
        // 且为目录——mount(2) 同款语义，杜绝"挂上即不可达"的幽灵项）
        mount_table.mkdir("/volumes", Permissions::all()).unwrap();
        mount_table.mkdir("/volumes/data", Permissions::all()).unwrap();
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
                    ppid: 0,
                    memory_bytes: 65536,
                },
                ProcessSnapshot {
                    pid: 2,
                    name: alloc::string::String::from("shell.elf"),
                    state: alloc::string::String::from("Ready"),
                    ppid: 0,
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
                    ppid: 0,
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
        fn storage_status_json(&self) -> alloc::string::String {
            alloc::string::String::from(
                r#"{"device":"mock-vol","sectors_read":7,"sectors_written":3}"#,
            )
        }
        fn net_stats_json(&self) -> alloc::string::String {
            alloc::string::String::from(
                r#"{"error":"nic_stats_unsupported","device":"mock-nic"}"#,
            )
        }
        fn display_mode_json(&self) -> alloc::string::String {
            // mock 真值：DevFS 层必须原样透传，不得注入自己的缺省分辨率。
            alloc::string::String::from(r#"{"width":640,"height":480,"bpp":16}"#)
        }
    }

    #[test]
    fn test_m63_special_filesystems() {
        let ramfs_root = Arc::new(RamFS::new());
        let mount_table = MountTable::new(ramfs_root);

        mount_table.mkdir("/processes", Permissions::all()).unwrap();
        mount_table.mkdir("/system", Permissions::all()).unwrap();
        mount_table.mkdir("/system/info", Permissions::all()).unwrap();
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

        // 2. SysFS 挂载与 JSON 读取（/system/info）
        let sysfs = Arc::new(SysFS::new(Arc::new(MockSystemProvider)));
        mount_table.mount("/system/info", sysfs).unwrap();

        let cpu_file = mount_table.resolve("/system/info/cpu", true).unwrap();
        let n3 = cpu_file.read_at(0, &mut buf).unwrap();
        let s3 = core::str::from_utf8(&buf[..n3]).unwrap();
        assert!(s3.contains(r#""arch":"x86_64""#));

        let mem_file = mount_table.resolve("/system/info/memory", true).unwrap();
        let n4 = mem_file.read_at(0, &mut buf).unwrap();
        let s4 = core::str::from_utf8(&buf[..n4]).unwrap();
        assert!(s4.contains(r#""capacity_bytes":134217728"#));

        // /system 本体仍是真实可写 RamFS：可容纳 swapfile 等运行时文件。
        mount_table
            .create_file("/system/swapfile", Permissions::read_write())
            .unwrap();
        let _swap = mount_table.resolve("/system/swapfile", true).unwrap();
        // SysFS 只读视图不应遮蔽 /system 的可写性：swapfile 存在而 info 视图同在。
        mount_table.resolve("/system/info/cpu", true).unwrap();

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
        // S10/S07：data_bits/parity/stop_bits 无真实数据源，必须显式
        // not_supported，绝不得编造 8/"none"/1 伪配置。
        assert!(
            s8.contains(r#""data_bits":"not_supported""#)
                && s8.contains(r#""parity":"not_supported""#)
                && s8.contains(r#""stop_bits":"not_supported""#),
            "config must disclose unsupported line settings, not fake 8/none/1"
        );
        assert!(!s8.contains(r#""data_bits":8"#), "must not fabricate data_bits=8");

        // 显示器分辨率 mode JSON：必须逐字透传 Provider 真值（DevFS 层无
        // 自己的分辨率缺省值），写路径如实 NotSupported（模式切换未实现）。
        let mode_file = mount_table
            .resolve("/devices/displays/primary/mode", true)
            .unwrap();
        let n9 = mode_file.read_at(0, &mut buf).unwrap();
        let s9 = core::str::from_utf8(&buf[..n9]).unwrap();
        assert!(s9.contains(r#""width":640"#));
        // 审计 B28 语义（HEAD 现状）：mode 节点是 read_only 动态节点，
        // write_at 走 DynamicFileNode 的无 writer 分支 → PermissionDenied。
        // "模式切换未实现"的能力性拒绝由 Provider 写路径（若未来提供
        // read_write 形态）承担 NotSupported；当前节点根本没有写半边，
        // 权限语义才是真相。测试同步 B28 后的现实。
        assert_eq!(
            mode_file.write_at(0, b"{}"),
            Err(Error::PermissionDenied),
            "mode node is read-only by construction (B28): no write half exists"
        );

        // DMYGH #16：storage/net 遥测节点必须原样透传 Provider 的真实数据，
        // DevFS 层不得注入任何设备名或计数。
        let status = mount_table.resolve("/devices/storage/primary/status", true).unwrap();
        let n10 = status.read_at(0, &mut buf).unwrap();
        assert_eq!(
            core::str::from_utf8(&buf[..n10]).unwrap(),
            "{\"device\":\"mock-vol\",\"sectors_read\":7,\"sectors_written\":3}\n"
        );
        let nstats = mount_table.resolve("/devices/net/primary/stats", true).unwrap();
        let n11 = nstats.read_at(0, &mut buf).unwrap();
        assert_eq!(
            core::str::from_utf8(&buf[..n11]).unwrap(),
            "{\"error\":\"nic_stats_unsupported\",\"device\":\"mock-nic\"}\n"
        );
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

    /// DMYGH #16：Provider 未实现遥测查询时，默认实现必须输出显式错误 JSON，
    /// 绝不允许回退到编造的健康计数（sectors_read:1024 / rx_bytes:65536 等）。
    #[test]
    fn test_devfs_defaults_must_not_fabricate_telemetry() {
        let devfs = DevFS::new(Arc::new(EmptyDeviceProvider));
        let mut buf = [0u8; 256];

        // 存储状态：默认实现禁止编造 sectors/latency
        let storage = devfs.root().lookup("storage").expect("storage dir");
        let primary = storage.lookup("primary").expect("storage primary dir");
        let status = primary.lookup("status").expect("storage status node");
        let n = status.read_at(0, &mut buf).expect("read storage status");
        let s = core::str::from_utf8(&buf[..n]).unwrap();
        assert!(s.contains(r#""error""#), "storage default must emit explicit error JSON, got: {}", s);
        assert!(!s.contains("healthy"), "storage default must not fabricate healthy status");
        assert!(!s.contains("sectors_read"), "storage default must not fabricate sector counters");
        assert!(!s.contains("io_latency_us"), "storage default must not fabricate latency");

        // 网络统计：默认实现禁止编造 rx/tx
        let net = devfs.root().lookup("net").expect("net dir");
        let nprimary = net.lookup("primary").expect("net primary dir");
        let stats = nprimary.lookup("stats").expect("net stats node");
        let n2 = stats.read_at(0, &mut buf).expect("read net stats");
        let s2 = core::str::from_utf8(&buf[..n2]).unwrap();
        assert!(s2.contains(r#""error""#), "net default must emit explicit error JSON, got: {}", s2);
        assert!(!s2.contains("rx_bytes"), "net default must not fabricate rx counters");
        assert!(!s2.contains("link_speed_mbps"), "net default must not fabricate link speed");

        // PCI BAR：默认实现禁止编造 BAR 结构
        let pci = devfs.root().lookup("pci").expect("pci dir");
        let bars = pci.lookup("bars").expect("pci fallback bars node");
        let n3 = bars.read_at(0, &mut buf).expect("read pci bars");
        let s3 = core::str::from_utf8(&buf[..n3]).unwrap();
        assert!(s3.contains(r#""error""#), "pci bars default must emit explicit error JSON, got: {}", s3);
        assert!(!s3.contains("49200"), "pci bars default must not fabricate BAR ports");
    }

    #[test]
    fn test_page_cache_2m_and_4k_eviction() {
        let ramfs = Arc::new(RamFS::new());
        let mount_table = Arc::new(MountTable::new(ramfs));
        mount_table.mkdir("/programs", Permissions::all()).unwrap();

        let file = mount_table
            .create_file("/programs/app.elf", Permissions::read_write())
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
            .read_cached(&file, 4090, &mut read_buf_4k)
            .unwrap();
        assert_eq!(n1, 100);
        assert_eq!(&read_buf_4k, &sample_data[4090..4190]);
        let stats1 = cache.stats();
        assert_eq!(stats1.misses, 2); // 跨 2 个 4KB 页未命中
        assert_eq!(stats1.hits, 0);

        // 再次读取命中 4KB 缓存（2 个页皆已缓存）
        let mut read_buf_4k_hit = [0u8; 100];
        let n2 = cache
            .read_cached(&file, 4090, &mut read_buf_4k_hit)
            .unwrap();
        assert_eq!(n2, 100);
        assert_eq!(&read_buf_4k_hit, &sample_data[4090..4190]);
        let stats2 = cache.stats();
        assert_eq!(stats2.hits, 2);

        // 2. 2MB 大页直通缓存读取
        let mut big_buf = alloc::vec![0u8; 256 * 1024];
        let n_big = cache.read_cached(&file, 0, &mut big_buf).unwrap();
        assert_eq!(n_big, 256 * 1024);
        assert_eq!(&big_buf[..], &sample_data[..256 * 1024]);
        let stats3 = cache.stats();
        assert_eq!(stats3.huge_pages, 1);

        // 再次命中 2MB 大页缓存
        let mut big_buf2 = alloc::vec![0u8; 1024];
        let n_big2 = cache
            .read_cached(&file, 65536, &mut big_buf2)
            .unwrap();
        assert_eq!(n_big2, 1024);
        assert_eq!(&big_buf2[..], &sample_data[65536..65536 + 1024]);
        let stats4 = cache.stats();
        assert_eq!(stats4.hits, 2);

        // 3. 淘汰机制测试（Eviction；ADR-023 §1 改名 evict_pages——
        // 失效一致性策略下不存在脏块，"clean" 定语是死机制的遗迹）
        let evicted = cache.evict_pages(1);
        assert!(evicted >= 1);
        let stats5 = cache.stats();
        assert!(stats5.evictions >= 1);
    }

    /// vfs1 D8-①（ADR-023 §3）：词法 dot-dot 不穿透目录符号链接。
    /// `/lnk/../secret.txt` 词法化为 `/secret.txt`——即使沿 `/lnk` 走
    /// 文件系统路径本可命中 `/d/secret.txt`，也必须 NotFound。
    #[test]
    fn test_dotdot_does_not_traverse_dir_symlink() {
        let ramfs = Arc::new(RamFS::new());
        let mt = MountTable::new(ramfs);
        mt.mkdir("/d", Permissions::read_write()).unwrap();
        mt.create_file("/d/secret.txt", Permissions::read_write()).unwrap();
        mt.symlink("/d", "/lnk").unwrap();

        assert_eq!(
            mt.resolve("/lnk/../secret.txt", true).err(),
            Some(Error::NotFound),
            "lexical dot-dot must collapse to /secret.txt, never through the link"
        );
        // 正向链接解析不受影响
        let through = mt.resolve("/lnk/secret.txt", true).unwrap();
        assert_eq!(through.node_type().unwrap(), crate::inode::INodeType::RegularFile);
    }

    /// vfs1 D8-②：相对符号链接目标中的 `..` 以**链接所在目录**为基准
    /// 词法消解，不产生越权路径。
    #[test]
    fn test_relative_symlink_dotdot_resolves_against_link_dir() {
        let ramfs = Arc::new(RamFS::new());
        let mt = MountTable::new(ramfs);
        mt.mkdir("/sub", Permissions::read_write()).unwrap();
        mt.create_file("/sub/data.txt", Permissions::read_write()).unwrap();
        mt.create_file("/top.txt", Permissions::read_write()).unwrap();
        // 链接体 "sub/../top.txt"：位于根，词法化后即 /top.txt。
        mt.symlink("sub/../top.txt", "/jump").unwrap();

        let node = mt.resolve("/jump", true).unwrap();
        let mut buf = [0u8; 32];
        let n = node.read_at(0, &mut buf).unwrap();
        // 写入可区分内容以确认命中的是 /top.txt 而非 /sub 下同名物。
        mt.resolve("/top.txt", true)
            .unwrap()
            .write_at(0, b"TOP")
            .unwrap();
        let n2 = node.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf[..n2], b"TOP");
        let _ = n;
    }

    /// vfs1 D8-③：`..` 词法跳过挂载点——挂载子树内的 `..` 永远不会
    /// "向上穿越"到挂载点之外的宿主文件。
    #[test]
    fn test_dotdot_skips_mount_point_lexically() {
        let root_fs = Arc::new(RamFS::new());
        let mt = MountTable::new(root_fs.clone());
        mt.create_file("/escape.txt", Permissions::read_write()).unwrap();
        mt.mkdir("/mnt", Permissions::read_write()).unwrap();

        let child_fs = Arc::new(RamFS::new());
        child_fs
            .root()
            .create("m.txt", Permissions::read_write())
            .unwrap();
        mt.mount("/mnt", child_fs).unwrap();

        // /mnt/../escape.txt 词法化为 /escape.txt —— 宿主文件，
        // 绝不是子树的任何路径。
        let node = mt.resolve("/mnt/../escape.txt", true).unwrap();
        node.write_at(0, b"HOST").unwrap();
        let host = mt.resolve("/escape.txt", true).unwrap();
        let mut buf = [0u8; 8];
        let n = host.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"HOST");
        // 子树自身仍正常可达。
        assert!(mt.resolve("/mnt/m.txt", true).is_ok());
    }

    /// vfs1 D8-④：多级软链接链中段 + 尾部 dot-dot 组合的锁定行为。
    #[test]
    fn test_symlink_chain_with_trailing_dotdot() {
        let ramfs = Arc::new(RamFS::new());
        let mt = MountTable::new(ramfs);
        mt.mkdir("/r", Permissions::read_write()).unwrap();
        mt.create_file("/r/deep.txt", Permissions::read_write()).unwrap();
        mt.create_file("/deep2.txt", Permissions::read_write()).unwrap();
        mt.symlink("/r", "/q").unwrap();
        mt.symlink("/q", "/p").unwrap();

        // 正向两级链
        assert!(mt.resolve("/p/deep.txt", true).is_ok());
        // 尾部 dot-dot：/p/../deep2.txt → /deep2.txt（宿主），而非链内目标
        assert!(mt.resolve("/p/../deep2.txt", true).is_ok());
        assert!(mt.resolve("/p/../nope.txt", true).err() == Some(Error::NotFound));
    }

    /// vfs1 D7：软链接环必须在 MAX_SYMLINK_DEPTH 内如实报 TooManySymlinks，
    /// 绝不无限递归。
    #[test]
    fn test_symlink_loop_reports_too_many_symlinks() {
        let ramfs = Arc::new(RamFS::new());
        let mt = MountTable::new(ramfs);
        mt.symlink("/b", "/a").unwrap();
        mt.symlink("/a", "/b").unwrap();
        assert_eq!(
            mt.resolve("/a", true).err(),
            Some(Error::TooManySymlinks)
        );
    }

    /// vfs1 R5：变更入口的名字校验（C0 控制字符与 DEL 拒绝）。
    #[test]
    fn test_entry_name_validation_rejects_control_chars() {
        let ramfs = Arc::new(RamFS::new());
        let mt = MountTable::new(ramfs);
        for bad in ["a\u{1}b", "x\n", "\u{7f}", "tab\tchar"] {
            assert_eq!(
                mt.create_file(bad, Permissions::read_write()).err(),
                Some(Error::InvalidParam),
                "control-char name {:?} must be rejected",
                bad
            );
            assert_eq!(
                mt.mkdir(bad, Permissions::read_write()).err(),
                Some(Error::InvalidParam)
            );
            assert_eq!(mt.unlink(bad).err(), Some(Error::InvalidParam));
        }
        // 合法名字不受影响（UTF-8 多字节、空格、点号均允许）。
        mt.create_file("/数据 文件.v2.txt", Permissions::read_write()).unwrap();
    }

    /// vfs1 M1：MountTable 公共操作拒绝相对路径（显式 InvalidParam，
    /// 不静默当绝对路径解析）。
    #[test]
    fn test_mount_table_rejects_relative_paths() {
        let ramfs = Arc::new(RamFS::new());
        let mt = MountTable::new(ramfs);
        assert_eq!(
            mt.create_file("relative.txt", Permissions::read_write()).err(),
            Some(Error::InvalidParam)
        );
        assert_eq!(
            mt.mkdir("rel/dir", Permissions::read_write()).err(),
            Some(Error::InvalidParam)
        );
        assert_eq!(mt.unlink("relative.txt").err(), Some(Error::InvalidParam));
        assert_eq!(
            mt.symlink("x", "rel-link").err(),
            Some(Error::InvalidParam)
        );
        // M1：mount/unmount/resolve 同样拒绝相对路径（审计 L500 修复点）。
        assert_eq!(
            mt.mount("rel/mnt", Arc::new(RamFS::new())).err(),
            Some(Error::InvalidParam)
        );
        assert_eq!(mt.unmount("rel/mnt").err(), Some(Error::InvalidParam));
        assert_eq!(mt.resolve("rel/path", true).err(), Some(Error::InvalidParam));
    }

    /// vfs1 A6：mount 目标必须存在且为目录。
    #[test]
    fn test_mount_target_must_be_existing_directory() {
        let root_fs = Arc::new(RamFS::new());
        let mt = MountTable::new(root_fs.clone());
        // 不存在的目标
        assert_eq!(
            mt.mount("/ghost", Arc::new(RamFS::new())).err(),
            Some(Error::NotFound)
        );
        // 存在但是普通文件
        mt.create_file("/plain.txt", Permissions::read_write()).unwrap();
        assert_eq!(
            mt.mount("/plain.txt", Arc::new(RamFS::new())).err(),
            Some(Error::NotDirectory)
        );
        // 合法目录成功
        mt.mkdir("/ok", Permissions::read_write()).unwrap();
        assert!(mt.mount("/ok", Arc::new(RamFS::new())).is_ok());
    }

    /// ADR-014 SYS_ENTRY_UPDATE (0x43)：同目录重命名语义。
    #[test]
    fn test_rename_same_dir_semantics() {
        let root_fs = Arc::new(RamFS::new());
        let mt = MountTable::new(root_fs.clone());
        mt.create_file("/a.txt", Permissions::read_write()).unwrap();
        // 同目录重命名成功，内容保 inode 身份（读写经旧名关闭后新名可达）。
        mt.rename("/a.txt", "/b.txt").expect("rename within dir");
        assert!(mt.resolve("/a.txt", true).is_err(), "old name gone");
        assert_eq!(
            mt.create_file("/b.txt", Permissions::read_write()).err(),
            Some(Error::AlreadyExists)
        );
        assert!(mt.resolve("/b.txt", true).is_ok(), "new name reachable");
        // 源不存在 → NotFound。
        assert_eq!(
            mt.rename("/ghost", "/c.txt").err(),
            Some(Error::NotFound)
        );
        // 目标已存在 → AlreadyExists（绝不静默覆盖）。
        mt.create_file("/d.txt", Permissions::read_write()).unwrap();
        assert_eq!(
            mt.rename("/b.txt", "/d.txt").err(),
            Some(Error::AlreadyExists)
        );
        // 相对路径 → InvalidParam（M1）。
        assert_eq!(mt.rename("b.txt", "/e.txt").err(), Some(Error::InvalidParam));
        assert_eq!(mt.rename("/b.txt", "e.txt").err(), Some(Error::InvalidParam));
        // 跨目录 → NotSupported（宁缺毋假，跨 FS 移动未实现）。
        mt.mkdir("/dir1", Permissions::read_write()).unwrap();
        mt.mkdir("/dir2", Permissions::read_write()).unwrap();
        mt.create_file("/dir1/x.txt", Permissions::read_write()).unwrap();
        assert_eq!(
            mt.rename("/dir1/x.txt", "/dir2/x.txt").err(),
            Some(Error::NotSupported)
        );
    }

    /// vfs1 A7：活动挂载点及其祖先目录不可 unlink；卸载后恢复可删。
    #[test]
    fn test_unlink_blocked_while_mounted() {
        let root_fs = Arc::new(RamFS::new());
        let mt = MountTable::new(root_fs.clone());
        mt.mkdir("/mnt", Permissions::read_write()).unwrap();
        mt.mount("/mnt", Arc::new(RamFS::new())).unwrap();

        assert_eq!(mt.unlink("/mnt").err(), Some(Error::Busy));

        // 祖先目录同理：删除 "/" 之下的直接祖先会孤儿化挂载键。
        mt.mkdir("/anc", Permissions::read_write()).unwrap();
        mt.mkdir("/anc/deep", Permissions::read_write()).unwrap();
        mt.unmount("/mnt").unwrap();
        mt.mount("/anc/deep", Arc::new(RamFS::new())).unwrap();
        assert_eq!(mt.unlink("/anc").err(), Some(Error::Busy));

        mt.unmount("/anc/deep").unwrap();
        // 卸载只解除绑定；目录树里的 deep 条目仍在——先删子（空目录）
        // 再删父，非空保护语义不变。
        assert!(mt.unlink("/anc/deep").is_ok());
        assert!(mt.unlink("/anc").is_ok());
    }

    /// vfs1 M16：append 打开的写起点是当前真实大小；seek(End,+) 越 EOF
    /// 后写入形成稀疏洞，洞内字节如实读回零。
    #[test]
    fn test_append_offset_and_sparse_hole() {
        let ramfs = Arc::new(RamFS::new());
        let mt = MountTable::new(ramfs.clone());
        let path = "/log.txt";
        {
            let f = mt.create_file(path, Permissions::read_write()).unwrap();
            f.write_at(0, b"abc").unwrap();
        }
        {
            let node = mt.resolve(path, true).unwrap();
            let h = crate::file_handle::FileHandle::new(
                node,
                crate::file_handle::OpenFlags::READ_WRITE_APPEND,
            )
            .unwrap();
            assert_eq!(h.write(b"de").unwrap(), 2);
        }
        let node = mt.resolve(path, true).unwrap();
        let mut buf = [0u8; 8];
        let n = node.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"abcde");

        // 稀疏洞：seek End +1024 后写一个字节 → size = 5 + 1024 + 1
        let h = crate::file_handle::FileHandle::new(
            node.clone(),
            crate::file_handle::OpenFlags::READ_WRITE,
        )
        .unwrap();
        h.seek(1024, crate::file_handle::SeekWhence::End).unwrap();
        h.write(b"X").unwrap();
        let mut probe = [0u8; 1030];
        let total = node.read_at(0, &mut probe).unwrap();
        assert_eq!(total, 1030);
        assert_eq!(&probe[..5], b"abcde");
        assert!(
            probe[5..1029].iter().all(|&b| b == 0),
            "hole bytes must read back as zeros"
        );
        assert_eq!(probe[1029], b'X');
    }

    /// 全局页缓存失效一致性（vfs1 A2 / ADR-023 §1）：句柄写必须经
    /// write_cached 作废受影响缓存块——先读入缓存，再经句柄覆写，
    /// 读缓存不得返回陈旧数据。
    #[test]
    fn test_global_cache_coherence_on_handle_write() {
        // 全局缓存是进程级 Once（与内核启动期单次注入同构）：用 Box::leak
        // 取 'static 实例注入。重复调用是幂等的，测试并行下安全。
        let cache: &'static crate::page_cache::PageCache =
            alloc::boxed::Box::leak(alloc::boxed::Box::new(
                crate::page_cache::PageCache::new(),
            ));
        crate::page_cache::set_global_page_cache(cache);

        let ramfs = Arc::new(RamFS::new());
        let mt = MountTable::new(ramfs);
        let node = mt
            .create_file("/coh.txt", Permissions::read_write())
            .unwrap();
        let h = crate::file_handle::FileHandle::new(
            node.clone(),
            crate::file_handle::OpenFlags::READ_WRITE,
        )
        .unwrap();

        // v1 进缓存
        h.write(b"stale-data-v1").unwrap();
        let mut buf = [0u8; 16];
        let n1 = cache.read_cached(&node, 0, &mut buf).unwrap();
        assert_eq!(&buf[..n1], b"stale-data-v1");

        // 句柄覆写 → 必须写穿并作废缓存块
        h.pwrite(0, b"FRESH").unwrap();
        let n2 = cache.read_cached(&node, 0, &mut buf).unwrap();
        assert_eq!(
            &buf[..n2],
            b"FRESH-data-v1",
            "cached read after coordinated write must observe new data"
        );
    }

    /// 审计 R9-F1 红绿锁定：双文件同偏移必须互相隔离——读侧不串数据，
    /// 写侧失效不越界。旧实现以裸偏移为唯一键，本测试在旧代码上必红。
    #[test]
    fn test_page_cache_two_files_same_offset_isolated() {
        let ramfs = Arc::new(RamFS::new());
        let mt = MountTable::new(ramfs);
        let a = mt.create_file("/A.bin", Permissions::read_write()).unwrap();
        let b = mt.create_file("/B.bin", Permissions::read_write()).unwrap();
        a.write_at(0, &[0xAA; 128]).unwrap();
        b.write_at(0, &[0xBB; 128]).unwrap();

        let cache = crate::page_cache::PageCache::new();

        // 先缓存 A@0，再读 B 同偏移：绝不允许命中 A 的页。
        let mut buf = [0u8; 64];
        let n1 = cache.read_cached(&a, 0, &mut buf).unwrap();
        assert_eq!(&buf[..n1], &[0xAA; 64]);
        let n2 = cache.read_cached(&b, 0, &mut buf).unwrap();
        assert_eq!(
            &buf[..n2],
            &[0xBB; 64],
            "same-offset read of another file must not hit A's cached page"
        );

        // 写侧隔离：覆写 B@0 后，A 的缓存块必须原样幸存（旧实现按偏移
        // 全域作废，会误删 A 的页）。
        let h = crate::file_handle::FileHandle::new(
            b.clone(),
            crate::file_handle::OpenFlags::READ_WRITE,
        )
        .unwrap();
        h.pwrite(0, &[0xCC; 16]).unwrap();
        let mut buf_a = [0u8; 64];
        let n3 = cache.read_cached(&a, 0, &mut buf_a).unwrap();
        assert_eq!(
            &buf_a[..n3],
            &[0xAA; 64],
            "invalidation must be scoped to the written node only"
        );
    }

    /// vfs1 M5：跨页连续读取完整补齐；命中但请求越过历史截断缓存边界时
    /// 必须回落装载路径重查，而不是误报 EOF。
    #[test]
    fn test_cross_page_read_and_hit_overflow_reload() {
        let ramfs = Arc::new(RamFS::new());
        let mt = MountTable::new(ramfs.clone());
        let node = mt
            .create_file("/big.bin", Permissions::read_write())
            .unwrap();
        let payload: alloc::vec::Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        node.write_at(0, &payload).unwrap();

        let cache = crate::page_cache::PageCache::new();
        // 一口跨多页读全量
        let mut out = alloc::vec![0u8; payload.len()];
        let n = cache.read_cached(&node, 0, &mut out).unwrap();
        assert_eq!(n, payload.len());
        assert_eq!(out, payload);

        // 历史截断场景：只读到旧 EOF（缓存末页短于满页）→ 文件增长 →
        // 再跨旧 EOF 读，新字节必须可见（不允许 Ok(0) 早退）。
        let grown: alloc::vec::Vec<u8> = (0..12_000u32).map(|i| (i % 241) as u8).collect();
        node.write_at(payload.len() as u64, &grown[payload.len()..]).unwrap();
        let mut out2 = alloc::vec![0u8; grown.len()];
        let n2 = cache.read_cached(&node, 0, &mut out2).unwrap();
        assert_eq!(n2, grown.len(), "growth past cached truncation must be visible");
        assert_eq!(out2[payload.len()], grown[payload.len()]);
    }

    /// vfs1 D7：挂载遮蔽在构造上不可能（同前缀二次挂载拒绝）+ 卸载回落。
    #[test]
    fn test_mount_shadow_impossible_and_unmount_fallback() {
        let root_fs = Arc::new(RamFS::new());
        let mt = MountTable::new(root_fs.clone());
        mt.mkdir("/mnt", Permissions::read_write()).unwrap();
        mt.mount("/mnt", Arc::new(RamFS::new())).unwrap();
        // 同前缀二次挂载被拒——"谁遮蔽谁"的歧义从未产生。
        assert_eq!(
            mt.mount("/mnt", Arc::new(RamFS::new())).err(),
            Some(Error::AlreadyExists)
        );

        let a = Arc::new(RamFS::new());
        a.root()
            .create("marker.txt", Permissions::read_write())
            .unwrap();
        mt.unmount("/mnt").unwrap();
        mt.mount("/mnt", a).unwrap();
        assert!(
            mt.resolve("/mnt/marker.txt", true).is_ok(),
            "after unmount+remount the new tree must be visible"
        );
    }

    /// vfs1 D7：多线程并发写同一文件冒烟（宿主 std 线程；内核单核语义下
    /// 由 M18 锁序保证，此处锁定"无 panic + 尺寸确定"底线）。
    #[test]
    fn test_concurrent_ramfs_writers_smoke() {
        let ramfs = Arc::new(RamFS::new());
        let mt = MountTable::new(ramfs.clone());
        let node = mt
            .create_file("/race.bin", Permissions::read_write())
            .unwrap();

        let workers: alloc::vec::Vec<_> = (0u64..4)
            .map(|i| {
                let n = node.clone();
                std::thread::spawn(move || {
                    n.write_at(i * 16, &[i as u8; 16]).unwrap();
                })
            })
            .collect();
        for w in workers {
            w.join().unwrap();
        }
        assert_eq!(node.metadata().unwrap().size, 64);
    }
}
