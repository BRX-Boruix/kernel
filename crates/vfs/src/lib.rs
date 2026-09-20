//! BORUIX 虚拟文件系统（VFS）。
//!
//! 遵循 ADR-005（RESTful 命名）、ADR-011（VFS 架构规范）与 ADR-012（存储卷）。

#![no_std]

#[cfg(test)]
extern crate std;

extern crate alloc;

pub mod audio;
pub mod devfs;
pub mod dynamic;
pub mod file_handle;
pub mod flock;
pub mod huge_page_cache;
pub mod inode;
pub mod mount;
pub mod page_cache;
pub mod path;
pub mod procfs;
pub mod ramfs;
pub mod stdio;
pub mod sysfs;

pub use audio::{AudioRing, DspNode, WriteGate, AUDIO_RING_CAPACITY, AUDIO_STREAM_COUNT};
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
pub use flock::{LockMode, LockOwner};
pub use huge_page_cache::{HugeCacheStats, HugePageDirectCache};
pub use inode::{
    AccessPolicy, Ace, DirEntry, FileMetadata, FileSystem, GATE_SYSTEM_BIT, INode, INodeType,
    PermBits, Principal, Subject,
};
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
    use crate::inode::{AccessPolicy, Ace, GATE_SYSTEM_BIT, INodeType, PermBits, Principal, Subject};
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
            .mkdir("/config", 0o777, (0, 0))
            .expect("mkdir");
        mount_table
            .mkdir("/programs", 0o777, (0, 0))
            .expect("mkdir");

        // 创建文件
        let file = mount_table
            .create_file("/config/system.toml", 0o666, (0, 0))
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

        mount_table.mkdir("/users", 0o777, (0, 0)).unwrap();
        mount_table
            .mkdir("/users/aixiaoji", 0o777, (0, 0))
            .unwrap();
        mount_table
            .create_file("/users/aixiaoji/notes.txt", 0o777, (0, 0))
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
        mount_table.mkdir("/volumes", 0o777, (0, 0)).unwrap();
        mount_table.mkdir("/volumes/data", 0o777, (0, 0)).unwrap();
        let data_ramfs = Arc::new(RamFS::new());
        mount_table.mount("/volumes/data", data_ramfs).unwrap();

        // 在挂载的文件系统上创建文件
        mount_table
            .create_file("/volumes/data/project.rs", 0o777, (0, 0))
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

        mount_table.mkdir("/testdir", 0o777, (0, 0)).unwrap();
        mount_table
            .create_file("/testdir/file1", 0o777, (0, 0))
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
        fn time_json(&self) -> alloc::string::String {
            alloc::string::String::from(
                r#"{"year":2026,"month":1,"day":1,"hour":0,"minute":0,"second":0}"#,
            )
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

        mount_table.mkdir("/processes", 0o777, (0, 0)).unwrap();
        mount_table.mkdir("/system", 0o777, (0, 0)).unwrap();
        mount_table.mkdir("/system/info", 0o777, (0, 0)).unwrap();
        mount_table.mkdir("/devices", 0o777, (0, 0)).unwrap();

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
            .create_file("/system/swapfile", 0o666, (0, 0))
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
        mount_table.mkdir("/programs", 0o777, (0, 0)).unwrap();

        let file = mount_table
            .create_file("/programs/app.elf", 0o666, (0, 0))
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
        mt.mkdir("/d", 0o666, (0, 0)).unwrap();
        mt.create_file("/d/secret.txt", 0o666, (0, 0)).unwrap();
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
        mt.mkdir("/sub", 0o666, (0, 0)).unwrap();
        mt.create_file("/sub/data.txt", 0o666, (0, 0)).unwrap();
        mt.create_file("/top.txt", 0o666, (0, 0)).unwrap();
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
        mt.create_file("/escape.txt", 0o666, (0, 0)).unwrap();
        mt.mkdir("/mnt", 0o666, (0, 0)).unwrap();

        let child_fs = Arc::new(RamFS::new());
        child_fs
            .root()
            .create("m.txt", 0o666, (0, 0))
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
        mt.mkdir("/r", 0o666, (0, 0)).unwrap();
        mt.create_file("/r/deep.txt", 0o666, (0, 0)).unwrap();
        mt.create_file("/deep2.txt", 0o666, (0, 0)).unwrap();
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
                mt.create_file(bad, 0o666, (0, 0)).err(),
                Some(Error::InvalidParam),
                "control-char name {:?} must be rejected",
                bad
            );
            assert_eq!(
                mt.mkdir(bad, 0o666, (0, 0)).err(),
                Some(Error::InvalidParam)
            );
            assert_eq!(mt.unlink(bad).err(), Some(Error::InvalidParam));
        }
        // 合法名字不受影响（UTF-8 多字节、空格、点号均允许）。
        mt.create_file("/数据 文件.v2.txt", 0o666, (0, 0)).unwrap();
    }

    /// vfs1 M1：MountTable 公共操作拒绝相对路径（显式 InvalidParam，
    /// 不静默当绝对路径解析）。
    #[test]
    fn test_mount_table_rejects_relative_paths() {
        let ramfs = Arc::new(RamFS::new());
        let mt = MountTable::new(ramfs);
        assert_eq!(
            mt.create_file("relative.txt", 0o666, (0, 0)).err(),
            Some(Error::InvalidParam)
        );
        assert_eq!(
            mt.mkdir("rel/dir", 0o666, (0, 0)).err(),
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
        mt.create_file("/plain.txt", 0o666, (0, 0)).unwrap();
        assert_eq!(
            mt.mount("/plain.txt", Arc::new(RamFS::new())).err(),
            Some(Error::NotDirectory)
        );
        // 合法目录成功
        mt.mkdir("/ok", 0o666, (0, 0)).unwrap();
        assert!(mt.mount("/ok", Arc::new(RamFS::new())).is_ok());
    }

    /// ADR-014 SYS_ENTRY_UPDATE (0x43)：同目录重命名语义。
    #[test]
    fn test_rename_same_dir_semantics() {
        let root_fs = Arc::new(RamFS::new());
        let mt = MountTable::new(root_fs.clone());
        mt.create_file("/a.txt", 0o666, (0, 0)).unwrap();
        // 同目录重命名成功，内容保 inode 身份（读写经旧名关闭后新名可达）。
        mt.rename("/a.txt", "/b.txt").expect("rename within dir");
        assert!(mt.resolve("/a.txt", true).is_err(), "old name gone");
        assert_eq!(
            mt.create_file("/b.txt", 0o666, (0, 0)).err(),
            Some(Error::AlreadyExists)
        );
        assert!(mt.resolve("/b.txt", true).is_ok(), "new name reachable");
        // 源不存在 → NotFound。
        assert_eq!(
            mt.rename("/ghost", "/c.txt").err(),
            Some(Error::NotFound)
        );
        // 目标已存在 → AlreadyExists（绝不静默覆盖）。
        mt.create_file("/d.txt", 0o666, (0, 0)).unwrap();
        assert_eq!(
            mt.rename("/b.txt", "/d.txt").err(),
            Some(Error::AlreadyExists)
        );
        // 相对路径 → InvalidParam（M1）。
        assert_eq!(mt.rename("b.txt", "/e.txt").err(), Some(Error::InvalidParam));
        assert_eq!(mt.rename("/b.txt", "e.txt").err(), Some(Error::InvalidParam));
        // 跨目录 → NotSupported（宁缺毋假，跨 FS 移动未实现）。
        mt.mkdir("/dir1", 0o666, (0, 0)).unwrap();
        mt.mkdir("/dir2", 0o666, (0, 0)).unwrap();
        mt.create_file("/dir1/x.txt", 0o666, (0, 0)).unwrap();
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
        mt.mkdir("/mnt", 0o666, (0, 0)).unwrap();
        mt.mount("/mnt", Arc::new(RamFS::new())).unwrap();

        assert_eq!(mt.unlink("/mnt").err(), Some(Error::Busy));

        // 祖先目录同理：删除 "/" 之下的直接祖先会孤儿化挂载键。
        mt.mkdir("/anc", 0o666, (0, 0)).unwrap();
        mt.mkdir("/anc/deep", 0o666, (0, 0)).unwrap();
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
            let f = mt.create_file(path, 0o666, (0, 0)).unwrap();
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
            .create_file("/coh.txt", 0o666, (0, 0))
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
        let a = mt.create_file("/A.bin", 0o666, (0, 0)).unwrap();
        let b = mt.create_file("/B.bin", 0o666, (0, 0)).unwrap();
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
            .create_file("/big.bin", 0o666, (0, 0))
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
        mt.mkdir("/mnt", 0o666, (0, 0)).unwrap();
        mt.mount("/mnt", Arc::new(RamFS::new())).unwrap();
        // 同前缀二次挂载被拒——"谁遮蔽谁"的歧义从未产生。
        assert_eq!(
            mt.mount("/mnt", Arc::new(RamFS::new())).err(),
            Some(Error::AlreadyExists)
        );

        let a = Arc::new(RamFS::new());
        a.root()
            .create("marker.txt", 0o666, (0, 0))
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
            .create_file("/race.bin", 0o666, (0, 0))
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

    /// A1 音频哑管道测试（plan_audio_vfs.md 批次一）。
    ///
    /// 覆盖 §3.4 背压语义三分支与 §3.3 属性子文件。
    #[test]
    fn test_audio_dsp_pipe() {
        let mt = MountTable::new(Arc::new(RamFS::new()));
        mt.mkdir("/devices", 0o777, (0, 0)).unwrap();
        let devfs = Arc::new(DevFS::new(Arc::new(MockDeviceProvider {
            baud: core::sync::atomic::AtomicU32::new(115200),
        })));
        mt.mount("/devices", devfs).unwrap();

        // --- 节点存在性与类型 ---
        let dsp = mt.resolve("/devices/audio/dsp", true).unwrap();
        assert_eq!(dsp.node_type().unwrap(), INodeType::CharacterDevice);
        // 字符流不可定位（KM17）。
        assert!(!dsp.is_seekable(), "dsp is a character stream, must not be seekable");
        // 截断语义不存在，如实 NotSupported（M17 纪律）。
        assert_eq!(dsp.truncate(0), Err(Error::NotSupported));

        // --- S06/S09 红线：无消费者时写入必须失败可见，绝不接受后丢弃 ---
        assert_eq!(
            dsp.write_at(0, b"\x01\x02\x03\x04"),
            Err(Error::NotSupported),
            "writing PCM with no attached consumer must fail loudly, never be silently dropped"
        );

        // --- 属性子目录必须可枚举 ---
        let entries = dsp.list_dir().unwrap();
        let names: alloc::vec::Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        for want in ["format", "channels", "rate", "status"] {
            assert!(names.contains(&want), "missing attribute sub-file: {want}");
        }
    }

    /// A1 属性子文件：合法值往返 + 非法值如实拒绝（不静默 clamp/转换）。
    #[test]
    fn test_audio_dsp_attrs() {
        let mt = MountTable::new(Arc::new(RamFS::new()));
        mt.mkdir("/devices", 0o777, (0, 0)).unwrap();
        let devfs = Arc::new(DevFS::new(Arc::new(MockDeviceProvider {
            baud: core::sync::atomic::AtomicU32::new(115200),
        })));
        mt.mount("/devices", devfs).unwrap();
        let mut buf = [0u8; 512];

        // format：仅支持 s16le；其它格式如实 NotSupported（不静默转换）。
        let fmt = mt.resolve("/devices/audio/dsp/format", true).unwrap();
        let n = fmt.read_at(0, &mut buf).unwrap();
        assert_eq!(core::str::from_utf8(&buf[..n]).unwrap().trim(), "s16le");
        assert_eq!(fmt.write_at(0, b"f32le"), Err(Error::NotSupported));
        assert_eq!(fmt.write_at(0, b"s16le"), Ok(5));

        // channels：仅支持 2。
        let ch = mt.resolve("/devices/audio/dsp/channels", true).unwrap();
        let n2 = ch.read_at(0, &mut buf).unwrap();
        assert_eq!(core::str::from_utf8(&buf[..n2]).unwrap().trim(), "2");
        assert_eq!(ch.write_at(0, b"1"), Err(Error::NotSupported));

        // rate：非数字如实 InvalidParam（输入非法）；数字但不受支持 NotSupported
        // （输入合法、实现不支持）——两者语义不同，不得含混。
        let rate = mt.resolve("/devices/audio/dsp/rate", true).unwrap();
        let n3 = rate.read_at(0, &mut buf).unwrap();
        assert_eq!(core::str::from_utf8(&buf[..n3]).unwrap().trim(), "48000");
        assert_eq!(rate.write_at(0, b"44100"), Err(Error::NotSupported));
        assert_eq!(rate.write_at(0, b"abc"), Err(Error::InvalidParam));
        assert_eq!(rate.write_at(0, b""), Err(Error::InvalidParam));

        // status：必须是真实运行态，不得编造。
        let st = mt.resolve("/devices/audio/dsp/status", true).unwrap();
        let n4 = st.read_at(0, &mut buf).unwrap();
        let s = core::str::from_utf8(&buf[..n4]).unwrap();
        assert!(s.contains(r#""attached":false"#), "no consumer yet: {s}");
        assert!(s.contains(r#""capacity":65536"#), "must disclose real capacity: {s}");
        assert!(s.contains(r#""underruns":0"#), "must disclose underrun count: {s}");
    }


    /// 批次五 M5：`stream/N` 接受混音器支持的输入采样率，`dsp` 仍然只接受 48000。
    ///
    /// 两者**必须不同**，这是本测试的重点：输入端可以带自己的采样率（audiod 会
    /// 重采样），输出端直通 codec 且 codec 固定 48000 —— 在那里接受 44100 等于
    /// 承诺一件内核做不到的事，而链路上不会有任何一处报错。
    #[test]
    fn test_audio_stream_accepts_input_rates_but_dsp_does_not() {
        let mt = MountTable::new(Arc::new(RamFS::new()));
        mt.mkdir("/devices", 0o777, (0, 0)).unwrap();
        let devfs = Arc::new(DevFS::new(Arc::new(MockDeviceProvider {
            baud: core::sync::atomic::AtomicU32::new(115200),
        })));
        mt.mount("/devices", devfs).unwrap();

        let stream = mt.resolve("/devices/audio/stream/0/rate", true).unwrap();
        let dsp = mt.resolve("/devices/audio/dsp/rate", true).unwrap();

        // 输入端：集合中的每一项都必须被接受（否则生产者配不出该速率）。
        for r in crate::audio::AUDIO_INPUT_RATES {
            assert_eq!(
                stream.write_at(0, r.as_bytes()),
                Ok(r.len()),
                "stream must accept supported input rate {r}"
            );
        }
        // 集合之外仍然如实拒绝，而不是接受后按错误速度播。
        assert_eq!(stream.write_at(0, b"96000"), Err(Error::NotSupported));
        // 非法输入与不受支持是两种语义，不得含混。
        assert_eq!(stream.write_at(0, b"abc"), Err(Error::InvalidParam));

        // 输出端：仅 48000。44100 在这里必须被拒 —— 硬件无法兑现。
        assert_eq!(dsp.write_at(0, b"48000"), Ok(5));
        assert_eq!(dsp.write_at(0, b"44100"), Err(Error::NotSupported));
    }
    /// A1 对抗测试（S30/S31）：ring 边界、回绕、溢出、拒绝路径。
    #[test]
    fn test_audio_ring_adversarial() {
        let ring = AudioRing::with_capacity(16);
        assert_eq!(ring.used(), 0);
        assert_eq!(ring.free(), 16);
        let mut dst = [0u8; 4];
        assert_eq!(ring.peek(&mut dst), 0, "empty ring yields nothing, no fake data");

        // 精确填满不溢出；满了再写返回 0（不覆盖、不丢弃）。
        let data = [7u8; 16];
        assert_eq!(ring.push(&data), 16);
        assert_eq!(ring.used(), 16);
        assert_eq!(ring.free(), 0);
        assert_eq!(ring.push(b"x"), 0);

        let mut out = [0u8; 16];
        assert_eq!(ring.peek(&mut out), 16);
        assert_eq!(out, data);

        // S19：commit 越界必须如实拒绝，绝不静默截断。
        // 边界以 `reserved()`（=已借出量 16）为准，故 17 越界。
        assert_eq!(ring.commit(17), Err(Error::InvalidParam));
        assert_eq!(ring.commit(16), Ok(()));
        assert_eq!(ring.used(), 0);

        // 回绕：跨缓冲末尾写入，验证环形两段拷贝保持字节序。
        assert_eq!(ring.push(&[1u8; 12]), 12);
        let mut tmp = [0u8; 12];
        assert_eq!(ring.peek(&mut tmp), 12);
        assert_eq!(ring.commit(12), Ok(()));
        assert_eq!(ring.push(&[2u8; 8]), 8);
        let mut out2 = [0u8; 8];
        assert_eq!(ring.peek(&mut out2), 8);
        assert_eq!(out2, [2u8; 8], "wrap-around must preserve byte order");
        assert_eq!(ring.commit(8), Ok(()));

        // 部分读取：dst 小于可用量时只取 dst.len()。
        assert_eq!(ring.push(&[3u8; 10]), 10);
        let mut small = [0u8; 4];
        assert_eq!(ring.peek(&mut small), 4);
        assert_eq!(small, [3u8; 4]);
        assert_eq!(ring.used(), 10, "peek must not advance read_pos");
        // 借出水位推进 4：这 4 字节已被取走，不构成"未借出"的可用数据。
        assert_eq!(ring.reserved(), 4);
        // 续读只能拿到剩下的 6 字节，**不会重放**刚取过的 4 字节。
        let mut rest = [0u8; 8];
        assert_eq!(ring.peek(&mut rest), 6);
        assert_eq!(ring.reserved(), 10);
        // 累计提交 10（= 全部借出量）：越界与否以借出量为准。
        assert_eq!(ring.commit(10), Ok(()));

        // 超大输入：短写为容量值，不 panic。
        let huge = alloc::vec![9u8; 1000];
        assert_eq!(ring.push(&huge), 16, "push must short-write, not panic");
        // **必须先借出才能提交**（不变量 3）：初版此处直接 commit(16) 而
        // 从未 peek —— 那正是"提交从未取走的数据"，现被如实拒绝。
        assert_eq!(ring.commit(16), Err(Error::InvalidParam));
        let mut hb = [0u8; 16];
        assert_eq!(ring.peek(&mut hb), 16);
        assert_eq!(hb, [9u8; 16]);
        assert_eq!(ring.commit(16), Ok(()));

        // 空输入：无副作用。
        assert_eq!(ring.push(&[]), 0);
        assert_eq!(ring.used(), 0);
    }

    /// **根治轮新增**：`reserved_pos` 三指针不变式与"借出不重复"语义。
    ///
    /// 本测试锁定的是导致实测"播放卡顿、重复"的**根因**：在只有
    /// `read_pos`/`write_pos` 两指针的初版里，`peek` 不推进任何指针，
    /// 同一个消费者可以**反复取到同一段字节**——驱动一旦少 commit 一次
    /// （或 commit 被拒），硬件就把同一段声音重复播出去。
    ///
    /// 三条不变式必须同时成立（任一被破坏即成缺陷）：
    ///   1. `read_pos <= reserved_pos <= write_pos`；
    ///   2. 同一字节在被 `commit` 前**不可被第二次 peek 交付**；
    ///   3. `commit` 只能提交**已借出**的量（不能提交从未取走的数据）。
    #[test]
    fn test_audio_ring_reserved_prevents_double_delivery() {
        let ring = AudioRing::with_capacity(64);
        assert_eq!(ring.push(&[1u8; 16]), 16);
        assert_eq!(ring.used(), 16);
        assert_eq!(ring.reserved(), 0, "未取走前借出量为 0");

        // 第一次取：拿到 16，借出水位推进到 16。
        let mut a = [0u8; 16];
        assert_eq!(ring.peek(&mut a), 16);
        assert_eq!(a, [1u8; 16]);
        assert_eq!(ring.reserved(), 16);
        assert_eq!(ring.used(), 16, "peek 不推进 read_pos");

        // **第二次取：必须取不到**（不变量 2）。
        let mut b = [0xFFu8; 16];
        assert_eq!(ring.peek(&mut b), 0, "已借出的字节不得重复交付");
        assert_eq!(b, [0xFFu8; 16], "取不到时不得改写调用方缓冲（S09）");

        // **不能提交从未取走的数据**（不变量 3）：此刻仅借出 16，17 越界。
        assert_eq!(ring.push(&[2u8; 16]), 16);
        assert_eq!(ring.commit(17), Err(Error::InvalidParam));
        assert_eq!(ring.commit(16), Ok(()), "提交恰好等于借出量");
        assert_eq!(ring.reserved(), 0);
        assert_eq!(ring.used(), 16, "只有借出的 16 被释放，后写的 16 仍在");

        // 提交后原先那 16 字节不再可读，剩下的是第二次写入的数据——
        // 证明读位置确实前进了，而不是原地重放。
        let mut c = [0u8; 16];
        assert_eq!(ring.peek(&mut c), 16);
        assert_eq!(c, [2u8; 16], "commit 后必须读到后续数据，不是旧数据");

        // 不变量 1：三指针单调且有序。
        assert_eq!(ring.reserved(), 16);
        assert_eq!(ring.used(), 16);
        ring.commit(16).unwrap();
        assert_eq!(ring.reserved(), 0);
        assert_eq!(ring.used(), 0);
        assert_eq!(ring.free(), 64, "全部提交后空间完整归还");
    }

    /// 输入流（`WriteGate::Open`）走 peek+commit，在 reserved 语义下
    /// 必须**恰好消费一次**——既不多（重复交付）也不少（丢数据）。
    ///
    /// 这是对 `test_audio_stream_read_consumes_data` 的强化：该测试只验证
    /// "读后 used()==0"，在初版实现下**照样通过**（因为 commit 兜住了）；
    /// 本测试追加"借出量归零"，使 `reserved_pos` 与 `read_pos` 同步前进
    /// 成为被断言的事实，防止只改一半。
    #[test]
    fn test_audio_stream_open_gate_consumes_exactly_once() {
        let stream = DspNode::stream_with_capacity(64);
        stream.write_at(0, &[9u8; 32]).unwrap();
        assert_eq!(stream.as_audio_ring().unwrap().reserved(), 0);

        let mut out = [0u8; 32];
        assert_eq!(stream.read_at(0, &mut out), Ok(32));
        assert_eq!(out, [9u8; 32]);
        // 输入端读走即取走：used 与 reserved 双双归零。
        assert_eq!(stream.as_audio_ring().unwrap().used(), 0);
        assert_eq!(stream.as_audio_ring().unwrap().reserved(), 0);

        // 再读必须为空（不重放）。
        assert_eq!(stream.read_at(0, &mut out), Err(Error::WouldBlock));
    }

    /// A1 诚实性红线正向测试：附加消费者后，写入必须真正落进 ring。
    ///
    /// 与 `test_audio_dsp_pipe` 的"无消费者必须失败"构成一对——
    /// 证明 NotSupported 是**条件性**的，而非恒返回的错误。
    #[test]
    fn test_audio_dsp_attached_write_lands() {
        let node = DspNode::with_capacity(256);
        // 未附加 → 如实失败。
        assert_eq!(node.write_at(0, &[0xABu8; 64]), Err(Error::NotSupported));
        // 附加 → 写入必须成功且落进 ring。
        assert_eq!(node.ring().attach(4242), Ok(()));
        let pcm = [0xABu8; 64];
        assert_eq!(node.write_at(0, &pcm), Ok(64));
        assert_eq!(node.ring().used(), 64);

        // 读回一致（peek 不推进指针）。
        let mut out = [0u8; 64];
        assert_eq!(node.read_at(0, &mut out), Ok(64));
        assert_eq!(out, pcm);
        assert_eq!(node.ring().used(), 64, "peek must not advance read_pos");

        // 提交后才释放空间（两阶段语义）。
        assert_eq!(node.ring().commit(64), Ok(()));
        assert_eq!(node.ring().used(), 0);

        // status 必须如实反映本实例的真实状态（非常量）。
        let st = node.lookup("status").unwrap();
        let mut buf = [0u8; 512];
        let n = st.read_at(0, &mut buf).unwrap();
        let s = alloc::string::String::from(core::str::from_utf8(&buf[..n]).unwrap());
        assert!(s.contains(r#""attached":true"#), "must reflect real attach: {s}");
        assert!(s.contains(r#""capacity":256"#), "must reflect real capacity: {s}");

        // 未附加的另一实例必须报 false——两者不同即证明字段来自真实状态。
        let other = DspNode::with_capacity(256);
        let st2 = other.lookup("status").unwrap();
        let n2 = st2.read_at(0, &mut buf).unwrap();
        let s2 = alloc::string::String::from(core::str::from_utf8(&buf[..n2]).unwrap());
        assert!(s2.contains(r#""attached":false"#), "unattached must report false: {s2}");
        assert_ne!(s, s2, "status must be per-instance real state, not a constant");
    }

    /// M1：`stream/N` 是混音器**输入端**，写入门禁必须与 `dsp` 不同。
    ///
    /// **为何必须有这条测试**：`dsp` 的语义是"无消费者即拒绝写入"（A1 红线，
    /// 防止"接受后丢弃"的伪链路）。但 `stream/N` 根本没有消费者概念——它就是
    /// 一个输入缓冲，等混音器来取。若照搬 dsp 的门禁，生产者将**永远写不进去**，
    /// M1 链路直接不成立。
    ///
    /// 本测试钉死两者的差异是**条件性**的（S19 边界 / S26 自审）：
    /// 同一份 ring 代码，因门禁策略不同而行为不同。
    #[test]
    fn test_audio_stream_accepts_write_without_consumer() {
        let stream = DspNode::stream_with_capacity(256);
        // 无任何消费者 attach —— dsp 会 NotSupported，stream 必须接受。
        assert!(
            !stream.ring().is_attached(),
            "premise: stream test must start unattached"
        );
        let pcm = [0x5Au8; 64];
        assert_eq!(
            stream.write_at(0, &pcm),
            Ok(64),
            "stream/N must accept writes with no consumer attached"
        );
        assert_eq!(stream.ring().used(), 64, "data must actually land in the ring");

        // 对照组：同一容量、dsp 门禁下必须拒绝。两者不同才证明策略真的生效。
        let dsp = DspNode::with_capacity(256);
        assert_eq!(dsp.write_at(0, &pcm), Err(Error::NotSupported));
        assert_eq!(dsp.ring().used(), 0, "rejected write must not land");
    }

    /// M1：`stream/N` 满时仍须**如实背压**，不得静默丢弃或覆盖。
    ///
    /// 这是 A1"绝不静默丢弃"红线在 stream 上的**延续**：门禁放宽的是"要不要
    /// 消费者"，**不是**"满了怎么办"。两类语义容易被混为一谈，故单列测试。
    #[test]
    fn test_audio_stream_backpressure_when_full() {
        let stream = DspNode::stream_with_capacity(16);
        assert_eq!(stream.write_at(0, &[0x11u8; 16]), Ok(16));
        assert_eq!(stream.ring().used(), 16);
        // 满 → 如实 WouldBlock（EAGAIN），而不是静默成功或覆盖旧数据。
        assert_eq!(stream.write_at(0, &[0x22u8; 8]), Err(Error::WouldBlock));
        // 关键：被拒的写入**不得**污染 ring 内容。
        let mut out = [0u8; 16];
        assert_eq!(stream.read_at(0, &mut out), Ok(16));
        assert_eq!(out, [0x11u8; 16], "rejected write must not overwrite ring data");
    }
    
    /// The read path of an INPUT stream must CONSUME, not just peek.
    ///
    /// Regression test for a defect found while validating batch-4 M2. `read_at`
    /// originally called `ring.peek` unconditionally, which never advances the read
    /// pointer. The consumer of a dsp node commits explicitly through the AUDIO
    /// syscall, so peek is correct there -- but that path is hardcoded to
    /// /devices/audio/dsp, leaving stream/N with no way to commit at all.
    ///
    /// The consequence was severe and nearly invisible: audiod read the SAME bytes
    /// every round, so its output was one frozen buffer repeated forever rather than
    /// streaming audio. It still sounded continuous, and the M1 byte-for-byte check
    /// passed precisely because a peek returns the very bytes written. Only the
    /// two-stream scenario exposed it, as `live_inputs` never dropped.
    ///
    /// Marked with the same WriteGate that governs writes: the input end consumes on
    /// read, the output end keeps its two-phase peek/commit contract.
    #[test]
    fn test_audio_stream_read_consumes_data() {
        let stream = DspNode::stream_with_capacity(256);
        let mut wbuf = [0u8; 64];
        for (i, b) in wbuf.iter_mut().enumerate() {
            *b = i as u8;
        }
        stream.write_at(0, &wbuf).expect("write must be accepted");
        assert_eq!(stream.as_audio_ring().unwrap().used(), 64);

        // First read gets the data...
        let mut rbuf = [0u8; 64];
        let n = stream.read_at(0, &mut rbuf).expect("first read");
        assert_eq!(n, 64);
        assert_eq!(rbuf, wbuf, "first read must return what was written");

        // ...and must have CONSUMED it: the ring is now empty.
        assert_eq!(
            stream.as_audio_ring().unwrap().used(),
            0,
            "read on an input stream must advance the read pointer (consume)"
        );

        // A second read therefore finds nothing, rather than replaying the same
        // bytes forever. This is the assertion that would have caught the defect.
        assert!(
            stream.read_at(0, &mut rbuf).is_err(),
            "second read must find an empty ring, not replay stale data"
        );
    }

    /// The OUTPUT end must keep its two-phase peek/commit semantics (A2/A3).
    ///
    /// This is the control for the test above: making every read consume would break
    /// the driver contract, where fetched data must be delivered to hardware BEFORE
    /// being committed, so a crash mid-transfer does not silently discard audio.
    ///
    /// **修正（根治轮）**：初版本测试只断言 `used()` 仍为 32，即"数据还在"。
    /// 该断言**不足以防住真正的缺陷**：它放过了"同一个消费者能反复取到同一段
    /// 字节"——那正是实测"播放卡顿、重复"的根因。现在 `peek` 推进
    /// `reserved_pos`，故补上"第二次取必须取不到"的断言（见下）。
    #[test]
    fn test_audio_dsp_read_still_peeks_until_commit() {
        let dsp = DspNode::with_capacity(256);
        dsp.as_audio_ring().unwrap().attach(7).unwrap();
        let wbuf = [0x5au8; 32];
        dsp.write_at(0, &wbuf).expect("attached write must be accepted");

        let mut rbuf = [0u8; 32];
        assert_eq!(dsp.read_at(0, &mut rbuf).unwrap(), 32);
        // Still present: the output end requires an explicit commit.
        assert_eq!(
            dsp.as_audio_ring().unwrap().used(),
            32,
            "dsp read must NOT consume; two-phase contract requires commit"
        );
        // 但**已经借出**：32 字节全部在 reserved 水位里。
        assert_eq!(
            dsp.as_audio_ring().unwrap().reserved(),
            32,
            "peek must record the borrowed bytes so they cannot be borrowed twice"
        );

        // **关键新断言**：再读一次必须取不到数据（而不是重放同一段）。
        // 初版 peek 不推进任何指针，此处会再次返回 32 字节——驱动少 commit
        // 一次就会把同一段声音播两遍（实测症状的直接来源）。
        let mut again = [0u8; 32];
        assert!(
            dsp.read_at(0, &mut again).is_err(),
            "a second peek must not replay already-borrowed bytes"
        );
        assert_eq!(again, [0u8; 32], "拒绝时不得写入任何数据（S09）");

        // After an explicit commit the data is gone.
        dsp.as_audio_ring().unwrap().commit(32).unwrap();
        assert_eq!(dsp.as_audio_ring().unwrap().used(), 0);
        assert_eq!(dsp.as_audio_ring().unwrap().reserved(), 0);
    }
fn test_audio_dsp_backpressure() {
        let node = DspNode::with_capacity(8);
        assert_eq!(node.ring().attach(4242), Ok(()));
        assert_eq!(node.write_at(0, &[1u8; 8]), Ok(8));
        assert_eq!(node.ring().free(), 0);
        assert_eq!(
            node.write_at(0, b"\xAA"),
            Err(Error::WouldBlock),
            "full ring must report WouldBlock, never silently drop PCM"
        );
        // 空间未变——证明数据确实没被吞掉。
        assert_eq!(node.ring().used(), 8);
        assert_eq!(node.ring().free(), 0);

        // 消费后空间释放，写入重新成功。
        let mut out = [0u8; 8];
        assert_eq!(node.read_at(0, &mut out), Ok(8));
        assert_eq!(node.ring().commit(8), Ok(()));
        assert_eq!(node.write_at(0, b"\xBB\xCC"), Ok(2));
        assert_eq!(node.ring().used(), 2);
    }

    /// A1 空读：如实 WouldBlock，且不写入任何伪造数据（S09）。
    ///
    /// 欠载计数的语义边界（S26 自审修正）：只统计**已附加消费者**取不到
    /// 数据的情形——否则任意进程读一次本节点就污染该指标，使之失去意义。
    #[test]
    fn test_audio_dsp_empty_read_and_underrun_semantics() {
        let node = DspNode::with_capacity(32);
        let mut buf = [0u8; 16];

        // 未附加：空读如实 WouldBlock，但**不计**欠载。
        assert_eq!(node.read_at(0, &mut buf), Err(Error::WouldBlock));
        assert_eq!(
            node.ring().underruns(),
            0,
            "empty read without an attached consumer is not an underrun"
        );
        // buf 未被写入任何数据（S09：绝不返回伪数据）。
        assert_eq!(buf, [0u8; 16]);

        // 附加后：同样的空读必须计入欠载。
        assert_eq!(node.ring().attach(4242), Ok(()));
        assert_eq!(node.read_at(0, &mut buf), Err(Error::WouldBlock));
        assert_eq!(node.read_at(0, &mut buf), Err(Error::WouldBlock));
        assert_eq!(node.ring().underruns(), 2);

        // 有数据时正常消费，不计数。
        assert_eq!(node.write_at(0, &[1u8; 4]), Ok(4));
        assert_eq!(node.read_at(0, &mut buf), Ok(4));
        assert_eq!(node.ring().underruns(), 2, "successful read is not an underrun");
    }

    /// A2 消费者注册表：独占attach + 属主校验 + 退出清理（TDD 先行）。
    ///
    /// **S21 并发语义**：注册表是**独占单槽**——同一时刻只允许一个音频
    /// 驱动消费 PCM（plan §3.6）。并发第二个 attach 得到 `Busy`（EBUSY：
    /// 结构性占用，重试不会成功），而不是把第一个顶掉。
    #[test]
    fn test_audio_consumer_registry() {
        let ring = AudioRing::with_capacity(64);

        // 初始无消费者。
        assert_eq!(ring.consumer(), None);
        assert!(!ring.is_attached());

        // 首次 attach 成功，且立刻反映为已附加。
        assert_eq!(ring.attach(7), Ok(()));
        assert_eq!(ring.consumer(), Some(7));
        assert!(ring.is_attached());

        // 独占：同一 pid 重复 attach 亦被拒（幂等不是这里的语义）。
        assert_eq!(ring.attach(7), Err(Error::Busy));
        // 独占：另一个 pid attach 被拒，绝不抢占。
        assert_eq!(ring.attach(8), Err(Error::Busy));
        // 二者都未改变属主。
        assert_eq!(ring.consumer(), Some(7));

        // 属主校验：非属主 detach 被如实拒绝。
        assert_eq!(ring.detach(8), Err(Error::PermissionDenied));
        assert_eq!(ring.consumer(), Some(7), "failed detach must not clear owner");

        // 属主 detach 成功，槽位释放。
        assert_eq!(ring.detach(7), Ok(()));
        assert_eq!(ring.consumer(), None);
        assert!(!ring.is_attached());

        // 释放后新消费者可以 attach。
        assert_eq!(ring.attach(8), Ok(()));
        assert_eq!(ring.consumer(), Some(8));

        // 退出清理：detach_any 幂等，非属主调用不报错（进程正在死亡）。
        ring.detach_any(999);
        assert_eq!(ring.consumer(), Some(8), "detach_any by non-owner must be a no-op");
        ring.detach_any(8);
        assert_eq!(ring.consumer(), None);
        ring.detach_any(8);
        assert_eq!(ring.consumer(), None, "detach_any must be idempotent");
    }

    /// A2 attach/detach 必须与 `is_attached` 的写路径门禁**同源**。
    ///
    /// 即：注册表状态就是写门禁依据——不存在"注册表说没人、写门禁说有人"
    /// 的分裂（S15 单点定义；历史上分裂的两份状态是伪数据的温床）。
    #[test]
    fn test_audio_attach_gates_write_path() {
        let node = DspNode::with_capacity(64);
        // 未 attach：写入如实失败。
        assert_eq!(node.write_at(0, &[1u8; 8]), Err(Error::NotSupported));
        // attach 后：写入成功。
        assert_eq!(node.ring().attach(42), Ok(()));
        assert_eq!(node.write_at(0, &[1u8; 8]), Ok(8));
        // detach 后：写入重新失败（证明门禁读的是注册表本身）。
        assert_eq!(node.ring().detach(42), Ok(()));
        assert_eq!(node.write_at(0, &[1u8; 8]), Err(Error::NotSupported));
        // 数据未因 detach 被丢弃（buf 里的 8 字节仍在 ring，水位不变）。
        assert_eq!(node.ring().used(), 8);
    }

    /// A2 status 的 consumer 字段必须是**真实**属主，且随 attach/detach 变化。
    #[test]
    fn test_audio_status_consumer_field() {
        let node = DspNode::with_capacity(64);
        let mut buf = [0u8; 512];
        let read_status = |n: &DspNode, b: &mut [u8; 512]| -> alloc::string::String {
            let st = n.lookup("status").unwrap();
            let k = st.read_at(0, b).unwrap();
            alloc::string::String::from(core::str::from_utf8(&b[..k]).unwrap())
        };
        // 无消费者 → JSON null（不是 0，不是 -1：0 是合法 pid）。
        let s0 = read_status(&node, &mut buf);
        assert!(s0.contains(r#""consumer":null"#), "no consumer must be null: {s0}");
        assert!(s0.contains(r#""attached":false"#), "{s0}");

        // 有消费者 → 真实 pid。
        assert_eq!(node.ring().attach(1234), Ok(()));
        let s1 = read_status(&node, &mut buf);
        assert!(s1.contains(r#""consumer":1234"#), "must disclose real owner pid: {s1}");
        assert!(s1.contains(r#""attached":true"#), "{s1}");

        // detach 后回到 null。
        assert_eq!(node.ring().detach(1234), Ok(()));
        let s2 = read_status(&node, &mut buf);
        assert!(s2.contains(r#""consumer":null"#), "{s2}");
    }
    // ------------------------------------------------------------------

    fn a11_ident(uid: u32, gid: u32) -> Subject<'static> {
        Subject { uid, gid, groups: &[] }
    }

    /// classic mode 构造助手：三段同值（r=4/w=2/x=1 每段）。
    fn a11_mode(r: bool, w: bool, x: bool) -> u32 {
        let seg = (if r { 4 } else { 0 }) | (if w { 2 } else { 0 }) | (if x { 1 } else { 0 });
        (seg << 6) | (seg << 3) | seg
    }

    #[test]
    fn test_access_policy_rule1_first_match_decides() {
        // 首匹配即决：deny 前置命中 owner 即停，隐式尾部的 allow 不再参与。
        // from_classic/new 的属主过渡态是 (0,0)：owner 语义用 uid0 身份验证。
        let policy = AccessPolicy::from_classic(0o777);
        let ace = Ace { principal: Principal::Owner, allow: false, perms: PermBits::WRITE, inherit: false };
        let deny_first = AccessPolicy::new(alloc::vec![ace], 0o777);
        let owner = a11_ident(0, 1000);
        assert_eq!(policy.evaluate(&owner, PermBits::WRITE), Ok(()), "classic 0777 owner 写放行");
        assert_eq!(
            deny_first.evaluate(&owner, PermBits::WRITE),
            Err(Error::PermissionDenied),
            "deny 前置：首匹配即决，不合并隐式尾部 allow"
        );
    }

    #[test]
    fn test_access_policy_rule1_hit_stops_scan() {
        // 命中即停（§2.1）：首条匹配的显式 allow 短路后置 deny——隐式尾部在
        // 全部显式 ACE 之后（§2.2），不存在"隐式 owner-allow 短路显式 deny"。
        let policy = AccessPolicy::new(
            alloc::vec![
                Ace { principal: Principal::NamedUid(1000), allow: true, perms: PermBits::WRITE, inherit: false },
                Ace { principal: Principal::Other, allow: false, perms: PermBits::WRITE, inherit: false },
            ],
            0o777,
        );
        let alice = a11_ident(1000, 1000);
        assert_eq!(policy.evaluate(&alice, PermBits::WRITE), Ok(()), "首条 NamedUid allow 命中即停，Other deny 不再参与");
        let stranger = a11_ident(2002, 2002);
        assert_eq!(policy.evaluate(&stranger, PermBits::WRITE), Err(Error::PermissionDenied), "非 alice 落到 Other deny");
    }

    #[test]
    fn test_access_policy_rule2_positional_deny_first() {
        // 位置表达 deny 优先：两条 ACE 均匹配 owner，先 deny 后 allow → 拒绝。
        let policy = AccessPolicy::new(
            alloc::vec![
                Ace { principal: Principal::Owner, allow: false, perms: PermBits::WRITE, inherit: false },
                Ace { principal: Principal::Owner, allow: true, perms: PermBits::WRITE, inherit: false },
            ],
            0o777,
        );
        let owner = a11_ident(0, 0);
        assert_eq!(policy.evaluate(&owner, PermBits::WRITE), Err(Error::PermissionDenied), "位置 deny 优先：先命中先决");
    }

    #[test]
    fn test_access_policy_rule3_implicit_classic_0644() {
        // 经典 0644（无显式 ACE）：owner rw / group r / other r —— 与 POSIX 一致。
        // from_classic_owned 烙印真属主 (1000,1000)（A1-1 起构造器支持）。
        let policy = AccessPolicy::from_classic_owned(0o644, 1000, 1000);
        let owner = a11_ident(1000, 1000);
        let peer = a11_ident(1001, 1000);
        let stranger = a11_ident(2000, 2000);
        assert_eq!(policy.evaluate(&owner, PermBits::READ.union(PermBits::WRITE)), Ok(()), "0644 owner 可读写");
        assert_eq!(policy.evaluate(&peer, PermBits::READ), Ok(()), "0644 同组可读");
        assert_eq!(policy.evaluate(&peer, PermBits::WRITE), Err(Error::PermissionDenied), "0644 同组不可写");
        assert_eq!(policy.evaluate(&stranger, PermBits::READ), Ok(()), "0644 其他可读");
        assert_eq!(policy.evaluate(&stranger, PermBits::WRITE), Err(Error::PermissionDenied), "0644 其他不可写");
    }

    #[test]
    fn test_access_policy_rule3_implicit_classic_0700() {
        // 经典 0700：group/other 全拒（隐式三条与 POSIX 一致）。
        let policy = AccessPolicy::from_classic_owned(0o700, 1000, 1000);
        let stranger = a11_ident(2000, 2000);
        assert_eq!(policy.evaluate(&stranger, PermBits::READ), Err(Error::PermissionDenied), "0700 其他不可读");
        assert_eq!(policy.evaluate(&stranger, PermBits::WRITE), Err(Error::PermissionDenied), "0700 其他不可写");
        assert_eq!(policy.evaluate(&stranger, PermBits::EXECUTE), Err(Error::PermissionDenied), "0700 其他不可执行");
        let owner = a11_ident(1000, 1000);
        assert_eq!(policy.evaluate(&owner, PermBits::ALL), Ok(()), "0700 owner 全放行");
    }

    #[test]
    fn test_access_policy_named_uid_gid_and_group_membership() {
        // NamedUid/NamedGid 精确匹配 + 组成员身份（groups 集合包含即可）。
        let policy = AccessPolicy::new(
            alloc::vec![
                Ace { principal: Principal::NamedUid(1001), allow: true, perms: PermBits::READ, inherit: false },
                Ace { principal: Principal::NamedGid(2000), allow: true, perms: PermBits::READ, inherit: false },
            ],
            0,
        );
        let bob = a11_ident(1001, 1001);
        assert_eq!(policy.evaluate(&bob, PermBits::READ), Ok(()), "NamedUid 精确命中");
        assert_eq!(policy.evaluate(&bob, PermBits::WRITE), Err(Error::PermissionDenied), "ACE 只授 Read");
        let group_member = Subject { uid: 3000, gid: 9, groups: &[2000] };
        assert_eq!(policy.evaluate(&group_member, PermBits::READ), Ok(()), "NamedGid 经组成员命中");
        let outsider = a11_ident(3000, 9);
        assert_eq!(policy.evaluate(&outsider, PermBits::READ), Err(Error::PermissionDenied), "非成员落到隐式 other（mode 0000 全拒）");
    }

    #[test]
    fn test_access_policy_other_principal_is_catch_all() {
        // Other 是兜底 principal：显式 Other-ACE 优先于隐式三条。
        let policy = AccessPolicy::new(
            alloc::vec![Ace { principal: Principal::Other, allow: true, perms: PermBits::READ, inherit: false }],
            a11_mode(true, false, false),
        );
        let stranger = a11_ident(4321, 4321);
        assert_eq!(policy.evaluate(&stranger, PermBits::READ), Ok(()), "显式 Other 兜底放行");
        assert_eq!(policy.evaluate(&stranger, PermBits::WRITE), Err(Error::PermissionDenied), "兜底只授 Read");
    }

    #[test]
    fn test_access_policy_owner_semantics_by_uid_not_gid() {
        // owner 判据是 uid；同 gid 不同 uid 命中 group 段而非 owner。
        let policy = AccessPolicy::from_classic_owned(0o644, 1000, 1000);
        let same_gid = Subject { uid: 1001, gid: 1000, groups: &[] };
        // 0644 的组段只有 r：同组 WRITE 拒绝、READ 放行（命中 group 段的证明）。
        assert_eq!(policy.evaluate(&same_gid, PermBits::WRITE), Err(Error::PermissionDenied), "同组命中 group 段（仅 r）");
        assert_eq!(policy.evaluate(&same_gid, PermBits::READ), Ok(()), "同组可读（group 段命中）");
        let outsider = a11_ident(3000, 9);
        assert_eq!(policy.evaluate(&outsider, PermBits::WRITE), Err(Error::PermissionDenied), "非属主非同组 → other 段不可写");
        let same_uid = a11_ident(1000, 9999);
        assert_eq!(policy.evaluate(&same_uid, PermBits::WRITE), Ok(()), "uid 相同即 owner，gid 无关");
    }

    #[test]
    fn test_access_policy_inherit_flag_roundtrip() {
        // inherit 标志是存储语义位（目录新建继承），求值不解读它——如实往返。
        let ace = Ace { principal: Principal::Owner, allow: false, perms: PermBits::WRITE, inherit: true };
        assert!(ace.inherit, "inherit 标志往返保真");
    }

    #[test]
    fn test_access_policy_wire_roundtrip() {
        // wire：classic 9 位直通（不含门禁位），from_wire/to_wire 往返保真。
        let p = AccessPolicy::from_wire(0o644);
        assert_eq!(p.classic_mode(), 0o644, "wire 直通往返");
        assert_eq!(p.to_wire() & !GATE_SYSTEM_BIT, 0o644, "wire 往返（屏蔽门禁位）");
        let p2 = AccessPolicy::from_classic(0o640);
        assert_eq!(p2.classic_mode(), 0o640, "classic 构造往返");
    }
}

    // ------------------------------------------------------------------
    // A1-1 / ADR-040 §2.1–§2.2：AccessPolicy 三规则 + 经典三段降级单测。
    // 求值规则（§2.1 单点）：
    //   1. 按序扫描 ACE 列表，第一条 principal 匹配调用者即决（Allow→放行，Deny→EACCES）；
    //   2. 扫描完毕无匹配 → 末尾三条隐式 ACE（owner/group/other）。
    // deny 优先由「有序 + 首匹配即决」的位置表达，不存在第二条判定路径。