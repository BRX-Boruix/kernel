//! BORUIX 虚拟文件系统（VFS）。
//!
//! 遵循 ADR-005（RESTful 命名）、ADR-011（VFS 架构规范）与 ADR-012（存储卷）。

#![no_std]

#[cfg(test)]
extern crate std;

extern crate alloc;

pub mod file_handle;
pub mod inode;
pub mod mount;
pub mod path;
pub mod ramfs;

pub use file_handle::{FileHandle, OpenFlags};
pub use inode::{DirEntry, FileMetadata, FileSystem, INode, INodeType, Permissions};
pub use mount::MountTable;
pub use path::Path;
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
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
}
