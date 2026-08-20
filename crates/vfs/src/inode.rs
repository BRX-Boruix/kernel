//! VFS 核心 INode 与文件系统抽象（ADR-011）。

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use klib::error::Error;

/// 节点类型。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum INodeType {
    RegularFile,
    Directory,
    CharacterDevice,
    BlockDevice,
    Symlink,
    Fifo,
}

/// 现代能力权限标签（ADR-011，淘汰 755/644）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permissions {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub system_only: bool,
}

impl Permissions {
    pub const fn all() -> Self {
        Self {
            readable: true,
            writable: true,
            executable: true,
            system_only: false,
        }
    }

    pub const fn readonly() -> Self {
        Self {
            readable: true,
            writable: false,
            executable: false,
            system_only: false,
        }
    }

    pub const fn read_write() -> Self {
        Self {
            readable: true,
            writable: true,
            executable: false,
            system_only: false,
        }
    }

    pub const fn read_exec() -> Self {
        Self {
            readable: true,
            writable: false,
            executable: true,
            system_only: false,
        }
    }

    pub const fn to_bits(self) -> u32 {
        let mut bits = 0;
        if self.readable { bits |= 1 << 0; }
        if self.writable { bits |= 1 << 1; }
        if self.executable { bits |= 1 << 2; }
        if self.system_only { bits |= 1 << 3; }
        bits
    }

    pub const fn from_bits(bits: u32) -> Self {
        Self {
            readable: (bits & (1 << 0)) != 0,
            writable: (bits & (1 << 1)) != 0,
            executable: (bits & (1 << 2)) != 0,
            system_only: (bits & (1 << 3)) != 0,
        }
    }
}

/// 精简三时间戳元数据（ADR-011，无 atime）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileMetadata {
    pub node_type: INodeType,
    pub size: u64,
    pub permissions: Permissions,
    pub created_time: u64,
    pub modified_time: u64,
    pub changed_time: u64,
}

/// 目录项（动态 String，无路径/文件名长度上限）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub node_type: INodeType,
    pub size: u64,
}

/// 核心文件节点抽象。
pub trait INode: Send + Sync {
    /// 读数据（从指定 offset 开始）。
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> Result<usize, Error> {
        Err(Error::NotSupported)
    }

    /// 写数据（从指定 offset 开始）。
    fn write_at(&self, _offset: u64, _buf: &[u8]) -> Result<usize, Error> {
        Err(Error::NotSupported)
    }

    /// 获取元数据。
    fn metadata(&self) -> Result<FileMetadata, Error>;

    /// 截断/调整大小。
    fn truncate(&self, _size: u64) -> Result<(), Error> {
        Err(Error::NotSupported)
    }

    // ---- 目录专用操作 ----

    /// 查找直接子节点。
    fn lookup(&self, _name: &str) -> Result<Arc<dyn INode>, Error> {
        Err(Error::NotDirectory)
    }

    /// 创建普通文件。
    fn create(&self, _name: &str, _perm: Permissions) -> Result<Arc<dyn INode>, Error> {
        Err(Error::NotDirectory)
    }

    /// 创建子目录。
    fn mkdir(&self, _name: &str, _perm: Permissions) -> Result<Arc<dyn INode>, Error> {
        Err(Error::NotDirectory)
    }

    /// 删除子项。
    fn unlink(&self, _name: &str) -> Result<(), Error> {
        Err(Error::NotDirectory)
    }

    /// 列出所有子目录项。
    fn list_dir(&self) -> Result<Vec<DirEntry>, Error> {
        Err(Error::NotDirectory)
    }

    // ---- 符号链接专用操作 ----

    /// 读取软链接目标路径字符串。
    fn read_link(&self) -> Result<String, Error> {
        Err(Error::NotSupported)
    }

    /// 创建软链接节点。
    fn symlink(&self, _name: &str, _target: &str) -> Result<Arc<dyn INode>, Error> {
        Err(Error::NotDirectory)
    }
}

/// 文件系统抽象。
pub trait FileSystem: Send + Sync {
    /// 获取根 INode。
    fn root(&self) -> Arc<dyn INode>;
    /// 文件系统类型名（如 "ramfs", "devfs", "procfs"）。
    fn name(&self) -> &'static str;
}
