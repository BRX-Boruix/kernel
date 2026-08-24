//! VFS 核心 INode 与文件系统抽象（ADR-011 / ADR-023）。
//!
//! ## 时间戳政策（vfs1 A3，ADR-023 §7 成文）
//!
//! `FileMetadata` 三个时间戳的语义按文件系统类别区分：
//! - **RamFS**：真实存储，出生/写/条目变更均取 `klib::time` 单调毫秒
//!   （单调钟非 wall clock——S03；wall clock 时间源接线是独立里程碑）；
//! - **EXT2**：盘上真值（fs1 FM1：mtime/ctime 直读，created 恒 0 =
//!   "rev1 无该字段"的成文事实）；
//! - **无状态视图节点**（procfs/devfs/sysfs/dynamic/stdio）：恒 0。0 的
//!   含义是"视图没有出生时刻"，不是伪造的时间零点（1970）。视图内容
//!   每次读取都重新生成，任何时间戳都会是谎言。

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
    /// 套接字节点。fs1 FA1：EXT2 mode 忠实映射要求七类盘上类型全部可表示
    /// ——缺 Socket 会把 0xC000 静默错报成别的类别（S09 禁伪数据）。
    Socket,
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
        if self.readable {
            bits |= 1 << 0;
        }
        if self.writable {
            bits |= 1 << 1;
        }
        if self.executable {
            bits |= 1 << 2;
        }
        if self.system_only {
            bits |= 1 << 3;
        }
        bits
    }

    /// 按位解码权限。
    ///
    /// KD7 成文策略（宽松掩码）：未知高位静默忽略（与 OpenFlags::from_bits
    /// 同一族决策——位集演进不破坏旧二进制）；需要严格语义时调用方自行做
    /// to_bits 往返比对。位分配见 [`Self::to_bits`]。
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

    /// 是否可定位（KM17/KM1）：字符流节点返回 `false`——syscall 层据此对
    /// 非顺序偏移如实报 `IllegalSeek`，而不是靠 fd 号魔法数字判断。
    fn is_seekable(&self) -> bool {
        true
    }

    /// 空读时是否应阻塞等待键盘输入（KM1/K1a）：仅标准输入为 `true`。
    /// syscall 层把该类句柄的 `WouldBlock` 翻译为登记等待者并切换进程，
    /// 其余句柄的 `WouldBlock` 如实上抛。
    fn interactive_input(&self) -> bool {
        false
    }

    /// 获取元数据。
    fn metadata(&self) -> Result<FileMetadata, Error>;

    /// 廉价节点类型查询（ADR-023 §4 / vfs1 A5）。
    ///
    /// 路径解析热路径用它判定软链接/目录：**不得执行动态内容生成、堆
    /// 分配或任何带副作用的计算**。历史上 resolve 用 `metadata()?.node_type`
    /// 判定软链接，导致读一次 `/processes/N/status` 在解析阶段就把 JSON
    /// 完整生成一遍再丢弃。默认实现退回 [`Self::metadata`] 以兼容第三方
    /// 实现；本 crate 内全部实现必须提供零生成覆盖。
    fn node_type(&self) -> INodeType {
        self.metadata()
            .map(|m| m.node_type)
            .unwrap_or(INodeType::RegularFile)
    }

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
