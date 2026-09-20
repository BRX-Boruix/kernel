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

/// 权限披露标签（ADR-011，淘汰 755/644）。
///
/// **诚实边界（2026-09，todo.md D-MU-C1）**：`readable`/`writable`/`executable`
/// 当前为**披露字段，不参与访问判定**（唯一强制点是 `system_only`，
/// 见 kernel `enforce_open_permission`）。称其为"能力"名不副实。
/// [ADR-040](../../../docs/adr/040-multi-user-access-model.md)（PROPOSED）将把本结构
/// 重构为有序 ACE 列表并建立真实强制矩阵；落地前请勿依据本字段编写安全逻辑。
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

/// stat 系统调用的 ABI 结果结构（内核→用户，经 syscall 整块拷出）。
///
/// `#[repr(C)]` 固定布局，与 `libsys` 侧同名镜像结构逐字段一致——这是 syscall
/// 边界的真实数据契约（S06），任一例改字段必须同步另一侧，否则是静默错位伪数据。
/// `node_type` 用稳定数字标签（见 [`StatInfo::type_tag`]），与 readdir 的 `type`
/// 字符串同义但可整块拷贝。
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatInfo {
    /// 节点类型稳定数字标签（[`StatInfo::type_tag`]）。
    pub node_type: u32,
    /// 文件字节大小。
    pub size: u64,
    /// 权限位（`Permissions::to_bits` 编码：readable=0/writable=1/executable=2/system_only=3）。
    pub perms: u32,
    /// 创建时间（Unix 秒；EXT2 rev1 无 crtime 字段时如实 0）。
    pub created_time: u64,
    /// 修改时间（Unix 秒）。
    pub modified_time: u64,
    /// 变更时间（Unix 秒）。
    pub changed_time: u64,
}

impl StatInfo {
    /// `INodeType` → 稳定数字标签（与 ADR-013 readdir `type` 字符串同义）。
    pub fn type_tag(t: INodeType) -> u32 {
        match t {
            INodeType::RegularFile => 1,
            INodeType::Directory => 2,
            INodeType::CharacterDevice => 3,
            INodeType::BlockDevice => 4,
            INodeType::Symlink => 5,
            INodeType::Fifo => 6,
            INodeType::Socket => 7,
        }
    }

    /// 从元数据构造 ABI 结果。
    pub fn from_metadata(m: &FileMetadata) -> Self {
        Self {
            node_type: Self::type_tag(m.node_type),
            size: m.size,
            perms: m.permissions.to_bits(),
            created_time: m.created_time,
            modified_time: m.modified_time,
            changed_time: m.changed_time,
        }
    }
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
    ///
    /// **A2 说明**：本方法与 [`Self::blocks_when_empty`] 是**不同**的语义——
    /// 前者专指"键盘输入"（等待源是 PS/2 中断），后者泛指"空读应当睡眠"。
    /// 保留本方法是为了让 stdin 的既有路径逐位不变（回归零风险）；新增节点
    /// 应当覆写 `blocks_when_empty` 而非本方法。
    fn interactive_input(&self) -> bool {
        false
    }

    /// 空读时是否应阻塞等待（A2，plan §3.5）：节点自述其 `WouldBlock` 是否
    /// 表示"稍后会有数据"而非"永久不可读"。
    ///
    /// **为何需要**：syscall 层此前以 `interactive_input()` 硬编码判定唯一的
    /// 阻塞场景（stdin）。音频 `dsp` 节点同样需要空读阻塞，但它不是键盘输入，
    /// 复用 `interactive_input` 会让 stdio.rs 的注释与实现凭空多出一个它不负责
    /// 的语义。本方法把"要不要睡"从**调用方的硬编码特判**变成**节点的自我描述**
    /// （S15 单点定义：语义归节点所有，syscall 层只做转发）。
    ///
    /// **默认 `false`**（S17 理由）：绝大多数节点（ramfs/procfs/sysfs/块设备）
    /// 的空读是真实的 EOF 或永久不可读，睡眠没有意义且会挂死调用者。默认不阻塞
    /// 是安全侧——需要阻塞的节点明确覆写，漏写只会导致"如实 WouldBlock"，
    /// 不会导致"莫名其妙挂起"。
    fn blocks_when_empty(&self) -> bool {
        false
    }

    /// 若本节点暴露音频 PCM ring，返回其共享句柄；否则 `None`（A2）。
    ///
    /// **为何是 trait 方法而非 downcast**：`Arc::downcast` 要求 `INode: Any`，
    /// 会给一个被十余种节点实现的 trait 加全局约束（牵动 ramfs/procfs/sysfs/
    /// stdio 等无关类型）。显式访问器保持 object-safe，并把"暴露音频 ring"变成
    /// **被声明的能力**（S15）而非运行时类型试探——后者类型不匹配时只能返回
    /// `None`，无法区分"不是音频节点"与"是音频节点但暂不可用"。
    ///
    /// **默认 `None`**（S17 理由）：音频 ring 是本计划专有的新概念，其余节点
    /// 一律没有；默认安全侧，漏写只会导致如实 `NotSupported`，不会错认节点。
    fn as_audio_ring(&self) -> Option<alloc::sync::Arc<crate::audio::AudioRing>> {
        None
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
    ///
    /// **S09**：返回 `Result`——默认实现 `metadata()` 失败时如实上抛，绝不
    /// 静默兜底为 `RegularFile`（旧 `unwrap_or(RegularFile)` 把任意错误
    /// 伪装成普通文件，属伪数据）。本 crate 内实现均零成本覆盖，热路径
    /// 不可达此默认。
    fn node_type(&self) -> Result<INodeType, Error> {
        self.metadata().map(|m| m.node_type)
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

    /// 设置权限（chmod 原语）。
    ///
    /// 覆写节点权限为 `perms`（r/w/x/system_only 四布尔）。默认实现返回
    /// [`Error::NotSupported`]——只读虚拟文件系统（procfs/sysfs/devfs）如实
    /// 拒绝；本 crate 内 RamFS 与 EXT2 提供实现。
    fn set_permissions(&self, _perms: Permissions) -> Result<(), Error> {
        Err(Error::NotSupported)
    }

    /// 在**同一目录内**重命名子项（ADR-014 SYS_ENTRY_UPDATE 0x43 的原语）。
    ///
    /// 把子项 `old_name` 改名/移动到本目录内的 `new_name`：不动内容、只改目录
    /// 项键（保 inode 身份）。约定：
    /// - `old_name` 不存在 → [`Error::NotFound`]；
    /// - `new_name` 已存在 → [`Error::AlreadyExists`]（不静默覆盖）；
    /// - 调用方（`MountTable::rename`）已先校验名字合法与同目录前提。
    ///
    /// 默认实现返回 [`Error::NotSupported`]——跨目录/跨文件系统移动不在本原语
    /// 语义内（调用方返回 NotSupported，宁缺毋假）。本 crate 内 RamFS 提供实现；
    /// 其余 FS（devfs/procfs/sysfs）如实 NotSupported。
    fn rename(&self, _old_name: &str, _new_name: &str) -> Result<(), Error> {
        Err(Error::NotSupported)
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

    /// **稳定文件身份**：同一个文件在不同时间、不同路径解析下必须给出相同的值。
    ///
    /// # 为什么需要它（而不是用 `Arc` 地址）
    ///
    /// 文件锁（`crate::flock`）需要"这两次拿到的 inode 是否是同一个文件"的判据。
    /// 此前用 `Arc::as_ptr(inode)` 当身份，**那是错的**：
    ///
    /// - RamFS 的 `lookup` 返回子节点表里**缓存的同一个 `Arc`**，两次 open
    ///   同路径得到相同地址——恰好像是对的；
    /// - EXT2 的 `lookup` **每次都 `Arc::new(Ext2Node { .. })`**，两次 open 同
    ///   一个文件得到**不同地址**——锁互不可见，互斥静默失效。
    ///
    /// 两种实现行为不一致，而 `Arc` 地址还会被分配器**复用**：一个已释放文件的
    /// 地址可能被下一个创建的文件拿到，使无关文件凭空继承前者的锁记录。
    /// 故身份必须由**文件系统自己**给出，而不是内存布局的副产物。
    ///
    /// # 契约
    ///
    /// - **相等 ⇔ 同一个文件**。取值范围不限，但同一文件在进程/时间/路径变化下
    ///   必须恒等；不同文件必须不等（碰撞会导致假锁冲突）。
    /// - 只要求**单次启动内**稳定（跨重启无意义：锁表本身是内存态）。
    /// - 默认实现见 [`Self::stable_id`] 的默认体——无状态视图节点（procfs/devfs/
    ///   stdio/dynamic）天然"一个实例就是一个文件"，返回基于 `self` 地址的标识
    ///   即可；**有持久身份的存储型节点必须覆写**（EXT2 用 `ino`）。
    ///
    /// # 默认实现为何基于 `self` 地址仍是正确的
    ///
    /// 无状态视图节点的 `lookup` 同样可能每次新建实例（如 procfs 的每 pid 文件），
    /// 但那类节点**不支持 flock**（无持久锁语义，见各实现的 `read_at`/`write_at`）
    /// ——身份不稳定的唯一实际后果是锁表里出现互不相干的两条记录，随后由
    /// `flock_release_all_for_owner` 在进程退出时清掉。存储型节点（EXT2/RamFS）
    /// 必须覆写本方法，因为它们**是**可加锁的真实文件。
    fn stable_id(&self) -> u64 {
        self as *const Self as *const () as u64
    }
}

/// 文件系统抽象。
pub trait FileSystem: Send + Sync {
    /// 获取根 INode。
    fn root(&self) -> Arc<dyn INode>;
    /// 文件系统类型名（如 "ramfs", "devfs", "procfs"）。
    fn name(&self) -> &'static str;
}
