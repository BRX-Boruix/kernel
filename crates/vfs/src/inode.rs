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

// ======================================================================
// A1-1 / ADR-040 §2.1–§2.5：AccessPolicy 访问策略模型（D-MU-C1 消解）。
// 经典 755/644 与四布尔 `Permissions` 均被本模型取代——全系统只有
// §2.1 一个求值算法（`evaluate`），不存在第二条判定路径。
// ======================================================================

/// 权限位集（Read/Write/Execute）。
///
/// 位分配与 classic 三段解耦：本类型是"单一请求所需/单条 ACE 所授"的
/// 权限集合，不携带属主归属信息（三段归属由 [`AccessPolicy`] 的隐式
/// 尾部 ACE 表达）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PermBits {
    bits: u8,
}

impl PermBits {
    pub const READ: Self = Self { bits: 1 };
    pub const WRITE: Self = Self { bits: 2 };
    pub const EXECUTE: Self = Self { bits: 4 };
    pub const ALL: Self = Self { bits: 7 };

    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    pub const fn union(self, other: Self) -> Self {
        Self { bits: self.bits | other.bits }
    }

    /// 本集合是否**覆盖**所需位集（`required` 的每一位置都在本集合中）。
    pub const fn contains(self, required: Self) -> bool {
        self.bits & required.bits == required.bits
    }

    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }

    /// classic 三段中的一段（r=4/w=2/x=1）→ 权限位集。
    pub const fn from_classic_segment(seg: u32) -> Self {
        Self {
            bits: (((seg & 4) != 0) as u8) | ((((seg & 2) != 0) as u8) << 1) | ((((seg & 1) != 0) as u8) << 2),
        }
    }

    /// 权限位集 → classic 三段中的一段（r=4/w=2/x=1）。
    pub const fn to_classic_segment(self) -> u32 {
        (((self.bits & 1) != 0) as u32) << 2 | (((self.bits & 2) != 0) as u32) << 1 | ((self.bits & 4) != 0) as u32
    }
}

/// ACE 主体形态（ADR-040 §2.4 单点定义）。
///
/// `Owner` 的判据是"调用者 uid == 节点属主 uid"（属主归属见
/// [`AccessPolicy`] 的 `owner_uid`/`owner_gid`）；`NamedGid` 的判据是
/// 调用者主组或补充组命中（组成员身份，ADR-040 §2.5）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Principal {
    Owner,
    NamedUid(u32),
    NamedGid(u32),
    Other,
}

/// 单条访问控制项（有序列表的元素；位置即优先级）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ace {
    pub principal: Principal,
    /// `true` = Allow（放行），`false` = Deny（拒绝，EACCES）。
    pub allow: bool,
    /// 本 ACE 授予/拒绝的权限位。
    pub perms: PermBits,
    /// 目录继承标记（A1-5 落地目录新建继承语义；求值不解读本位）。
    pub inherit: bool,
}

// ======================================================================
// A2-6 / ADR-040 §3.5.1 G4：显式 ACE 的 **wire 通道**（用户态读写门径）。
//
// 背景：`to_wire`/`from_wire` 是**单个 u32** 的 classic 直通形态，无 ACE 通道
// ——用户态既读不到也写不了显式 ACE，本 ADR 的核心创新（deny 优先/按主体授权）
// 只能由内核侧构造。
//
// 设计裁定（本项，按 S38 记录，可复议）：采用**独立定长 ACE 数组**形态，而
// **不**扩展 `StatInfo` 内联块。理由（皆为本仓既有规范约束，非偏好）：
//   1. ADR-040 §2.10 要求「参数只用定长数字」——定长数组满足，变长 blob 不满足；
//   2. §2.4 PRE-12 纪律规定 `StatInfo` 是定长 `#[repr(C)]` 且**只许向尾部增长**。
//      把 ACE 内联进 `StatInfo` 会让**每一次 stat** 都背负约 256B 拷贝（多数调用
//      方并不需要 ACE），且迫使全部既有 stat 调用点与两侧镜像断言同变更——代价
//      与收益不成比例；
//   3. 读写可分离：`perms` 字段保持单 u32 classic 直通**不变**（既有 ABI 零破坏），
//      ACE 经独立的读/写动词进出。
//
// 编码（双侧镜像，PRE-12：任一侧改字段必须同变更同步）：
//   wire ACE 定长 24 字节 = { principal_kind, principal_id, allow, perms,
//                            inherit, reserved } 各 u32
//   principal_kind: 0=Owner, 1=NamedUid, 2=NamedGid, 3=Other（Owner/Other 时 id 须为 0）
// 本模块是**唯一**编解码点（S13）。
// ======================================================================

/// wire 上的单条 ACE（定长 24 字节；`#[repr(C)]`）。
///
/// 与 `libsys` 侧同名镜像结构逐字段一致（PRE-12）：任一侧改字段必须同变更同步。
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AceWire {
    /// 主体类别：0=Owner, 1=NamedUid, 2=NamedGid, 3=Other。
    pub principal_kind: u32,
    /// 主体 id（NamedUid/NamedGid 的 uid/gid；Owner/Other 须为 0）。
    pub principal_id: u32,
    /// 1=Allow，0=Deny。
    pub allow: u32,
    /// 权限位（Read=1/Write=2/Execute=4 的位集，取值范围 0..=7）。
    pub perms: u32,
    /// 目录继承标记（0/1）。
    pub inherit: u32,
    /// 保留（须为 0；**不**做静默忽略——非 0 即 InvalidParam）。
    pub reserved: u32,
}

/// 单条 wire ACE 的字节大小（双侧断言用）。
pub const ACE_WIRE_SIZE: usize = 24;

/// 一次 ACE 传输允许的**最大条数**（定长数组上界）。
///
/// 取值理由：ACE 是「按主体授权」的精细表达，实际策略规模在个位数～十几条；
/// 64 条（1536 字节）已远超真实需要，同时把单次系统调用拷贝量钉在可控范围
/// （ADR-018 用户缓冲上限之内），避免用户态以「超大 ACE 表」制造资源压力。
pub const ACE_WIRE_MAX: usize = 64;

/// wire 主体类别编码（与 `AceWire::principal_kind` 同点定义，S13）。
pub const ACE_PRINCIPAL_OWNER: u32 = 0;
pub const ACE_PRINCIPAL_NAMED_UID: u32 = 1;
pub const ACE_PRINCIPAL_NAMED_GID: u32 = 2;
pub const ACE_PRINCIPAL_OTHER: u32 = 3;

impl AceWire {
    /// wire → [`Ace`]。**严格校验**：未知主体类别 / 越界权限位 / 非 0 保留位 /
    /// 非 0/1 的 allow/inherit 一律 `InvalidParam`。
    ///
    /// 为何严格而非「尽力解读」（S09）：静默忽略未知位会让**用户态以为自己设了
    /// 限制、实际没有生效**——那是安全面的伪成功。宁可如实报错。
    pub fn to_ace(self) -> Result<Ace, Error> {
        if self.reserved != 0 {
            return Err(Error::InvalidParam);
        }
        if self.allow > 1 || self.inherit > 1 {
            return Err(Error::InvalidParam);
        }
        if self.perms > 7 {
            return Err(Error::InvalidParam);
        }
        let principal = match self.principal_kind {
            ACE_PRINCIPAL_OWNER => Principal::Owner,
            ACE_PRINCIPAL_NAMED_UID => Principal::NamedUid(self.principal_id),
            ACE_PRINCIPAL_NAMED_GID => Principal::NamedGid(self.principal_id),
            ACE_PRINCIPAL_OTHER => Principal::Other,
            _ => return Err(Error::InvalidParam),
        };
        // Owner/Other 不带 id；非 0 视为调用方理解错误，如实拒绝（不静默丢弃）。
        if matches!(principal, Principal::Owner | Principal::Other) && self.principal_id != 0 {
            return Err(Error::InvalidParam);
        }
        let mut perms = PermBits::empty();
        if self.perms & 1 != 0 {
            perms = perms.union(PermBits::READ);
        }
        if self.perms & 2 != 0 {
            perms = perms.union(PermBits::WRITE);
        }
        if self.perms & 4 != 0 {
            perms = perms.union(PermBits::EXECUTE);
        }
        Ok(Ace {
            principal,
            allow: self.allow == 1,
            perms,
            inherit: self.inherit == 1,
        })
    }

    /// [`Ace`] → wire（逆映射；`Owner`/`Other` 的 `principal_id` 恒 0）。
    pub fn from_ace(ace: Ace) -> Self {
        let (kind, id) = match ace.principal {
            Principal::Owner => (ACE_PRINCIPAL_OWNER, 0),
            Principal::NamedUid(uid) => (ACE_PRINCIPAL_NAMED_UID, uid),
            Principal::NamedGid(gid) => (ACE_PRINCIPAL_NAMED_GID, gid),
            Principal::Other => (ACE_PRINCIPAL_OTHER, 0),
        };
        let b = ace.perms;
        let mut perms = 0u32;
        if b.contains(PermBits::READ) {
            perms |= 1;
        }
        if b.contains(PermBits::WRITE) {
            perms |= 2;
        }
        if b.contains(PermBits::EXECUTE) {
            perms |= 4;
        }
        Self {
            principal_kind: kind,
            principal_id: id,
            allow: ace.allow as u32,
            perms,
            inherit: ace.inherit as u32,
            reserved: 0,
        }
    }
}

/// 系统门禁 wire 位（bit9）。
///
/// **迁址说明**：旧 `Permissions::system_only` 占用 wire bit3，与 classic
/// 三段（bit0..8）冲突。A1-1 起门禁位迁至 bit9；旧 bit3 在 >`0o7` 输入下
/// 按 classic group 段位解读（现网无发送方——libsys `system_only` 恒
/// `false`，见各调用点）。门禁语义与强制点不变（open/exec）。
pub const GATE_SYSTEM_BIT: u32 = 1 << 9;

/// 访问主体视图（vfs 侧借用形态）。
///
/// **为何不是 `task::ProcessIdentity`**：依赖方向是 `task → vfs`，vfs
/// 反向依赖 task 会成环。本视图只含求值所需最小字段；kernel 强制点
/// （A1-3 单点 `check_access`）在调用 [`AccessPolicy::evaluate`] 前从
/// `ProcessIdentity` 借出本视图（`Groups::iter` 零拷贝切片）。
#[derive(Clone, Copy, Debug)]
pub struct Subject<'a> {
    pub uid: u32,
    pub gid: u32,
    /// 补充组（`Groups::iter` 借出；不含主组——主组见 `gid`）。
    pub groups: &'a [u32],
}

/// 访问策略本体（ADR-040 §2.1/§2.2）。
///
/// # 模型
///
/// ```text
/// 有效策略 = [ 显式 ACE 列表... ] ++ [ owner-ACE, group-ACE, other-ACE ]
/// ```
///
/// 三条隐式尾部 ACE 由 `mode`（classic 9 位）派生，经典 0644/0700 语义
/// 自动保留；显式 ACE 位置表达 deny 优先。全系统只有 [`Self::evaluate`]
/// 一个求值算法。
///
/// # 求值细则（本 ADR 草图 §2.1 的成文化补全）
///
/// 决定性 ACE = 有序扫描中**第一条 principal 匹配调用者且 perms 覆盖所需位**
/// 的 ACE：Allow → 放行；Deny → `PermissionDenied`。perms 不覆盖所需位的
/// ACE 跳过（NFSv4 applicability 约定——否则"deny W"会连带拒绝无关的 R，
/// 与经典三段等价性要求冲突）。扫描完毕无决定性 ACE → 拒绝。
///
/// # 诚实边界（A1-1 过渡态，S39）
///
/// - 属主暂为 `(0,0)`（`from_classic`/`from_wire`）：EXT2 `i_uid`/`i_gid`
///   真值与 RamFS 真属主存取是 A1-5 项；当前 uid0 进程是事实属主，行为
///   与过渡期一致。创建点（`create`/`mkdir`）已带属主参数并真实烙印
///   （RamFS 本体、EXT2 留位待 A1-5 盘上持久化）。
/// - 内核强制矩阵接线（read/write/readdir/unlink/chmod）是 A1-3 项；
///   当前强制点仍只有 open/exec。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessPolicy {
    /// 显式 ACE 列表（有序；空 = 纯经典三段）。
    aces: Vec<Ace>,
    /// classic 9 位 mode（隐式尾部真值来源；盘上/wire 直通形态）。
    mode: u32,
    /// 属主 uid（Owner principal 的匹配判据；A1-5 接真值）。
    owner_uid: u32,
    /// 属主 gid（隐式 group-ACE 的 NamedGid 判据；A1-5 接真值）。
    owner_gid: u32,
    /// 系统门禁位（open/exec 强制点使用；wire bit9）。
    gate_system: bool,
}

impl AccessPolicy {
    /// classic 9 位 mode 构造（无显式 ACE；属主过渡态 `(0,0)`）。
    pub const fn from_classic(mode: u32) -> Self {
        Self {
            aces: Vec::new(),
            mode: mode & 0o777,
            owner_uid: 0,
            owner_gid: 0,
            gate_system: false,
        }
    }

    /// classic 构造 + 真属主（创建点烙印 / EXT2 读侧 / 单测用）。
    pub fn from_classic_owned(mode: u32, owner_uid: u32, owner_gid: u32) -> Self {
        Self {
            aces: Vec::new(),
            mode: mode & 0o777,
            owner_uid,
            owner_gid,
            gate_system: false,
        }
    }

    /// 显式 ACE 列表 + classic 尾部构造（属主过渡态 `(0,0)`）。
    pub fn new(aces: Vec<Ace>, classic_mode: u32) -> Self {
        Self {
            aces,
            mode: classic_mode & 0o777,
            owner_uid: 0,
            owner_gid: 0,
            gate_system: false,
        }
    }

    /// 置系统门禁位（open/exec 强制点语义；wire bit9）。
    pub fn with_gate_system(mut self) -> Self {
        self.gate_system = true;
        self
    }

    /// 系统门禁位是否置位。
    pub const fn gate_system(&self) -> bool {
        self.gate_system
    }

    /// classic 9 位（不含门禁位；盘上 mode 直通形态）。
    pub const fn classic_mode(&self) -> u32 {
        self.mode
    }

    /// 属主 uid（A1-4 StatInfo 暴露 / A1-5 接真值）。
    pub const fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    /// 属主 gid。
    pub const fn owner_gid(&self) -> u32 {
        self.owner_gid
    }

    /// A1-5：以真属主覆写（EXT2 i_uid/i_gid 读侧 / RamFS 属主烙印）。
    pub fn set_owner(&mut self, uid: u32, gid: u32) {
        self.owner_uid = uid;
        self.owner_gid = gid;
    }

    /// wire 解码（syscall 参数/chmod 的位集入参）。
    ///
    /// **wire 兼容映射**（KD7 宽松掩码政策的 A1-1 版）：
    /// - `bits ≤ 0o7`：旧披露位（bit0=r/bit1=w/bit2=x，三段同权）——按旧
    ///   语义等值展开为三段同值 classic（如 `0o5` → `0o555`）。现网全部
    ///   发送方（libsys/libc）都落在该区，行为逐位不变；
    /// - `bits > 0o7`：classic 9 位直通（`bits & 0o777`）+ 门禁位 bit9
    ///   （[ `GATE_SYSTEM_BIT`]）。新发送方（A1-3+/libc 归真）走该区；
    /// - 未知高位静默忽略（与 OpenFlags::from_bits 同族决策）。
    pub fn from_wire(bits: u32) -> Self {
        let gate = bits & GATE_SYSTEM_BIT != 0;
        let mode = if bits <= 0o7 {
            let seg = PermBits::from_classic_segment(bits).to_classic_segment();
            seg << 6 | seg << 3 | seg
        } else {
            bits & 0o777
        };
        Self {
            aces: Vec::new(),
            mode,
            owner_uid: 0,
            owner_gid: 0,
            gate_system: gate,
        }
    }

    /// wire 编码（StatInfo/syscall 回传）。
    ///
    /// classic 9 位直通 + 门禁位 bit9（若有）。**恒为 classic 形态**——
    /// 只有盘上/wire 直通来源的策略会进入本分支；统一披露展开的输入
    /// 经 `from_wire` 已是三段同值 classic，往返保真。
    pub const fn to_wire(&self) -> u32 {
        self.mode | ((self.gate_system as u32) << 9)
    }

    /// 只替换 **classic 9 位 mode**、保留显式 ACE 列表与门禁位的副本。
    ///
    /// A2-6 前置（ADR-040 §3.5.3）：`chmod` 是**写门径**，不是"重建策略"。
    /// 此前强制层经 `from_wire(mode)` 重建——而 `from_wire` 恒产出空 ACE 列表
    /// （wire 只有一个 u32，无 ACE 通道），于是**一次 chmod 就把全部显式 ACE 清零**。
    /// 显式 deny 被清空后主体会落到 classic 尾部段，可能**由拒绝变放行**——
    /// 静默策略降级。本方法提供"只改 mode、其余原样"的正确写回形态（S13 单点）。
    /// 只替换 **显式 ACE 列表**、其余维度原样（A2-6）。
    ///
    /// 与 [`Self::with_classic_mode`] 对称：`chmod` 只动 mode，`set_aces` 只动
    /// 显式列表。两者都**不**碰属主与门禁位——"一次只改一维"是防止写门径之间
    /// 互相静默削弱的关键纪律（§3.5.3 的病因正是 chown/chmod 顺手重建了整份策略）。
    pub fn with_explicit_aces(&self, aces: Vec<Ace>) -> Self {
        Self {
            aces,
            mode: self.mode,
            owner_uid: self.owner_uid,
            owner_gid: self.owner_gid,
            gate_system: self.gate_system,
        }
    }

    pub fn with_classic_mode(&self, mode: u32) -> Self {
        Self {
            aces: self.aces.clone(),
            mode: mode & 0o777,
            owner_uid: self.owner_uid,
            owner_gid: self.owner_gid,
            gate_system: self.gate_system,
        }
    }

    /// 返回**属主替换为 `(uid, gid)`** 的策略副本（A1-5）。
    ///
    /// 用途：chmod/set_permissions 写回路径——chmod 是写门径而非易主
    /// （POSIX 语义：chmod 不改属主），自存储本体（盘上 i_uid/i_gid /
    /// RamFS 策略字段）补全属主后整体写回。显式 ACE 如实整体替换，
    /// **不做** ACE 归属重写。
    ///
    /// 依赖注记：不提供「读当前进程属主」的 vfs 级助手——task 依赖 vfs，
    /// 反向助手会成环；fs 层属主来源由调用方（kernel trait 层 / fs 原语
    /// 参数）携带。
    pub fn with_owner(&self, uid: u32, gid: u32) -> Self {
        Self {
            aces: self.aces.clone(),
            mode: self.mode,
            owner_uid: uid,
            owner_gid: gid,
            gate_system: self.gate_system,
        }
    }

    /// 有效策略：显式列表 ++ 三条隐式尾部 ACE（ADR-040 §2.2）。
    ///
    /// **命中即停**由 [`Self::evaluate`] 的首匹配即决保证；本方法只负责
    /// 序列展开，不做合并、不取并集。
    pub fn effective_aces(&self) -> impl Iterator<Item = Ace> + '_ {
        let seg_owner = (self.mode >> 6) & 7;
        let seg_group = (self.mode >> 3) & 7;
        let seg_other = self.mode & 7;
        let tail = [
            Ace {
                principal: Principal::Owner,
                allow: true,
                perms: PermBits::from_classic_segment(seg_owner),
                inherit: false,
            },
            Ace {
                principal: Principal::NamedGid(self.owner_gid),
                allow: true,
                perms: PermBits::from_classic_segment(seg_group),
                inherit: false,
            },
            Ace {
                principal: Principal::Other,
                allow: true,
                perms: PermBits::from_classic_segment(seg_other),
                inherit: false,
            },
        ];
        self.aces.iter().copied().chain(tail)
    }

    /// 显式 ACE 列表（不含三条隐式尾部 ACE）。
    ///
    /// A2-8：继承派生与用户态策略读取都要看**显式**列表本身，故提供本访问器
    /// （`effective_aces` 会把隐式尾部混进来，不适合做"复制哪些"的判据）。
    pub fn explicit_aces(&self) -> impl Iterator<Item = Ace> + '_ {
        self.aces.iter().copied()
    }

    /// A2-8 / ADR-040 §3.5 G3：**按父目录策略派生新建子节点的策略**。
    ///
    /// 语义（忠实于现有数据结构——"一条 ACE 一个 `inherit` 位"，不引入第二条
    /// 求值路径 S13）：
    /// - 父目录显式列表中 `inherit == true` 的 ACE **原样复制**进子节点显式列表
    ///   （含其 `inherit` 位——使继承在多级目录下**继续向下传播**，与 Windows/NFSv4
    ///   "inheritable 标志随行"一致）；
    /// - `inherit == false` 的显式 ACE **不复制**（仅对父目录自身生效）；
    /// - 父目录的 classic 三段**不复制**：`classic_mode` 取**创建请求**给定的 mode
    ///   （POSIX：`mkdir(dir, 0755)` 的 mode 决定子目录自身三段）。**不**做
    ///   "父三段 & 请求三段"的隐式掩码——那会造出第二条权限推导路径（S13 禁止），
    ///   且会静默削弱调用方显式给定的权限。
    /// - 属主**不**继承父目录：由调用方在创建点按创建者烙印（POSIX，见 `with_owner`）。
    /// - 门禁位**不**继承：门禁是节点级系统语义，不是目录派生物（不得经"在门禁
    ///   目录里建文件"来扩散门禁——那是权限放大面）。
    ///
    /// 返回的子策略仍是一个普通 `AccessPolicy`，求值照旧走唯一算法 `evaluate`。
    pub fn derive_for_child(&self, classic_mode: u32) -> Self {
        let inherited: Vec<Ace> = self.aces.iter().filter(|a| a.inherit).copied().collect();
        Self {
            aces: inherited,
            mode: classic_mode & 0o777,
            owner_uid: 0, // 由创建点 with_owner 烙印为创建者
            owner_gid: 0,
            gate_system: false,
        }
    }

    /// **唯一求值算法**（ADR-040 §2.1）：首匹配即决 + 隐式尾部兜底。
    ///
    /// 规则：
    /// 1. 按序扫描 [`Self::effective_aces`]，取第一条 principal 匹配
    ///    `subject` 且 `perms` 覆盖 `required` 的 ACE：Allow → 放行；
    ///    Deny → [`Error::PermissionDenied`]；
    /// 2. 扫描完毕无决定性 ACE → [`Error::PermissionDenied`]（安全侧）。
    ///
    /// `CAP_OWNER` 绕过（ADR-040 §2.6：持有者在求值前直接放行）由
    /// **调用方**处理——本方法只看策略，不看能力位（S13 单点：能力
    /// 豁免属于强制矩阵，不属于策略本体）。
    pub fn evaluate(&self, subject: &Subject, required: PermBits) -> Result<(), Error> {
        for ace in self.effective_aces() {
            if principal_matches(&ace.principal, subject, self) && ace.perms.contains(required) {
                return if ace.allow {
                    Ok(())
                } else {
                    Err(Error::PermissionDenied)
                };
            }
        }
        Err(Error::PermissionDenied)
    }
}

/// Principal 匹配判据（[`AccessPolicy::evaluate`] 专用）。
///
/// `Owner` ⇔ uid 等于属主；`NamedGid` ⇔ 主组或补充组命中（组成员身份，
/// ADR-040 §2.5）；`Other` 恒匹配（兜底段）。
fn principal_matches(principal: &Principal, subject: &Subject, policy: &AccessPolicy) -> bool {
    match *principal {
        Principal::Owner => subject.uid == policy.owner_uid,
        Principal::NamedUid(uid) => subject.uid == uid,
        Principal::NamedGid(gid) => subject.gid == gid || subject.groups.contains(&gid),
        Principal::Other => true,
    }
}

impl AccessPolicy {
    /// 全权限 classic（0777 三段同值）。
    ///
    /// 兼容旧 `Permissions::all()` 的披露语义（r/w/x 对三段同权）。
    pub const fn all() -> Self {
        Self::from_classic(0o777)
    }

    /// 只读 classic（0444）。
    pub const fn readonly() -> Self {
        Self::from_classic(0o444)
    }

    /// 读写 classic（0666）。
    pub const fn read_write() -> Self {
        Self::from_classic(0o666)
    }

    /// 读执行 classic（0555）——内置可执行 payload 的真实形态。
    pub const fn read_exec() -> Self {
        Self::from_classic(0o555)
    }
}

/// 精简三时间戳元数据（ADR-011，无 atime）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileMetadata {
    pub node_type: INodeType,
    pub size: u64,
    pub permissions: AccessPolicy,
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
    /// 权限位（classic 9 位 owner/group/other 直通 + 系统门禁 bit9，
    /// 见 [`AccessPolicy::to_wire`]）。
    pub perms: u32,
    /// 创建时间（Unix 秒；EXT2 rev1 无 crtime 字段时如实 0）。
    pub created_time: u64,
    /// 修改时间（Unix 秒）。
    pub modified_time: u64,
    /// 变更时间（Unix 秒）。
    pub changed_time: u64,
    /// 属主 uid（A1-4 / ADR-040 §2.4：**尾部追加**——repr(C) 布局只许
    /// 向尾部增长，两侧（kernel↔libsys）必须同变更同步；PRE-12 纪律）。
    pub owner_uid: u32,
    /// 属主 gid（同上）。
    pub owner_gid: u32,
    /// 本 fd 是否为终端（ADR-044 §1.2 / J-TOKEN-A）：`1` = 是，`0` = 否/未知。
    ///
    /// **尾部追加**（与 `owner_uid`/`owner_gid` 同一纪律）：`repr(C)` 布局只许
    /// 向尾部增长，既有字段偏移不变。kernel↔libsys 两侧必须同变更同步。
    ///
    /// **为何不是 `bool`**：跨 ABI 边界用定长整数，避免依赖两侧对 `bool` 的
    /// 表示约定（Rust `bool` 是 1 字节但有效值仅 0/1——显式 `u32` 更稳）。
    /// `0` 兼作「未知」：`from_metadata` 无节点身份，不得虚报，故默认 0。
    pub is_terminal: u32,
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

    /// 补写终端真值（供 syscall 层：拿到 inode 后调 `is_terminal()`）。
    ///
    /// 拆为独立构造器而非给 `from_metadata` 加参数：后者的契约是
    /// 「从元数据忠实投影」，而终端性不在元数据里（它是节点的自我描述）。
    /// 混在一起会让「元数据有什么就报什么」这一安全性质变模糊。
    pub fn with_terminal(mut si: Self, is_terminal: bool) -> Self {
        si.is_terminal = u32::from(is_terminal);
        si
    }

    /// 从元数据构造 ABI 结果。
    ///
    /// A1-4：属主字段取自节点 [`AccessPolicy`] 本体（A1-1 起策略即存储
    /// 属主；`from_classic` 过渡态为 (0,0)，EXT2 `i_uid` 真值归 A1-5——
    /// 字段自本项起如实投影，不再伪造 0）。
    pub fn from_metadata(m: &FileMetadata) -> Self {
        Self {
            node_type: Self::type_tag(m.node_type),
            size: m.size,
            perms: m.permissions.to_wire(),
            created_time: m.created_time,
            modified_time: m.modified_time,
            changed_time: m.changed_time,
            owner_uid: m.permissions.owner_uid(),
            owner_gid: m.permissions.owner_gid(),
            // 终端性由**节点**自述，而本函数只看得见 `FileMetadata`（无
            // 节点身份）——故此处**不得虚报**，统一为 0（未知）。
            // 真值由 syscall 层（`sys_fstat`）拿到 inode 后补写。
            is_terminal: 0,
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
    /// 本节点是否为**终端**（ADR-044 §1.2，决策 2）：`isatty` 的真值依据。
    ///
    /// **默认 `false`**（S17 安全侧）：绝大多数节点（ramfs/procfs/sysfs/块设备/
    /// 普通文件）都不是终端，漏写覆写只会导致 `isatty` 如实返回 0，**不会**把
    /// 一个普通文件误报成终端。只有标准流节点覆写为 `true`。
    ///
    /// **为何是节点真值而非调用方特判**（S15）：这是 `interactive_input()` /
    /// `blocks_when_empty()` 的同款模式——语义归节点所有，调用方只做转发。
    /// 此前 `libc` 的 `isatty` 硬编码 `fd ∈ {0,1,2} → 1`，那是**按 fd 号猜测**
    /// 而非询问真值：stdout 被重定向到普通文件后仍是 fd 1，却依旧被报成终端。
    fn is_terminal(&self) -> bool {
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

    /// 创建普通文件（A1-1：`mode` 为 classic 9 位；属主 = 创建者，POSIX 语义
    /// ——wire 只传 mode，杜绝"冒充他人属主创建"；chown 是唯一改属主通道）。
    fn create(&self, _name: &str, _mode: u32, _owner: (u32, u32)) -> Result<Arc<dyn INode>, Error> {
        Err(Error::NotDirectory)
    }

    /// 创建子目录（属主语义同 [`Self::create`]）。
    fn mkdir(&self, _name: &str, _mode: u32, _owner: (u32, u32)) -> Result<Arc<dyn INode>, Error> {
        Err(Error::NotDirectory)
    }

    /// 删除子项。
    fn unlink(&self, _name: &str) -> Result<(), Error> {
        Err(Error::NotDirectory)
    }

    /// 设置权限（chmod 原语，A1-1）：整体替换节点 [`AccessPolicy`]。
    ///
    /// **语义边界**：wire chmod 只携带 classic 位集（无 ACE 通道），故整体
    /// 替换即"重写 classic 段"；显式 ACE 的用户态写入门径属 A2-6（第一阶段
    /// 经内核测试路径构造，S39 如实披露）。
    ///
    /// A1-3 / ADR-040 §2.6：**调用方**（sys_entry_update 的 chmod 动作）须
    /// 先过属主校验（属主或 `CAP_OWNER`，见 kernel `check_chmod_access`）。
    /// 默认实现返回 [`Error::NotSupported`]——只读虚拟文件系统（procfs/
    /// sysfs/devfs）如实拒绝；本 crate 内 RamFS 与 EXT2 提供实现。
    fn set_permissions(&self, _policy: &AccessPolicy) -> Result<(), Error> {
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

/// PRE-12 / A1-4：**两侧镜像一致性断言**（编译期钉死）。
///
/// kernel vfs::inode::StatInfo 与 libsys::StatInfo 是同一 ABI 结构的两侧，
/// `#[repr(C)]` 布局逐字段一致是跨边界数据契约（S06）。此处把本侧的
/// 尺寸与属主字段偏移钉成常量；libsys 侧镜像同值断言（见 libsys/src/io.rs）。
/// 任一侧**尾部**追加字段而另一侧未同步时，两侧 sizeof 不等——宿主侧可
/// 直接对拍（kernel 宿主测试 / libsys 单测读同一对常量）；本侧先以编译期
/// 常量形式登记真值。
pub const STAT_INFO_SIZE: usize = core::mem::size_of::<StatInfo>();

const _: () = {
    assert!(STAT_INFO_SIZE == 64, "StatInfo layout drifted: sync libsys mirror");
    assert!(core::mem::offset_of!(StatInfo, owner_uid) == 48);
    assert!(core::mem::offset_of!(StatInfo, owner_gid) == 52);
    // J-TOKEN-A：终端真值尾部追加，偏移钉死。
    assert!(core::mem::offset_of!(StatInfo, is_terminal) == 56);
};
