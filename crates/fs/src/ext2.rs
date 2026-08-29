//! EXT2 只读文件系统驱动（C13.2；fs1 整改后形态）。
//!
//! 布局事实源：`sdk/sdk_build/disk.py` 生成的镜像——MBR 分区 1（起始 LBA
//! 由 [`crate::mbr`] 解析得出），分区内 1024B 块、超级块 @分区偏移 1024、
//! 组描述符 @first_data_block+1 块、inode 表由组描述符指向。
//!
//! 只读边界（fs1 整改后形态 → M3 可写）：本模块自 M3 起提供**最小可写
//! 支集**（块/inode 分配释放、位图更新、目录项增删、superblock/GDT 记账、
//! 直块 + 一级/二级间接块、文件数据写、truncate），写路径经页缓存写穿一致性
//! 落盘（本内核无页缓存写回期，写即落盘）。读侧亦支持一级/二级间接
//! 寻址；仅三重间接仍显式拒绝（当前镜像与工作负载不需要，写侧 blocks[14]
//! 不分配，读侧遇三重间接文件如实报错）。VFS 节点 writable 恒为 true，写族方法
//! 如实返回 [`Error::ReadOnly`] 仅当底层 `ByteDevice::write_bytes` 不可写
//! （返回 0）时由短写映射为 IO 错误。
//!
//! ## 镜像元数据信任边界（fs1 FA2 / ADR-021）
//!
//! EXT2 以只读挂载、运行期用户态写不进去 ⇒ **运行期不存在元数据注入面**；
//! 恶意/损坏元数据的唯一来源是启动时选定的镜像本身。因此镜像元数据按
//! "受信但需结构性自洽"处理：不做密码学级校验，但所有进入分配决策的盘上
//! 数值（目录 size、块号、inode 号）必须通过 sanity 上限——违反即显式报错，
//! 绝不以受信为名触发 OOM 类自伤（kernel K7 同型防线）。
//!
//! ## 元数据诚实性（fs1 F1/FM1）
//!
//! `list_dir` 携带真实 size 与按 mode 权威判定的节点类型；`metadata` 返回
//! 盘上 mtime/ctime 真值。唯一保留的零值是 `created_time`：EXT2 rev1 没有
//! 创建时间字段，0 在此表示"字段不存在"（成文的不可得，非伪造数据）。
//!
//! ## 性能立场（fs1 FM3 / S32）
//!
//! 当前成本画像（解析级量化，非基准测量）：`read_dir_raw` 每有效目录项
//! 1 次 GDT 扇区读 + 1 次 inode 读（无缓存）；`lookup` 在其上再线性扫描；
//! `map_indirect` 每逻辑块重读整个间接块。**明示不做优化**：本内核的 EXT2
//! 只承载启动期静态镜像（/programs 数个文件），上述常数在 100Hz tick 的
//! 交互尺度下不可感知；而全项目尚无内核侧基准设施（S32 第三次撞见：term
//! T 系、loader、fs 同一欠账）。在基准设施立项前引入缓存属于无量化依据
//! 的投机改动——GDT 缓存、目录项缓存的收益必须等 benchmark 就绪后实测
//! 再决策。

use crate::ByteDevice;
use alloc::sync::Arc;
use alloc::vec::Vec;
use klib::error::Error;

/// 超级块魔数偏移与期望值。
const SB_MAGIC_OFFSET: usize = 56;
pub const EXT2_SUPER_MAGIC: u16 = 0xEF53;
/// 根目录 inode 号（EXT2 规范固定）。
pub const EXT2_ROOT_INO: u32 = 2;
/// fast symlink 目标内联区上限：i_block 15×u32 = 60 字节。
const FAST_SYMLINK_MAX: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ext2Error {
    /// 魔数不符——该分区不是可辨认的 EXT2。
    BadMagic,
    /// 设备短读：请求范围越过介质末尾或传输失败。
    ShortRead,
    /// inode 号为 0 或超出 s_inodes_count。
    BadInode,
    /// 逻辑块号映射出的物理块越出 s_blocks_count。
    BlockOutOfRange,
    /// 三重间接块：当前镜像与工作负载不需要，显式拒绝而非静默出错。
    UnsupportedTripleIndirect,
    /// 片段(fragment)大小与块大小不等——本驱动只支持等大片段。
    UnsupportedFragmentSize,
    /// 块大小超过 4KiB（log_block_size > 2）——独立于片段语义的拒绝项
    /// （fs1 FD1：此前误用 UnsupportedFragmentSize 上报，排查方向被带偏）。
    UnsupportedBlockSize,
    /// 目录项损坏（rec_len 越界或不满足最小长度、size 与结构矛盾等）。
    CorruptDirEntry,
    /// 超级块结构性损坏（计数/几何/字段自相矛盾）。S13：超级块解析失败
    /// 不应借用 CorruptDirEntry/BadInode 等子结构变体——语义误导排查方向。
    CorruptSuperblock,
    /// 调用方缓冲小于一个完整块（fs1 FM4：内部契约设防，不再切片 panic）。
    BufferTooSmall,
}

/// 解析后的超级块（只保留只读路径需要的字段）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ext2Superblock {
    pub blocks_count: u32,
    pub inodes_count: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub inode_size: u16,
    pub first_data_block: u32,
    pub block_size: u32,
    /// 卷标 `s_volume_name`（@120，16 字节，未用空间以 NUL 填充）。
    ///
    /// 用于 `/volumes/{label}` 命名（ADR-028 §决策2 / ADR-029 §决策1）。
    /// 卷标是镜像创建者声明的友好名，可能全零（无卷标）或任意字节；
    /// 见 [`Ext2Superblock::volume_name_str`] 的截断/合法性策略。
    pub volume_name: [u8; 16],
    /// 文件系统 UUID `s_uuid`（@104，16 字节，EXT2 rev1 起存在）。
    ///
    /// 用于 boot 来源判定的 FS UUID 比对（ADR-029 §决策3）。镜像创建者
    /// 可填任意 16 字节；全零表示"未声明 UUID"，比对时须视为无 UUID
    /// 而非一个等于零的 UUID（S09 宁缺毋假）。
    pub uuid: [u8; 16],
    /// `s_free_blocks_count`（@12）：全卷空闲块计数（M3 写路径记账锚点）。
    pub free_blocks_count: u32,
    /// `s_free_inodes_count`（@16）：全卷空闲 inode 计数（M3 写路径记账锚点）。
    pub free_inodes_count: u32,
}

impl Ext2Superblock {
    /// 卷标字符串访问器：截断到首个 NUL，无卷标（首字节即 0 或全零）返回空串。
    ///
    /// 卷标合法性策略（S02/S09）：卷标是镜像创建者声明的友好名，可能
    /// 含任意字节。返回 [`Option`] 而非直接 `&str`——非 UTF-8 的卷标不能
    /// 用 lossy 替换（那会篡改展示名），如实返回 `None` 让调用方走无卷标
    /// 降级命名（`storage-{ShortUUID}`，ADR-030 §决策2）。
    pub fn volume_name_str(&self) -> Option<&str> {
        let end = self
            .volume_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.volume_name.len());
        if end == 0 {
            return Some("");
        }
        core::str::from_utf8(&self.volume_name[..end]).ok()
    }

    /// FS UUID 是否未声明（全零）。
    ///
    /// 用于 boot 来源比对：全零 UUID 是"无 UUID"而非"UUID 为零值"，
    /// 与任何真实 boot UUID 都不应命中（S09 宁缺毋假）。
    pub fn uuid_is_zero(&self) -> bool {
        self.uuid.iter().all(|&b| b == 0)
    }
}

/// EXT2 目录项文件名最大长度（规范硬约束：`name_len` 字段仅 1 字节）。
const EXT2_NAME_LEN_MAX: usize = 255;

/// 校验一个 EXT2 目录项组件名（写入侧统一入口）。
///
/// 对齐 VFS 层 `MountTable::validate_name`（mount.rs）的合法字符集合，并叠加
/// EXT2 自身的 `name_len` 1 字节上限。三处规则归一，消除"读侧任意非 NUL、
/// 写侧只拒 `/`、VFS 额外拒控制字符"的三套不一致：
/// - 非空；
/// - 长度 ≤ 255（`name_len` u8 上限，超长显式拒绝，杜绝 `as u8` 静默截断）；
/// - 不含 `/`（路径分隔符，单组件名不允许）；
/// - 不含控制字符 `<0x20` 与 `0x7F`（与 VFS `validate_name` 同规则）。
///
/// 违反返回 [`Ext2Error::CorruptDirEntry`]，调用方再按需映射（S04：显式拒绝
/// 而非静默截断字节）。
fn validate_component_name(name: &str) -> Result<(), Ext2Error> {
    let b = name.as_bytes();
    if b.is_empty() || b.len() > EXT2_NAME_LEN_MAX {
        return Err(Ext2Error::CorruptDirEntry);
    }
    for &byte in b {
        if byte == b'/' || byte <= 0x1F || byte == 0x7F {
            return Err(Ext2Error::CorruptDirEntry);
        }
    }
    Ok(())
}

fn le_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

fn le_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// 解析 1024 字节超级块镜像。
///
/// fs1 FA2：blocks_count/inodes_count/first_data_block 施加结构性 sanity
/// ——零值或与块大小矛盾的 first_data_block 直接拒绝挂载，把"坏镜像"
/// 拦在分配任何资源之前。
pub fn parse_superblock(sb: &[u8; 1024]) -> Result<Ext2Superblock, Ext2Error> {
    if le_u16(sb, SB_MAGIC_OFFSET) != EXT2_SUPER_MAGIC {
        return Err(Ext2Error::BadMagic);
    }
    let log_block_size = le_u32(sb, 24);
    // 片段必须与块等大（disk.py 与主流 mkfs 均如此），否则寻址语义不同。
    if le_u32(sb, 28) != log_block_size {
        return Err(Ext2Error::UnsupportedFragmentSize);
    }
    // fs1 FD1：块大小超限是独立事实，不再借用片段变体。
    if log_block_size > 2 {
        return Err(Ext2Error::UnsupportedBlockSize);
    }
    let block_size = 1024u32 << log_block_size;
    let blocks_count = le_u32(sb, 4);
    let inodes_count = le_u32(sb, 0);
    if blocks_count == 0 || inodes_count == 0 {
        return Err(Ext2Error::CorruptSuperblock);
    }
    // EXT2 规范：first_data_block 为 1 当且仅当块大小 1024，否则为 0。
    let first_data_block = le_u32(sb, 20);
    let expect_fdb = if block_size == 1024 { 1 } else { 0 };
    if first_data_block != expect_fdb {
        return Err(Ext2Error::CorruptSuperblock);
    }
    let inode_size = if le_u32(sb, 76) >= 1 {
        let s = le_u16(sb, 88);
        // S19/S31：inode_size 必须 >=128（最小 inode 结构）且为 128 的倍数
        //（EXT2 规范），并**不得超过块大小**——一个 inode 表块最多容纳
        // block_size 字节的 inode 数据。损坏超级块声明超大 inode_size 会让
        // 每次 read_inode 按该值分配内核堆（自伤面），此处必须在解析期拒绝。
        if s < 128 || s % 128 != 0 || s as u32 > block_size {
            return Err(Ext2Error::CorruptSuperblock);
        }
        s
    } else {
        128
    };
    let blocks_per_group = le_u32(sb, 32);
    if blocks_per_group == 0 {
        return Err(Ext2Error::CorruptSuperblock);
    }
    // 卷标 @120、FS UUID @104：均 16 字节原始字段（EXT2 规范）。
    // 不在此做 UTF-8 校验——卷标可能任意字节，合法性判定交给消费方
    // （volume_name_str），解析层只负责忠实取出盘上真值。
    let mut volume_name = [0u8; 16];
    volume_name.copy_from_slice(&sb[120..136]);
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&sb[104..120]);
    Ok(Ext2Superblock {
        blocks_count,
        inodes_count,
        blocks_per_group,
        inodes_per_group: le_u32(sb, 40),
        inode_size,
        first_data_block,
        block_size,
        volume_name,
        uuid,
        free_blocks_count: le_u32(sb, 12),
        free_inodes_count: le_u32(sb, 16),
    })
}

/// 解析后的 inode（只含只读路径字段；i_block 为 15 项块指针）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inode {
    pub ino: u32,
    pub mode: u16,
    pub size: u32,
    pub blocks: [u32; 15],
    /// i_blocks（@28，512B 扇区计数）。fast/slow symlink 的权威判别位：
    /// fast 链接不占用任何数据块 ⇒ 恒为 0。注意不能用"目标首 4 字节是否
    /// 为零"判别——目标字符串本身就存放在 i_block 区。
    pub sectors: u32,
    /// i_mtime（@8）：内容最后修改时间，POSIX 秒。
    pub mtime: u32,
    /// i_ctime（@16）：inode 状态最后变更时间，POSIX 秒。
    pub ctime: u32,
}

impl Inode {
    pub fn is_dir(&self) -> bool {
        self.mode & 0xF000 == 0x4000
    }
    pub fn is_regular(&self) -> bool {
        self.mode & 0xF000 == 0x8000
    }
    pub fn is_symlink(&self) -> bool {
        self.mode & 0xF000 == 0xA000
    }
}

/// 目录项原始记录。
///
/// fs1 F1/FA1(b)：解析期即逐项读出关联 inode，把 `size` 与权威 `mode`
/// 一并带出——消费方（list_dir）不再需要二次查询，也不会把真实大小丢在
/// 盘上而向用户展示恒零伪值。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawDirEntry {
    pub inode: u32,
    pub file_type: u8,
    pub name: Vec<u8>,
    /// 关联 inode 的真实字节大小（权威来自 inode.size，非 ft 字节推断）。
    pub size: u32,
    /// 关联 inode 的 mode（类型判定的唯一权威源；ft 字节仅存档备查）。
    pub mode: u16,
}

/// 已挂载的 EXT2 文件系统实例（只读，廉价 Clone 句柄）。
#[derive(Clone)]
pub struct Ext2Fs {
    inner: Arc<Ext2Inner>,
}

/// 组描述符（M3 写路径需要位图块号与组级空闲计数）。
#[derive(Debug, Clone, Copy)]
struct GroupDesc {
    block_bitmap: u32,
    inode_bitmap: u32,
    inode_table: u32,
    free_blocks: u32,
    free_inodes: u32,
}

struct Ext2Inner {
    dev: Arc<dyn ByteDevice>,
    /// 分区起始字节地址 = 分区起始 LBA × 512。
    part_start_byte: u64,
    sb: Ext2Superblock,
}

impl Ext2Fs {
    /// 打开位于 `part_start_byte` 的 EXT2 分区并校验超级块。
    pub fn open(dev: Arc<dyn ByteDevice>, part_start_byte: u64) -> Result<Self, Ext2Error> {
        let mut sb_buf = [0u8; 1024];
        let n = dev.read_bytes(part_start_byte + 1024, &mut sb_buf);
        if n < 1024 {
            return Err(Ext2Error::ShortRead);
        }
        let sb = parse_superblock(&sb_buf)?;
        Ok(Self {
            inner: Arc::new(Ext2Inner {
                dev,
                part_start_byte,
                sb,
            }),
        })
    }

    pub fn superblock(&self) -> &Ext2Superblock {
        &self.inner.sb
    }

    /// 读取一个完整块到新分配的 Vec（M3 写路径便捷原语，与 `read_block`
    /// 同界：block 越界 / 短读如实报错，缓冲恒为整块）。
    fn read_block_buf(&self, block: u32) -> Result<alloc::vec::Vec<u8>, Ext2Error> {
        let bs = self.superblock().block_size as usize;
        let mut buf = alloc::vec![0u8; bs];
        self.read_block(block, &mut buf)?;
        Ok(buf)
    }

    /// 计算 inode 的 EXT2 规范 `i_blocks`（512 字节扇区计数）。
    ///
    /// 规范定义 `i_blocks` 为文件占用的全部 512B 扇区数，**含间接指针表块
    /// 自身**——旧实现 `size.div_ceil(512)` 只按数据字节推算，把间接块占用
    /// 漏记（偏小）。本函数按块映射结构逐级清点：直块 + 一级间接表（含其
    /// 数据指针）+ 二级间接表（含各级 L1 表及其数据指针），再乘以每块扇区数。
    /// 数据块按映射中的非零指针计（稀疏区不计）。三重间接区（blocks[14]）
    /// 不建模，若出现按真实占用量清点到 blocks[14] 本身仍照常计入其表块。
    fn count_sectors(&self, inode: &Inode) -> Result<u32, Ext2Error> {
        let bs = self.superblock().block_size as usize;
        let per_block = bs / 4;
        let sectors_per_block = (bs / 512) as u32;
        let mut blocks = 0u32;
        // 直块：非零即计。
        for &b in &inode.blocks[..12] {
            if b != 0 {
                blocks += 1;
            }
        }
        // 一级间接表（blocks[12]）：表块 1 + 非零数据指针。
        if inode.blocks[12] != 0 {
            blocks += 1;
            let l1 = self.read_block_buf(inode.blocks[12])?;
            for i in 0..per_block {
                if le_u32(&l1, i * 4) != 0 {
                    blocks += 1;
                }
            }
        }
        // 二级间接表（blocks[13]）：表块 1 + 各非零 L1 表块 + 各 L1 内非零数据指针。
        if inode.blocks[13] != 0 {
            blocks += 1;
            let dbl = self.read_block_buf(inode.blocks[13])?;
            for i in 0..per_block {
                let l1_ptr = le_u32(&dbl, i * 4);
                if l1_ptr == 0 {
                    continue;
                }
                blocks += 1; // L1 表块
                let l1 = self.read_block_buf(l1_ptr)?;
                for j in 0..per_block {
                    if le_u32(&l1, j * 4) != 0 {
                        blocks += 1;
                    }
                }
            }
        }
        // 三重间接表（blocks[14]）：本驱动不建模数据分配，但表块本身若存在
        // （外部工具写入）按真实占用量计入。
        if inode.blocks[14] != 0 {
            blocks += 1;
        }
        Ok(blocks * sectors_per_block)
    }

    /// 读取一个完整块。
    ///
    /// fs1 FM4：`out` 必须能容纳整个块——不足时显式返回
    /// [`Ext2Error::BufferTooSmall`]，不再对调用方缓冲做静默切片 panic。
    fn read_block(&self, block: u32, out: &mut [u8]) -> Result<(), Ext2Error> {
        let sb = self.superblock();
        if block >= sb.blocks_count {
            return Err(Ext2Error::BlockOutOfRange);
        }
        let bs = sb.block_size as usize;
        if out.len() < bs {
            return Err(Ext2Error::BufferTooSmall);
        }
        let off = self.inner.part_start_byte + block as u64 * bs as u64;
        let n = self.inner.dev.read_bytes(off, &mut out[..bs]);
        if n < bs {
            return Err(Ext2Error::ShortRead);
        }
        Ok(())
    }

    /// 读组描述符（GDT 位于 first_data_block + 1 块起，每项 32 字节）：
    /// 返回 (块位图块号, inode 位图块号, inode 表块号, 空闲块计数, 空闲 inode 计数)。
    ///
    /// fs1 FM4 附带：直接按 32 字节定长栈缓冲读取，不再整块分配堆内存
    /// 只为取前 32 字节。空闲计数 @12/@16 为 M3 写路径的组级记账锚点。
    fn read_group_desc(&self, group: u32) -> Result<GroupDesc, Ext2Error> {
        let sb = self.superblock();
        let gdt_block = (sb.first_data_block + 1) as u64;
        let mut buf = [0u8; 32];
        let off_abs =
            self.inner.part_start_byte + gdt_block * sb.block_size as u64 + group as u64 * 32;
        let n = self.inner.dev.read_bytes(off_abs, &mut buf);
        if n < 32 {
            return Err(Ext2Error::ShortRead);
        }
        Ok(GroupDesc {
            block_bitmap: le_u32(&buf, 0),
            inode_bitmap: le_u32(&buf, 4),
            inode_table: le_u32(&buf, 8),
            free_blocks: le_u16(&buf, 12) as u32,
            free_inodes: le_u16(&buf, 14) as u32,
        })
    }

    /// 按 inode 号读取 inode 结构。
    pub fn read_inode(&self, ino: u32) -> Result<Inode, Ext2Error> {
        let sb = self.superblock();
        if ino == 0 || ino > sb.inodes_count || sb.inodes_per_group == 0 {
            return Err(Ext2Error::BadInode);
        }
        let group = (ino - 1) / sb.inodes_per_group;
        let idx = (ino - 1) % sb.inodes_per_group;
        let gd = self.read_group_desc(group)?;
        let inode_table = gd.inode_table;
        let bs = sb.block_size as u64;
        let abs = self.inner.part_start_byte
            + inode_table as u64 * bs
            + idx as u64 * sb.inode_size as u64;
        let isz = sb.inode_size as usize;
        let mut raw = alloc::vec![0u8; isz];
        if self.inner.dev.read_bytes(abs, &mut raw) < isz {
            return Err(Ext2Error::ShortRead);
        }
        let mut blocks = [0u32; 15];
        for (i, slot) in blocks.iter_mut().enumerate() {
            *slot = le_u32(&raw, 40 + i * 4);
        }
        Ok(Inode {
            ino,
            mode: le_u16(&raw, 0),
            size: le_u32(&raw, 4),
            blocks,
            sectors: le_u32(&raw, 28),
            // fs1 FM1：时间戳真读——偏移就在已取回的原始字节里。
            mtime: le_u32(&raw, 8),
            ctime: le_u32(&raw, 16),
        })
    }

    /// 逻辑块号 → 物理块号。直接 12 块 + 一级/二级间接；三重间接显式拒绝。
    fn map_logical_block(&self, inode: &Inode, logical: u32) -> Result<u32, Ext2Error> {
        let per_block = self.superblock().block_size / 4;
        if logical < 12 {
            return Ok(inode.blocks[logical as usize]);
        }
        let mut rem = logical - 12;
        if rem < per_block {
            return self.map_indirect(inode.blocks[12], rem);
        }
        rem -= per_block;
        let l2_span = per_block * per_block;
        if rem < l2_span {
            let l1_idx = rem / per_block;
            let l1 = self.map_indirect(inode.blocks[13], l1_idx)?;
            return self.map_indirect(l1, rem % per_block);
        }
        Err(Ext2Error::UnsupportedTripleIndirect)
    }

    /// 从一级间接块中取出第 `idx` 个块指针（稀疏块返回 0）。
    fn map_indirect(&self, indirect_block: u32, idx: u32) -> Result<u32, Ext2Error> {
        if indirect_block == 0 {
            return Ok(0); // 稀疏：整个间接块为空洞
        }
        let bs = self.superblock().block_size as usize;
        let mut buf = alloc::vec![0u8; bs];
        self.read_block(indirect_block, &mut buf)?;
        let off = idx as usize * 4;
        if off + 4 > bs {
            return Err(Ext2Error::BlockOutOfRange);
        }
        Ok(le_u32(&buf, off))
    }

    /// 从 inode 数据区读取 `[offset, offset+buf.len())`，返回实际读取字节数。
    /// 越过文件末尾的部分不读取（EOF 截断）；稀疏块补零。
    pub fn read_inode_data(
        &self,
        inode: &Inode,
        mut offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, Ext2Error> {
        if offset >= inode.size as u64 {
            return Ok(0);
        }
        let avail = (inode.size as u64).saturating_sub(offset) as usize;
        let want = core::cmp::min(buf.len(), avail);
        let bs = self.superblock().block_size as u64;
        let mut done = 0usize;
        let mut scratch = alloc::vec![0u8; bs as usize];
        while done < want {
            let logical = (offset / bs) as u32;
            let in_block = (offset % bs) as usize;
            let take = core::cmp::min(want - done, bs as usize - in_block);
            let phys = self.map_logical_block(inode, logical)?;
            if phys == 0 {
                // 稀疏洞：真实语义是读出零。
                buf[done..done + take].fill(0);
            } else {
                self.read_block(phys, &mut scratch)?;
                buf[done..done + take].copy_from_slice(&scratch[in_block..in_block + take]);
            }
            done += take;
            offset += take as u64;
        }
        Ok(done)
    }

    /// 设备字节容量（fs1 FA2 / 审计 R7-F1 / S09-S20-S31）。
    ///
    /// 一切"盘上声明的字节数 → 内核分配量"的换算必须先过这道上界——
    /// 目录数据与符号链接目标同受此约束，单点实现防止政策执行面再次
    /// 出现遗漏（R7 正是 read_dir_raw 有帽而 read_link_target 无帽的
    /// 不一致被点名）。
    ///
    /// S09/S20/S31：上界**必须锚定真实设备容量** `dev.byte_len()`，不得
    /// 只信超级块几何。超级块来自不可信镜像：恶意镜像把 `s_blocks_count`
    /// 夸大即可让"目录/链接 size ≤ 设备容量"防线以虚高几何放行超真实
    /// 容量的分配声明 → `alloc::vec![0u8; size]` 触发内核 OOM 自伤，与
    /// "绝不以受信为名触发 OOM 自伤"矛盾。此处取几何与真实容量的较小者：
    /// 真实介质总是真值上限（寻址不可越界），几何只是结构一致性约束。
    ///
    /// 退化策略：设备不报告容量（`byte_len() == None`，非可寻址流设备）
    /// 时，退回超级块几何作为唯一可用的受信上限——此时介质无"真实末尾"
    /// 可比，几何是唯一的事实来源，但绝不因此无限放大。
    fn device_byte_capacity(&self) -> u64 {
        let sb = self.superblock();
        let sb_cap = sb.blocks_count as u64 * sb.block_size as u64;
        match self.inner.dev.byte_len() {
            Some(real) => core::cmp::min(sb_cap, real),
            None => sb_cap,
        }
    }

    /// 遍历目录 inode 的全部目录项。
    ///
    /// fs1 FA2：分配前先以"目录 size 不得超过设备块总数 × 块大小"设防——
    /// 损坏镜像声明 4GB 目录不再转化为内核 4GB 分配，而是显式
    /// [`Ext2Error::CorruptDirEntry`]。上限取自超级块的 blocks_count（同一
    /// 受信级别内的交叉验证），不是拍脑袋常数。
    ///
    /// fs1 F1/FA1(b)：有效项逐个 read_inode 把 size/mode 带出（方案 b，
    /// 解析期一次完成）；某项 inode 号非法即整目录报 BadInode——那是镜像
    /// 损坏的如实表达，好过静默产出伪条目。
    ///
    /// fs1 FD2：循环终止后剩余的 1..7 字节残段按规范属块对齐破坏迹象；
    /// 采取 lenient 跳过策略（残段不影响已解析条目）并 klib::warn 留痕，
    /// 策略本身在此成文。
    pub fn read_dir_raw(&self, dir: &Inode) -> Result<Vec<RawDirEntry>, Ext2Error> {
        if !dir.is_dir() {
            return Err(Ext2Error::CorruptDirEntry);
        }
        let max_dir_bytes = self.device_byte_capacity();
        if dir.size as u64 > max_dir_bytes {
            return Err(Ext2Error::CorruptDirEntry);
        }
        let mut data = alloc::vec![0u8; dir.size as usize];
        let n = self.read_inode_data(dir, 0, &mut data)?;
        data.truncate(n);
        let mut out = Vec::new();
        let mut cur = 0usize;
        while cur + 8 <= data.len() {
            let ino = le_u32(&data, cur);
            let rec_len = le_u16(&data, cur + 4) as usize;
            let name_len = data[cur + 6] as usize;
            let ft = data[cur + 7];
            if rec_len < 8 || cur + rec_len > data.len() {
                return Err(Ext2Error::CorruptDirEntry);
            }
            if ino != 0 && name_len > 0 {
                if 8 + name_len > rec_len {
                    return Err(Ext2Error::CorruptDirEntry);
                }
                let linked = self.read_inode(ino)?;
                out.push(RawDirEntry {
                    inode: ino,
                    file_type: ft,
                    name: data[cur + 8..cur + 8 + name_len].to_vec(),
                    size: linked.size,
                    mode: linked.mode,
                });
            }
            cur += rec_len;
        }
        if cur < data.len() {
            // fs1 FD2：lenient 但可见——损坏迹象绝不静默。
            klib::warn!(
                "[ext2] dir ino={} trailing {} unaligned byte(s) skipped",
                dir.ino,
                data.len() - cur
            );
        }
        Ok(out)
    }

    /// 读取符号链接目标（fs1 FA1 补完）。
    ///
    /// EXT2 双形态判别用 i_blocks（[`Inode::sectors`]）：fast 链接不占数据
    /// 块 ⇒ 恒 0；目标 ≤60B 内联在 i_block 区。slow 链接目标存常规数据块。
    /// 此前 read_inode_data 把 fast link 当数据块读必然读到垃圾，本函数是
    /// 两种形态的唯一正确入口。
    pub fn read_link_target(&self, inode: &Inode) -> Result<Vec<u8>, Ext2Error> {
        if !inode.is_symlink() {
            return Err(Ext2Error::CorruptDirEntry);
        }
        let size = inode.size as u64;
        if inode.sectors == 0 {
            // fast：目标即 i_block 区原始字节。blocks 数组就是该区间的
            // LE u32 视图，重组后按 size 截取。
            if size == 0 || size > FAST_SYMLINK_MAX {
                return Err(Ext2Error::CorruptDirEntry);
            }
            let mut out = Vec::with_capacity(size as usize);
            for w in inode.blocks.iter() {
                out.extend_from_slice(&w.to_le_bytes());
            }
            out.truncate(size as usize);
            Ok(out)
        } else {
            // slow：目标在常规数据块链上，按普通文件读。分配前先过设备
            // 容量上界（R7-F1：与目录 size 同一政策同一单点——损坏镜像
            // 声明的超大目标在此被拒，绝不转化为内核巨型分配）。
            if size == 0 || size > self.device_byte_capacity() {
                return Err(Ext2Error::CorruptDirEntry);
            }
            let mut buf = alloc::vec![0u8; size as usize];
            let n = self.read_inode_data(inode, 0, &mut buf)?;
            buf.truncate(n);
            Ok(buf)
        }
    }

    /// 目录内按名查找。
    pub fn lookup_in_dir(&self, dir: &Inode, name: &str) -> Result<(u32, Inode), Error> {
        let entries = self.read_dir_raw(dir).map_err(ext2_to_klib)?;
        for e in entries {
            if e.name.as_slice() == name.as_bytes() {
                let inode = self.read_inode(e.inode).map_err(ext2_to_klib)?;
                return Ok((e.inode, inode));
            }
        }
        Err(Error::NotFound)
    }

    // ---- M3 写路径（EXT2 最小可写支集，disk.md P1-6） ----
    //
    // 只读挂载已废除：本模块现提供最小可写支集——块/inode 分配释放、位图
    // 更新、目录项增删、superblock/GDT 记账、直块 + 一级间接块分配、文件
    // 数据写、truncate。所有写都经 [`ByteDevice::write_bytes`] 落盘（M0.2
    // 桥接），写穿无延迟（本内核无页缓存写回期，PageCache 语义见 ADR-026）。
    // 双重间接/三重间接仍显式拒绝（当前镜像与工作负载不需要，见只读注释）。

    /// 写入一个完整块（M3 地基：与 [`Self::read_block`] 对称的写原语）。
    ///
    /// `data` 必须恰为块大小；不足/超长都显式拒绝（不静默截断或越界），
    /// 短写（设备返回少于块大小）如实报 `ShortRead`——绝不把部分写伪装成
    /// 成功（S09）。
    fn write_block(&self, block: u32, data: &[u8]) -> Result<(), Ext2Error> {
        let sb = self.superblock();
        if block >= sb.blocks_count {
            return Err(Ext2Error::BlockOutOfRange);
        }
        let bs = sb.block_size as usize;
        if data.len() != bs {
            return Err(Ext2Error::BufferTooSmall);
        }
        let off = self.inner.part_start_byte + block as u64 * bs as u64;
        let n = self.inner.dev.write_bytes(off, data);
        if n < bs {
            return Err(Ext2Error::ShortRead);
        }
        Ok(())
    }

    /// 块号 → 所属组号。
    #[inline]
    fn block_group(&self, block: u32) -> u32 {
        block / self.superblock().blocks_per_group
    }

    /// inode 号 → 所属组号。
    #[inline]
    fn inode_group(&self, ino: u32) -> u32 {
        (ino - 1) / self.superblock().inodes_per_group
    }

    /// 读整块位图（块位图或 inode 位图）。
    fn read_bitmap(&self, bitmap_block: u32) -> Result<alloc::vec::Vec<u8>, Ext2Error> {
        let bs = self.superblock().block_size as usize;
        let mut buf = alloc::vec![0u8; bs];
        self.read_block(bitmap_block, &mut buf)?;
        Ok(buf)
    }

    /// 在位图中置位（置 1 = 占用）。
    fn bitmap_set(&self, bitmap_block: u32, bit: u32) -> Result<(), Ext2Error> {
        let mut map = self.read_bitmap(bitmap_block)?;
        let byte = (bit / 8) as usize;
        if byte >= map.len() {
            return Err(Ext2Error::BlockOutOfRange);
        }
        map[byte] |= 1 << (bit % 8);
        self.write_block(bitmap_block, &map)
    }

    /// 在位图中清零（清 0 = 空闲）。
    fn bitmap_clear(&self, bitmap_block: u32, bit: u32) -> Result<(), Ext2Error> {
        let mut map = self.read_bitmap(bitmap_block)?;
        let byte = (bit / 8) as usize;
        if byte >= map.len() {
            return Err(Ext2Error::BlockOutOfRange);
        }
        map[byte] &= !(1 << (bit % 8));
        self.write_block(bitmap_block, &map)
    }

    /// 分配一个空闲块：跨组扫描，组内位图中找 0 位，置位并更新组/全局空闲计数。
    fn alloc_block(&self) -> Result<u32, Ext2Error> {
        let sb = self.superblock();
        // 读盘上实时空闲计数（快照 `sb.free_blocks_count` 不随写更新，S31）。
        if self.live_free_blocks()? == 0 {
            return Err(Ext2Error::BlockOutOfRange); // 卷满：显式无空闲块
        }
        let group_count = sb.blocks_count.div_ceil(sb.blocks_per_group);
        for group in 0..group_count {
            let gd = self.read_group_desc(group)?;
            let map = self.read_bitmap(gd.block_bitmap)?;
            // 组内位范围：该组覆盖的块号区间。
            let group_start = group * sb.blocks_per_group;
            let group_end = core::cmp::min(group_start + sb.blocks_per_group, sb.blocks_count);
            let bits = (group_end - group_start) as usize;
            for idx in 0..bits {
                let byte = idx / 8;
                if byte >= map.len() {
                    break;
                }
                if map[byte] & (1 << (idx % 8)) == 0 {
                    // 找到空闲位：置位并记账。
                    let block = group_start + idx as u32;
                    self.bitmap_set(gd.block_bitmap, idx as u32)?;
                    self.adjust_group_free_blocks(group, -1)?;
                    self.adjust_superblock_free_blocks(-1)?;
                    // S06/S18：新分配块清零——`free_block` 只清位图位不清数据，
                    // 块内容保留被删文件的残留。若此处不置零，间接表块首次使用
                    // 会读入陈旧指针（N1），文件增长后未写区会读出残留数据（N2）。
                    // 统一在此清零，任何经 alloc_block 的块都是干净的。
                    let bs = sb.block_size as usize;
                    let zero = alloc::vec![0u8; bs];
                    self.write_block(block, &zero)?;
                    return Ok(block);
                }
            }
        }
        Err(Ext2Error::BlockOutOfRange)
    }

    /// 释放一个块：清零位图位并更新组/全局空闲计数。
    fn free_block(&self, block: u32) -> Result<(), Ext2Error> {
        let sb = self.superblock();
        if block == 0 || block >= sb.blocks_count {
            return Err(Ext2Error::BlockOutOfRange);
        }
        let group = self.block_group(block);
        let gd = self.read_group_desc(group)?;
        let bit = block - group * sb.blocks_per_group;
        self.bitmap_clear(gd.block_bitmap, bit)?;
        self.adjust_group_free_blocks(group, 1)?;
        self.adjust_superblock_free_blocks(1)?;
        Ok(())
    }

    /// 分配一个空闲 inode：置位 inode 位图 + 记账，返回 inode 号（1-based）。
    fn alloc_inode(&self) -> Result<u32, Ext2Error> {
        let sb = self.superblock();
        // 读盘上实时空闲 inode 计数（快照 `sb.free_inodes_count` 不随写更新）。
        if self.live_free_inodes()? == 0 {
            return Err(Ext2Error::BadInode); // inode 耗尽
        }
        let group_count = sb.inodes_count.div_ceil(sb.inodes_per_group);
        for group in 0..group_count {
            let gd = self.read_group_desc(group)?;
            let map = self.read_bitmap(gd.inode_bitmap)?;
            let group_start = group * sb.inodes_per_group;
            let group_end = core::cmp::min(group_start + sb.inodes_per_group, sb.inodes_count);
            let bits = (group_end - group_start) as usize;
            for idx in 0..bits {
                let byte = idx / 8;
                if byte >= map.len() {
                    break;
                }
                if map[byte] & (1 << (idx % 8)) == 0 {
                    self.bitmap_set(gd.inode_bitmap, idx as u32)?;
                    self.adjust_group_free_inodes(group, -1)?;
                    self.adjust_superblock_free_inodes(-1)?;
                    // inode 号 = 组内偏移 + 1（inode 号从 1 起）。
                    return Ok(group_start + idx as u32 + 1);
                }
            }
        }
        Err(Ext2Error::BadInode)
    }

    /// 释放一个 inode：清零位图位 + 记账。
    fn free_inode(&self, ino: u32) -> Result<(), Ext2Error> {
        let sb = self.superblock();
        if ino == 0 || ino > sb.inodes_count {
            return Err(Ext2Error::BadInode);
        }
        let group = self.inode_group(ino);
        let gd = self.read_group_desc(group)?;
        let bit = (ino - 1) - group * sb.inodes_per_group;
        self.bitmap_clear(gd.inode_bitmap, bit)?;
        self.adjust_group_free_inodes(group, 1)?;
        self.adjust_superblock_free_inodes(1)?;
        Ok(())
    }

    /// 组级空闲块计数增减（GDT @12）。
    fn adjust_group_free_blocks(&self, group: u32, delta: i32) -> Result<(), Ext2Error> {
        let gd = self.read_group_desc(group)?;
        let updated = gd.free_blocks as i32 + delta;
        if updated < 0 {
            return Err(Ext2Error::CorruptSuperblock);
        }
        let sb = self.superblock();
        let gdt_block = (sb.first_data_block + 1) as u64;
        let off_abs =
            self.inner.part_start_byte + gdt_block * sb.block_size as u64 + group as u64 * 32;
        self.inner.dev.write_bytes(off_abs + 12, &(updated as u16).to_le_bytes());
        Ok(())
    }

    /// 组级空闲 inode 计数增减（GDT @14）。
    fn adjust_group_free_inodes(&self, group: u32, delta: i32) -> Result<(), Ext2Error> {
        let gd = self.read_group_desc(group)?;
        let updated = gd.free_inodes as i32 + delta;
        if updated < 0 {
            return Err(Ext2Error::CorruptSuperblock);
        }
        let sb = self.superblock();
        let gdt_block = (sb.first_data_block + 1) as u64;
        let off_abs =
            self.inner.part_start_byte + gdt_block * sb.block_size as u64 + group as u64 * 32;
        self.inner.dev.write_bytes(off_abs + 14, &(updated as u16).to_le_bytes());
        Ok(())
    }

    /// 全局空闲块计数增减（superblock @12）。
    fn adjust_superblock_free_blocks(&self, delta: i32) -> Result<(), Ext2Error> {
        let sb_off = self.inner.part_start_byte + 1024;
        let mut buf = [0u8; 4];
        if self.inner.dev.read_bytes(sb_off + 12, &mut buf) < 4 {
            return Err(Ext2Error::ShortRead);
        }
        let cur = le_u32(&buf, 0) as i64;
        let updated = cur + delta as i64;
        if updated < 0 {
            return Err(Ext2Error::CorruptSuperblock);
        }
        self.inner.dev.write_bytes(sb_off + 12, &(updated as u32).to_le_bytes());
        Ok(())
    }

    /// 全局空闲 inode 计数增减（superblock @16）。
    fn adjust_superblock_free_inodes(&self, delta: i32) -> Result<(), Ext2Error> {
        let sb_off = self.inner.part_start_byte + 1024;
        let mut buf = [0u8; 4];
        if self.inner.dev.read_bytes(sb_off + 16, &mut buf) < 4 {
            return Err(Ext2Error::ShortRead);
        }
        let cur = le_u32(&buf, 0) as i64;
        let updated = cur + delta as i64;
        if updated < 0 {
            return Err(Ext2Error::CorruptSuperblock);
        }
        self.inner.dev.write_bytes(sb_off + 16, &(updated as u32).to_le_bytes());
        Ok(())
    }

    /// 读回盘上 superblock 的**实时**空闲块计数（@12）。
    ///
    /// 写路径改的是盘上 superblock，`self.inner.sb`（[`Ext2Superblock`] 是
    /// 打开时 Copy 快照）里的 `free_blocks_count` 不随写更新。分配前判定
    /// "卷是否满"必须读实时值，否则基于陈旧快照会误判（如已分配若干块后
    /// 快照仍显示非零，或本已耗尽却因缓存失真）。几何字段（blocks_count 等）
    /// 不会变，仍用快照。
    fn live_free_blocks(&self) -> Result<u32, Ext2Error> {
        let sb_off = self.inner.part_start_byte + 1024;
        let mut buf = [0u8; 4];
        if self.inner.dev.read_bytes(sb_off + 12, &mut buf) < 4 {
            return Err(Ext2Error::ShortRead);
        }
        Ok(le_u32(&buf, 0))
    }

    /// 读回盘上 superblock 的**实时**空闲 inode 计数（@16）。
    fn live_free_inodes(&self) -> Result<u32, Ext2Error> {
        let sb_off = self.inner.part_start_byte + 1024;
        let mut buf = [0u8; 4];
        if self.inner.dev.read_bytes(sb_off + 16, &mut buf) < 4 {
            return Err(Ext2Error::ShortRead);
        }
        Ok(le_u32(&buf, 0))
    }

    /// 把 inode 结构写回 inode 表（M3）。
    fn write_inode(&self, inode: &Inode) -> Result<(), Ext2Error> {
        let sb = self.superblock();
        if inode.ino == 0 || inode.ino > sb.inodes_count || sb.inodes_per_group == 0 {
            return Err(Ext2Error::BadInode);
        }
        let group = self.inode_group(inode.ino);
        let idx = (inode.ino - 1) % sb.inodes_per_group;
        let gd = self.read_group_desc(group)?;
        let bs = sb.block_size as u64;
        let abs = self.inner.part_start_byte
            + gd.inode_table as u64 * bs
            + idx as u64 * sb.inode_size as u64;
        let isz = sb.inode_size as usize;
        // 先读回既有 inode 字节（保留我们未建模的字段，避免清零 i_flags 等），
        // 再覆写我们建模的字段。
        let mut raw = alloc::vec![0u8; isz];
        if self.inner.dev.read_bytes(abs, &mut raw) < isz {
            return Err(Ext2Error::ShortRead);
        }
        raw[0..2].copy_from_slice(&inode.mode.to_le_bytes());
        raw[4..8].copy_from_slice(&inode.size.to_le_bytes());
        raw[8..12].copy_from_slice(&inode.mtime.to_le_bytes());
        raw[16..20].copy_from_slice(&inode.ctime.to_le_bytes());
        raw[28..32].copy_from_slice(&inode.sectors.to_le_bytes());
        for (i, b) in inode.blocks.iter().enumerate() {
            raw[40 + i * 4..44 + i * 4].copy_from_slice(&b.to_le_bytes());
        }
        if self.inner.dev.write_bytes(abs, &raw) < isz {
            return Err(Ext2Error::ShortRead);
        }
        Ok(())
    }

    /// 释放 inode 占用的全部数据块（含一级/二级间接块），随后释放 inode 本身。
    fn free_inode_blocks(&self, inode: &Inode) -> Result<(), Ext2Error> {
        let sb = self.superblock();
        let bs = sb.block_size as usize;
        // 直块 0..12。
        for &b in &inode.blocks[..12] {
            if b != 0 {
                self.free_block(b)?;
            }
        }
        // 一级间接块（blocks[12]）：每个指针指向一个数据块。
        if inode.blocks[12] != 0 {
            let map = self.read_block_buf(inode.blocks[12])?;
            for i in 0..(bs / 4) {
                let b = le_u32(&map, i * 4);
                if b != 0 {
                    self.free_block(b)?;
                }
            }
            self.free_block(inode.blocks[12])?;
        }
        // 二级间接块（blocks[13]）：每个一级项指向一张 L1 表，L1 表每项指向数据块。
        if inode.blocks[13] != 0 {
            let dbl = self.read_block_buf(inode.blocks[13])?;
            for i in 0..(bs / 4) {
                let l1_ptr = le_u32(&dbl, i * 4);
                if l1_ptr == 0 {
                    continue;
                }
                let l1 = self.read_block_buf(l1_ptr)?;
                for j in 0..(bs / 4) {
                    let b = le_u32(&l1, j * 4);
                    if b != 0 {
                        self.free_block(b)?;
                    }
                }
                self.free_block(l1_ptr)?;
            }
            self.free_block(inode.blocks[13])?;
        }
        // 三重间接（blocks[14]）：读侧不建模，写侧亦不支持——显式拒绝而非
        // 静默泄漏（含三重间接的文件无法 unlink，如实报错）。
        if inode.blocks[14] != 0 {
            return Err(Ext2Error::UnsupportedTripleIndirect);
        }
        self.free_inode(inode.ino)
    }

    /// 把 inode 扩展到 `new_size`：分配直块 + 一级/二级间接块。
    /// 不收缩（收缩走 truncate_inode）。
    fn grow_inode_blocks(
        &self,
        inode: &mut Inode,
        new_size: u64,
    ) -> Result<(), Ext2Error> {
        let sb = self.superblock();
        let bs = sb.block_size as u64;
        // size 存 u32：超过 u32::MAX 无法表示，显式拒绝（S04，杜绝 as u32 截断）。
        if new_size > u32::MAX as u64 {
            return Err(Ext2Error::BlockOutOfRange);
        }
        let new_blocks = new_size.div_ceil(bs) as u32;
        // 当前已占块数（按 size 推算，稀疏块按 0 计但此处按连续分配模型）。
        let cur_blocks = (inode.size as u64).div_ceil(bs) as u32;
        if new_blocks <= cur_blocks {
            inode.size = new_size as u32;
            return Ok(());
        }
        for logical in cur_blocks..new_blocks {
            let phys = self.alloc_block()?;
            self.set_inode_block(inode, logical, phys)?;
        }
        inode.size = new_size as u32;
        Ok(())
    }

    /// 设置 inode 的第 `logical` 个逻辑块的物理块号（含一级/二级间接块分配）。
    ///
    /// 与读侧 [`Self::map_logical_block`] 的寻址语义严格对称：直块 0..12、
    /// 一级间接（`blocks[12]`，覆盖 per_block 项）、二级间接（`blocks[13]`，
    /// 覆盖 per_block² 项）。超出直块+二级间接范围才 `UnsupportedTripleIndirect`
    /// （`blocks[14]` 三重间接写仍未实现，读侧亦不支持，对称）。
    fn set_inode_block(&self, inode: &mut Inode, logical: u32, phys: u32) -> Result<(), Ext2Error> {
        let per_block = self.superblock().block_size / 4;
        if logical < 12 {
            inode.blocks[logical as usize] = phys;
            return Ok(());
        }
        let rem = logical - 12;
        // 一级间接区：rem < per_block。
        if rem < per_block {
            // 一级间接块尚未分配则先分配。
            if inode.blocks[12] == 0 {
                inode.blocks[12] = self.alloc_block()?;
            }
            let mut map = self.read_block_buf(inode.blocks[12])?;
            map[rem as usize * 4..rem as usize * 4 + 4].copy_from_slice(&phys.to_le_bytes());
            return self.write_block(inode.blocks[12], &map);
        }
        // 二级间接区：rem in [per_block, per_block + per_block²)。
        let rem2 = rem - per_block;
        let l2_span = per_block * per_block;
        if rem2 < l2_span {
            let l1_idx = rem2 / per_block;
            let l1_off = (rem2 % per_block) as usize;
            // 二级间接表（blocks[13]）尚未分配则先分配。
            if inode.blocks[13] == 0 {
                inode.blocks[13] = self.alloc_block()?;
            }
            // 取/建一级间接表块。
            let mut l1_map = self.read_block_buf(inode.blocks[13])?;
            let l1_ptr = le_u32(&l1_map, l1_idx as usize * 4);
            let l1_block = if l1_ptr == 0 {
                let b = self.alloc_block()?;
                l1_map[l1_idx as usize * 4..l1_idx as usize * 4 + 4]
                    .copy_from_slice(&b.to_le_bytes());
                self.write_block(inode.blocks[13], &l1_map)?;
                b
            } else {
                l1_ptr
            };
            let mut map = self.read_block_buf(l1_block)?;
            map[l1_off * 4..l1_off * 4 + 4].copy_from_slice(&phys.to_le_bytes());
            return self.write_block(l1_block, &map);
        }
        // 超出直块+二级间接：需要三重间接，显式拒绝。
        Err(Ext2Error::UnsupportedTripleIndirect)
    }

    /// truncate：收缩释放尾部块，扩展分配新块；更新 size/sectors/mtime/ctime。
    fn truncate_inode(&self, inode: &mut Inode, new_size: u64) -> Result<(), Ext2Error> {
        let sb = self.superblock();
        let bs = sb.block_size as u64;
        // size 存 u32：超过 u32::MAX 无法表示，显式拒绝（S04，杜绝 as u32 截断）。
        if new_size > u32::MAX as u64 {
            return Err(Ext2Error::BlockOutOfRange);
        }
        let cur_blocks = (inode.size as u64).div_ceil(bs) as u32;
        let new_blocks = new_size.div_ceil(bs) as u32;
        if new_blocks < cur_blocks {
            // 收缩：释放 [new_blocks, cur_blocks) 的逻辑块。
            for logical in new_blocks..cur_blocks {
                let phys = self.map_logical_block(inode, logical)?;
                if phys != 0 {
                    self.clear_inode_block(inode, logical)?;
                    self.free_block(phys)?;
                }
            }
        } else if new_blocks > cur_blocks {
            for logical in cur_blocks..new_blocks {
                let phys = self.alloc_block()?;
                self.set_inode_block(inode, logical, phys)?;
            }
        }
        inode.size = new_size as u32;
        // i_blocks 按规范含间接表块占用（count_sectors），非 size/512。
        inode.sectors = self.count_sectors(inode)?;
        let now = now_timestamp_secs();
        inode.mtime = now;
        inode.ctime = now;
        self.write_inode(inode)
    }

    /// 清零 inode 第 `logical` 个逻辑块指针（与 [`Self::set_inode_block`] 的
    /// 直块/一级/二级间接寻址语义对称）。
    fn clear_inode_block(&self, inode: &mut Inode, logical: u32) -> Result<(), Ext2Error> {
        let per_block = self.superblock().block_size / 4;
        if logical < 12 {
            inode.blocks[logical as usize] = 0;
            return Ok(());
        }
        let rem = logical - 12;
        // 一级间接区。
        if rem < per_block {
            if inode.blocks[12] == 0 {
                return Ok(());
            }
            let mut map = self.read_block_buf(inode.blocks[12])?;
            map[rem as usize * 4..rem as usize * 4 + 4].fill(0);
            return self.write_block(inode.blocks[12], &map);
        }
        // 二级间接区。
        let rem2 = rem - per_block;
        let l2_span = per_block * per_block;
        if rem2 < l2_span {
            if inode.blocks[13] == 0 {
                return Ok(());
            }
            let l1_idx = rem2 / per_block;
            let l1_off = (rem2 % per_block) as usize;
            let dbl = self.read_block_buf(inode.blocks[13])?;
            let l1_ptr = le_u32(&dbl, l1_idx as usize * 4);
            if l1_ptr == 0 {
                return Ok(());
            }
            let mut l1 = self.read_block_buf(l1_ptr)?;
            l1[l1_off * 4..l1_off * 4 + 4].fill(0);
            self.write_block(l1_ptr, &l1)
        } else {
            // 三重间接：读侧不建模，写侧亦不支持，如实拒绝。
            Err(Ext2Error::UnsupportedTripleIndirect)
        }
    }

    /// 写入 inode 数据（M3.4）：`[offset, offset+buf.len())` 范围内按需分配
    /// 块、读改写部分块、写穿落盘；返回实际写入字节数。
    pub fn write_inode_data(
        &self,
        inode: &mut Inode,
        mut offset: u64,
        buf: &[u8],
    ) -> Result<usize, Ext2Error> {
        let sb = self.superblock();
        let bs = sb.block_size as u64;
        // 写越界需扩展文件：先 grow 到目标末尾。
        let end = offset + buf.len() as u64;
        if end > inode.size as u64 {
            self.grow_inode_blocks(inode, end)?;
        }
        let mut done = 0usize;
        let mut scratch = alloc::vec![0u8; bs as usize];
        while done < buf.len() {
            let logical = (offset / bs) as u32;
            let in_block = (offset % bs) as usize;
            let take = core::cmp::min(buf.len() - done, bs as usize - in_block);
            let phys = self.map_logical_block(inode, logical)?;
            if take == bs as usize {
                // 整块覆盖：直接写新数据，免读旧块。
                scratch[..take].copy_from_slice(&buf[done..done + take]);
            } else {
                // 部分块：读-改-写。
                if phys == 0 {
                    scratch.fill(0);
                } else {
                    self.read_block(phys, &mut scratch)?;
                }
                scratch[in_block..in_block + take].copy_from_slice(&buf[done..done + take]);
            }
            let phys2 = if phys == 0 {
                // 稀疏块首次写入：分配新块（grow 阶段已按 size 分配，但
                // 部分块写且 phys==0 只可能在分配被绕过时出现——防御性分配）。
                let p = self.alloc_block()?;
                self.set_inode_block(inode, logical, p)?;
                p
            } else {
                phys
            };
            self.write_block(phys2, &scratch)?;
            done += take;
            offset += take as u64;
        }
        let now = now_timestamp_secs();
        inode.mtime = now;
        inode.ctime = now;
        // i_blocks 按规范含间接表块占用（count_sectors），非 size/512。
        inode.sectors = self.count_sectors(inode)?;
        self.write_inode(inode)?;
        Ok(done)
    }

    /// 在目录 `dir` 中新增目录项（M3.3），必要时扩展目录块。
    fn add_dir_entry(
        &self,
        dir: &mut Inode,
        ino: u32,
        name: &str,
        ft: u8,
    ) -> Result<(), Ext2Error> {
        let name_bytes = name.as_bytes();
        // 统一校验（非空、≤255、无 `/`、无控制字符）——与 create_entry 同源。
        validate_component_name(name)?;
        let rec_len = ((8 + name_bytes.len() + 3) & !3) as usize;
        // 读目录现有数据。
        let dir_bytes = dir.size as usize;
        let mut data = alloc::vec![0u8; dir_bytes];
        if dir_bytes > 0 {
            let n = self.read_inode_data(dir, 0, &mut data)?;
            data.truncate(n);
        }
        // 扫描已有项，尝试把新项塞进某个末项的空隙（分裂）。
        let mut cur = 0usize;
        while cur + 8 <= data.len() {
            let rec_len_cur = le_u16(&data, cur + 4) as usize;
            let name_len = data[cur + 6] as usize;
            let min_need = 8 + name_len;
            let is_last = cur + rec_len_cur >= data.len();
            if is_last {
                // 末项实际占用 = 对齐到 4 的 min_need；空隙 = rec_len_cur - 占用。
                let occupied = (min_need + 3) & !3;
                let leftover = rec_len_cur - occupied;
                if leftover >= rec_len {
                    // 空隙足够：收缩末项 rec_len，新项紧随其后并**继承剩余空间**
                    // 作为其 rec_len（EXT2 末项 rec_len 延至块尾的约定——否则
                    // 后续扫描遇到 rec_len 为 0 的残段会误判 CorruptDirEntry）。
                    data[cur + 4..cur + 6].copy_from_slice(&(occupied as u16).to_le_bytes());
                    let new_off = cur + occupied;
                    self.write_dir_entry_at(&mut data, new_off, ino, name, ft, leftover)?;
                    self.write_dir_data(dir, &data)?;
                    let now = now_timestamp_secs();
                    dir.mtime = now;
                    dir.ctime = now;
                    self.write_inode(dir)?;
                    return Ok(());
                }
            }
            cur += rec_len_cur;
        }
        // 目录无空隙：扩展一个块并追加到末尾。
        let old_size = data.len();
        let new_size = old_size + rec_len;
        data.resize(new_size, 0);
        // 增长目录 size 并分配块。
        dir.size = new_size as u32;
        self.grow_inode_blocks(dir, new_size as u64)?;
        self.write_dir_entry_at(&mut data, old_size, ino, name, ft, rec_len)?;
        self.write_dir_data(dir, &data)?;
        let now = now_timestamp_secs();
        dir.mtime = now;
        dir.ctime = now;
        self.write_inode(dir)?;
        Ok(())
    }

    /// 在目录数据缓冲的 `off` 处写一个目录项（含 rec_len 尾部填充语义）。
    fn write_dir_entry_at(
        &self,
        data: &mut [u8],
        off: usize,
        ino: u32,
        name: &str,
        ft: u8,
        rec_len: usize,
    ) -> Result<(), Ext2Error> {
        let nb = name.as_bytes();
        if off + 8 + nb.len() > data.len() {
            return Err(Ext2Error::CorruptDirEntry);
        }
        // name_len 字段只有 1 字节：>255 的名字必须在此显式拒绝（S04），绝不
        // 用 `as u8` 静默截断字节。调用方应已过 validate_component_name，此处
        // 为第二道防线（跨模块直接调用本函数的路径不受上层校验约束）。
        let name_len: u8 = nb.len().try_into().map_err(|_| Ext2Error::CorruptDirEntry)?;
        data[off..off + 4].copy_from_slice(&ino.to_le_bytes());
        data[off + 4..off + 6].copy_from_slice(&(rec_len as u16).to_le_bytes());
        data[off + 6] = name_len;
        data[off + 7] = ft;
        data[off + 8..off + 8 + nb.len()].copy_from_slice(nb);
        Ok(())
    }

    /// 把目录数据写回（按块对齐；data.len() 必须是块大小的倍数或按 size 截断）。
    fn write_dir_data(&self, dir: &Inode, data: &[u8]) -> Result<(), Ext2Error> {
        let bs = self.superblock().block_size as usize;
        let mut scratch = alloc::vec![0u8; bs];
        let mut off = 0usize;
        let mut logical = 0u32;
        while off < data.len() {
            let take = core::cmp::min(bs, data.len() - off);
            let phys = self.map_logical_block(dir, logical)?;
            if phys == 0 {
                return Err(Ext2Error::BlockOutOfRange);
            }
            if take < bs {
                // 末块部分写：读-改-写。
                self.read_block(phys, &mut scratch)?;
                scratch[..take].copy_from_slice(&data[off..off + take]);
            } else {
                scratch.copy_from_slice(&data[off..off + take]);
            }
            self.write_block(phys, &scratch)?;
            off += take;
            logical += 1;
        }
        Ok(())
    }

    /// 从目录删除指定名字的目录项（M3.3）：inode 置 0 并合并前项 rec_len。
    ///
    /// R7 同型防线：分配目录数据前先过 [`Self::device_byte_capacity`] 上界——
    /// 与 [`Self::read_dir_raw`] 同一防 OOM 政策。损坏镜像声明超大目录 size
    /// 在此被拒，绝不转化为内核巨型分配。
    fn remove_dir_entry(&self, dir: &mut Inode, name: &str) -> Result<u32, Ext2Error> {
        if dir.size as u64 > self.device_byte_capacity() {
            return Err(Ext2Error::CorruptDirEntry);
        }
        let dir_bytes = dir.size as usize;
        let mut data = alloc::vec![0u8; dir_bytes];
        if dir_bytes > 0 {
            let n = self.read_inode_data(dir, 0, &mut data)?;
            data.truncate(n);
        }
        let mut cur = 0usize;
        let mut prev_off: Option<usize> = None;
        while cur + 8 <= data.len() {
            let ino = le_u32(&data, cur);
            let rec_len = le_u16(&data, cur + 4) as usize;
            let name_len = data[cur + 6] as usize;
            if ino != 0 && &data[cur + 8..cur + 8 + name_len] == name.as_bytes() {
                let removed_ino = ino;
                // 清零 inode（标记为空闲项），并把 rec_len 合并给前一项。
                data[cur..cur + 4].fill(0);
                if let Some(prev) = prev_off {
                    let prev_rec = le_u16(&data, prev + 4) as usize;
                    let merged = prev_rec + rec_len;
                    data[prev + 4..prev + 6].copy_from_slice(&(merged as u16).to_le_bytes());
                }
                self.write_dir_data(dir, &data)?;
                return Ok(removed_ino);
            }
            prev_off = Some(cur);
            cur += rec_len;
        }
        Err(Ext2Error::CorruptDirEntry)
    }

    /// 创建文件/目录/symlink inode 并加入目录项（M3.3 统一入口）。
    fn create_entry(
        &self,
        dir: &mut Inode,
        name: &str,
        mode: u16,
        init_block: Option<u32>,
    ) -> Result<(u32, Inode), Ext2Error> {
        // 名字合法性（统一校验：非空、≤255、无 `/`、无控制字符）。入口即拒，
        // 不把超长名放行进 add_dir_entry 才拦截，杜绝后续 `as u8` 截断路径。
        validate_component_name(name)?;
        // 重名检查。
        if self.lookup_in_dir(dir, name).is_ok() {
            return Err(Ext2Error::CorruptDirEntry); // AlreadyExists 语义由调用方映射
        }
        let ino = self.alloc_inode()?;
        let now = now_timestamp_secs();
        let mut inode = Inode {
            ino,
            mode,
            size: 0,
            blocks: [0u32; 15],
            sectors: 0,
            mtime: now,
            ctime: now,
        };
        if let Some(block) = init_block {
            inode.blocks[0] = block;
        }
        self.write_inode(&inode)?;
        let ft = match mode & 0xF000 {
            0x4000 => 2, // EXT2_FT_DIR
            0xA000 => 7, // EXT2_FT_SYMLINK
            _ => 1,      // EXT2_FT_REG_FILE
        };
        self.add_dir_entry(dir, ino, name, ft)?;
        Ok((ino, inode))
    }

    /// 创建普通文件（M3.3）。
    pub fn create_file(
        &self,
        dir: &mut Inode,
        name: &str,
        _perm: Permissions,
    ) -> Result<Inode, Ext2Error> {
        let (_, inode) = self.create_entry(dir, name, 0x8000 | 0o644, None)?;
        Ok(inode)
    }

    /// 创建子目录（M3.3）：含 `.`/`..` 两项，`..` 指向父目录。
    pub fn mkdir(&self, dir: &mut Inode, name: &str, _perm: Permissions) -> Result<Inode, Ext2Error> {
        // 先分配目录数据块。
        let block = self.alloc_block()?;
        let (ino, mut inode) = self.create_entry(dir, name, 0x4000 | 0o755, Some(block))?;
        // 写 `.` 和 `..` 两项，size=块大小。
        let bs = self.superblock().block_size as usize;
        let mut d = alloc::vec![0u8; bs];
        self.write_dir_entry_at(&mut d, 0, ino, ".", 2, 12)?;
        self.write_dir_entry_at(&mut d, 12, dir.ino, "..", 2, bs - 12)?;
        self.write_block(block, &d)?;
        inode.size = bs as u32;
        inode.sectors = bs.div_ceil(512) as u32;
        self.write_inode(&inode)?;
        Ok(inode)
    }

    /// 删除目录项并释放其 inode 与数据块（M3.3）。
    pub fn unlink(&self, dir: &mut Inode, name: &str) -> Result<(), Ext2Error> {
        let (_, inode) = self.lookup_in_dir(dir, name).map_err(|_| Ext2Error::CorruptDirEntry)?;
        if inode.is_dir() {
            return Err(Ext2Error::CorruptDirEntry); // rmdir 需空目录，此处拒绝非空删除
        }
        self.remove_dir_entry(dir, name)?;
        self.free_inode_blocks(&inode)?;
        // 更新父目录 mtime/ctime。
        let now = now_timestamp_secs();
        dir.mtime = now;
        dir.ctime = now;
        self.write_inode(dir)
    }

    /// 创建软链接（M3.3）：目标 ≤60B 内联（fast），否则走数据块（slow）。
    pub fn symlink(&self, dir: &mut Inode, name: &str, target: &str) -> Result<Inode, Ext2Error> {
        let target_bytes = target.as_bytes();
        if target_bytes.len() <= FAST_SYMLINK_MAX as usize {
            // fast：目标内联 i_block 区，blocks 全 0。
            let (_, mut inode) = self.create_entry(dir, name, 0xA000 | 0o777, None)?;
            inode.size = target_bytes.len() as u32;
            inode.sectors = 0; // fast 判别位
            let mut raw = alloc::vec![0u8; FAST_SYMLINK_MAX as usize];
            raw[..target_bytes.len()].copy_from_slice(target_bytes);
            // 把目标写进 i_block 字节区（blocks 数组即该区 LE u32 视图）。
            for (i, chunk) in raw.chunks(4).enumerate() {
                let mut w = [0u8; 4];
                w[..chunk.len()].copy_from_slice(chunk);
                inode.blocks[i] = u32::from_le_bytes(w);
            }
            self.write_inode(&inode)?;
            Ok(inode)
        } else {
            // slow：目标存数据块（目标 > 60B）。按需分配 1..n 块并写穿——
            // 目标长度可能跨多个块（如 1024B 块 + 2000B 目标），绝不把整串
            // 目标写进单个数据块（旧实现 `d[..target_bytes.len()]` 会越界
            // panic）。目标上限仍受 size 字段 u32 约束，grow 侧已显式拒绝
            // 超限。
            let (_, mut inode) = self.create_entry(dir, name, 0xA000 | 0o777, None)?;
            let bs = self.superblock().block_size as u64;
            // 先 grow 再设 size：grow 以 inode.size 为"当前已占"基准，若预先
            // 把 size 提到目标值会让 grow 误判"无需扩展"而不分配任何块（见
            // write_inode_data 的既有模式：grow 内负责把 size 设为 new_size）。
            self.grow_inode_blocks(&mut inode, target_bytes.len() as u64)?;
            inode.size = target_bytes.len() as u32;
            // 逐逻辑块写穿目标字节（末块部分写需读-改-写）。
            let mut done = 0usize;
            let mut logical = 0u32;
            while done < target_bytes.len() {
                let phys = self.map_logical_block(&inode, logical)?;
                let in_block = done % bs as usize;
                let take = core::cmp::min(target_bytes.len() - done, bs as usize - in_block);
                let mut d = alloc::vec![0u8; bs as usize];
                if take < bs as usize {
                    self.read_block(phys, &mut d)?;
                }
                d[in_block..in_block + take]
                    .copy_from_slice(&target_bytes[done..done + take]);
                self.write_block(phys, &d)?;
                done += take;
                logical += 1;
            }
            // i_blocks 按规范含间接表块占用（count_sectors），非 size/512。
            inode.sectors = self.count_sectors(&inode)?;
            self.write_inode(&inode)?;
            Ok(inode)
        }
    }
}

/// fs1 FA3b：错误分类学忠实映射。五类故障不再压扁成单一 Io——
/// 介质尾/传输失败（Io）、非法 inode 号（InvalidParam）、盘上结构损坏
/// （Corrupt，EUCLEAN）、能力不支持（NotSupported）各自可达用户态。
/// 逐项分界理由见各变体文档与 ADR-021。
pub(crate) fn ext2_to_klib(e: Ext2Error) -> Error {
    match e {
        Ext2Error::BadMagic | Ext2Error::ShortRead => Error::Io,
        Ext2Error::BadInode | Ext2Error::BufferTooSmall => Error::InvalidParam,
        Ext2Error::CorruptDirEntry
        | Ext2Error::CorruptSuperblock
        | Ext2Error::BlockOutOfRange => Error::Corrupt,
        Ext2Error::UnsupportedTripleIndirect
        | Ext2Error::UnsupportedFragmentSize
        | Ext2Error::UnsupportedBlockSize => Error::NotSupported,
    }
}

/// M3 写路径时间戳源：优先 Unix epoch 秒，退单调秒。
///
/// 接线 wall clock 后（`klib::time::wall_clock_secs`），EXT2 写盘的
/// `i_mtime`/`i_ctime` 应为**真实 epoch**（外部工具可正确读成真实日期）。
/// 但墙钟是独立里程碑（arch RTC → epoch 换算，S03 允许 UTC0）：墙钟未
/// 注入或 RTC 时间无效（`wall_clock_secs` 返回 `None`）时，诚实退回单调
/// 秒（自启动起的秒数，非 1970 epoch）并在此成文——绝不用 0 或伪造时间
/// 填充（S09）。函数返回值类型与 EXT2 `i_*time` 字段（u32 epoch 秒）一致。
fn now_timestamp_secs() -> u32 {
    // 优先真实墙钟 epoch；不可用退单调秒。
    match klib::time::wall_clock_secs() {
        Some(epoch) => epoch.min(u32::MAX as u64) as u32,
        None => klib::time::now_millis().map(|ms| (ms / 1000) as u32).unwrap_or(0),
    }
}

// ---- VFS 集成 ----

use alloc::string::String;
use vfs::inode::{DirEntry, FileMetadata, FileSystem, INode, INodeType, Permissions};

/// EXT2 的 VFS 目录/文件节点。
pub struct Ext2Node {
    fs: Ext2Fs,
    inode: Inode,
}

/// mode 高 4 位 → 节点类型的权威映射（fs1 FA1）。
///
/// 七类 EXT2 盘上类型全部可表示（INodeType 自 fs1 起含 Socket）；返回
/// None 表示 mode 类型字段非法——那不是"当作普通文件"的理由，而是镜像
/// 损坏的证据，由调用方如实上抛 [`Error::Corrupt`]。
fn node_type_of(mode: u16) -> Option<INodeType> {
    match mode & 0xF000 {
        0x4000 => Some(INodeType::Directory),
        0x8000 => Some(INodeType::RegularFile),
        0xA000 => Some(INodeType::Symlink),
        0x2000 => Some(INodeType::CharacterDevice),
        0x6000 => Some(INodeType::BlockDevice),
        0x1000 => Some(INodeType::Fifo),
        0xC000 => Some(INodeType::Socket),
        _ => None,
    }
}

impl INode for Ext2Node {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        if self.inode.is_dir() {
            return Err(Error::IsDirectory);
        }
        // M3：重读最新 inode（写路径会更新 size/blocks，缓存的 inode 已陈旧），
        // 读到的 size 才是盘上真值——否则写后立即读会按旧 size 截断。
        let inode = self.fs.read_inode(self.inode.ino).map_err(ext2_to_klib)?;
        self.fs
            .read_inode_data(&inode, offset, buf)
            .map_err(ext2_to_klib)
    }

    /// M3：可写介质——经 [`Ext2Fs::write_inode_data`] 落盘。目录写按
    /// [`Error::IsDirectory`] 拒绝（与 read_at 对称）。
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<usize, Error> {
        if self.inode.is_dir() {
            return Err(Error::IsDirectory);
        }
        // 重读最新 inode（本节点缓存的 inode 可能已被先前写路径更新），
        // 写后写回——写路径的 inode 权威始终是盘上最新态。
        let mut inode = self.fs.read_inode(self.inode.ino).map_err(ext2_to_klib)?;
        self.fs
            .write_inode_data(&mut inode, offset, buf)
            .map_err(ext2_to_klib)
    }

    fn truncate(&self, size: u64) -> Result<(), Error> {
        let mut inode = self.fs.read_inode(self.inode.ino).map_err(ext2_to_klib)?;
        if inode.is_dir() {
            return Err(Error::IsDirectory);
        }
        self.fs.truncate_inode(&mut inode, size).map_err(ext2_to_klib)
    }

    /// A5（ADR-023 §4）：类型从缓存 mode 派生，零盘访问零分配——
    /// S09：node_type 如实上抛——未知 mode 不再静默兜底为 RegularFile
    /// （伪数据），而是按 Corrupt 报告；完整校验仍由 metadata() 承担。
    fn node_type(&self) -> Result<INodeType, Error> {
        node_type_of(self.inode.mode).ok_or(Error::Corrupt)
    }

    /// 元数据：size/type/权限/时间全部来自盘上真值。
    ///
    /// 时间戳政策（fs1 FM1）：modified=mtime、changed=ctime 为盘上真值；
    /// created_time 恒 0——EXT2 rev1 无创建时间字段（crtime 仅 rev2 且
    /// inode_size>128 才有），0 是成文的"字段不存在"，不是伪造的时间。
    fn metadata(&self) -> Result<FileMetadata, Error> {
        // M3：重读最新 inode——写路径会更新 size/mtime/ctime，缓存副本已陈旧。
        // mode 用于类型与权限判定，重读保证 size/时间戳是盘上真值。
        let inode = self.fs.read_inode(self.inode.ino).map_err(ext2_to_klib)?;
        let node_type =
            node_type_of(inode.mode).ok_or(Error::Corrupt)?;
        Ok(FileMetadata {
            node_type,
            size: inode.size as u64,
            permissions: Permissions {
                // fd1 FD3 映射取舍：单用户内核无身份区分，owner/group/other
                // 抹平为"任意一位即可"。粒度损失是有意的简化，接线多用户
                // 身份模型时此处必须重审。
                readable: inode.mode & 0o444 != 0,
                // M3：可写挂载，writable 如实为 true（写路径已接通）。
                writable: true,
                executable: inode.mode & 0o111 != 0,
                system_only: false,
            },
            created_time: 0,
            modified_time: inode.mtime as u64,
            changed_time: inode.ctime as u64,
        })
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn INode>, Error> {
        if !self.inode.is_dir() {
            return Err(Error::NotDirectory);
        }
        // M3：重读目录 inode（新增目录项会改变 size，缓存副本陈旧）。
        let dir = self.fs.read_inode(self.inode.ino).map_err(ext2_to_klib)?;
        let (_, inode) = self.fs.lookup_in_dir(&dir, name)?;
        Ok(Arc::new(Ext2Node {
            fs: self.fs.clone(),
            inode,
        }))
    }

    /// M3：创建普通文件（EXT2 可写支集）。
    fn create(&self, name: &str, perm: Permissions) -> Result<Arc<dyn INode>, Error> {
        if !self.inode.is_dir() {
            return Err(Error::NotDirectory);
        }
        let mut dir = self.fs.read_inode(self.inode.ino).map_err(ext2_to_klib)?;
        let inode = self.fs.create_file(&mut dir, name, perm).map_err(ext2_to_klib)?;
        Ok(Arc::new(Ext2Node {
            fs: self.fs.clone(),
            inode,
        }))
    }

    /// M3：创建子目录（含 `.`/`..`）。
    fn mkdir(&self, name: &str, perm: Permissions) -> Result<Arc<dyn INode>, Error> {
        if !self.inode.is_dir() {
            return Err(Error::NotDirectory);
        }
        let mut dir = self.fs.read_inode(self.inode.ino).map_err(ext2_to_klib)?;
        let inode = self.fs.mkdir(&mut dir, name, perm).map_err(ext2_to_klib)?;
        Ok(Arc::new(Ext2Node {
            fs: self.fs.clone(),
            inode,
        }))
    }

    /// M3：删除子项并释放 inode/数据块。
    fn unlink(&self, name: &str) -> Result<(), Error> {
        if !self.inode.is_dir() {
            return Err(Error::NotDirectory);
        }
        let mut dir = self.fs.read_inode(self.inode.ino).map_err(ext2_to_klib)?;
        self.fs.unlink(&mut dir, name).map_err(ext2_to_klib)
    }

    /// M3：创建软链接（fast/slow 双形态）。
    fn symlink(&self, name: &str, target: &str) -> Result<Arc<dyn INode>, Error> {
        if !self.inode.is_dir() {
            return Err(Error::NotDirectory);
        }
        let mut dir = self.fs.read_inode(self.inode.ino).map_err(ext2_to_klib)?;
        let inode = self.fs.symlink(&mut dir, name, target).map_err(ext2_to_klib)?;
        Ok(Arc::new(Ext2Node {
            fs: self.fs.clone(),
            inode,
        }))
    }

    /// 列出子项：size 与 node_type 全部来自关联 inode 真值（fs1 F1/FA1）。
    /// 此前的 `size: 0` 硬编码让 sys_readdir 对每个 EXT2 文件都报"0 字节"
    /// ——与同一文件的 cat/exec 结果自相矛盾，属用户可见伪数据。
    fn list_dir(&self) -> Result<Vec<DirEntry>, Error> {
        if !self.inode.is_dir() {
            return Err(Error::NotDirectory);
        }
        // M3：重读目录 inode（目录项增删会改变 size）。
        let dir = self.fs.read_inode(self.inode.ino).map_err(ext2_to_klib)?;
        let entries = self.fs.read_dir_raw(&dir).map_err(ext2_to_klib)?;
        entries
            .into_iter()
            .map(|e| {
                let node_type = node_type_of(e.mode).ok_or(Error::Corrupt)?;
                // S02/S09：文件名是原始字节，非 UTF-8 即损坏。不得用
                // from_utf8_lossy 静默替换为 U+FFFD——那会让展示名与
                // lookup_in_dir 按原始字节的匹配不一致（伪数据）。如实
                // 上抛 Corrupt。
                let name = core::str::from_utf8(&e.name)
                    .map_err(|_| Error::Corrupt)
                    .map(String::from)?;
                Ok(DirEntry {
                    name,
                    node_type,
                    size: e.size as u64,
                })
            })
            .collect()
    }

    /// 符号链接目标（fs1 FA1）：fast/slow 双形态经 [`Ext2Fs::read_link_target`]
    /// 统一读取。非链接节点按 POSIX readlink 语义返回 InvalidParam（EINVAL）。
    fn read_link(&self) -> Result<String, Error> {
        if !self.inode.is_symlink() {
            return Err(Error::InvalidParam);
        }
        let raw = self.fs.read_link_target(&self.inode).map_err(ext2_to_klib)?;
        // S02/S09：符号链接目标是非 UTF-8 时不得静默替换为 U+FFFD
        // （伪数据）。如实上抛 Corrupt。
        core::str::from_utf8(&raw)
            .map(|s| String::from(s))
            .map_err(|_| Error::Corrupt)
    }
}

/// EXT2 文件系统句柄（实现 vfs::FileSystem，可挂入 MountTable）。
impl FileSystem for Ext2Fs {
    fn root(&self) -> Arc<dyn INode> {
        // open() 已校验超级块；根 inode（固定 2 号）缺失说明镜像残缺，
        // 属于不可恢复契约，expect 表达该契约并让挂载方在启动日志中看到。
        let inode = self
            .read_inode(EXT2_ROOT_INO)
            .expect("ext2 root inode must exist after successful open");
        Arc::new(Ext2Node {
            fs: self.clone(),
            inode,
        })
    }

    fn name(&self) -> &'static str {
        "ext2"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(test)]
    use crate::MockByteDevice;

    const PART_START_LBA: u64 = 2048;
    const SECTOR: u64 = 512;
    const BS: usize = 1024;

    struct Img {
        data: Vec<u8>,
        part: usize,
    }

    impl Img {
        fn new(total_sectors: u32) -> Self {
            Self {
                data: alloc::vec![0u8; total_sectors as usize * SECTOR as usize],
                part: (PART_START_LBA * SECTOR) as usize,
            }
        }
        fn w8(&mut self, off: usize, v: u8) {
            self.data[off] = v;
        }
        fn w16(&mut self, off: usize, v: u16) {
            self.data[off..off + 2].copy_from_slice(&v.to_le_bytes());
        }
        fn w32(&mut self, off: usize, v: u32) {
            self.data[off..off + 4].copy_from_slice(&v.to_le_bytes());
        }
        fn write_bytes(&mut self, off: usize, content: &[u8]) {
            self.data[off..off + content.len()].copy_from_slice(content);
        }
        fn write_block(&mut self, block: u32, content: &[u8]) {
            let off = self.part + block as usize * BS;
            let n = core::cmp::min(content.len(), BS);
            self.data[off..off + n].copy_from_slice(&content[..n]);
        }
    }

    fn put_de(d: &mut [u8], off: usize, ino: u32, name: &str, ft: u8, rec: usize) -> usize {
        let nb = name.as_bytes();
        d[off..off + 4].copy_from_slice(&ino.to_le_bytes());
        d[off + 4..off + 6].copy_from_slice(&(rec as u16).to_le_bytes());
        d[off + 6] = nb.len() as u8;
        d[off + 7] = ft;
        d[off + 8..off + 8 + nb.len()].copy_from_slice(nb);
        off + rec
    }

    /// 与 disk.py 完全同构的最小镜像：
    /// MBR(part@LBA2048) + SB/GDT/位图/inode表 + 根目录 +
    /// hello.txt（单直块）+ big.bin（双直块 + 一级间接，跨块边界）+
    /// link（fast symlink，目标内联）+ longlink（slow symlink，目标在数据块）
    /// ——fs1 FA1/F1/FM1 验收夹具。
    fn build_image() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut img = Img::new(4096); // 2MB 盘，分区 2048 扇区
        // MBR
        img.w8(510, 0x55);
        img.w8(511, 0xAA);
        img.w8(0x1BE, 0x80);
        img.w8(0x1BE + 4, 0x83);
        img.w32(0x1BE + 8, PART_START_LBA as u32);
        img.w32(0x1BE + 12, 2048);
        // Superblock
        let sb = img.part + 1024;
        img.w32(sb, 1024); // s_inodes_count
        img.w32(sb + 4, 1024); // s_blocks_count
        img.w32(sb + 20, 1); // s_first_data_block
        img.w32(sb + 24, 0); // s_log_block_size
        img.w32(sb + 28, 0); // s_log_frag_size
        img.w32(sb + 32, 8192); // s_blocks_per_group
        img.w32(sb + 40, 1024); // s_inodes_per_group
        img.w16(sb + 56, EXT2_SUPER_MAGIC);
        img.w32(sb + 76, 1); // s_rev_level
        img.w16(sb + 88, 128); // s_inode_size
        // 卷标 @120（16B）与 FS UUID @104（16B）：M0.1 解析锚点。
        img.write_bytes(sb + 104, &[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C]);
        img.write_bytes(sb + 120, b"BORUIX_DATA");
        // GDT @block2: inode_table = block 5
        img.w32(img.part + 2 * BS + 8, 5);
        // Inode 表 @block5
        let itab = img.part + 5 * BS;
        // 根 ino2：目录，size=1024，block[0]=20
        img.w16(itab + 128, 0x4000 | 0o755);
        img.w32(itab + 128 + 4, 1024);
        img.w32(itab + 128 + 40, 20);
        // hello.txt ino11：单直块 25；mtime/ctime 真值（fs1 FM1 断言锚点）
        let hello: Vec<u8> = b"Welcome to BORUIX Real Ext2 Filesystem!\n".to_vec();
        img.w16(itab + 1280, 0x8000 | 0o644);
        img.w32(itab + 1280 + 4, hello.len() as u32);
        img.w32(itab + 1280 + 8, 1_234_567_890);
        img.w32(itab + 1280 + 16, 1_987_654_321);
        img.w32(itab + 1280 + 40, 25);
        // big.bin ino12：13000B = 12 个直块(12288B，块30..41) + 一级间接块60->[50]
        // （必须超过 12*1024 才能真正走进间接链——这是本测试的存在意义）
        let big: Vec<u8> = (0..13000usize).map(|i| (i % 251) as u8).collect();
        img.w16(itab + 1408, 0x8000 | 0o644);
        img.w32(itab + 1408 + 4, big.len() as u32);
        for i in 0..12u32 {
            img.w32(itab + 1408 + 40 + (i as usize) * 4, 30 + i);
        }
        img.w32(itab + 1408 + 40 + 12 * 4, 60);
        // link ino13：FAST symlink——blocks[0]=0，目标内联 i_block 区（≤60B）
        let fast_target = b"/hello.txt";
        img.w16(itab + 1536, 0xA000 | 0o777);
        img.w32(itab + 1536 + 4, fast_target.len() as u32);
        // blocks 保持全 0（fast 判别位）；目标写进 i_block 字节区 @40
        img.write_bytes(itab + 1536 + 40, fast_target);
        // longlink ino14：SLOW symlink——目标 70B > 60B，存数据块 26
        let slow_target: Vec<u8> = b"some/very/long/path/prefix/repeated/again/target-file"
            .iter()
            .copied()
            .chain(core::iter::repeat(b'x').take(17))
            .collect();
        assert_eq!(slow_target.len(), 70, "fixture slow target must exceed 60B");
        img.w16(itab + 1664, 0xA000 | 0o777);
        img.w32(itab + 1664 + 4, slow_target.len() as u32);
        img.w32(itab + 1664 + 28, 2); // i_blocks：占 1 块 = 2 扇区（slow 判别）
        img.w32(itab + 1664 + 40, 26);
        // 根目录数据块 20（fs1：追加两个 symlink 项，big.bin rec 收窄腾位）
        let mut d = [0u8; BS];
        let mut cur = put_de(&mut d, 0, 2, ".", 2, 12);
        cur = put_de(&mut d, cur, 2, "..", 2, 12);
        cur = put_de(&mut d, cur, 11, "hello.txt", 1, 24);
        cur = put_de(&mut d, cur, 12, "big.bin", 1, 28);
        cur = put_de(&mut d, cur, 13, "link", 7, 24);
        put_de(&mut d, cur, 14, "longlink", 7, BS - cur);
        img.write_block(20, &d);
        // 文件数据
        img.write_block(25, &hello);
        for i in 0..12usize {
            let start = i * BS;
            img.write_block(30 + i as u32, &big[start..start + BS]);
        }
        img.write_block(50, &big[12288..]);
        let mut ind = [0u8; BS];
        ind[0..4].copy_from_slice(&50u32.to_le_bytes());
        img.write_block(60, &ind);
        // slow symlink 目标块 26
        img.write_block(26, &slow_target);
        (img.data, hello, big)
    }

    fn open_fs() -> (Ext2Fs, Vec<u8>, Vec<u8>) {
        let (img, hello, big) = build_image();
        let dev = Arc::new(MockByteDevice::new(img));
        (
            Ext2Fs::open(dev, PART_START_LBA * SECTOR).expect("fixture must open"),
            hello,
            big,
        )
    }

    #[test]
    fn test_ext2_open_rejects_bad_magic() {
        let (img, _, _) = build_image();
        let mut bad = img;
        let sb = (PART_START_LBA * SECTOR) as usize + 1024;
        bad[sb + SB_MAGIC_OFFSET] = 0;
        bad[sb + SB_MAGIC_OFFSET + 1] = 0;
        let dev = Arc::new(MockByteDevice::new(bad));
        let got = Ext2Fs::open(dev, PART_START_LBA * SECTOR);
        assert!(
            matches!(got, Err(Ext2Error::BadMagic)),
            "non-EXT2 partition must be rejected by magic"
        );
    }

    #[test]
    fn test_ext2_root_listing_and_lookup() {
        use vfs::inode::INode;
        let (fs, _, _) = open_fs();
        let root = vfs::inode::FileSystem::root(&fs);
        let entries = root.list_dir().expect("root is a directory");
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"."), "must list .");
        assert!(names.contains(&".."), "must list ..");
        assert!(names.contains(&"hello.txt"));
        assert!(names.contains(&"big.bin"));

        let hello = root.lookup("hello.txt").expect("hello.txt present");
        let meta = hello.metadata().expect("metadata");
        assert_eq!(meta.node_type, INodeType::RegularFile);
        // M3 可写契约：writable 如实为 true（写路径已接通）。
        assert!(meta.permissions.writable);
        assert!(meta.permissions.readable);
        // 对文件做 lookup 必须 NotDirectory。
        assert_eq!(
            hello.lookup("anything").map(|_| ()).unwrap_err(),
            Error::NotDirectory
        );
        // 缺失项必须 NotFound。
        assert_eq!(root.lookup("nope.txt").map(|_| ()).unwrap_err(), Error::NotFound);
    }

    /// fs1 F1 红线验收：readdir 面的 size 必须是盘上真值——
    /// 此前恒硬编码 0，与 cat/exec 的实际字节数自相矛盾。
    #[test]
    fn test_list_dir_reports_real_sizes_and_faithful_types() {
        use vfs::inode::INode;
        let (fs, hello, big) = open_fs();
        let root = FileSystem::root(&fs);
        let entries = root.list_dir().expect("list");
        let by_name = |n: &str| {
            entries
                .iter()
                .find(|e| e.name == n)
                .unwrap_or_else(|| panic!("entry {} missing", n))
                .clone()
        };
        assert_eq!(by_name("hello.txt").size, hello.len() as u64, "F1: real size");
        assert_eq!(by_name("big.bin").size, big.len() as u64, "F1: real size");
        assert_eq!(by_name(".").size, 1024);
        assert_eq!(by_name("hello.txt").node_type, INodeType::RegularFile);
        assert_eq!(by_name(".").node_type, INodeType::Directory);
        // FA1(b)：symlink 不再被抹平成 RegularFile。
        assert_eq!(by_name("link").node_type, INodeType::Symlink);
        assert_eq!(by_name("longlink").node_type, INodeType::Symlink);
    }

    /// S02/S09 回归：非 UTF-8 文件名必须如实报 Corrupt，不得被
    /// from_utf8_lossy 静默替换为 U+FFFD——那会让展示名与 lookup_in_dir
    /// 按原始字节的匹配不一致（伪数据）。
    #[test]
    fn test_non_utf8_name_rejected_as_corrupt() {
        use vfs::inode::INode;
        let (img, _, _) = build_image();
        let mut bad = img;
        // 根目录块 20 里 "link" 项：第 5 个 put_de 从 off 76 起，名字字节在
        // off 76+8=84（8 字节头：ino4+rec_len2+name_len1+ft1）。把名字首字节
        // 改成非法 UTF-8（0xFF 单独不成序列）。
        let base = (PART_START_LBA * SECTOR) as usize;
        let dirblk = base + 20 * BS;
        bad[dirblk + 84] = 0xFF;
        let dev = Arc::new(MockByteDevice::new(bad));
        let fs = Ext2Fs::open(dev, PART_START_LBA * SECTOR).expect("sb still valid");
        let root = FileSystem::root(&fs);
        let err = root.list_dir().map(|_| ()).unwrap_err();
        assert_eq!(
            err, Error::Corrupt,
            "non-UTF8 filename must be reported as Corrupt, not lossy-replaced"
        );
    }

    /// fs1 FM1：三时间戳中可得的两个必须是盘上真值；created_time=0 是
    /// "rev1 无此字段"的成文不可得，而非伪造时间点。
    #[test]
    fn test_metadata_timestamps_real_values() {
        use vfs::inode::INode;
        let (fs, _, _) = open_fs();
        let root = FileSystem::root(&fs);
        let meta = root.lookup("hello.txt").expect("present").metadata().unwrap();
        assert_eq!(meta.modified_time, 1_234_567_890, "mtime from disk");
        assert_eq!(meta.changed_time, 1_987_654_321, "ctime from disk");
    }

    /// fs1 FA1：fast（≤60B 内联）与 slow（>60B 数据块）双形态 read_link，
    /// 以及经 MountTable resolve 的端到端跟随。
    #[test]
    fn test_symlink_fast_slow_read_link_and_resolve() {
        use vfs::inode::{FileSystem, INode};
        let (fs, hello, _) = open_fs();
        let root = FileSystem::root(&fs);

        let fast = root.lookup("link").expect("fast link present");
        assert_eq!(
            fast.read_link().expect("read fast link"),
            "/hello.txt",
            "fast symlink target from inline i_block bytes"
        );
        let slow = root.lookup("longlink").expect("slow link present");
        let slow_target = slow.read_link().expect("read slow link");
        assert_eq!(slow_target.len(), 70, "slow target length preserved");
        assert!(slow_target.starts_with("some/very/long"), "slow target from data block");

        // 非 symlink 上 readlink 必须 EINVAL（InvalidParam），不是 NotSupported。
        let hello_node = root.lookup("hello.txt").expect("present");
        assert_eq!(
            hello_node.read_link().map(|_| ()).unwrap_err(),
            Error::InvalidParam
        );

        // 端到端：绝对目标链接的路径解析直达文件并读出真内容。
        let table = vfs::mount::MountTable::new(Arc::new(fs.clone()));
        let resolved = table
            .resolve("/link", true)
            .expect("resolve through absolute symlink");
        let mut buf = alloc::vec![0u8; hello.len()];
        let n = resolved.read_at(0, &mut buf).expect("read via symlink");
        assert_eq!(n, hello.len());
        assert_eq!(&buf[..], &hello[..], "content identical through link path");
    }

    /// M3 写路径夹具：一个含正确位图与空闲计数的干净 EXT2 镜像——
    /// 根目录只有 `.`/`..`，块 0..7 已占（boot/sb/gdt/两 bitmap/inode表/根数据块），
    /// inode 1..2 已占（根），其余全部空闲。供 create/write/mkdir/unlink 测试。
    fn build_writable_image() -> Vec<u8> {
        let mut img = Img::new(8192); // 4MB 盘，分区 4096 扇区 = 2048 块
        // MBR
        img.w8(510, 0x55);
        img.w8(511, 0xAA);
        img.w8(0x1BE, 0x80);
        img.w8(0x1BE + 4, 0x83);
        img.w32(0x1BE + 8, PART_START_LBA as u32);
        img.w32(0x1BE + 12, 4096);
        // Superblock：2048 块、256 inode、单组。
        let sb = img.part + 1024;
        img.w32(sb, 256); // s_inodes_count
        img.w32(sb + 4, 2048); // s_blocks_count
        img.w32(sb + 8, 0); // s_r_blocks_count
        img.w32(sb + 12, 2048 - 8); // s_free_blocks_count（块 0..7 已占）
        img.w32(sb + 16, 256 - 2); // s_free_inodes_count（inode 1..2 已占）
        img.w32(sb + 20, 1); // s_first_data_block
        img.w32(sb + 24, 0); // s_log_block_size
        img.w32(sb + 28, 0); // s_log_frag_size
        img.w32(sb + 32, 8192); // s_blocks_per_group
        img.w32(sb + 40, 256); // s_inodes_per_group
        img.w16(sb + 56, EXT2_SUPER_MAGIC);
        img.w32(sb + 76, 1); // s_rev_level
        img.w16(sb + 88, 128); // s_inode_size
        img.write_bytes(sb + 104, &[0xAB; 16]); // s_uuid 非零
        img.write_bytes(sb + 120, b"WRITABLE"); // 卷标
        // GDT @block2：bitmap=3/4，inode 表=5，空闲计数。
        img.w32(img.part + 2 * BS, 3); // bg_block_bitmap
        img.w32(img.part + 2 * BS + 4, 4); // bg_inode_bitmap
        img.w32(img.part + 2 * BS + 8, 5); // bg_inode_table
        img.w16(img.part + 2 * BS + 12, (2048 - 8) as u16); // bg_free_blocks_count
        img.w16(img.part + 2 * BS + 14, (256 - 2) as u16); // bg_free_inodes_count
        img.w16(img.part + 2 * BS + 16, 1); // bg_used_dirs_count
        // 块位图 @3：块 0..7 已占（字节 0 = 0xFF，其余空闲）。
        let mut blk_bmp = [0u8; BS];
        blk_bmp[0] = 0xFF;
        img.write_block(3, &blk_bmp);
        // inode 位图 @4：inode 1..2 已占（0x03）。
        let mut ino_bmp = [0u8; BS];
        ino_bmp[0] = 0x03;
        img.write_block(4, &ino_bmp);
        // inode 表 @5：根 ino2 目录，block[0]=7，size=块大小。
        let itab = img.part + 5 * BS;
        img.w16(itab + 128, 0x4000 | 0o755);
        img.w32(itab + 128 + 4, BS as u32);
        img.w32(itab + 128 + 26, 2); // i_links_count
        img.w32(itab + 128 + 28, 2); // i_blocks
        img.w32(itab + 128 + 40, 7); // i_block[0] = block 7
        // 根目录数据块 @7：`.` 与 `..`。
        let mut d = [0u8; BS];
        put_de(&mut d, 0, 2, ".", 2, 12);
        put_de(&mut d, 12, 2, "..", 2, BS - 12);
        img.write_block(7, &d);
        img.data
    }

    fn open_writable() -> Ext2Fs {
        let img = build_writable_image();
        let dev = Arc::new(MockByteDevice::new(img));
        Ext2Fs::open(dev, PART_START_LBA * SECTOR).expect("writable fixture opens")
    }

    /// M3 端到端 + 重挂一致性（M3.5）：建文件 → 写入 → 重开（重挂）→ 读回一致。
    #[test]
    fn test_write_create_and_remount_consistency() {
        use vfs::inode::{FileSystem, Permissions};
        let perm = Permissions::all();
        let img = build_writable_image();
        let dev: Arc<dyn ByteDevice> = Arc::new(MockByteDevice::new(img));
        let payload = b"M3 write-through payload: hello ext2 write path!";
        // 阶段 1：首次挂载，建文件并写入。
        {
            let fs = Ext2Fs::open(dev.clone(), PART_START_LBA * SECTOR).expect("open 1");
            let root = FileSystem::root(&fs);
            let f = root.create("new.txt", perm).expect("create file");
            assert_eq!(f.metadata().expect("meta").permissions.writable, true);
            let n = f.write_at(0, payload).expect("write");
            assert_eq!(n, payload.len());
        }
        // 阶段 2：重开同一设备（模拟重挂），读回应与写入一致。
        {
            let fs2 = Ext2Fs::open(dev.clone(), PART_START_LBA * SECTOR).expect("open 2 (remount)");
            let root2 = FileSystem::root(&fs2);
            let f2 = root2.lookup("new.txt").expect("new.txt persists across remount");
            let mut back = alloc::vec![0u8; payload.len()];
            let rn = f2.read_at(0, &mut back).expect("read after remount");
            assert_eq!(rn, payload.len());
            assert_eq!(&back[..], payload, "content identical across remount");
            assert_eq!(f2.metadata().expect("meta").size, payload.len() as u64);
            let names: Vec<String> = root2.list_dir().unwrap().iter().map(|e| e.name.clone()).collect();
            assert!(names.iter().any(|n| n == "new.txt"), "new.txt listed after remount");
        }
    }

    /// M3：create/mkdir/unlink/symlink 的目录项增删与 inode/块分配释放记账。
    ///
    /// 空闲计数以**重挂（重开设备）读回的盘上真值**为准——写路径把记账
    /// 落在 superblock/GDT 上，缓存的 `Ext2Superblock` 是打开时的快照，
    /// 用它断言增量会读到陈旧值（那正是"重挂一致性"要锁定的真值）。
    #[test]
    fn test_write_dir_ops_and_free_count_accounting() {
        use vfs::inode::{FileSystem, Permissions};
        let perm = Permissions::all();
        let img = build_writable_image();
        let dev: Arc<dyn ByteDevice> = Arc::new(MockByteDevice::new(img));
        let (free_blocks_before, free_inodes_before) = {
            let fs = Ext2Fs::open(dev.clone(), PART_START_LBA * SECTOR).expect("open");
            let sb = *fs.superblock();
            (sb.free_blocks_count, sb.free_inodes_count)
        };
        {
            let fs = Ext2Fs::open(dev.clone(), PART_START_LBA * SECTOR).expect("open");
            let root = FileSystem::root(&fs);
            // 建目录（耗 1 inode + 1 块），建文件（耗 1 inode），symlink（耗 1 inode）。
            let d = root.mkdir("subdir", perm).expect("mkdir");
            root.create("afile", perm).expect("create");
            root.symlink("alink", "afile").expect("symlink");
            // 目录列出新项。
            let names: Vec<String> = root.list_dir().unwrap().iter().map(|e| e.name.clone()).collect();
            assert!(names.iter().any(|n| n == "subdir"));
            assert!(names.iter().any(|n| n == "afile"));
            assert!(names.iter().any(|n| n == "alink"));
            // subdir 内 `.`/`..`。
            let sub_entries = d.list_dir().expect("subdir list");
            let sub_names: Vec<&str> = sub_entries.iter().map(|e| e.name.as_str()).collect();
            assert!(sub_names.contains(&"."));
            assert!(sub_names.contains(&".."));
            // 删除 afile：inode 与块归还。
            root.unlink("afile").expect("unlink afile");
            assert_eq!(root.lookup("afile").map(|_| ()).unwrap_err(), Error::NotFound);
        }
        // 重挂读回盘上真值记账：free_inodes 减 2（subdir + alink，afile 已删归还），
        // free_blocks 减 1（subdir 数据块；afile/alink 无数据块）。
        {
            let fs = Ext2Fs::open(dev.clone(), PART_START_LBA * SECTOR).expect("remount");
            let sb = *fs.superblock();
            assert_eq!(sb.free_inodes_count, free_inodes_before - 2, "2 inodes remain allocated (subdir, alink)");
            assert_eq!(sb.free_blocks_count, free_blocks_before - 1, "1 block (subdir data) allocated");
            let root = FileSystem::root(&fs);
            assert_eq!(root.lookup("afile").map(|_| ()).unwrap_err(), Error::NotFound, "afile gone after remount");
            assert!(root.lookup("subdir").is_ok(), "subdir persists after remount");
            assert!(root.lookup("alink").is_ok(), "alink persists after remount");
        }
    }

    /// M3：文件写越界自动扩展（grow）与 truncate 收缩。
    #[test]
    fn test_write_grow_and_truncate() {
        use vfs::inode::{FileSystem, Permissions};
        let perm = Permissions::all();
        let fs = open_writable();
        let root = FileSystem::root(&fs);
        let f = root.create("grow.bin", perm).expect("create");
        // 写 3000 字节（跨 3 个 1KB 块，触发 grow + 多块分配）。
        let payload: Vec<u8> = (0..3000usize).map(|i| (i % 251) as u8).collect();
        let n = f.write_at(0, &payload).expect("write 3000B");
        assert_eq!(n, 3000);
        assert_eq!(n, 3000);
        // 读回整段。
        let mut back = alloc::vec![0u8; 3000];
        let rn = f.read_at(0, &mut back).expect("read back");
        assert_eq!(rn, 3000);
        assert_eq!(back, payload);
        assert_eq!(f.metadata().expect("meta").size, 3000);
        // truncate 到 1500：size 收缩，尾部块释放。
        f.truncate(1500).expect("truncate");
        assert_eq!(f.metadata().expect("meta").size, 1500);
        let mut small = alloc::vec![0u8; 1500];
        let rn2 = f.read_at(0, &mut small).expect("read after truncate");
        assert_eq!(rn2, 1500);
        assert_eq!(&small[..], &payload[..1500]);
    }

    /// fs1 FA2：目录 size 声明超过设备容量必须被拒——绝不允许把损坏
    /// 元数据转成内核巨型分配（K7 同型防线）。
    #[test]
    fn test_corrupt_dir_size_is_capped_not_allocated() {
        let (img, _, _) = build_image();
        let mut bad = img;
        // 根 inode size 改为 0xFFFF_FFFF（≈4GB 声明）
        let itab = (PART_START_LBA * SECTOR) as usize + 5 * BS;
        let sz_off = itab + 128 + 4;
        bad[sz_off..sz_off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let dev = Arc::new(MockByteDevice::new(bad));
        let fs = Ext2Fs::open(dev, PART_START_LBA * SECTOR).expect("sb still valid");
        let root = vfs::inode::FileSystem::root(&fs);
        let err = root.list_dir().unwrap_err();
        assert_eq!(err, Error::Corrupt, "oversized dir declaration must be rejected");
    }

    /// S09/S20/S31 回归（清单 high）：`device_byte_capacity()` 不得只信
    /// 超级块几何——恶意镜像夸大 `s_blocks_count` 后，K7 防线"目录/符号
    /// 链接 size ≤ 设备容量"会以虚高几何放行超真实设备容量的分配声明，
    /// 触发内核 OOM 自伤。上限必须锚定真实设备容量 `dev.byte_len()`。
    ///
    /// 直接单测返回值：把 `s_blocks_count` 抬到 u32::MAX（几何 ≈4TB），
    /// 真实 MockByteDevice 容量为 2MiB。修复前函数返回 4TB（红）；修复后
    /// 返回 min(几何, 真实容量) = 2MiB（绿）。
    #[test]
    fn test_device_byte_capacity_anchored_to_real_device() {
        let (img, _, _) = build_image(); // Img::new(4096) → 2MiB 设备
        let mut bad = img;
        let base = (PART_START_LBA * SECTOR) as usize;
        let sb = base + 1024;
        // 夸大 s_blocks_count → 几何 ≈4TB（恶意声明）
        bad[sb + 4..sb + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        let dev = Arc::new(MockByteDevice::new(bad));
        let fs = Ext2Fs::open(dev, PART_START_LBA * SECTOR).expect("sb still valid");
        // 真实设备容量：MockByteDevice::new(img) → data.len() == 2MiB
        let real_cap = 4096u64 * SECTOR;
        assert_ne!(
            fs.device_byte_capacity(),
            u32::MAX as u64 * 1024u64,
            "S09/S20/S31: capacity must NOT trust sb geometry when it exceeds the real device"
        );
        assert_eq!(
            fs.device_byte_capacity(),
            real_cap,
            "device_byte_capacity must be anchored to the real device byte length"
        );
    }

    /// M0.1：卷标与 FS UUID 从超级块忠实读回——`volume_name_str` 截断到
    /// 首个 NUL、返回空串/None 的策略，以及 UUID 全零判定。
    #[test]
    fn test_superblock_volume_name_and_uuid() {
        let (img, _, _) = build_image();
        let sb = img[(PART_START_LBA * SECTOR) as usize + 1024..][..1024].try_into().unwrap();
        let sb = parse_superblock(sb).expect("fixture sb parses");
        // 卷标 "BORUIX_DATA"（11 字节）后接 NUL，截断到首个 NUL 得完整标签。
        assert_eq!(sb.volume_name_str(), Some("BORUIX_DATA"));
        // 无卷标（首字节 0）→ 空串（不是 None，也不是伪造名）。
        let mut bare = build_image().0;
        let base = (PART_START_LBA * SECTOR) as usize;
        bare[base + 1024 + 120..base + 1024 + 136].fill(0);
        let sb_bare = parse_superblock(&bare[base + 1024..][..1024].try_into().unwrap()).unwrap();
        assert_eq!(sb_bare.volume_name_str(), Some(""));
        // 非 UTF-8 卷标（0xFF 单字节）→ None（不得 lossy 篡改，S02）。
        let mut bad = build_image().0;
        bad[base + 1024 + 120] = 0xFF;
        let sb_bad = parse_superblock(&bad[base + 1024..][..1024].try_into().unwrap()).unwrap();
        assert_eq!(sb_bad.volume_name_str(), None);
        // UUID 真读：DEADBEEF... 非零；全零即未声明。
        assert!(!sb.uuid_is_zero());
        assert_eq!(sb.uuid[0], 0xDE);
        assert_eq!(sb.uuid[1], 0xAD);
        let mut zero = build_image().0;
        zero[base + 1024 + 104..base + 1024 + 120].fill(0);
        let sb_zero = parse_superblock(&zero[base + 1024..][..1024].try_into().unwrap()).unwrap();
        assert!(sb_zero.uuid_is_zero());
    }

    /// fs1 FA2：超级块结构性 sanity——first_data_block 与块大小矛盾、
    /// 计数字段为零，一律拒绝挂载。
    #[test]
    fn test_superblock_sanity_rejects_inconsistent_metadata() {
        let base_sectors = PART_START_LBA * SECTOR;
        // first_data_block=0 而 1K 块（应为 1）
        let (mut img, _, _) = build_image();
        let sb = base_sectors as usize + 1024;
        img[sb + 20..sb + 24].copy_from_slice(&0u32.to_le_bytes());
        let got = Ext2Fs::open(Arc::new(MockByteDevice::new(img)), base_sectors);
        assert!(matches!(got, Err(Ext2Error::CorruptSuperblock)), "fdb mismatch rejected");
        // blocks_count=0
        let (mut img, _, _) = build_image();
        img[sb + 4..sb + 8].copy_from_slice(&0u32.to_le_bytes());
        let got = Ext2Fs::open(Arc::new(MockByteDevice::new(img)), base_sectors);
        assert!(matches!(got, Err(Ext2Error::CorruptSuperblock)), "zero blocks_count rejected");
        // inodes_count=0
        let (img, _, _) = build_image();
        let mut img = img;
        img[sb..sb + 4].copy_from_slice(&0u32.to_le_bytes());
        let got = Ext2Fs::open(Arc::new(MockByteDevice::new(img)), base_sectors);
        assert!(matches!(got, Err(Ext2Error::CorruptSuperblock)), "zero inodes_count rejected");
    }

    /// S19/S31 回归：`s_inode_size` 声明超块大（inode 表单块放不下）必须被拒，
    /// 否则每次 read_inode 都按该超大值分配内核堆（损坏镜像可令每次 inode
    /// 读取分配 64KB，自伤面）。
    #[test]
    fn test_superblock_rejects_huge_inode_size() {
        let base_sectors = PART_START_LBA * SECTOR;
        // inode_size=65535（> 1K 块大小），结构上不可能——一个 inode 表块
        // 最多容纳 block_size 字节的 inode 数据。
        let (mut img, _, _) = build_image();
        let sb = base_sectors as usize + 1024;
        // s_rev_level(76)=1 使 parse 走 inode_size 读取分支；s_inode_size 在 88。
        img[sb + 76..sb + 80].copy_from_slice(&1u32.to_le_bytes());
        img[sb + 88..sb + 90].copy_from_slice(&65535u16.to_le_bytes());
        let got = parse_superblock(&img[sb..sb + 1024].try_into().unwrap());
        assert!(
            matches!(got, Err(Ext2Error::CorruptSuperblock)),
            "inode_size larger than block_size must be rejected as CorruptSuperblock"
        );
    }

    /// fs1 FM2/FD1：七个显式错误变体逐一有测试锁定。
    #[test]
    fn test_error_branches_each_locked() {        let base = PART_START_LBA * SECTOR;
        // FD1：log_block_size=3（8K 块）→ UnsupportedBlockSize（不再冒充片段问题）
        let (mut img, _, _) = build_image();
        let sb = base as usize + 1024;
        img[sb + 24..sb + 28].copy_from_slice(&3u32.to_le_bytes());
        img[sb + 28..sb + 32].copy_from_slice(&3u32.to_le_bytes()); // frag==block 保持一致
        let got = parse_superblock(&img[sb..sb + 1024].try_into().unwrap());
        assert_eq!(got.unwrap_err(), Ext2Error::UnsupportedBlockSize, "FD1 distinct variant");
        // 片段≠块 → UnsupportedFragmentSize
        let (mut img, _, _) = build_image();
        img[sb + 28..sb + 32].copy_from_slice(&1u32.to_le_bytes());
        let got = parse_superblock(&img[sb..sb + 1024].try_into().unwrap());
        assert_eq!(got.unwrap_err(), Ext2Error::UnsupportedFragmentSize);
        // rec_len < 8
        let (fs, _, _) = open_fs();
        let root_ino = fs.read_inode(2).unwrap();
        {
            let (img, _, _) = build_image();
            let mut bad = img;
            let dirblk = base as usize + 20 * BS;
            bad[dirblk + 4..dirblk + 6].copy_from_slice(&3u16.to_le_bytes());
            let dev = Arc::new(MockByteDevice::new(bad));
            let fs2 = Ext2Fs::open(dev, base).unwrap();
            assert_eq!(
                fs2.read_dir_raw(&root_ino).unwrap_err(),
                Ext2Error::CorruptDirEntry,
                "rec_len<8"
            );
        }
        // rec_len 越界（跨出目录尾）
        {
            let (img, _, _) = build_image();
            let mut bad = img;
            let dirblk = base as usize + 20 * BS;
            bad[dirblk + 4..dirblk + 6].copy_from_slice(&2000u16.to_le_bytes());
            let dev = Arc::new(MockByteDevice::new(bad));
            let fs2 = Ext2Fs::open(dev, base).unwrap();
            assert_eq!(
                fs2.read_dir_raw(&root_ino).unwrap_err(),
                Ext2Error::CorruptDirEntry,
                "rec_len overflow"
            );
        }
        // name_len 溢出（8+name_len > rec_len）
        {
            let (img, _, _) = build_image();
            let mut bad = img;
            let dirblk = base as usize + 20 * BS;
            bad[dirblk + 6] = 250; // 名长 250，rec_len 只有 12
            let dev = Arc::new(MockByteDevice::new(bad));
            let fs2 = Ext2Fs::open(dev, base).unwrap();
            assert_eq!(
                fs2.read_dir_raw(&root_ino).unwrap_err(),
                Ext2Error::CorruptDirEntry,
                "name_len overflow"
            );
        }
        // 三重间接显式拒绝：direct12 + L1(256) + L2(65536) 之后的第一个逻辑块
        {
            let mut tri = Inode {
                ino: 99,
                mode: 0x8000,
                size: 200 * 1024,
                blocks: [0u32; 15],
                sectors: 0,
                mtime: 0,
                ctime: 0,
            };
            tri.blocks[14] = 77;
            assert_eq!(
                fs.map_logical_block(&tri, 12 + 256 + 256 * 256),
                Err(Ext2Error::UnsupportedTripleIndirect)
            );
        }
        // 块指针越界
        {
            let mut oob = Inode {
                ino: 99,
                mode: 0x8000,
                size: 1024,
                blocks: [0u32; 15],
                sectors: 2,
                mtime: 0,
                ctime: 0,
            };
            oob.blocks[0] = 999_999;
            let mut out = alloc::vec![0u8; 16];
            assert_eq!(
                fs.read_inode_data(&oob, 0, &mut out).unwrap_err(),
                Ext2Error::BlockOutOfRange
            );
        }
        // 设备末端短读（目录数据块中段即被介质尾截断）
        {
            let (img, _, _) = build_image();
            let cut = base as usize + 20 * BS + 512; // 目录块只留前半
            let truncated = img[..cut].to_vec();
            let dev = Arc::new(MockByteDevice::new(truncated));
            let fs2 = Ext2Fs::open(dev, base).expect("sb within truncation");
            assert_eq!(
                fs2.read_dir_raw(&root_ino).unwrap_err(),
                Ext2Error::ShortRead,
                "device-end short read surfaces as ShortRead"
            );
        }
    }

    /// fs1 FM4：read_block 对不足一块的缓冲显式 BufferTooSmall，不再切片 panic。
    #[test]
    fn test_read_block_rejects_small_buffer() {
        let (fs, _, _) = open_fs();
        let mut tiny = [0u8; 64];
        assert_eq!(
            fs.read_block(25, &mut tiny).unwrap_err(),
            Ext2Error::BufferTooSmall
        );
    }

    /// 审计 R7-F1：slow symlink 的盘上 size 声明必须受设备容量上界约束——
    /// 损坏镜像声明 4GiB 链接目标不得转化为内核巨型分配（FA2 政策对
    /// 符号链接面的执行补齐）。取 2MiB（> 设备 1MiB、分配无害）作越界样本，
    /// 红绿判据 = Err(Corrupt) vs Ok(大缓冲)。
    #[test]
    fn test_slow_symlink_size_capped_not_allocated() {
        use vfs::inode::{FileSystem, INode};
        let (img, _, _) = build_image();
        let mut bad = img;
        let base = (PART_START_LBA * SECTOR) as usize;
        let sz_off = base + 5 * BS + 1664 + 4; // longlink ino14 的 size 字段
        bad[sz_off..sz_off + 4].copy_from_slice(&(2 * 1024 * 1024u32).to_le_bytes());
        let dev = Arc::new(MockByteDevice::new(bad));
        let fs = Ext2Fs::open(dev, PART_START_LBA * SECTOR).expect("sb still valid");
        let root = FileSystem::root(&fs);
        let node = root.lookup("longlink").expect("entry present");
        assert_eq!(
            node.read_link().map(|_| ()).unwrap_err(),
            Error::Corrupt,
            "oversized slow-link declaration must be rejected before allocation"
        );
    }

    /// fs1 FD2：目录尾部 1..7 字节残段 lenient 跳过且不影响有效条目。
    #[test]
    fn test_trailing_residual_tail_is_lenient() {
        let (img, hello, _) = build_image();
        let mut bad = img;
        let base = (PART_START_LBA * SECTOR) as usize;
        let dirblk = base + 20 * BS;
        // 收窄最后一项 rec_len（924→900），再把目录 size 声明为 1005：
        // 链条止于 1000，尾部剩 5 字节 <8 的残段——lenient 跳过 + warn。
        bad[dirblk + 100 + 4..dirblk + 100 + 6].copy_from_slice(&900u16.to_le_bytes());
        let itab = base + 5 * BS;
        let sz_off = itab + 128 + 4;
        bad[sz_off..sz_off + 4].copy_from_slice(&1005u32.to_le_bytes());
        let dev = Arc::new(MockByteDevice::new(bad));
        let fs = Ext2Fs::open(dev, PART_START_LBA * SECTOR).expect("open");
        let root = vfs::inode::FileSystem::root(&fs);
        let entries = root.list_dir().expect("residual tail must not fail listing");
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"longlink"), "all real entries still listed");
        assert_eq!(entries.iter().find(|e| e.name == "hello.txt").unwrap().size, hello.len() as u64);
    }

    /// fs1 FA3b：错误映射表逐变体锁定——用户态可区分介质尾/非法号/
    /// 结构损坏/不支持四类。
    #[test]
    fn test_error_mapping_is_faithful() {
        assert_eq!(ext2_to_klib(Ext2Error::ShortRead), Error::Io);
        assert_eq!(ext2_to_klib(Ext2Error::BadMagic), Error::Io);
        assert_eq!(ext2_to_klib(Ext2Error::BadInode), Error::InvalidParam);
        assert_eq!(ext2_to_klib(Ext2Error::BufferTooSmall), Error::InvalidParam);
        assert_eq!(ext2_to_klib(Ext2Error::CorruptDirEntry), Error::Corrupt);
        assert_eq!(ext2_to_klib(Ext2Error::BlockOutOfRange), Error::Corrupt);
        assert_eq!(ext2_to_klib(Ext2Error::UnsupportedTripleIndirect), Error::NotSupported);
        assert_eq!(ext2_to_klib(Ext2Error::UnsupportedFragmentSize), Error::NotSupported);
        assert_eq!(ext2_to_klib(Ext2Error::UnsupportedBlockSize), Error::NotSupported);
    }

    #[test]
    fn test_ext2_read_hello_byte_exact() {
        use vfs::inode::INode;
        let (fs, hello, _) = open_fs();
        let root = FileSystem::root(&fs);
        let node = root.lookup("hello.txt").expect("present");
        let mut buf = alloc::vec![0u8; hello.len() + 16];
        let n = node.read_at(0, &mut buf).expect("read");
        assert_eq!(n, hello.len(), "EOF 截断必须精确到文件大小");
        assert_eq!(&buf[..n], &hello[..], "C13.2 验收：逐字节一致");
        // EOF 之后再读必须为 0 字节而非报错。
        assert_eq!(node.read_at(hello.len() as u64, &mut buf).unwrap(), 0);
        // 中段窗口读取。
        let mut win = [0u8; 7];
        let wn = node.read_at(9, &mut win).unwrap();
        assert_eq!(wn, 7);
        assert_eq!(&win, &hello[9..16]);
    }

    #[test]
    fn test_ext2_read_indirect_file_cross_boundary() {
        use vfs::inode::INode;
        let (fs, _, big) = open_fs();
        let root = FileSystem::root(&fs);
        let node = root.lookup("big.bin").expect("present");
        let meta = node.metadata().unwrap();
        assert_eq!(meta.size, big.len() as u64);
        // 全量读回（跨 直块→直块→间接块 三种映射）。
        let mut out = alloc::vec![0u8; big.len()];
        let n = node.read_at(0, &mut out).expect("full read");
        assert_eq!(n, big.len());
        assert_eq!(out, big, "直接块与一级间接链路逐字节一致");
        // 跨越 直块→一级间接 边界（逻辑块 11→12，字节 12288）的窗口。
        let mut win = alloc::vec![0u8; 600];
        let wn = node.read_at(12000, &mut win).unwrap();
        assert_eq!(wn, 600);
        assert_eq!(&win[..], &big[12000..12600]);
    }

    #[test]
    fn test_ext2_sparse_hole_reads_zeros() {
        let (fs, _, _) = open_fs();
        // 合成稀疏 inode：全部块指针为 0，size 跨两个块。
        let sparse = Inode {
            ino: 99,
            mode: 0x8000,
            size: 2048,
            blocks: [0u32; 15],
            sectors: 0,
            mtime: 0,
            ctime: 0,
        };
        let mut out = alloc::vec![0xAAu8; 2048];
        let n = fs.read_inode_data(&sparse, 0, &mut out).expect("sparse read");
        assert_eq!(n, 2048);
        assert!(out.iter().all(|&b| b == 0), "hole semantics = zeros");
    }

    #[test]
    fn test_ext2_read_inode_out_of_range() {
        let (fs, _, _) = open_fs();
        assert_eq!(fs.read_inode(0), Err(Ext2Error::BadInode));
        assert_eq!(fs.read_inode(999999), Err(Ext2Error::BadInode));
    }

    #[test]
    fn test_ext2_read_at_eof_returns_zero() {
        use vfs::inode::INode;
        let (fs, hello, _) = open_fs();
        let root = FileSystem::root(&fs);
        let node = root.lookup("hello.txt").expect("present");
        let meta = node.metadata().unwrap();
        assert_eq!(meta.size, hello.len() as u64);
        // offset >= size：EOF 语义 = 返回 0，绝不越界读。
        let mut buf = [0xAAu8; 16];
        let n = node
            .read_at(hello.len() as u64 + 100, &mut buf)
            .expect("EOF read is Ok(0)");
        assert_eq!(n, 0, "read past EOF must return 0");
    }

    #[test]
    fn test_ext2_read_crossing_eof_truncates() {
        use vfs::inode::INode;
        let (fs, hello, _) = open_fs();
        let root = FileSystem::root(&fs);
        let node = root.lookup("hello.txt").expect("present");
        // 窗口从 'size-4' 开始、宽 16：只能读到尾部 4 字节，剩余按短读截断。
        let mut buf = [0xAAu8; 16];
        let n = node
            .read_at(hello.len() as u64 - 4, &mut buf)
            .expect("partial read is Ok");
        assert_eq!(n, 4, "crossing-EOF read returns only available bytes");
        assert_eq!(&buf[..4], &hello[hello.len() - 4..]);
    }

    #[test]
    fn test_ext2_list_dir_on_regular_file_rejected() {
        use vfs::inode::INode;
        let (fs, _, _) = open_fs();
        let root = FileSystem::root(&fs);
        let node = root.lookup("hello.txt").expect("regular file present");
        assert_eq!(node.list_dir().map(|_| ()).unwrap_err(), Error::NotDirectory);
    }

    #[test]
    fn test_ext2_read_dir_as_file_rejected() {
        use vfs::inode::INode;
        let (fs, _, _) = open_fs();
        let root = FileSystem::root(&fs);
        // 根目录的 read_at 必须如实返回 IsDirectory——数据区只有目录项，
        // 按字节读读出的是一堆无意义的结构编码，绝不能伪装成文件内容。
        let mut buf = [0u8; 16];
        assert_eq!(root.read_at(0, &mut buf).map(|_| ()).unwrap_err(), Error::IsDirectory);
    }

    // ---- 限制点修复回归（S04/S09/S31）----

    /// S04：create_entry 入口即拒超长名（>255），不等到 add_dir_entry 才拦，
    /// 杜绝后续 `as u8` 静默截断字节。VFS create 经 mount 层再下到 ext2，
    /// 超长名在入口被显式拒绝为 CorruptDirEntry。
    #[test]
    fn test_create_rejects_name_over_255() {
        use vfs::inode::{FileSystem, Permissions};
        let fs = open_writable();
        let root = FileSystem::root(&fs);
        let long = "a".repeat(256);
        let err = root.create(&long, Permissions::all()).map(|_| ()).unwrap_err();
        assert_eq!(err, Error::Corrupt, "256-byte name must be rejected (name_len is u8)");
        // 恰好 255 应成功。
        let ok255 = "b".repeat(255);
        assert!(root.create(&ok255, Permissions::all()).is_ok(), "255-byte name must succeed");
    }

    /// S04/S31：名字校验与 VFS validate_name 对齐——含控制字符的名字在
    /// create_entry 入口即拒，不产生一条 VFS 能建而 ext2 拒绝（或反之）的
    /// 不一致条目。
    #[test]
    fn test_create_rejects_control_chars() {
        use vfs::inode::{FileSystem, Permissions};
        let fs = open_writable();
        let root = FileSystem::root(&fs);
        for bad in ["bad\nname", "ctl\x01name", "tab\tname", "del\x7fname"] {
            let err = root.create(bad, Permissions::all()).map(|_| ()).unwrap_err();
            assert_eq!(err, Error::Corrupt, "control-char name '{}' must be rejected", bad);
        }
        // 正例：合法名字可建。
        assert!(root.create("ok-name.txt", Permissions::all()).is_ok());
    }

    /// S31：超块缓存陈旧修复——分配后不重挂，同进程内再分配不会因缓存
    /// 快照里的旧 free_blocks_count 误判"卷满"。直接调用底层 alloc 原语
    /// 两次，第二次仍应成功（位图实际有剩余块）。
    #[test]
    fn test_alloc_after_alloc_uses_live_free_count() {
        let fs = open_writable();
        // 快照 free_blocks=2040；连续分配两块，第二次若误读陈旧缓存仍非零，
        // 但为验证"实时读取"正确性：连续分配直到耗尽前都能成功。
        let b1 = fs.alloc_block().expect("first alloc");
        let b2 = fs.alloc_block().expect("second alloc (must not use stale count)");
        assert_ne!(b1, b2, "two allocations must yield distinct blocks");
        let i1 = fs.alloc_inode().expect("first inode alloc");
        let i2 = fs.alloc_inode().expect("second inode alloc");
        assert_ne!(i1, i2, "two inode allocations must yield distinct inodes");
    }

    /// S31：重挂读回的空闲块/inode 计数与未重挂时的实时计数一致——
    /// alloc 每次从盘上实时读取，故同一 fs 实例内 alloc 若干次后盘上记账
    /// 已递减（重挂也读到相同值）。
    #[test]
    fn test_free_counts_decrement_on_disk() {
        let img = build_writable_image();
        let dev: Arc<dyn ByteDevice> = Arc::new(MockByteDevice::new(img));
        let fs = Ext2Fs::open(dev.clone(), PART_START_LBA * SECTOR).expect("open");
        let before = *fs.superblock();
        fs.alloc_block().expect("alloc block");
        fs.alloc_inode().expect("alloc inode");
        // 重挂读盘上真值：各减 1。
        let fs2 = Ext2Fs::open(dev.clone(), PART_START_LBA * SECTOR).expect("remount");
        let after = *fs2.superblock();
        assert_eq!(after.free_blocks_count, before.free_blocks_count - 1);
        assert_eq!(after.free_inodes_count, before.free_inodes_count - 1);
    }

    /// S04：truncate 目标超过 u32::MAX 显式拒绝（不再 `as u32` 静默截断）。
    #[test]
    fn test_truncate_rejects_size_overflow() {
        use vfs::inode::{FileSystem, INode, Permissions};
        let fs = open_writable();
        let root = FileSystem::root(&fs);
        let f = root.create("big.bin", Permissions::all()).expect("create");
        // 目标超过 u32::MAX：底层 truncate_inode 必须显式 BlockOutOfRange 拒绝，
        // 而非 `as u32` 静默截断成一个看似合法的错误 size。4GB 目标远超镜像
        // 容量，但先触发的应是 size 越界判据（在分配任何块之前）。
        let err = f.truncate((u32::MAX as u64) + 1).unwrap_err();
        assert_eq!(err, Error::Corrupt, "size beyond u32::MAX must be rejected (BlockOutOfRange -> Corrupt)");
    }

    /// S04 消除 as u8 截断：write_dir_entry_at 对 >255 名显式拒绝而非截断。
    #[test]
    fn test_write_dir_entry_rejects_overlong_name() {
        let fs = open_writable();
        let bs = fs.superblock().block_size as usize;
        let mut buf = alloc::vec![0u8; bs];
        let long = "a".repeat(256);
        // 直接调 write_dir_entry_at（绕开上层校验的防线）：应显式 CorruptDirEntry。
        let err = fs
            .write_dir_entry_at(&mut buf, 0, 3, &long, 1, bs)
            .map(|_| ()).unwrap_err();
        assert_eq!(err, Ext2Error::CorruptDirEntry, "over-255 name must be rejected, not truncated");
    }

    /// R7 同型：remove_dir_entry 对超大目录 size 在分配前即拒（无帽分配的
    /// 欠账已补）。
    #[test]
    fn test_remove_dir_entry_caps_size() {
        let fs = open_writable();
        // 构造一个 size 声明超设备容量的目录 inode（Corrupt 镜像）。
        let mut bogus = fs.read_inode(2).expect("root inode");
        bogus.size = u32::MAX;
        let err = fs
            .remove_dir_entry(&mut bogus, "nope")
            .map(|_| ()).unwrap_err();
        assert_eq!(err, Ext2Error::CorruptDirEntry, "oversized dir size must be rejected pre-alloc");
    }

    /// 二级间接写 + 读 + unlink 对称：写入超过一级间接区（直块 12 + 每块
    /// per_block 项）的大文件，读回一致，unlink 释放全部块（含二级间接
    /// 表与数据），不报 UnsupportedTripleIndirect。
    #[test]
    fn test_write_read_unlink_double_indirect() {
        use vfs::inode::{FileSystem, Permissions};
        let fs = open_writable();
        let root = FileSystem::root(&fs);
        let f = root.create("dbl.bin", Permissions::all()).expect("create");
        // 每块 1KB，per_block=256；跨一级间接区需 > (12+256)*1024 字节。
        let size = (12 + 256 + 5) * 1024; // 进入二级间接区 5 块
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let n = f.write_at(0, &payload).expect("write across double indirect");
        assert_eq!(n, size);
        let mut back = alloc::vec![0u8; size];
        let rn = f.read_at(0, &mut back).expect("read back");
        assert_eq!(rn, size);
        assert_eq!(back, payload, "double-indirect file round-trips");
        assert_eq!(f.metadata().expect("meta").size, size as u64);
        // unlink：含二级间接的文件可删除，不报 UnsupportedTripleIndirect。
        root.unlink("dbl.bin").expect("unlink double-indirect file");
        assert_eq!(root.lookup("dbl.bin").map(|_| ()).unwrap_err(), Error::NotFound);
    }

    /// slow symlink 目标跨多块（> 块大小）不再越界 panic，读回一致。
    #[test]
    fn test_slow_symlink_multiblock_target() {
        use vfs::inode::FileSystem;
        let fs = open_writable();
        let root = FileSystem::root(&fs);
        // 目标 > 块大小（1KB）：如 2000 字节，跨 2 块。
        let target = "x".repeat(2000);
        let l = root.symlink("longlink", &target).expect("slow multi-block symlink");
        let resolved = l.read_link().expect("read_link");
        assert_eq!(resolved, target, "multi-block symlink target round-trips");
    }

    /// i_blocks（sectors）按 EXT2 规范计入间接表块占用：文件大小对应的
    /// 数据扇区数 < count_sectors（后者含一级/二级间接表块自身）。
    #[test]
    fn test_sectors_accounts_for_indirect_blocks() {
        use vfs::inode::{FileSystem, Permissions};
        let fs = open_writable();
        let root = FileSystem::root(&fs);
        let f = root.create("sect.bin", Permissions::all()).expect("create");
        // 覆盖一级+二级间接区的大文件（块 1KB，per_block=256）。
        let size = (12 + 256 + 5) * 1024;
        let payload = alloc::vec![0u8; size];
        f.write_at(0, &payload).expect("write");
        // 经目录查找重读 inode 得真实 i_blocks（count_sectors）。
        let root_inode = fs.read_inode(EXT2_ROOT_INO).expect("root inode");
        let (_, inode) = fs.lookup_in_dir(&root_inode, "sect.bin").expect("lookup");
        let data_only_sectors = (size as u32).div_ceil(512);
        assert!(
            inode.sectors > data_only_sectors,
            "i_blocks must include indirect table blocks: sectors={} > data_only={}",
            inode.sectors,
            data_only_sectors
        );
        // 精确验证：273 数据块 + 1 一级表 + 1 二级表 + 1 个 L1 表 = 276 块，
        // ×2 扇区/块 = 552。
        assert_eq!(inode.sectors, 276 * 2, "expected 276 blocks × 2 sectors");
    }

    /// N1 回归：新分配块内容清零（间接表块、数据块都经 alloc_block）。
    /// 直接调底层 alloc_block，读回内容必须全 0——若不清零，会读入被删
    /// 文件残留（间接指针污染 / 数据泄漏的根）。
    #[test]
    fn test_alloc_block_zeroes_fresh_block() {
        let fs = open_writable();
        let b = fs.alloc_block().expect("alloc");
        let buf = fs.read_block_buf(b).expect("read");
        assert!(
            buf.iter().all(|&x| x == 0),
            "newly allocated block {} must be zeroed, got {:02X?}",
            b,
            &buf[..8]
        );
    }

    /// N2 回归：文件增长后未写区域读回 0，而非被删文件的残留数据。
    /// 写满一个含 0xAB 残留的文件并删除（释放块但残留仍在盘上），再建新
    /// 文件写部分块——新块复用被删块时，未写字节必须为 0（不泄漏旧数据）。
    #[test]
    fn test_file_grow_does_not_leak_stale_data() {
        use vfs::inode::{FileSystem, Permissions};
        let perm = Permissions::all();
        let fs = open_writable();
        let root = FileSystem::root(&fs);
        // 1) 建文件写满整个块为 0xAB，删除（free_block 只清位图位，残留保留）。
        let f = root.create("stale.bin", perm).expect("create");
        let garbage = alloc::vec![0xABu8; 1024];
        f.write_at(0, &garbage).expect("write garbage");
        root.unlink("stale.bin").expect("unlink");
        // 2) 建新文件，truncate 到整块（grow 复用到刚释放的块），再写部分字节。
        let g = root.create("fresh.bin", perm).expect("create");
        g.truncate(1024).expect("grow to full block");
        g.write_at(0, b"abc").expect("write partial");
        // 3) 读整块：字节 0..3 为 'abc'，其余必须为 0（不得是残留 0xAB）。
        let mut back = alloc::vec![0xEEu8; 1024];
        let n = g.read_at(0, &mut back).expect("read");
        assert_eq!(n, 1024, "read full grown block");
        assert_eq!(&back[..3], b"abc", "written bytes preserved");
        for &x in &back[3..] {
            assert_eq!(x, 0, "unwritten grown region must read back 0, got {:02X}", x);
        }
    }
}
