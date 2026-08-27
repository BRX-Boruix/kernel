//! EXT2 只读文件系统驱动（C13.2；fs1 整改后形态）。
//!
//! 布局事实源：`sdk/sdk_build/disk.py` 生成的镜像——MBR 分区 1（起始 LBA
//! 由 [`crate::mbr`] 解析得出），分区内 1024B 块、超级块 @分区偏移 1024、
//! 组描述符 @first_data_block+1 块、inode 表由组描述符指向。
//!
//! 只读边界：本模块不提供任何写路径；VFS 节点的 writable 恒为 false，全部
//! 写族方法如实返回 [`Error::ReadOnly`]（EROFS）而非 trait 默认的
//! NotDirectory/NotSupported 谎言（fs1 FA3a）。稀疏块（块指针 0）按全零
//! 读出——这是 EXT2 的真实语义而非伪造。
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
        return Err(Ext2Error::CorruptDirEntry);
    }
    // EXT2 规范：first_data_block 为 1 当且仅当块大小 1024，否则为 0。
    let first_data_block = le_u32(sb, 20);
    let expect_fdb = if block_size == 1024 { 1 } else { 0 };
    if first_data_block != expect_fdb {
        return Err(Ext2Error::CorruptDirEntry);
    }
    let inode_size = if le_u32(sb, 76) >= 1 {
        let s = le_u16(sb, 88);
        if s < 128 {
            return Err(Ext2Error::BadInode);
        }
        s
    } else {
        128
    };
    let blocks_per_group = le_u32(sb, 32);
    if blocks_per_group == 0 {
        return Err(Ext2Error::BadInode);
    }
    Ok(Ext2Superblock {
        blocks_count,
        inodes_count,
        blocks_per_group,
        inodes_per_group: le_u32(sb, 40),
        inode_size,
        first_data_block,
        block_size,
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
    /// 返回 (块位图块号, inode 位图块号, inode 表块号)。
    ///
    /// fs1 FM4 附带：直接按 32 字节定长栈缓冲读取，不再整块分配堆内存
    /// 只为取前 32 字节。
    fn read_group_desc(&self, group: u32) -> Result<(u32, u32, u32), Ext2Error> {
        let sb = self.superblock();
        let gdt_block = (sb.first_data_block + 1) as u64;
        let mut buf = [0u8; 32];
        let off_abs =
            self.inner.part_start_byte + gdt_block * sb.block_size as u64 + group as u64 * 32;
        let n = self.inner.dev.read_bytes(off_abs, &mut buf);
        if n < 32 {
            return Err(Ext2Error::ShortRead);
        }
        Ok((le_u32(&buf, 0), le_u32(&buf, 4), le_u32(&buf, 8)))
    }

    /// 按 inode 号读取 inode 结构。
    pub fn read_inode(&self, ino: u32) -> Result<Inode, Ext2Error> {
        let sb = self.superblock();
        if ino == 0 || ino > sb.inodes_count || sb.inodes_per_group == 0 {
            return Err(Ext2Error::BadInode);
        }
        let group = (ino - 1) / sb.inodes_per_group;
        let idx = (ino - 1) % sb.inodes_per_group;
        let (_, _, inode_table) = self.read_group_desc(group)?;
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
}

/// fs1 FA3b：错误分类学忠实映射。五类故障不再压扁成单一 Io——
/// 介质尾/传输失败（Io）、非法 inode 号（InvalidParam）、盘上结构损坏
/// （Corrupt，EUCLEAN）、能力不支持（NotSupported）各自可达用户态。
/// 逐项分界理由见各变体文档与 ADR-021。
pub(crate) fn ext2_to_klib(e: Ext2Error) -> Error {
    match e {
        Ext2Error::BadMagic | Ext2Error::ShortRead => Error::Io,
        Ext2Error::BadInode | Ext2Error::BufferTooSmall => Error::InvalidParam,
        Ext2Error::CorruptDirEntry | Ext2Error::BlockOutOfRange => Error::Corrupt,
        Ext2Error::UnsupportedTripleIndirect
        | Ext2Error::UnsupportedFragmentSize
        | Ext2Error::UnsupportedBlockSize => Error::NotSupported,
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
        self.fs
            .read_inode_data(&self.inode, offset, buf)
            .map_err(ext2_to_klib)
    }

    /// fs1 FA3a：只读介质的写访问如实返回 ReadOnly（EROFS）。
    ///
    /// trait 默认值是 NotSupported 或 NotDirectory——前者谎称"没实现"
    ///（暗示将来会有），后者谎称"你不是目录"。真相只有一句话：介质只读，
    /// 任何调用者都不可写。
    fn write_at(&self, _offset: u64, _buf: &[u8]) -> Result<usize, Error> {
        Err(Error::ReadOnly)
    }

    fn truncate(&self, _size: u64) -> Result<(), Error> {
        Err(Error::ReadOnly)
    }

    /// A5（ADR-023 §4）：类型从缓存 mode 派生，零盘访问零分配——
    /// metadata 的 Corrupt 语义在此退化为"未知模式按 RegularFile 兜底"，
    /// 热路径判型不允许失败；完整校验仍由 metadata() 承担。
    fn node_type(&self) -> INodeType {
        node_type_of(self.inode.mode).unwrap_or(INodeType::RegularFile)
    }

    /// 元数据：size/type/权限/时间全部来自盘上真值。
    ///
    /// 时间戳政策（fs1 FM1）：modified=mtime、changed=ctime 为盘上真值；
    /// created_time 恒 0——EXT2 rev1 无创建时间字段（crtime 仅 rev2 且
    /// inode_size>128 才有），0 是成文的"字段不存在"，不是伪造的时间。
    fn metadata(&self) -> Result<FileMetadata, Error> {
        let node_type =
            node_type_of(self.inode.mode).ok_or(Error::Corrupt)?;
        Ok(FileMetadata {
            node_type,
            size: self.inode.size as u64,
            permissions: Permissions {
                // fd1 FD3 映射取舍：单用户内核无身份区分，owner/group/other
                // 抹平为"任意一位即可"。粒度损失是有意的简化，接线多用户
                // 身份模型时此处必须重审。
                readable: self.inode.mode & 0o444 != 0,
                // C13.2：只读挂载，writable 必须如实为 false。
                writable: false,
                executable: self.inode.mode & 0o111 != 0,
                system_only: false,
            },
            created_time: 0,
            modified_time: self.inode.mtime as u64,
            changed_time: self.inode.ctime as u64,
        })
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn INode>, Error> {
        if !self.inode.is_dir() {
            return Err(Error::NotDirectory);
        }
        let (_, inode) = self.fs.lookup_in_dir(&self.inode, name)?;
        Ok(Arc::new(Ext2Node {
            fs: self.fs.clone(),
            inode,
        }))
    }

    fn create(&self, _name: &str, _perm: Permissions) -> Result<Arc<dyn INode>, Error> {
        Err(Error::ReadOnly)
    }

    fn mkdir(&self, _name: &str, _perm: Permissions) -> Result<Arc<dyn INode>, Error> {
        Err(Error::ReadOnly)
    }

    fn unlink(&self, _name: &str) -> Result<(), Error> {
        Err(Error::ReadOnly)
    }

    fn symlink(&self, _name: &str, _target: &str) -> Result<Arc<dyn INode>, Error> {
        Err(Error::ReadOnly)
    }

    /// 列出子项：size 与 node_type 全部来自关联 inode 真值（fs1 F1/FA1）。
    /// 此前的 `size: 0` 硬编码让 sys_readdir 对每个 EXT2 文件都报"0 字节"
    /// ——与同一文件的 cat/exec 结果自相矛盾，属用户可见伪数据。
    fn list_dir(&self) -> Result<Vec<DirEntry>, Error> {
        if !self.inode.is_dir() {
            return Err(Error::NotDirectory);
        }
        let entries = self.fs.read_dir_raw(&self.inode).map_err(ext2_to_klib)?;
        entries
            .into_iter()
            .map(|e| {
                let node_type = node_type_of(e.mode).ok_or(Error::Corrupt)?;
                Ok(DirEntry {
                    name: String::from_utf8_lossy(&e.name).into_owned(),
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
        Ok(String::from_utf8_lossy(&raw).into_owned())
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
        // C13.2 只读契约：writable 必须如实为 false。
        assert!(!meta.permissions.writable);
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

    /// fs1 FA3a：全部写族操作如实 EROFS——不再是默认 trait 的
    /// NotDirectory/NotSupported 谎言。
    #[test]
    fn test_write_paths_return_read_only() {
        use vfs::inode::{FileSystem, INode, Permissions};
        let (fs, _, _) = open_fs();
        let root = FileSystem::root(&fs);
        let ro = Error::ReadOnly;
        let perm = Permissions { readable: true, writable: false, executable: false, system_only: false };
        assert_eq!(root.create("x", perm).map(|_| ()).unwrap_err(), ro);
        assert_eq!(root.mkdir("x", perm).map(|_| ()).unwrap_err(), ro);
        assert_eq!(root.unlink("hello.txt").unwrap_err(), ro);
        assert_eq!(root.symlink("x", "/y").map(|_| ()).unwrap_err(), ro);
        let f = root.lookup("hello.txt").expect("present");
        assert_eq!(f.write_at(0, b"no").unwrap_err(), ro);
        assert_eq!(f.truncate(0).unwrap_err(), ro);
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
        assert!(matches!(got, Err(Ext2Error::CorruptDirEntry)), "fdb mismatch rejected");
        // blocks_count=0
        let (mut img, _, _) = build_image();
        img[sb + 4..sb + 8].copy_from_slice(&0u32.to_le_bytes());
        let got = Ext2Fs::open(Arc::new(MockByteDevice::new(img)), base_sectors);
        assert!(matches!(got, Err(Ext2Error::CorruptDirEntry)), "zero blocks_count rejected");
        // inodes_count=0
        let (img, _, _) = build_image();
        let mut img = img;
        img[sb..sb + 4].copy_from_slice(&0u32.to_le_bytes());
        let got = Ext2Fs::open(Arc::new(MockByteDevice::new(img)), base_sectors);
        assert!(matches!(got, Err(Ext2Error::CorruptDirEntry)), "zero inodes_count rejected");
    }

    /// fs1 FM2/FD1：七个显式错误变体逐一有测试锁定。
    #[test]
    fn test_error_branches_each_locked() {
        let base = PART_START_LBA * SECTOR;
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
}
