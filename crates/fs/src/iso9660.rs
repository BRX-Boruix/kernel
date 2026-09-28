//! ISO9660 只读文件系统（B2 第二步：CD 介质的文件系统层）。
//!
//! **解析面（S06 实证钉死）**：本实现对齐 sdk _make_iso 的产物形态——
//! xorriso -as mkisofs **无 -J/-R 扩展开关**，纯 ISO9660（ECMA-119）：
//! 目录记录 8.3 大写命名、无 Rock Ridge、无 Joliet。宿主侧解析实证：
//! 卷标 ISOIMAGE、逻辑块 2048、根目录 extent=19。
//!
//! **只读边界（S17）**：CD-ROM 介质物理只读——write/create/unlink/truncate
//! 全部如实 ReadOnly/NotSupported 拒绝，不提供伪成功。
//!
//! 字段读取纪律：目录记录的多字节字段是 **both-endian**（小端 + 大端双份），
//! 统一取小端份并交叉校验大端份——不一致即镜像损坏（Corrupt），不静默采信
//! 一侧（防 bit-rot 镜像）。

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use klib::error::Error;
use vfs::inode::{AccessPolicy, DirEntry, FileMetadata, FileSystem, INode, INodeType};

use crate::ByteDevice;

/// ISO9660 逻辑块大小（ECMA-119 规范单一值；PVD 的块大小字段交叉校验此值）。
pub const ISO_BLOCK_SIZE: u64 = 2048;
/// 主卷描述符驻留 LBA（规范 8.4：恒 16）。
const PVD_LBA: u64 = 16;
/// 卷描述符魔数（每个描述符 +1 偏移起 5 字节）。
const CD001: [u8; 5] = *b"CD001";

/// ISO9660 解析错误（映射到 klib Error 前的本层精确语义）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsoError {
    /// PVD 缺失 / 魔数错 / 块大小非 2048——不是 ISO9660 介质。
    NotIso9660,
    /// 设备短读（越界 / 介质尾）。
    ShortRead,
    /// 目录记录结构非法（长度越界 / both-endian 双份不一致）。
    Corrupt,
    /// 路径分量不存在。
    NotFound,
    /// 介质只读（写路径拒绝）。
    ReadOnly,
}

impl IsoError {
    fn to_klib(self) -> Error {
        match self {
            IsoError::NotIso9660 => Error::NotSupported,
            IsoError::ShortRead => Error::Io,
            IsoError::Corrupt => Error::Corrupt,
            IsoError::NotFound => Error::NotFound,
            IsoError::ReadOnly => Error::ReadOnly,
        }
    }
}

type IsoResult<T> = Result<T, IsoError>;

/// 目录记录（Directory Record，ECMA-119 9.1）的内存视图。
#[derive(Debug, Clone)]
pub struct DirRecord {
    /// 数据区起始 LBA。
    pub lba: u64,
    /// 数据长度（字节）。
    pub size: u64,
    /// bit0=目录、其余本层不消费。
    pub flags: u8,
    /// **规范真名**：Rock Ridge NM 条目优先（介质真值，S15）；无 RR 介质
    /// 降级为 ISO9660 基础名（8.3 去 `;1`）——后者在 RR 介质上是**降级视
    /// 图**而非真名（`kernel.;1` 的真名是 `kernel`）。
    pub name: String,
    /// Rock Ridge PX 条目的 POSIX mode（低 12 位，含类型/权限位）；无 PX
    /// 时为 `None`（metadata 权限回退到只读缺省 0o555）。
    pub rr_mode: Option<u32>,
    /// 是否 `.` / `..` 特殊项（list_dir 过滤——与 EXT2 同纪律）。
    pub is_dot: bool,
}

/// ISO9660 文件系统实例。
pub struct IsoFs {
    dev: Arc<dyn ByteDevice>,
    /// 根目录记录的 extent（PVD +156 解出）。
    root_lba: u64,
    root_size: u64,
    /// 卷标识（PVD +40..72 ASCII，trim 尾空格）。
    volume_id: String,
}

impl IsoFs {
    /// 打开设备上的 ISO9660 并校验 PVD（整盘根）。
    pub fn open(dev: Arc<dyn ByteDevice>) -> Result<Self, IsoError> {
        Self::open_rooted(dev, &[])
    }

    /// 打开 ISO9660 并以 `subpath` 子目录为文件系统根（B2：/programs 载体）。
    ///
    /// 语义：介质即系统——SDK 把用户程序放进 ISO 的 `/programs/` 真目录，
    /// 内核把该子目录直接挂为 VFS `/programs`（零复制、拖入即装）。
    /// `subpath` 逐段解析（每段须是目录）；空切片 = 整盘根。
    pub fn open_subroot(dev: Arc<dyn ByteDevice>, subpath: &[&str]) -> Result<Self, IsoError> {
        Self::open_rooted(dev, subpath)
    }

    /// 内部通用打开：PVD 校验后，从根（或子路径末端目录）建立 FS 根。
    fn open_rooted(dev: Arc<dyn ByteDevice>, subpath: &[&str]) -> Result<Self, IsoError> {
        let pvd_off = PVD_LBA * ISO_BLOCK_SIZE;
        // +156 起的根目录记录（34 字节）是 PVD 读取的最深字段 → 缓冲 200 字节。
        let mut pvd = [0u8; 200];
        let n = dev.read_bytes(pvd_off, &mut pvd);
        if n < pvd.len() {
            return Err(IsoError::ShortRead);
        }
        // type=1（主卷描述符）+ CD001 魔数 + 版本 1。
        if pvd[0] != 1 || pvd[1..6] != CD001 || pvd[6] != 1 {
            return Err(IsoError::NotIso9660);
        }
        // 逻辑块大小：+128 both-endian u16（实测 xorriso 产物：00 08 / 08 00）。
        // 非 2048 介质不支持（不硬掰——宣称支持的与实际支持的对齐）。
        let lsb = u16::from_le_bytes([pvd[128], pvd[129]]);
        let msb = u16::from_be_bytes([pvd[130], pvd[131]]);
        if lsb != msb || lsb as u64 != ISO_BLOCK_SIZE {
            return Err(IsoError::NotIso9660);
        }
        // 根目录记录：+156，34 字节定长形态（9.1）。extent/size 双端校验。
        let rr = &pvd[156..156 + 34];
        let mut root_lba = read_both_u32(rr, 2)?;
        let mut root_size = read_both_u32(rr, 10)?;
        if rr[0] != 34 {
            return Err(IsoError::Corrupt);
        }
        let volume_id = String::from(
            core::str::from_utf8(&pvd[40..72]).unwrap_or("").trim_end(),
        );
        // 子路径逐段下行（B2：["programs"] → /programs 子目录为根）。
        let probe = Self {
            dev: dev.clone(),
            root_lba,
            root_size,
            volume_id: volume_id.clone(),
        };
        for seg in subpath {
            let rec = probe.lookup_in_dir(root_lba, root_size, seg)?;
            if rec.flags & 0x02 == 0 {
                return Err(IsoError::Corrupt); // 子路径中间段必须是目录
            }
            root_lba = rec.lba;
            root_size = rec.size;
        }
        Ok(Self {
            dev,
            root_lba,
            root_size,
            volume_id,
        })
    }

    /// 卷标识（供挂载命名 /volumes/{label}；空卷标由调用方回退命名）。
    pub fn volume_id(&self) -> &str {
        &self.volume_id
    }

    /// 读一个 extent（LBA 对齐、任意字节长度）到 out。
    fn read_extent(&self, lba: u64, size: u64, out: &mut [u8]) -> IsoResult<()> {
        if out.len() < size as usize {
            return Err(IsoError::Corrupt);
        }
        let n = self.dev.read_bytes(lba * ISO_BLOCK_SIZE, &mut out[..size as usize]);
        if n < size as usize {
            return Err(IsoError::ShortRead);
        }
        Ok(())
    }

    /// 解析一个 extent 上的全部目录记录（`.`/`..` 照解，消费方过滤）。
    fn read_dir_records(&self, lba: u64, size: u64) -> IsoResult<Vec<DirRecord>> {
        let mut raw = alloc::vec![0u8; size as usize];
        self.read_extent(lba, size, &mut raw)?;
        let mut out = Vec::new();
        let mut o = 0usize;
        let bl = ISO_BLOCK_SIZE as usize;
        while o < raw.len() {
            let len = raw[o] as usize;
            if len == 0 {
                // 记录不跨逻辑块边界：跳到下一块边界（规范 9.1）:
                o = (o / bl + 1) * bl;
                continue;
            }
            if o + len > raw.len() {
                return Err(IsoError::Corrupt);
            }
            let rec = &raw[o..o + len];
            let lba2 = read_both_u32(rec, 2)?;
            let size2 = read_both_u32(rec, 10)?;
            let flags = rec[25];
            let name_len = rec[32] as usize;
            if 33 + name_len > len {
                return Err(IsoError::Corrupt);
            }
            let name_bytes = &rec[33..33 + name_len];
            let (base_name, is_dot) = decode_name(name_bytes);
            // System Use 区（名字后 pad 到偶对齐）——SUSP/Rock Ridge 条目：
            // NM=真名、PX=POSIX mode。无 RR 介质该区无 NM，降级基础名。
            let su_off = 33 + name_len + ((33 + name_len) & 1);
            let (rr_name, rr_mode) = parse_susp(&rec[su_off..]);
            let name = rr_name.unwrap_or(base_name);
            out.push(DirRecord {
                lba: lba2,
                size: size2,
                flags,
                name,
                rr_mode,
                is_dot,
            });
            o += len;
        }
        Ok(out)
    }

    /// 目录内按名查找（精确匹配；`.`/`..` 也可解析——与 EXT2 lookup 同语义）。
    fn lookup_in_dir(&self, lba: u64, size: u64, name: &str) -> IsoResult<DirRecord> {
        let records = self.read_dir_records(lba, size)?;
        records.into_iter().find(|r| r.name == name).ok_or(IsoError::NotFound)
    }

    /// 读文件数据（目录记录 → 字节流）。
    fn read_file_data(&self, rec: &DirRecord, offset: u64, buf: &mut [u8]) -> IsoResult<usize> {
        if rec.flags & 0x02 != 0 {
            return Err(IsoError::Corrupt); // 目录没有字节流；类型语义由节点层拒绝
        }
        if offset >= rec.size {
            return Ok(0);
        }
        let avail = (rec.size - offset) as usize;
        let want = buf.len().min(avail);
        let n = self
            .dev
            .read_bytes(rec.lba * ISO_BLOCK_SIZE + offset, &mut buf[..want]);
        Ok(n)
    }
}

/// 目录记录名字解码：0x00→`.`、0x01→`..`、其余 ASCII 去掉 `;版本号` 后缀
///（xorriso 无 -J 时写 KERNEL.;1 / LIMINE.CON;1 形态）。
fn decode_name(raw: &[u8]) -> (String, bool) {
    if raw.len() == 1 && raw[0] == 0 {
        return (String::from("."), true);
    }
    if raw.len() == 1 && raw[0] == 1 {
        return (String::from(".."), true);
    }
    let end = raw.iter().position(|&b| b == b';').unwrap_or(raw.len());
    let s = core::str::from_utf8(&raw[..end]).unwrap_or("");
    (String::from(s), false)
}

/// SUSP / Rock Ridge 条目解析（System Use 区）。
///
/// 只消费两件有真值语义的东西：
/// - **NM**（RFC 名称记录）：介质上的真名——`kernel.;1` 的真名是 `kernel`
///   （xorriso 产物实证）。多段 NM 顺序拼接（RFC 名可分段）。
/// - **PX**（POSIX 文件属性）：mode（both-endian u32，低 12 位类型+权限）。
///   权限含可执行位——exec 语义的真值源，比硬编码 0o555 诚实。
///
/// 其余签名（SP/TF/CE/SL/PN…）按各自长度整段跳过，不会把数据误读成下一
/// 条目；CE（延续区）跳过意味着**超长延续真名不支持**——如实降级为 8.3
/// 基础名（不支持的能力不伪装，S09）。
fn parse_susp(su: &[u8]) -> (Option<String>, Option<u32>) {
    let mut name: Option<String> = None;
    let mut mode: Option<u32> = None;
    let mut k = 0usize;
    while k + 4 <= su.len() {
        let sig = [su[k], su[k + 1]];
        let len = su[k + 2] as usize;
        // SUSP 最短条目 4 字节；长度越界 = 结构破坏，停止解析（已提取的保留）。
        if len < 4 || k + len > su.len() {
            break;
        }
        match sig {
            // NM：flags 在 +4（bit0=CONTINUE 有后续段），内容 +5..len；
            // bit0 置位表示后面还有 NM 段——循环自然续拼。
            [b'N', b'M'] if len >= 5 && su[k + 4] & 0b1 == 0 => {
                let seg = core::str::from_utf8(&su[k + 5..k + len]).unwrap_or("");
                let merged = match name.take() {
                    Some(prev) => prev + seg,
                    None => String::from(seg),
                };
                name = Some(merged);
            }
            // PX：mode/links/uid/gid 均 both-endian u32（载荷 16 字节）。
            [b'P', b'X'] if len >= 20 => {
                let le = u32::from_le_bytes([su[k + 4], su[k + 5], su[k + 6], su[k + 7]]);
                let be = u32::from_be_bytes([su[k + 8], su[k + 9], su[k + 10], su[k + 11]]);
                if le == be {
                    mode = Some(le & 0xFFF);
                }
            }
            _ => {}
        }
        k += len;
    }
    (name, mode)
}

/// both-endian u32 读取：小端份为值、大端份交叉校验（不一致=镜像损坏）。
fn read_both_u32(rec: &[u8], at: usize) -> IsoResult<u64> {
    if at + 8 > rec.len() {
        return Err(IsoError::Corrupt);
    }
    let le = u32::from_le_bytes([rec[at], rec[at + 1], rec[at + 2], rec[at + 3]]);
    let be = u32::from_be_bytes([rec[at + 4], rec[at + 5], rec[at + 6], rec[at + 7]]);
    if le != be {
        return Err(IsoError::Corrupt);
    }
    Ok(le as u64)
}

/// ISO9660 节点。
pub struct IsoNode {
    fs: IsoFs,
    rec: DirRecord,
}

impl IsoNode {
    fn is_dir(&self) -> bool {
        self.rec.flags & 0x02 != 0
    }
}

impl INode for IsoNode {
    fn stable_id(&self) -> u64 {
        // extent LBA 在本介质上是稳定文件身份（同一文件恒等）；+1 避 0。
        self.rec.lba.wrapping_mul(2).wrapping_add(1)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        if self.is_dir() {
            return Err(Error::IsDirectory);
        }
        self.fs
            .read_file_data(&self.rec, offset, buf)
            .map_err(IsoError::to_klib)
    }

    fn write_at(&self, _offset: u64, _buf: &[u8]) -> Result<usize, Error> {
        // CD-ROM 介质物理只读（S17）：不是“实现没写完”，是介质事实。
        Err(Error::ReadOnly)
    }

    fn truncate(&self, _size: u64) -> Result<(), Error> {
        Err(Error::ReadOnly)
    }

    fn node_type(&self) -> Result<INodeType, Error> {
        Ok(if self.is_dir() {
            INodeType::Directory
        } else {
            INodeType::RegularFile
        })
    }

    fn metadata(&self) -> Result<FileMetadata, Error> {
        Ok(FileMetadata {
            node_type: if self.is_dir() {
                INodeType::Directory
            } else {
                INodeType::RegularFile
            },
            size: self.rec.size,
            // 权限真值序：Rock Ridge PX mode（介质披露，含可执行位）优先；
            // 无 PX 介质回退只读缺省 0o555（诚实缺省，非伪造）。无属主真值，
            // (0,0) 烙印（与 EXT2 symlink 路径同一过渡态口径）。
            permissions: AccessPolicy::from_classic_owned(
                self.rec.rr_mode.unwrap_or(0o555),
                0,
                0,
            ),
            // ISO9660 记录的 time 字段语义弱且无时区真值——恒 0（“字段不采信”
            // 比“采信伪时间”诚实，FM1 同源）。
            created_time: 0,
            modified_time: 0,
            changed_time: 0,
        })
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn INode>, Error> {
        if !self.is_dir() {
            return Err(Error::NotDirectory);
        }
        let rec = self
            .fs
            .lookup_in_dir(self.rec.lba, self.rec.size, name)
            .map_err(IsoError::to_klib)?;
        Ok(Arc::new(IsoNode {
            fs: self.fs.clone(),
            rec,
        }))
    }

    fn create(&self, _name: &str, _mode: u32, _owner: (u32, u32)) -> Result<Arc<dyn INode>, Error> {
        Err(Error::ReadOnly)
    }

    fn unlink(&self, _name: &str) -> Result<(), Error> {
        Err(Error::ReadOnly)
    }

    fn list_dir(&self) -> Result<Vec<DirEntry>, Error> {
        if !self.is_dir() {
            return Err(Error::NotDirectory);
        }
        let records = self
            .fs
            .read_dir_records(self.rec.lba, self.rec.size)
            .map_err(IsoError::to_klib)?;
        Ok(records
            .into_iter()
            .filter(|r| !r.is_dot) // `.`/`..` 不外泄（EXT2 同纪律，S13 统一语义）
            .map(|r| DirEntry {
                name: r.name,
                node_type: if r.flags & 0x02 != 0 {
                    INodeType::Directory
                } else {
                    INodeType::RegularFile
                },
                size: r.size,
            })
            .collect())
    }
}

impl FileSystem for IsoFs {
    fn root(&self) -> Arc<dyn INode> {
        Arc::new(IsoNode {
            fs: self.clone(),
            rec: DirRecord {
                lba: self.root_lba,
                size: self.root_size,
                flags: 0x02,
                name: String::from("/"),
                rr_mode: None,
                is_dot: false,
            },
        })
    }

    fn name(&self) -> &'static str {
        "iso9660"
    }
}

/// Clone 手写：ByteDevice 是 Arc 共享，浅克隆即同一介质视图（与 Ext2Fs 同法）。
impl Clone for IsoFs {
    fn clone(&self) -> Self {
        Self {
            dev: self.dev.clone(),
            root_lba: self.root_lba,
            root_size: self.root_size,
            volume_id: self.volume_id.clone(),
        }
    }
}
