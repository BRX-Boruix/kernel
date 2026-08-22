//! EXT2 只读文件系统驱动（C13.2）。
//!
//! 布局事实源：`sdk/sdk_build/disk.py` 生成的镜像——MBR 分区 1（起始 LBA
//! 由 [`crate::mbr`] 解析得出），分区内 1024B 块、超级块 @分区偏移 1024、
//! 组描述符 @first_data_block+1 块、inode 表由组描述符指向。
//!
//! 只读边界：本模块不提供任何写路径；VFS 节点的 writable 恒为 false。
//! 稀疏块（块指针 0）按全零读出——这是 EXT2 的真实语义而非伪造。

use crate::ByteDevice;
use alloc::sync::Arc;
use alloc::vec::Vec;
use klib::error::Error;

/// 超级块魔数偏移与期望值。
const SB_MAGIC_OFFSET: usize = 56;
pub const EXT2_SUPER_MAGIC: u16 = 0xEF53;
/// 根目录 inode 号（EXT2 规范固定）。
pub const EXT2_ROOT_INO: u32 = 2;
/// 目录项 filetype 常量。
const FT_DIR: u8 = 2;

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
    /// 目录项损坏（rec_len 越界或不满足最小长度）。
    CorruptDirEntry,
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
pub fn parse_superblock(sb: &[u8; 1024]) -> Result<Ext2Superblock, Ext2Error> {
    if le_u16(sb, SB_MAGIC_OFFSET) != EXT2_SUPER_MAGIC {
        return Err(Ext2Error::BadMagic);
    }
    let log_block_size = le_u32(sb, 24);
    // 片段必须与块等大（disk.py 与主流 mkfs 均如此），否则寻址语义不同。
    if le_u32(sb, 28) != log_block_size || log_block_size > 2 {
        return Err(Ext2Error::UnsupportedFragmentSize);
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
        blocks_count: le_u32(sb, 4),
        inodes_count: le_u32(sb, 0),
        blocks_per_group,
        inodes_per_group: le_u32(sb, 40),
        inode_size,
        first_data_block: le_u32(sb, 20),
        block_size: 1024u32 << log_block_size,
    })
}

/// 解析后的 inode（只含只读路径字段；i_block 为 15 项块指针）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inode {
    pub ino: u32,
    pub mode: u16,
    pub size: u32,
    pub blocks: [u32; 15],
}

impl Inode {
    pub fn is_dir(&self) -> bool {
        self.mode & 0xF000 == 0x4000
    }
    pub fn is_regular(&self) -> bool {
        self.mode & 0xF000 == 0x8000
    }
}

/// 目录项原始记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawDirEntry {
    pub inode: u32,
    pub file_type: u8,
    pub name: Vec<u8>,
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
    fn read_block(&self, block: u32, out: &mut [u8]) -> Result<(), Ext2Error> {
        if block >= self.superblock().blocks_count {
            return Err(Ext2Error::BlockOutOfRange);
        }
        let sb = self.superblock();
        let bs = sb.block_size as u64;
        let off = self.inner.part_start_byte + block as u64 * bs;
        let n = self
            .inner
            .dev
            .read_bytes(off, &mut out[..bs as usize]);
        if n < bs as usize {
            return Err(Ext2Error::ShortRead);
        }
        Ok(())
    }

    /// 读组描述符（GDT 位于 first_data_block + 1 块起，每项 32 字节）：
    /// 返回 (块位图块号, inode 位图块号, inode 表块号)。
    fn read_group_desc(&self, group: u32) -> Result<(u32, u32, u32), Ext2Error> {
        let sb = self.superblock();
        let bs = sb.block_size as usize;
        let gdt_block = (sb.first_data_block + 1) as u64;
        let mut buf = alloc::vec![0u8; bs];
        let off_abs =
            self.inner.part_start_byte + gdt_block * bs as u64 + group as u64 * 32;
        let n = self.inner.dev.read_bytes(off_abs, &mut buf[..32]);
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

    /// 遍历目录 inode 的全部目录项。
    pub fn read_dir_raw(&self, dir: &Inode) -> Result<Vec<RawDirEntry>, Ext2Error> {
        if !dir.is_dir() {
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
                out.push(RawDirEntry {
                    inode: ino,
                    file_type: ft,
                    name: data[cur + 8..cur + 8 + name_len].to_vec(),
                });
            }
            cur += rec_len;
        }
        Ok(out)
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

pub(crate) fn ext2_to_klib(e: Ext2Error) -> Error {
    match e {
        Ext2Error::BadMagic | Ext2Error::BadInode | Ext2Error::CorruptDirEntry => Error::Io,
        Ext2Error::ShortRead | Ext2Error::BlockOutOfRange => Error::Io,
        Ext2Error::UnsupportedTripleIndirect | Ext2Error::UnsupportedFragmentSize => {
            Error::NotSupported
        }
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

fn node_type_of(mode: u16) -> INodeType {
    match mode & 0xF000 {
        0x4000 => INodeType::Directory,
        0x8000 => INodeType::RegularFile,
        0xA000 => INodeType::Symlink,
        _ => INodeType::RegularFile,
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

    fn metadata(&self) -> Result<FileMetadata, Error> {
        Ok(FileMetadata {
            node_type: node_type_of(self.inode.mode),
            size: self.inode.size as u64,
            permissions: Permissions {
                readable: self.inode.mode & 0o444 != 0,
                // C13.2：只读挂载，writable 必须如实为 false。
                writable: false,
                executable: self.inode.mode & 0o111 != 0,
                system_only: false,
            },
            created_time: 0,
            modified_time: 0,
            changed_time: 0,
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

    fn list_dir(&self) -> Result<Vec<DirEntry>, Error> {
        if !self.inode.is_dir() {
            return Err(Error::NotDirectory);
        }
        let entries = self.fs.read_dir_raw(&self.inode).map_err(ext2_to_klib)?;
        Ok(entries
            .into_iter()
            .map(|e| DirEntry {
                name: String::from_utf8_lossy(&e.name).into_owned(),
                node_type: if e.file_type == FT_DIR {
                    INodeType::Directory
                } else {
                    INodeType::RegularFile
                },
                size: 0,
            })
            .collect())
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
    /// hello.txt（单直块）+ big.bin（双直块 + 一级间接，跨块边界）。
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
        // hello.txt ino11：单直块 25
        let hello: Vec<u8> = b"Welcome to BORUIX Real Ext2 Filesystem!\n".to_vec();
        img.w16(itab + 1280, 0x8000 | 0o644);
        img.w32(itab + 1280 + 4, hello.len() as u32);
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
        // 根目录数据块 20
        let mut d = [0u8; BS];
        let mut cur = put_de(&mut d, 0, 2, ".", 2, 12);
        cur = put_de(&mut d, cur, 2, "..", 2, 12);
        cur = put_de(&mut d, cur, 11, "hello.txt", 1, 24);
        put_de(&mut d, cur, 12, "big.bin", 1, BS - cur);
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
}
