//! 打开文件句柄（FileHandle）与打开标志（OpenFlags）（ADR-011 方案 A）。

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use klib::error::Error;

use crate::inode::{FileMetadata, INode};

/// 打开标志。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenFlags {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub truncate: bool,
    pub append: bool,
    pub directory: bool,
}

impl OpenFlags {
    pub const READ_ONLY: Self = Self {
        read: true,
        write: false,
        create: false,
        truncate: false,
        append: false,
        directory: false,
    };

    pub const WRITE_ONLY: Self = Self {
        read: false,
        write: true,
        create: false,
        truncate: false,
        append: false,
        directory: false,
    };

    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
        create: false,
        truncate: false,
        append: false,
        directory: false,
    };

    pub const CREATE_OR_TRUNCATE: Self = Self {
        read: true,
        write: true,
        create: true,
        truncate: true,
        append: false,
        directory: false,
    };

    /// 追加写（O_APPEND 语义）：每次 write 的落点锚定当前真实大小。
    pub const READ_WRITE_APPEND: Self = Self {
        read: true,
        write: true,
        create: false,
        truncate: false,
        append: true,
        directory: false,
    };

    pub const fn to_bits(self) -> u32 {
        let mut bits = 0;
        if self.read {
            bits |= 1 << 0;
        }
        if self.write {
            bits |= 1 << 1;
        }
        if self.create {
            bits |= 1 << 2;
        }
        if self.truncate {
            bits |= 1 << 3;
        }
        if self.append {
            bits |= 1 << 4;
        }
        if self.directory {
            bits |= 1 << 5;
        }
        bits
    }

    /// 按位解码打开标志。
    ///
    /// KD7 成文策略（宽松掩码）：`bits` 中不属于本 ABI 的未知高位被**静默
    /// 忽略**（逐位提取，不做 EINVAL）。这是有意选择而非疏漏——标志集随内核
    /// 版本演进，旧二进制携带新内核不认识的位不应导致打开失败；调用方如需
    /// 严格校验可先经 [`Self::to_bits`] 往返比对丢弃的位。位分配见 [`Self::to_bits`]。
    pub const fn from_bits(bits: u32) -> Self {
        Self {
            read: (bits & (1 << 0)) != 0,
            write: (bits & (1 << 1)) != 0,
            create: (bits & (1 << 2)) != 0,
            truncate: (bits & (1 << 3)) != 0,
            append: (bits & (1 << 4)) != 0,
            directory: (bits & (1 << 5)) != 0,
        }
    }
}

/// 进程打开文件句柄（持有底层 INode + 独立读写偏移量 offset + 打开标志）。
pub struct FileHandle {
    pub inode: Arc<dyn INode>,
    pub offset: AtomicU64,
    pub flags: OpenFlags,
}

impl FileHandle {
    /// 构造句柄（ADR-023 §5）。
    ///
    /// - **M4**：`flags.directory`（O_DIRECTORY）在此强制——目标非目录即
    ///   `NotDirectory`。解析后无人执行的旗标等于不存在；
    /// - **M3**：append 初始 offset 取自 inode 真实 size，metadata 失败
    ///   如实上抛——旧 `unwrap_or(0)` 会把追加起点静默落回文件头，
    ///   第一次写入就覆盖既有内容。
    pub fn new(inode: Arc<dyn INode>, flags: OpenFlags) -> Result<Self, Error> {
        if flags.directory && inode.node_type()? != crate::inode::INodeType::Directory {
            return Err(Error::NotDirectory);
        }
        let initial_offset = if flags.append {
            inode.metadata()?.size
        } else {
            0
        };
        Ok(Self {
            inode,
            offset: AtomicU64::new(initial_offset),
            flags,
        })
    }

    /// 流式读（自动推进 offset）。
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, Error> {
        if !self.flags.read {
            return Err(Error::PermissionDenied);
        }
        let cur = self.offset.load(Ordering::SeqCst);
        let n = self.inode.read_at(cur, buf)?;
        self.offset.fetch_add(n as u64, Ordering::SeqCst);
        Ok(n)
    }

    /// 流式写（自动推进 offset）。
    ///
    /// ADR-023 §1：注入全局页缓存时经 [`PageCache::write_cached`] 写穿
    /// 并作废受影响缓存块（失效一致性策略的唯一合法写通道）；未注入时
    /// 直写 inode。
    pub fn write(&self, buf: &[u8]) -> Result<usize, Error> {
        if !self.flags.write {
            return Err(Error::PermissionDenied);
        }
        let cur = if self.flags.append {
            // S21：append 的"读 size + 写"非原子——两个并发 append 可能读到
            // 相同 size 相互覆盖，丢失 O_APPEND 追加原子性。成文假设：当前
            // 内核单 CPU、同一文件的并发 append 不存在（VFS 层无对同句柄的
            // 跨进程并发写语义）；未来引入多写者时须把 size 读取+写入纳入
            // 同一把 content 锁。
            let size = self.inode.metadata()?.size;
            self.offset.store(size, Ordering::SeqCst);
            size
        } else {
            self.offset.load(Ordering::SeqCst)
        };
        let n = self.write_coordinated(cur, buf)?;
        self.offset.fetch_add(n as u64, Ordering::SeqCst);
        Ok(n)
    }

    /// 无状态定位读（pread，不影响句柄内部 offset）。
    pub fn pread(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        if !self.flags.read {
            return Err(Error::PermissionDenied);
        }
        self.inode.read_at(offset, buf)
    }

    /// 无状态定位写（pwrite，不影响句柄内部 offset）。一致性语义同 [`Self::write`]。
    pub fn pwrite(&self, offset: u64, buf: &[u8]) -> Result<usize, Error> {
        if !self.flags.write {
            return Err(Error::PermissionDenied);
        }
        self.write_coordinated(offset, buf)
    }

    /// 经全局缓存（若注入）的协调写落点。
    fn write_coordinated(&self, offset: u64, buf: &[u8]) -> Result<usize, Error> {
        match crate::page_cache::global_page_cache() {
            Some(cache) => cache.write_cached(&self.inode, offset, buf),
            None => self.inode.write_at(offset, buf),
        }
    }

    /// 调整偏移量（Seek）。
    pub fn seek(&self, offset: i64, whence: SeekWhence) -> Result<u64, Error> {
        let meta = self.inode.metadata()?;
        let cur = self.offset.load(Ordering::SeqCst);
        let target = match whence {
            SeekWhence::Set => {
                if offset < 0 {
                    return Err(Error::OutOfRange);
                }
                offset as u64
            }
            SeekWhence::Current => {
                if offset < 0 {
                    // S19：`-offset` 在 offset==i64::MIN 时溢出 panic；
                    // unsigned_abs() 对全部负值安全。
                    let neg = offset.unsigned_abs();
                    cur.checked_sub(neg).ok_or(Error::OutOfRange)?
                } else {
                    cur.checked_add(offset as u64).ok_or(Error::OutOfRange)?
                }
            }
            SeekWhence::End => {
                if offset < 0 {
                    let neg = offset.unsigned_abs();
                    meta.size.checked_sub(neg).ok_or(Error::OutOfRange)?
                } else {
                    meta.size
                        .checked_add(offset as u64)
                        .ok_or(Error::OutOfRange)?
                }
            }
        };
        self.offset.store(target, Ordering::SeqCst);
        Ok(target)
    }

    /// 获取元数据。
    pub fn metadata(&self) -> Result<FileMetadata, Error> {
        self.inode.metadata()
    }
}

/// Seek 模式。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeekWhence {
    Set = 0,
    Current = 1,
    End = 2,
}
