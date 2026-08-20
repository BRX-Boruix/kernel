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

    pub const fn to_bits(self) -> u32 {
        let mut bits = 0;
        if self.read { bits |= 1 << 0; }
        if self.write { bits |= 1 << 1; }
        if self.create { bits |= 1 << 2; }
        if self.truncate { bits |= 1 << 3; }
        if self.append { bits |= 1 << 4; }
        if self.directory { bits |= 1 << 5; }
        bits
    }

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
    pub fn new(inode: Arc<dyn INode>, flags: OpenFlags) -> Self {
        let initial_offset = if flags.append {
            inode.metadata().map(|m| m.size).unwrap_or(0)
        } else {
            0
        };
        Self {
            inode,
            offset: AtomicU64::new(initial_offset),
            flags,
        }
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
    pub fn write(&self, buf: &[u8]) -> Result<usize, Error> {
        if !self.flags.write {
            return Err(Error::PermissionDenied);
        }
        let cur = if self.flags.append {
            let size = self.inode.metadata()?.size;
            self.offset.store(size, Ordering::SeqCst);
            size
        } else {
            self.offset.load(Ordering::SeqCst)
        };
        let n = self.inode.write_at(cur, buf)?;
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

    /// 无状态定位写（pwrite，不影响句柄内部 offset）。
    pub fn pwrite(&self, offset: u64, buf: &[u8]) -> Result<usize, Error> {
        if !self.flags.write {
            return Err(Error::PermissionDenied);
        }
        self.inode.write_at(offset, buf)
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
                    let neg = (-offset) as u64;
                    cur.checked_sub(neg).ok_or(Error::OutOfRange)?
                } else {
                    cur.checked_add(offset as u64).ok_or(Error::OutOfRange)?
                }
            }
            SeekWhence::End => {
                if offset < 0 {
                    let neg = (-offset) as u64;
                    meta.size.checked_sub(neg).ok_or(Error::OutOfRange)?
                } else {
                    meta.size.checked_add(offset as u64).ok_or(Error::OutOfRange)?
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
