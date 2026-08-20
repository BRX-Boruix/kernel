//! 动态只读/只写虚拟节点（基于生成器回调与写入处理器）。
//!
//! 用于 ProcFS、SysFS、DevFS 等特殊虚拟文件系统的轻量节点构造。

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use klib::error::Error;
use spin::RwLock;

use crate::inode::{DirEntry, FileMetadata, INode, INodeType, Permissions};

/// 动态内容生成器类型（返回生成的字节数据）。
pub type ContentGenerator = Box<dyn Fn() -> Vec<u8> + Send + Sync>;

/// 动态写入处理器类型（入参写入的字节切片，返回实际处理字节数）。
pub type WriteHandler = Box<dyn Fn(&[u8]) -> Result<usize, Error> + Send + Sync>;

/// 动态只读/控制虚拟文件节点。
pub struct DynamicFileNode {
    generator: Option<ContentGenerator>,
    writer: Option<WriteHandler>,
    perms: Permissions,
}

impl DynamicFileNode {
    /// 创建只读动态节点（每次读取调用 generator 生成实时内容）。
    pub fn read_only<F>(generator: F) -> Self
    where
        F: Fn() -> Vec<u8> + Send + Sync + 'static,
    {
        Self {
            generator: Some(Box::new(generator)),
            writer: None,
            perms: Permissions::readonly(),
        }
    }

    /// 创建读写动态节点（读取由 generator 动态生成，写入由 writer 处理）。
    pub fn read_write<F, W>(generator: F, writer: W) -> Self
    where
        F: Fn() -> Vec<u8> + Send + Sync + 'static,
        W: Fn(&[u8]) -> Result<usize, Error> + Send + Sync + 'static,
    {
        Self {
            generator: Some(Box::new(generator)),
            writer: Some(Box::new(writer)),
            perms: Permissions::read_write(),
        }
    }
}

impl INode for DynamicFileNode {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        let Some(ref func) = self.generator else {
            return Err(Error::PermissionDenied);
        };
        let content = func();
        let off = offset as usize;
        if off >= content.len() {
            return Ok(0);
        }
        let available = &content[off..];
        let copy_len = core::cmp::min(buf.len(), available.len());
        buf[..copy_len].copy_from_slice(&available[..copy_len]);
        Ok(copy_len)
    }

    fn write_at(&self, _offset: u64, buf: &[u8]) -> Result<usize, Error> {
        let Some(ref writer) = self.writer else {
            return Err(Error::PermissionDenied);
        };
        writer(buf)
    }

    fn metadata(&self) -> Result<FileMetadata, Error> {
        let size = self
            .generator
            .as_ref()
            .map(|func| func().len() as u64)
            .unwrap_or(0);
        Ok(FileMetadata {
            size,
            node_type: INodeType::RegularFile,
            permissions: self.perms,
            created_time: 0,
            modified_time: 0,
            changed_time: 0,
        })
    }

    fn truncate(&self, _size: u64) -> Result<(), Error> {
        Err(Error::PermissionDenied)
    }

    fn lookup(&self, _name: &str) -> Result<Arc<dyn INode>, Error> {
        Err(Error::NotDirectory)
    }

    fn create(&self, _name: &str, _permissions: Permissions) -> Result<Arc<dyn INode>, Error> {
        Err(Error::NotDirectory)
    }

    fn mkdir(&self, _name: &str, _permissions: Permissions) -> Result<Arc<dyn INode>, Error> {
        Err(Error::NotDirectory)
    }

    fn unlink(&self, _name: &str) -> Result<(), Error> {
        Err(Error::NotDirectory)
    }

    fn list_dir(&self) -> Result<Vec<DirEntry>, Error> {
        Err(Error::NotDirectory)
    }
}

/// 动态/静态混合虚拟目录节点。
pub struct DynamicDirNode {
    entries: RwLock<Vec<(alloc::string::String, Arc<dyn INode>)>>,
    perms: Permissions,
}

impl DynamicDirNode {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
            perms: Permissions::all(),
        }
    }

    pub fn add_child(&self, name: &str, node: Arc<dyn INode>) {
        let mut entries = self.entries.write();
        entries.retain(|(n, _)| n != name);
        entries.push((alloc::string::String::from(name), node));
    }
}

impl INode for DynamicDirNode {
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> Result<usize, Error> {
        Err(Error::IsDirectory)
    }

    fn write_at(&self, _offset: u64, _buf: &[u8]) -> Result<usize, Error> {
        Err(Error::IsDirectory)
    }

    fn metadata(&self) -> Result<FileMetadata, Error> {
        Ok(FileMetadata {
            size: self.entries.read().len() as u64,
            node_type: INodeType::Directory,
            permissions: self.perms,
            created_time: 0,
            modified_time: 0,
            changed_time: 0,
        })
    }

    fn truncate(&self, _size: u64) -> Result<(), Error> {
        Err(Error::IsDirectory)
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn INode>, Error> {
        let entries = self.entries.read();
        for (n, node) in entries.iter() {
            if n == name {
                return Ok(node.clone());
            }
        }
        Err(Error::NotFound)
    }

    fn create(&self, _name: &str, _permissions: Permissions) -> Result<Arc<dyn INode>, Error> {
        Err(Error::PermissionDenied)
    }

    fn mkdir(&self, _name: &str, _permissions: Permissions) -> Result<Arc<dyn INode>, Error> {
        Err(Error::PermissionDenied)
    }

    fn unlink(&self, _name: &str) -> Result<(), Error> {
        Err(Error::PermissionDenied)
    }

    fn list_dir(&self) -> Result<Vec<DirEntry>, Error> {
        let entries = self.entries.read();
        let mut list = Vec::with_capacity(entries.len());
        for (name, node) in entries.iter() {
            let meta = node.metadata()?;
            list.push(DirEntry {
                name: name.clone(),
                node_type: meta.node_type,
                size: meta.size,
            });
        }
        Ok(list)
    }
}
