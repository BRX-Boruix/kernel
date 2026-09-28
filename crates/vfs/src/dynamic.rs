//! 动态只读/只写虚拟节点（基于生成器回调与写入处理器）。
//!
//! 用于 ProcFS、SysFS、DevFS 等特殊虚拟文件系统的轻量节点构造。

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use klib::error::Error;
use spin::RwLock;

use crate::inode::{AccessPolicy, DirEntry, FileMetadata, INode, INodeType};

/// 动态内容生成器类型（返回生成的字节数据）。
pub type ContentGenerator = Box<dyn Fn() -> Vec<u8> + Send + Sync>;

/// 动态写入处理器类型（入参写入的字节切片，返回实际处理字节数）。
pub type WriteHandler = Box<dyn Fn(&[u8]) -> Result<usize, Error> + Send + Sync>;

/// 动态只读/控制虚拟文件节点。
pub struct DynamicFileNode {
    generator: Option<ContentGenerator>,
    writer: Option<WriteHandler>,
    perms: AccessPolicy,
    // 快照一致性缓存（B3 阻塞缺陷修复，2026-09-28 晚）：read_at(offset==0)
    // 重生成并替换；offset>0 的续读复用同一快照。此前每次 read_at 都
    // 重新调用 generator——/processes/list 这类实时内容在 512B 分块
    // 续读中途进程表变化，第二块与第一块来自不同快照，拼接后 JSON
    // 撕裂（init 看门狗把活着的 consoled 误判死亡，respawn 风暴；
    // S13：同一 open-read-close 事务必须看到同一份内容）。并发边界
    // （S09 如实）：两读者同时流式读同一节点时，后到者的 offset==0
    // 刷新会让先到者的续读换快照——当前读者均为短事务，交错窗口可忽略。
    snapshot: RwLock<Option<Arc<Vec<u8>>>>,
}

/// 手写 Debug（D5 / ADR-023 §7）：安全摘要，不调用生成器/写入器。
impl core::fmt::Debug for DynamicFileNode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DynamicFileNode")
            .field("has_generator", &self.generator.is_some())
            .field("has_writer", &self.writer.is_some())
            .field("perms", &self.perms)
            .finish()
    }
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
            perms: AccessPolicy::readonly(),
            snapshot: RwLock::new(None),
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
            perms: AccessPolicy::read_write(),
            snapshot: RwLock::new(None),
        }
    }
}

impl INode for DynamicFileNode {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        let Some(ref func) = self.generator else {
            return Err(Error::PermissionDenied);
        };
        // 快照一致性（B3 阻塞缺陷修复）：offset==0 = 新一轮读（或重读）
        // → 重生成并替换快照；offset>0 = 续读 → 复用快照，保证同一
        // open-read-close 事务内内容单一真值（S13）。
        let content: Arc<Vec<u8>> = if offset == 0 {
            let fresh = Arc::new(func());
            *self.snapshot.write() = Some(fresh.clone());
            fresh
        } else {
            match self.snapshot.read().clone() {
                Some(snap) => snap,
                None => {
                    // 首读即 offset>0（罕见：调用方自行 seek）：生成一次补缓存。
                    let fresh = Arc::new(func());
                    *self.snapshot.write() = Some(fresh.clone());
                    fresh
                }
            }
        };
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
            permissions: self.perms.clone(),
            created_time: 0,
            modified_time: 0,
            changed_time: 0,
        })
    }

    fn truncate(&self, _size: u64) -> Result<(), Error> {
        Err(Error::PermissionDenied)
    }

    /// A5：文件判型零成本——**绝不调用 generator**（metadata 的 size 字段
    /// 才需要生成；类型判定进热路径，历史实现曾因此每次 resolve 全量
    /// 生成动态内容后丢弃）。
    fn node_type(&self) -> Result<INodeType, Error> {
        Ok(INodeType::RegularFile)
    }

    fn lookup(&self, _name: &str) -> Result<Arc<dyn INode>, Error> {
        Err(Error::NotDirectory)
    }

    fn create(&self, _name: &str, _mode: u32, _owner: (u32, u32)) -> Result<Arc<dyn INode>, Error> {
        Err(Error::NotDirectory)
    }

    fn mkdir(&self, _name: &str, _mode: u32, _owner: (u32, u32)) -> Result<Arc<dyn INode>, Error> {
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
    perms: AccessPolicy,
}

/// 手写 Debug（D5 / ADR-023 §7）：安全摘要，不枚举目录项内容。
impl core::fmt::Debug for DynamicDirNode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DynamicDirNode")
            .field("entry_count", &self.entries.read().len())
            .field("perms", &self.perms)
            .finish()
    }
}

impl DynamicDirNode {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
            perms: AccessPolicy::all(),
        }
    }

    pub fn add_child(&self, name: &str, node: Arc<dyn INode>) {
        // M13 成文（ADR-023 §6）：upsert 语义——同名子项被静默替换。这是
        // 有意行为而非疏漏：DevFS/ProcFS 等投影重建路径依赖"以新换旧"
        // 而不必先手工摘除。调用方若需排他创建，先 lookup 自查。
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
            permissions: self.perms.clone(),
            created_time: 0,
            modified_time: 0,
            changed_time: 0,
        })
    }

    /// A5：目录判型零成本（entries 长度都不必读）。
    fn node_type(&self) -> Result<INodeType, Error> {
        Ok(INodeType::Directory)
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

    fn create(&self, _name: &str, _mode: u32, _owner: (u32, u32)) -> Result<Arc<dyn INode>, Error> {
        Err(Error::PermissionDenied)
    }

    fn mkdir(&self, _name: &str, _mode: u32, _owner: (u32, u32)) -> Result<Arc<dyn INode>, Error> {
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
