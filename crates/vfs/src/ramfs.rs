//! 纯内存通用文件系统（RamFS）。

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use klib::error::Error;
use spin::RwLock;

use crate::inode::{DirEntry, FileMetadata, FileSystem, INode, INodeType, Permissions};

/// RamFS 内部节点数据。
enum RamNodeData {
    File {
        content: RwLock<Vec<u8>>,
    },
    Directory {
        children: RwLock<BTreeMap<String, Arc<RamINode>>>,
    },
    Symlink {
        target: String,
    },
}

/// RamFS 节点实现。
pub struct RamINode {
    meta: RwLock<FileMetadata>,
    data: RamNodeData,
}

impl RamINode {
    pub fn new_file(perm: Permissions) -> Arc<Self> {
        Arc::new(Self {
            meta: RwLock::new(FileMetadata {
                node_type: INodeType::RegularFile,
                size: 0,
                permissions: perm,
                created_time: 0,
                modified_time: 0,
                changed_time: 0,
            }),
            data: RamNodeData::File {
                content: RwLock::new(Vec::new()),
            },
        })
    }

    pub fn new_dir(perm: Permissions) -> Arc<Self> {
        Arc::new(Self {
            meta: RwLock::new(FileMetadata {
                node_type: INodeType::Directory,
                size: 0,
                permissions: perm,
                created_time: 0,
                modified_time: 0,
                changed_time: 0,
            }),
            data: RamNodeData::Directory {
                children: RwLock::new(BTreeMap::new()),
            },
        })
    }

    pub fn new_symlink(target: &str) -> Arc<Self> {
        Arc::new(Self {
            meta: RwLock::new(FileMetadata {
                node_type: INodeType::Symlink,
                size: target.len() as u64,
                permissions: Permissions::all(),
                created_time: 0,
                modified_time: 0,
                changed_time: 0,
            }),
            data: RamNodeData::Symlink {
                target: target.to_string(),
            },
        })
    }
}

impl INode for RamINode {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        match &self.data {
            RamNodeData::File { content } => {
                let c = content.read();
                let len = c.len() as u64;
                if offset >= len {
                    return Ok(0);
                }
                let available = (len - offset) as usize;
                let to_read = buf.len().min(available);
                let start = offset as usize;
                buf[..to_read].copy_from_slice(&c[start..start + to_read]);
                Ok(to_read)
            }
            _ => Err(Error::IsDirectory),
        }
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<usize, Error> {
        match &self.data {
            RamNodeData::File { content } => {
                let mut c = content.write();
                let end = (offset as usize).checked_add(buf.len()).ok_or(Error::OutOfRange)?;
                if end > c.len() {
                    c.resize(end, 0);
                }
                let start = offset as usize;
                c[start..end].copy_from_slice(buf);
                let new_size = c.len() as u64;
                drop(c);

                let mut meta = self.meta.write();
                meta.size = new_size;
                Ok(buf.len())
            }
            _ => Err(Error::IsDirectory),
        }
    }

    fn metadata(&self) -> Result<FileMetadata, Error> {
        Ok(self.meta.read().clone())
    }

    fn truncate(&self, size: u64) -> Result<(), Error> {
        match &self.data {
            RamNodeData::File { content } => {
                let mut c = content.write();
                c.resize(size as usize, 0);
                drop(c);
                let mut meta = self.meta.write();
                meta.size = size;
                Ok(())
            }
            _ => Err(Error::IsDirectory),
        }
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn INode>, Error> {
        match &self.data {
            RamNodeData::Directory { children } => {
                let c = children.read();
                c.get(name)
                    .cloned()
                    .map(|n| n as Arc<dyn INode>)
                    .ok_or(Error::NotFound)
            }
            _ => Err(Error::NotDirectory),
        }
    }

    fn create(&self, name: &str, perm: Permissions) -> Result<Arc<dyn INode>, Error> {
        match &self.data {
            RamNodeData::Directory { children } => {
                let mut c = children.write();
                if c.contains_key(name) {
                    return Err(Error::AlreadyExists);
                }
                let file = RamINode::new_file(perm);
                c.insert(name.to_string(), file.clone());
                Ok(file)
            }
            _ => Err(Error::NotDirectory),
        }
    }

    fn mkdir(&self, name: &str, perm: Permissions) -> Result<Arc<dyn INode>, Error> {
        match &self.data {
            RamNodeData::Directory { children } => {
                let mut c = children.write();
                if c.contains_key(name) {
                    return Err(Error::AlreadyExists);
                }
                let dir = RamINode::new_dir(perm);
                c.insert(name.to_string(), dir.clone());
                Ok(dir)
            }
            _ => Err(Error::NotDirectory),
        }
    }

    fn unlink(&self, name: &str) -> Result<(), Error> {
        match &self.data {
            RamNodeData::Directory { children } => {
                let mut c = children.write();
                if let Some(child) = c.get(name) {
                    if let RamNodeData::Directory { children: sub_c } = &child.data {
                        if !sub_c.read().is_empty() {
                            return Err(Error::NotEmpty);
                        }
                    }
                    c.remove(name);
                    Ok(())
                } else {
                    Err(Error::NotFound)
                }
            }
            _ => Err(Error::NotDirectory),
        }
    }

    fn list_dir(&self) -> Result<Vec<DirEntry>, Error> {
        match &self.data {
            RamNodeData::Directory { children } => {
                let c = children.read();
                let mut list = Vec::new();
                for (name, node) in c.iter() {
                    let meta = node.metadata()?;
                    list.push(DirEntry {
                        name: name.clone(),
                        node_type: meta.node_type,
                        size: meta.size,
                    });
                }
                Ok(list)
            }
            _ => Err(Error::NotDirectory),
        }
    }

    fn read_link(&self) -> Result<String, Error> {
        match &self.data {
            RamNodeData::Symlink { target } => Ok(target.clone()),
            _ => Err(Error::NotSupported),
        }
    }

    fn symlink(&self, name: &str, target: &str) -> Result<Arc<dyn INode>, Error> {
        match &self.data {
            RamNodeData::Directory { children } => {
                let mut c = children.write();
                if c.contains_key(name) {
                    return Err(Error::AlreadyExists);
                }
                let link = RamINode::new_symlink(target);
                c.insert(name.to_string(), link.clone());
                Ok(link)
            }
            _ => Err(Error::NotDirectory),
        }
    }
}

/// 内存文件系统实例。
pub struct RamFS {
    root: Arc<RamINode>,
}

impl RamFS {
    pub fn new() -> Self {
        Self {
            root: RamINode::new_dir(Permissions::all()),
        }
    }
}

impl FileSystem for RamFS {
    fn root(&self) -> Arc<dyn INode> {
        self.root.clone()
    }

    fn name(&self) -> &'static str {
        "ramfs"
    }
}
