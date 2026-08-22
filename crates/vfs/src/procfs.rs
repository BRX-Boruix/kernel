//! ProcFS 进程虚拟文件系统（挂载于 `/processes`）。
//!
//! 遵循 ADR-005（RESTful 资源观）与 ADR-013（JSON 第一公民）：
//! - `/processes/list`：输出所有存活进程的 JSON 数组（`[{"pid":1,"name":"init","state":"Running",...}]`）；
//! - `/processes/{pid}/status`：输出单个进程详细状态 JSON。

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use klib::error::Error;
use klib::json::{JsonObject, JsonWriter, VecTarget};

use crate::dynamic::{DynamicDirNode, DynamicFileNode};
use crate::inode::{DirEntry, FileMetadata, FileSystem, INode, INodeType, Permissions};

/// 进程状态快照信息结构体。
#[derive(Clone, Debug)]
pub struct ProcessSnapshot {
    pub pid: usize,
    pub name: String,
    pub state: String,
    /// 已声明用户虚拟区域的字节数；来自地址空间区域账本，包含尚未 fault-in 的预留页。
    pub memory_bytes: u64,
}

/// 进程查询回调 Provider Trait（由内核 process / scheduler 注入实现）。
pub trait ProcessInfoProvider: Send + Sync {
    fn list_processes(&self) -> Vec<ProcessSnapshot>;
    fn get_process(&self, pid: usize) -> Option<ProcessSnapshot>;
}

/// ProcFS 根目录节点。
pub struct ProcRootNode {
    provider: Arc<dyn ProcessInfoProvider>,
    perms: Permissions,
}

impl ProcRootNode {
    pub fn new(provider: Arc<dyn ProcessInfoProvider>) -> Self {
        Self {
            provider,
            perms: Permissions::all(),
        }
    }
}

impl INode for ProcRootNode {
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> Result<usize, Error> {
        Err(Error::IsDirectory)
    }

    fn write_at(&self, _offset: u64, _buf: &[u8]) -> Result<usize, Error> {
        Err(Error::IsDirectory)
    }

    fn metadata(&self) -> Result<FileMetadata, Error> {
        Ok(FileMetadata {
            size: 0,
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
        if name == "list" {
            let p = self.provider.clone();
            let node = DynamicFileNode::read_only(move || {
                let procs = p.list_processes();
                let mut target = VecTarget::new();
                let mut writer = JsonWriter::new(&mut target);
                if let Ok(mut arr) = writer.start_array() {
                    for proc in procs {
                        let _ = arr.push_object(|obj| {
                            let _ = obj.field_u64("pid", proc.pid as u64);
                            let _ = obj.field_str("name", &proc.name);
                            let _ = obj.field_str("state", &proc.state);
                            let _ = obj.field_u64("memory_bytes", proc.memory_bytes);
                            let _ = obj.field_str(
                                "uri",
                                &alloc::format!("/processes/{}/status", proc.pid),
                            );
                            Ok(())
                        });
                    }
                    let _ = arr.end();
                }
                let mut bytes = target.into_bytes();
                bytes.push(b'\n');
                bytes
            });
            return Ok(Arc::new(node));
        }

        // 解析 PID 目录
        if let Ok(pid) = name.parse::<usize>() {
            if let Some(_) = self.provider.get_process(pid) {
                let p = self.provider.clone();
                let dir = DynamicDirNode::new();
                let status_node = DynamicFileNode::read_only(move || {
                    let mut target = VecTarget::new();
                    let mut writer = JsonWriter::new(&mut target);
                    if let Some(proc) = p.get_process(pid) {
                        if let Ok(mut obj) = writer.start_object() {
                            let _ = obj.field_u64("pid", proc.pid as u64);
                            let _ = obj.field_str("name", &proc.name);
                            let _ = obj.field_str("state", &proc.state);
                            let _ = obj.field_u64("memory_bytes", proc.memory_bytes);
                            let _ = obj.field_str(
                                "uri",
                                &alloc::format!("/processes/{}/status", proc.pid),
                            );
                            let _ = obj.end();
                        }
                    }
                    let mut bytes = target.into_bytes();
                    bytes.push(b'\n');
                    bytes
                });
                dir.add_child("status", Arc::new(status_node));
                return Ok(Arc::new(dir));
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
        let mut list = Vec::new();
        list.push(DirEntry {
            name: String::from("list"),
            node_type: INodeType::RegularFile,
            size: 0,
        });
        for proc in self.provider.list_processes() {
            list.push(DirEntry {
                name: proc.pid.to_string(),
                node_type: INodeType::Directory,
                size: 0,
            });
        }
        Ok(list)
    }
}

/// ProcFS 文件系统实例。
pub struct ProcFS {
    root: Arc<ProcRootNode>,
}

impl ProcFS {
    pub fn new(provider: Arc<dyn ProcessInfoProvider>) -> Self {
        Self {
            root: Arc::new(ProcRootNode::new(provider)),
        }
    }
}

impl FileSystem for ProcFS {
    fn root(&self) -> Arc<dyn INode> {
        self.root.clone()
    }

    fn name(&self) -> &'static str {
        "procfs"
    }
}
