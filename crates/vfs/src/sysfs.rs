//! SysFS 系统信息虚拟文件系统（挂载于 `/system`）。
//!
//! 遵循 ADR-005（RESTful 资源观）与 ADR-013（JSON 第一公民）：
//! - `/system/cpu`：CPU 架构、核心数、频率及特性列表 JSON；
//! - `/system/memory`：LazyBuddy 内存容量、已分配、空闲及紧急预留池状态 JSON；
//! - `/system/kernel`：内核版本、启动时间及构建元数据 JSON。

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use klib::error::Error;
use klib::json::{JsonObject, JsonWriter, VecTarget};

use crate::dynamic::{DynamicDirNode, DynamicFileNode};
use crate::inode::{DirEntry, FileMetadata, FileSystem, INode, INodeType, Permissions};

/// 系统信息 Provider Trait（由内核注入硬件与内存状态）。
pub trait SystemInfoProvider: Send + Sync {
    fn cpu_json(&self) -> String;
    fn memory_json(&self) -> String;
    fn kernel_json(&self) -> String;
}

/// SysFS 文件系统实现。
pub struct SysFS {
    root: Arc<DynamicDirNode>,
}

impl SysFS {
    pub fn new(provider: Arc<dyn SystemInfoProvider>) -> Self {
        let root = Arc::new(DynamicDirNode::new());

        let p1 = provider.clone();
        let cpu_node = Arc::new(DynamicFileNode::read_only(move || {
            let mut s = p1.cpu_json();
            if !s.ends_with('\n') {
                s.push('\n');
            }
            s.into_bytes()
        }));
        root.add_child("cpu", cpu_node);

        let p2 = provider.clone();
        let mem_node = Arc::new(DynamicFileNode::read_only(move || {
            let mut s = p2.memory_json();
            if !s.ends_with('\n') {
                s.push('\n');
            }
            s.into_bytes()
        }));
        root.add_child("memory", mem_node);

        let p3 = provider.clone();
        let kernel_node = Arc::new(DynamicFileNode::read_only(move || {
            let mut s = p3.kernel_json();
            if !s.ends_with('\n') {
                s.push('\n');
            }
            s.into_bytes()
        }));
        root.add_child("kernel", kernel_node);

        Self { root }
    }
}

impl FileSystem for SysFS {
    fn root(&self) -> Arc<dyn INode> {
        self.root.clone()
    }

    fn name(&self) -> &'static str {
        "sysfs"
    }
}
