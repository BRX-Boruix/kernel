//! 全局挂载路由表与路径解析器（ADR-011 / ADR-012）。

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use klib::error::Error;
use spin::RwLock;

use crate::inode::{FileSystem, INode, INodeType, Permissions};
use crate::path::Path;

/// 最大符号链接跳转深度（防死循环）。
pub const MAX_SYMLINK_DEPTH: usize = 64;

/// 全局挂载表。
pub struct MountTable {
    root_fs: Arc<dyn FileSystem>,
    mounts: RwLock<BTreeMap<String, Arc<dyn FileSystem>>>,
}

impl MountTable {
    pub fn new(root_fs: Arc<dyn FileSystem>) -> Self {
        Self {
            root_fs,
            mounts: RwLock::new(BTreeMap::new()),
        }
    }

    /// 在指定规范化绝对路径挂载文件系统。
    pub fn mount(&self, target_path: &str, fs: Arc<dyn FileSystem>) -> Result<(), Error> {
        let norm = Path::canonicalize(target_path);
        if norm == "/" {
            return Err(Error::AlreadyExists);
        }
        let mut mounts = self.mounts.write();
        if mounts.contains_key(&norm) {
            return Err(Error::AlreadyExists);
        }
        mounts.insert(norm, fs);
        Ok(())
    }

    /// 卸载挂载点。
    pub fn unmount(&self, target_path: &str) -> Result<(), Error> {
        let norm = Path::canonicalize(target_path);
        let mut mounts = self.mounts.write();
        if mounts.remove(&norm).is_some() {
            Ok(())
        } else {
            Err(Error::NotFound)
        }
    }

    /// 核心路径解析：从根开始逐级解析路径并处理挂载点与软链接。
    pub fn resolve(&self, path_str: &str, follow_symlink: bool) -> Result<Arc<dyn INode>, Error> {
        self.resolve_internal(path_str, follow_symlink, 0)
    }

    fn resolve_internal(
        &self,
        path_str: &str,
        follow_symlink: bool,
        depth: usize,
    ) -> Result<Arc<dyn INode>, Error> {
        if depth > MAX_SYMLINK_DEPTH {
            return Err(Error::TooManySymlinks);
        }

        let canon = Path::canonicalize(path_str);
        if canon == "/" {
            return Ok(self.root_fs.root());
        }

        // 检查是否有精确前缀挂载匹配
        let mut cur_node = self.root_fs.root();
        let mut cur_path = String::new();

        let comps: Vec<&str> = Path::new(&canon).components().collect();
        let total = comps.len();

        for (i, comp) in comps.iter().enumerate() {
            cur_path.push('/');
            cur_path.push_str(comp);

            // 检查当前路径是否为挂载点
            let mounted_fs = {
                let mounts = self.mounts.read();
                mounts.get(&cur_path).cloned()
            };

            if let Some(fs) = mounted_fs {
                cur_node = fs.root();
                continue;
            }

            // 正常 lookup
            let next_node = cur_node.lookup(comp)?;
            let is_last = i == total - 1;

            if next_node.metadata()?.node_type == INodeType::Symlink {
                if !is_last || follow_symlink {
                    let link_target = next_node.read_link()?;
                    // 如果是绝对路径，从根重算；否则拼接
                    let target_full = if link_target.starts_with('/') {
                        link_target
                    } else {
                        // 相对链接：拼接上级目录
                        let mut parent_path = String::new();
                        for p in &comps[..i] {
                            parent_path.push('/');
                            parent_path.push_str(p);
                        }
                        if parent_path.is_empty() {
                            parent_path.push('/');
                        }
                        Path::canonicalize(&alloc::format!("{}/{}", parent_path, link_target))
                    };

                    // 链接剩余尾部路径
                    let full_reconstructed = if is_last {
                        target_full
                    } else {
                        let mut rem = target_full;
                        for rem_comp in &comps[i + 1..] {
                            rem.push('/');
                            rem.push_str(rem_comp);
                        }
                        rem
                    };

                    return self.resolve_internal(&full_reconstructed, follow_symlink, depth + 1);
                }
            }

            cur_node = next_node;
        }

        Ok(cur_node)
    }

    /// 在指定路径创建普通文件（如果不存在）。
    pub fn create_file(&self, path_str: &str, perm: Permissions) -> Result<Arc<dyn INode>, Error> {
        let canon = Path::canonicalize(path_str);
        let (parent_path, file_name) = split_parent(&canon)?;
        let parent_node = self.resolve(&parent_path, true)?;
        parent_node.create(&file_name, perm)
    }

    /// 在指定路径创建目录。
    pub fn mkdir(&self, path_str: &str, perm: Permissions) -> Result<Arc<dyn INode>, Error> {
        let canon = Path::canonicalize(path_str);
        let (parent_path, dir_name) = split_parent(&canon)?;
        let parent_node = self.resolve(&parent_path, true)?;
        parent_node.mkdir(&dir_name, perm)
    }

    /// 删除指定路径的节点。
    pub fn unlink(&self, path_str: &str) -> Result<(), Error> {
        let canon = Path::canonicalize(path_str);
        if canon == "/" {
            return Err(Error::PermissionDenied);
        }
        let (parent_path, name) = split_parent(&canon)?;
        let parent_node = self.resolve(&parent_path, true)?;
        parent_node.unlink(&name)
    }

    /// 创建软链接。
    pub fn symlink(&self, target: &str, link_path: &str) -> Result<Arc<dyn INode>, Error> {
        let canon = Path::canonicalize(link_path);
        let (parent_path, name) = split_parent(&canon)?;
        let parent_node = self.resolve(&parent_path, true)?;
        parent_node.symlink(&name, target)
    }
}

fn split_parent(path_str: &str) -> Result<(String, String), Error> {
    if path_str == "/" || path_str.is_empty() {
        return Err(Error::InvalidParam);
    }
    let pos = path_str.rfind('/').unwrap_or(0);
    let parent = if pos == 0 {
        String::from("/")
    } else {
        path_str[..pos].to_string()
    };
    let name = path_str[pos + 1..].to_string();
    if name.is_empty() {
        return Err(Error::InvalidParam);
    }
    Ok((parent, name))
}
