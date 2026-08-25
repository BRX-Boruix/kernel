//! 全局挂载路由表与路径解析器（ADR-011 / ADR-012 / ADR-023 §2-§3）。
//!
//! ## 入口契约（vfs1 R5/M1/A6/A7，S21 锁序标注）
//!
//! - 只接受**绝对路径**；相对路径显式 [`Error::InvalidParam`]，绝不静默
//!   当作绝对路径解析（ADR-023 §2）；
//! - 变更类操作（create/mkdir/symlink/unlink）对末段名字统一执行
//!   [`validate_name`]：拒绝空名、内嵌 `/`、C0 控制字符与 DEL——名字是
//!   JSON/日志的第一公民注入面（POSIX 名字域 = 除 `/` 与 NUL 外任意字节，
//!   本表取其严格子集并成文；U+202E 等可打印 Unicode 不在拒绝之列，
//!   欺骗风险由展示层转义承担）；
//! - mount 目标必须已存在且为目录（A6）；unlink 目标是活动挂载点或其
//!   祖先目录时拒绝（A7，`Busy`），杜绝幽灵挂载复活；
//! - 锁序（S21）：本表仅一把 `mounts` RwLock。resolve 在逐组件循环内取
///   read 短临界区后立即释放再做 lookup（lookup 可能进入各 fs 内部锁），
///   故锁序恒为 `mounts → fs 内部锁`，无反向获取点，无死锁环。

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

/// 校验路径末段文件名（ADR-023 §2）：非空、不含 `/`、不含 C0 控制字符与 DEL。
fn validate_name(name: &str) -> Result<(), Error> {
    if name.is_empty() {
        return Err(Error::InvalidParam);
    }
    for &b in name.as_bytes() {
        if b == b'/' || b <= 0x1F || b == 0x7F {
            return Err(Error::InvalidParam);
        }
    }
    Ok(())
}

/// 全局挂载表。
pub struct MountTable {
    root_fs: Arc<dyn FileSystem>,
    mounts: RwLock<BTreeMap<String, Arc<dyn FileSystem>>>,
}

/// 手写 Debug（D5 / ADR-023 §7）：安全摘要，不遍历内部数据。
impl core::fmt::Debug for MountTable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MountTable")
            .field("root_fs", &self.root_fs.name())
            .field("mount_count", &self.mounts.read().len())
            .finish()
    }
}

impl MountTable {
    pub fn new(root_fs: Arc<dyn FileSystem>) -> Self {
        Self {
            root_fs,
            mounts: RwLock::new(BTreeMap::new()),
        }
    }

    /// 在指定规范化绝对路径挂载文件系统。
    ///
    /// A6：目标必须先可解析且为目录——否则挂载项插入成功却永久不可达
    /// （父链不存在），或遮蔽一个普通文件。校验在读锁下完成后再取写锁
    /// 插入（单线程启动期 + 写锁内 contains_key 复查，TOCTOU 面为零）。
    pub fn mount(&self, target_path: &str, fs: Arc<dyn FileSystem>) -> Result<(), Error> {
        let norm = Path::canonicalize(target_path);
        if norm == "/" {
            return Err(Error::AlreadyExists);
        }
        let target = self.resolve(&norm, true)?;
        if target.node_type() != INodeType::Directory {
            return Err(Error::NotDirectory);
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

            // 检查当前路径是否为挂载点（读锁短临界区，随取随放）
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

            // A5（ADR-023 §4）：廉价类型查询判定软链接——绝不在此触发
            // 动态内容全量生成（metadata 对 DynamicFileNode 意味着执行
            // generator，历史上让每次路径解析付出 O(内容生成) 代价）。
            if next_node.node_type() == INodeType::Symlink {
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

    /// 规范化绝对路径并拆出 (父路径, 末段名字)；相对路径显式拒绝（M1）。
    fn split_entry(path_str: &str) -> Result<(String, String), Error> {
        if !path_str.starts_with('/') {
            return Err(Error::InvalidParam);
        }
        let canon = Path::canonicalize(path_str);
        split_parent(&canon)
    }

    /// 在指定路径创建普通文件（如果不存在）。
    pub fn create_file(&self, path_str: &str, perm: Permissions) -> Result<Arc<dyn INode>, Error> {
        let (parent_path, file_name) = Self::split_entry(path_str)?;
        validate_name(&file_name)?;
        let parent_node = self.resolve(&parent_path, true)?;
        parent_node.create(&file_name, perm)
    }

    /// 在指定路径创建目录。
    pub fn mkdir(&self, path_str: &str, perm: Permissions) -> Result<Arc<dyn INode>, Error> {
        let (parent_path, dir_name) = Self::split_entry(path_str)?;
        validate_name(&dir_name)?;
        let parent_node = self.resolve(&parent_path, true)?;
        parent_node.mkdir(&dir_name, perm)
    }

    /// 删除指定路径的节点。
    ///
    /// A7：目标路径若是活动挂载点本身，或位于某个活动挂载点之下（即某
    /// 挂载键以 `目标/` 为前缀），必须先 unmount——否则注册表里留下永远
    /// 不可达的孤儿挂载，且重建同名目录后旧挂载原地复活。
    pub fn unlink(&self, path_str: &str) -> Result<(), Error> {
        let (parent_path, name) = Self::split_entry(path_str)?;
        validate_name(&name)?;
        let canon = Path::canonicalize(path_str);
        {
            let mounts = self.mounts.read();
            if mounts.contains_key(&canon)
                || mounts.keys().any(|k| k.len() > canon.len() && k.starts_with(&canon) && k.as_bytes()[canon.len()] == b'/')
            {
                return Err(Error::Busy);
            }
        }
        let parent_node = self.resolve(&parent_path, true)?;
        parent_node.unlink(&name)
    }

    /// 创建软链接。
    pub fn symlink(&self, target: &str, link_path: &str) -> Result<Arc<dyn INode>, Error> {
        let (parent_path, name) = Self::split_entry(link_path)?;
        validate_name(&name)?;
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
