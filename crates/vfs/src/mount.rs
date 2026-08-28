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
use core::sync::atomic::{AtomicUsize, Ordering};
use klib::error::Error;
use spin::RwLock;

use crate::inode::{FileSystem, INode, INodeType, Permissions};
use crate::path::Path;

/// 最大符号链接跳转深度（防死循环）。
pub const MAX_SYMLINK_DEPTH: usize = 64;

/// 未命名卷自动降级的短标识序号源（ADR-012 §3.2.2）：无硬件提示时生成
/// 确定性 `storage-{seq}`，seq 单调递增，结合同名自增消解保证唯一。
static UNNAMED_SEQ: AtomicUsize = AtomicUsize::new(1);

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

/// M1 绝对路径契约（ADR-027 §3 第 26 条 / vfs1 R5）：公共操作只接受绝对路径。
///
/// 相对路径（不以 `/` 开头）显式 [`Error::InvalidParam`]，绝不静默当作绝对路径
/// 解析——`canonicalize` 对相对输入会保留前导 `..`（`"../x"` 保持 `"../x"`），
/// 若被当绝对路径解析会伪造位置。`create_file/mkdir/unlink/symlink` 经
/// `split_entry` 已拒绝相对路径；此处统一 `mount/unmount/resolve` 的入口，
/// 使全表公共操作绝对路径契约一致（与模块头声称相符）。
fn require_absolute(path_str: &str) -> Result<(), Error> {
    if path_str.starts_with('/') {
        Ok(())
    } else {
        Err(Error::InvalidParam)
    }
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
        require_absolute(target_path)?;
        let norm = Path::canonicalize(target_path);
        if norm == "/" {
            return Err(Error::AlreadyExists);
        }
        let target = self.resolve(&norm, true)?;
        if target.node_type()? != INodeType::Directory {
            return Err(Error::NotDirectory);
        }
        let mut mounts = self.mounts.write();
        if mounts.contains_key(&norm) {
            return Err(Error::AlreadyExists);
        }
        mounts.insert(norm, fs);
        Ok(())
    }

    /// 按卷名挂载文件系统到 `/volumes/{name}`，同名卷自动自增后缀（ADR-012 §3.2.1）。
    ///
    /// 卷重名消解语义：首个挂载为 `/volumes/{name}`；若该路径已是**活动挂载点**
    /// （已被某个同名卷占用），依次尝试 `/volumes/{name}-2`、`{name}-3`……直到
    /// 找到空闲目标，挂载后返回最终绝对路径。挂载目标目录不存在时先创建。
    ///
    /// ## 冲突判定（S21 锁序 + TOCTOU 审计）
    ///
    /// 占用判定的标准是 `mounts` 表中是否已有该路径键（卷挂载后即在表中登记），
    /// 而非 `/volumes` 下普通目录是否存在——`/volumes` 是卷专用命名空间，每个
    /// 子项都应是挂载点；同名冲突 = 目标键已被占。
    ///
    /// 锁序（S21）：本方法**不**持 `mounts` 写锁调用 `mkdir`/`resolve`——那会
    /// 在持写锁时取读锁（自锁死，spin RwLock 不可重入）。目录创建在占位检查
    /// 之外完成；写锁内只做 `contains_key` 复查与插入（与 [`Self::mount`] 的
    /// 既有 TOCTOU 界面一致）。极端并发下若目标在检查后被抢先挂载，
    /// `Self::mount` 因写锁内 `contains_key` 复查返回 `AlreadyExists`，本方法
    /// 捕捉后继续递增——绝不挂错路径（BORUIX 卷挂载为启动期顺序操作，此窗口
    /// 单线程下不存在）。
    pub fn mount_volume(&self, name: &str, fs: Arc<dyn FileSystem>) -> Result<String, Error> {
        validate_name(name)?;
        let base = alloc::format!("/volumes/{}", name);
        self.mount_named(base, fs)
    }

    /// 按未命名卷自动降级路径挂载（ADR-012 §3.2.2 未命名卷自动降级）。
    ///
    /// 无卷标分区不具友好名，须自动使用**短 UUID 或硬件识别名**挂载，避免
    /// 退化为空名/乱名。本方法接收调用方从设备/分区识别出的硬件标识作为
    /// 提示（如 `disk-2-part1`）；若未提供（`None` 或空/非法），则生成一个
    /// 单调递增的短标识 `storage-{seq}`。生成是**确定性**的，不伪造硬件
    /// 身份（S09：无 UUID 源时绝不以假 UUID 冒充）。
    ///
    /// 落到 `/volumes/{base}` 后仍走同名自增消解（与 [`Self::mount_volume`]
    /// 同源），返回最终绝对路径。
    pub fn mount_unnamed_volume(
        &self,
        hint: Option<&str>,
        fs: Arc<dyn FileSystem>,
    ) -> Result<String, Error> {
        // 卷命名空间须存在（A6：父链可解析）。
        self.resolve("/volumes", true)?;
        let base = match hint {
            // 硬件识别名：合法则直接采用。
            Some(h) if !h.is_empty() && validate_name(h).is_ok() => {
                alloc::format!("/volumes/{}", h)
            }
            // 无/非法提示：生成确定性短标识 storage-{seq}（seq 单调递增）。
            _ => {
                let seq = UNNAMED_SEQ.fetch_add(1, Ordering::Relaxed);
                alloc::format!("/volumes/storage-{:x}", seq)
            }
        };
        self.mount_named(base, fs)
    }

    /// 卷挂载核心：以 `/volumes/` 下 base 为候选，同名自增消解后挂载返回
    /// 最终绝对路径（ADR-012 §3.2.1）。base 已含 `/volumes/` 前缀且未段经
    /// [`validate_name`] 校验，故不再重复校验。
    fn mount_named(&self, base: String, fs: Arc<dyn FileSystem>) -> Result<String, Error> {
        // 创建首个候选挂载点目录（占用时多建几个空目录无害，最终以 mounts 键为准）。
        if let Err(e) = self.mkdir(&base, Permissions::all()) {
            match e {
                // 目录已存在（普通目录或占用前已建）——允许。
                Error::AlreadyExists => {}
                // 已存在但非目录：无法作为挂载点。
                Error::NotDirectory => return Err(Error::NotDirectory),
                other => return Err(other),
            }
        }
        // 自增寻找空闲挂载目标：以 mounts 表中是否已登记该路径键为占用判定。
        // `mount` 内部写锁复查 contains_key（TOCTOU 防线）；极端并发下若目标被
        // 抢先挂载返回 AlreadyExists，则继续递增重试——绝不挂错路径（BORUIX
        // 卷挂载为启动期顺序操作，该窗口单线程下不可达，循环仅为 S39 严谨兜底）。
        let mut candidate = base.clone();
        let mut suffix = 2usize;
        loop {
            let canon = Path::canonicalize(&candidate);
            if self.mounts.read().contains_key(&canon) {
                candidate = alloc::format!("{}-{}", base, suffix);
                suffix += 1;
                continue;
            }
            // 目标挂载点目录须存在且为目录（A6）。候选可能因自增而尚未创建。
            match self.resolve(&candidate, true) {
                Ok(node) => {
                    if node.node_type()? != INodeType::Directory {
                        return Err(Error::NotDirectory);
                    }
                }
                Err(Error::NotFound) => {
                    self.mkdir(&candidate, Permissions::all())?;
                }
                Err(e) => return Err(e),
            }
            match self.mount(&candidate, fs.clone()) {
                Ok(()) => return Ok(candidate),
                Err(Error::AlreadyExists) => {
                    // 并发窗口被抢先：递增重试（单线程启动期不可达）。
                    candidate = alloc::format!("{}-{}", base, suffix);
                    suffix += 1;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// 卸载挂载点。
    pub fn unmount(&self, target_path: &str) -> Result<(), Error> {
        require_absolute(target_path)?;
        let norm = Path::canonicalize(target_path);
        let mut mounts = self.mounts.write();
        if mounts.remove(&norm).is_some() {
            Ok(())
        } else {
            Err(Error::NotFound)
        }
    }

    /// 核心路径解析：从根开始逐级解析路径并处理挂载点与软链接。
    ///
    /// M1：只接受绝对路径；相对路径显式 [`Error::InvalidParam`]。软链接目标解析
    /// 产生的内部递归路径恒为绝对（链接目标绝对化或与父路径拼接），不重复检查。
    pub fn resolve(&self, path_str: &str, follow_symlink: bool) -> Result<Arc<dyn INode>, Error> {
        require_absolute(path_str)?;
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
            if next_node.node_type()? == INodeType::Symlink {
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

    /// 重命名/移动节点（ADR-014 SYS_ENTRY_UPDATE 0x43 / vfs1 M1）。
    ///
    /// 把 `old_path` 改名到 `new_path`。当前实现为**同目录重命名**：
    /// 两个路径的父目录须为同一个（跨目录/跨文件系统移动返回
    /// [`Error::NotSupported`]，宁缺毋假，见 `INode::rename` 约定）。
    ///
    /// 前置校验（S31/M1）：两路径均须绝对；`old_path` 与 `new_path` 的末段
    /// 名字均须合法（`validate_name`）；源项存在、目标项不冲突（由底层
    /// `INode::rename` 保证 NotFound/AlreadyExists）。挂载点本身的目录项不参与
    /// 本操作（目标若命中挂载点键，交由调用方语义；此处直接委托目录节点）。
    pub fn rename(&self, old_path: &str, new_path: &str) -> Result<(), Error> {
        require_absolute(old_path)?;
        require_absolute(new_path)?;
        let (old_parent, old_name) = Self::split_entry(old_path)?;
        validate_name(&old_name)?;
        let (new_parent, new_name) = Self::split_entry(new_path)?;
        validate_name(&new_name)?;
        // 同目录前提：跨目录/跨 FS 移动非本原语范围，如实 NotSupported。
        if old_parent != new_parent {
            return Err(Error::NotSupported);
        }
        let parent_node = self.resolve(&old_parent, true)?;
        parent_node.rename(&old_name, &new_name)
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
