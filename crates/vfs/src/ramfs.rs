//! 纯内存通用文件系统（RamFS）。

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use klib::error::Error;
use spin::RwLock;

use crate::inode::{AccessPolicy, DirEntry, FileMetadata, FileSystem, INode, INodeType};

/// 单文件最大字节数（A8 放大 8MiB → 64MiB，owner 指令 2026-09-27）。
/// 保留闸门的理由（S17）：RamFS 内容驻留内核堆，无 per-process 记账时
/// 「单文件独占堆」的唯一防线是本闸 + 水位钩子（后者是最终防线，前者挡
/// 单点独占）；64MiB 与单次拷贝上限（MAX_SYSCALL_BUF_BYTES）同量级对齐。
/// 超 ENOSPC 语义不变。
pub const RAMFS_MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// 单目录最大条目数（A8 放大 4096 → 65536，owner 指令 2026-09-27）。
/// 保留闸门理由同上（防无配额时的条目表无界增长）；65536 条 ≈ 数 MiB 堆。
pub const RAMFS_MAX_ENTRIES_PER_DIR: usize = 65536;

/// 水位咨询阈值（D4/ADR-023 §7）：单次增长达到该字节数才向内存水位
/// 钩子咨询。低于它的增长即使堆紧张也由 try_reserve 兜底——逐字节写
/// 入高频咨询钩子的开销大于收益。
pub const RAMFS_WATERMARK_CONSULT_BYTES: usize = 64 * 1024;

/// 水位紧张时的一次性驱逐页数（ADR-023 §7）：约 256KiB 的缓存回笼量，
/// 与典型增长跨度同量级；驱逐后仍紧张即如实 OutOfMemory，不做多轮
/// 抖动式重试。调校依据同 [`RAMFS_WATERMARK_CONSULT_BYTES`]。
const EVICT_PAGES_ON_TIGHT: usize = 64;

use spin::Once as SpinOnce;

static MEMORY_TIGHT_HOOK: SpinOnce<fn() -> bool> = SpinOnce::new();

/// RamFS 节点身份分配器（单调递增，**不复用**）。
///
/// 不复用是刻意的：复用的 id 会让"已删除文件"与"新建文件"撞成同一个身份，
/// 于是新文件凭空继承前者的锁记录（真实缺陷的成因正是地址复用，见
/// [`INode::stable_id`]）。`u64` 单次启动内不可能耗尽。
static NEXT_NODE_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

/// 分配下一个 RamFS 节点身份。
fn alloc_node_id() -> u64 {
    NEXT_NODE_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}

/// 注入内存水位钩子（内核启动期一次）：返回 true 表示内核内存紧张
/// （实现侧读 mm 预留池统计）。RamFS 大跨度增长路径据此先驱逐全局
/// PageCache 再试，仍紧张则如实失败。未注入（宿主单测）时不咨询。
pub fn set_ramfs_memory_tight_hook(hook: fn() -> bool) {
    let _ = MEMORY_TIGHT_HOOK.call_once(|| hook);
}

fn memory_tight() -> bool {
    MEMORY_TIGHT_HOOK.get().map(|f| f()).unwrap_or(false)
}

/// 增长前纪律（write_at/truncate 共用）：
/// 1. 大跨度增长且水位紧张 → 驱逐全局缓存一轮后复查；
/// 2. try_reserve 失败 → 同上一轮补救后重试一次；
/// 3. 仍不可行 → 如实 OutOfMemory。绝不走 Vec::resize 的 abort 路径。
fn reserve_with_watermark(
    c: &mut Vec<u8>,
    grow: usize,
    watermark_consult: bool,
) -> Result<(), Error> {
    if watermark_consult && grow >= RAMFS_WATERMARK_CONSULT_BYTES && memory_tight() {
        if let Some(cache) = crate::page_cache::global_page_cache() {
            cache.evict_pages(EVICT_PAGES_ON_TIGHT);
        }
    }
    if c.try_reserve(grow).is_err() {
        // 分配器已拒：做同一轮缓存驱逐补救后最后重试一次。
        if let Some(cache) = crate::page_cache::global_page_cache() {
            cache.evict_pages(EVICT_PAGES_ON_TIGHT);
        }
        if c.try_reserve(grow).is_err() {
            return Err(Error::OutOfMemory);
        }
    }
    Ok(())
}

/// 单调毫秒时间戳来源（S03：klib::time 为单调时间线，非 wall clock）。
fn now_ms() -> u64 {
    klib::time::now_millis().unwrap_or(0)
}

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
    /// **稳定文件身份**（见 [`INode::stable_id`]）。
    ///
    /// RamFS 的 `lookup` 返回子节点表里缓存的 `Arc`，故"地址"恰好在当前实现下
    /// 也是稳定的——但那**依赖实现细节**，一旦将来引入 `Arc` 重建（缓存逐出、
    /// 重新解析路径等）就会静默破坏文件锁。显式 id 把这条契约写进数据本身，
    /// 不再依赖内存布局（S15 单点定义）。
    id: u64,
}

impl RamINode {
    pub fn new_file(policy: AccessPolicy) -> Arc<Self> {
        // A3（ADR-023 §7）：RamFS 是有出生时刻的真实存储，三时间戳取
        // 单调钟真值；无状态视图节点（procfs/devfs/dynamic/stdio）的恒 0
        // 政策见 crate::inode 模块注释。
        let now = now_ms();
        Arc::new(Self {
            id: alloc_node_id(),
            meta: RwLock::new(FileMetadata {
                node_type: INodeType::RegularFile,
                size: 0,
                permissions: policy,
                created_time: now,
                modified_time: now,
                changed_time: now,
            }),
            data: RamNodeData::File {
                content: RwLock::new(Vec::new()),
            },
        })
    }

    pub fn new_dir(policy: AccessPolicy) -> Arc<Self> {
        let now = now_ms();
        Arc::new(Self {
            id: alloc_node_id(),
            meta: RwLock::new(FileMetadata {
                node_type: INodeType::Directory,
                size: 0,
                permissions: policy,
                created_time: now,
                modified_time: now,
                changed_time: now,
            }),
            data: RamNodeData::Directory {
                children: RwLock::new(BTreeMap::new()),
            },
        })
    }

    pub fn new_symlink(target: &str) -> Arc<Self> {
        let now = now_ms();
        Arc::new(Self {
            id: alloc_node_id(),
            meta: RwLock::new(FileMetadata {
                node_type: INodeType::Symlink,
                size: target.len() as u64,
                permissions: AccessPolicy::all(),
                created_time: now,
                modified_time: now,
                changed_time: now,
            }),
            data: RamNodeData::Symlink {
                target: target.to_string(),
            },
        })
    }

    /// 目录条目发生增删时联动父目录 changed/modified 时间（POSIX 语义）。
    fn touch_dir_meta(&self) {
        let mut meta = self.meta.write();
        let now = now_ms();
        meta.modified_time = now;
        meta.changed_time = now;
    }
}

impl INode for RamINode {
    /// 覆写为构造时分配的**单调 id**（见 [`RamINode::id`]）。
    ///
    /// 默认实现（`self` 地址）在当前 `lookup` 实现下恰好也正确，但那依赖
    /// "同一文件永远复用同一个 `Arc` "这一未经声明的前提。显式 id 去掉该依赖。
    fn stable_id(&self) -> u64 {
        self.id
    }

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
                // M18 锁序（S21，ADR-023 §7）：content → meta 单向嵌套。
                // size 与时间戳的更新在 content 临界区内完成后一并落账，
                // 消除"先放 content 锁再拿 meta 锁"窗口里并发读者看到的
                // 内容/大小不一致与 size 回退。
                let mut c = content.write();
                let end = (offset as usize)
                    .checked_add(buf.len())
                    .ok_or(Error::OutOfRange)?;
                // KA7：文件大小配额 + 分配失败诚实化。try_reserve 先验证
                // 堆可满足增长需求——Vec::resize 的 OOM 路径是直接 panic，
                // 用户态一次越界写绝不能把内核推过那条路。D4：大跨度增长
                // 先过水位纪律（驱逐缓存补救一轮）。
                if end as u64 > RAMFS_MAX_FILE_BYTES {
                    return Err(Error::NoSpace);
                }
                if end > c.len() {
                    let grow = end - c.len();
                    reserve_with_watermark(&mut c, grow, true)?;
                    c.resize(end, 0);
                }
                let start = offset as usize;
                c[start..end].copy_from_slice(buf);
                let new_size = c.len() as u64;
                let now = now_ms();
                let mut meta = self.meta.write();
                meta.size = new_size;
                meta.modified_time = now;
                meta.changed_time = now;
                Ok(buf.len())
            }
            _ => Err(Error::IsDirectory),
        }
    }

    fn metadata(&self) -> Result<FileMetadata, Error> {
        Ok(self.meta.read().clone())
    }

    /// A5：按数据族判型，零锁零分配（读 meta 反而要拿 RwLock）。
    fn node_type(&self) -> Result<INodeType, Error> {
        Ok(match &self.data {
            RamNodeData::File { .. } => INodeType::RegularFile,
            RamNodeData::Directory { .. } => INodeType::Directory,
            RamNodeData::Symlink { .. } => INodeType::Symlink,
        })
    }

    fn truncate(&self, size: u64) -> Result<(), Error> {
        match &self.data {
            RamNodeData::File { content } => {
                // KA7：truncate 扩容与 write_at 同一配额与 OOM 纪律；
                // M18 同锁序：meta 更新在 content 临界区内完成。
                if size > RAMFS_MAX_FILE_BYTES {
                    return Err(Error::NoSpace);
                }
                let mut c = content.write();
                if size as usize > c.len() {
                    let grow = size as usize - c.len();
                    reserve_with_watermark(&mut c, grow, true)?;
                }
                c.resize(size as usize, 0);
                let now = now_ms();
                let mut meta = self.meta.write();
                meta.size = size;
                meta.modified_time = now;
                meta.changed_time = now;
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

    fn create(&self, name: &str, mode: u32, owner: (u32, u32)) -> Result<Arc<dyn INode>, Error> {
        match &self.data {
            RamNodeData::Directory { children } => {
                let mut c = children.write();
                if c.contains_key(name) {
                    return Err(Error::AlreadyExists);
                }
                // KA7：目录条目配额（create/mkdir/symlink 三入口同一防线）。
                if c.len() >= RAMFS_MAX_ENTRIES_PER_DIR {
                    return Err(Error::NoSpace);
                }
                let file = RamINode::new_file(AccessPolicy::from_classic_owned(mode, owner.0, owner.1));
                c.insert(name.to_string(), file.clone());
                drop(c);
                self.touch_dir_meta();
                Ok(file)
            }
            _ => Err(Error::NotDirectory),
        }
    }

    fn mkdir(&self, name: &str, mode: u32, owner: (u32, u32)) -> Result<Arc<dyn INode>, Error> {
        match &self.data {
            RamNodeData::Directory { children } => {
                let mut c = children.write();
                if c.contains_key(name) {
                    return Err(Error::AlreadyExists);
                }
                if c.len() >= RAMFS_MAX_ENTRIES_PER_DIR {
                    return Err(Error::NoSpace);
                }
                let dir = RamINode::new_dir(AccessPolicy::from_classic_owned(mode, owner.0, owner.1));
                c.insert(name.to_string(), dir.clone());
                drop(c);
                self.touch_dir_meta();
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
                    drop(c);
                    self.touch_dir_meta();
                    Ok(())
                } else {
                    Err(Error::NotFound)
                }
            }
            _ => Err(Error::NotDirectory),
        }
    }

    /// 同目录内重命名子项（ADR-014 SYS_ENTRY_UPDATE 0x43 原语）：只改目录项键、
    /// 不动内容与 inode 身份。`old_name` 缺失 → NotFound；`new_name` 已占 → 
    /// AlreadyExists（绝不静默覆盖）。
    fn rename(&self, old_name: &str, new_name: &str) -> Result<(), Error> {
        match &self.data {
            RamNodeData::Directory { children } => {
                let mut c = children.write();
                if !c.contains_key(old_name) {
                    return Err(Error::NotFound);
                }
                if c.contains_key(new_name) {
                    return Err(Error::AlreadyExists);
                }
                // 弹出旧键，以新键插回（保 Arc 身份，内容零拷贝）。
                if let Some(node) = c.remove(old_name) {
                    c.insert(new_name.to_string(), node);
                    drop(c);
                    self.touch_dir_meta();
                    Ok(())
                } else {
                    Err(Error::NotFound)
                }
            }
            _ => Err(Error::NotDirectory),
        }
    }

    /// 设置节点权限（chmod 原语，A1-1）：**策略本体整体替换**（属主含在
    /// 策略内）并刷新 changed 时间。
    ///
    /// A1-7 分层更正：保主**不是**本原语的职责——chmod 是写门径而非易主，
    /// 保主由 chmod 调用方（kernel ENTRY_UPDATE_CHMOD 分支 `with_owner`
    /// 构造）负责；chown 走同一原语时需要**写入新属主**，fs 层若再保主
    /// 会把易主静默覆盖（曾致 test_chown_e2e 红灯，分层教训成文）。
    fn set_permissions(&self, policy: &AccessPolicy) -> Result<(), Error> {
        let mut meta = self.meta.write();
        meta.permissions = policy.clone();
        meta.changed_time = now_ms();
        Ok(())
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
                if c.len() >= RAMFS_MAX_ENTRIES_PER_DIR {
                    return Err(Error::NoSpace);
                }
                let link = RamINode::new_symlink(target);
                c.insert(name.to_string(), link.clone());
                drop(c);
                self.touch_dir_meta();
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
            root: RamINode::new_dir(AccessPolicy::all()),
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

// ---------------------------------------------------------------------------
// D5（ADR-023 §7）：诊断用 Debug 摘要——只暴露类型/大小/条目数等元事实，
// 绝不倾倒文件内容字节（内容可能含用户数据，日志即泄漏面）。
// ---------------------------------------------------------------------------

impl core::fmt::Debug for RamINode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.data {
            RamNodeData::File { content } => f
                .debug_struct("RamINode/File")
                .field("size", &content.read().len())
                .finish(),
            RamNodeData::Directory { children } => f
                .debug_struct("RamINode/Dir")
                .field("entries", &children.read().len())
                .finish(),
            RamNodeData::Symlink { target } => f
                .debug_struct("RamINode/Symlink")
                .field("target_len", &target.len())
                .finish(),
        }
    }
}

impl core::fmt::Debug for RamFS {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RamFS").finish()
    }
}
