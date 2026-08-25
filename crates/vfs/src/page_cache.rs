//! 页缓存：文件读路径的堆缓冲分块缓存（ADR-011 §2.3 / ADR-023 §1）。
//!
//! ## 本体如实描述（vfs1 R4 / D6——旧头注释宣称的 "2MB 物理大页直通 /
//! ORDER_2M / TLB 命中率提升 / 基数树索引" 在实现中从未存在，全部删除）
//!
//! - **存储介质是普通堆 Vec**，无物理页对齐、无 LazyBuddy 大页交互、无
//!   页表映射。`HUGE_PAGE_SIZE` 只是"整块预载的块粒度"常量（≥128KiB 的
//!   连续读按 2MB 对齐块预载，减少逐页锁开销），与 mm 物理大页无关；
//! - 索引是 [`alloc::collections::BTreeMap`]（键见下），不是基数树；
//! - **键控作用域（审计 R9-F1 / ADR-023 §1 补条款）：`(节点身份, 文件内偏移)`
//!   二元组**。节点身份取 `Arc` 分配地址，且每个缓存条目**钉住一份
//!   `Arc` 克隆**——条目存活期间该地址不可能被新分配复用，因此不存在
//!   "释放后地址重用导致跨文件串读"的别名窗口；淘汰即释放钉引用。
//!   代价：被缓存的节点在条目淘汰前不析构（对 ramfs 是其常态生存期，
//!   对 ext2 延迟节点回收）——有界淘汰约束下的有意取舍。旧实现以裸偏移
//!   为键、无归属维度，全局化后即跨文件共享槽位：读侧静默串数据、写侧
//!   过失效（audit R9 确认 P1）；
//! - 惰性按需填充：未命中时经 `inode.read_at` 装载；
//! - 淘汰：显式调用 [`PageCache::evict_pages`]，按访问计数取最久未被
//!   访问的受害者（LRU 语义）；容量上限由调用方的淘汰目标约束。
//!   真·物理大页直通依赖 mm ORDER_2M 分配阶，作为独立里程碑登记
//!   （docs/todo.md），届时本模块按新架构重建而非在堆缓存上贴皮。

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::Once;
use spin::RwLock;

use crate::inode::INode;

/// 整块预载块粒度：连续大读按此对齐块预载（历史名 HUGE_PAGE_SIZE 保留，
/// 以免与既有 API 使用方断裂；语义见上——它是**缓存块粒度**，不是物理页）。
pub const HUGE_PAGE_SIZE: usize = 2 * 1024 * 1024;
/// 4KB 标准缓存页粒度。
pub const PAGE_SIZE: usize = 4096;

/// 连续读启用整块预载的最小缓冲字节数（M6 命名化）。
///
/// 取值理由：低于该阈值的读取逐 4KB 页装载已足够（单次至多几十次页锁），
/// 预载 2MB 块反而造成过量驻留；达到该量级后整块装载把每字节均摊的
/// 锁/查找开销压到近常数。属工程折中阈值而非硬件边界；若未来有 benchmark
/// 设施（S32 登记项），应以实测重校。
pub const READ_BULK_THRESHOLD_BYTES: usize = 128 * 1024;

/// 缓存键：(节点身份, 文件内偏移)。节点身份 = Arc 分配地址（条目钉住
/// Arc 克隆保证存活期内唯一）；偏移为块对齐基址。
type PageKey = (usize, u64);

/// 从 Arc 句柄提取节点身份地址。
fn node_key(inode: &Arc<dyn INode>) -> usize {
    Arc::as_ptr(inode) as *const core::ffi::c_void as usize
}

/// 一个缓存块条目。
///
/// A2（ADR-023 §1）：失效一致性策略下**不存在脏块**——一切句柄写都经
/// [`PageCache::write_cached`] 写穿并作废受影响块，因此没有 `is_dirty`
/// 字段（旧字段恒 false，是永不生效的死机制）。`access_count` 是淘汰
/// 依据：每次命中递增，[`PageCache::evict_pages`] 取最小值受害。
pub struct CachePage {
    /// 钉住的节点句柄：既是身份来源也是防地址复用的存活保证。
    #[allow(dead_code)]
    owner: Arc<dyn INode>,
    pub data: Vec<u8>,
    pub access_count: AtomicU64,
}

impl CachePage {
    fn new(owner: Arc<dyn INode>, data: Vec<u8>) -> Self {
        Self {
            owner,
            data,
            access_count: AtomicU64::new(1),
        }
    }

    /// 该块折合多少个 4KB 页（M8：截断过的块按实际数据量计账，
    /// 不再一律虚记 512 页）。至少记 1——块本身有元数据开销。
    fn page_equivalent(&self) -> usize {
        core::cmp::max(1, self.data.len().div_ceil(PAGE_SIZE))
    }
}

/// 统合页缓存统计信息。
#[derive(Default, Debug, Clone, Copy)]
pub struct PageCacheStats {
    pub total_pages: usize,
    pub huge_pages: usize,
    pub hits: usize,
    pub misses: usize,
    pub evictions: usize,
}

/// 统合文件页缓存管理器。
pub struct PageCache {
    /// 4KB 页缓存映射：`(节点身份, 块基址) -> CachePage`。
    pages_4k: RwLock<BTreeMap<PageKey, Arc<CachePage>>>,
    /// 整块预载缓存映射：`(节点身份, HUGE_PAGE_SIZE 对齐基址) -> CachePage`。
    pages_huge: RwLock<BTreeMap<PageKey, Arc<CachePage>>>,
    hits: AtomicUsize,
    misses: AtomicUsize,
    evictions: AtomicUsize,
}

/// 手写 Debug（D5 / ADR-023 §7）：安全摘要，不倾倒缓存内容字节。
impl core::fmt::Debug for PageCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PageCache")
            .field("pages_4k_count", &self.pages_4k.read().len())
            .field("pages_huge_count", &self.pages_huge.read().len())
            .field("hits", &self.hits)
            .field("misses", &self.misses)
            .field("evictions", &self.evictions)
            .finish()
    }
}

impl PageCache {
    pub fn new() -> Self {
        Self {
            pages_4k: RwLock::new(BTreeMap::new()),
            pages_huge: RwLock::new(BTreeMap::new()),
            hits: AtomicUsize::new(0),
            misses: AtomicUsize::new(0),
            evictions: AtomicUsize::new(0),
        }
    }

    /// 从缓存读取单个 4KB 页片段数据，若未命中则惰性填充。
    ///
    /// 返回 Ok(0) 当且仅当到达文件尾（或 inode 报告无数据）。
    fn read_page_4k(
        &self,
        inode: &Arc<dyn INode>,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, klib::error::Error> {
        let page_offset = (offset / PAGE_SIZE as u64) * PAGE_SIZE as u64;
        let page_inner_off = (offset % PAGE_SIZE as u64) as usize;
        let key = (node_key(inode), page_offset);

        // 尝试从 4KB 缓存读取。命中但请求偏移越出已缓存数据（inner_off
        // >= len）时**落到装载路径重查**而不是直接报 EOF（M5）：缓存的
        // 页可能因历史截断短于满页，文件此后又增长过——EOF 只能由当下
        // 的 inode 读回判定，不能由陈旧的缓存边界判定。
        let cached = {
            let map = self.pages_4k.read();
            map.get(&key).cloned()
        };
        if let Some(page) = cached {
            if page_inner_off < page.data.len() {
                let available = &page.data[page_inner_off..];
                let copy_len = core::cmp::min(buf.len(), available.len());
                buf[..copy_len].copy_from_slice(&available[..copy_len]);
                page.access_count.fetch_add(1, Ordering::Relaxed);
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Ok(copy_len);
            }
        }

        // 未命中（或命中但越出缓存边界）：按需加载该 4KB 页。
        self.misses.fetch_add(1, Ordering::Relaxed);
        let mut page_buf = alloc::vec![0u8; PAGE_SIZE];
        let read_len = inode.read_at(page_offset, &mut page_buf)?;
        if read_len == 0 {
            return Ok(0);
        }
        page_buf.truncate(read_len);
        let page = Arc::new(CachePage::new(Arc::clone(inode), page_buf));
        self.pages_4k.write().insert(key, page.clone());

        if page_inner_off < page.data.len() {
            let available = &page.data[page_inner_off..];
            let copy_len = core::cmp::min(buf.len(), available.len());
            buf[..copy_len].copy_from_slice(&available[..copy_len]);
            Ok(copy_len)
        } else {
            Ok(0)
        }
    }

    /// 从缓存读取数据（支持跨页连续读取与大块整块预载）。
    ///
    /// **短读契约**（M5 成文）：返回值 < `buf.len()` 当且仅当到达 EOF
    /// （或底层 inode 返回错误）。跨多个 4KB 页/多个预载块的读取在本
    /// 函数内部循环补齐，调用方不需要自行重试。
    ///
    /// 键控作用域（R9-F1）：按调用方传入的节点身份隔离——两个文件的
    /// 同偏移互不可见。
    pub fn read_cached(
        &self,
        inode: &Arc<dyn INode>,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, klib::error::Error> {
        if buf.is_empty() {
            return Ok(0);
        }

        // 大缓冲：优先尝试整块预载缓存；无论成败，剩余部分继续走逐页
        // 循环补齐（M5：单块只交付一段、其余静默丢失的旧行为废除）。
        if buf.len() >= READ_BULK_THRESHOLD_BYTES {
            let mut total_read = 0usize;
            while total_read < buf.len() {
                let cur = offset + total_read as u64;
                let huge_offset = (cur / HUGE_PAGE_SIZE as u64) * HUGE_PAGE_SIZE as u64;
                let huge_inner_off = (cur % HUGE_PAGE_SIZE as u64) as usize;
                let huge_key = (node_key(inode), huge_offset);

                let cached = {
                    let huge_map = self.pages_huge.read();
                    huge_map.get(&huge_key).cloned()
                };
                let delivered = match cached {
                    Some(page) if huge_inner_off < page.data.len() => {
                        let available = &page.data[huge_inner_off..];
                        let dest = &mut buf[total_read..];
                        let copy_len = core::cmp::min(dest.len(), available.len());
                        dest[..copy_len].copy_from_slice(&available[..copy_len]);
                        page.access_count.fetch_add(1, Ordering::Relaxed);
                        self.hits.fetch_add(1, Ordering::Relaxed);
                        copy_len
                    }
                    _ => {
                        // 未命中：预载该对齐块（大小按文件元数据截断；
                        // 元数据失败如实走 4KB 逐页路径，绝不投机假设
                        // 满块大小——M3）。
                        self.misses.fetch_add(1, Ordering::Relaxed);
                        let meta_size = inode.metadata().map(|m| m.size);
                        let needed_size = match meta_size {
                            Ok(size) => {
                                if huge_offset < size {
                                    core::cmp::min(
                                        HUGE_PAGE_SIZE as u64,
                                        size - huge_offset,
                                    ) as usize
                                } else {
                                    0
                                }
                            }
                            Err(_) => 0,
                        };
                        if needed_size > 0 {
                            let mut block_buf = alloc::vec![0u8; needed_size];
                            let read_len = inode.read_at(huge_offset, &mut block_buf)?;
                            if read_len > 0 {
                                block_buf.truncate(read_len);
                                let page = Arc::new(CachePage::new(
                                    Arc::clone(inode),
                                    block_buf,
                                ));
                                self.pages_huge.write().insert(huge_key, page.clone());
                                if huge_inner_off < page.data.len() {
                                    let available = &page.data[huge_inner_off..];
                                    let dest = &mut buf[total_read..];
                                    let copy_len = core::cmp::min(dest.len(), available.len());
                                    dest[..copy_len].copy_from_slice(&available[..copy_len]);
                                    copy_len
                                } else {
                                    0
                                }
                            } else {
                                0
                            }
                        } else {
                            0
                        }
                    }
                };
                if delivered == 0 {
                    // 本块无更多数据：转 4KB 逐页路径收尾（可能是稀疏
                    // 边界或 EOF，由它如实判定）。
                    let n = self.read_page_4k(inode, cur, &mut buf[total_read..])?;
                    if n == 0 {
                        break;
                    }
                    total_read += n;
                } else {
                    total_read += delivered;
                }
            }
            return Ok(total_read);
        }

        // 普通读取（支持跨页，逐页填充 buf）。
        let mut total_read = 0;
        let mut cur_offset = offset;

        while total_read < buf.len() {
            let chunk_dest = &mut buf[total_read..];
            let n = self.read_page_4k(inode, cur_offset, chunk_dest)?;
            if n == 0 {
                break;
            }
            total_read += n;
            cur_offset += n as u64;
        }

        Ok(total_read)
    }

    /// 协调写：先写穿 inode，再作废**本节点**受影响的全部缓存块
    /// （ADR-023 §1 + R9-F1 键控作用域）。
    ///
    /// 这是全局缓存策略下的**唯一合法写通道**——`FileHandle::write/pwrite`
    /// 经由此函数落盘，保证任何句柄写之后读缓存不可能返回陈旧数据，
    /// 且失效严格限于本节点的键空间（不误删其他文件的缓存块）。
    /// 绕过句柄直调 `inode.write_at` 属于裸通道，一致性由调用方自理
    /// （模块头成文）。
    pub fn write_cached(
        &self,
        inode: &Arc<dyn INode>,
        offset: u64,
        buf: &[u8],
    ) -> Result<usize, klib::error::Error> {
        let written = inode.write_at(offset, buf)?;
        if written > 0 {
            self.invalidate(inode, offset, written as u64);
        }
        Ok(written)
    }

    /// 作废**本节点**覆盖 `[offset, offset+len)` 的所有缓存块。
    fn invalidate(&self, inode: &Arc<dyn INode>, offset: u64, len: u64) {
        let nk = node_key(inode);

        let mut map4k = self.pages_4k.write();
        let mut map_huge = self.pages_huge.write();

        let start_page = (offset / PAGE_SIZE as u64) * PAGE_SIZE as u64;
        let end_page =
            ((offset + len + PAGE_SIZE as u64 - 1) / PAGE_SIZE as u64) * PAGE_SIZE as u64;

        // 元组序性质：`(nk, start)..(nk, end)` 恰好框住本节点该区间内
        // 全部键——首分量不同的键必然落在区间之外。
        let victims4k: Vec<PageKey> = map4k
            .range((nk, start_page)..(nk, end_page))
            .map(|(k, _)| *k)
            .collect();
        for k in victims4k {
            map4k.remove(&k);
        }

        let huge_start = (offset / HUGE_PAGE_SIZE as u64) * HUGE_PAGE_SIZE as u64;
        let huge_end = ((offset + len + HUGE_PAGE_SIZE as u64 - 1) / HUGE_PAGE_SIZE as u64)
            * HUGE_PAGE_SIZE as u64;
        let victims_huge: Vec<PageKey> = map_huge
            .range((nk, huge_start)..(nk, huge_end))
            .map(|(k, _)| *k)
            .collect();
        for k in victims_huge {
            map_huge.remove(&k);
        }
    }

    /// 内存紧凑感知淘汰（Eviction）：释放缓存块直到折算释放量达标。
    ///
    /// 受害者选择：access_count 最小者优先（LRU 语义，A2——旧实现是
    /// BTreeMap 序 first-fit，access_count 形同虚设）。同分时按键序
    /// （节点身份、偏移）保证确定性。
    pub fn evict_pages(&self, target_free_count: usize) -> usize {
        let mut evicted = 0usize;

        // 两级表合并收集候选：(access, level, 节点身份, 偏移, 折算页数)。
        let mut candidates: Vec<(u64, u8, usize, u64, usize)> = Vec::new();
        {
            let map4k = self.pages_4k.read();
            for ((nk, off), page) in map4k.iter() {
                candidates.push((
                    page.access_count.load(Ordering::Relaxed),
                    0,
                    *nk,
                    *off,
                    page.page_equivalent(),
                ));
            }
        }
        {
            let map_huge = self.pages_huge.read();
            for ((nk, off), page) in map_huge.iter() {
                candidates.push((
                    page.access_count.load(Ordering::Relaxed),
                    1,
                    *nk,
                    *off,
                    page.page_equivalent(),
                ));
            }
        }
        candidates.sort_by(|a, b| (a.0, a.1, a.2, a.3).cmp(&(b.0, b.1, b.2, b.3)));

        let mut drop4k: Vec<PageKey> = Vec::new();
        let mut drop_huge: Vec<PageKey> = Vec::new();
        for (access, level, nk, off, equiv) in candidates {
            if evicted >= target_free_count {
                break;
            }
            // 复查 access_count：收集与删除之间无写入（全程持读锁快照 +
            // 删除持写锁，单线程语义下无竞态窗口；多核化时此处需要升级
            // 为写锁内重验——S21 显式标注，同审计 O1）。
            let _ = access;
            if level == 0 {
                drop4k.push((nk, off));
            } else {
                drop_huge.push((nk, off));
            }
            evicted += equiv;
        }

        if !drop4k.is_empty() {
            let mut map4k = self.pages_4k.write();
            for k in drop4k {
                map4k.remove(&k);
            }
        }
        if !drop_huge.is_empty() {
            let mut map_huge = self.pages_huge.write();
            for k in drop_huge {
                map_huge.remove(&k);
            }
        }

        self.evictions.fetch_add(evicted, Ordering::Relaxed);
        evicted
    }

    /// 获取缓存统计快照。
    pub fn stats(&self) -> PageCacheStats {
        let total_4k: usize = self.pages_4k.read().len();
        let total_huge: usize = self.pages_huge.read().len();
        PageCacheStats {
            total_pages: total_4k + total_huge * (HUGE_PAGE_SIZE / PAGE_SIZE),
            huge_pages: total_huge,
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
        }
    }
}

// ---------------------------------------------------------------------------
// 全局缓存单点（ADR-023 §1）
// ---------------------------------------------------------------------------

static GLOBAL_CACHE: Once<&'static PageCache> = Once::new();

/// 注入全局页缓存（内核启动期一次）。注入后 [`crate::file_handle::FileHandle`]
/// 的全部写操作经 `write_cached` 写穿并作废**本节点**受影响缓存块；未注入
/// （宿主单测等场景）时句柄直写 inode，缓存一致性由测试自身保证。
pub fn set_global_page_cache(cache: &'static PageCache) {
    let _ = GLOBAL_CACHE.call_once(|| cache);
}

/// 全局缓存引用（未注入为 None）。crate 内部使用。
pub(crate) fn global_page_cache() -> Option<&'static PageCache> {
    GLOBAL_CACHE.get().copied()
}
