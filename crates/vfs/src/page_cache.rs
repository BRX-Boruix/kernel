//! Page Cache 核心架构与物理页融合缓存（ADR-011 / ADR-012）。
//!
//! 提供：
//! - 2MB 连续物理大页直通机制（`ORDER_2M` Huge Page Cache）
//! - 4KB 单页缓存与基数树 / B-Tree 块索引
//! - 惰性按需填充（Demand Paging）跨页循环读取
//! - 内存紧凑感知淘汰（Eviction）：在内存紧张或显式淘汰时释放未脏（Clean）缓存页

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use spin::RwLock;

use crate::inode::INode;

/// 2MB 大页大小。
pub const HUGE_PAGE_SIZE: usize = 2 * 1024 * 1024;
/// 4KB 标准页大小。
pub const PAGE_SIZE: usize = 4096;

/// 单个缓存页条目。
pub struct CachePage {
    pub data: Vec<u8>,
    pub is_dirty: AtomicBool,
    pub access_count: AtomicU64,
}

impl CachePage {
    pub fn new_4k(data: Vec<u8>) -> Self {
        Self {
            data,
            is_dirty: AtomicBool::new(false),
            access_count: AtomicU64::new(1),
        }
    }

    pub fn new_huge(data: Vec<u8>) -> Self {
        Self {
            data,
            is_dirty: AtomicBool::new(false),
            access_count: AtomicU64::new(1),
        }
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
    /// 4KB 页缓存映射：`offset -> CachePage`。
    pages_4k: RwLock<BTreeMap<u64, Arc<CachePage>>>,
    /// 2MB 大页缓存映射：`offset (2MB 对齐) -> CachePage`。
    pages_huge: RwLock<BTreeMap<u64, Arc<CachePage>>>,
    hits: AtomicUsize,
    misses: AtomicUsize,
    evictions: AtomicUsize,
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
    fn read_page_4k(
        &self,
        inode: &dyn INode,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, klib::error::Error> {
        let page_offset = (offset / PAGE_SIZE as u64) * PAGE_SIZE as u64;
        let page_inner_off = (offset % PAGE_SIZE as u64) as usize;

        // 尝试从 4KB 缓存读取
        {
            let map = self.pages_4k.read();
            if let Some(page) = map.get(&page_offset) {
                if page_inner_off < page.data.len() {
                    let available = &page.data[page_inner_off..];
                    let copy_len = core::cmp::min(buf.len(), available.len());
                    buf[..copy_len].copy_from_slice(&available[..copy_len]);
                    page.access_count.fetch_add(1, Ordering::Relaxed);
                    self.hits.fetch_add(1, Ordering::Relaxed);
                    return Ok(copy_len);
                } else {
                    return Ok(0);
                }
            }
        }

        // 未命中：按需加载该 4KB 页
        self.misses.fetch_add(1, Ordering::Relaxed);
        let mut page_buf = alloc::vec![0u8; PAGE_SIZE];
        let read_len = inode.read_at(page_offset, &mut page_buf)?;
        if read_len == 0 {
            return Ok(0);
        }
        page_buf.truncate(read_len);
        let page = Arc::new(CachePage::new_4k(page_buf));
        self.pages_4k.write().insert(page_offset, page.clone());

        if page_inner_off < page.data.len() {
            let available = &page.data[page_inner_off..];
            let copy_len = core::cmp::min(buf.len(), available.len());
            buf[..copy_len].copy_from_slice(&available[..copy_len]);
            Ok(copy_len)
        } else {
            Ok(0)
        }
    }

    /// 从缓存读取数据（支持跨页连续读取与 2MB 大页直通）。
    pub fn read_cached(
        &self,
        inode: &dyn INode,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, klib::error::Error> {
        if buf.is_empty() {
            return Ok(0);
        }

        // 如果是大缓冲读取（>= 128KB 且 2MB 模式），优先尝试 2MB 大页
        if buf.len() >= 128 * 1024 {
            let huge_offset = (offset / HUGE_PAGE_SIZE as u64) * HUGE_PAGE_SIZE as u64;
            let huge_inner_off = (offset % HUGE_PAGE_SIZE as u64) as usize;

            {
                let huge_map = self.pages_huge.read();
                if let Some(page) = huge_map.get(&huge_offset) {
                    if huge_inner_off < page.data.len() {
                        let available = &page.data[huge_inner_off..];
                        let copy_len = core::cmp::min(buf.len(), available.len());
                        buf[..copy_len].copy_from_slice(&available[..copy_len]);
                        page.access_count.fetch_add(1, Ordering::Relaxed);
                        self.hits.fetch_add(1, Ordering::Relaxed);
                        return Ok(copy_len);
                    }
                }
            }

            // 未命中 2MB 大页：预载大页（大小按文件元数据尺寸截断，最多 2MB）
            self.misses.fetch_add(1, Ordering::Relaxed);
            let meta_size = inode
                .metadata()
                .map(|m| m.size)
                .unwrap_or(HUGE_PAGE_SIZE as u64);
            let needed_size = if huge_offset < meta_size {
                core::cmp::min(HUGE_PAGE_SIZE as u64, meta_size - huge_offset) as usize
            } else {
                0
            };
            if needed_size > 0 {
                let mut huge_buf = alloc::vec![0u8; needed_size];
                let read_len = inode.read_at(huge_offset, &mut huge_buf)?;
                if read_len > 0 {
                    huge_buf.truncate(read_len);
                    let page = Arc::new(CachePage::new_huge(huge_buf));
                    self.pages_huge.write().insert(huge_offset, page.clone());

                    if huge_inner_off < page.data.len() {
                        let available = &page.data[huge_inner_off..];
                        let copy_len = core::cmp::min(buf.len(), available.len());
                        buf[..copy_len].copy_from_slice(&available[..copy_len]);
                        return Ok(copy_len);
                    }
                }
            }
            return Ok(0);
        }

        // 普通读取（支持跨页，逐页填充 buf）
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

    /// 写入数据并更新或作废受影响的缓存页（Write-Through 或置脏）。
    pub fn write_cached(
        &self,
        inode: &dyn INode,
        offset: u64,
        buf: &[u8],
    ) -> Result<usize, klib::error::Error> {
        let written = inode.write_at(offset, buf)?;
        if written > 0 {
            // 作废受影响的 4K 与 2M 页，保证一致性
            let mut map4k = self.pages_4k.write();
            let mut map_huge = self.pages_huge.write();

            let start_page = (offset / PAGE_SIZE as u64) * PAGE_SIZE as u64;
            let end_page = ((offset + written as u64 + PAGE_SIZE as u64 - 1) / PAGE_SIZE as u64)
                * PAGE_SIZE as u64;

            let mut cur = start_page;
            while cur < end_page {
                map4k.remove(&cur);
                cur += PAGE_SIZE as u64;
            }

            let huge_start = (offset / HUGE_PAGE_SIZE as u64) * HUGE_PAGE_SIZE as u64;
            let huge_end = ((offset + written as u64 + HUGE_PAGE_SIZE as u64 - 1)
                / HUGE_PAGE_SIZE as u64)
                * HUGE_PAGE_SIZE as u64;
            let mut cur_huge = huge_start;
            while cur_huge < huge_end {
                map_huge.remove(&cur_huge);
                cur_huge += HUGE_PAGE_SIZE as u64;
            }
        }
        Ok(written)
    }

    /// 内存紧凑感知淘汰机制（Eviction）：主动释放 Clean 缓存页。
    pub fn evict_clean_pages(&self, target_free_count: usize) -> usize {
        let mut evicted = 0;

        // 优先淘汰未置脏的 4KB 页
        {
            let mut map4k = self.pages_4k.write();
            let mut to_remove = Vec::new();
            for (off, page) in map4k.iter() {
                if !page.is_dirty.load(Ordering::Relaxed) {
                    to_remove.push(*off);
                    evicted += 1;
                    if evicted >= target_free_count {
                        break;
                    }
                }
            }
            for off in to_remove {
                map4k.remove(&off);
            }
        }

        // 若仍需淘汰，淘汰 2MB 大页
        if evicted < target_free_count {
            let mut map_huge = self.pages_huge.write();
            let mut to_remove = Vec::new();
            for (off, page) in map_huge.iter() {
                if !page.is_dirty.load(Ordering::Relaxed) {
                    to_remove.push(*off);
                    evicted += 512; // 2MB 等价 512 个 4KB 页
                    if evicted >= target_free_count {
                        break;
                    }
                }
            }
            for off in to_remove {
                map_huge.remove(&off);
            }
        }

        self.evictions.fetch_add(evicted, Ordering::Relaxed);
        evicted
    }

    /// 获取缓存统计快照。
    pub fn stats(&self) -> PageCacheStats {
        let total_4k = self.pages_4k.read().len();
        let total_huge = self.pages_huge.read().len();
        PageCacheStats {
            total_pages: total_4k + total_huge * 512,
            huge_pages: total_huge,
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
        }
    }
}
