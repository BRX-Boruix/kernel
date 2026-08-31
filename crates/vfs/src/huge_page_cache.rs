//! 真·物理大页直通读缓存（D-VFS1-R4 第一阶段 R4-1）。
//!
//! ## 本体如实描述
//!
//! 这是与既有堆缓冲分块缓存（`page_cache.rs`）**并行的新路径**：大块读取的
//! 缓存存储介质是 **mm ORDER_2M 分配的 2MiB 物理大页**，经内核 HHDM 直接映射
//! （`arch::phys_to_virt`，页表映射）访问，而非普通堆 `Vec`。
//!
//! - **存储介质**：`mm::allocate_frames(ORDER_2M)` 分配的 2MiB 物理帧，
//!   通过 HHDM 直接映射别名（内核页表已建立的大页映射）读写；
//! - **键控作用域**（R9-F1 / ADR-023 §1）：与 `page_cache.rs` 一致——
//!   `(节点身份, 文件内偏移)` 二元组，节点身份取 `Arc` 分配地址，
//!   条目钉住一份 `Arc` 克隆防地址复用（淘汰即释放钉引用 + 归还物理帧）；
//! - **淘汰**：`evict` 按 access_count 取最久未访问者，归还物理帧（`deallocate_frame`）；
//! - **写一致性**：`write_cached` 写穿 inode 后作废本节点受影响大页并归还物理帧。
//!
//! ## 生产接入状态（审计 K1）
//!
//! **本模块目前是并行新增路径，尚未接入生产读路径**：
//! - 生产 FileHandle / ramfs 读路径经注入的全局 PageCache（堆缓冲分块缓存）
//!   走 page_cache.rs；本 HugePageDirectCache 仅在 kernel/tests.rs 中作为停机
//!   验证路径被引用，未 set_global 到文件句柄读链路。
//! - 这是**有意的分阶段落地**（见 docs/TODO/huge-page-direct-cache.md 第一阶段 + 回滚）：
//!   大页直通先以并行路径落地并测得数据，再接生产；防止未经验证即替换主读路径。
//! - **生产接线为显式待办（债务登记）**：把大页直通接进 FileHandle 大读路径（作为
//!   全局 PageCache 的补充/前插），须在 R4-3 数据稳定、且一致性/淘汰与既有写路径
//!   对齐后立项实施。当前未接线是诚实状态，不得伪称已接入（S31）。
//!
//! ## 诚实边界（S31）
//!
//! - 本模块证明物理大页确实经页表映射、命中确实从该映射取数（R4-2 提供翻译
//!   证据）；**TLB 收益数据**由 R4-3 的实测周期对比产出，未测得前不宣称存在；
//! - 大页分配失败（无连续 2MiB 物理块）时**如实回退**——本模块返回 None，由调用方
//!   落到堆缓冲分块缓存路径，不假装大页直通成功。

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::RwLock;

use arch::phys_to_virt;
use mm::PhysFrame;
use mm::frame_allocator::{ORDER_2M, allocate_frames, deallocate_frame};

use crate::inode::INode;
use crate::page_cache::{HUGE_PAGE_SIZE, READ_BULK_THRESHOLD_BYTES};

/// 大页对齐掩码（2MiB - 1）。
const HUGE_MASK: u64 = (HUGE_PAGE_SIZE as u64) - 1;

/// 缓存键：(节点身份, 2MiB 对齐基址)。节点身份 = Arc 分配地址。
type HugeKey = (usize, u64);

fn node_key(inode: &Arc<dyn INode>) -> usize {
    Arc::as_ptr(inode) as *const core::ffi::c_void as usize
}

/// 一个物理大页缓存条目：钉住 2MiB 物理帧 + 节点句柄。
///
/// 物理帧经 HHDM 直接映射别名访问（`kernel_base()`），`loaded_len` 是
/// 实际装载的有效字节数（≤ 2MiB，按文件元数据/读回截断），读取越出即判为
/// 需回退或重载，绝不静默读零。
pub struct HugeBlock {
    /// 钉住的节点句柄：既是身份来源也是防地址复用的存活保证。
    #[allow(dead_code)]
    owner: Arc<dyn INode>,
    /// 2MiB 物理帧（ORDER_2M 分配）。
    frame: PhysFrame,
    /// 已装载有效字节数。
    loaded_len: usize,
    /// 淘汰依据：每次命中递增，evict 取最小者受害。
    access_count: AtomicU64,
}

impl HugeBlock {
    /// 经内核 HHDM 直接映射取得的可访问虚拟基址（即页表映射别名）。
    fn kernel_base(&self) -> *mut u8 {
        phys_to_virt(self.frame.start_paddr()) as *mut u8
    }

    /// 从该大页拷出 `[inner, inner+len)`（len ≤ 可用字节数）到 `dst`。
    fn copy_out(&self, inner: usize, dst: &mut [u8]) -> usize {
        let avail = self.loaded_len - inner;
        let n = core::cmp::min(dst.len(), avail);
        unsafe {
            core::ptr::copy_nonoverlapping(self.kernel_base().add(inner), dst.as_mut_ptr(), n);
        }
        n
    }

    /// 把 inode 的 `[base, base+len)` 装载进本大页（经 HHDM 别名直写物理帧）。
    fn load(&mut self, inode: &Arc<dyn INode>, base: u64, len: usize) -> Result<usize, klib::error::Error> {
        let dst = unsafe { core::slice::from_raw_parts_mut(self.kernel_base(), len) };
        let n = inode.read_at(base, dst)?;
        self.loaded_len = n;
        Ok(n)
    }
}

/// 物理帧归一的唯一出口：`HugeBlock` 析构时归还其持有的 2MiB 物理帧。
///
/// `PhysFrame` 是 Copy、无自带 Drop，若此处不归还，则帧的所有权随 Arc 引用
/// 生命周期悬空——尤其并发未命中重复插入时（BTreeMap 的 insert 会替换旧
/// Arc），旧块被丢弃而不归还帧，造成永久泄漏（审计 K2）。把归还收敛到
/// `HugeBlock::drop`（由编译期调用）使任何丢弃路径（insert 替换 /
/// evict / invalidate / 缓存析构）都统一归还，杜绝分散的 deallocate 与双释放。
impl Drop for HugeBlock {
    fn drop(&mut self) {
        deallocate_frame(self.frame);
    }
}

/// 真·物理大页直通读缓存统计。
#[derive(Default, Debug, Clone, Copy)]
pub struct HugeCacheStats {
    pub blocks: usize,
    pub hits: usize,
    pub misses: usize,
    pub evictions: usize,
    pub alloc_fails: usize,
}

/// 真·物理大页直通读缓存。
pub struct HugePageDirectCache {
    blocks: RwLock<BTreeMap<HugeKey, Arc<HugeBlock>>>,
    hits: AtomicUsize,
    misses: AtomicUsize,
    evictions: AtomicUsize,
    alloc_fails: AtomicUsize,
}

impl core::fmt::Debug for HugePageDirectCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HugePageDirectCache")
            .field("blocks", &self.blocks.read().len())
            .field("hits", &self.hits)
            .field("misses", &self.misses)
            .field("evictions", &self.evictions)
            .field("alloc_fails", &self.alloc_fails)
            .finish()
    }
}

/// 析构：直接丢弃映射表即可——每个 `HugeBlock` 的 `Drop` 已负责归还其物理帧。
///
/// 旧实现在此手动 `deallocate_frame` 再 `clear()`，若 `HugeBlock` 同时有 Drop
/// 会双释放；现把归还收敛到 `HugeBlock::drop`（见上），缓存析构只需丢弃 Arc
/// 集合，帧归还由引用归零时自动完成。
impl Drop for HugePageDirectCache {
    fn drop(&mut self) {
        let map = self.blocks.get_mut();
        map.clear();
    }
}

impl HugePageDirectCache {
    pub fn new() -> Self {
        Self {
            blocks: RwLock::new(BTreeMap::new()),
            hits: AtomicUsize::new(0),
            misses: AtomicUsize::new(0),
            evictions: AtomicUsize::new(0),
            alloc_fails: AtomicUsize::new(0),
        }
    }

    /// 分配一个新的 2MiB 物理大页。失败（无连续大块）返回 None。
    fn alloc_huge(&self) -> Option<PhysFrame> {
        match allocate_frames(ORDER_2M) {
            Some(f) => Some(f),
            None => {
                self.alloc_fails.fetch_add(1, Ordering::Relaxed);
                None
            },
        }
    }


    /// 大块读取：命中经物理大页（HHDM 映射）取数，未命中分配大页并装载。
    ///
    /// 返回实际读字节数。**若无法分配物理大页，返回 None**——调用方须回退
    /// 到堆缓冲分块缓存路径（诚实边界，不假装大页直通成功）。
    ///
    /// `offset` 须落在 2MiB 对齐块内；本方法按调用方给定的对齐块装载。
    pub fn read_cached(
        &self,
        inode: &Arc<dyn INode>,
        offset: u64,
        buf: &mut [u8],
    ) -> Option<Result<usize, klib::error::Error>> {
        if buf.is_empty() {
            return Some(Ok(0));
        }
        // 仅服务大块读取；小读由调用方走逐页堆缓存（本对象不负责）。
        if buf.len() < READ_BULK_THRESHOLD_BYTES {
            return Some(Ok(0));
        }

        let block_base = offset & !HUGE_MASK;
        let inner = (offset - block_base) as usize;
        let key = (node_key(inode), block_base);

        // 命中
        {
            let map = self.blocks.read();
            if let Some(block) = map.get(&key) {
                if inner < block.loaded_len {
                    let n = block.copy_out(inner, buf);
                    block.access_count.fetch_add(1, Ordering::Relaxed);
                    self.hits.fetch_add(1, Ordering::Relaxed);
                    return Some(Ok(n));
                }
                // 命中但越出已装载边界：陈旧块，落到重载路径。
            }
        }

        self.misses.fetch_add(1, Ordering::Relaxed);

        // 未命中：分配物理大页。
        let frame = match self.alloc_huge() {
            Some(f) => f,
            None => return None, // 无大页可分配 → 调用方回退堆缓存
        };

        // 装载大小按文件元数据截断（不投机假设满块）。
        // **元数据失败如实传播错误（审计 K3）**：与 `page_cache.rs` 一致，不静默
        // 当成 0 字节返回掩盖底层故障；此时已分配的裸帧须立即归还。
        let needed = match inode.metadata() {
            Ok(m) => {
                if block_base < m.size {
                    core::cmp::min(HUGE_PAGE_SIZE as u64, m.size - block_base) as usize
                } else {
                    0
                }
            },
            Err(e) => {
                deallocate_frame(frame); // 裸帧（尚未进 HugeBlock），须手动归还
                return Some(Err(e));
            },
        };

        let mut block = HugeBlock {
            owner: Arc::clone(inode),
            frame,
            loaded_len: 0,
            access_count: AtomicU64::new(1),
        };
        if needed > 0 {
            match block.load(inode, block_base, needed) {
                Ok(_) => {}
                // 装载失败：不手动归还（HugeBlock::drop 负责归还本帧），
                // 仅返回错误；`block` 随本作用域结束被析构即归还。
                Err(e) => return Some(Err(e)),
            }
        }

        let block = Arc::new(block);
        self.blocks.write().insert(key, block.clone());

        if inner < block.loaded_len {
            let n = block.copy_out(inner, buf);
            Some(Ok(n))
        } else {
            Some(Ok(0))
        }
    }

    /// 写穿 + 作废本节点覆盖 `[offset, offset+len)` 的大页块（归还物理帧）。
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

    /// 作废本节点覆盖区间的大页块并归还物理帧。
    fn invalidate(&self, inode: &Arc<dyn INode>, offset: u64, len: u64) {
        let nk = node_key(inode);
        let start = (offset / HUGE_PAGE_SIZE as u64) * HUGE_PAGE_SIZE as u64;
        let end = ((offset.saturating_add(len).saturating_add(HUGE_MASK))
            / HUGE_PAGE_SIZE as u64)
            * HUGE_PAGE_SIZE as u64;

        let victims: Vec<HugeKey> = {
            let map = self.blocks.read();
            map.range((nk, start)..(nk, end)).map(|(k, _)| *k).collect()
        };
        // 从映射移除即触发 HugeBlock::drop 归还物理帧（无需手动 free）。
        let mut map = self.blocks.write();
        for k in victims {
            map.remove(&k);
        }
    }

    /// 淘汰：归还物理大页直到释放块数达标。按 access_count 升序取受害者（LRU）。
    pub fn evict(&self, target_blocks: usize) -> usize {
        let mut candidates: Vec<(u64, usize, u64, PhysFrame)> = {
            let map = self.blocks.read();
            map.iter()
                .map(|((nk, off), b)| {
                    (
                        b.access_count.load(Ordering::Relaxed),
                        *nk,
                        *off,
                        b.frame,
                    )
                })
                .collect()
        };
        candidates.sort_by(|a, b| (a.0, a.1, a.2).cmp(&(b.0, b.1, b.2)));

        let mut evicted = 0usize;
        let mut drop: Vec<(usize, u64)> = Vec::new();
        for (_, nk, off, _frame) in candidates {
            if evicted >= target_blocks {
                break;
            }
            drop.push((nk, off));
            evicted += 1;
        }

        // 从映射移除即触发 HugeBlock::drop 归还物理帧（无需手动 free）。
        let mut map = self.blocks.write();
        for k in drop {
            map.remove(&k);
        }
        self.evictions.fetch_add(evicted, Ordering::Relaxed);
        evicted
    }

    /// 统计快照。
    pub fn stats(&self) -> HugeCacheStats {
        HugeCacheStats {
            blocks: self.blocks.read().len(),
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            alloc_fails: self.alloc_fails.load(Ordering::Relaxed),
        }
    }

    /// 页表映射证据访问器：取某块物理帧起始物理地址（供测试翻译 HHDM 别名）。
    pub fn frame_paddr(&self, inode: &Arc<dyn INode>, offset: u64) -> Option<u64> {
        let block_base = offset & !HUGE_MASK;
        let key = (node_key(inode), block_base);
        self.blocks.read().get(&key).map(|b| b.frame.start_paddr())
    }
}