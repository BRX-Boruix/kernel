//! 面向外部的页帧分配/释放 API。

use core::sync::atomic::Ordering;

use klib::warn;

use arch::PhysFrame;

use super::allocator_core::{MAX_ORDER, ORDER_4K};
use super::{LazyBuddyAllocator, current_cpu_id};

impl LazyBuddyAllocator {
    /// Allocate a frame of order N
    pub fn allocate(&self, order: usize) -> Option<PhysFrame> {
        if order >= MAX_ORDER {
            return None;
        }

        self.alloc_calls.fetch_add(1, Ordering::Relaxed);
        let cpu = current_cpu_id();

        if let Some(idx) = self
            .percpu_pop(cpu, order)
            .or_else(|| self.percpu_refill(cpu, order))
            .or_else(|| self.alloc_global(order, cpu))
            .or_else(|| {
                if order == ORDER_4K {
                    self.reserve_pop()
                } else {
                    None
                }
            })
        {
            self.allocated_frames
                .fetch_add(1 << order, Ordering::Relaxed);
            return Some(PhysFrame::from_paddr_raw((idx * 4096) as u64));
        }

        // Auto-compact on higher-order failure with throttling.
        if order > ORDER_4K {
            let now = self.alloc_calls.load(Ordering::Relaxed);
            let last = self.compact_last_alloc_call.load(Ordering::Relaxed);
            let min_interval = 1024;
            if now.saturating_sub(last) >= min_interval {
                let max_order = self.max_free_order();
                if max_order < order {
                    self.compact_last_alloc_call.store(now, Ordering::Relaxed);
                    self.compact();
                    if let Some(idx) = self.alloc_global(order, cpu) {
                        self.allocated_frames
                            .fetch_add(1 << order, Ordering::Relaxed);
                        return Some(PhysFrame::from_paddr_raw((idx * 4096) as u64));
                    }
                }
            }
        }

        self.alloc_fail.fetch_add(1, Ordering::Relaxed);
        self.alloc_fail_by_order[order].fetch_add(1, Ordering::Relaxed);
        None
    }

    /// 释放前校验：pfn 越界或落在无元数据孔洞（memmap 不可用区段）时
    /// 告警并返回 false。**必须在任何帧元数据解引用（含 refcount）之前
    /// 调用**（审计 #7）：孔洞地址流入 refs_cell 是对 null+offset 的野
    /// 指针 RMW。mod.rs 公开入口与本入口共用此单点校验（S15）。
    pub(crate) fn pfn_managed(&self, pfn: usize) -> bool {
        let cfg = self.config();
        if pfn >= cfg.total_frames {
            warn!("PMM: Deallocate out of bounds pfn {}", pfn);
            return false;
        }
        // 无元数据（孔洞）检查：必须在读取帧元数据前完成，避免空指针解引用。
        let block_idx = pfn / cfg.frames_per_block;
        if unsafe { self.block_ptr(block_idx) }.is_null() {
            warn!(
                "PMM: Deallocate frame with no metadata (hole?): pfn {}",
                pfn
            );
            return false;
        }
        true
    }

    pub fn deallocate(&self, frame: PhysFrame) {
        self.dealloc_calls.fetch_add(1, Ordering::Relaxed);
        let pfn = frame.start_paddr() as usize / 4096;

        if !self.pfn_managed(pfn) {
            return;
        }

        // 在元数据锁保护下校验状态并读取 order（消除无锁读取的 TOCTOU 数据竞争）：
        // 同时把帧标记为瞬态 Freeing，防止释放完成前被并发重复释放。
        let order = match self.deallocate_checked(pfn) {
            Some(order) => order,
            None => {
                warn!("PMM: Double free or invalid free at pfn {}", pfn);
                return;
            }
        };

        if order == ORDER_4K {
            // reserve_push 内部在 reserve_list 锁下判断是否入池（上限 32）；
            // 池满时它会把该 4K 帧回收到全局 buddy（可参与合并）。
            self.reserve_push(pfn);
        } else {
            let cpu = current_cpu_id();
            // percpu_push 把状态改写为 FreePerCpu，溢出后再由合并路径置为 FreeGlobal。
            self.percpu_push(cpu, pfn, order);
        }

        self.allocated_frames
            .fetch_sub(1 << order, Ordering::Relaxed);
    }
}
