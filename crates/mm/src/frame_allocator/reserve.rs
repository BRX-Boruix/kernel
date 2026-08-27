//! 预留(reserve)页管理。
//!
//! 维护两级紧急预留池（ADR-020 P2「类型化分级紧急储备」）：
//! - **Regular 池**（容量 [`RESERVE_CAP_PAGES`]）：既有行为保持不动——常规
//!   分配在全局空闲耗尽时兜底；池满时释放页回收到全局 buddy（可参与合并）。
//! - **Critical 池**（容量 [`CRITICAL_RESERVE_CAP_PAGES`]）：启动时单独截留，
//!   仅经 [`ReserveLevel::Critical`] 的分配路径取用（页表页等"失败即不可恢复"
//!   路径），与 Regular 池物理隔离，杜绝 OOM 边缘常规分配与关键路径抢同一口锅。
//!
//! 语义注记（v1）：Critical 池是启动截留的存量兜底，**只出不进**——归还的帧
//! （无论来源）一律走常规释放路径；池耗尽后关键路径退化为与现状相同的
//! "无储备兜底"（概率极低，且该时刻本就全局 OOM）。分级储备的回补与水位
//! 自适应属于 ADR-020 P4（遥测闭环）范畴，不在本实现。

use core::sync::atomic::Ordering;

use klib::{info, warn};

use super::LazyBuddyAllocator;
use super::allocator_core::{FrameState, ORDER_4K};

/// 分配危急度级别：决定 `allocate` 失败兜底时可否动用紧急预留池。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReserveLevel {
    /// 常规分配：可动用 Regular 紧急池（既有行为）。
    Regular,
    /// 关键分配（页表页、中断上下文等失败即不可恢复）：可动用 Critical 池。
    Critical,
}

/// 紧急预留池容量上限（单位：4K 页）。
///
/// 固定上限保证 reserve 池只保留少量兜底页，不会随反复 churn 无限增长。
/// 公开给内核层做水位判断（vfs1 D4 / ADR-023 §7：RamFS 水位钩子以
/// "reserve_count 低于容量的四分之一"为紧张信号），避免阈值魔法值散落。
pub const RESERVE_CAP_PAGES: usize = 32;

/// Critical 紧急预留池容量上限（单位：4K 页）。
///
/// 独立于 Regular 池的启动截留；只被 [`ReserveLevel::Critical`] 分配消耗。
/// 数值（16 页）为初版定价，随首个真实 OOM 演练修订（ADR-020 §4）。
pub const CRITICAL_RESERVE_CAP_PAGES: usize = 16;

impl LazyBuddyAllocator {
    /// 兼容名（历史关联常量）；真实容量见模块级 [`RESERVE_CAP_PAGES`]。
    const RESERVE_CAP: usize = RESERVE_CAP_PAGES;
    const CRITICAL_RESERVE_CAP: usize = CRITICAL_RESERVE_CAP_PAGES;

    /// 按级别从对应紧急池弹出一帧（无则 `None`）。
    pub(crate) fn reserve_pop_for(&self, level: ReserveLevel) -> Option<usize> {
        match level {
            ReserveLevel::Regular => self.pop_from_pool(
                &self.reserve_list,
                &self.reserve_count,
            ),
            ReserveLevel::Critical => self.pop_from_pool(
                &self.critical_reserve_list,
                &self.critical_reserve_count,
            ),
        }
    }

    fn pop_from_pool(
        &self,
        list: &spin::Mutex<super::percpu_cache::ReserveList>,
        count: &core::sync::atomic::AtomicUsize,
    ) -> Option<usize> {
        let mut list = list.lock();
        if let Some(head) = list.head {
            unsafe {
                let frame = self.frame_ptr(head);
                list.head = (*frame).next;
                self.reset_frame_with(frame, ORDER_4K as u8);
            }
            count.fetch_sub(1, Ordering::Relaxed);
            return Some(head);
        }
        None
    }

    /// 把一个 4K 帧放入应急 reserve 池。
    ///
    /// S18 池生命周期（成文）：reserve 池帧以 `FrameState::Allocated` 标记并
    /// 挂在 `reserve_list` 上，**仅**通过 `pop_from_pool` 出池复用（紧急分配
    /// 路径），或池满时经 [`Self::free_and_merge`] 回收到全局 buddy 合并。
    /// 出池帧与全局 buddy 正常交互；**不得**对仍在池中的帧重复调用
    /// `reserve_push` 或与外部 allocator 交换（双重分配/账目不一致）。池上限
    /// `RESERVE_CAP` 决定常驻应急帧上界，超限帧即回收到 buddy。
    pub(crate) fn reserve_push(&self, pfn: usize) {
        let mut list = self.reserve_list.lock();
        // 把"容量判断"与"入池"收敛到同一临界区内：多 CPU 并发释放时，
        // 不会出现都通过 `< RESERVE_CAP` 检查、从而令 reserve_count 超出上限的情况。
        if self.reserve_count.load(Ordering::Relaxed) >= Self::RESERVE_CAP {
            // 池已满：先释放 reserve 锁，再回收到全局 buddy（可参与后续合并），
            // 避免这些 4K 帧被 reserve 池独占、永不合并而加剧碎片化。
            drop(list);
            self.free_and_merge(pfn, ORDER_4K);
            return;
        }
        unsafe {
            self.link_frame_as(pfn, ORDER_4K as u8, FrameState::Allocated, list.head);
        }
        list.head = Some(pfn);
        self.reserve_count.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn init_reserve(&self, pages: usize) {
        let mut added = 0usize;
        let mut first_pfn = 0usize;
        let mut last_pfn = 0usize;
        while added < pages {
            if let Some(pfn) = self.alloc_global(ORDER_4K, 0) {
                if added == 0 {
                    first_pfn = pfn;
                }
                last_pfn = pfn;
                self.reserve_push(pfn);
                added += 1;
            } else {
                break;
            }
        }
        if added > 0 {
            info!(
                "PMM: Reserved {} emergency pages (pfn {}..{} = phys 0x{:x}-0x{:x})",
                added,
                first_pfn,
                last_pfn,
                first_pfn * 4096,
                last_pfn * 4096
            );
        } else {
            warn!("PMM: Failed to reserve emergency pages");
        }
    }

    /// 从全局 buddy 截留页填充 Critical 池（ADR-020 P2）。
    ///
    /// 与 [`Self::init_reserve`] 的差异只在入池目标：Critical 池容量上限独立
    /// 判定（`CRITICAL_RESERVE_CAP`），不足时截留页回收到全局 buddy。
    pub(crate) fn init_reserve_critical(&self, pages: usize) {
        let mut added = 0usize;
        let mut first_pfn = 0usize;
        let mut last_pfn = 0usize;
        while added < pages {
            if let Some(pfn) = self.alloc_global(ORDER_4K, 0) {
                let mut list = self.critical_reserve_list.lock();
                if self.critical_reserve_count.load(Ordering::Relaxed) >= Self::CRITICAL_RESERVE_CAP
                {
                    drop(list);
                    self.free_and_merge(pfn, ORDER_4K);
                    break;
                }
                if added == 0 {
                    first_pfn = pfn;
                }
                last_pfn = pfn;
                unsafe {
                    self.link_frame_as(pfn, ORDER_4K as u8, FrameState::Allocated, list.head);
                }
                list.head = Some(pfn);
                self.critical_reserve_count.fetch_add(1, Ordering::Relaxed);
                added += 1;
            } else {
                break;
            }
        }
        if added > 0 {
            info!(
                "PMM: Reserved {} critical emergency pages (pfn {}..{} = phys 0x{:x}-0x{:x})",
                added,
                first_pfn,
                last_pfn,
                first_pfn * 4096,
                last_pfn * 4096
            );
        } else {
            warn!("PMM: Failed to reserve critical emergency pages");
        }
    }
}