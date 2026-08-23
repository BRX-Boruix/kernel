//! 空闲页压缩。
//!
//! 把 per-CPU 缓存中的空闲页回收到全局 buddy 系统，从而合并出更大的连续块。
//!
//! 所有权不变量（mm1.md MA1）：per-CPU 缓存槽位只允许属主 CPU 无锁触碰
//! （`with_cache` 是裸指针转发，无任何同步）。本地压缩只处理当前 CPU 槽；
//! 跨核排空经 **IPI 邮箱**（MA1b）完成——请求核发 IPI，目标核在自身中断
//! 上下文里排空**自己的**槽并回写结果，属主不变量全程保持。

use core::sync::atomic::{AtomicU32, Ordering};

use klib::warn;

use super::allocator_core::{MAX_ORDER, for_each_global_list};
use super::{ALLOCATOR, LazyBuddyAllocator, PER_CPU, current_cpu_id};

/// 邮箱状态：空闲。
const MAILBOX_IDLE: u32 = 0;
/// 邮箱状态：请求已投递，等待属主处理。
const MAILBOX_PENDING: u32 = 1;
/// 完成标记位（bit31）：置位时低 31 位 = 本次实际排空的帧数。
const MAILBOX_DONE: u32 = 1 << 31;

/// 每 CPU 排空邮箱。索引 = 紧凑 CPU 槽位（上限 256 = LAPIC id 全空间，
/// 槽位本身即从该空间分配）。仅属主 CPU 写自己的 DONE 结果；请求核只在
/// 属主完成（DONE 置位）后读取计数并复位——无任何裸跨槽元数据访问。
static MAILBOXES: [AtomicU32; 256] = [const { AtomicU32::new(MAILBOX_IDLE) }; 256];

/// 跨核投递函数（MA1b 注入点）：`fn(目标槽位) -> bool`。由 kernel 层接线到
/// arch 的 LAPIC ICI + 槽位反查表；mm 保持架构中立。返回 false = 投递失败。
type RemoteDrain = fn(usize) -> bool;
static REMOTE_DRAIN: spin::Once<RemoteDrain> = spin::Once::new();

/// 注入跨核 IPI 投递函数（kernel 启动路径在 SMP 初始化后调用一次）。
pub fn set_remote_drain(f: RemoteDrain) {
    let _ = REMOTE_DRAIN.call_once(|| f);
}

/// IPI 到达回调（由 kernel 注册进 `interrupts::register_ipi_handler`）：
/// 目标核排空**自己的**缓存并把结果写回自己的邮箱。
///
/// 写入纪律（审计 #6）：仅当邮箱处于 `PENDING` 才 CAS 写入 `DONE`——
/// - **杂散 IPI**（邮箱本为 IDLE）：丢弃结果，绝不污染邮箱（无条件写
///   DONE 会让该槽永卡、从此被请求方跳过）；
/// - **迟到完成**（请求方已超时把邮箱复位为 IDLE）：同样丢弃——排空本身
///   已真实改变分配器状态（帧入全局 buddy），只是计数不再入账。
/// 可见性由请求方超时分支的 warn 负责，此处不重复告警。
pub fn ipi_drain_current_cpu() {
    let cpu = current_cpu_id();
    let drained = ALLOCATOR.drain_percpu_current() as u32;
    let mailbox = &MAILBOXES[cpu & 0xFF];
    let _ = mailbox.compare_exchange(
        MAILBOX_PENDING,
        MAILBOX_DONE | drained,
        Ordering::Release,
        Ordering::Acquire,
    );
}

/// 等待目标核确认的有界轮询轮数。与 serial TX 上限（AM2）同一防自旋纪律：
/// 正常投递+排空在微秒级完成；超限说明目标核失联，降级为本地排空并如实
/// 告警，绝不永久自旋拖死发起核（那会把内存压力升级成全系统停机）。
const DRAIN_ACK_POLL_ROUNDS: usize = 200_000_000;

impl LazyBuddyAllocator {
    /// 排空**当前 CPU** 缓存回全局 buddy，返回排空的帧数。
    fn drain_percpu_current(&self) -> usize {
        let cpu = current_cpu_id();
        let mut drained = 0usize;
        for order in 0..MAX_ORDER {
            loop {
                let pfn = self.percpu_pop_raw(cpu, order);
                if let Some(pfn) = pfn {
                    self.free_and_merge(pfn, order);
                    drained = drained.saturating_add(1);
                } else {
                    break;
                }
            }
        }
        drained
    }

    /// 当前最大空闲块阶（决策压缩是否值得执行）。
    ///
    /// 全局链表各分片有锁可安全遍历；per-CPU 部分**只读当前 CPU 槽的计数**
    /// （所有权不变量）。其它 CPU 缓存中的空闲页不计入——低估只会让压缩更
    /// 早触发（安全侧偏差），绝不产生数据竞争。
    pub(crate) fn max_free_order(&self) -> usize {
        let mut free_global = [0usize; MAX_ORDER];
        for_each_global_list(|order, _shard, list| {
            let mut cur = list.head;
            while let Some(pfn) = cur {
                free_global[order] += 1;
                unsafe {
                    let frame = self.frame_ptr(pfn);
                    cur = (*frame).next;
                }
            }
        });
        let mut free_percpu = [0usize; MAX_ORDER];
        let cpu = current_cpu_id();
        debug_assert!(cpu < PER_CPU.cpu_count(), "cpu slot out of range");
        if cpu < PER_CPU.cpu_count() {
            PER_CPU.with_cache(cpu, |cache| {
                for order in 0..MAX_ORDER {
                    free_percpu[order] += cache.counts[order] as usize;
                }
            });
        }
        for order in (0..MAX_ORDER).rev() {
            if free_global[order] + free_percpu[order] > 0 {
                return order;
            }
        }
        0
    }

    pub(crate) fn compact(&self) {
        let before = self.max_free_order();
        self.compact_calls.fetch_add(1, Ordering::Relaxed);
        let mut drained = self.drain_percpu_current();
        drained += self.drain_remote_caches();
        self.compact_drained.fetch_add(drained, Ordering::Relaxed);
        let after = self.max_free_order();
        self.compact_last_before.store(before, Ordering::Relaxed);
        self.compact_last_after.store(after, Ordering::Relaxed);
        if after > before {
            self.compact_success.fetch_add(1, Ordering::Relaxed);
        }
        warn!("PMM: compact triggered drained={}", drained);
    }

    /// 跨核排空（MA1b）：向每个其它在线 CPU 的邮箱投递排空请求并等待确认。
    ///
    /// 未注入投递函数（SMP 未初始化/单核）时为空操作；单个目标投递失败或
    /// 确认超时都只跳过该核并告警——压缩是尽力而为的优化，绝不因它停机。
    fn drain_remote_caches(&self) -> usize {
        let Some(send) = REMOTE_DRAIN.get() else {
            return 0;
        };
        let me = current_cpu_id();
        let count = PER_CPU.cpu_count();
        let mut total = 0usize;
        for slot in 0..count {
            if slot == me {
                continue;
            }
            // 仅对已注册 LAPIC id 的槽位发起（未上线槽位无 IPI 目标）。
            let mailbox = &MAILBOXES[slot & 0xFF];
            if mailbox.load(Ordering::Acquire) != MAILBOX_IDLE {
                continue; // 上一次请求尚未被消费：该核正忙，跳过不排队
            }
            mailbox.store(MAILBOX_PENDING, Ordering::Release);
            if !send(slot) {
                warn!("PMM: remote drain send failed slot={} (skip)", slot);
                mailbox.store(MAILBOX_IDLE, Ordering::Release);
                continue;
            }
            let mut acked = false;
            for _ in 0..DRAIN_ACK_POLL_ROUNDS {
                let v = mailbox.load(Ordering::Acquire);
                if v & MAILBOX_DONE != 0 {
                    total += (v & !MAILBOX_DONE) as usize;
                    mailbox.store(MAILBOX_IDLE, Ordering::Release);
                    acked = true;
                    break;
                }
                core::hint::spin_loop();
            }
            if !acked {
                // 超时闭环（审计 #6）：CAS(PENDING→IDLE) 复位邮箱，让该槽
                // 未来可再被投递；若 CAS 失败说明目标核恰在本轮询结束后完成，
                // 吸收其计数——结果不丢、邮箱也不残留 PENDING 永卡。
                match mailbox.compare_exchange(
                    MAILBOX_PENDING,
                    MAILBOX_IDLE,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => warn!("PMM: remote drain ack timeout slot={} (skip)", slot),
                    Err(v) => {
                        total += (v & !MAILBOX_DONE) as usize;
                        mailbox.store(MAILBOX_IDLE, Ordering::Release);
                        warn!("PMM: remote drain late-ack slot={} (absorbed)", slot);
                    }
                }
            }
        }
        total
    }
}

pub fn compact_now() {
    ALLOCATOR.compact();
}
