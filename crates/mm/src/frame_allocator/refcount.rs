//! 物理帧引用计数（M5 写时复制 COW 用）——MA2 下沉为每帧元数据字段。
//!
//! 写时复制（COW）：`clone_cow` 让父子进程**共享**同一批物理数据帧，仅在
//! 任一方写入时才真正复制。共享后一个物理帧被多个地址空间引用，若某一方
//! 解映射就盲目归还物理帧，会令其它方悬空（悬垂帧/双重释放）。为此为每个
//! 物理帧维护引用计数：
//!
//! - 分配时引用计数初始化为 1（`init`，由 `allocate_frames` 逐帧调用）；
//! - `clone_cow` 共享某帧时 `incref`（计数 +1）；
//! - 请求释放时走 `decref`：计数降到 0 才真正归还物理帧分配器；否则仅减计数。
//!
//! 归还在 `frame_allocator::deallocate_frame` 统一处理，因此所有现有释放路径
//! （`UserAddressSpace` 的 brk 收缩 / unmap_area_pages 等）自动获得 COW 安全，
//! 无需逐个改动调用点。
//!
//! ## 并发模型（MA2 重构的核心论证）
//!
//! 计数存放在 `BuddyFrame.refs`（`AtomicU32` 视图），取代原全局
//! `Mutex<BTreeMap>`——后者让整套分片/per-CPU 无锁化设计在每次 alloc/free
//! 上都排队过同一把锁，且 1GB 内存需约 12MB 堆元数据；帧内 u32 字段零额外
//! 内存、零堆、无全局串行点。
//!
//! 正确性依据 buddy 分配器的既有所有权不变量：
//!
//! 1. **空闲帧的元数据归分配器所有**（shard 锁保护）；`refs` 只在
//!    `Allocated` 状态下被读写。分配路径把帧交给调用者前先 `init(1)`，
//!    归还路径经 `deallocate_checked` 的 shard 锁认领后才触碰元数据——
//!    两端都与本模块对 `refs` 的访问互斥于状态机转换。
//! 2. **incref/decref 只作用于调用方持有 ≥1 引用的活动帧**（COW 协议：
//!    共享前提是映射已存在）。因此同一帧的并发 incref/decref 天然被
//!    "至少一方持引用"约束限定为合法的计数增减，`AtomicU32` RMW 足够。
//! 3. `refs == 0` 仅出现在两种情形：从未经 `allocate_frames` 登记的帧
//!    （如 reserve 直通块）与 decref 归零后的窗口（随后立即走归还）。
//!    按旧 BTreeMap 语义"未登记按 1 处理"，读侧折叠为 1。

use core::sync::atomic::{AtomicU32, Ordering};

use super::ALLOCATOR;
use super::allocator_core::FRAME_SIZE_BYTES;

/// 物理地址 → 该帧 `refs` 字段的原子视图。
///
/// 经 `addr_of_mut!` 定位字段再 cast：`AtomicU32` 与 `u32` 布局兼容，
/// 且字段偏移由 `repr(C)` 固定（order@0/state@1/flags@2/**refs@4**）。
///
/// ## 调用方不变量（审计 #7）
///
/// `paddr` 必须是**分配器管辖且元数据存在**的帧地址（孔洞/越界地址流入
/// 即对 null+offset 野指针 RMW）。公开入口 `deallocate_frame` 已把边界+
/// 孔洞校验前置到任何 refs 触达之前；`incref` 仅由 clone_cow 在已过滤
/// DeviceMmap、逐页 translate 出的 RAM 帧上调用。
#[inline]
fn refs_cell(paddr: u64) -> *mut AtomicU32 {
    debug_assert_eq!(paddr % FRAME_SIZE_BYTES, 0, "frame paddr must be 4K aligned");
    let pfn = (paddr / FRAME_SIZE_BYTES) as usize;
    unsafe {
        let frame = ALLOCATOR.frame_ptr(pfn);
        core::ptr::addr_of_mut!((*frame).refs).cast::<AtomicU32>()
    }
}

/// 登记一个刚分配的物理帧，引用计数置 1（覆盖残留登记）。
pub fn init(paddr: u64) {
    // Relaxed 足够：此刻帧刚脱离分配器、尚无任何其它执行流持有引用。
    unsafe { (*refs_cell(paddr)).store(1, Ordering::Relaxed) }
}

/// 共享某帧（COW）：引用计数 +1。未登记帧按 1 → 2 处理（与旧表语义对齐；
/// COW 协议下 incref 只触达已登记帧，0 分支是不可达的防御性修复路径）。
///
/// 审计 B1：全 CAS 实现——原 fetch_add+条件 store 在 0 分支留有窗口：
/// fetch_add 把 0 变 1 后、store(2) 前并发 decref 看到 1 即 CAS 归零并
/// 归还帧，随后 store(2) 写进**已归还帧**的元数据。CAS(0→2) 单步完成，
/// 无中间态可被抢走。
pub fn incref(paddr: u64) {
    let cell = refs_cell(paddr);
    // AcqRel：与并发的 decref 构成 release/acquire 对，保证"减到 0 后归还"
    // 的决策不会读到滞后的计数。
    loop {
        match unsafe { (*cell).load(Ordering::Acquire) } {
            0 => {
                if unsafe {
                    (*cell)
                        .compare_exchange_weak(0, 2, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                } {
                    return;
                }
            }
            v => {
                assert!(v != u32::MAX, "refcount overflow on frame {:#x}", paddr);
                if unsafe {
                    (*cell)
                        .compare_exchange_weak(v, v + 1, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                } {
                    return;
                }
            }
        }
    }
}

/// 请求释放某帧：引用计数 -1。
///
/// 返回 `true` 表示引用降到 0，调用方（`deallocate_frame`）应真正归还物理帧；
/// 返回 `false` 表示仍有其它引用（如父子 COW 共享），仅减计数、不归还。
pub fn decref(paddr: u64) -> bool {
    let cell = refs_cell(paddr);
    loop {
        match unsafe { (*cell).load(Ordering::Acquire) } {
            // 未登记：按 count=1 处理直接归还；保持 0 不改写（reserve 直通帧
            // 可能再次被查询计数）。
            0 => return true,
            // 归零：CAS 1→0 保证并发双 decref 只有一方看到胜利。
            1 => {
                if unsafe { (*cell)
                    .compare_exchange_weak(1, 0, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok() }
                {
                    return true;
                }
            }
            v => {
                if unsafe { (*cell)
                    .compare_exchange_weak(v, v - 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok() }
                {
                    return false;
                }
            }
        }
    }
}

/// 当前引用计数（未登记按 1 计）。
pub fn count(paddr: u64) -> u32 {
    match unsafe { (*refs_cell(paddr)).load(Ordering::Acquire) } {
        0 => 1,
        v => v,
    }
}
