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

/// "已归还"哨兵：用于区分"从未登记（0）"与"已归还（DEAD）"。
///
/// `decref` 把未登记帧的 0 翻成该值，从而保证同一帧只被归还一次。
/// `init`（每次分配时调用）会把它重置为 1，故帧被重新分配后可正常复用。
/// 取 `u32::MAX` 是因为正常引用计数不可能达到该值（`incref` 已在接近时断言失败）。
pub const DEAD: u32 = u32::MAX;

/// 登记一个刚分配的物理帧，引用计数置 1（覆盖残留登记，含 DEAD 哨兵）。
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
            // 已归还（哨兵）：该帧不属于任何存活映射，**不得复活**。
            // 若在此 CAS(DEAD→DEAD+1)，计数会绕回 0/1，之后任何 decref 都会
            // 再次返回 true，把已经归还的帧又归还一次（重复释放复活路径）。
            // 保留其"不可再归还"的语义：直接返回，不增计数。
            DEAD => return,
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
///
/// ## 未登记帧（count==0）的语义修正（本轮定位的真实缺陷）
///
/// 旧实现把 `0` 一律当作"按 count=1 处理，直接归还"，即**每次调用都返回 true**。
/// 后果：一个帧首次归还（1→0）后即处于未登记态，此后**任何**针对该地址的
/// `deallocate_frame` 都会再次返回 true，把同一个物理帧反复交还分配器。
/// 实测症状：HDA 驱动的 DMA 缓冲帧（如 0x8a8000/0x8a9000）在一次 boot 内被
/// 释放十余次，而它们从未被重新分配；与此同时这些帧被分配器再次发给其它进程，
/// 进程代码覆盖了驱动的 CORB/RIRB/BDL 内容——设备 DMA 读到的因此是 x86 机器码，
/// 表现为 `bdl/0: 0x0`、LPIB 恒 0、CORB 命令"取走了却没有应答"。
///
/// 修正：未登记帧**只允许归还一次**。用 CAS(0→`DEAD`) 把"已归还"与"从未登记"
/// 区分开——首个 decref 把 0 翻成哨兵值并返回 true，后续 decref 看到哨兵即返回
/// false（不再归还）。这样既保留"reserve 直通帧可被释放一次"的既有能力，
/// 又杜绝重复归还。
pub fn decref(paddr: u64) -> bool {
    let cell = refs_cell(paddr);
    loop {
        match unsafe { (*cell).load(Ordering::Acquire) } {
            // 未登记：CAS 0→DEAD，只有第一个调用者获胜并归还。
            0 => {
                if unsafe { (*cell)
                    .compare_exchange_weak(0, DEAD, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok() }
                {
                    return true;
                }
            }
            // 已归还过：不再归还（防重复释放）。
            DEAD => return false,
            // 归零：CAS 1→DEAD（**直接落到哨兵**，不是落到 0）。
            //
            // 关键：若这里落到 0，后续 decref 会命中上面的 0 分支再做 CAS(0→DEAD)
            // 并**再次返回 true**——重复归还依旧发生（本实现第一版即踩此坑，
            // 实测某帧在一次 boot 内仍被释放三次）。一步落到 DEAD 后，后续
            // decref 立即命中 DEAD 分支返回 false，重复归还才真正被杜绝。
            1 => {
                if unsafe { (*cell)
                    .compare_exchange_weak(1, DEAD, Ordering::AcqRel, Ordering::Acquire)
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
///
/// 语义与 incref/decref 保持一致：
/// - 0（从未登记，如 reserve 直通块）按 1 计；
/// - DEAD（已归还）**按 0 计**——否则会把"已归还的帧"报告成 u32::MAX 引用，
///   误导所有读侧调用方（旧实现只折叠 0，会把哨兵原样返回）。
pub fn count(paddr: u64) -> u32 {
    match unsafe { (*refs_cell(paddr)).load(Ordering::Acquire) } {
        0 => 1,
        DEAD => 0,
        v => v,
    }
}
