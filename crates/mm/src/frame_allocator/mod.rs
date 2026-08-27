mod allocator_core;
mod api;
mod buddy;
mod compact;
mod init;
mod percpu;
mod percpu_cache;
mod refcount;
mod reserve;
mod stats;

use core::mem::size_of;

use arch::{PhysFrame, phys_to_virt};
use limine::{MemmapEntry, NonNullPtr};
use spin::Once;

use allocator_core::{LazyBuddyAllocator, MAX_ORDER, ORDER_4K};
use percpu_cache::{FreeListTable, PerCpuCache, PerCpuCacheSet};

pub use allocator_core::{FRAME_SIZE_BYTES, HUGE_FRAME_SIZE_BYTES, ORDER_1G, ORDER_2M};
pub use compact::{compact_now, ipi_drain_current_cpu, set_remote_drain};
pub use reserve::{CRITICAL_RESERVE_CAP_PAGES, RESERVE_CAP_PAGES, ReserveLevel};
pub use init::dropped_uninit_frames;
pub use refcount::{count as frame_refcount, decref as frame_decref, incref as frame_incref};
pub use stats::reset_stats as reset_frame_stats;
pub use stats::{FrameAllocatorStats, PmmFragStats, frag_stats, reset_stats, stats};

/// 获取物理页帧总数。
pub fn total_frames() -> usize {
    ALLOCATOR.config().total_frames
}

// Global allocator instance
static ALLOCATOR: LazyBuddyAllocator = LazyBuddyAllocator::new();
static FREE_LISTS: Once<FreeListTable> = Once::new();
static PER_CPU: PerCpuCacheSet = PerCpuCacheSet::new();

/// 当前 CPU id 的读取器（函数指针，返回当前 LAPIC/CPU id）。
/// 由 arch 层在 SMP 初始化时注入。单核时默认为 0。
static CPU_ID_READER: spin::Once<fn() -> usize> = spin::Once::new();

/// 注入当前 CPU id 的读取函数（由 SMP 子系统调用）。
pub fn set_cpu_id_reader(f: fn() -> usize) {
    let _ = CPU_ID_READER.call_once(|| f);
}

/// 获取当前 CPU id。
pub(crate) fn current_cpu_id() -> usize {
    match CPU_ID_READER.get() {
        Some(f) => f(),
        None => 0,
    }
}

/// 计算容纳 `need_frames` 个连续帧所需的最小 order（满足 2^order ≥ need_frames）。
///
/// 上限为 `MAX_ORDER - 1`（buddy 能分配的最大块）。`need_frames` 必须 ≥ 1。
#[inline]
fn order_for_need_frames(need_frames: usize) -> usize {
    if need_frames <= 1 {
        return 0;
    }
    // ceil(log2(need_frames)): 最小的 2^order ≥ need_frames。
    // need_frames=2 → 2.next_power_of_two()=2 → trailing_zeros=1 → order=1 ✓
    // 注意不可用 (need_frames-1)：1.next_power_of_two()=1（1 已是 2^0）→ order=0，
    // 又回到旧 off-by-one。旧实现 (bits-1-(need_frames-1).leading_zeros()) 对
    // need_frames=2 也只得 0，只分配 1 帧却写入 count 个 PerCpuCache → 越界写（S19 回归）。
    let order = need_frames.next_power_of_two().trailing_zeros() as usize;
    order.min(MAX_ORDER - 1)
}

/// 依据实际 CPU 数初始化 per-CPU 页帧缓存（自适应核数）。
///
/// 缓存数组从**物理帧分配器**分配连续帧，经 HHDM 映射为 `&'static mut [PerCpuCache]`，
/// 而非从有限的内核堆分配，从而不占用 4MB 堆、也不受核数导致的堆容量限制。
/// 须在任何 AP 使用帧分配前调用（内核在 SMP 启动前按 Limine 响应注入 CPU 数）。
pub fn init_percpu_caches(cpu_count: usize) {
    let count = cpu_count.max(1);

    // 计算所需连续帧数与可容纳的最小 order（2^order 个 4KB 帧）。
    // order 上限 MAX_ORDER-1：buddy 能分配的最大块（2^(MAX_ORDER-1) 帧）。
    // S19：count*size_of 无保护乘法在极端 count 下可回绕——saturating_mul
    // 保证字节数不归零（归零会让后续 div_ceil 得 0 帧、order 又退化为旧越界写）。
    let bytes = count.saturating_mul(size_of::<PerCpuCache>());
    let need_frames = bytes.div_ceil(4096);
    let order = order_for_need_frames(need_frames);

    // 注意：这里不能走公共 `allocate_frames`（会先查 per-CPU 缓存，而缓存此时
    // 尚未初始化 → panic）。直接走全局空闲列表分配缓存数组本身的物理帧。
    let idx = ALLOCATOR
        .alloc_global(order, 0)
        .expect("failed to allocate per-CPU cache frames");
    let start = PhysFrame::from_paddr_raw((idx * 4096) as u64);
    let base = phys_to_virt(start.start_paddr()) as *mut u8;

    // 清零整个分配区
    unsafe { core::ptr::write_bytes(base, 0, (1 << order) * 4096) };

    // 映射为可写 slice（每个槽位一个 PerCpuCache）
    let caches: &'static mut [PerCpuCache] =
        unsafe { core::slice::from_raw_parts_mut(base as *mut PerCpuCache, count) };
    for c in caches.iter_mut() {
        *c = PerCpuCache::new();
    }

    PER_CPU.init(caches);
}

unsafe impl Send for LazyBuddyAllocator {}
unsafe impl Sync for LazyBuddyAllocator {}

/// Initialize the global allocator
pub unsafe fn init(mmap: &[NonNullPtr<MemmapEntry>]) {
    unsafe {
        ALLOCATOR.init(mmap);
    }
}

/// Allocate a physical frame
pub fn allocate_frame() -> Option<PhysFrame> {
    allocate_frames(ORDER_4K)
}

/// Allocate a physical frame from the Critical emergency pool (ADR-020 P2).
///
/// 页表页等"失败即不可恢复"的分配路径使用此入口，确保在常规 32 页紧急池
/// 已被耗尽时仍有一份独立的 16 页备用池可兜底，与常规分配不竞争同一口锅。
pub fn allocate_frame_critical() -> Option<PhysFrame> {
    allocate_frames_critical(ORDER_4K)
}

/// Allocate physical frames with specific order
pub fn allocate_frames(order: usize) -> Option<PhysFrame> {
    let f = ALLOCATOR.allocate(order)?;
    Some(register_frames(f, order))
}

/// Allocate physical frames from the Critical emergency pool (ADR-020 P2).
///
/// 语义同 [`allocate_frames`]，但全局空闲耗尽后的兜底路径切换至
/// Critical 紧急池——页表页、中断上下文等不可失败分配的安全阀。
pub fn allocate_frames_critical(order: usize) -> Option<PhysFrame> {
    let f = ALLOCATOR.allocate_with_level(order, ReserveLevel::Critical)?;
    Some(register_frames(f, order))
}

/// 登记一块物理帧的引用计数（`allocate_frames` / `allocate_frames_critical`
/// 的共享尾递归）。
fn register_frames(f: PhysFrame, order: usize) -> PhysFrame {
    let n = 1usize << order;
    for i in 0..n {
        refcount::init(f.start_paddr() + (i * 4096) as u64);
    }
    f
}

/// Deallocate a physical frame
///
/// **先校验后变更**（审计 #7）：pfn 越界/孔洞检查必须发生在任何帧元数据
/// 解引用（含 refcount 的 refs_cell）之前——孔洞地址流入引用计数即对
/// null+offset 野指针 RMW。校验通过后先递减引用计数；仅当引用降到 0 才
/// 真正归还物理帧分配器（COW 安全）。
pub fn deallocate_frame(frame: PhysFrame) {
    let pfn = frame.start_paddr() as usize / 4096;
    if !ALLOCATOR.pfn_managed(pfn) {
        return;
    }
    if refcount::decref(frame.start_paddr()) {
        ALLOCATOR.deallocate(frame);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// order 必须满足最小覆盖：2^order ≥ need_frames（S19 回归——旧实现
    /// 对 need_frames=2 得 order=0，只分配 1 帧却写入 count 个 PerCpuCache，
    /// 越界写内存）。
    #[test]
    fn order_covers_need_frames() {
        for need in 1..=64usize {
            let order = order_for_need_frames(need);
            let cap = 1usize << order;
            assert!(
                cap >= need,
                "need_frames={need} -> order={order} (cap={cap}) under-covers"
            );
        }
    }

    /// 精确校验 off-by-one 触发的具体点：need_frames=2 必须给 order=1（2 帧），
    /// 而不是旧实现的 0（1 帧）。
    #[test]
    fn two_frames_needs_order_one() {
        assert_eq!(order_for_need_frames(2), 1, "need_frames=2 must allocate 2 frames");
    }

    /// 幂等边界：1 帧 order=0；2 的幂次仍取对数值（不浪费、不超配）。
    #[test]
    fn exact_powers_of_two() {
        assert_eq!(order_for_need_frames(1), 0);
        assert_eq!(order_for_need_frames(2), 1);
        assert_eq!(order_for_need_frames(4), 2);
        assert_eq!(order_for_need_frames(8), 3);
        assert_eq!(order_for_need_frames(16), 4);
    }

    /// 非 2 的幂次向上取整到下一个 2 的幂。
    #[test]
    fn non_power_of_two_rounds_up() {
        assert_eq!(order_for_need_frames(3), 2); // 2^2=4 >= 3
        assert_eq!(order_for_need_frames(5), 3); // 2^3=8 >= 5
        assert_eq!(order_for_need_frames(9), 4); // 2^4=16 >= 9
        assert_eq!(order_for_need_frames(17), 5);
    }
}
