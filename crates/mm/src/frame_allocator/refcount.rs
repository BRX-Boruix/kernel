//! 物理帧引用计数（M5 写时复制 COW 用）。
//!
//! 写时复制（COW）：`clone_cow` 让父子进程**共享**同一批物理数据帧，仅在
//! 任一方写入时才真正复制。共享后一个物理帧被多个地址空间引用，若某一方
//! 解映射就盲目归还物理帧，会令其它方悬空（悬垂帧/双重释放）。为此为每个
//! 物理帧维护引用计数：
//!
//! - 分配时引用计数初始化为 1（`init`）；
//! - `clone_cow` 共享某帧时 `incref`（计数 +1）；
//! - 请求释放时走 `decref`：计数降到 0 才真正归还物理帧分配器；否则仅减计数。
//!
//! 归还在 `frame_allocator::deallocate_frame` 统一处理，因此所有现有释放路径
//! （`UserAddressSpace` 的 brk 收缩 / unmap_area_pages 等）自动获得 COW 安全，
//! 无需逐个改动调用点。
//!
//! 未登记引用计数的帧（理论上不应发生）按 `count=1` 处理：释放时直接归还。

use alloc::collections::BTreeMap;
use spin::Mutex;

/// 引用计数表：物理地址 → 引用计数。
static REFS: Mutex<BTreeMap<u64, u32>> = Mutex::new(BTreeMap::new());

/// 登记一个刚分配的物理帧，引用计数置 1（覆盖残留登记）。
pub fn init(paddr: u64) {
    REFS.lock().insert(paddr, 1);
}

/// 共享某帧（COW）：引用计数 +1。未登记帧按 1 → 2 处理。
pub fn incref(paddr: u64) {
    let mut m = REFS.lock();
    *m.entry(paddr).or_insert(1) += 1;
}

/// 请求释放某帧：引用计数 -1。
///
/// 返回 `true` 表示引用降到 0，调用方（`deallocate_frame`）应真正归还物理帧；
/// 返回 `false` 表示仍有其它引用（如父子 COW 共享），仅减计数、不归还。
pub fn decref(paddr: u64) -> bool {
    let mut m = REFS.lock();
    match m.get_mut(&paddr) {
        Some(c) if *c > 1 => {
            *c -= 1;
            false
        }
        Some(_) => {
            m.remove(&paddr);
            true
        }
        // 未登记：按 count=1 处理，归还。
        None => true,
    }
}

/// 当前引用计数（未登记按 1 计）。
pub fn count(paddr: u64) -> u32 {
    REFS.lock().get(&paddr).copied().unwrap_or(1)
}
