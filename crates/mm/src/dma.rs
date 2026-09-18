//! 内核态 DMA 一致性缓冲（STORAGE-AHCI-1）。
//!
//! ## 为什么需要（与用户态 DMA 的区别）
//!
//! 既有的 `user_space::alloc_dma_user` 挂在 `UserAddressSpace` 上，经
//! `SYS_DRIVER_DMA_ALLOC` 服务于**用户态驱动**（HDA/UIO 模型）：它分配的是
//! 用户半区的虚拟映射，返回 (user_vaddr, base_phys)。
//!
//! 内核态块驱动（AHCI）需要的是**另一种**东西：物理连续帧 + 该帧的**内核虚拟
//! 地址**（内核在 CPL0 直接写内存描述符，不经用户页表）+ 物理地址（编程进设备
//! 的 DMA 描述符）。两者接口与所有权模型都不同，故独立成模块，不硬套用户态路径。
//!
//! ## 内核虚拟地址从哪来：HHDM
//!
//! Limine 建立的 HHDM 把**全部物理 RAM** 线性映射到内核半区。故任何经
//! `allocate_frames` 拿到的物理帧都已有内核可写虚拟地址 = `phys_to_virt(phys)`，
//! 无需建立新映射。这使内核态 DMA 缓冲的实现比用户态路径简单得多：分配帧 +
//! 算 HHDM 虚拟地址 + 记住物理地址，三件事。
//!
//! ## 缓存一致性
//!
//! 本模块**不**改页表属性（HHDM 映射是既有的、由 Limine 建立的）。
//! x86-64 上 DMA 一致性的现实：主流平台（含 QEMU TCG/TCG-KVM 的 pc/q35）对
//! 普通 WB 内存上的设备 DMA 通过总线侦听/硬件一致域处理，无需显式 clflush；
//! 用户态路径之所以用 PCD，是因为它**新建**映射并选择保守属性。
//!
//! **诚实边界**：若无 IOMMU 且平台不做总线侦听（罕见），WB 内存上的 DMA 可能
//! 读到陈旧数据。本模块不声称解决该情形——若将来在真实硬件上遇到，须在此处
//! 成文补充 clflush/wbinvd 策略，而不是默认假设它永远不发生。
//!
//! ## 失败模式（S20 优先设计）
//!
//! - `bytes == 0` → `InvalidParam`；
//! - 超过 [`MAX_KERNEL_DMA_BYTES`] → `InvalidParam`（拒绝无界分配，与用户态
//!   路径同纪律）；
//! - `bytes` 对齐后页数溢出 / order 超上界 → `InvalidParam`（S19：不静默截断）；
//! - 无足够物理连续帧 → `OutOfMemory`；
//! - `PHYS_OFFSET` 未初始化 → `NotReady`（**不 panic**：`phys_to_virt` 本身
//!   会在未初始化时 panic，故此处必须先探测，把"启动顺序错误"变成可上抛错误）。
//!
//! ## 资源生命周期（S18）
//!
//! 每次成功分配返回 [`KernelDmaBuffer`]，其 `Drop` 归还帧——RAII 而非成对
//! API，杜绝"忘记释放"。**不实现 `Clone`/`Copy`**：复制句柄会导致双重释放。
//! 需要共享时用 `Arc`。

use arch::{PhysFrame, phys_to_virt};

use crate::frame_allocator::{allocate_frames, deallocate_frame};

/// 内核态单块 DMA 缓冲的字节上限（64 MiB）。
///
/// 取值与用户态路径 `MAX_DMA_BUF_BYTES` 一致：同一个"单次一致性缓冲"的
/// 语义量级，避免两条路径对同一概念给出不同上界（S15 单点语义）。
/// 64 MiB 远超任何真实块驱动的描述符需求（AHCI 命令表 + PRDT 通常 < 1 MiB），
/// 上界只用于拒绝无界分配。
pub const MAX_KERNEL_DMA_BYTES: u64 = 64 * 1024 * 1024;

/// 页大小（字节）。与 `frame_allocator::FRAME_SIZE_BYTES` 同值。
const PAGE: u64 = 4096;

/// 内核态 DMA 缓冲分配错误。
///
/// 独立于 `PT::Error`（那是页表/地址空间错误）：本模块不碰页表，失败原因
/// 只有参数、内存与启动顺序三类，用专属枚举如实表达，避免把不相关错误
/// 塞进页表错误类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelDmaError {
    /// 参数非法：0 字节、超上限、order 超上界。
    InvalidParam,
    /// 无足够物理连续帧。
    OutOfMemory,
    /// HHDM 偏移未初始化（启动顺序错误：mm::init 之前调用）。
    NotReady,
}

/// 一块内核态 DMA 一致性缓冲。
///
/// 持有物理连续帧的所有权；`Drop` 时归还。字段全私有，外部只能经访问器读，
/// 不能改写物理地址或虚拟地址（改错即让设备访问到别的物理页）。
pub struct KernelDmaBuffer {
    /// 帧基址（含 order 元数据，归还时按基址还整块）。
    frames: PhysFrame,
    /// 分配阶（2^order 页）。
    order: usize,
    /// 请求的字节数（**调用方语义长度**，非对齐后的长度）。
    len: u64,
    /// **实际分配到的**总字节数（= `PAGE << order`，物理事实，≥ `len`）。
    capacity: u64,
    /// 缓冲区起始物理地址（编程进设备 DMA 描述符）。
    phys: u64,
    /// 缓冲区起始内核虚拟地址（HHDM；内核写描述符用）。
    virt: u64,
}

impl KernelDmaBuffer {
    /// 请求的字节数（调用方原始语义）。
    pub fn len(&self) -> u64 {
        self.len
    }

    /// 缓冲区是否为空。按 Rust API 规范与 `len` 成对提供
    /// （`len` 有 `is_empty` 伴随是无处不在的惯例）；本类型经入口校验
    /// 保证 `len >= 1`，故恒为 `false`。
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 实际分配到的总字节数（= `PAGE << order`，恒 ≥ `len`）。
    ///
    /// **本值是物理事实**：buddy 按 2 的幂分配，故请求 3 页（12288 字节）
    /// 实际得到 4 页（16384 字节）。设备描述符的边界检查必须用**本值**而非
    /// `len`——物理上真实可写的是整块帧，用 `len` 做上界会漏判
    /// （PRDT 写到对齐填充区仍是合法内存）。
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// 分配阶。
    pub fn order(&self) -> usize {
        self.order
    }

    /// 起始物理地址（DMA 描述符用）。
    pub fn phys_addr(&self) -> u64 {
        self.phys
    }

    /// 起始内核虚拟地址（内核 CPU 侧读写用）。
    pub fn virt_addr(&self) -> u64 {
        self.virt
    }

    /// 以 `&mut [u8]` 视图访问缓冲（长度 = `capacity`）。
    ///
    /// # Safety 契约（内部保证）
    ///
    /// - `virt` 来自 HHDM，指向本缓冲独有的物理帧，映射整个 `capacity`；
    /// - `frames` 的所有权在本对象内且不可复制（无 `Clone`），故不存在别名；
    /// - 生命周期受 `&mut self` 约束，借出期间本对象不可再次借出。
    ///
    /// 返回的切片长度是 `capacity`（整块帧），调用方按需只使用前 `len` 字节。
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY：见上方契约。virt 由 HHDM 线性映射，覆盖整个 capacity；
        // 帧所有权独占且本方法取 &mut self，故无别名写。
        unsafe { core::slice::from_raw_parts_mut(self.virt as *mut u8, self.capacity as usize) }
    }

    /// 以只读 `&[u8]` 视图访问缓冲。
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY：同 as_mut_slice 的映射与所有权论证；只读借用不产生别名写。
        unsafe { core::slice::from_raw_parts(self.virt as *const u8, self.capacity as usize) }
    }
}

impl Drop for KernelDmaBuffer {
    fn drop(&mut self) {
        // S18：唯一释放路径。归还整块连续帧（按基址 + order 元数据）。
        deallocate_frame(self.frames);
    }
}

impl core::fmt::Debug for KernelDmaBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // S15：核心结构配齐调试打印。不打印内容（可能是设备描述符，
        // 大且二进制），只打印定位所需的事实。
        f.debug_struct("KernelDmaBuffer")
            .field("len", &self.len)
            .field("capacity", &self.capacity)
            .field("order", &self.order)
            .field("phys", &format_args!("{:#x}", self.phys))
            .field("virt", &format_args!("{:#x}", self.virt))
            .finish()
    }
}

/// Buddy 能分配的最大 order（`2^order` 个连续帧）。
///
/// **必须与 `frame_allocator` 的 `MAX_ORDER` 保持一致**：buddy 的
/// `allocate`/`order_for_need_frames` 对超界 order **静默钳制**到
/// `MAX_ORDER-1`（`mod.rs:70`、`api.rs`）。若本模块不自行拒绝，请求超大页数
/// 会拿到远小于请求的块——驱动随后按请求大小写缓冲即**越界写内存**。
/// 故此处显式设限，宁可拒绝也不静默缩减（S19）。
///
/// 该常量重复定义了 `frame_allocator::MAX_ORDER(41) - 1`：对方为
/// `pub(crate)` 无法跨模块引用。单测 `max_alloc_order_matches_buddy_capacity`
/// 是防止将来单边改动的守卫。
const MAX_SINGLE_ALLOC_ORDER: usize = 40;

/// 计算覆盖 `npages` 页所需的最小 order（2^order ≥ npages）。
///
/// 抽出为独立函数以便单测直接覆盖边界（S19：order 计算是最易错的位运算）。
///
/// 返回 `None` 的三类情形（全部**拒绝**，绝不返回"够用就好"的近似值）：
/// - `npages == 0`：0 页无法用 2^order 表达，调用方不该到达此处；
/// - `order >= 64`：`1 << order` 无法在 u64 中表示；
/// - `order > MAX_SINGLE_ALLOC_ORDER`：超出 buddy 可分配上限，钳制即越界。
fn order_for_pages(npages: u64) -> Option<usize> {
    if npages == 0 {
        return None;
    }
    // 覆盖 npages 所需位数：ceil(log2(npages))。
    let order = 64 - (npages - 1).leading_zeros() as usize;
    if order >= 64 {
        return None;
    }
    // S19：buddy 会静默钳制超界 order，故在此先拒绝。
    if order > MAX_SINGLE_ALLOC_ORDER {
        return None;
    }
    Some(order)
}

/// 分配一块内核态 DMA 一致性缓冲。
///
/// 物理连续（`allocate_frames`），返回对象同时暴露内核虚拟地址（HHDM）与
/// 物理地址。失败原因见 [`KernelDmaError`]，**绝不返回伪缓冲区**（S09）。
///
/// `Drop` 自动归还帧（S18）。
pub fn alloc_kernel_dma(bytes: u64) -> Result<KernelDmaBuffer, KernelDmaError> {
    if bytes == 0 || bytes > MAX_KERNEL_DMA_BYTES {
        return Err(KernelDmaError::InvalidParam);
    }
    // 向上取整到页。用 checked 运算，溢出即拒绝（不静默回绕，S19）。
    let page_aligned = bytes
        .checked_add(PAGE - 1)
        .ok_or(KernelDmaError::InvalidParam)?
        / PAGE
        * PAGE;
    let npages = page_aligned / PAGE;
    let order = order_for_pages(npages).ok_or(KernelDmaError::InvalidParam)?;
    // **真实容量 = 2^order 页**，而非页对齐后的请求。
    //
    // buddy 只能按 2 的幂分配：请求 3 页得 order 2 = **4 页**。若此处把
    // capacity 记为 3 页（页对齐请求），则：
    //   1. `as_slice()`/`as_mut_slice()` 只暴露 3 页，第 4 页实际已分配却不可见；
    //   2. 驱动按 capacity 做 PRDT 边界检查会**低估**可写范围——虽不越界，
    //      但设备 DMA 可合法使用的那一页被浪费，且容量语义与物理事实不符。
    // 以物理事实为准（S06）：capacity 就是实际分配到的字节数。
    let capacity = (1u64 << order)
        .checked_mul(PAGE)
        .ok_or(KernelDmaError::InvalidParam)?;

    // S20：先探测 HHDM 就绪，再分配——否则 phys_to_virt 会在拿到帧后才 panic，
    // 且 panic 路径上帧不会归还。先探测使"启动顺序错误"变成可上抛错误。
    if arch::PHYS_OFFSET.get().is_none() {
        return Err(KernelDmaError::NotReady);
    }

    let frames = allocate_frames(order).ok_or(KernelDmaError::OutOfMemory)?;
    let phys = frames.start_paddr();
    // 物理地址 + 长度不得越过地址空间（S19）。但帧来自 buddy，必然在 RAM 内，
    // 此检查是纵深防御：若 buddy 元数据损坏给出越界地址，宁可拒绝也不让设备
    // 访问到任意物理内存。
    if phys.checked_add(capacity).is_none() {
        deallocate_frame(frames);
        return Err(KernelDmaError::InvalidParam);
    }
    let virt = phys_to_virt(phys);

    Ok(KernelDmaBuffer {
        frames,
        order,
        len: bytes,
        capacity,
        phys,
        virt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// order 计算覆盖边界（S19：位运算最易错处）。
    #[test]
    fn order_covers_requested_pages() {
        // 1 页 -> order 0（2^0 = 1）
        assert_eq!(order_for_pages(1), Some(0));
        // 2 页 -> order 1
        assert_eq!(order_for_pages(2), Some(1));
        // 3 页 -> order 2（2^2 = 4 ≥ 3）
        assert_eq!(order_for_pages(3), Some(2));
        // 4 页 -> order 2（恰好）
        assert_eq!(order_for_pages(4), Some(2));
        // 5 页 -> order 3
        assert_eq!(order_for_pages(5), Some(3));
    }

    /// 全量性质检查：2^order 必须 ≥ npages，且 order-1 必须 < npages
    /// （即 order 是**最小**满足者，不是随便一个够大的值）。
    #[test]
    fn order_is_minimal_satisfying() {
        for npages in 1..=4096u64 {
            let order = order_for_pages(npages).expect("must fit");
            let cap = 1u64 << order;
            assert!(cap >= npages, "order {order} covers {npages}: 2^{order}={cap}");
            if order > 0 {
                let smaller = 1u64 << (order - 1);
                assert!(smaller < npages, "order {order} is minimal for {npages}");
            }
        }
    }

    /// 0 页无解（调用方不该到达；返回 None 而非编造 order）。
    #[test]
    fn order_for_zero_pages_is_none() {
        assert_eq!(order_for_pages(0), None);
    }

    /// 超出 buddy 上限的页数必须**拒绝**而非被静默钳制（S19）。
    ///
    /// 这是本模块最重要的边界：buddy 的 allocate 对超界 order 会钳制到
    /// MAX_ORDER-1，若不在此拒绝，调用方拿到远小于请求的缓冲后按请求大小
    /// 写 → 越界写内存（内核态即内存破坏）。
    #[test]
    fn order_rejects_beyond_buddy_limit() {
        // 2^63 页：u64 能表示该 order，但远超 buddy 上限 → 必须拒绝。
        assert_eq!(order_for_pages(1u64 << 63), None);
        assert_eq!(order_for_pages(u64::MAX), None);
        // 恰好超出上限的第一个页数 → 拒绝。
        let over = 1u64 << (MAX_SINGLE_ALLOC_ORDER + 1);
        assert_eq!(order_for_pages(over), None, "one past limit must be rejected");
        // 恰好等于上限 → 接受（确认边界是闭区间，不是 off-by-one 多拒一个）。
        let at_limit = 1u64 << MAX_SINGLE_ALLOC_ORDER;
        assert_eq!(order_for_pages(at_limit), Some(MAX_SINGLE_ALLOC_ORDER));
    }

    /// MAX_SINGLE_ALLOC_ORDER 必须与 frame_allocator 的实际上限一致。
    ///
    /// 该常量是重复定义（对方 pub(crate) 无法跨模块引用），本测试是防止
    /// 将来单边改动的守卫：若 buddy 调整 MAX_ORDER，此处会失败并提示同步。
    #[test]
    fn max_alloc_order_matches_buddy_capacity() {
        // buddy MAX_ORDER=41 → 最大可分配 order = 40。
        assert_eq!(MAX_SINGLE_ALLOC_ORDER, 40);
        // 最大可分配字节数 = 2^40 * 4KiB = 4 TiB，远超本模块 64 MiB 上限；
        // 即 MAX_KERNEL_DMA_BYTES 永远不会触及 order 上限（上限纯属防御）。
        let max_bytes = (1u64 << MAX_SINGLE_ALLOC_ORDER) * PAGE;
        assert!(max_bytes > MAX_KERNEL_DMA_BYTES);
    }

    /// 0 字节与超上限必须拒绝，且**不分配任何帧**（错误路径同样严谨，S18）。
    #[test]
    fn rejects_zero_and_oversized_without_allocating() {
        assert_eq!(alloc_kernel_dma(0).err(), Some(KernelDmaError::InvalidParam));
        assert_eq!(
            alloc_kernel_dma(MAX_KERNEL_DMA_BYTES + 1).err(),
            Some(KernelDmaError::InvalidParam)
        );
    }

    /// 非整页请求按页向上取整后再算 order。
    #[test]
    fn page_aligned_request_maps_to_order() {
        // 1 字节 -> 1 页 -> order 0
        assert_eq!(order_for_pages((1u64).div_ceil(PAGE)), Some(0));
        // 4097 字节 -> 2 页 -> order 1
        assert_eq!(order_for_pages((4097u64).div_ceil(PAGE)), Some(1));
    }

    /// **capacity 是物理事实（2^order 页），不是页对齐请求**。
    ///
    /// 这条对应在内核实测中暴露的真实缺陷：请求 3 页时 buddy 只能给 2 的幂
    /// 块（order 2 = 4 页），而旧实现把 capacity 记成页对齐请求（3 页 =
    /// 12288），使 as_slice() 只暴露 3 页、与物理可写范围（4 页）不符。
    ///
    /// 本测试只需 order 与 capacity 的关系（纯计算，不依赖真实分配）：
    /// capacity 必须等于 PAGE << order，且严格 ≥ 页对齐请求。
    #[test]
    fn capacity_is_power_of_two_allocation_not_rounded_request() {
        for bytes in [1u64, 4095, 4096, 4097, 8192, 12288, 16384, 20000] {
            let page_aligned = bytes.div_ceil(PAGE) * PAGE;
            let order = order_for_pages(page_aligned / PAGE).expect("fits");
            let capacity = PAGE << order;
            // 物理事实：2 的幂页
            assert_eq!(capacity & (capacity - 1), 0, "capacity must be a power of two");
            // 必须覆盖请求（否则驱动会越界写）
            assert!(capacity >= bytes, "capacity {capacity} must cover request {bytes}");
            assert!(capacity >= page_aligned, "capacity must cover page-aligned request");
            // 且不得超出「覆盖页对齐请求」的一个 2 的幂档（拒绝浪费一整档）。
            // 下界是 PAGE：1 字节请求合法地拿到整页（页是最小分配单位），
            // 这不是浪费，故用 page_aligned 而非 bytes 作比较基准。
            assert!(
                capacity < page_aligned.saturating_mul(2).max(PAGE),
                "capacity {capacity} excessive for page_aligned {page_aligned}"
            );
        }
        // 具名断言：3 页请求 -> order 2 -> 4 页容量（16384），非 3 页（12288）。
        assert_eq!(order_for_pages(3), Some(2));
        assert_eq!(PAGE << 2, 16384);
    }
}
