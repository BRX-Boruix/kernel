//! 页表抽象（架构无关）。
//!
//! 统一成"把某物理页映射到某虚拟地址"的抽象，不绑定 x86 的 PML4 层级数
//! （ADR-007）。各架构实现本 trait，`mm` 等上层只依赖此接口。

use crate::addr::{PhysAddr, VirtAddr};

/// 页大小。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PageSize {
    /// 4KB 页。
    Size4K,
    /// 2MB 页。
    Size2M,
    /// 1GB 页。
    Size1G,
}

impl PageSize {
    /// 该页大小对应的字节数。
    pub const fn bytes(self) -> u64 {
        match self {
            PageSize::Size4K => 0x1000,
            PageSize::Size2M => 0x20_0000,
            PageSize::Size1G => 0x4000_0000,
        }
    }
}

/// 页权限标志。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PageFlags(u64);

impl PageFlags {
    /// 空标志。
    pub const fn empty() -> Self {
        Self(0)
    }

    /// 是否可写。
    pub const fn writable(mut self) -> Self {
        self.0 |= 1 << 1;
        self
    }

    /// 是否用户态可访问。
    pub const fn user(mut self) -> Self {
        self.0 |= 1 << 2;
        self
    }

    /// 是否可执行（内核页通常需要）。
    ///
    /// 默认页**不可执行**（架构实现据此置 NX=bit63）；仅当调用此方法显式授予
    /// 执行权限时才可执行，从而强制 W^X 保护。
    pub const fn executable(mut self) -> Self {
        self.0 |= 1 << 63;
        self
    }

    /// 设备内存语义（K2：`map_mmio_user` 专用）。
    ///
    /// 置位后架构实现必须把该页映射为**不可缓存**（x86 = PCD，bit4）：设备
    /// 寄存器/FIFO 的读取有副作用，可缓存映射允许 CPU 投机预读与写合并，
    /// 会把"读寄存器清标志"这类语义破坏成不可复现的硬件行为。普通 RAM 页
    /// 绝不允许携带此位。
    pub const fn device_memory(mut self) -> Self {
        self.0 |= 1 << 3;
        self
    }

    /// 取出裸 u64 标志位（架构实现可据此构造条目）。
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// 是否含可写位。
    ///
    /// 抽象层定义的语义位编码（与构造器一致）：writable=bit1、user=bit2、
    /// executable=bit63。查询走这里而非各模块手解裸位，避免编码知识扩散。
    pub const fn is_writable(self) -> bool {
        self.0 & (1 << 1) != 0
    }

    /// 是否含用户态可访问位。
    pub const fn is_user(self) -> bool {
        self.0 & (1 << 2) != 0
    }

    /// 是否为设备内存语义页（不可缓存映射）。
    pub const fn is_device_memory(self) -> bool {
        self.0 & (1 << 3) != 0
    }

    /// 是否含可执行位。
    pub const fn is_executable(self) -> bool {
        self.0 & (1 << 63) != 0
    }
}

/// 页表操作抽象。
///
/// 实现方操作真实硬件页表（如 x86 的 CR3/PML4）。
pub trait PageTable {
    /// 错误类型（架构相关，如"页表层级已满"）。
    /// 须可从 `klib::error::Error` 构造，保证上层（`mm`/`kernel`）经统一错误码
    /// 传递（ADR-010），架构差异不泄漏成不同错误类型（ADR-007）。
    type Error: core::fmt::Debug + From<klib::error::Error>;

    /// 新建一个独立的页表：**继承当前内核半区映射**（所有进程共享内核映射），
    /// **用户半区为空**（每个进程独立的用户地址空间）。
    ///
    /// 用于进程地址空间：`spawn`（ADR-003）时从内核页表派生出新进程页表，
    /// 但不复制父进程的用户区。
    fn new() -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// 把物理页 `paddr` 以 `size` 大小映射到虚拟地址 `vaddr`。
    fn map(
        &mut self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        size: PageSize,
        flags: PageFlags,
    ) -> Result<(), Self::Error>;

    /// 解除 `vaddr` 处的映射，返回被解映射的物理地址。
    fn unmap(&mut self, vaddr: VirtAddr) -> Result<PhysAddr, Self::Error>;

    /// 翻译虚拟地址 → 物理地址。
    fn translate(&self, vaddr: VirtAddr) -> Option<PhysAddr>;

    /// 翻译虚拟地址 → （物理地址，叶层权限标志）。
    ///
    /// 与 [`PageTable::translate`] 相同的遍历，但额外返回**叶层条目**的权限
    /// 语义（可写 / 用户态可访问 / 可执行），供内核在代表用户态访问用户缓冲区
    /// 前做预校验（EFAULT 路线，arch1.md AR1a）：present 但只读的页对"写意图"
    /// 必须判为不可访问，否则内核侧写入会在内核态触发 #PF。
    fn translate_with_flags(&self, vaddr: VirtAddr) -> Option<(PhysAddr, PageFlags)>;

    /// 顶层页表物理基址（= 装载到 CR3 等页表寄存器的值）。
    ///
    /// 用于进程进入用户态/调度切换时装载进程自己的页表（M2.1 扩展 TrapFrame
    /// 的 `cr3` 字段）。架构实现必须返回真实页表物理基址。
    ///
    /// S09：默认实现直接 panic（未实现），绝不静默返回 0——返回 0 会让调用方
    /// 把 0 当作合法 CR3 装载而 triple fault，属"未实现伪装成有效值"。
    fn paddr(&self) -> u64 {
        panic!("PageTable::paddr() must be overridden by the architecture");
    }

    /// 当前活动页表的顶层物理基址（= CR3 & ~0xFFF）。
    ///
    /// 供 `UserAddressSpace::destroy` 判断"待释放的顶层页表是否正被活动使用"：
    /// 若某地址空间的顶层页表恰是当前 CR3，则不能释放它（否则后续内核页表遍历
    /// 会读到已归还的物理帧 → 崩溃）；此时保守保留该页表页。默认返回 0（调用方
    /// 视为"无法判定 → 不释放顶层页表"，偏安全）。
    fn current_paddr() -> u64
    where
        Self: Sized,
    {
        0
    }

    /// 切换到架构在启动期快照的内核根页表（mm1.md MD4：销毁**活动**地址空间
    /// 前先"回家"，使顶层表页可安全归还而非慢性泄漏）。
    ///
    /// 返回 `false` 表示架构未提供根表快照——调用方必须退回保守泄漏路径。
    /// 默认 `false`（未实现快照的架构）。
    fn switch_to_kernel_root() -> bool
    where
        Self: Sized,
    {
        false
    }

    /// 查询**除 `except_slot` 外**有多少核的 CR3 指向 `top` 这张用户顶层表（S2）。
    ///
    /// 供 `UserAddressSpace::destroy` 判断"中间页表页能否安全归还"：只要还有别的
    /// 核悬在该表上，归还任何页表页都会让那个核执行内核代码时取指缺页
    /// （→ #DF → 三重故障）。
    ///
    /// `except_slot` 传调用方自己的槽位——销毁核已经（或将）离开该表。
    /// 默认 `0`：未实现的架构不谎报"有人持有"，但调用方据 `current_paddr`
    /// 的既有保守语义自行决定；支持多核的架构**必须**覆盖本方法。
    fn other_holders_of(_top: u64, _except_slot: usize) -> usize
    where
        Self: Sized,
    {
        0
    }

    /// 本核的紧凑 CPU 槽位（架构层经 LAPIC id 反查）。
    /// 默认 `0`（单核架构恒为 BSP 槽位）。
    fn my_cpu_slot() -> usize
    where
        Self: Sized,
    {
        0
    }
}

/// 当前活动的页表（活动地址空间）。
///
/// 由具体架构在启动时装载到 CR3 等寄存器。
pub trait ActivePageTable {
    /// 获取当前活动页表的句柄。
    fn current() -> Self;

    /// 切换活动页表（装入 CR3）。
    ///
    /// **不更新 per-CPU CR3 追踪**。需要追踪时用 [`Self::activate_tracked`]。
    fn activate(&self);

    /// 切换活动页表（装入 CR3）**并更新 per-CPU CR3 追踪**。
    ///
    /// 槽位由架构实现自行解析（`arch-x86_64` 经 LAPIC id 反查紧凑槽位），
    /// 故本方法无需参数——架构无关层（`mm`）不掌握槽位概念，也不该掌握。
    ///
    /// **顺序纪律**：实现必须**先记录、后写 CR3**（保守方向），详见
    /// `arch-x86_64::paging` 的 per-CPU CR3 追踪说明。
    fn activate_tracked(&self);

}

/// #PF 错误码的语义视图（ADR-007：位编码知识归架构层所有）。
///
/// 架构无关层（`mm` 的缺页处理策略）只通过本 trait 查询**访问意图**，
/// 禁止手解原始错误码位——x86_64 的 bit 编码由 `arch-x86_64` 的实现类型
/// 私有持有，换架构只重写实现、不改策略代码（mm1.md MM6 后半：语义面
/// 覆盖 present / write / user / 取指四轴，架构无对应概念时如实返回
/// `false`，不伪造）。
pub trait PageFaultCode: Copy {
    /// 本次缺页是否由写访问引发（COW 判定与补页权限校验的唯一判据）。
    fn is_write(self) -> bool;
    /// 缺页是否发生在用户态访问（CPL=3）。
    fn is_user(self) -> bool;
    /// 页是否已在 TLB/页表中存在、故障性质为**保护违规**（如写只读页），
    /// 而非"页不在内存"。按需分页策略据此区分"补页"与"越权拒绝"。
    fn is_present(self) -> bool;
    /// 故障是否由指令取指引发。
    fn is_instruction_fetch(self) -> bool;
}
