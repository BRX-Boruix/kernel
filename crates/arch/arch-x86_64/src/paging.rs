//! x86-64 页表实现（基于 CR3 的多级分页）。
//!
//! 实现 `arch::paging::PageTable`。x86-64 使用 4 级页表：
//! PML4 → PDPT → PD → PT。支持 4KB / 2MB / 1GB 页。
//!
//! 支持 LA57（5 级分页）：启动时检测 `CR4.LA57` 位，动态选择 4 级或 5 级
//! 页表，避免在 LA57 机器上把 CR3 指向的 PML5 误当 PML4 使用导致地址错位。
//!
//! 由于 `arch-x86_64` 不依赖 `mm`（避免循环），页表页的分配通过
//! 启动时注入的函数指针完成。

use core::sync::atomic::{AtomicU64, Ordering};

use arch::{PageFlags, PageSize, PhysAddr, VirtAddr, phys_to_virt};
use spin::Once;

use crate::mmio;

// ---- 页表页分配 / 释放注入 ----

/// 分配一个物理页帧作为页表页，返回其物理地址（4KB 对齐）。
/// 返回 0 表示分配失败。由内核在早期注入（实际调用 `mm::allocate_frame`）。
static FRAME_ALLOC: Once<extern "C" fn() -> u64> = Once::new();

/// 释放一个物理页帧（用于回收不再使用的中间页表页）。
/// 由内核注入（实际调用 `mm` 的释放接口）。
static FRAME_DEALLOC: Once<extern "C" fn(u64)> = Once::new();

/// 注入页表页分配与释放。
///
/// KA5 修正：删除原第三参数 `phys_offset`——它是误导性死参。HHDM 偏移由
/// `arch::PHYS_OFFSET` 统一持有，且**只能**由 mm 从 Limine hhdm response
/// 填充（mm::init 先于本函数执行，此处的 `call_once` 永远是 no-op；一旦
/// 初始化顺序重构，调用者传入的 0 会静默生效把物理地址当虚拟指针）。
/// 现以 debug_assert 固化"偏移必须已就绪"的前置契约，顺序回归即刻可见。
pub fn init(alloc: extern "C" fn() -> u64, dealloc: extern "C" fn(u64)) {
    debug_assert!(
        arch::PHYS_OFFSET.get().is_some(),
        "paging::init requires PHYS_OFFSET set by mm::init (HHDM response) beforehand"
    );
    let _ = FRAME_ALLOC.call_once(|| alloc);
    let _ = FRAME_DEALLOC.call_once(|| dealloc);
}

/// 分配一个物理帧并返回其物理地址（0 表示失败）。
///
/// `pub(crate)` 供 `mmio::map_lapic` 在中间页表页缺失时主动分配。
pub(crate) fn alloc_frame() -> Option<u64> {
    let p = FRAME_ALLOC.get().map(|f| f())?;
    if p == 0 { None } else { Some(p) }
}

/// 释放一个物理页帧（页表页回收用）。
pub(crate) fn dealloc_frame(paddr: u64) {
    if let Some(f) = FRAME_DEALLOC.get() {
        f(paddr);
    }
}

// ---- 页表标志 ----

pub(crate) const FLAG_PRESENT: u64 = 1 << 0;pub(crate) const FLAG_WRITABLE: u64 = 1 << 1;
pub(crate) const FLAG_USER: u64 = 1 << 2;
/// PCD（Page Cache Disable，bit4）：设备内存页必须置位——读设备寄存器有
/// 副作用，可缓存映射允许投机预读破坏硬件语义（K2 map_mmio_user）。
pub(crate) const FLAG_PCD: u64 = 1 << 4;
pub(crate) const FLAG_LARGE: u64 = 1 << 7;
pub(crate) const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// 顶层页表条目 256..512 为内核高半区（线性地址最高位 bit47/bit56 决定，与层级数无关）。
///
/// 内核高半区页表页**跨地址空间共享**（每个进程 `new()` 时复制这些顶层条目），
/// 因此这些页表页不能由单个用户地址空间回收/释放——否则会破坏其它进程的内核映射。
pub const KERNEL_HALF_START: usize = 256;

/// 由 `PageFlags` 与页大小构造 4KB 页表条目。
fn entry_from_flags(flags: PageFlags, large: bool) -> u64 {
    let mut e = 0u64;
    e |= FLAG_PRESENT;
    if flags.bits() & (1 << 1) != 0 {
        e |= FLAG_WRITABLE;
    }
    if flags.bits() & (1 << 2) != 0 {
        e |= FLAG_USER;
    }
    // 设备内存语义（PageFlags::device_memory，bit3）→ PCD：不可缓存。
    if flags.bits() & (1 << 3) != 0 {
        e |= FLAG_PCD;
    }
    // NX：未显式授予执行权限（PageFlags::executable，bit 63）的页一律不可执行
    if flags.bits() & (1 << 63) == 0 {
        e |= 1 << 63;
    }
    if large {
        e |= FLAG_LARGE;
    }
    e
}

// ---- LA57 / 页表层级数 ----

/// 检测当前是否处于 LA57（5 级分页）模式。
///
/// 读 CR4 的 LA57 位（bit 12）。
#[inline]
fn la57_enabled() -> bool {
    let cr4: u64;
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack));
    }
    cr4 & (1 << 12) != 0
}

/// 当前页表层级数（4 = LA48，5 = LA57）。
///
/// 整个系统在同一时刻只会有一种分页模式，故用运行时函数即可，
/// 无需在 `X86PageTable` 里存字段。
#[inline]
pub(crate) fn page_levels() -> usize {
    if la57_enabled() { 5 } else { 4 }
}

/// 计算虚地址在 `levels` 级页表中第 `level` 层的索引。
///
/// `level` 从 0（最顶层，PML4 或 PML5）开始计数，最低层是 PT。
///
/// 各层占位域（LA48 为例）：
/// - 顶层 PML4：位 39..48
/// - PDPT：位 30..39
/// - PD：位 21..30
/// - PT：位 12..21
///
/// 通用公式：第 `level` 层的起始位 = `12 + (levels - 1 - level) * 9`。
#[inline]
pub(crate) fn index_at(level: usize, levels: usize, vaddr: u64) -> usize {
    let bit = 12 + (levels - 1 - level) * 9;
    ((vaddr >> bit) & 0x1FF) as usize
}

/// 从叶层表项解析物理地址（区分大页与 4KB 页）。
///
/// `leaf` 是该叶子所处的层级（从顶层 0 数起），`levels` 为页表层级数。
/// 大页大小 = 2^(12 + (levels - 1 - leaf) * 9)。
///
/// 必须与 `ADDR_MASK` 相与以排除 NX（bit63）等高位标志位——否则启用 NX 后
/// `translate`/`unmap` 会把 NX 位误当作物理地址的一部分返回（见回归修复）。
#[inline]
fn entry_paddr(entry: u64, leaf: usize, levels: usize) -> u64 {
    let shift = 12 + (levels - 1 - leaf) * 9;
    // ADDR_MASK 排除 bit63/NX 及其它标志位；再按页大小对齐掩掉低位。
    entry & ADDR_MASK & !((1u64 << shift) - 1)
}

// ---- 页表 ----

/// x86-64 活动页表（持有 CR3 物理地址）。
///
/// 注意：`pml4` 字段在 LA57 下实际是最顶层（PML5），名字沿用以便兼容。
pub struct X86PageTable {
    /// 最顶层页表的物理地址（LA48 为 PML4，LA57 为 PML5）。
    pml4: u64,
}

impl X86PageTable {
    /// 创建一个空的页表：分配一个顶层页并清零。
    pub fn new_empty() -> Option<Self> {
        let top = alloc_frame()?;
        let top_virt = phys_to_virt(top) as *mut u64;
        // 清零 512 项
        unsafe { core::ptr::write_bytes(top_virt, 0, 512) };
        Some(Self { pml4: top })
    }

    /// 从顶层页表物理地址构造（用于包装当前活动页表）。
    pub fn from_pml4(pml4: u64) -> Self {
        Self { pml4 }
    }

    /// 获取顶层页表物理地址（= CR3 值）。
    pub fn pml4_paddr(&self) -> u64 {
        self.pml4
    }

    /// 把本页表切换为活动页表（写 CR3）。
    ///
    /// **不更新 per-CPU CR3 追踪**——需要追踪时用 [`Self::activate_tracked`]。
    /// 保留此入口供"地址空间不归任何进程所有"的场合（如内核自检切表）。
    pub fn activate(&self) {
        mmio::write_cr3(self.pml4);
    }

    /// 切到本页表并**记录**到 per-CPU CR3 追踪（SMP 审计 S2）。
    ///
    /// 顺序有意为之：**先记录、后写 CR3**。这样别核若在两步之间查询，看到的是
    /// "记录已指向新表"——即便硬件尚未切换，判定方向也是保守的（认为有人持有），
    /// 绝不会出现"以为没人持有、实际有人"的危险方向。
    pub fn activate_tracked(&self) {
        record_current_cr3(my_slot(), self.pml4);
        mmio::write_cr3(self.pml4);
    }

    /// 直接读一个虚拟地址处的 u64（物理页表页通过 HHDM 访问）。
    unsafe fn table_at(&self, phys: u64, index: usize) -> u64 {
        unsafe { mmio::read_u64(phys_to_virt(phys) as u64 + index as u64 * 8) }
    }

    /// 直接写一个虚拟地址处的 u64。
    unsafe fn table_set(&self, phys: u64, index: usize, val: u64) {
        unsafe { mmio::write_u64(phys_to_virt(phys) as u64 + index as u64 * 8, val) }
    }

    /// 沿虚地址从顶层逐级下降，返回路径上每层的表项、叶层索引与层级数。
    ///
    /// `leaf` 是命中叶子所在的层（`0..=levels-1`）：非最低层命中代表大页。
    /// 若某层表项不存在（present=0）返回 `None`。
    /// 检查一个页表页（512 项）是否全空（present=0）。
    unsafe fn is_table_empty(&self, phys: u64) -> bool {
        let virt = phys_to_virt(phys) as *const u64;
        for i in 0..512 {
            if unsafe { *virt.add(i) } & FLAG_PRESENT != 0 {
                return false;
            }
        }
        true
    }

    unsafe fn walk(&self, vaddr: u64) -> Option<([u64; 5], usize, usize)> {
        let levels = page_levels();
        let mut entries = [0u64; 5];
        let mut table_phys = self.pml4;
        for lvl in 0..levels {
            let entry = unsafe { self.table_at(table_phys, index_at(lvl, levels, vaddr)) };
            if entry & FLAG_PRESENT == 0 {
                return None;
            }
            entries[lvl] = entry;
            // 除最低层外，命中大页即为叶子
            if lvl + 1 < levels && entry & FLAG_LARGE != 0 {
                return Some((entries, lvl, levels));
            }
            table_phys = entry & ADDR_MASK;
        }
        Some((entries, levels - 1, levels))
    }
}

impl arch::ActivePageTable for X86PageTable {
    /// 获取当前活动页表（包装当前 CR3）。
    fn current() -> Self {
        Self {
            pml4: mmio::cr3() & !0xFFF,
        }
    }

    /// 切换活动页表（写 CR3）。
    fn activate(&self) {
        mmio::write_cr3(self.pml4);
    }

    /// 切换活动页表并更新 per-CPU CR3 追踪（SMP 审计 S2）。
    ///
    /// 先记录、后写 CR3：别核若在两步之间查询，看到"已记录"即保守认为有人
    /// 持有，绝不会出现"以为没人持有、实际有人"的危险方向。
    fn activate_tracked(&self) {
        record_current_cr3(my_slot(), self.pml4);
        mmio::write_cr3(self.pml4);
    }

}

impl arch::PageTable for X86PageTable {
    type Error = klib::error::Error;

    fn new() -> Result<Self, Self::Error> {
        // 1. 分配新顶层页表页并清零
        let top = alloc_frame().ok_or(klib::error::Error::OutOfMemory)?;
        let top_virt = phys_to_virt(top) as *mut u64;
        unsafe { core::ptr::write_bytes(top_virt, 0, 512) };

        // 2. 复制当前内核页表的高半区顶层条目（所有进程共享内核映射）。
        //    用户/内核分界在顶层条目 256 处（线性地址的最高位，bit47/bit56 决定，
        //    对应顶层 9 位索引的最高位），与页表层级数（LA48/LA57）无关。
        //    用户半区（顶层条目 0..255）保持为空，实现"独立用户地址空间"。
        //    CR3 返回的是 PML4 的物理地址，须经 HHDM 映射为虚拟地址才能解引用。
        let cur_top = phys_to_virt(mmio::cr3() & !0xFFF) as *const u64;
        for i in KERNEL_HALF_START..512 {
            let entry = unsafe { *cur_top.add(i) };
            if entry != 0 {
                unsafe { *top_virt.add(i) = entry };
            }
        }

        Ok(Self { pml4: top })
    }

    fn map(
        &mut self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        size: PageSize,
        flags: PageFlags,
    ) -> Result<(), Self::Error> {
        let levels = page_levels();
        let v = vaddr.as_u64();
        let p = paddr.as_u64();

        // 页大小决定叶层（从顶层 0 数起）：
        //   4K -> 最低层 (levels-1)
        //   2M -> 低二层 (levels-2)
        //   1G -> 低三层 (levels-3)
        let leaf_level = match size {
            PageSize::Size4K => levels - 1,
            PageSize::Size2M => levels - 2,
            PageSize::Size1G => levels - 3,
        };

        // 逐级下降，必要时创建中间页表页。
        let mut table_phys = self.pml4;
        for lvl in 0..leaf_level {
            let idx = index_at(lvl, levels, v);
            let entry = unsafe { self.table_at(table_phys, idx) };
            if entry & FLAG_PRESENT == 0 {
                let new_child = alloc_frame().ok_or(klib::error::Error::OutOfMemory)?;
                // 清零子表
                unsafe { core::ptr::write_bytes(phys_to_virt(new_child) as *mut u64, 0, 512) };
                // 连接：present | writable |（若叶层映射是用户页，则中间层也须置 USER 位）
                // 关键：用户态（Ring3）访问时，CPU 会检查每一级条目的 U/S 位。若中间层
                // 条目没有 USER 位，即使叶层有 USER 位，用户态访问也会 #PF（present 但
                // 权限不足，错误码 P=1,U/S=1）。故中间层必须继承叶层的 USER 位。
                let user_bit = flags.bits() & FLAG_USER;
                let child_entry = new_child & ADDR_MASK | FLAG_PRESENT | FLAG_WRITABLE | user_bit;
                unsafe { self.table_set(table_phys, idx, child_entry) };
                table_phys = new_child;
            } else {
                table_phys = entry & ADDR_MASK;
            }
        }

        // 在叶层写条目。先检查既有叶项：present 即拒绝（AlreadyExists）——
        // 静默覆写会把"换映射"伪装成普通映射成功，且旧映射若 TLB 热还会继续
        // 被命中（arch1.md AM6）。需要更换映射的调用方必须先显式 `unmap`
        // （它自带 flush 与空表回收），使"替换"成为可审计的独立动作。
        // 检查粒度为叶层条目本身；中间层冲突不在本检查范围（当前全部调用方
        // 均遵守先 unmap 后 map 的纪律）。
        let leaf_idx = index_at(leaf_level, levels, v);
        let large = leaf_level + 1 < levels; // 非最低层即大页
        let existing = unsafe { self.table_at(table_phys, leaf_idx) };
        if existing & FLAG_PRESENT != 0 {
            return Err(klib::error::Error::AlreadyExists);
        }
        let base = if large {
            // 大页：按页大小对齐物理地址
            let shift = 12 + (levels - 1 - leaf_level) * 9;
            p & !((1u64 << shift) - 1)
        } else {
            p & !0xFFF
        };
        let entry_val = base | entry_from_flags(flags, large);
        unsafe { self.table_set(table_phys, leaf_idx, entry_val) };
        // 新建映射同样 invlpg：该虚拟地址可能残留陈旧的 TLB 条目（如刚被
        // unmap 的旧映射在其它 CPU/路径上的残影），刷新是廉价的无害操作。
        flush_tlb(v);
        Ok(())
    }

    fn unmap(&mut self, vaddr: VirtAddr) -> Result<PhysAddr, Self::Error> {
        let v = vaddr.as_u64();
        let (entries, leaf, levels) = unsafe { self.walk(v) }.ok_or(klib::error::Error::NotFound)?;
        // 内核半区标记：叶项**清除**对两半区都合法（内核自身映射管理，如
        // KA3 守护页布防）；但中间页表页**回收**只允许用户半区（见下）。
        let kernel_half = index_at(0, levels, v) >= KERNEL_HALF_START;

        // 大页叶（leaf+1 < levels）：整条目覆盖多页，直接清除会把整个大页
        // 区域一起失映射。正确语义 = 拆分：分配下一级表页，把大页按 4KB 粒度
        // 展开继承（基址 + 原标志、去 LARGE 位），装回父级后对目标 4K 页
        // 递归走常规路径。拆分失败（无帧）如实上抛 OutOfMemory，绝不静默
        // 扩大破坏面。
        //
        // 审计 B22：本展开**仅对 2M 叶正确**（leaf == levels-2：下一级恰为
        // PT）。1G 叶（leaf < levels-2）需要两级展开（先建 PD 再建 PT），
        // 现算法会把 1G 基址当 2M 基址展开成 512 个"指向 base+i*4K 的表项"
        // ——语义完全错误的页表。如实拒绝而非产出错误映射；当前系统无 1G
        // unmap 调用方（1G 仅 mmio 早期建图，不经本路径销毁），拒绝即未来
        // 新调用方的编译期/运行期哨兵。
        if leaf + 2 < levels {
            return Err(klib::error::Error::NotSupported.into());
        }
        if leaf + 1 < levels {
            let huge = entries[leaf];
            let parent_phys =
                if leaf == 0 { self.pml4 } else { entries[leaf - 1] & ADDR_MASK };
            let new_table = alloc_frame().ok_or(klib::error::Error::OutOfMemory)?;
            let tv = phys_to_virt(new_table) as *mut u64;
            unsafe { core::ptr::write_bytes(tv, 0, 512) };
            // 子表各 4K 项：物理地址 = 大页基址 + i*4K；标志继承并去 LARGE。
            let inherited = huge & !ADDR_MASK & !FLAG_LARGE & !FLAG_PRESENT;
            for i in 0..512usize {
                let chunk = entry_paddr(huge, leaf, levels) + (i as u64) * 0x1000;
                unsafe { tv.add(i).write_volatile(chunk | inherited | FLAG_PRESENT) };
            }
            let leaf_idx = index_at(leaf, levels, v);
            unsafe { self.table_set(parent_phys, leaf_idx, new_table | inherited | FLAG_PRESENT) };
            flush_tlb(v);
            // 拆分后重走：现在命中 4K 叶，进入下方常规清除与回收路径。
            return self.unmap(vaddr);
        }

        // 清掉叶层条目：父表 = 上一层的下一级表（顶层时为自身）
        let parent_phys = if leaf == 0 {
            self.pml4
        } else {
            entries[leaf - 1] & ADDR_MASK
        };
        let leaf_idx = index_at(leaf, levels, v);
        unsafe { self.table_set(parent_phys, leaf_idx, 0) };
        flush_tlb(v);

        // 回收中间页表页：仅当映射的是 4KB 页（leaf == levels-1）时才存在
        // 其下方的页表页链。逐级向上检查，若某级页表页全空则释放该页并清掉
        // 父层对应条目，直到某级不空或到达顶层（顶层/大页永不释放）。
        //
        // 地址空间隔离（ADR-007）：`new()` 派生页表时复制了内核高半区顶层条目，
        // 其指向的中间页表页**跨地址空间共享**。因此只有**用户半区**的页表页是
        // 本地址空间私有的、可回收；内核半区页表页绝不能在此释放（否则破坏其它
        // 进程的内核映射）——内核半区只清叶项、永不回收。
        if !kernel_half && leaf == levels - 1 && levels >= 3 {
            // 从 PT 的父层（leaf-1）开始，逐级向上回收已空的中间页表页；
            // 一直收到 level 1（PDPT），但**不回收顶层页表页**（level 0 / PML4）——
            // 顶层由 `UserAddressSpace::destroy` 统一释放，此处若释放会破坏同地址
            // 空间内仍存在的其它映射。用 `isize` 以便 `cur_level` 递减到 -1 自然退出。
            let mut cur_level = leaf as isize - 1;
            while cur_level >= 0 {
                let cl = cur_level as usize;
                // 当前层指向的（下一级）空页表页物理地址 = entries[cl] & ADDR_MASK。
                let table_phys = entries[cl] & ADDR_MASK;
                if table_phys == 0 || table_phys == self.pml4 {
                    break; // 空表或顶层页表页本身（顶层由 destroy 回收），停止
                }
                if !unsafe { self.is_table_empty(table_phys) } {
                    break; // 该层还有其它映射，停止回收
                }
                // 清掉父层指向该空表的条目：父表为上一层（cl-1）的表，
                // 当 cl==0 时父表即顶层表自身。
                let parent_phys = if cl == 0 {
                    self.pml4
                } else {
                    entries[cl - 1] & ADDR_MASK
                };
                unsafe { self.table_set(parent_phys, index_at(cl, levels, v), 0) };
                flush_tlb(v);
                dealloc_frame(table_phys);
                // 继续向上（直到 PDPT / 顶层边界）
                cur_level -= 1;
            }
        }

        Ok(PhysAddr::new(entry_paddr(entries[leaf], leaf, levels)))
    }

    fn translate(&self, vaddr: VirtAddr) -> Option<PhysAddr> {
        let (entries, leaf, levels) = unsafe { self.walk(vaddr.as_u64()) }?;
        Some(PhysAddr::new(entry_paddr(entries[leaf], leaf, levels)))
    }

    fn translate_with_flags(&self, vaddr: VirtAddr) -> Option<(PhysAddr, PageFlags)> {
        let (entries, leaf, levels) = unsafe { self.walk(vaddr.as_u64()) }?;
        let entry = entries[leaf];
        // 从叶层条目重建抽象层 PageFlags（entry_from_flags 的逆）：
        // bit1=W、bit2=U/S；NX=bit63 置位表示不可执行，故可执行 = NX 未置位。
        // present 已由 walk() 保证。
        let mut flags = PageFlags::empty();
        if entry & FLAG_WRITABLE != 0 {
            flags = flags.writable();
        }
        if entry & FLAG_USER != 0 {
            flags = flags.user();
        }
        if entry & FLAG_PCD != 0 {
            flags = flags.device_memory();
        }
        if entry & (1 << 63) == 0 {
            flags = flags.executable();
        }
        Some((PhysAddr::new(entry_paddr(entry, leaf, levels)), flags))
    }

    fn paddr(&self) -> u64 {
        self.pml4
    }

    /// 当前活动页表的顶层物理基址（= CR3 & ~0xFFF）。
    fn current_paddr() -> u64 {
        mmio::cr3() & !0xFFF
    }

    /// 切回启动期快照的内核根页表（MD4）。
    fn switch_to_kernel_root() -> bool {
        switch_to_kernel_root()
    }

    /// 有多少**别的**核的 CR3 指向 `top` 这张表（S2：跨核销毁门）。
    fn other_holders_of(top: u64, except_slot: usize) -> usize {
        other_holders_of(top, except_slot)
    }

    /// 本核紧凑槽位（经 LAPIC id 反查）。
    fn my_cpu_slot() -> usize {
        my_slot()
    }
}

// ---------------------------------------------------------------------------
// per-CPU CR3 追踪（SMP 审计 S2）
// ---------------------------------------------------------------------------
//
// **为什么必须有这个**：`UserAddressSpace::destroy` 逐页 `unmap`，而 `unmap`
// 在中间页表页变空时会 `dealloc_frame` 它。该回收只看 `!kernel_half`（挡内核
// 半区），对用户半区自己的中间页**无条件归还**；`destroy` 第 3 步的
// `top == PT::current_paddr()` 也只包住**顶层页**，且 `current_paddr()` 读的是
// **本核** CR3。于是：别的核 CR3 仍悬在该进程表上时表页被归还 → 该核执行内核
// 代码取指缺页 → #DF → 三重故障重启。
//
// 修复的前提是**能回答"此刻哪些核的 CR3 指向这张表"**。本表即该事实的唯一记录。
//
// ## 并发纪律（S21）
//
// - 写入者：只有**本核**写自己的槽。跨核写别人的槽是 bug。
// - 读写序：`record_current_cr3` 必须在 `mov cr3` **之前**调用（见
//   [`PAGE_TABLE::activate_tracked`]）。这样任何别核读到的状态都是
//   "记录已更新"——若记录说"有人持有"，硬件必然已经（或即将）持有，
//   方向保守，不会漏判。
// - 内存序：写 `Release` / 读 `Acquire`。
// - 哨兵：`CR3_NO_USER_SPACE` 用 `u64::MAX` 而非 `0`——`0` 在架构上是合法 CR3，
//   兼作"无"的标记会掩盖真错误（S19 数值边界）。

/// 可追踪的 CPU 槽位上限。与 SMP 子系统分配的紧凑槽位空间一致；
/// 越界槽位是调用方缺陷，一律显式 panic（S19：不静默错位）。
pub const MAX_TRACKED_CPUS: usize = 256;

/// "本核当前不持有任何用户地址空间"的哨兵值。
///
/// CR3 物理基址必然 4KiB 对齐，故 `u64::MAX`（低 12 位全 1）不可能是合法 CR3。
pub const CR3_NO_USER_SPACE: u64 = u64::MAX;

/// 本核的紧凑槽位。由 LAPIC id 反查（`smp` 在 AP 上线时登记该映射）。
///
/// 为什么在这里算而不从 `task` 传入：`arch-x86_64` 不依赖 `task`（避免循环），
/// 而槽位本身是**架构层**概念（LAPIC ↔ 紧凑索引），故在本层解析最合适。
///
/// **LAPIC 未映射时回退 0（BSP 槽）**：`current_lapic_id()` 会读 LAPIC MMIO，
/// 而早期引导阶段（LAPIC 映射建立之前）该地址不可访问——直接读会 #PF
/// （实测 `cr2=0x20`）。回退 0 是安全的：早期只跑在 BSP 上，且 `smp::init`
/// 写入槽位表前其默认值本就是 0（与 `smp::my_slot` 同款纪律，不另立规矩）。
#[inline]
fn my_slot() -> usize {
    if !crate::lapic::is_mapped() {
        return 0;
    }
    crate::smp::slot_of_lapic(crate::lapic::current_lapic_id())
}

/// per-CPU 当前 CR3 记录：值 = 该核当前加载的用户顶层页表物理基址；
/// 哨兵表示该核不在用户地址空间上（如运行在内核根表或 idle）。
static PER_CPU_CR3: [AtomicU64; MAX_TRACKED_CPUS] =
    [const { AtomicU64::new(CR3_NO_USER_SPACE) }; MAX_TRACKED_CPUS];

/// 记录某核当前持有的用户地址空间顶层表。
///
/// **调用时机**：必须在写 CR3 之前（保守方向，见模块内并发纪律）。
/// `top` 必须 4KiB 对齐；传 [`CR3_NO_USER_SPACE`] 表示离开用户地址空间。
pub fn record_current_cr3(slot: usize, top: u64) {
    assert!(slot < MAX_TRACKED_CPUS, "CR3 track slot out of range");
    assert!(
        top == CR3_NO_USER_SPACE || top & 0xFFF == 0,
        "CR3 must be 4KiB-aligned or the no-user-space sentinel"
    );
    PER_CPU_CR3[slot].store(top, Ordering::Release);
}

/// 某核当前记录的 CR3 值（不在用户地址空间时为 [`CR3_NO_USER_SPACE`]）。
pub fn recorded_cr3_of(slot: usize) -> u64 {
    assert!(slot < MAX_TRACKED_CPUS, "CR3 track slot out of range");
    PER_CPU_CR3[slot].load(Ordering::Acquire)
}

/// 查询**除 `except_slot` 外**有多少核的 CR3 指向 `top` 这张表。
///
/// `destroy` 用它回答"我能不能安全归还这张表的页表页"：调用方传自己（销毁核）
/// 的槽位——销毁核已经（或将）离开该表，不该把自己算作持有者。
pub fn other_holders_of(top: u64, except_slot: usize) -> usize {
    let mut n = 0usize;
    let mut i = 0usize;
    while i < MAX_TRACKED_CPUS {
        if i != except_slot && PER_CPU_CR3[i].load(Ordering::Acquire) == top {
            n += 1;
        }
        i += 1;
    }
    n
}

/// 当前有多少核处于用户地址空间（记录值非哨兵）。
pub fn active_user_cr3_count() -> usize {
    let mut n = 0usize;
    let mut i = 0usize;
    while i < MAX_TRACKED_CPUS {
        if PER_CPU_CR3[i].load(Ordering::Acquire) != CR3_NO_USER_SPACE {
            n += 1;
        }
        i += 1;
    }
    n
}

/// 自检用：把某槽复位为"不在用户地址空间"。
///
/// 仅测试夹具可调：生产路径上槽的生命周期由调度器的 CR3 切换唯一维护，
/// 手动复位会制造"硬件在用户表、记录说没有"的反向不一致（危险方向）。
pub fn reset_tracking_slot(slot: usize) {
    assert!(slot < MAX_TRACKED_CPUS, "CR3 track slot out of range");
    PER_CPU_CR3[slot].store(CR3_NO_USER_SPACE, Ordering::Release);
}

/// 刷新 TLB 中一个虚拟地址。
#[inline]
pub(crate) fn flush_tlb(vaddr: u64) {
    unsafe { core::arch::asm!("invlpg [{}]", in(reg) vaddr, options(nostack, preserves_flags)) };
}

// ---- #PF 错误码语义（mm1.md MM6 后半：位编码知识归本层所有）----

/// x86_64 #PF error code 原始位定义（SDM §4.7）。
///
/// `pub` 仅供 **extern "C" ABI 边界**构造原始错误码（如测试直接调用
/// `page_fault_entry(vaddr, ec)`）；进入策略层必须走 [`PageFaultCode::new`]
/// 包装，策略代码禁止引用这些常量。
pub const PF_EC_PRESENT: u64 = 1 << 0;
pub const PF_EC_WRITE: u64 = 1 << 1;
pub const PF_EC_USER: u64 = 1 << 2;
pub const PF_EC_RSVD: u64 = 1 << 3;
pub const PF_EC_INSN: u64 = 1 << 4;

/// x86_64 #PF error code 的类型化包装。
///
/// 原始错误码只允许在 extern "C" ABI 边界（中断栈帧 → 处理器注册链）以
/// u64 存在；进入策略层（`mm::handle_page_fault`）前必须经 [`PageFaultCode::new`]
/// 包装为语义视图，位解读只发生在下方 trait impl 一处。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PageFaultCode(u64);

impl PageFaultCode {
    /// 包装中断路径交付的原始错误码。
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// 取出原始位（仅供日志/透传，禁止策略层解码）。
    pub const fn raw(self) -> u64 {
        self.0
    }
}

impl arch::PageFaultCode for PageFaultCode {
    fn is_write(self) -> bool {
        self.0 & PF_EC_WRITE != 0
    }
    fn is_user(self) -> bool {
        self.0 & PF_EC_USER != 0
    }
    fn is_present(self) -> bool {
        self.0 & PF_EC_PRESENT != 0
    }
    fn is_instruction_fetch(self) -> bool {
        self.0 & PF_EC_INSN != 0
    }
}

/// 保留位违规查询（x86 特有语义：bit3）。策略层经 [`arch::PageFaultCode`]
/// 四轴即可完成全部判定；本方法仅供诊断路径使用。
impl PageFaultCode {
    pub const fn is_reserved_violation(self) -> bool {
        self.0 & PF_EC_RSVD != 0
    }
}

// ---- 内核根页表（mm1.md MD4：销毁活动地址空间前的"回家表"）----

/// 启动期快照的内核根页表物理基址。
///
/// kmain 在**任何用户地址空间存在之前**调用 [`snapshot_kernel_root`] 一次；
/// 此后每个进程页表的内核半区都派生自该表（`X86PageTable::new` 复制当前表
/// 高半区顶层条目），它因此是唯一可长期驻留、销毁任意用户表后仍有效的根。
static KERNEL_ROOT: Once<u64> = Once::new();

/// 快照当前 CR3 为内核根页表（整个运行期恰好一次）。
///
/// 只允许 kmain 入口调用——晚于任何 `UserAddressSpace::activate` 就会把
/// 用户表误当内核根，debug_assert 当场暴露该顺序回归。
pub fn snapshot_kernel_root() {
    debug_assert!(
        KERNEL_ROOT.get().is_none(),
        "kernel root must be snapshotted exactly once, before any user address space exists"
    );
    KERNEL_ROOT.call_once(|| mmio::cr3() & !0xFFF);
}

/// 切回内核根页表。返回是否成功（未快照 = false 且不动 CR3）。
pub fn switch_to_kernel_root() -> bool {
    match KERNEL_ROOT.get() {
        Some(root) => {
            // 顺序同 `activate_tracked`：**先记录、后写 CR3**（保守方向）。
            // 本核离开用户地址空间，故记录置哨兵 —— 此后销毁该表的核不会把
            // 本核误判为持有者。
            record_current_cr3(my_slot(), CR3_NO_USER_SPACE);
            mmio::write_cr3(*root);
            true
        }
        None => false,
    }
}
