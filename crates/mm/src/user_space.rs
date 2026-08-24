//! 用户地址空间（每进程独立虚拟地址空间）。
//!
//! M1 里程碑：为进程提供独立的用户地址空间。
//! - 通过 `PT::new()` 从当前内核页表派生（继承内核映射，用户半区为空）——ADR-007/ADR-003。
//! - 提供用户区映射/解映射/翻译 API，区分用户映射（带 `user` 标志）。
//! - 记录已声明的用户区域（Area），为 M1.3 按需分页提供基础。
//! - M1.3 按需分页：支持"预留区域（present=0）"语义，缺页时按需补页。
//!
//! 泛型 `PT: PageTable` 使其不绑定具体架构（ADR-007）。
//! `PT::Error` 需可从 `klib::error::Error` 构造（ADR-010，统一错误码）。

use alloc::vec::Vec;

use arch::{
    ActivePageTable, PageFlags, PageSize, PageTable, PhysAddr, PhysFrame, VirtAddr, phys_to_virt,
};
use core::sync::atomic::{AtomicUsize, Ordering};

use klib::error::Error;
use klib::sync::irq::IrqSpinLock;

use crate::{allocate_frame, deallocate_frame};

/// 用户地址空间默认边界。x86-64 低半区为 bit63=0 的 128TiB。
pub const USER_BASE: u64 = 0x0000_0000_0000_0000;
pub const USER_TOP: u64 = 0x0000_8000_0000_0000; // 128TiB，x86-64 低半区边界

/// 用户缓冲区的访问意图（内核侧 STAC 拷贝预校验用）。
///
/// 方向决定校验强度：读意图只要求"已映射 + user 位"；写意图额外要求可写位
/// （present 但只读的页——如 COW 共享页——对内核侧写入同样会在内核态触发
/// #PF，必须在校验阶段就拒绝）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UserAccess {
    /// 内核从用户缓冲区读取（`copy_from_user` 方向）。
    Read,
    /// 内核向用户缓冲区写入（`copy_to_user` 方向）。
    Write,
}

/// 用户栈顶（低半区高地址）。栈向下增长，固定栈顶便于 `_start` 组装参数。
pub const USER_STACK_TOP: u64 = 0x0000_7fff_0000_0000;
/// 用户堆基址（`brk` 的初始断点）。
pub const USER_HEAP_BASE: u64 = 0x0000_0001_0000_0000;
/// 默认用户栈大小（预留区域，按需分页）。
pub const DEFAULT_STACK_SIZE: u64 = 4 * 1024 * 1024; // 4MiB

/// 单页属性查询结果（[`UserAddressSpace::query_page`] 返回，SYS_MEMORY_QUERY
/// 后端）。字段来自页表真值，不做任何推断。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PageQuery {
    /// 页表项 present。`query_page` 对 present=0 的 PTE 返回 `None`，
    /// 故经由 `Some` 路径观察到的本字段恒为 true——保留字段以稳定 ABI 投影。
    pub present: bool,
    /// 用户态可访问（PTE user 位）。
    pub user: bool,
    /// 可写（PTE rw 位）。
    pub writable: bool,
}

/// mmap 虚拟地址区间（预留区，按需分页）。
#[derive(Clone, Copy)]
pub struct MmapRegion {
    /// 起始虚拟地址。
    pub start: u64,
    /// 结束虚拟地址（不含）。
    pub end: u64,
}

/// 用户区来源。`munmap` 只允许释放由匿名 `mmap` 创建的区域，防止用户进程
/// 解除 ELF、堆或用户栈等由其专属生命周期管理的映射。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum UserAreaKind {
    /// 加载器或内核在指定虚拟地址建立的映射。
    Fixed,
    /// 堆、栈等按需分页保留区；由对应的专用 API 收缩/销毁。
    Reserved,
    /// `mmap` 创建的匿名按需分页区域；可经 `munmap` 释放。
    AnonymousMmap,
    /// 设备 MMIO 映射（K2 `map_mmio_user`）：页**真实映射**设备物理帧，
    /// 帧不归本地址空间所有——销毁/回收只清 PTE，绝不 `deallocate_frame`
    /// （与 shm 同一所有权纪律）。
    DeviceMmap,
}

/// 用户区映射记录（按需分页 / 统计用）。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UserArea {
    /// 起始虚拟地址（页对齐）。
    pub start: VirtAddr,
    /// 结束虚拟地址（不含，页对齐）。
    pub end: VirtAddr,
    /// 预留对齐粒度声明（MM5 语义定案）。
    ///
    /// 这是补页路径**优先尝试**的对齐粒度（2M 区先试 ORDER_2M 直通），不是
    /// 对实际叶粒度的承诺：直通失败（物理连续大块缺席）时按需补页会退化为
    /// 4K 逐页补齐，同一区域内 2M/4K 叶混用是**定案的合法状态**——后续补页
    /// 以 `translate` 探测跳过已映射页收敛，不依赖本字段的叶粒度含义。消费方
    /// （对齐计算/统计）不得把它当"区域内每一叶的实际大小"使用。
    pub size: PageSize,
    /// 权限标志。
    pub flags: PageFlags,
    /// 是否按需分页（`true` = 预留区域，尚未映射，访问时补页）。
    pub demand_paging: bool,
    /// 区域的所有权与释放策略。
    pub kind: UserAreaKind,
}

/// 写时复制（COW）共享页记账：一个已映射但被多个地址空间共享、只读的叶页。
///
/// `clone_cow` 把父用户区叶帧共享给子地址空间时记录在此；任一方对该页写入
/// 触发 #PF，`handle_page_fault` 据此分配新帧复制内容、改回可写独立映射，
/// 并从记账移除（该页此后归本地址空间私有）。
#[derive(Clone, Copy)]
pub struct CowPage {
    /// 虚拟地址（页对齐）。
    pub vaddr: u64,
    /// 当前共享的物理帧地址。
    pub phys: u64,
    /// 该页完整权限（含可写位，COW 复制后恢复）。
    pub flags: PageFlags,
}

/// 共享内存（shm）映射记账：本地址空间把某 shm 对象的物理帧映射到的区间。
///
/// 与 `areas` 分离：shm 帧归 shm 对象所有（多个进程共享），解映射/进程销毁时
/// **不能**释放这些帧（否则破坏其它进程的共享视图），故单独记账、单独清理。
#[derive(Clone, Copy)]
pub struct ShmMap {
    /// shm 对象 id。
    pub id: u64,
    /// 起始虚拟地址（页对齐）。
    pub vaddr: u64,
    /// 结束虚拟地址（不含，页对齐）。
    pub end: u64,
}

/// shm 映射所有权钩子（ipc1 IA1 / ADR-019）。
///
/// mm 只负责"本地址空间持有哪些映射条目"的事实；**引用计数归 ipc 对象表所
/// 有**——fork 继承与销毁清账时经本钩子通知对象所有方增减 refs。kernel 适配
/// 层在 init 时注入实现（mm 不反向依赖 ipc，依赖方向保持单向）。
pub trait ShmMappingHooks: Send + Sync {
    /// 本地址空间新继承了 `ids` 中每条映射（fork 成功路径，每条目一个元素）。
    fn on_mappings_acquired(&self, ids: &[u64]);
    /// 本地址空间销毁，`ids` 中每条映射随之消失（每条目一个元素）。
    fn on_mappings_released(&self, ids: &[u64]);
}

static SHM_HOOKS: IrqSpinLock<Option<&'static dyn ShmMappingHooks>> = IrqSpinLock::new(None);

/// 注入 shm 所有权钩子（kernel 启动时一次）。未注入时 clone/destroy 的钩子
/// 调用点以告警可见——静默跳过会掩盖 refs 漂移。
pub fn set_shm_mapping_hooks(hooks: &'static dyn ShmMappingHooks) {
    *SHM_HOOKS.lock() = Some(hooks);
}

fn shm_hooks_notify_acquired(ids: &[u64]) {
    if ids.is_empty() {
        return;
    }
    match SHM_HOOKS.lock().as_ref() {
        Some(h) => h.on_mappings_acquired(ids),
        None => klib::warn!(
            "[mm] {} shm mapping(s) inherited but ShmMappingHooks not installed; refs not bumped",
            ids.len()
        ),
    }
}

fn shm_hooks_notify_released(ids: &[u64]) {
    if ids.is_empty() {
        return;
    }
    match SHM_HOOKS.lock().as_ref() {
        Some(h) => h.on_mappings_released(ids),
        None => klib::warn!(
            "[mm] {} shm mapping(s) destroyed but ShmMappingHooks not installed; refs not decremented",
            ids.len()
        ),
    }
}

/// 用户地址空间：持有独立页表 `PT`，管理用户区。
pub struct UserAddressSpace<PT: PageTable> {
    /// 独立页表（继承内核映射 + 独立用户区）。
    pt: PT,
    /// 已声明的用户区域。
    areas: spin::Mutex<Vec<UserArea>>,
    /// 下一次 `mmap` 分配的候选虚拟地址（hint，单调向上增长）。
    next_mmap: u64,
    /// 当前堆断点（`brk` 管理；初始为 `USER_HEAP_BASE`）。
    heap_break: u64,
    /// 写时复制共享页记账（M5 COW）。
    cow_pages: spin::Mutex<Vec<CowPage>>,
    /// 共享内存映射记账（M5 IPC）。
    shm_maps: spin::Mutex<Vec<ShmMap>>,
    /// 资源是否已回收（防 `Drop` 与显式 `destroy` 重复释放）。
    destroyed: bool,
}

impl<PT> UserAddressSpace<PT>
where
    PT: PageTable,
    PT::Error: From<Error>,
{
    /// 新建一个用户地址空间：从当前内核页表派生独立页表（ADR-003 纯 spawn）。
    pub fn new() -> Result<Self, PT::Error> {
        let pt = PT::new()?;
        Ok(Self {
            pt,
            areas: spin::Mutex::new(Vec::new()),
            // mmap hint 从堆区上方的低地址开始增长（避开栈/堆的固定区）
            next_mmap: USER_HEAP_BASE + 16 * 1024 * 1024,
            heap_break: USER_HEAP_BASE,
            cow_pages: spin::Mutex::new(Vec::new()),
            shm_maps: spin::Mutex::new(Vec::new()),
            destroyed: false,
        })
    }

    /// 在用户空间映射一段物理页。
    ///
    /// `start`/`end` 必须在用户半区（`USER_BASE..USER_TOP`），否则返回错误。
    /// `phys_frames` 提供每页物理地址，长度需覆盖 `end-start` 的页数。
    pub fn map_user(
        &mut self,
        start: VirtAddr,
        end: VirtAddr,
        size: PageSize,
        flags: PageFlags,
        phys_frames: &[u64],
    ) -> Result<(), PT::Error> {
        let s = start.as_u64();
        let e = end.as_u64();
        if s < USER_BASE || e > USER_TOP || e <= s {
            return Err(Error::OutOfRange.into());
        }
        // 强制带 user 标志，保证用户态可访问
        let uflags = flags.user();
        let page = size.bytes();
        let count = ((e - s) + page - 1) / page;
        if (phys_frames.len() as u64) < count {
            return Err(Error::InvalidParam.into());
        }
        let mut vaddr = s;
        self.check_area_quota(e - s)?;
        for &phys in phys_frames.iter().take(count as usize) {
            self.pt
                .map(VirtAddr::new(vaddr), PhysAddr::new(phys), size, uflags)?;
            vaddr += page;
        }
        self.areas.lock().push(UserArea {
            start,
            end,
            size,
            flags: uflags,
            demand_paging: false,
            kind: UserAreaKind::Fixed,
        });
        Ok(())
    }

    /// 声明一个**按需分页**的预留区域：记录区域但不立即映射（present=0）。
    ///
    /// 用户态访问该区域时触发 #PF，由 `handle_page_fault` 按需补页。
    /// `start`/`end` 必须在用户半区且页对齐。
    pub fn reserve_user(
        &mut self,
        start: VirtAddr,
        end: VirtAddr,
        size: PageSize,
        flags: PageFlags,
    ) -> Result<(), PT::Error> {
        self.reserve_user_with_kind(start, end, size, flags, UserAreaKind::Reserved)
    }

    /// 声明按需分页区，并在区域记录中写入唯一的所有权策略。
    fn reserve_user_with_kind(
        &mut self,
        start: VirtAddr,
        end: VirtAddr,
        size: PageSize,
        flags: PageFlags,
        kind: UserAreaKind,
    ) -> Result<(), PT::Error> {
        let s = start.as_u64();
        let e = end.as_u64();
        if s < USER_BASE || e > USER_TOP || e <= s {
            return Err(Error::OutOfRange.into());
        }
        let uflags = flags.user();
        self.check_area_quota(e - s)?;
        self.areas.lock().push(UserArea {
            start,
            end,
            size,
            flags: uflags,
            demand_paging: true,
            kind,
        });
        Ok(())
    }

    /// 解除用户空间某虚拟地址的映射，返回被解映射的物理地址。
    pub fn unmap_user(&mut self, vaddr: VirtAddr) -> Result<PhysAddr, PT::Error> {
        self.pt.unmap(vaddr)
    }

    /// 翻译用户空间虚拟地址 → 物理地址。
    pub fn translate(&self, vaddr: VirtAddr) -> Option<PhysAddr> {
        self.pt.translate(vaddr)
    }

    /// 翻译用户空间虚拟地址 → （物理地址，叶层权限标志）。
    ///
    /// 供内核侧验证映射真实性/属性（如 K2 设备窗口的 PCD 断言）。
    pub fn translate_with_flags(&self, vaddr: VirtAddr) -> Option<(PhysAddr, PageFlags)> {
        self.pt.translate_with_flags(vaddr)
    }

    /// 单页属性查询（KM2：SYS_MEMORY_QUERY 的内核后端）。
    ///
    /// 返回该 4KB 页的页表真值属性；未映射（含 demand 区未触碰）返回 `None`。
    /// 只读页表，不触发补页。
    pub fn query_page(&self, vaddr: u64) -> Option<PageQuery> {
        /// 4KB 页对齐掩码。
        const PAGE_MASK: u64 = !0xFFF;
        let page = VirtAddr::new(vaddr & PAGE_MASK);
        let (_, flags) = self.pt.translate_with_flags(page)?;
        Some(PageQuery {
            present: true,
            user: flags.is_user(),
            writable: flags.is_writable(),
        })
    }

    /// 预校验用户缓冲区 `[start, start + len)` 对给定访问意图是否可被内核
    /// 侧 STAC 拷贝安全访问（EFAULT 路线，arch1.md AR1a）。
    ///
    /// 逐页检查本地址空间页表：
    /// - 页必须**已映射**（present）。按需分页预留区在用户触碰前没有 PTE，
    ///   判为不可访问——这是与 Linux 的成文差异：本项目无异常 fixup 表
    ///   （extable），内核态缺页无法补页，只能在校验阶段如实拒绝。用户程序
    ///   须先触碰自己的缓冲区（如写入）再把它交给 syscall。
    /// - 页必须带 user 权限位。
    /// - [`UserAccess::Write`] 意图额外要求可写位：present 但只读的页对内核
    ///   写入同样会触发内核态 #PF（arch 层对内核态 #PF 一律停机），一并拒绝。
    ///
    /// 校验通过后调用方的拷贝仍须一次性完整执行：本函数不提供并发屏障，
    /// 单线程 syscall 路径内校验与拷贝之间不存在解除映射的第三方。
    pub fn is_range_mapped(&self, start: u64, len: u64, access: UserAccess) -> bool {
        const PAGE_SIZE: u64 = 0x1000;
        if len == 0 {
            return true;
        }
        let Some(end) = start.checked_add(len) else {
            return false;
        };
        if start < USER_BASE || end > USER_TOP || end <= start {
            return false;
        }
        let mut page = start & !(PAGE_SIZE - 1);
        while page < end {
            match self.pt.translate_with_flags(VirtAddr::new(page)) {
                Some((_, flags)) => {
                    if !flags.is_user() {
                        return false;
                    }
                    if access == UserAccess::Write && !flags.is_writable() {
                        return false;
                    }
                }
                None => return false,
            }
            page += PAGE_SIZE;
        }
        true
    }

    /// 把本用户地址空间切换为活动页表（装入 CR3）。需 `PT: ActivePageTable`。
    pub fn activate(&self)
    where
        PT: ActivePageTable,
    {
        self.pt.activate();
    }

    /// 顶层页表物理基址（= 装载到 CR3 的值）。
    ///
    /// 供进程进入用户态（`TrapFrame::cr3`）与调度切换时使用。
    pub fn page_table_paddr(&self) -> u64 {
        self.pt.paddr()
    }

    /// 已声明用户虚拟区域的总字节数（O(区域数)）。
    ///
    /// MM7 语义澄清（原误名 used_bytes）：这是**虚拟预留量**（virtual size），
    /// 不是驻留集（RSS）——固定 ELF/栈映射与尚未 fault-in 的堆、匿名 mmap
    /// 预留区都按声明范围全额计入。任何把它当 RSS 消费的配额/telemetry 都会
    /// 得到夸大数倍的数字；真实驻留统计需按 PTE present 位逐页核算，待
    /// KA4 配额模型定案时一并引入。已 `munmap` 的范围不在统计中；共享内存
    /// 拥有独立对象生命周期，不属于此账本。
    pub fn declared_bytes(&self) -> u64 {
        self.areas
            .lock()
            .iter()
            .map(|area| area.end.as_u64() - area.start.as_u64())
            .sum()
    }

    /// 已声明的用户区域数（诊断用）。
    pub fn area_count(&self) -> usize {
        self.areas.lock().len()
    }

    /// 按需补页：处理用户态 #PF。
    ///
    /// 若 `vaddr` 落在某个 `demand_paging=true` 的预留区域内，则分配一个物理页、
    /// 建立映射（present=1），返回 `true`（补页成功，CPU 重试）。
    ///
    /// `code` 是架构层类型化的 #PF 错误码语义视图（ADR-007 / MM6）：本层只经
    /// [`arch::PageFaultCode::is_write`] 查询访问意图，禁止手解位编码。写访问
    /// 对**只读**预留区域会被拒绝，防止对不可写页反复补页导致的物理帧泄漏。
    ///
    /// 非法访问（未预留 / 越界 / 越权）返回 `false`，由上层终止进程。
    pub fn handle_page_fault<PC: arch::PageFaultCode>(&mut self, vaddr: u64, code: PC) -> bool {
        // COW 写故障（优先于按需分页）：命中共享页记账且本次为写访问 → 写时复制。
        if code.is_write() {
            let hit = self
                .cow_pages
                .lock()
                .iter()
                .position(|c| vaddr >= c.vaddr && vaddr < c.vaddr + 0x1000);
            if let Some(idx) = hit {
                return self.cow_fault(idx);
            }
        }
        let areas = self.areas.lock();
        let Some(idx) = areas
            .iter()
            .position(|a| a.demand_paging && vaddr >= a.start.as_u64() && vaddr < a.end.as_u64())
        else {
            return false; // 未预留区域 → 非法访问
        };
        let area = areas[idx];

        // 校验访问权限：写访问落在不可写区域一律拒绝（语义查询走抽象层
        // PageFlags，不手解位编码——MM6 前半已立的规矩同样适用于本处），
        // 避免"映射出不可写页 → CPU 重试仍写失败 → 再次 #PF → 再分配
        // 新帧覆盖旧 PTE"的无限循环与物理帧泄漏。
        if code.is_write() && !area.flags.is_writable() {
            return false;
        }

        // 1. 2MB 大页直通优化：如果区域本身是 Size2M 且对齐，直接分配 ORDER_2M 物理大页。
        //    MM5 定案：直通失败（无连续物理大块）即退化为下方 4K 逐页补齐——同一
        //    区域内叶粒度混合是该路径的**定案合法状态**，不是异常；`UserArea::size`
        //    只是预留对齐粒度声明，不构成叶粒度承诺（见其字段文档）。
        if area.size == PageSize::Size2M {
            let aligned = area.start.as_u64()
                + ((vaddr - area.start.as_u64()) / area.size.bytes()) * area.size.bytes();
            if let Some(frame) =
                crate::frame_allocator::allocate_frames(crate::frame_allocator::ORDER_2M)
            {
                let phys = frame.start_paddr();
                let page_virt = phys_to_virt(phys) as *mut u8;
                unsafe { core::ptr::write_bytes(page_virt, 0, area.size.bytes() as usize) };
                if self
                    .pt
                    .map(
                        VirtAddr::new(aligned),
                        PhysAddr::new(phys),
                        PageSize::Size2M,
                        area.flags.user(),
                    )
                    .is_ok()
                {
                    drop(areas);
                    return true;
                }
                deallocate_frame(frame);
            }
        }

        // 2. 4KB 页按需分配 + 批量预取（Fault-Ahead Prefetch）：
        // 当访问连续堆/栈区时，一次性从 LazyBuddy PerCpuCache 预充连续的最多 4 个物理页，
        // 极大降低连续线性写（如 Vec::push / 扩容）时的连续 #PF 异常触发开销。
        let aligned = area.start.as_u64() + ((vaddr - area.start.as_u64()) / 4096) * 4096;
        let mut mapped_any = false;
        let prefetch_count = 4usize;

        for step in 0..prefetch_count {
            let cur_v = aligned + (step as u64) * 4096;
            if cur_v >= area.end.as_u64() {
                break;
            }
            // 若该虚拟页已映射（可能被之前的操作建立过），跳过
            if self.pt.translate(VirtAddr::new(cur_v)).is_some() {
                continue;
            }

            let Some(frame) = allocate_frame() else {
                break;
            };
            let phys = frame.start_paddr();
            let page_virt = phys_to_virt(phys) as *mut u8;
            unsafe { core::ptr::write_bytes(page_virt, 0, 4096) };

            if self
                .pt
                .map(
                    VirtAddr::new(cur_v),
                    PhysAddr::new(phys),
                    PageSize::Size4K,
                    area.flags.user(),
                )
                .is_ok()
            {
                mapped_any = true;
            } else {
                deallocate_frame(frame);
                break;
            }
        }

        drop(areas);
        mapped_any
    }

    /// 写时复制（COW）页：把当前共享页复制为私有可写页（供 #PF 写故障调用）。
    ///
    /// 流程：先 `unmap` 清掉当前 PTE 并 flush TLB（COW 改映射必须 flush，否则 TLB
    /// 残留"只读→旧帧"条目导致重试仍 #PF、反复复制泄漏）→ 分配新帧并拷贝旧帧
    /// 内容 → 按完整权限（含可写位）重映射为独立页 → 释放对旧共享帧的引用
    /// （refcount 决定是否真正归还，因父子可能仍共享）→ 从 COW 记账移除本页。
    fn cow_fault(&mut self, idx: usize) -> bool {
        let cow = self.cow_pages.lock()[idx];
        let vaddr = VirtAddr::new(cow.vaddr);
        // unmap 清 PTE + flush TLB，返回当前共享物理帧。
        let old_phys = match self.pt.unmap(vaddr) {
            Ok(p) => p.as_u64(),
            Err(_) => return false,
        };
        // 分配新帧并拷贝旧帧内容。
        let Some(frame) = allocate_frame() else {
            // 物理内存耗尽：恢复原**只读**共享映射。必须用 readonly_flags——
            // 若按 cow.flags（含可写位）恢复，共享帧在 refcount≥2 时被重新映射
            // 为可写，父子进程获得同一物理帧的双写窗口，COW 语义整体击穿
            // （mm1.md MM1）。恢复本身失败必须告警：那会留下无解释缺页洞
            // （正是本回滚要防的事态，审计 B6），绝不静默。
            if self
                .pt
                .map(
                    vaddr,
                    PhysAddr::new(old_phys),
                    PageSize::Size4K,
                    readonly_flags(cow.flags),
                )
                .is_err()
            {
                klib::warn!(
                    "[cow] OOM rollback remap failed v={:#x} phys={:#x}; page stays faulting",
                    cow.vaddr,
                    old_phys
                );
            }
            return false;
        };
        let new_phys = frame.start_paddr();
        unsafe {
            core::ptr::copy_nonoverlapping(
                phys_to_virt(old_phys) as *const u8,
                phys_to_virt(new_phys) as *mut u8,
                4096,
            );
        }
        // 按完整权限（含可写）重映射为独立页。
        if self
            .pt
            .map(vaddr, PhysAddr::new(new_phys), PageSize::Size4K, cow.flags)
            .is_err()
        {
            // 罕见：映射失败，归还新帧，恢复原**只读**共享映射（同上：可写恢复
            // 会在 refcount≥2 时打开双写窗口，见 mm1.md MM1）。恢复失败告警
            // 同 B6——静默即无解释缺页洞。
            deallocate_frame(frame);
            if self
                .pt
                .map(
                    vaddr,
                    PhysAddr::new(old_phys),
                    PageSize::Size4K,
                    readonly_flags(cow.flags),
                )
                .is_err()
            {
                klib::warn!(
                    "[cow] rollback remap failed v={:#x} phys={:#x}; page stays faulting",
                    cow.vaddr,
                    old_phys
                );
            }
            return false;
        }
        // 释放对旧共享帧的引用（可能仍有其它地址空间引用，由 refcount 决定是否归还）。
        deallocate_frame(PhysFrame::from_paddr_raw(old_phys));
        // 本页此后归本地址空间私有，移出 COW 记账。
        self.cow_pages.lock().remove(idx);
        true
    }

    /// 写时复制（COW）派生一个**共享用户区**的子地址空间（M5）。
    ///
    /// 这是 ADR-003 纯 `spawn` 的补充能力：当需要"从父地址空间派生新进程用户区"
    /// 时，不做深拷贝（不复制每个物理帧），而是**浅拷贝页表、共享同一批物理
    /// 数据帧**并把双方对应 PTE 改为只读、记录 COW 记账。任一方后续写某页会
    /// 触发 #PF → [`cow_fault`] 按需复制该页，从而规避"复制父地址空间"的开销
    /// （ADR-003 路线下纯 spawn 本就深拷贝/独立建，COW 提供高效共享变体）。
    ///
    /// - 父、子各自持有**独立页表树**（中间页表页私有，unmap 互不干扰）；
    /// - 仅 **4KB 叶数据帧**被共享，引用计数在 [`crate::frame_allocator`] 统一管理，
    ///   保证任一方解映射不会令另一方悬空；
    /// - 调用后父进程对应用户页变为只读（后续写由父侧 COW 复制）。
    pub fn clone_cow(&mut self) -> Result<UserAddressSpace<PT>, PT::Error> {
        // 1. 收集父所有已映射用户叶页 (vaddr, phys, 完整 flags)。
        //
        // 审计 #8：**排除 DeviceMmap**——设备物理帧不是 RAM，COW 化它意味着
        // frame_incref(设备地址)=帧元数据野写、写故障触发真实设备寄存器读
        // 副作用、拷贝出的 RAM 帧因 destroy 的 kind 豁免永不归还（确定性
        // 泄漏）。设备窗口随进程语义本就应只读共享/随进程消亡。
        // 审计 B5：**固定 4K 步进**而非按声明粒度——大页拆分（KA3）后同一
        // 区域可混有 2M 叶与 4K 叶，按声明粒度步进会跳过区内的 4K 页令
        // fork 后父子静默分歧；逐 4K translate 对任意叶粒度都取到正确帧。
        const COW_STEP: u64 = PageSize::Size4K.bytes();
        let mut shares: Vec<(u64, u64, PageFlags)> = Vec::new();
        {
            let areas = self.areas.lock();
            for a in areas.iter() {
                if a.kind == UserAreaKind::DeviceMmap {
                    continue;
                }
                let mut v = a.start.as_u64();
                while v < a.end.as_u64() {
                    if let Some(phys) = self.pt.translate(VirtAddr::new(v)) {
                        shares.push((v, phys.as_u64(), a.flags));
                    }
                    v += COW_STEP;
                }
            }
        }
        // 2. 新建子地址空间（继承内核半区，用户区空），复制布局状态。
        let mut child = UserAddressSpace::<PT>::new()?;
        child.next_mmap = self.next_mmap;
        child.heap_break = self.heap_break;
        *child.areas.lock() = self.areas.lock().clone();
        // 3. 逐页 COW：父改只读 + 子映射共享帧只读 + 共享帧 incref + 双方记账。
        //    失败回滚纪律（mm1.md MM3）：父页一旦被 unmap，任何后续失败都必须
        //    先恢复父页映射再上抛——否则父地址空间留下无解释的缺页洞（静默
        //    损坏）。子半成品由 Drop 统一回收，无需在此手工清理。
        let mut child_cow = Vec::new();
        for (v, phys, flags) in shares {
            let ro = readonly_flags(flags);
            // 父 PTE 改只读（unmap 清 TLB + 重建只读，保留共享物理帧）。
            if self.pt.unmap(VirtAddr::new(v)).is_err() {
                continue;
            }
            if let Err(e) = self.pt.map(VirtAddr::new(v), PhysAddr::new(phys), PageSize::Size4K, ro)
            {
                // 父只读重建失败：恢复父页原映射（原权限），保持父空间完整。
                // 恢复失败必须告警（B6：静默即无解释缺页洞）。
                if self
                    .pt
                    .map(VirtAddr::new(v), PhysAddr::new(phys), PageSize::Size4K, flags)
                    .is_err()
                {
                    klib::warn!(
                        "[cow] clone rollback remap failed v={:#x} phys={:#x}; page stays faulting",
                        v,
                        phys
                    );
                }
                return Err(e);
            }
            if let Err(e) = child
                .pt
                .map(VirtAddr::new(v), PhysAddr::new(phys), PageSize::Size4K, ro)
            {
                // 子映射失败：撤销本页的 COW 改动——恢复父页原映射（原权限），
                // 引用计数未增无需回退，父空间不留洞。恢复失败告警（B6 同款）。
                if self
                    .pt
                    .map(VirtAddr::new(v), PhysAddr::new(phys), PageSize::Size4K, flags)
                    .is_err()
                {
                    klib::warn!(
                        "[cow] clone rollback remap failed v={:#x} phys={:#x}; page stays faulting",
                        v,
                        phys
                    );
                }
                return Err(e);
            }
            // 共享帧引用计数 +1（父 + 子各持一份引用）。
            crate::frame_allocator::frame_incref(phys);
            let cow = CowPage {
                vaddr: v,
                phys,
                flags,
            };
            self.cow_pages.lock().push(cow);
            child_cow.push(cow);
        }
        *child.cow_pages.lock() = child_cow;
        // 共享内存映射区：子地址空间独立页表，需重新映射同一批物理帧。
        // IA1（ADR-019）：子进程的每条继承映射都是一个**新的存活引用**——
        // 经所有权钩子为子列表中每个条目向对象表增记 refs（旧注释"不额外
        // 持有引用，保持简单"的决策已被审计推翻：它同时制造提前释放 UAF
        // 与永久泄漏两个方向的灾难）。
        //
        // 审计 R6-F1 时序修正：子 shm_maps 必须在重映射**全部成功后**才赋值。
        // 旧实现先整体克隆再逐条重映射，中途失败时被 Drop 的子空间会对已
        // 填充列表逐条发 release——acquire 零次 / release N 次，saturating_sub
        // 把 refs 压到 0，父进程仍存活的映射被提前回收（UAF/数据腐坏）。
        // 改为失败路径子表恒空：destroy 零释放，与未发生的 acquire 天然对称；
        // 已重映射的残余 PTE 随子页表顶层整体销毁，无需逐条清理。
        let inherited: alloc::vec::Vec<ShmMap> = self.shm_maps.lock().clone();
        for m in inherited.iter() {
            let npages = ((m.end - m.vaddr) / 0x1000) as usize;
            for i in 0..npages {
                if let Some(phys) = self
                    .pt
                    .translate(VirtAddr::new(m.vaddr + (i as u64) * 0x1000))
                {
                    child.pt.map(
                        VirtAddr::new(m.vaddr + (i as u64) * 0x1000),
                        phys,
                        PageSize::Size4K,
                        PageFlags::empty().writable().user(),
                    )?;
                }
            }
        }
        *child.shm_maps.lock() = inherited.clone();
        let inherited_ids: alloc::vec::Vec<u64> =
            inherited.iter().map(|m| m.id).collect();
        shm_hooks_notify_acquired(&inherited_ids);
        Ok(child)
    }

    /// 释放某个按需分页区域已映射的物理页（供进程退出/区域删除时回收）。
    /// 仅回收当前已映射的页，未映射部分不动。
    pub fn unmap_area_pages(&mut self, area_idx: usize) {
        let areas = self.areas.lock();
        let Some(&area) = areas.get(area_idx) else {
            return;
        };
        // 设备 MMIO 区的帧不归本地址空间，绝不回收。
        if area.kind == UserAreaKind::DeviceMmap {
            return;
        }
        drop(areas);
        let page = area.size.bytes();
        let mut v = area.start.as_u64();
        while v < area.end.as_u64() {
            if let Some(phys) = self.pt.translate(VirtAddr::new(v)) {
                if let Err(_) = self.pt.unmap(VirtAddr::new(v)) {
                    break;
                }
                deallocate_frame(PhysFrame::from_paddr_raw(phys.as_u64()));
            }
            v += page;
        }
    }

    /// 回收本地址空间占有的**全部物理资源**（进程退出 / 地址空间销毁时统一调用）。
    ///
    /// 覆盖三类资源：
    /// 1. **用户叶数据帧**：遍历 `areas`，对每个已映射页 `unmap` + `deallocate_frame`
    ///    （refcount 安全，COW 共享帧由帧引用计数决定是否真正归还）。`unmap` 会递归
    ///    释放已空的中间页表页（PD/PDPT/PT），故这些中间页一并回收；
    /// 2. **共享内存区**：仅清空对应 PTE（**不释放帧**——帧归 shm 对象所有，由对象
    ///    自身在最后一次 `shm_unmap` 时释放，此处若释放会破坏其它进程视图）；
    /// 3. **顶层页表页**：由 `new()` 分配、其它路径不回收的独立页，单独 `deallocate_frame`。
    ///
    /// 内核高半区顶层条目指向的是**跨地址空间共享**的内核页表，本地址空间只释放
    /// 顶层表页自身（帧），不触碰其指向的内核中间表，避免破坏其它进程内核映射。
    ///
    /// 幂等：`destroyed` 守卫避免 `Drop` 与显式 `destroy` 重复释放。
    pub fn destroy(&mut self) {
        if self.destroyed {
            return;
        }
        self.destroyed = true;

        // 1. 用户区叶帧 + 中间页表页（unmap 递归释放已空中间层）。
        //    DeviceMmap 区例外：帧属设备，只清 PTE、绝不归还（与 shm 同纪律）。
        let areas = self.areas.lock().clone();
        for a in areas.iter() {
            let page = a.size.bytes();
            let mut v = a.start.as_u64();
            while v < a.end.as_u64() {
                if let Some(phys) = self.pt.translate(VirtAddr::new(v)) {
                    let _ = self.pt.unmap(VirtAddr::new(v));
                    if a.kind != UserAreaKind::DeviceMmap {
                        deallocate_frame(PhysFrame::from_paddr_raw(phys.as_u64()));
                    }
                }
                v += page;
            }
        }

        // 2. 共享内存区：仅清 PTE，不释放帧（帧归 shm 对象）。IA1（ADR-019）：
        //    每条被销毁的映射经所有权钩子递减一个引用——否则任一进程不显式
        //    unmap 即退出，对象 refs 永不归零，帧与条目永久滞留（泄漏半边）。
        let shms = self.shm_maps.lock().clone();
        for m in shms.iter() {
            let mut v = m.vaddr;
            while v < m.end {
                let _ = self.pt.unmap(VirtAddr::new(v));
                v += 0x1000;
            }
        }
        let released_ids: alloc::vec::Vec<u64> = shms.iter().map(|m| m.id).collect();
        drop(shms);
        self.shm_maps.lock().clear();
        shm_hooks_notify_released(&released_ids);

        // 3. 顶层页表页自身。MD4：本地址空间恰为活动 CR3 时不再保守泄漏——
        //    先经架构快照切回内核根页表（回家表与本表高半区映射一致，切换对
        //    运行中的内核代码透明），随后顶层表页即可安全归还；架构未提供
        //    快照（理论不可达：kmain 必先快照）时保留旧的保守路径并显式 warn，
        //    绝不静默。
        let top = self.pt.paddr();
        let cur = PT::current_paddr();
        if top == cur {
            if PT::switch_to_kernel_root() {
                deallocate_frame(PhysFrame::from_paddr_raw(top));
            } else {
                klib::warn!(
                    "[user-space] leaking active top-level table {:#x}: arch has no kernel root snapshot",
                    top
                );
            }
        } else {
            deallocate_frame(PhysFrame::from_paddr_raw(top));
        }
    }

    /// 解映射并释放虚拟区间 `[lo, hi)` 内**已补页**的物理页（未映射的页跳过）。
    ///
    /// 供 `brk` 收缩等场景回收已映射内存。`lo`/`hi` 须页对齐。
    /// 步进大小取自覆盖该区间的区域页大小（缺省 4KB）。
    fn unmap_range(&mut self, lo: u64, hi: u64) {
        if lo >= hi {
            return;
        }
        let page = self
            .areas
            .lock()
            .iter()
            .find_map(|a| {
                if lo >= a.start.as_u64() && hi <= a.end.as_u64() {
                    Some(a.size.bytes())
                } else {
                    None
                }
            })
            .unwrap_or(4096);
        let mut v = lo;
        while v < hi {
            if let Some(phys) = self.pt.translate(VirtAddr::new(v)) {
                if self.pt.unmap(VirtAddr::new(v)).is_ok() {
                    deallocate_frame(PhysFrame::from_paddr_raw(phys.as_u64()));
                }
            }
            v += page;
        }
    }

    /// 检查虚拟区间 `[start, end)` 是否与任何已声明区域重叠。
    fn overlaps(&self, start: u64, end: u64) -> bool {
        self.areas.lock().iter().any(|a| {
            let as_ = a.start.as_u64();
            let ae = a.end.as_u64();
            !(end <= as_ || start >= ae) // 区间相交
        })
    }

    /// `mmap` 雏形：在用户半区分配一块**预留（按需分页）**虚拟地址区间。
    ///
    /// 返回区间起始地址（页对齐）。仅在地址空间中保留（present=0），
    /// 访问时由 `handle_page_fault` 补页。`size` 向上取整到页。
    ///
    /// 采用**确定性线性扫描**（非翻倍步进）：收集所有已声明区域，排序后从
    /// `next_mmap` 起逐个空隙寻找能容纳 `size` 的区间。这样保证**穷尽**——
    /// 只要存在足够大的空隙就一定能找到，不会像翻倍步进那样跳过大段空闲区间
    /// 而误报"no free mmap region"。扫描区间数即已声明区域数，规模很小（远小于
    /// 虚拟页数），不会退化死循环。
    pub fn mmap_user(&mut self, size: u64, flags: PageFlags) -> Result<u64, PT::Error> {
        let size = align_up_checked(size, 4096).ok_or(Error::InvalidParam)?;
        if size == 0 {
            return Err(Error::InvalidParam.into());
        }
        let gap_start = self.find_free_region(size).ok_or(Error::NoSpace)?;
        let end = gap_start + size;
        self.reserve_user_with_kind(
            VirtAddr::new(gap_start),
            VirtAddr::new(end),
            PageSize::Size4K,
            flags,
            UserAreaKind::AnonymousMmap,
        )?;
        self.next_mmap = end;
        Ok(gap_start)
    }

    /// 单地址空间设备 MMIO 映射上限（KA7 限额纪律：用户可申请的设备映射
    /// 总量有界，防循环 claim 耗尽地址空间/页表页）。
    const MAX_USER_MMIO_MAP_BYTES: u64 = 16 * 1024 * 1024;

    /// 单地址空间**区域总量**配额（KA7 第二层：内存记账强制第一级，
    /// RLIMIT_AS 语义）。默认值 = 参考平台（selftest QEMU -m 128MiB）物理
    /// 内存的一半：按需分页下"预留"即 OOM 承诺，单进程默认不得承诺超过
    /// 半数物理内存。**当前为编译期常量、无运行时覆盖机制**（审计 B3 如实
    /// 更正；S17 默认值理由如上）。若真机部署需要不同上限，须先立项注入点
    /// （启动参数/配置服务），不得静默改此值。DeviceMmap 另有更严的 16MiB
    /// 单类上限，但仍计入本配额。
    const MAX_USER_AREA_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

    /// 配额校验：`extra` 为本次拟新增的区域字节量。
    ///
    /// 占用量 = areas 区间长度和 + shm_maps 区间长度和（共享内存同样占用
    /// 本地址空间的页表页与 OOM 承诺）。锁序：areas → shm_maps，与 brk 的
    /// heap_clashes 检查一致（S21）。
    fn check_area_quota(&self, extra: u64) -> Result<(), PT::Error> {
        let used = {
            let areas = self.areas.lock();
            let shms = self.shm_maps.lock();
            let area_bytes: u64 = areas
                .iter()
                .map(|a| a.end.as_u64() - a.start.as_u64())
                .sum();
            let shm_bytes: u64 = shms.iter().map(|m| m.end - m.vaddr).sum();
            area_bytes + shm_bytes
        };
        if used.saturating_add(extra) > Self::MAX_USER_AREA_TOTAL_BYTES {
            // NoSpace 与 fd 表上限同一语义家族："进程级资源额度耗尽"。
            return Err(Error::NoSpace.into());
        }
        Ok(())
    }

    /// 把设备物理区间 `[phys, phys+size)` 真实映射到用户半区（K2 完全体，
    /// kernel1.md：UIO claim 的映射半程）。
    /// - `phys` 必须 4KiB 对齐，`size` 非零（向上取整到页）；总量受
    ///   [`MAX_USER_MMIO_MAP_BYTES`] 上限。
    /// - 页以 `writable + user + device_memory`（不可缓存，PCD）映射——设备
    ///   寄存器读有副作用，绝不允许缓存/投机语义介入。
    /// - 区域登记为 [`UserAreaKind::DeviceMmap`]：进程退出销毁时**只清 PTE、
    ///   不归还帧**（帧属设备，非本地址空间）。
    /// - 中途任一页映射失败即整体回滚（已映射页清 PTE 不还帧 + 撤销区域
    ///   记账），如实上抛首个错误。
    pub fn map_mmio_user(&mut self, phys: u64, size: u64) -> Result<u64, PT::Error> {
        const PAGE: u64 = 4096;
        if size == 0 || phys % PAGE != 0 {
            return Err(Error::InvalidParam.into());
        }
        // B4：size 用户可控，对齐前先 checked——溢出如实拒绝而非回绕。
        let len = align_up_checked(size, PAGE).ok_or(Error::InvalidParam)?;
        if len > Self::MAX_USER_MMIO_MAP_BYTES {
            return Err(Error::NoSpace.into());
        }
        // 物理端溢出防护（u64 回绕即非法请求）。
        if phys.checked_add(len).is_none() {
            return Err(Error::InvalidParam.into());
        }
        let va = self.find_free_region(len).ok_or(Error::NoSpace)?;
        let flags = PageFlags::empty().writable().user().device_memory();
        self.reserve_user_with_kind(
            VirtAddr::new(va),
            VirtAddr::new(va + len),
            PageSize::Size4K,
            flags,
            UserAreaKind::DeviceMmap,
        )?;
        // 逐页真实映射；失败回滚已映射部分（只 unmap，不还帧），撤销记账。
        let npages = (len / PAGE) as usize;
        for i in 0..npages {
            if let Err(e) = self.pt.map(
                VirtAddr::new(va + (i as u64) * PAGE),
                PhysAddr::new(phys + (i as u64) * PAGE),
                PageSize::Size4K,
                flags,
            ) {
                for j in 0..i {
                    let _ = self.pt.unmap(VirtAddr::new(va + (j as u64) * PAGE));
                }
                self.areas.lock().retain(|a| a.start.as_u64() != va);
                return Err(e);
            }
        }
        Ok(va)
    }

    /// 解除匿名 `mmap` 区间 `[start, start + len)`。
    ///
    /// `start` 必须 4KiB 对齐，`len` 必须非零且为 4KiB 的整数倍。整个请求必须
    /// 落在**同一个**由 [`mmap_user`] 创建的匿名区域内；这禁止借由 `munmap`
    /// 删除 ELF、堆、栈或共享内存等具有不同生命周期/所有权的映射。
    ///
    /// 已按需补页的叶 PTE 会真实解除并将帧交还给 frame allocator；尚未补页的
    /// 页面没有帧，只从区域记账中删除。完成后地址不再属于 demand-paging 区域，
    /// 因此随后的访问会被 #PF 路径拒绝而非重新分配。
    pub fn munmap_anonymous(&mut self, start: u64, len: u64) -> Result<(), PT::Error> {
        const PAGE_SIZE: u64 = 4096;
        if len == 0 || start % PAGE_SIZE != 0 || len % PAGE_SIZE != 0 {
            return Err(Error::InvalidParam.into());
        }
        let end = start.checked_add(len).ok_or(Error::InvalidParam)?;
        if start < USER_BASE || end > USER_TOP || end <= start {
            return Err(Error::InvalidParam.into());
        }

        // 先完整验证所有权和边界，任何非法请求均在修改页表/记账前失败。
        let (area_idx, area) = {
            let areas = self.areas.lock();
            let Some((idx, area)) = areas.iter().copied().enumerate().find(|(_, area)| {
                area.kind == UserAreaKind::AnonymousMmap
                    && start >= area.start.as_u64()
                    && end <= area.end.as_u64()
            }) else {
                return Err(Error::NotFound.into());
            };
            (idx, area)
        };
        debug_assert_eq!(area.size, PageSize::Size4K);

        // PTE 与数据帧始终成对释放。translate 为 None 的页是尚未 demand-fault 的
        // 预留页；它没有任何资源可回收，但仍必须从区域范围中移除。
        let mut vaddr = start;
        while vaddr < end {
            if let Some(phys) = self.pt.translate(VirtAddr::new(vaddr)) {
                self.pt.unmap(VirtAddr::new(vaddr))?;
                deallocate_frame(PhysFrame::from_paddr_raw(phys.as_u64()));
            }
            vaddr += PAGE_SIZE;
        }

        // COW 记录与 PTE 同步删除，防止后续 #PF 将已经 munmap 的页错误视为 COW 页。
        self.cow_pages
            .lock()
            .retain(|cow| cow.vaddr < start || cow.vaddr >= end);

        // 区间可以从匿名区域中部切除；保留左右两侧的原属性和匿名所有权。先 remove
        // 再插入，保证同一匿名区域不出现重叠的重复记录。
        let mut areas = self.areas.lock();
        let removed = areas.remove(area_idx);
        debug_assert_eq!(removed.start.as_u64(), area.start.as_u64());
        if area.start.as_u64() < start {
            areas.push(UserArea {
                end: VirtAddr::new(start),
                ..area
            });
        }
        if end < area.end.as_u64() {
            areas.push(UserArea {
                start: VirtAddr::new(end),
                ..area
            });
        }
        drop(areas);

        // MD2：释放区间若位于 mmap 游标之下，把游标回退到该区间起点——线性
        // 扫描只向游标上方找空隙，不回退则刚释放的地址带永远不可复用（虚拟
        // 区间单向往上泄漏）。回退是安全的：find_free_region 仍会避开全部
        // 已声明区域，且紧邻释放点的复用正是期望行为。
        if start < self.next_mmap {
            self.next_mmap = start;
        }
        Ok(())
    }

    /// 在用户半区找一个能容纳 `size`（页对齐）的空闲虚拟区间，不记账。
    ///
    /// 采用**确定性线性扫描**（非翻倍步进）：收集所有已声明区域，排序后从
    /// `next_mmap` 起逐个空隙寻找能容纳 `size` 的区间。这样保证**穷尽**——
    /// 只要存在足够大的空隙就一定能找到，不会像翻倍步进那样跳过大段空闲区间
    /// 而误报"no free mmap region"。扫描区间数即已声明区域数，规模很小。
    ///
    /// 返回区间起始地址（页对齐），仅供调用方决定（`mmap_user` 记账为按需分页
    /// 预留区；`map_shm` 记账为共享内存映射）。
    fn find_free_region(&self, size: u64) -> Option<u64> {
        if size == 0 {
            return None;
        }
        let mut regions: Vec<(u64, u64)> = self
            .areas
            .lock()
            .iter()
            .map(|a| (a.start.as_u64(), a.end.as_u64()))
            .collect();
        // 共享内存映射区也要参与空隙计算，避免与 shm 区重叠。
        for s in self.shm_maps.lock().iter() {
            regions.push((s.vaddr, s.end));
        }
        regions.sort_unstable();

        let top_limit = USER_STACK_TOP - 8 * 1024 * 1024;
        let candidate = align_up(self.next_mmap, 4096);
        let mut prev_end = candidate;
        for (rs, re) in regions.iter() {
            let rs = align_up(*rs, 4096);
            let gap_start = candidate.max(prev_end);
            if gap_start < rs {
                let end = gap_start.checked_add(size).unwrap_or(u64::MAX);
                if end <= rs && end <= top_limit {
                    return Some(gap_start);
                }
            }
            prev_end = prev_end.max(*re);
        }
        let gap_start = candidate.max(prev_end);
        if gap_start < top_limit {
            let end = gap_start.checked_add(size).unwrap_or(u64::MAX);
            if end <= top_limit {
                return Some(gap_start);
            }
        }
        None
    }

    /// 把共享内存对象 `id` 的物理帧映射到本地址空间（M5 IPC）。
    ///
    /// 分配一段空闲虚拟区间，把 `frames` 逐页映射（带 user/可写）。**不**把该
    /// 区间记入 `areas`（帧归 shm 对象所有，多进程共享，解映射时不能释放），
    /// 而记入独立的 `shm_maps`。返回映射起始虚拟地址。
    pub fn map_shm(&mut self, id: u64, frames: &[u64], size: u64) -> Result<u64, PT::Error> {
        // B4：size 经 IPC 路径最终源自用户，对齐前 checked。
        let size = align_up_checked(size, 4096).ok_or(Error::InvalidParam)?;
        let npages = (size / 0x1000) as usize;
        if npages == 0 || frames.len() < npages {
            return Err(Error::InvalidParam.into());
        }
        let gap_start = self.find_free_region(size).ok_or(Error::NoSpace)?;
        let flags = PageFlags::empty().writable().user();
        self.check_area_quota(size)?;
        for i in 0..npages {
            self.pt.map(
                VirtAddr::new(gap_start + (i as u64) * 0x1000),
                PhysAddr::new(frames[i]),
                PageSize::Size4K,
                flags,
            )?;
        }
        self.next_mmap = gap_start + size;
        self.shm_maps.lock().push(ShmMap {
            id,
            vaddr: gap_start,
            end: gap_start + size,
        });
        Ok(gap_start)
    }

    /// 解除本地址空间对共享内存对象 `id` 的映射（**不释放帧**，帧归 shm 对象）。
    ///
    /// 找到该 id 的映射区间，逐页 `unmap`（返回物理帧但交给 shm 对象管理），
    /// 并从 `shm_maps` 记账移除。返回被解映射的区间起始地址。
    pub fn unmap_shm(&mut self, id: u64) -> Result<u64, PT::Error> {
        let mut maps = self.shm_maps.lock();
        let Some(idx) = maps.iter().position(|m| m.id == id) else {
            return Err(Error::NotFound.into());
        };
        let m = maps[idx];
        let mut v = m.vaddr;
        while v < m.end {
            // 忽略解映射结果（帧不在此释放，交由 shm 对象 / 最后一次 unmap 时释放）。
            let _ = self.pt.unmap(VirtAddr::new(v));
            v += 0x1000;
        }
        maps.remove(idx);
        Ok(m.vaddr)
    }

    /// 共享内存映射数（诊断）。
    #[allow(dead_code)]
    pub fn shm_map_count(&self) -> usize {
        self.shm_maps.lock().len()
    }

    /// 在固定栈顶下方预留用户栈区（向下增长，按需分页）。
    ///
    /// 返回栈顶虚拟地址（高地址端）。栈区起点 = 栈顶 - 栈大小。
    pub fn setup_stack(&mut self, size: u64) -> Result<u64, PT::Error> {
        let size = align_up(size, 4096);
        let top = USER_STACK_TOP;
        let bottom = top - size;
        if bottom < USER_BASE {
            return Err(Error::OutOfRange.into());
        }
        if self.overlaps(bottom, top) {
            return Err(Error::AlreadyExists.into());
        }
        self.reserve_user(
            VirtAddr::new(bottom),
            VirtAddr::new(top),
            PageSize::Size4K,
            PageFlags::empty().writable(),
        )?;
        Ok(top)
    }

    /// `brk` 雏形：调整堆断点。
    ///
    /// - 传入 `0`：仅查询当前断点。
    /// - 传入新断点：若在 `[USER_HEAP_BASE, 栈底)` 内则更新（可收缩），返回新断点。
    /// - 扩展：记录新断点，访问新堆区由 `handle_page_fault` 按需补页。
    /// - 收缩：收窄堆区域的 `end`，并解映射/释放 `[new_break, 旧断点)` 内已补页，
    ///   保证进程无法访问"已归还"的堆内存。
    pub fn brk(&mut self, new_break: u64) -> Result<u64, PT::Error> {
        if new_break == 0 {
            return Ok(self.heap_break);
        }
        if new_break < USER_HEAP_BASE || new_break >= USER_STACK_TOP {
            return Err(Error::OutOfRange.into());
        }
        let new_break = align_up(new_break, 4096);
        if new_break < self.heap_break {
            // 收缩：收窄堆区域的 end，并解映射/释放 [new_break, heap_break) 内已补页，
            // 避免进程访问"已归还"的堆内存（越权读写/信息泄露）。
            let mut areas = self.areas.lock();
            if let Some(a) = areas
                .iter_mut()
                .find(|a| a.start.as_u64() == USER_HEAP_BASE)
            {
                a.end = VirtAddr::new(new_break);
            }
            drop(areas);
            self.unmap_range(new_break, self.heap_break);
        } else if new_break > self.heap_break {
            // 扩展：把 [heap_base, new_break) 声明为按需分页区。
            //
            // 配额先于一切变更（RLIMIT_AS：增长量计入区域总量）。
            self.check_area_quota(new_break - self.heap_break)?;
            //
            // 先校验目标区间与既有**非堆**区域及共享内存映射无重叠。堆区自身
            // （start == USER_HEAP_BASE）是被扩展对象，豁免。若放行重叠，
            // handle_page_fault 会按 Vec 顺序取第一个匹配 area 补页：页归谁、
            // 用什么权限全看记录顺序——同进程内可对"声称只读的 mmap 区"获得
            // 可写页，或反之（mm1.md MM2）。返回 AlreadyExists，与 setup_stack
            // 的既有纪律一致。
            let heap_clashes = |areas: &[UserArea], shms: &[ShmMap]| -> bool {
                let intersects = |as_: u64, ae: u64| !(new_break <= as_ || USER_HEAP_BASE >= ae);
                areas.iter().any(|a| {
                    a.start.as_u64() != USER_HEAP_BASE && intersects(a.start.as_u64(), a.end.as_u64())
                }) || shms.iter().any(|s| intersects(s.vaddr, s.end))
            };
            if heap_clashes(&self.areas.lock(), &self.shm_maps.lock()) {
                return Err(Error::AlreadyExists.into());
            }
            // 若之前从未声明堆区，创建；否则更新现有堆区的 end。
            let mut areas = self.areas.lock();
            let mut found = false;
            for a in areas.iter_mut() {
                if a.start.as_u64() == USER_HEAP_BASE {
                    a.end = VirtAddr::new(new_break);
                    a.flags = PageFlags::empty().writable().user();
                    found = true;
                    break;
                }
            }
            drop(areas);
            if !found {
                self.reserve_user(
                    VirtAddr::new(USER_HEAP_BASE),
                    VirtAddr::new(new_break),
                    PageSize::Size4K,
                    PageFlags::empty().writable(),
                )?;
            }
        }
        self.heap_break = new_break;
        Ok(self.heap_break)
    }

    /// 当前堆断点。
    pub fn heap_break(&self) -> u64 {
        self.heap_break
    }
}

impl<PT> Drop for UserAddressSpace<PT>
where
    PT: PageTable,
{
    /// 地址空间析构即回收全部物理资源（进程退出 / 调度器 `terminate` 丢弃 `Process`
    /// 时自动触发），保证"进程退出后页表/帧不泄漏"。
    fn drop(&mut self) {
        self.destroy();
    }
}

/// 向上对齐到页（4KB）。溢出安全版（审计 B4）：`v` 接近 u64::MAX 时裸
/// `v + align - 1` 回绕——debug 构建下用户一个 size 参数即可 panic 内核
/// （DoS），release 下回绕为小值静默通过。溢出如实返回 None。
fn align_up_checked(v: u64, align: u64) -> Option<u64> {
    v.checked_add(align - 1).map(|x| x & !(align - 1))
}

/// 向上对齐到页（4KB）。
///
/// 仅限**内核内部已论证有界**的值（如页表遍历游标）；一切用户可控的
/// size/len 必须走 [`align_up_checked`] 并把 None 翻译为 InvalidParam。
fn align_up(v: u64, align: u64) -> u64 {
    (v + align - 1) & !(align - 1)
}

/// 构造只读页标志：保留 user / executable，清除 writable（COW 共享页用）。
///
/// 经抽象层 [`PageFlags`] 的查询/构造器逐位还原，不在本层手解裸位编码
/// （mm1.md MM6：架构语义归 arch 层所有）。
fn readonly_flags(flags: PageFlags) -> PageFlags {
    let mut f = PageFlags::empty();
    if flags.is_user() {
        f = f.user();
    }
    if flags.is_executable() {
        f = f.executable();
    }
    f
}

// ---- 全局"当前用户地址空间"（M1.3 按需分页的 #PF 入口）----
// M1 阶段以单地址空间简化处理；M2/M3 引入进程结构后改为 per-process 挂载。

/// 缺页处理函数类型（extern "C"，与 `arch_x86_64::interrupts::PageFaultHandler` 一致）。
type FaultHandlerFn = extern "C" fn(u64, u64) -> bool;

/// 当前活动用户地址空间的缺页处理器（函数指针，避免泛型静态）。
static CURRENT_PF_HANDLER: AtomicUsize = AtomicUsize::new(0);

/// 设置当前用户地址空间的缺页处理函数（M2/M3 前简化：全局唯一）。
pub fn set_page_fault_handler(f: FaultHandlerFn) {
    CURRENT_PF_HANDLER.store(f as usize, Ordering::SeqCst);
}

/// #PF 入口：转发给当前用户地址空间的 `handle_page_fault`。
///
/// extern "C" ABI 载体：第二参数是**架构不透明的原始错误码**（由中断链原样
/// 交付）。位解读发生在下游注册方的边界处（task/tests 各自包装为实现了
/// [`arch::PageFaultCode`] 的架构类型），本函数不做任何解码。
pub extern "C" fn page_fault_entry(vaddr: u64, error_code: u64) -> bool {
    let f = CURRENT_PF_HANDLER.load(Ordering::SeqCst);
    if f == 0 {
        return false;
    }
    let f: FaultHandlerFn = unsafe { core::mem::transmute(f) };
    f(vaddr, error_code)
}
