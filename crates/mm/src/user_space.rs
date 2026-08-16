//! 用户地址空间（每进程独立虚拟地址空间）。
//!
//! M1 里程碑：为进程提供独立的用户地址空间。
//! - 通过 `PT::new()` 从当前内核页表派生（继承内核映射，用户半区为空）——ADR-007/ADR-003。
//! - 提供用户区映射/解映射/翻译 API，区分用户映射（带 `user` 标志）。
//! - 记录已声明的用户区域（Area），为 M1.3 按需分页提供基础。
//! - M1.3 按需分页：支持"预留区域（present=0）"语义，缺页时按需补页。
//!
//! 泛型 `PT: PageTable` 使其不绑定具体架构（ADR-007）。
//! `PT::Error` 需可从 `&'static str` 构造（x86 实现 `Error = &'static str` 满足）。

use alloc::vec::Vec;

use arch::{
    phys_to_virt, ActivePageTable, PageFlags, PageSize, PhysAddr, PhysFrame, PageTable, VirtAddr,
};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::{allocate_frame, deallocate_frame};

/// 用户地址空间默认边界。x86-64 低半区为 bit63=0 的 128TiB。
pub const USER_BASE: u64 = 0x0000_0000_0000_0000;
pub const USER_TOP: u64 = 0x0000_8000_0000_0000; // 128TiB，x86-64 低半区边界

/// 用户栈顶（低半区高地址）。栈向下增长，固定栈顶便于 `_start` 组装参数。
pub const USER_STACK_TOP: u64 = 0x0000_7fff_0000_0000;
/// 用户堆基址（`brk` 的初始断点）。
pub const USER_HEAP_BASE: u64 = 0x0000_0001_0000_0000;
/// 默认用户栈大小（预留区域，按需分页）。
pub const DEFAULT_STACK_SIZE: u64 = 4 * 1024 * 1024; // 4MiB

/// mmap 虚拟地址区间（预留区，按需分页）。
#[derive(Clone, Copy)]
pub struct MmapRegion {
    /// 起始虚拟地址。
    pub start: u64,
    /// 结束虚拟地址（不含）。
    pub end: u64,
}

/// 用户区映射记录（按需分页 / 统计用）。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UserArea {
    /// 起始虚拟地址（页对齐）。
    pub start: VirtAddr,
    /// 结束虚拟地址（不含，页对齐）。
    pub end: VirtAddr,
    /// 页大小。
    pub size: PageSize,
    /// 权限标志。
    pub flags: PageFlags,
    /// 是否按需分页（`true` = 预留区域，尚未映射，访问时补页）。
    pub demand_paging: bool,
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
}

impl<PT> UserAddressSpace<PT>
where
    PT: PageTable,
    PT::Error: From<&'static str>,
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
            return Err("user region out of range".into());
        }
        // 强制带 user 标志，保证用户态可访问
        let uflags = flags.user();
        let page = size.bytes();
        let count = ((e - s) + page - 1) / page;
        if (phys_frames.len() as u64) < count {
            return Err("not enough phys frames".into());
        }
        let mut vaddr = s;
        for &phys in phys_frames.iter().take(count as usize) {
            self.pt.map(VirtAddr::new(vaddr), PhysAddr::new(phys), size, uflags)?;
            vaddr += page;
        }
        self.areas.lock().push(UserArea {
            start,
            end,
            size,
            flags: uflags,
            demand_paging: false,
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
        let s = start.as_u64();
        let e = end.as_u64();
        if s < USER_BASE || e > USER_TOP || e <= s {
            return Err("user region out of range".into());
        }
        let uflags = flags.user();
        self.areas.lock().push(UserArea {
            start,
            end,
            size,
            flags: uflags,
            demand_paging: true,
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

    /// 把本用户地址空间切换为活动页表（装入 CR3）。需 `PT: ActivePageTable`。
    pub fn activate(&self)
    where
        PT: ActivePageTable,
    {
        self.pt.activate();
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
    /// `error_code` 用于校验访问权限：bit1(W) 置位表示写访问，对**只读**预留区域
    /// 的写故障会被拒绝，防止对不可写页反复补页导致的物理帧泄漏。
    ///
    /// 非法访问（未预留 / 越界 / 越权）返回 `false`，由上层终止进程。
    pub fn handle_page_fault(&mut self, vaddr: u64, error_code: u64) -> bool {
        let areas = self.areas.lock();
        let Some(idx) = areas.iter().position(|a| {
            a.demand_paging
                && vaddr >= a.start.as_u64()
                && vaddr < a.end.as_u64()
        }) else {
            return false; // 未预留区域 → 非法访问
        };
        let area = areas[idx];

        // 校验访问权限：error_code 的 bit1(W) 表示本次为写访问。若区域不可写，
        // 拒绝写故障，避免"映射出不可写页 → CPU 重试仍写失败 → 再次 #PF → 再分配
        // 新帧覆盖旧 PTE"的无限循环与物理帧泄漏。
        if error_code & 0b10 != 0 && area.flags.bits() & (1 << 1) == 0 {
            return false;
        }

        // 分配物理页
        let frame = match allocate_frame() {
            Some(f) => f,
            None => return false, // 物理内存耗尽
        };
        let phys = frame.start_paddr();

        // 清零该物理页（经 HHDM 虚拟地址），保证新页内容确定
        let page_virt = phys_to_virt(phys) as *mut u8;
        unsafe { core::ptr::write_bytes(page_virt, 0, area.size.bytes() as usize) };

        // 建立映射（带 user 标志 + 区域权限）
        let aligned = area.start.as_u64() + ((vaddr - area.start.as_u64()) / area.size.bytes()) * area.size.bytes();
        if let Err(_) = self.pt.map(
            VirtAddr::new(aligned),
            PhysAddr::new(phys),
            area.size,
            area.flags.user(),
        ) {
            // 映射失败：释放刚分配的页
            deallocate_frame(frame);
            return false;
        }
        drop(areas);
        true
    }

    /// 释放某个按需分页区域已映射的物理页（供进程退出/区域删除时回收）。
    /// 仅回收当前已映射的页，未映射部分不动。
    pub fn unmap_area_pages(&mut self, area_idx: usize) {
        let areas = self.areas.lock();
        let Some(&area) = areas.get(area_idx) else { return };
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
    pub fn mmap_user(&mut self, size: u64, flags: PageFlags) -> Result<u64, PT::Error> {
        let size = align_up(size, 4096);
        if size == 0 {
            return Err("mmap size is zero".into());
        }
        // 从 hint 起单调向上找不与已有区域重叠的空闲区间。
        // 采用"翻倍步进"探测：在碎片化地址空间（大量小区域）下，固定 `size` 步长
        // 逐段扫描会退化为接近 USER_TOP/4096 ≈ 2^47 次迭代（近乎死循环）；
        // 翻倍步进可在 ~64 次迭代内覆盖整个 128TiB 用户空间，且仍返回合法的空闲区间。
        let mut candidate = align_up(self.next_mmap, 4096);
        let mut step = size;
        let mut tries = 0u32;
        while candidate + size <= USER_TOP && tries < 64 {
            if !self.overlaps(candidate, candidate + size) {
                self.reserve_user(
                    VirtAddr::new(candidate),
                    VirtAddr::new(candidate + size),
                    PageSize::Size4K,
                    flags,
                )?;
                self.next_mmap = candidate + size;
                return Ok(candidate);
            }
            // 跳过密集已用区：以翻倍步长快速推进候选地址（saturating 防 u64 溢出）。
            candidate = align_up(candidate.saturating_add(step), 4096);
            step = step.saturating_mul(2);
            tries += 1;
            // 保护：跳过栈区（USER_STACK_TOP 以下 8MiB 内不做 mmap）
            if candidate >= USER_STACK_TOP - 8 * 1024 * 1024 {
                break;
            }
        }
        Err("no free mmap region".into())
    }

    /// 在固定栈顶下方预留用户栈区（向下增长，按需分页）。
    ///
    /// 返回栈顶虚拟地址（高地址端）。栈区起点 = 栈顶 - 栈大小。
    pub fn setup_stack(&mut self, size: u64) -> Result<u64, PT::Error> {
        let size = align_up(size, 4096);
        let top = USER_STACK_TOP;
        let bottom = top - size;
        if bottom < USER_BASE {
            return Err("stack too large".into());
        }
        if self.overlaps(bottom, top) {
            return Err("stack region overlaps".into());
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
            return Err("brk out of range".into());
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

/// 向上对齐到页（4KB）。
fn align_up(v: u64, align: u64) -> u64 {
    (v + align - 1) & !(align - 1)
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
pub extern "C" fn page_fault_entry(vaddr: u64, error_code: u64) -> bool {
    let f = CURRENT_PF_HANDLER.load(Ordering::SeqCst);
    if f == 0 {
        return false;
    }
    let f: FaultHandlerFn = unsafe { core::mem::transmute(f) };
    f(vaddr, error_code)
}
