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
    /// 非法访问（未预留 / 越界 / 越权）返回 `false`，由上层终止进程。
    pub fn handle_page_fault(&mut self, vaddr: u64, _error_code: u64) -> bool {
        let areas = self.areas.lock();
        let Some(idx) = areas.iter().position(|a| {
            a.demand_paging
                && vaddr >= a.start.as_u64()
                && vaddr < a.end.as_u64()
        }) else {
            return false; // 未预留区域 → 非法访问
        };
        let area = areas[idx];

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
