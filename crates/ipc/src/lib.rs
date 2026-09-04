//! 进程间通信（IPC）子系统（共享内存 shm + 管道 pipe，独立 Crate）。
//!
//! 设计（RESTful 资源观，对齐 syscall 二维编码 ADR-003）：
//! - **共享内存（shm）**：`shm_create(size) -> id` 分配一组物理帧登记为对象；
//!   `shm_map(id) -> addr` 把对象帧映射进调用进程地址空间；`shm_unmap(id)` 解除映射。
//! - **管道（pipe）**：`pipe_create() -> id` 建环形缓冲；`pipe_read` / `pipe_write`
//!   必要时阻塞读写。
//!
//! ## 用户缓冲边界契约（ipc1 IR1 / ADR-018）
//!
//! 本 crate 的管道 API 是用户缓冲的合法入口，但**绝不裸解引用用户指针**：
//! 所有拷贝经 [`validate_user_range`]（窗口 + 逐页页表预校验，复用 mm 单点
//! `is_range_mapped`）通过后，才在 SMAP 放行窗口内整块 memcpy（复用 arch
//! 的 copy_from_user/copy_to_user，ipc1 ID3）。校验失败如实上抛
//! `BadAddress`/`OutOfRange`，不存在内核态 #PF 路径。
//!
//! ## 阻塞原子性契约（ipc1 IA2a + 审计 R6-F2）
//!
//! 等待者登记与置 Blocked 在调度锁内由
//! [`IpcTaskNotifier::block_with_registration`] 原子完成，且**登记点持表锁
//! 复检唤醒条件**——条件在登记与主循环检查之间被唤醒方翻转时，复检置位
//! ready 通道、本方不入册直接重试。因此唤醒方的 "消费 + drain + wake" 无论
//! 发生在本方循环检查之前还是之后，都不可能造成信号丢失：发生在前 ⇒ 复检
//! 看见条件为真；发生在后 ⇒ 本方已在册且 Blocked，wake 正常生效。经典
//! lost-wakeup 窗口不存在。唤醒侧先收集后 wake，PIPE→per-pid(调度进程锁) 反向锁边已根除。
//! 锁序全局单向：NOTIFIER → per-pid(调度进程锁，逐进程取放，无全局池锁) → PIPE_TABLE。
//!
//! ## shm 映射记账契约（ipc1 IA1 / ADR-019）
//!
//! `refs` 数的是**跨全部地址空间的存活映射条目**：fork 继承按条目增记、
//! 地址空间销毁按条目递减、显式 unmap 移除一条递减一。归零即对象与帧一并
//! 回收。钩子入口 [`shm_on_mappings_acquired`] / [`shm_on_mappings_released`]
//! 由 kernel 适配层实现 mm 的 `ShmMappingHooks` 后接线。

#![no_std]

mod sync;
pub use sync::*;

extern crate alloc;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use arch::PageSize;
use arch_x86_64::interrupts::InterruptFrame;
use klib::error::Error;
use klib::sync::irq::IrqSpinLock;

/// 管道单轮搬运的切块上限（字节，非总容量）。
///
/// 为什么是 4096：与单页粒度一致——管道数据通常伴随页对齐的用户缓冲流动，
/// 切块取页大小使"单次写满一页"与"单次校验一页数"同为 1 页量级；亦与 Linux
/// pipe buffer 的页粒度传统一致。
///
/// **非总容量**：ipc1 同期修复后管道缓冲为**无界**（`pipe.buf` 按需增长），
/// 写者绝不因"缓冲满"阻塞——彻底移除顺序管道模型下中间段写满 4096B 即
/// 死锁的限制（shell `A | B | C` 可流通任意大中间数据）。单轮 staging 拷贝仍
/// 以 4096B 为界（B2 有界上限纪律），故本常量保留为每轮切块上限。
pub const PIPE_CAPACITY: usize = 4096;

/// 单次用户范围校验的字节上限（S13：抽取散落魔法字面量）。与 syscall 层
/// `MAX_SYSCALL_BUF_BYTES` 同值同源——64 MiB 是"一用户拷贝请求"的合理
/// 有界上限，超过直接拒绝（B2 有界上限纪律），避免拷贝路径被任意大长度
/// 撑爆。
pub const MAX_COPY_BYTES: u64 = 64 * 1024 * 1024;

/// 单管道每方向等待者上限（ipc1 IM6）。
///
/// 为什么是 64：远超单用户玩具内核同一管道上并发阻塞读者/写者的合理规模
/// （进程总数受物理内存约束在两位数量级），同时把等待 Vec 的增长钉死在常数
/// ——用户态忙轮询重试无法再借重复登记线性吃尽内核堆。
pub const MAX_PIPE_WAITERS: usize = 64;

/// 阻塞请求的结果（KA6：bool+frame 形状的枚举化收口）。
///
/// bool 返回值可被调用方无视——`Switched` 分支下 `*frame` 已整体替换为下一
/// 进程保存现场，任何"照常返回值"的处理都会写穿目标进程；枚举强制 match。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlockOutcome {
    /// 已切走：`*frame` 是下一进程现场，调用方不得再触碰 frame/rax。
    Switched,
    /// 拒绝阻塞（无可调度进程可切，或登记被拒）：现场未动、等待者未入册，
    /// 调用方应如实报 `WouldBlock`。
    Refused,
}

/// 调度器与进程回调 Provider（解耦 IPC 与 Task/Scheduler 的循环依赖）。
///
/// 平台注记（ipc1 IM3 残余）：`block_with_registration` 的 frame 参数仍为
/// arch-x86_64 具体类型——平台无关中断帧抽象是依赖地图 #6 的缺失前置组件，
/// 在其立项前本 trait 边界是管道路径唯一的平台接触点（词汇表翻译收敛在
/// kernel 适配层一次完成）。shm 路径已完全泛型化，无此残留。
pub trait IpcTaskNotifier: Send + Sync {
    fn current_pid(&self) -> usize;
    fn wake_process(&self, pid: usize);
    /// 带值唤醒：预置目标进程保存帧 rax 为 `value` 后唤醒（SYNC 域唤醒值交付，
    /// 同事件机制 `wake_event_timeout` 预置哨兵的手法）。供 `ipc::sync_wake` 使用。
    fn wake_process_with_value(&self, pid: usize, value: u64);
    /// 原子阻塞原语：在**调度锁内**执行 `register`（返回 false = 登记被拒，
    /// 此时不阻塞、零副作用），随后置 Blocked 并切换到下一就绪进程。语义与
    /// 键盘路径 block_for_kbd 的 CAS 纪律同源（crate 级"阻塞原子性契约"）。
    fn block_with_registration(
        &self,
        frame: &mut InterruptFrame,
        register: &mut dyn FnMut() -> bool,
    ) -> BlockOutcome;
}

static NOTIFIER: IrqSpinLock<Option<&'static dyn IpcTaskNotifier>> = IrqSpinLock::new(None);

pub fn set_ipc_notifier(notifier: &'static dyn IpcTaskNotifier) {
    *NOTIFIER.lock() = Some(notifier);
}

/// 共享内存对象：一组物理帧，可被多个进程共享映射。
struct ShmObject {
    size: u64,
    frames: Vec<u64>,
    /// 存活映射条目数（跨全部地址空间的 `shm_maps` 条目总数）。
    ///
    /// 记账语义（ipc1 IA1 / ADR-019）：refs 数的是**映射实例**而非 unmap
    /// 调用次数——fork 继承按继承条目数增记（[`shm_on_mappings_acquired`]），
    /// 地址空间销毁按销毁条目数递减（[`shm_on_mappings_released`]）。归零即
    /// 对象连同帧一并回收。同进程重复 map 同一 id 会产生两个条目、两个引用，
    /// 与两次 unmap 对称，无需 pid 参与记账即可保持守恒。
    refs: usize,
}

/// 管道对象：环形缓冲 + 读写阻塞等待者（按 pid 记）。
///
/// 不变式：同一 pid 至多出现一次（登记时查重，ipc1 IM6）；两表长度均不超过
/// [`MAX_PIPE_WAITERS`]；close 时两表整体 drain 并逐个 wake（ipc1 IA2b）。
struct PipeObject {
    buf: VecDeque<u8>,
    read_waiters: Vec<usize>,
    write_waiters: Vec<usize>,
    /// 打开该管道的 fd 端引用计数（ADR-014 FLAG_PIPE 成对句柄）。
    ///
    /// 一个管道可被多个 fd 引用（一次 FLAG_PIPE 创建一对读写端，两端均指向
    /// 同一 id）。`refs` 记的是"仍持有的 fd 端"总数：归零才销毁对象并唤醒
    /// 全部残留等待者。`pipe_create` 建表时 `refs=0`，每分配一个 fd 端经
    /// [`pipe_ref_inc`] 增记，关闭一个 fd 端经 [`pipe_ref_dec`] 减记。
    refs: usize,
}

static SHM_TABLE: IrqSpinLock<BTreeMap<u64, ShmObject>> = IrqSpinLock::new(BTreeMap::new());
static PIPE_TABLE: IrqSpinLock<BTreeMap<u64, PipeObject>> = IrqSpinLock::new(BTreeMap::new());
// id 从 1 起：0 预留给"无效句柄"哨兵语义，杜绝 id=0 与未初始化返回值混淆；
// u64 回绕不可达论证（ipc1 ID2 / S19）：每次分配伴随至少一次堆分配与一次表
// 插入，堆与表容量都比 2^64 早枯竭若干数量级，回绕在任何可达运行史上不会
// 发生。fetch_add 的 Relaxed 序满足本计数器的唯一不变式——全序唯一性由
// 单核 + 表锁临界区保证，无需 AcqRel 同步边。
static NEXT_SHM: AtomicU64 = AtomicU64::new(1);
static NEXT_PIPE: AtomicU64 = AtomicU64::new(1);

// ---------- 共享内存 ----------

/// 页对齐的 checked 版本（ipc1 IA3）：`size` 向上取整到 [`PageSize::Size4K`]，
/// 加法回绕即溢出——返回 None 由调用方如实报错，绝不静默回绕出零页幻影对象。
fn align_up_page_checked(size: u64) -> Option<u64> {
    let page = PageSize::Size4K.bytes();
    size.checked_add(page - 1).map(|v| v & !(page - 1))
}

/// `shm_create(size) -> id`：分配 `size`（向上取整到页）物理帧，登记为共享对象。
pub fn shm_create(size: u64) -> Result<u64, Error> {
    if size == 0 {
        return Err(Error::InvalidParam);
    }
    // IA3：checked 对齐。导致回绕的 size 属参数值越界（OutOfRange），
    // 不是内部错误——debug 构建不再 panic，release 不再产生零页幻影对象。
    let size = align_up_page_checked(size).ok_or(Error::OutOfRange)?;
    // usize 宽度论证（ipc1 ID2 / S04+S19）：x86_64 上 u64→usize 无损；npages
    // 受物理帧总量约束远早于宽度耗尽。
    let page_bytes = PageSize::Size4K.bytes();
    let npages = (size / page_bytes) as usize;
    // S20：用 try_reserve 而非 with_capacity——后者 OOM 时全局 alloc error
    // panic，前者如实返回错误走退款路径。
    let mut frames: Vec<u64> = Vec::new();
    frames.try_reserve(npages).map_err(|_| Error::OutOfMemory)?;
    // IM1：中途 OOM 时逆序归还已成功分配的帧——错误路径的资源释放义务
    // （S18）在 OOM 这种最需要回收的场景同样成立。
    for _ in 0..npages {
        match mm::allocate_frame() {
            Some(f) => frames.push(f.start_paddr()),
            None => {
                for p in frames.iter().rev() {
                    mm::deallocate_frame(arch::PhysFrame::from_paddr_raw(*p));
                }
                return Err(Error::OutOfMemory);
            }
        }
    }
    // IM2：清零前显式确认 HHDM 偏移已初始化——PHYS_OFFSET 未设置属内核启动
    // 不变式被破坏，与 mm1.md MD1 同款显式 panic 收口；绝无 off=0 写空指针
    // 页的伪值降级路径。清零本身保证首映射内容确定（跨进程残留信息不泄漏）。
    if arch::PHYS_OFFSET.get().copied().is_none() {
        for p in frames.iter().rev() {
            mm::deallocate_frame(arch::PhysFrame::from_paddr_raw(*p));
        }
        panic!("ipc: PHYS_OFFSET unset before shm_create zeroing (HHDM not initialized)");
    }
    for p in frames.iter() {
        unsafe {
            core::ptr::write_bytes(arch::phys_to_virt(*p) as *mut u8, 0, page_bytes as usize)
        };
    }
    let id = NEXT_SHM.fetch_add(1, Ordering::Relaxed);
    SHM_TABLE.lock().insert(
        id,
        ShmObject {
            size,
            frames,
            refs: 0,
        },
    );
    klib::info!("[ipc] shm_create id={} size={:#x}", id, size);
    Ok(id)
}

/// `shm_destroy(id)`：销毁一个共享内存对象并释放其全部物理帧。
///
/// S18（生命周期）：创建的 shm 若从未映射（或已全部 unmap），refs 恒 0，
/// 若无销毁 API，其分配的物理帧将永久不可回收（帧泄漏）。本 API 提供显式
/// 销毁路径——对象仍有存活映射（refs>0）时拒绝（`Busy`），须先全部 unmap。
///
/// 与 `shm_create`/`shm_map`/`shm_unmap` 同持 `SHM_TABLE` 锁，无新增锁序。
pub fn shm_destroy(id: u64) -> Result<(), Error> {
    let mut table = SHM_TABLE.lock();
    match table.get(&id) {
        None => return Err(Error::NotFound),
        Some(obj) if obj.refs > 0 => return Err(Error::Busy),
        Some(_) => {}
    }
    if let Some(obj) = table.remove(&id) {
        for p in obj.frames.iter().rev() {
            mm::deallocate_frame(arch::PhysFrame::from_paddr_raw(*p));
        }
        klib::info!(
            "[ipc] shm_destroy id={} freed {} frames",
            id,
            obj.frames.len()
        );
    }
    Ok(())
}

/// 把 `ids` 中每个映射条目计为一个新存活引用（ipc1 IA1 fork 继承路径；
/// 由 kernel 适配层实现 mm 的 ShmMappingHooks 后在本 crate 落账）。
pub fn shm_on_mappings_acquired(ids: &[u64]) {
    if ids.is_empty() {
        return;
    }
    let mut table = SHM_TABLE.lock();
    for &id in ids {
        match table.get_mut(&id) {
            Some(obj) => obj.refs += 1,
            // fork 继承列表只会来自先前成功的 map_shm，对象必然在册；缺失
            // 意味着记账已被外部破坏——静默跳过会掩盖漂移，告警可见。
            None => klib::warn!("[ipc] acquire hook: unknown shm id {}", id),
        }
    }
}

/// 把 `ids` 中每个映射条目的引用撤销；归零的对象连同帧一并回收
/// （ipc1 IA1 销毁路径）。
pub fn shm_on_mappings_released(ids: &[u64]) {
    if ids.is_empty() {
        return;
    }
    let mut table = SHM_TABLE.lock();
    for &id in ids {
        let dead = match table.get_mut(&id) {
            Some(obj) => {
                obj.refs = obj.refs.saturating_sub(1);
                obj.refs == 0
            }
            None => {
                klib::warn!("[ipc] release hook: unknown shm id {}", id);
                false
            }
        };
        if dead {
            if let Some(obj) = table.remove(&id) {
                for p in obj.frames.iter().rev() {
                    mm::deallocate_frame(arch::PhysFrame::from_paddr_raw(*p));
                }
                klib::info!(
                    "[ipc] last mapping of id={} gone, freed {} frames",
                    id,
                    obj.frames.len()
                );
            }
        }
    }
}

#[cfg(feature = "kernel-tests")]
/// 测试探针：读取对象当前存活引用数（IA1 记账断言用）。
pub fn debug_shm_refs(id: u64) -> Option<usize> {
    SHM_TABLE.lock().get(&id).map(|o| o.refs)
}

#[cfg(feature = "kernel-tests")]
/// 测试探针：对象是否仍在册（回收断言用）。
pub fn debug_shm_exists(id: u64) -> bool {
    SHM_TABLE.lock().contains_key(&id)
}

/// `shm_map(id) -> addr`：把 shm 对象帧映射进调用进程地址空间。
///
/// 泛型 `PT`（ipc1 IM3 可泛化半）：逻辑层不绑定具体架构页表实现。
pub fn shm_map<PT: arch::PageTable>(
    id: u64,
    addr_space: &mut mm::user_space::UserAddressSpace<PT>,
) -> Result<u64, PT::Error> {
    let mut table = SHM_TABLE.lock();
    let obj = table.get_mut(&id).ok_or(Error::NotFound)?;
    let vaddr = addr_space.map_shm(id, &obj.frames, obj.size)?;
    obj.refs += 1;
    klib::info!("[ipc] shm_map id={} refs={} -> {:#x}", id, obj.refs, vaddr);
    Ok(vaddr)
}

/// `shm_unmap(id)`：解除调用进程对该 shm 对象的一次映射。
///
/// 按**映射条目**记账（ADR-019）：移除本空间的一条 `shm_maps` 条目并递减
/// 一个引用；归零即回收。
///
/// **锁序（S21）**：与 [`shm_map`] 统一为 `SHM_TABLE → mm`——先持 SHM_TABLE，
/// 再对地址空间做 unmap（取 mm 的 shm_maps 锁）。旧实现 `shm_unmap` 走
/// `mm → SHM_TABLE` 反向序，与 `shm_map` 的 `SHM_TABLE → mm` 构成 SMP 锁反转
/// 死锁点（单核掩盖）。注意地址空间销毁钩子（`ipc_init.rs` 的
/// `on_mappings_released`）由 mm 驱动、以 `mm → SHM_TABLE` 序调用
/// [`shm_on_mappings_released`]——该路径为进程销毁独有，与 syscall 触发的
/// `shm_unmap` 互斥（同一地址空间不会同时销毁与 unmap），成文记录。
pub fn shm_unmap<PT: arch::PageTable>(
    id: u64,
    addr_space: &mut mm::user_space::UserAddressSpace<PT>,
) -> Result<(), PT::Error> {
    // 统一锁序：先 SHM_TABLE，后 mm。
    let mut table = SHM_TABLE.lock();
    addr_space.unmap_shm(id)?;
    let dead = match table.get_mut(&id) {
        Some(obj) => {
            obj.refs = obj.refs.saturating_sub(1);
            obj.refs == 0
        }
        None => {
            klib::warn!("[ipc] shm_unmap: unknown shm id {}", id);
            false
        }
    };
    if dead {
        if let Some(obj) = table.remove(&id) {
            for p in obj.frames.iter().rev() {
                mm::deallocate_frame(arch::PhysFrame::from_paddr_raw(*p));
            }
            klib::info!(
                "[ipc] last mapping of id={} gone, freed {} frames",
                id,
                obj.frames.len()
            );
        }
    }
    Ok(())
}

// ---------- 管道 ----------

/// `pipe_create() -> id`：新建一个空管道。
pub fn pipe_create() -> Result<u64, Error> {
    let id = NEXT_PIPE.fetch_add(1, Ordering::Relaxed);
    // S20：先 try_reserve 管道缓冲容量，OOM 如实返回错误——with_capacity
    // 在分配失败时会全局 alloc error panic。
    let mut pipe = PipeObject {
        buf: VecDeque::new(),
        read_waiters: Vec::new(),
        write_waiters: Vec::new(),
        refs: 0,
    };
    pipe.buf
        .try_reserve(PIPE_CAPACITY)
        .map_err(|_| Error::OutOfMemory)?;
    PIPE_TABLE.lock().insert(id, pipe);
    klib::info!("[ipc] pipe id={} created", id);
    Ok(id)
}

/// 管道 `id` 的一个 fd 端引用（ADR-014 FLAG_PIPE 分配 fd 端时调用）。
///
/// 增加 `refs`。若 `id` 不存在返回 `NotFound`（宁缺毋假：未建引用绝不
/// 伪造成功）。调用方在 fd 分配失败需回滚时应配对的 [`pipe_ref_dec`]。
pub fn pipe_ref_inc(id: u64) -> Result<(), Error> {
    let mut table = PIPE_TABLE.lock();
    let Some(pipe) = table.get_mut(&id) else {
        return Err(Error::NotFound);
    };
    // S19：refs 是 fd 端计数，最多同进程 fd 表上限量级；checked_add 防
    // 极端路径回绕（2^64 个 fd 端不可达，防御性）——回绕即资源上限，ENOSPC。
    let new = pipe.refs.checked_add(1).ok_or(Error::NoSpace)?;
    pipe.refs = new;
    Ok(())
}

/// 释放管道 `id` 的一个 fd 端引用（关闭 fd 端时调用）。
///
/// 递减 `refs`；归零即销毁管道并唤醒全部残留读写等待者（同 [`pipe_close`]）。
/// 若 `id` 不存在返回 `NotFound`。`refs` 已为 0 时如实返回 `NotFound`——
/// 绝不静默减出下溢。
pub fn pipe_ref_dec(id: u64) -> Result<(), Error> {
    let wake: Vec<usize> = {
        let mut table = PIPE_TABLE.lock();
        let Some(pipe) = table.get_mut(&id) else {
            return Err(Error::NotFound);
        };
        if pipe.refs == 0 {
            return Err(Error::NotFound);
        }
        pipe.refs -= 1;
        if pipe.refs > 0 {
            return Ok(());
        }
        let (rw, ww) = (core::mem::take(&mut pipe.read_waiters), core::mem::take(&mut pipe.write_waiters));
        table.remove(&id);
        rw.into_iter().chain(ww).collect()
    };
    for pid in wake {
        wake_proc(pid);
    }
    klib::info!("[ipc] pipe id={} refcount-destroyed", id);
    Ok(())
}

fn current_pid() -> usize {
    if let Some(notifier) = *NOTIFIER.lock() {
        notifier.current_pid()
    } else {
        0
    }
}

fn wake_proc(pid: usize) {
    if let Some(notifier) = *NOTIFIER.lock() {
        notifier.wake_process(pid);
    }
}

/// 带值唤醒 helper（SYNC 域）：预置目标 pid 保存帧 rax 为 `value` 后唤醒。
/// notifier 未注册（早期/单测）时安全 no-op。
fn wake_proc_with_value(pid: usize, value: u64) {
    if let Some(notifier) = *NOTIFIER.lock() {
        notifier.wake_process_with_value(pid, value);
    }
}

/// 用户缓冲区间预校验（ipc1 IR1 的单点入口）。
///
/// 三层检查与 syscall 层 validate_user_range 同源（B2 有界上限 → 用户半区
/// 窗口 → mm 逐页意图校验）；管道路径单轮 chunk 天然 ≤ [`PIPE_CAPACITY`]，
/// 上限在此防御未来调用形状变化。通过后才允许 SMAP 整块拷贝。
fn validate_user_range<PT: arch::PageTable>(
    space: &mm::user_space::UserAddressSpace<PT>,
    buf: u64,
    len: usize,
    access: mm::user_space::UserAccess,
) -> Result<(), Error> {
    // S13：具名常量（见 MAX_COPY_BYTES），不再是散落魔法字面量。
    if len as u64 > MAX_COPY_BYTES {
        return Err(Error::InvalidParam);
    }
    let end = buf.checked_add(len as u64).ok_or(Error::OutOfRange)?;
    if buf < mm::user_space::USER_BASE || end > mm::user_space::USER_TOP {
        return Err(Error::OutOfRange);
    }
    if space.is_range_mapped(buf, len as u64, access) {
        Ok(())
    } else {
        Err(Error::BadAddress)
    }
}

/// 在调度锁内被回调执行的登记逻辑（ipc1 IA2a / 审计 R6-F2）。
///
/// 返回 false = 不入册不阻塞。两条拒绝路径：
/// - **唤醒条件复检已满足**（写侧有空位/读侧有数据，`*ready` 置位）：本方
///   无需入睡，调用方直接重试。这是 lost-wakeup 的根治点——主循环顶的
///   条件检查与调度锁内的登记是两个临界区，其间唤醒方可能完成
///   "消费 + drain(空表) + wake(无人可醒)"全套；只有**登记点持同一把锁
///   复检条件**才能看见这个翻转。
/// - 查重命中或超 [`MAX_PIPE_WAITERS`]（IM6 防线）。
/// 管道不存在同样返回 false。所有 false 路径零副作用。
fn register_waiter(
    waiters: &mut Vec<usize>,
    pid: usize,
    cond_met: bool,
    ready: &mut bool,
) -> bool {
    if cond_met {
        *ready = true;
        return false;
    }
    if waiters.contains(&pid) || waiters.len() >= MAX_PIPE_WAITERS {
        return false;
    }
    waiters.push(pid);
    true
}

/// 构造"在调度锁内把 pid 登记进管道 `id` 写等待者"的回调（IA2a）。
/// `ready` 由调用方栈上持有：登记点发现有空位时置位（R6-F2 复检通道）。
fn write_registrant<'a>(
    id: u64,
    pid: usize,
    ready: &'a mut bool,
) -> impl FnMut() -> bool + 'a {
    move || {
        let mut table = PIPE_TABLE.lock();
        match table.get_mut(&id) {
            Some(pipe) => register_waiter(
                &mut pipe.write_waiters,
                pid,
                true, // 无界缓冲：写方向恒有空位（ipc1 同期修复，顺序模型写者不因容量阻塞）
                ready,
            ),
            None => false,
        }
    }
}

/// 构造读方向的同款回调（IA2a；复检条件为"缓冲非空"）。
fn read_registrant<'a>(id: u64, pid: usize, ready: &'a mut bool) -> impl FnMut() -> bool + 'a {
    move || {
        let mut table = PIPE_TABLE.lock();
        match table.get_mut(&id) {
            Some(pipe) => register_waiter(
                &mut pipe.read_waiters,
                pid,
                !pipe.buf.is_empty(),
                ready,
            ),
            None => false,
        }
    }
}

fn try_block(
    frame: &mut InterruptFrame,
    register: &mut dyn FnMut() -> bool,
) -> BlockOutcome {
    match *NOTIFIER.lock() {
        Some(notifier) => notifier.block_with_registration(frame, register),
        None => BlockOutcome::Refused,
    }
}

/// `pipe_write(id, space, src, len)`：把 `len` 字节从**调用进程的用户缓冲**
/// 写入管道，必要时阻塞。
///
/// `space` 是调用方的地址空间视图（未来的 syscall 包装层传入当前进程空间；
/// 内核自测传测试空间）——本函数以它做预校验后整块拷贝，绝不裸解引用
/// `src`（IR1）。POSIX 对齐（IM4）：目标不存在返回 NotFound（EBADF 同族）；
/// 存在且 len==0 时 Ok(0)，无副作用、不唤醒任何人。
pub fn pipe_write<PT: arch::PageTable>(
    frame: &mut InterruptFrame,
    id: u64,
    space: &mm::user_space::UserAddressSpace<PT>,
    src: u64,
    len: u64,
) -> Result<u64, Error> {
    let pid = current_pid();
    let len = len as usize;
    let mut written = 0usize;
    loop {
        let wake_readers;
        {
            let mut table = PIPE_TABLE.lock();
            let Some(pipe) = table.get_mut(&id) else {
                return Err(Error::NotFound);
            };
            if len == 0 {
                return Ok(0);
            }
            // 无界缓冲（ipc1 同期修复）：chunk 仅受单轮 staging 大小
            // （PIPE_CAPACITY）约束，**总量不受缓冲容量限制**——顺序管道模型下
            // 写者绝不会因"缓冲满"阻塞（彻底移除 PIPE_CAPACITY 顺序死锁限制）。
            // 读端仍是按需排空；无界仅在顺序模型下成立，见 docs/adr/pipe 同期记录。
            let remaining = len - written;
            let chunk = remaining.min(PIPE_CAPACITY);
            if chunk > 0 {
                validate_user_range(
                    space,
                    src + written as u64,
                    chunk,
                    mm::user_space::UserAccess::Read,
                )?;
                let mut staging = [0u8; PIPE_CAPACITY];
                unsafe {
                    arch_x86_64::mmio::copy_from_user(
                        staging.as_mut_ptr(),
                        src + written as u64,
                        chunk,
                    )
                };
                pipe.buf.extend(staging.iter().take(chunk).copied());
                written += chunk;
            }
            // 先收集后唤醒（IA2a 锁序纪律）：wake 一律移出 PIPE_TABLE 临界区。
            wake_readers = if written > 0 {
                core::mem::take(&mut pipe.read_waiters)
            } else {
                Vec::new()
            };
            if written == len {
                drop(table);
                for w in wake_readers {
                    wake_proc(w);
                }
                return Ok(written as u64);
            }
        }
        for w in wake_readers {
            wake_proc(w);
        }
        // 无界缓冲下，只要还有剩余字节（written < len）本轮必已写入 chunk>0，
        // 直接续写，绝不因"缓冲满"登记阻塞（顺序模型写者一次性产出全部数据）。
        if written < len {
            continue;
        }
        // R6-F2：ready 置位 = 登记点复检发现唤醒条件已满足（主循环检查之后、
        // 登记之前被唤醒方翻转）——直接重试，绝不带"条件已真"的认知入睡。
        // （此路径仅在 chunk==0 的理论不可达情形下命中，保留作防御回退。）
        let mut ready = false;
        let outcome = {
            let mut register = write_registrant(id, pid, &mut ready);
            try_block(frame, &mut register)
        };
        match outcome {
            BlockOutcome::Refused => {
                if ready {
                    continue;
                }
                return Err(Error::WouldBlock);
            }
            BlockOutcome::Switched => {}
        }
    }
}

/// `pipe_read(id, space, dst, len)`：从管道读 `len` 字节到**调用进程的用户
/// 缓冲**，必要时阻塞。
///
/// 校验-拷贝纪律同 [`pipe_write`]（IR1）。POSIX 对齐（IM4）：目标不存在返回
/// NotFound；存在但缓冲为空且 len==0 时 Ok(0)。注意 len==0 的检查在查表之后
/// ——旧实现"查表前返回 Ok(0)"会把不存在的管道伪装成可读，属误导性伪成功。
pub fn pipe_read<PT: arch::PageTable>(
    frame: &mut InterruptFrame,
    id: u64,
    space: &mm::user_space::UserAddressSpace<PT>,
    dst: u64,
    len: u64,
) -> Result<u64, Error> {
    let pid = current_pid();
    let len = len as usize;
    let mut total = 0usize;
    loop {
        let mut writers = Vec::new();
        let mut consumed = false;
        {
            let mut table = PIPE_TABLE.lock();
            let Some(pipe) = table.get_mut(&id) else {
                // 管道已消失：若已读回部分数据则如实交付，否则 NotFound。
                if total > 0 {
                    return Ok(total as u64);
                }
                return Err(Error::NotFound);
            };
            if len == 0 {
                return Ok(0);
            }
            let avail = pipe.buf.len();
            if avail > 0 {
                // 单轮 chunk 受 staging 大小（PIPE_CAPACITY）约束（ipc1 同期修复：
                // 无界缓冲下 buf 可超 4096B，旧实现 chunk=buf.len() 会溢出 staging）。
                // 循环搬运直到填满 len 或缓冲排空。
                let chunk = avail.min(len - total).min(PIPE_CAPACITY);
                // 校验先行：校验失败时缓冲零消费，语义与"读未发生"一致。
                validate_user_range(
                    space,
                    dst + total as u64,
                    chunk,
                    mm::user_space::UserAccess::Write,
                )?;
                // S20/S09：不得在交付证明前消费共享缓冲。锁内先做不可故障的拷贝
                // （validate_user_range 已使目标页驻留，属"无内核态 #PF"契约路径），
                // 成功后才 pop 消费——数据交付与消费原子，杜绝"已消费但拷贝失败"丢失。
                let mut staging = [0u8; PIPE_CAPACITY];
                for (out, src) in staging
                    .iter_mut()
                    .take(chunk)
                    .zip(pipe.buf.iter().take(chunk))
                {
                    *out = *src;
                }
                unsafe {
                    arch_x86_64::mmio::copy_to_user(dst + total as u64, staging.as_ptr(), chunk)
                };
                // 拷贝成功（契约保证不 fault）后才消费缓冲。
                for _ in 0..chunk {
                    pipe.buf.pop_front();
                }
                total += chunk;
                consumed = true;
                // 先收集后唤醒（同 write），唤醒在表锁之外。
                writers = core::mem::take(&mut pipe.write_waiters);
                if total == len {
                    drop(table);
                    for w in writers {
                        wake_proc(w);
                    }
                    return Ok(total as u64);
                }
            }
        }
        for w in writers {
            wake_proc(w);
        }
        if consumed {
            // 缓冲仍有数据或剩余要读：继续循环（无界缓冲下逐轮搬运）。
            continue;
        }
        // 已读回部分数据但缓冲此刻排空：如实交付部分读（POSIX：read 返回
        // 当前可用量），绝不因等更多数据而悬挂——顺序模型下写端可能已关。
        if total > 0 {
            return Ok(total as u64);
        }
        // R6-F2：同 write 侧——登记点复检"缓冲非空"，条件已真则重试不入睡。
        let mut ready = false;
        let outcome = {
            let mut register = read_registrant(id, pid, &mut ready);
            try_block(frame, &mut register)
        };
        match outcome {
            BlockOutcome::Refused => {
                if ready {
                    continue;
                }
                return Err(Error::WouldBlock);
            }
            BlockOutcome::Switched => {}
        }
    }
}

/// `pipe_close(id)`：销毁管道。
///
/// IA2b：close 前 drain 双向等待者并逐个 wake——正阻塞在本管道上的进程若
/// 不被唤醒将永久悬挂（它们只可能被"对该管道的读写"唤醒，而对象即将消失）。
/// 唤醒发生在表锁之外（锁序纪律）；被唤醒者循环顶部的查表会得到 NotFound，
/// 如实以错误收场而非悬挂。
pub fn pipe_close(id: u64) -> Result<(), Error> {
    let (readers, writers) = {
        let mut table = PIPE_TABLE.lock();
        match table.remove(&id) {
            Some(pipe) => (pipe.read_waiters, pipe.write_waiters),
            None => return Err(Error::NotFound),
        }
    };
    for p in readers {
        wake_proc(p);
    }
    for p in writers {
        wake_proc(p);
    }
    klib::info!("[ipc] pipe_close id={}", id);
    Ok(())
}
