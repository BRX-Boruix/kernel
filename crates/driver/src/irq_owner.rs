//! PCI 设备中断投递：IRQ → 认领该设备的用户态驱动 (pid)。
//!
//! 目标：让一个 UIO 用户态驱动在 claim 了某块 PCI 设备后，能收到该设备
//! 的中断（如 HDA "buffer 播完"、网卡 "收包"）——从而**中断驱动**而非轮询。
//!
//! 现状约束（arch 层，AD2）：全系统走 8259 PIC 模式，外部 IRQ 表仅 16 槽
//! （IRQ 0..15），当前只有键盘 IRQ1 被占用（IRQ0 归 LAPIC 定时器、IRQ2 为
//! 8259 级联）。QEMU pc 机下 PCI 设备的中断经 PIC 落在某条空闲 IRQ 线
//! （配置空间 0x3C 的 Interrupt Line，多为 5/9/10/11）。故本模块在 IRQ 3..15
//! 内登记"某 IRQ → 认领该设备驱动的 pid"。
//!
//! 机制（与 driver::event 的 interrupt-to-futex 同构，但按 IRQ 定向）：
//! - 归属表 IRQ_OWNER：每 PIC IRQ 一个 pid 槽（u32::MAX = 无归属），原子读写
//!   （IRQ 上下文安全，不取锁）。
//! - arch handler device_irq_handler：extern "C" fn(u8)->bool，在某 IRQ 触发时
//!   读该 IRQ 的归属 pid，若存在则调用 kernel 注入的唤醒回调 IRQ_WAKE_CB
//!   （指向 task::scheduler::wake_with_value(pid, 哨兵)），使阻塞在
//!   driver_irq_wait 的驱动被唤醒。
//! - 生命周期：claim 设备时 claim_device_irq 登记归属 + 注册 arch handler；
//!   注销/进程退出时 release_device_irq 清理（复用 UIO 的退出隔离路径）。
//!
//! 锁纪律：handler 在**中断上下文**执行，绝不可取任何 spin::Mutex（否则与持有
//! 该锁的普通路径死锁）。故归属表与唤醒回调都走无锁原子。函数指针存入 usize
//! 原子再读回，与 arch 层 interrupts.rs 自身对 IRQ_HANDLERS 的处理同款（该表
//! 即存 usize、读回 transmute 为 IrqHandler）。

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use klib::error::Error;

/// PIC 外部中断总数（IRQ 0..15）。
pub const PIC_IRQ_COUNT: usize = 16;
/// IRQ 0 = LAPIC 定时器；IRQ 1 = 键盘；IRQ 2 = 8259 级联。设备中断可用的
/// 是 IRQ 3..15。
const FIRST_DEVICE_IRQ: u8 = 3;

/// 归属表无归属哨兵（同 task 层 u32::MAX = 无等待者约定）。
const NO_OWNER: u32 = u32::MAX;

/// 每个 PIC IRQ 上认领该设备的用户驱动 pid。u32::MAX = 无归属。
static IRQ_OWNER: [AtomicU32; PIC_IRQ_COUNT] = {
    const NONE: AtomicU32 = AtomicU32::new(NO_OWNER);
    [NONE; PIC_IRQ_COUNT]
};

/// 唤醒回调：IRQ 命中归属驱动时调用 fn(pid)。kernel 启动期注入一次（指向
/// task::scheduler 的定向唤醒）。以 usize 承载 fn 指针（启动期写入一次，
/// IRQ 上下文无锁读取，见文件头锁纪律）。0 = 未注入。
static IRQ_WAKE_CB: AtomicUsize = AtomicUsize::new(0);

/// 每 IRQ 的"已触发待服务"闩锁（0/1，非累加器）。
///
/// 设备中断是边沿/电平信号，驱动常在运行中服务多段工作；若某 IRQ 在驱动
/// 未阻塞等待（忙于服务）时再次触发，仅靠"唤醒阻塞者"会丢失该次边沿。
/// 本闩锁在 handler 触发归属驱动的**同时**置 1，驱动下次进入 driver_irq_wait
/// 时复检到 1 即立即返回"已触发"，不入睡——绝不丢失"有活要干"的信号。
/// 驱动通过读设备状态寄存器完成真实服务（电平语义），闩锁只承担"通知去
/// 检查"职责，故 0/1 足够（多个边沿合流为一次唤醒，驱动据此扫全部状态位）。
static IRQ_PENDING: [AtomicU32; PIC_IRQ_COUNT] = {
    const ZERO: AtomicU32 = AtomicU32::new(0);
    [ZERO; PIC_IRQ_COUNT]
};

/// 每 IRQ 上"当前 driver_irq_wait 阻塞段注册的一次性超时定时器 id"。
/// `u64::MAX` = 无待取消定时器。
///
/// 防 stale 定时器（复查 FINDING-1）：driver_irq_wait 的阻塞段注册超时定时器
/// 后，若**设备中断先到**唤醒驱动（Switched 路径），须取消该定时器——否则它
/// 会残留到驱动下一次 driver_irq_wait，在无关的新等待里空转触发，伪造一次
/// 超时唤醒（`wake_irq_timeout` 对任意 Blocked 的本 pid 都置 rax=0 并 wake）。
/// 本槽把定时器绑定到**满足等待的那个 IRQ**：device_irq_handler 触发归属驱动
/// 时据此取消并清槽，保证定时器绝不跨等待泄漏。`u64::MAX` 哨兵与 klib 定时
/// 器表 next_id 回绕语义不冲突（klib 永不返回 0，live id 也非 MAX）。
static IRQ_TIMER: [AtomicU64; PIC_IRQ_COUNT] = {
    const NONE: AtomicU64 = AtomicU64::new(u64::MAX);
    [NONE; PIC_IRQ_COUNT]
};

/// 登记某 IRQ 的 driver_irq_wait 阻塞段超时定时器 id（阻塞入睡前调用）。
pub fn irq_timer_arm(irq: u8, timer_id: u64) {
    if irq as usize >= PIC_IRQ_COUNT {
        return;
    }
    IRQ_TIMER[irq as usize].store(timer_id, Ordering::Release);
}

/// 清某 IRQ 的超时定时器槽（`u64::MAX` = 无），**不**取锁取消（供提前返回路径
/// 与 klib::time::cancel_timeout 搭配：先 cancel 实际定时器、再清槽）。
pub fn irq_timer_clear(irq: u8) {
    if irq as usize >= PIC_IRQ_COUNT {
        return;
    }
    IRQ_TIMER[irq as usize].store(u64::MAX, Ordering::Release);
}

/// 查询某 IRQ 是否登记了未清的 driver_irq_wait 超时定时器（供测试/诊断观测
/// 槽位真值；也用于验证 FIRING-1 修复：设备中断触发后槽位必须已清）。
pub fn irq_timer_armed(irq: u8) -> bool {
    if irq as usize >= PIC_IRQ_COUNT {
        return false;
    }
    IRQ_TIMER[irq as usize].load(Ordering::Acquire) != u64::MAX
}

/// 取消并清某 IRQ 上已登记的 driver_irq_wait 超时定时器（若有）。
///
/// 中断上下文安全：`klib::time::cancel_timeout` 与 `poll_timeouts` 同持一把
/// IRQ-safe 锁，线性化无竞态；handler 在本 IRQ 触发归属驱动时调用，杜绝定时器
/// 跨等待残留（复查 FINDING-1）。无登记/已过期返回 false 静默无害。
pub fn irq_timer_cancel(irq: u8) {
    if irq as usize >= PIC_IRQ_COUNT {
        return;
    }
    let id = IRQ_TIMER[irq as usize].load(Ordering::Acquire);
    if id != u64::MAX {
        klib::time::cancel_timeout(id);
    }
    IRQ_TIMER[irq as usize].store(u64::MAX, Ordering::Release);
}

/// 注册设备中断的唤醒回调（kernel 启动期调用一次）。
/// 回调签名 fn(pid: usize)：把认领某 IRQ 的阻塞驱动进程唤醒。
pub fn set_irq_wake_callback(cb: fn(usize)) {
    IRQ_WAKE_CB.store(cb as usize, Ordering::Release);
}

/// arch 设备中断 handler（注册到 arch_x86_64::interrupts::register_irq）。
///
/// 中断上下文执行，只做无锁读 + 定向唤醒：
/// - 该 IRQ 无归属驱动（pid == NO_OWNER）→ 返回 false（未处理，让共享该 IRQ
///   的其它 handler / 默认 EOI 路径继续）。
/// - 有归属驱动 → 调用注入的唤醒回调把该 pid 置 Ready，返回 true（已处理）。
extern "C" fn device_irq_handler(irq: u8) -> bool {
    if irq as usize >= PIC_IRQ_COUNT {
        return false;
    }
    let pid = IRQ_OWNER[irq as usize].load(Ordering::Acquire);
    if pid == NO_OWNER {
        return false;
    }
    // 置待服务闩锁（丢失边沿防线）：即使驱动此刻未阻塞等待，下次
    // driver_irq_wait 也能立即发现该 IRQ 已触发。Release 保证此前对归属
    // pid 的观察对等待方可见。
    IRQ_PENDING[irq as usize].store(1, Ordering::Release);
    // 本 IRQ 触发归属驱动 = 该次 driver_irq_wait 等待已被满足：取消其阻塞段
    // 登记的超时定时器并清槽，杜绝定时器残留到下一次等待（复查 FINDING-1）。
    // 中断上下文安全（cancel_timeout 与 poll_timeouts 同持 IRQ-safe 锁）。
    irq_timer_cancel(irq);
    let cb = IRQ_WAKE_CB.load(Ordering::Acquire);
    if cb == 0 {
        // 归属存在但唤醒回调未注入（不应发生）：闩锁已置，等待方下次复检
        // 能取到，此处避免误报共享 IRQ 已被处理——返回 true 并交由闩锁承载
        // 通知职责。
        return true;
    }
    // 指针来自 set_irq_wake_callback 写入的合法 'static 函数地址。
    let f: fn(usize) = unsafe { core::mem::transmute(cb) };
    f(pid as usize);
    true
}

/// 查询某 IRQ 当前的归属 pid（None = 无）。供测试/诊断观测归属表真值。
pub fn irq_owner_of(irq: u8) -> Option<usize> {
    if irq as usize >= PIC_IRQ_COUNT {
        return None;
    }
    let pid = IRQ_OWNER[irq as usize].load(Ordering::Acquire);
    if pid == NO_OWNER {
        None
    } else {
        Some(pid as usize)
    }
}

/// 读并清除某 IRQ 的待服务闩锁。返回是否已触发（1→true 并清零；0→false）。
///
/// driver_irq_wait 的立即返回路径用它做一次性检查：闩锁置位说明有中断已
/// 触发而驱动尚未被告知，立即返回"已触发"而不入睡。调用方须随后读设备状态
/// 寄存器完成真实服务。
pub fn irq_pending_consume(irq: u8) -> bool {
    if irq as usize >= PIC_IRQ_COUNT {
        return false;
    }
    IRQ_PENDING[irq as usize].swap(0, Ordering::AcqRel) == 1
}

/// 只读某 IRQ 的待服务闩锁（不清除）。供阻塞路径在 per-pid 锁内复检使用。
pub fn irq_pending_peek(irq: u8) -> bool {
    if irq as usize >= PIC_IRQ_COUNT {
        return false;
    }
    IRQ_PENDING[irq as usize].load(Ordering::Acquire) == 1
}

/// 内核态驱动的**有界中断等待**：等到该 IRQ 的待服务闩锁置位，或自旋预算耗尽。
///
/// 返回 `true` = 观察到中断（闩锁已消费）；`false` = 预算耗尽（**不阻塞、不挂死**）。
///
/// ## 为什么是「有界自旋」而不是「睡下去」
///
/// 本原语服务**内核态同步块驱动**（AHCI）。它与用户态驱动的处境根本不同：
///
/// 1. **没有调度帧**：AHCI 盘到 ext2 的链路全同步——
///    `ext2 -> CachingByteDevice -> DrvByteBridge(vfs_init.rs:1329) -> io.read_at(...)`。
///    `read_bytes` 直接同步调用，没有 `&mut InterruptFrame` 可传；而面向用户态的
///    `task::block_for_irq` 必须有帧（唯一调用点是 syscall 路径）。
/// 2. **不能持锁切走**：本函数通常在 `fs`/`vfs` 层锁内被调用（块缓存到盘）。
///    持锁状态下阻塞切走，下一进程会在同一把锁上自旋死锁——`scheduler.rs:1199`
///    明确禁止「持锁阻塞切走」。
///
/// 故本原语**绝不阻塞调度**，只把「不可中断的长自旋」换成「中断通知 + 紧界自旋」。
/// 收益来自消除长自旋空转（STORAGE-AHCI-4 实测修复前 22.6M cycles/扇区），
/// **不是**「等待期间让出 CPU」——后者需要改 `BlockDevice`/`ByteDevice` 契约，
/// 不在本原语职责内。
///
/// ## 失败模式（S20：先定义再实现）
///
/// - **中断提前到达**：闩锁已置 → 首次复检即消费返回 `true`（不丢失）。
/// - **中断在自旋中到达**：下一轮复检消费返回 `true`。
/// - **中断永不到达**：预算耗尽返回 `false`——调用方据此**回退到有界轮询**，
///   绝不永久挂死。
/// - **闩锁无归属不置**：无归属者的 IRQ 上 `device_irq_handler` 不置闩锁
///   （见归属语义），此时本函数等价于纯自旋，语义仍正确。
///
/// ## 并发与锁序（S21）
///
/// 本函数**不获取任何锁**：只对 `IRQ_PENDING` 做原子读改写（与中断上下文的
/// `device_irq_handler` 共享该原子，AcqRel 保证可见性）。因此可在任意锁内调用，
/// 不引入新的锁序边，也不存在与中断上下文的死锁面。
///
/// `spins == 0` 退化为「只做一次复检」——调用方要求「不等待、只查状态」时使用。
pub fn wait_bounded_irq(irq: u8, spins: u32) -> bool {
    // 首次复检：覆盖「中断在等待开始前已到达」的 lost-wakeup 面。
    if irq_pending_consume(irq) {
        return true;
    }
    for _ in 0..spins {
        if irq_pending_consume(irq) {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// 返回某 IRQ 上当前已注册的 arch handler 数量（供测试/诊断）。
pub fn irq_handler_count_of(irq: u8) -> usize {
    if irq as usize >= PIC_IRQ_COUNT {
        return 0;
    }
    arch_x86_64::interrupts::irq_handler_count(irq)
}

/// 设备认领后登记其中断归属：把 irq 归属给 pid，并确保该 IRQ 的 arch handler
/// 已注册。
///
/// - irq == 0（无中断线）→ 无中断可登记，返回 Ok(0) 静默跳过。
/// - irq 非设备可用范围（<3 或 >=16）→ Err(InvalidParam)。
/// - IRQ 已被其它 pid 归属 → Err(AlreadyExists)，不覆盖他人归属。
/// - 同 pid 重复登记同一 IRQ → 幂等 Ok(irq)。
/// - 注册 arch handler 失败 → Err(NoSpace)（诚实上报，不静默）。
pub fn claim_device_irq(irq: u8, pid: usize) -> Result<u8, Error> {
    if irq == 0 {
        return Ok(0);
    }
    if irq as usize >= PIC_IRQ_COUNT || irq < FIRST_DEVICE_IRQ {
        return Err(Error::InvalidParam);
    }
    let slot = &IRQ_OWNER[irq as usize];
    let cur = slot.load(Ordering::Acquire);
    if cur == pid as u32 {
        return Ok(irq); // 同 pid 幂等
    }
    if cur != NO_OWNER {
        return Err(Error::AlreadyExists);
    }
    if slot
        .compare_exchange(NO_OWNER, pid as u32, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(Error::AlreadyExists); // 竞争失败：已被并发登记
    }
    // 注册 arch handler。register_irq 同指针去重返回 false——若该 IRQ 已由本
    // 模块注册过（此前有归属者释放后重新登记），false 属正常去重，不视为失败；
    // 仅当该 IRQ 上确无任何 handler 时才真正失败（回滚归属并上报）。
    let ok = arch_x86_64::interrupts::register_irq(irq, device_irq_handler);
    if !ok && arch_x86_64::interrupts::irq_handler_count(irq) == 0 {
        slot.store(NO_OWNER, Ordering::Release);
        return Err(Error::NoSpace);
    }
    Ok(irq)
}

/// 释放设备中断归属（注销/进程退出时）。仅当归属确为本 pid 才清除。
pub fn release_device_irq(irq: u8, pid: usize) {
    if irq == 0 || irq as usize >= PIC_IRQ_COUNT {
        return;
    }
    let slot = &IRQ_OWNER[irq as usize];
    let _ = slot.compare_exchange(pid as u32, NO_OWNER, Ordering::AcqRel, Ordering::Acquire);
}

/// kernel-tests：模拟一次设备 IRQ 触发（不含真实中断投递路径）。
///
/// 复现 [`device_irq_handler`] 的核心动作（置待服务闩锁 + 若有归属则调用注入
/// 回调唤醒），供内核自检在无真实硬件中断下验证闩锁 → 定向唤醒语义。仅编译
/// 进 kernel-tests 构建；生产路径零足迹。
#[cfg(feature = "kernel-tests")]
pub fn debug_simulate_irq(irq: u8) -> bool {
    if irq as usize >= PIC_IRQ_COUNT {
        return false;
    }
    let pid = IRQ_OWNER[irq as usize].load(Ordering::Acquire);
    if pid == NO_OWNER {
        // 无归属：模拟真实 handler 行为——不置闩锁、不唤醒（返回 false 未处理）。
        return false;
    }
    IRQ_PENDING[irq as usize].store(1, Ordering::Release);
    // 与真实 handler 一致：IRQ 触发归属驱动即取消该等待的超时定时器（防跨等待
    // 残留，复查 FINDING-1）。
    irq_timer_cancel(irq);
    let cb = IRQ_WAKE_CB.load(Ordering::Acquire);
    if cb == 0 {
        return true;
    }
    let f: fn(usize) = unsafe { core::mem::transmute(cb) };
    f(pid as usize);
    true
}
