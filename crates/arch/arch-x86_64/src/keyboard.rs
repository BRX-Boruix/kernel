//! PS/2 8042 键盘驱动（I-EVENTS 阶段 2 后形态；P5 轨道 A 退役 §6.15.5）。
//!
//! - 初始化 8042 控制器（端口 0x60/0x64），请求并等待键盘自检、开扫描；
//! - 注册 IRQ1 中断 handler（vector 33 → irq 1）：读扫描码 → **原始键码投递
//!   事件环**（`push_event`，16B 记录，ADR-047）——ASCII 译码/转义序列展开
//!   归用户态（libsys keymap，consoled），内核不再持 KEYMAP（P5 退役）。
//! - 旧字节环形缓冲（BUF/pop/peek/has_input）与内核 KEYMAP/KEYMAP_SHIFT 已
//!   **整体退役**：其唯一消费者（stdin 直读路径 / DriverHub ps2-keyboard
//!   read）在 P4 单径切换后无数据可读。
//!
//! 外部中断路由：QEMU `pc` 机器下 IRQ1 走 **8259 → LAPIC LINT0 (ExtINT)**
//! 路径（`pic::init` 重映射解屏蔽 + `imcr::switch_to_pic_mode` 切模式 +
//! `lapic::init` 配 LINT0），本驱动假设中断已使能，handler 自行 EOI。

use crate::interrupts;
use crate::port::{inb, outb};

// 8042 端口
const DATA_PORT: u16 = 0x60; // 数据端口（读写键盘数据）
const CMD_PORT: u16 = 0x64; // 命令/状态端口

// 8042 命令
const CMD_READ_CTRL: u8 = 0x20; // 读控制器配置字节
const CMD_WRITE_CTRL: u8 = 0x60; // 写控制器配置字节
const CMD_SELF_TEST: u8 = 0xAA; // 自检

// 键盘命令（写到数据端口）
const KB_CMD_ACK: u8 = 0xFA;
const KB_ENABLE_SCAN: u8 = 0xF4; // 开扫描（键盘响应 ACK 后开始）
/// 扫描码集选择命令前缀（后随集合号，如 0x01 = Set 1）。
const KB_CMD_SCANCODE_SET: u8 = 0xF0;
/// 扫描码集 1（事件记录 `code` 字段的键码基准，ADR-047 §2.1）。
const KB_SCANCODE_SET1: u8 = 0x01;

// 控制器配置字节位
const CFG_IRQ_ENABLE: u8 = 0x01; // bit0：键盘 IRQ1 使能
const CFG_TRANSLATE: u8 = 0x40; // bit6：扫描码集 1 翻译

// 状态寄存器位
const STATUS_OUTPUT_FULL: u8 = 0x01; // 输出缓冲满（可读数据）
const STATUS_INPUT_FULL: u8 = 0x02; // 输入缓冲满（忙）

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

// ----------（I-EVENTS P5 轨道 A 退役 §6.15.5）----------
// 旧字节输入路径整体移除：SPSC 字节环（BUF_*/push/pop/peek/has_input）、
// 内核 KEYMAP/KEYMAP_SHIFT 译码表与 decode_key、Shift/Ctrl 状态位、stdin
// 唤醒回调（INPUT_CB → task::wake_kbd）。P4 单径切换后该路径无任何消费者；
// ASCII/转义译码归用户态 libsys keymap（consoled），内核只投递原始键码事件。

// ---------- 内部 8042 操作（现役：事件环路径的硬件初始化/中断读取依赖） ----------

/// 等待输入缓冲空（可写命令/数据），超时返回 false。
fn wait_input_empty() -> bool {
    for _ in 0..100_000 {
        if inb(CMD_PORT) & STATUS_INPUT_FULL == 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// 等待输出缓冲满（有数据可读），超时返回 false。
fn wait_output_full() -> bool {
    for _ in 0..100_000 {
        if inb(CMD_PORT) & STATUS_OUTPUT_FULL != 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// 读 8042 配置字节。超时返回 `None`（读不到真值时宁可报错，不返回垃圾）。
fn read_cfg() -> Option<u8> {
    outb(CMD_PORT, CMD_READ_CTRL);
    if wait_output_full() {
        Some(inb(DATA_PORT))
    } else {
        None
    }
}

/// 写 8042 配置字节。
fn write_cfg(cfg: u8) {
    wait_input_empty();
    outb(CMD_PORT, CMD_WRITE_CTRL);
    wait_input_empty();
    outb(DATA_PORT, cfg);
}

/// 向键盘数据端口发命令并等待 ACK（0xFA）。返回 ACK 或 0（超时/异常）。
fn send_kbd_cmd(cmd: u8) -> u8 {
    if !wait_input_empty() {
        return 0;
    }
    outb(DATA_PORT, cmd);
    if wait_output_full() {
        inb(DATA_PORT)
    } else {
        0
    }
}

/// `0xE0` 扩展前缀标志：现代 101 键键盘的方向键/编辑键/小键盘（NumLock 关）/
/// 右 Ctrl/Alt 等以 `0xE0 0xXX` 双字节序列发送。IRQ 每中断只读 1 字节，须跨中断
/// 缓存前缀，待下一字节到达再合成完整键码。
///
/// E0 安全前提（AM4 补记，审计 #4 按现路由重写）：本静态 `mut` 仅在 IRQ1
/// 中断上下文读写。IRQ1 的现役投递路径是 **8259 PIC → LAPIC LINT0
/// (ExtINT)**（见 imcr.rs / pic.rs / lapic.rs 三处配合）——8259 是单输出
/// 设备，其输出只连到**一个** CPU 的 LINT0，不存在 IOAPIC 式多目标均衡，
/// 因此同一中断天然单投递、不会跨核并发重入；同核重入也不可能（handler
/// EOI 前后 IF=0）。访问点不持任何普通自旋锁，无优先级反转死锁路径。
/// 若未来引入多队列/多键盘路由（IOAPIC 回归），必须先改为 per-CPU 或
/// IrqSpinLock 保护。
static mut E0_PREFIX: bool = false;

/// 事件记录入队后通知等待方的回调（I-EVENTS 阶段 2）。由内核在启动时经
/// [`set_event_callback`] 注册（指向 `task::wake_input_event`）。arch 层不反向
/// 依赖 task，故与 [`INPUT_CB`] 同样用函数指针解耦。
///
/// **为何与 `INPUT_CB` 分开**：`INPUT_CB`（[`notify_input`]）挂的是 stdin 字节
/// 路径的唯一等待者（`KBD_WAITER`），由每次 `push()` 调用；本回调挂的是
/// `/devices/input/events` 事件流路径的等待者（`IN_EVENT_WAITER`），由
/// [`push_event`] 调用。两条路径的等待者语义不同（字节 vs 16 字节记录），
/// 共用回调会把「事件到达」误当成「stdin 有字符」唤醒错误的进程。
static mut EVENT_CB: Option<fn()> = None;

/// 注册事件记录入队回调（内核启动时调用一次）。
pub fn set_event_callback(cb: fn()) {
    // SAFETY: 早期单线程注册，之后仅只读访问。
    unsafe {
        EVENT_CB = Some(cb);
    }
}

/// 通知事件等待方：有记录入队（IRQ1 中断上下文调用）。
fn notify_event() {
    // SAFETY: 回调只读，且已注册（未注册时为 None，静默跳过）。
    unsafe {
        if let Some(cb) = EVENT_CB {
            cb();
        }
    }
}

// ---------- 原始键事件缓冲（I-EVENTS 阶段 1，ADR-047；双轨，旧字节路径不动） ----------

/// 事件记录布局（ADR-047 §2.1）：定长 16 字节、小端。
///
/// | offset | size | 字段 | 说明 |
/// | --- | --- | --- | --- |
/// | 0 | 1 | kind | 1=键按下 2=键释放（本阶段只产键事件；3/4/5 指针类预留） |
/// | 1 | 1 | flags | bit0=e0 前缀；bit1=时间戳不可得标注；其余保留恒 0 |
/// | 2 | 2 | code | scancode set 1 键码（不含 bit7；释放语义在 kind） |
/// | 4 | 4 | value | 键事件恒 0（指针/滚轮字段预留） |
/// | 8 | 8 | timestamp | HPET ns；不可得时恒 0 且 flags.bit1=1（S09） |
pub const EVENT_RECORD_SIZE: usize = 16;

/// 事件 kind：键按下（ADR-047 §2.1）。
pub const EVENT_KIND_KEY_DOWN: u8 = 1;
/// 事件 kind：键释放。字节流形态下被丢弃的释放事件自此保留
/// （组合键/修饰键语义需要两侧——ADR-047 §2.2）。
pub const EVENT_KIND_KEY_UP: u8 = 2;

/// flags bit0：`0xE0` 扩展前缀标志（右 Ctrl/Alt、方向键/编辑键区）。
pub const EVENT_FLAG_E0: u8 = 1 << 0;
/// flags bit1：时间戳不可得（`now_nanos()` 返回 `None`）——timestamp 恒 0 且带此标注，
/// 不伪装成真实时间（S09/S17：0 是合法 HPET 值，单独的 0 有歧义）。
pub const EVENT_FLAG_NO_TIME: u8 = 1 << 1;

/// 事件环形缓冲容量（**记录数**，非字节数）。
///
/// 与字节缓冲（`BUF_CAP=128` 字节）不同的量纲：128 条 16B 记录 = 2 KiB。
/// 消费者（/devices/input/events 节点，后续小点接线）读得慢时最多积压 128 条。
const EVQ_CAP: usize = 128;

/// SPSC 环形缓冲：写=IRQ1 中断上下文（单生产者），读=内核读取路径（单消费者）。
/// 索引单调递增（wrapping），槽位取模；与字节缓冲同一手法。
static EVQ_WRITE: AtomicUsize = AtomicUsize::new(0);
static EVQ_READ: AtomicUsize = AtomicUsize::new(0);
/// 事件存储：每条记录 16 字节，按 [u64; 2] 两字存放（避免 per-byte 原子操作）。
///
/// 内存序纪律：`EVQ_DATA` 的写入先于 `EVQ_WRITE` 的 Release 存储；读者以
/// `EVQ_WRITE` 的 Acquire 读配对——与字节缓冲（`BUF_DATA`/`WRITE_INDEX`）同一约定。
static EVQ_DATA: [AtomicU64; EVQ_CAP * 2] = [const { AtomicU64::new(0) }; EVQ_CAP * 2];
/// 首条事件写入后置 1（读侧快速判空，与 BUF_INIT 同款）。
static EVQ_INIT: AtomicU32 = AtomicU32::new(0);

/// 因事件缓冲满而被丢弃的事件总数（单调递增）。
///
/// AM4 同款纪律（S09）：满时丢弃不覆盖未读，但**必须留下计数痕迹**——
/// 「输入无损」不是假设，是可观察的事实。
static DROPPED_EVENTS: AtomicU64 = AtomicU64::new(0);

/// 投递一条原始键事件（IRQ1 中断上下文调用；ADR-047 §2.5「原子入流」：
/// 单条事件 16 字节一次写完，读者不会看到半条）。
///
/// `code` 传**原始键码**（scancode set 1，已剥 bit7），`e0` 为扩展前缀标志，
/// `key_up` 决定 kind。**不译 ASCII、不折叠 Ctrl**——那是用户态转换层的事
/// （ADR-047 §2.2 / ADR-045 决策 3）。Shift/Ctrl 键自身也投递（`0x2A/0x36/0x1D`），
/// 转换层要靠它们维护修饰键状态机。
fn push_event(e0: bool, code: u8, key_up: bool) {
    let w = EVQ_WRITE.load(Ordering::Relaxed);
    let r = EVQ_READ.load(Ordering::Relaxed);
    if w.wrapping_sub(r) >= EVQ_CAP {
        DROPPED_EVENTS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    // 时间戳：不可得时恒 0 + 显式标注（S09）。
    let (ts, no_time) = match klib::time::now_nanos() {
        Some(t) => (t, false),
        None => (0u64, true),
    };
    let mut flags = 0u8;
    if e0 {
        flags |= EVENT_FLAG_E0;
    }
    if no_time {
        flags |= EVENT_FLAG_NO_TIME;
    }
    let kind = if key_up { EVENT_KIND_KEY_UP } else { EVENT_KIND_KEY_DOWN };
    // 记录低 8 字节：kind | flags | code(u16 LE) | value(u32 LE，键事件恒 0)。
    let lo = (kind as u64)
        | ((flags as u64) << 8)
        | ((code as u64) << 16)
        | (0u64 << 32);
    // 入环 + 唤醒（S13 单点：流控/存储/唤醒唯一在 `enqueue_record`）。
    let _ = enqueue_record(lo, ts);
}

/// 环操作单点（S13）：流控（满则丢新并计数）→ 存记录两字 → Release 发布写
/// 指针 → 置 INIT → 唤醒事件读者。`push_event`（生产）与
/// `test_push_raw_event`（测试注流）共用；返回 `false` = 满丢弃。
fn enqueue_record(lo: u64, ts: u64) -> bool {
    let w = EVQ_WRITE.load(Ordering::Relaxed);
    let r = EVQ_READ.load(Ordering::Relaxed);
    if w.wrapping_sub(r) >= EVQ_CAP {
        DROPPED_EVENTS.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    let base = (w % EVQ_CAP) * 2;
    EVQ_DATA[base].store(lo, Ordering::Relaxed);
    EVQ_DATA[base + 1].store(ts, Ordering::Relaxed);
    EVQ_WRITE.store(w + 1, Ordering::Release);
    EVQ_INIT.store(1, Ordering::Release);
    // I-EVENTS 阶段 2：唤醒阻塞在 `/devices/input/events` 读上的进程。
    // 与旧字节路径的 `notify_input` 分开（两条路径的等待者语义不同，见
    // `EVENT_CB` 说明）——旧路径零改动（双轨红线）。
    notify_event();
    true
}

/// 因事件缓冲满被丢弃的事件总数（诊断接口，AM4 同款）。
pub fn dropped_events() -> u64 {
    DROPPED_EVENTS.load(Ordering::Relaxed)
}
/// 事件环当前**待读记录数**（诊断接口，§6.13 定位用）。
///
/// **为何需要这个读数**：§6.13 的缺陷表现为「有进程阻塞在事件节点上时烧满一个核」。
/// 判定它是「`has_event()` 为真而 `read_at` 交付 0 字节」的内核态紧循环，
/// 还是「环里真有一条永不消费的记录」，需要**同时**看到「环深度」与
/// 「`read` 是否在推进」两个真值。仅凭 `has_pending` 布尔无法区分二者。
///
/// **无副作用**：只读两个原子索引，不推进 `EVQ_READ`（与 [`has_event`] 同纪律，
/// 可安全重复调用，不会像 `pop_event` 那样消费记录而改变被观察系统）。
pub fn pending_events() -> u64 {
    if EVQ_INIT.load(Ordering::Acquire) == 0 {
        return 0;
    }
    let r = EVQ_READ.load(Ordering::Relaxed);
    let w = EVQ_WRITE.load(Ordering::Acquire);
    w.wrapping_sub(r) as u64
}

/// 弹出一条事件记录，写入 `out`（须 ≥ 16 字节；ADR-047 §2.1 布局）。
/// 无事件返回 `false`（out 不被触碰）。
///
/// **P1（§6.15）起为 legacy 单读者消费点**：多读者层不再逐条 pop（改用
/// 下方环视图 `evq_peek`/`evq_advance`，每读者一把游标）；本函数保留为
/// trait 默认读路径的实现（未覆写该缝的 Provider 仍走它）。全局读指针
/// 的推进点自 P1 起有两处：本函数与 `evq_advance`（受控、不越写指针）。
pub fn pop_event(out: &mut [u8]) -> bool {
    if out.len() < EVENT_RECORD_SIZE {
        return false;
    }
    if EVQ_INIT.load(Ordering::Acquire) == 0 {
        return false;
    }
    let r = EVQ_READ.load(Ordering::Relaxed);
    let w = EVQ_WRITE.load(Ordering::Acquire);
    if r == w {
        return false;
    }
    let base = (r % EVQ_CAP) * 2;
    let lo = EVQ_DATA[base].load(Ordering::Relaxed);
    let ts = EVQ_DATA[base + 1].load(Ordering::Relaxed);
    EVQ_READ.store(r + 1, Ordering::Release);
    out[0] = (lo & 0xFF) as u8;
    out[1] = ((lo >> 8) & 0xFF) as u8;
    out[2] = ((lo >> 16) & 0xFF) as u8;
    out[3] = ((lo >> 24) & 0xFF) as u8;
    out[4] = ((lo >> 32) & 0xFF) as u8;
    out[5] = ((lo >> 40) & 0xFF) as u8;
    out[6] = ((lo >> 48) & 0xFF) as u8;
    out[7] = ((lo >> 56) & 0xFF) as u8;
    out[8..16].copy_from_slice(&ts.to_le_bytes());
    true
}

// ---------- 事件环视图（I-EVENTS P1 多读者，§6.15） ----------
//
// `pop_event` 是 SPSC 的唯一消费点；多读者层（`vfs::stream`）不再逐条 pop，
// 而是「每读者一把游标 + 全局读指针按最慢读者推进」。这里导出环的**视图**
// 与**受控推进**，供 Provider 缝（vfs_init.rs 的 `KernelDeviceProvider`）
// 反射——vfs 不依赖 arch_x86_64（KM1），全部经 trait 方法间接到达。
//
// 内存序与 `pop_event` 同纪律：先 Acquire 写指针，再读槽（记录数据先于
// `EVQ_WRITE` 的 Release 存储可见，Acquire 配对后槽内容必然完整）。

/// wrapping 序比较：`x` 是否落在 `[lo, hi)` 内（三值同一单调域；域跨度
/// 远小于 2^63——环深 128，游标差不可能进入高位歧义区）。
fn evq_in_range(x: u64, lo: u64, hi: u64) -> bool {
    let dx = x.wrapping_sub(lo);
    let dh = hi.wrapping_sub(lo);
    dx < dh && (dh >> 63) == 0
}

/// 全局读指针（回收墙下游；只读不推进）。本环恒存在，恒 `Some`。
pub fn evq_read_index() -> Option<u64> {
    Some(EVQ_READ.load(Ordering::Relaxed) as u64)
}

/// 全局写指针（已投递记录总数；只读不推进）。本环恒存在，恒 `Some`。
pub fn evq_write_index() -> Option<u64> {
    Some(EVQ_WRITE.load(Ordering::Acquire) as u64)
}

/// 环容量（记录数）；本环恒存在，恒 `Some`。
pub fn evq_capacity() -> Option<u64> {
    Some(EVQ_CAP as u64)
}

/// 读游标 `cursor` 处的记录**但不消费**（多读者 peek）。
///
/// 可用判据与 `pop_event` 同纪律（S15）：`cursor ∈ [读墙, 写指针)`。
/// 越过读墙的槽位可能已被覆盖——交付覆盖中的槽位 = 伪造数据（S09）；
/// 越过写指针 = 尚未就绪。两种情况都返回 `false`（out 不被触碰）。
pub fn evq_peek(cursor: u64, out: &mut [u8]) -> bool {
    if out.len() < EVENT_RECORD_SIZE {
        return false;
    }
    let r = EVQ_READ.load(Ordering::Relaxed) as u64;
    let w = EVQ_WRITE.load(Ordering::Acquire) as u64;
    if !evq_in_range(cursor, r, w) {
        return false;
    }
    let base = (cursor as usize % EVQ_CAP) * 2;
    let lo = EVQ_DATA[base].load(Ordering::Relaxed);
    let ts = EVQ_DATA[base + 1].load(Ordering::Relaxed);
    out[..8].copy_from_slice(&lo.to_le_bytes());
    out[8..16].copy_from_slice(&ts.to_le_bytes());
    true
}

/// 受控推进全局读指针（回收墙回馈；绝不越过写指针，CAS 防并发重推）。
/// 由最慢读者下界驱动（`vfs::stream`）；`pop_event` 之外的唯一推进点。
pub fn evq_advance(n: u64) {
    if n == 0 {
        return;
    }
    let w = EVQ_WRITE.load(Ordering::Acquire) as u64;
    let mut cur = EVQ_READ.load(Ordering::Relaxed) as u64;
    loop {
        // 目标 = min(写指针, 当前 + n)：宁可少推，不可越界（S17）。
        let target = core::cmp::min(w, cur.wrapping_add(n));
        if target <= cur {
            return;
        }
        match EVQ_READ.compare_exchange(
            cur as usize,
            target as usize,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(actual) => cur = actual as u64, // 并发重推：以最新值重来
        }
    }
}

/// 测试/自检注流：向事件环投递一条原始 16 字节记录（kernel-tests 用；
/// 生产投递路径是 IRQ1 → `push_event`，从不经过这里）。与 `push_event`
/// 走同一条环、同一条流控（满则丢弃并计数）与同一条唤醒回调（S13：
/// 唯一在 `enqueue_record`）。
pub fn test_push_raw_event(rec: &[u8; EVENT_RECORD_SIZE]) -> bool {
    let mut lo = [0u8; 8];
    lo.copy_from_slice(&rec[..8]);
    let mut ts = [0u8; 8];
    ts.copy_from_slice(&rec[8..16]);
    enqueue_record(u64::from_le_bytes(lo), u64::from_le_bytes(ts))
}

/// 事件缓冲是否**可读**（即 `pop_event` 此刻是否会返回 `true`）。
///
/// **必须与 [`pop_event`] 判据逐位一致**（S15 单点真值）：`pop_event` 先查
/// `EVQ_INIT`、再查 `r == w`，本函数也必须两者都查。否则「`has_event()` 为真
/// 而 `pop_event` 返回空」的矛盾态会让调用方（`block_for_input_event` 的锁内
/// 复检 → `sys_read` 重读）陷入**内核态紧循环**——实测缺陷：evdemo 在事件环
/// 为空后固定冻结（该矛盾态出现在 `push_event` 尚未完成 `EVQ_INIT` 置位的
/// 极早窗口，以及 `EVQ_READ` 被推进到与 `EVQ_WRITE` 相等的瞬间）。
pub fn has_event() -> bool {
    if EVQ_INIT.load(Ordering::Acquire) == 0 {
        return false;
    }
    EVQ_READ.load(Ordering::Relaxed) != EVQ_WRITE.load(Ordering::Acquire)
}

// ---------- IRQ1 中断 handler ----------

/// IRQ1 键盘中断：读扫描码、处理 `0xE0` 扩展前缀、译码并压入缓冲。
pub extern "C" fn irq1_handler(_irq: u8) -> bool {
    // 读数据端口（清中断挂起）。
    let scancode = inb(DATA_PORT);

    // `0xE0` 扩展前缀：缓存标志，等待下一 IRQ 的真正键码（单独一字节无意义）。
    if scancode == 0xE0 {
        unsafe { E0_PREFIX = true };
        crate::lapic::end_of_interrupt();
        return true;
    }
    // `0xE1`（Pause/Break 序列）：忽略后续字节。
    if scancode == 0xE1 {
        unsafe { E0_PREFIX = false };
        crate::lapic::end_of_interrupt();
        return true;
    }

    let e0 = unsafe { E0_PREFIX };
    unsafe { E0_PREFIX = false };
    let key_up = scancode & 0x80 != 0; // bit7=1 表示释放
    let code = scancode & 0x7F;

    // I-EVENTS（ADR-047）：**全部**键事件（含 Shift/Ctrl 自身、含释放）以原始
    // 键码投递到事件环——不译 ASCII、不折叠 Ctrl（转换层归用户态 keymap，
    // ADR-047 §2.2）。
    // （I-EVENTS P5 轨道 A 退役：原「双轨」的旧轨——Shift/Ctrl 状态位维护 +
    //  decode_key 字节译码 + push 入字节环——已整体移除，见文件头说明。）
    push_event(e0, code, key_up);

    // 键盘 IRQ 属于外部中断：发送 LAPIC EOI。
    crate::lapic::end_of_interrupt();
    true
}

// ---------- 初始化 ----------

/// 初始化 PS/2 8042 键盘并注册 IRQ1 handler。
///
/// 返回是否成功（键盘自检通过）。须在中断已配置（IDT 加载）、外部中断
/// 路由就绪后调用。
pub fn init() -> bool {
    // 1. 8042 自检。
    wait_input_empty();
    outb(CMD_PORT, CMD_SELF_TEST);
    // 自检结果会写到输出缓冲：0x55 表示通过。
    wait_output_full();
    let test = inb(DATA_PORT);
    if test != 0x55 {
        klib::info!("[kbd] 8042 self-test failed (0x{:02x})", test);
        return false;
    }

    // 2. 使能键盘 IRQ（**关闭**扫描码翻译）。事件记录投递的是 Set 1 原始键码；
    //    开启 8042 的 Set2→Set1 翻译会让 backspace(Set2 0x66) 等码在翻译环节被
    //    丢弃（翻译表无对应项），导致删除键收不到扫描码。故关闭翻译，并随后把
    //    键盘切到 Set 1，使所有键（含 backspace 0x0e）直通。
    let Some(mut cfg) = read_cfg() else {
        klib::info!("[kbd] config byte read timed out");
        return false;
    };
    cfg |= CFG_IRQ_ENABLE;
    cfg &= !CFG_TRANSLATE;
    write_cfg(cfg);

    // 3. 切换键盘到扫描码集 1（Set 1），再开扫描。顺序：F0 01 切 Set1，F4 开扫描。
    //    两条命令的 ACK 都必须验证（arch1.md AM3）：翻译已关闭的前提是键盘真的
    //    切到了 Set 1——静默失败会让键盘留在 Set 2，所有键以错误码进缓冲且无
    //    诊断。任一 ACK 不符即判初始化失败，绝不带病上岗。
    let ack_set = send_kbd_cmd(KB_CMD_SCANCODE_SET);
    if ack_set != KB_CMD_ACK {
        klib::info!(
            "[kbd] scancode-set cmd ack mismatch (0x{:02x})",
            ack_set
        );
        return false;
    }
    let ack_val = send_kbd_cmd(KB_SCANCODE_SET1);
    if ack_val != KB_CMD_ACK {
        klib::info!(
            "[kbd] scancode-set 1 ack mismatch (0x{:02x})",
            ack_val
        );
        return false;
    }
    if wait_input_empty() {
        outb(DATA_PORT, KB_ENABLE_SCAN);
        // 等 ACK（0xFA）；可能需先清多余输出。
        let ack = if wait_output_full() {
            inb(DATA_PORT)
        } else {
            0
        };
        if ack != KB_CMD_ACK {
            klib::info!("[kbd] enable-scan ack mismatch (0x{:02x})", ack);
            return false;
        }
    } else {
        klib::info!("[kbd] input buffer never drained before enable-scan");
        return false;
    }

    // 4. 注册 IRQ1 handler。
    let ok = interrupts::register_irq(1, irq1_handler);
    if ok {
        klib::info!("[kbd] PS/2 keyboard initialized (IRQ1)");
    } else {
        klib::info!("[kbd] failed to register IRQ1 handler");
    }
    ok
}
