//! PS/2 8042 键盘驱动（阶段 B）。
//!
//! - 初始化 8042 控制器（端口 0x60/0x64），请求并等待键盘自检、开扫描；
//! - 注册 IRQ1 中断 handler（vector 33 → irq 1）：读扫描码 → 译码为 ASCII →
//!   压入输入环形缓冲；
//! - 供内核 `read` syscall（stdin=0）从缓冲取字节；
//! - 支持 Shift 组合（普通/上档两套键位映射）。
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
/// 扫描码集 1（本驱动 KEYMAP 的译码基准）。
const KB_SCANCODE_SET1: u8 = 0x01;

// 控制器配置字节位
const CFG_IRQ_ENABLE: u8 = 0x01; // bit0：键盘 IRQ1 使能
const CFG_TRANSLATE: u8 = 0x40; // bit6：扫描码集 1 翻译

// 状态寄存器位
const STATUS_OUTPUT_FULL: u8 = 0x01; // 输出缓冲满（可读数据）
const STATUS_INPUT_FULL: u8 = 0x02; // 输入缓冲满（忙）

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

/// 简单 SPSC 环形缓冲（写入=IRQ1 中断，读取=syscall）。
const BUF_CAP: usize = 128;
static WRITE_INDEX: AtomicUsize = AtomicUsize::new(0);
static READ_INDEX: AtomicUsize = AtomicUsize::new(0);
static BUF_DATA: [AtomicU32; BUF_CAP] = [const { AtomicU32::new(0) }; BUF_CAP];
/// 缓冲是否已初始化（首次键盘输入前 false，read 检查）。
static BUF_INIT: AtomicU32 = AtomicU32::new(0);

/// Shift 是否按住。
static SHIFT: AtomicU32 = AtomicU32::new(0);

/// Ctrl 是否按住（§6.8：此前完全缺失，故 `0x03` 永远产生不出来）。
///
/// 与 `SHIFT` 同一手法：IRQ1 里按 scancode 置位/清位，`decode_key` 里消费。
/// **本状态只影响字节译码**——不产生任何信号、不新增 syscall、不引入模式开关。
/// `Ctrl+字母` 折叠为 `字符 & 0x1F`（Ctrl-C → `0x03`、Ctrl-D → `0x04`），
/// 与 `0x04`/\t/\x1b 走**同一条**既有入缓冲路径；信号语义仍全部在用户态
/// （ADR-042 §3.1）。
static CTRL: AtomicU32 = AtomicU32::new(0);

// ---------- 内部 8042 操作 ----------

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

// ---------- 扫描码译码 ----------

/// 扫描码 → ASCII（无 Shift 时）。索引 = 扫描码（Set 1，~0x01..=0x58）。
///
/// AD3 披露：当前译码为主键盘**子集**——**CapsLock/Alt/功能键仍部分未实现**，
/// 双表结构（KEYMAP/KEYMAP_SHIFT）貌似完整键位支持，实际只覆盖可打印字符 +
/// Esc/Tab/Backspace/Enter。扩展键位时须同步补 0xE0 前缀路径
/// （该路径已存在但仅处理方向键）。
///
/// **2026-10-04（§6.8 修复后更新）**：**Ctrl 已实现**——修饰键状态在 IRQ1 里
/// 按 scancode 维护（左/右均为 0x1D），`decode_key` 对字母折叠 `字符 & 0x1F`，
/// 故 Ctrl-C → `0x03`、Ctrl-D → `0x04` 可正常入缓冲。
/// **Alt 仍未实现**（按下被静默丢弃）；CapsLock 仍不改变字母大小写语义。
const KEYMAP: [u8; 0x80] = {
    let mut m = [0u8; 0x80];
    m[0x01] = 27; // Esc
    m[0x02] = b'1';
    m[0x03] = b'2';
    m[0x04] = b'3';
    m[0x05] = b'4';
    m[0x06] = b'5';
    m[0x07] = b'6';
    m[0x08] = b'7';
    m[0x09] = b'8';
    m[0x0A] = b'9';
    m[0x0B] = b'0';
    m[0x0C] = b'-';
    m[0x0D] = b'=';
    m[0x0E] = 0x7F; // backspace
    m[0x0F] = b'\t';
    m[0x10] = b'q';
    m[0x11] = b'w';
    m[0x12] = b'e';
    m[0x13] = b'r';
    m[0x14] = b't';
    m[0x15] = b'y';
    m[0x16] = b'u';
    m[0x17] = b'i';
    m[0x18] = b'o';
    m[0x19] = b'p';
    m[0x1A] = b'[';
    m[0x1B] = b']';
    m[0x1C] = b'\n';
    m[0x1E] = b'a';
    m[0x1F] = b's';
    m[0x20] = b'd';
    m[0x21] = b'f';
    m[0x22] = b'g';
    m[0x23] = b'h';
    m[0x24] = b'j';
    m[0x25] = b'k';
    m[0x26] = b'l';
    m[0x27] = b';';
    m[0x28] = b'\'';
    m[0x29] = b'`';
    m[0x2B] = b'\\';
    m[0x2C] = b'z';
    m[0x2D] = b'x';
    m[0x2E] = b'c';
    m[0x2F] = b'v';
    m[0x30] = b'b';
    m[0x31] = b'n';
    m[0x32] = b'm';
    m[0x33] = b',';
    m[0x34] = b'.';
    m[0x35] = b'/';
    m[0x39] = b' ';
    m
};

/// 扫描码 → ASCII（Shift 按住时）。
const KEYMAP_SHIFT: [u8; 0x80] = {
    let mut m = [0u8; 0x80];
    m[0x02] = b'!';
    m[0x03] = b'@';
    m[0x04] = b'#';
    m[0x05] = b'$';
    m[0x06] = b'%';
    m[0x07] = b'^';
    m[0x08] = b'&';
    m[0x09] = b'*';
    m[0x0A] = b'(';
    m[0x0B] = b')';
    m[0x0C] = b'_';
    m[0x0D] = b'+';
    m[0x10] = b'Q';
    m[0x11] = b'W';
    m[0x12] = b'E';
    m[0x13] = b'R';
    m[0x14] = b'T';
    m[0x15] = b'Y';
    m[0x16] = b'U';
    m[0x17] = b'I';
    m[0x18] = b'O';
    m[0x19] = b'P';
    m[0x1A] = b'{';
    m[0x1B] = b'}';
    m[0x1E] = b'A';
    m[0x1F] = b'S';
    m[0x20] = b'D';
    m[0x21] = b'F';
    m[0x22] = b'G';
    m[0x23] = b'H';
    m[0x24] = b'J';
    m[0x25] = b'K';
    m[0x26] = b'L';
    m[0x27] = b':';
    m[0x28] = b'"';
    m[0x29] = b'~';
    m[0x2B] = b'|';
    m[0x2C] = b'Z';
    m[0x2D] = b'X';
    m[0x2E] = b'C';
    m[0x2F] = b'V';
    m[0x30] = b'B';
    m[0x31] = b'N';
    m[0x32] = b'M';
    m[0x33] = b'<';
    m[0x34] = b'>';
    m[0x35] = b'?';
    m
};

/// Shift 键扫描码（左/右）。
const SC_LSHIFT: u8 = 0x2A;
const SC_RSHIFT: u8 = 0x36;

/// Ctrl 键扫描码。
///
/// 左 Ctrl 是**无 `E0` 前缀**的 `0x1D`；右 Ctrl 走 `0xE0 0x1D`（`e0 == true`，
/// 与左键同码值 `0x1D`，靠 `e0` 标志区分——两者语义相同，故只用一个常量）。
const SC_LCTRL: u8 = 0x1D;

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

/// 译码结果：无输出 / 单个 ASCII 字节 / 一段（转义序列，静态生命周期）。
enum KeyOut {
    None,
    Ascii(u8),
    Seq(&'static [u8]),
}

/// 把（扩展标志, 键码, 释放?）译码为可入缓冲的字节序列。
///
/// - 主键盘可打印键 → ASCII（受 Shift 影响，查 `KEYMAP`/`KEYMAP_SHIFT`）。
/// - 非 `E0` 的 `0x47..=0x53` 等区域：来自 **NumLock 开启**时的数字小键盘 → 数字。
/// - `E0` 前缀的光标/编辑键 → ANSI 转义序列（与终端约定一致，shell 可据此行编辑）。
/// - F1–F12（主集 `0x3B..=0x44`/`0x57`/`0x58`）→ ANSI 转义序列。
fn decode_key(e0: bool, code: u8, key_up: bool) -> KeyOut {
    if key_up {
        return KeyOut::None;
    }
    if !e0 {
        // 主键盘可打印字符（受 Shift 影响）。
        let shift = SHIFT.load(Ordering::Relaxed) != 0;
        let ch = if shift {
            KEYMAP_SHIFT[code as usize]
        } else {
            KEYMAP[code as usize]
        };
        if ch != 0 {
            // §6.8：Ctrl + 字母 → 控制字符（字符 & 0x1F）。
            //
            // 只对**字母**折叠：Ctrl-C → 0x03、Ctrl-D → 0x04，正是终端约定。
            // 对非字母保持原样，避免把 Ctrl+数字/符号变成难以预期的控制码
            // （那些组合的真实语义属应用层，本驱动不臆造，S17 安全侧默认）。
            if CTRL.load(Ordering::Relaxed) != 0 && ch.is_ascii_alphabetic() {
                return KeyOut::Ascii(ch & 0x1F);
            }
            return KeyOut::Ascii(ch);
        }
        // NumLock 语义的数字小键盘 / 主键盘符号，以及 F-keys。
        return match code {
            // 小键盘数字（NumLock 开）
            0x47 => KeyOut::Ascii(b'7'),
            0x48 => KeyOut::Ascii(b'8'),
            0x49 => KeyOut::Ascii(b'9'),
            0x4B => KeyOut::Ascii(b'4'),
            0x4C => KeyOut::Ascii(b'5'),
            0x4D => KeyOut::Ascii(b'6'),
            0x4F => KeyOut::Ascii(b'1'),
            0x50 => KeyOut::Ascii(b'2'),
            0x51 => KeyOut::Ascii(b'3'),
            0x52 => KeyOut::Ascii(b'0'),
            0x53 => KeyOut::Ascii(b'.'),
            // 小键盘/主键盘符号
            0x37 => KeyOut::Ascii(b'*'), // 主键盘 '*'（8 上方）
            0x4A => KeyOut::Ascii(b'-'), // 小键盘 '-'
            0x4E => KeyOut::Ascii(b'+'), // 小键盘 '+'
            // F1–F12
            0x3B => KeyOut::Seq(b"\x1bOP"),
            0x3C => KeyOut::Seq(b"\x1bOQ"),
            0x3D => KeyOut::Seq(b"\x1bOR"),
            0x3E => KeyOut::Seq(b"\x1bOS"),
            0x3F => KeyOut::Seq(b"\x1b[15~"),
            0x40 => KeyOut::Seq(b"\x1b[17~"),
            0x41 => KeyOut::Seq(b"\x1b[18~"),
            0x42 => KeyOut::Seq(b"\x1b[19~"),
            0x43 => KeyOut::Seq(b"\x1b[20~"),
            0x44 => KeyOut::Seq(b"\x1b[21~"),
            0x57 => KeyOut::Seq(b"\x1b[23~"),
            0x58 => KeyOut::Seq(b"\x1b[24~"),
            _ => KeyOut::None,
        };
    }
    // 扩展键（E0 前缀）：方向键 / 编辑键 / 小键盘 Enter、'/' → 转义序列。
    match code {
        0x48 => KeyOut::Seq(b"\x1b[A"),  // ↑
        0x50 => KeyOut::Seq(b"\x1b[B"),  // ↓
        0x4B => KeyOut::Seq(b"\x1b[D"),  // ←
        0x4D => KeyOut::Seq(b"\x1b[C"),  // →
        0x47 => KeyOut::Seq(b"\x1b[H"),  // Home
        0x4F => KeyOut::Seq(b"\x1b[F"),  // End
        0x52 => KeyOut::Seq(b"\x1b[2~"), // Insert
        0x53 => KeyOut::Seq(b"\x1b[3~"), // Delete
        0x49 => KeyOut::Seq(b"\x1b[5~"), // PgUp
        0x51 => KeyOut::Seq(b"\x1b[6~"), // PgDn
        0x35 => KeyOut::Seq(b"/"),       // 小键盘 '/'
        0x1C => KeyOut::Seq(b"\n"),      // 小键盘 Enter
        _ => KeyOut::None,
    }
}

// ---------- 输入缓冲 ----------

/// 键盘有输入时通知等待方（如阻塞的 read）的回调。由内核在启动时通过
/// `set_input_callback` 注册（指向 `scheduler::wake_kbd`）。arch 层不反向依赖
/// kernel，故用函数指针解耦。
static mut INPUT_CB: Option<fn()> = None;

/// 注册键盘输入回调（内核启动时调用一次）。
pub fn set_input_callback(cb: fn()) {
    // SAFETY: 早期单线程注册，之后仅只读访问。
    unsafe {
        INPUT_CB = Some(cb);
    }
}

/// 通知等待方：有字符入缓冲（中断上下文调用）。
fn notify_input() {
    // SAFETY: 回调只读，且已注册。
    unsafe {
        if let Some(cb) = INPUT_CB {
            cb();
        }
    }
}

/// 压入一个字符到缓冲（IRQ1 中断上下文调用）。
///
/// AM4：缓冲满时的静默丢弃不再无痕——累计进 [`DROPPED_KEYS`] 计数器，
/// 诊断/自检可经 [`dropped_keys()`] 观察真实丢失量，而不是假装输入无损。
fn push(ch: u8) {
    let w = WRITE_INDEX.load(Ordering::Relaxed);
    let r = READ_INDEX.load(Ordering::Relaxed);
    if w.wrapping_sub(r) >= BUF_CAP {
        // 满，丢弃（避免覆盖未读）——但留下计数痕迹。
        DROPPED_KEYS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    BUF_DATA[w % BUF_CAP].store(ch as u32, Ordering::Relaxed);
    WRITE_INDEX.store(w + 1, Ordering::Release);
    BUF_INIT.store(1, Ordering::Release);
    notify_input(); // 唤醒阻塞在 read 的进程
}

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

/// 因缓冲满而被丢弃的键字节总数（单调递增）。
static DROPPED_KEYS: AtomicU64 = AtomicU64::new(0);

/// 返回至今因缓冲满被丢弃的键字节数（AM4 诊断接口）。
pub fn dropped_keys() -> u64 {
    DROPPED_KEYS.load(Ordering::Relaxed)
}

/// 弹出一个字符（read syscall 调用）。无数据返回 None。
pub fn pop() -> Option<u8> {
    if BUF_INIT.load(Ordering::Acquire) == 0 {
        return None;
    }
    let r = READ_INDEX.load(Ordering::Relaxed);
    let w = WRITE_INDEX.load(Ordering::Acquire);
    if r == w {
        return None;
    }
    let ch = BUF_DATA[r % BUF_CAP].load(Ordering::Relaxed) as u8;
    READ_INDEX.store(r + 1, Ordering::Release);
    Some(ch)
}

/// 缓冲是否非空。
/// 窥视下一个字符但**不消费**（`read` syscall 的非阻塞「探键」路径调用）。
///
/// # 为什么必须存在这个函数（裁决甲，§6.12.5）
///
/// shell 在前台子进程运行期间需要「看一眼有没有 `^C`」。若用 `pop()`，
/// 取到的若是普通字符（属于**子进程**的输入，例如 `cat` 的用户输入），
/// 该字节就**永久丢失**了——没有 pushback 设施可以放回。
///
/// 实测症状（真实 QEMU + 真实 PS/2 按键）：输入 `/programs/spinburn.elf`
/// 会变成 `/prams/spinburn.elf`——`o` 与 `g` 在 shell 等待循环里被探键吃掉。
/// 这是**真实的用户可见缺陷**，不是理论问题。
///
/// [`peek`] 与 [`pop`] 的唯一差别：**不推进** `READ_INDEX`。故调用方看完
/// 若决定不处理，字节仍在缓冲里，下一个读者（子进程或行编辑）照样能取到。
///
/// # 内存序
///
/// 与 [`pop`] 相同的 Acquire 读 `WRITE_INDEX`——窥视同样必须看到生产者
/// 已发布的完整状态（`BUF_DATA` 写入先于 `WRITE_INDEX` 的 Release 存储）。
pub fn peek() -> Option<u8> {
    if BUF_INIT.load(Ordering::Acquire) == 0 {
        return None;
    }
    let r = READ_INDEX.load(Ordering::Relaxed);
    let w = WRITE_INDEX.load(Ordering::Acquire);
    if r == w {
        return None;
    }
    // 只读不推进：本函数对缓冲状态**无副作用**，可安全重复调用。
    Some(BUF_DATA[r % BUF_CAP].load(Ordering::Relaxed) as u8)
}

pub fn has_input() -> bool {
    READ_INDEX.load(Ordering::Relaxed) != WRITE_INDEX.load(Ordering::Acquire)
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
    let base = (w % EVQ_CAP) * 2;
    EVQ_DATA[base].store(lo, Ordering::Relaxed);
    EVQ_DATA[base + 1].store(ts, Ordering::Relaxed);
    EVQ_WRITE.store(w + 1, Ordering::Release);
    EVQ_INIT.store(1, Ordering::Release);
    // I-EVENTS 阶段 2：唤醒阻塞在 `/devices/input/events` 读上的进程。
    // 与旧字节路径的 `notify_input` 分开（两条路径的等待者语义不同，见
    // `EVENT_CB` 说明）——旧路径零改动（双轨红线）。
    notify_event();
}

/// 因事件缓冲满被丢弃的事件总数（诊断接口，AM4 同款）。
pub fn dropped_events() -> u64 {
    DROPPED_EVENTS.load(Ordering::Relaxed)
}

/// 弹出一条事件记录，写入 `out`（须 ≥ 16 字节；ADR-047 §2.1 布局）。
/// 无事件返回 `false`（out 不被触碰）。
///
/// 读取路径（后续小点接 `/devices/input/events` 节点）调用；
/// 单消费者纪律：与字节缓冲相同——只有这一处 pop。
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

    // I-EVENTS 阶段 1（ADR-047；双轨）：**全部**键事件（含 Shift/Ctrl 自身、含释放）
    // 以原始键码投递到事件缓冲——不译 ASCII、不折叠 Ctrl（转换层归用户态，ADR-047 §2.2）。
    // 位于状态位维护之后、字节译码之外：旧字节路径（下方 match）零改动。
    push_event(e0, code, key_up);
    if code == SC_LSHIFT || code == SC_RSHIFT {
        SHIFT.store(if key_up { 0 } else { 1 }, Ordering::Relaxed);
    } else if code == SC_LCTRL {
        // §6.8：左右 Ctrl 同为 0x1D（右键靠 E0 前缀区分），语义相同。
        CTRL.store(if key_up { 0 } else { 1 }, Ordering::Relaxed);
    } else if !key_up {
        match decode_key(e0, code, key_up) {
            KeyOut::None => {}
            KeyOut::Ascii(c) => push(c),
            KeyOut::Seq(s) => {
                for &b in s {
                    push(b);
                }
            }
        }
    }

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

    // 2. 使能键盘 IRQ（**关闭**扫描码翻译）。本驱动键位表 `KEYMAP` 是 Set 1；
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
