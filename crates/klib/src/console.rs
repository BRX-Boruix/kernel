//! 统一控制台输出层。
//!
//! 内核所有日志输出（串口、framebuffer 终端等）最终汇聚到这里。
//! 各架构/设备在初始化早期把各自的 `Console` 实现注册为 sink，
//! 之后每次写操作把整串文本转发给所有已注册 sink。
//!
//! 设计约束：
//! - `no_std`、无堆分配：sink 表用静态定长数组存储（`&'static dyn Console`
//!   为胖指针，拆成 data + vtable 两个 `usize` 原子槽）。
//! - **不引入额外全局锁**：每个 sink 必须自行保证 `write_str` 内部原子
//!   （架构层串口写、flanterm 终端已各自持锁整串写入）。若在此再加一把
//!   简单自旋锁，中断上下文重入时会自旋等自己而死锁。多 sink 之间只
//!   要求"各自完整"，相互顺序不作强保证。
//! - 注册只发生在初始化早期，之后只有读操作，无并发写竞争。
//! - [`Console`] trait 允许各设备按接口实现；对简单的 `fn(&str)` 输出端
//!   保留 [`register`] 便捷注册（内部包装为 [`FnConsole`]）。

use core::fmt;
use core::sync::atomic::{AtomicUsize, Ordering};

extern crate alloc;

use alloc::string::String;

/// 控制台输出接口：每种输出设备（串口、framebuffer 终端…）实现一份。
pub trait Console {
    /// 设备名（调试/统计用）。
    fn name(&self) -> &'static str;

    /// 输出整串文本（含 `\n`，`\r\n` 转换由实现自行处理）。
    fn write_str(&self, s: &str);

    /// 输出单个原始字节。
    ///
    /// 契约（term1 T5 成文）：本接口仅承载**单字节自足**的文本——ASCII
    /// 字符或调用方明确意图发送的控制字节。多字节 UTF-8 字符不得按字节
    /// 逐个喂入：单字节视角下续字节是非法序列，将按 U+FFFD 如实转换
    /// （宁可替换标记，不伪造完整字符）。多字节内容一律走
    /// [`Console::write_str`] / [`Console::write_bytes`] 整段路径。
    fn write_byte(&self, b: u8) {
        let s = core::str::from_utf8(core::slice::from_ref(&b)).unwrap_or("\u{FFFD}");
        self.write_str(s);
    }

    /// 输出**原始字节流**（K5 完全体）。
    ///
    /// 字节透明设备（串口）覆写本方法原样发出，用户输出数据零销毁；
    /// 纯文本设备（framebuffer 终端）保持缺省实现——整段按 UTF-8 lossy
    /// 转换后走 [`Console::write_str`]，这是文本介质的固有约束而非数据
    /// 销毁决策。stdout 字节路径经此方法下发。
    fn write_bytes(&self, bytes: &[u8]) {
        let s = String::from_utf8_lossy(bytes);
        self.write_str(&s);
    }

    /// 冲刷（对带缓冲设备有用；默认空操作）。
    fn flush(&self) {}
}

/// 兼容旧 API：把 `fn(&str)` 输出端包装为 [`Console`]。
#[derive(Clone, Copy)]
pub struct FnConsole(pub fn(&str));

impl Console for FnConsole {
    fn name(&self) -> &'static str {
        "fn-sink"
    }
    fn write_str(&self, s: &str) {
        (self.0)(s)
    }
}

/// 旧的输出函数指针类型（兼容别名）。
pub type SinkFn = fn(&str);

/// sink 表容量上限（串口 + 屏幕 + 未来扩展，8 个足够）。
pub const MAX_SINKS: usize = 8;

/// 单个 sink 槽：`&'static dyn Console` 拆为 data + vtable 两个原子字。
/// `data == 0` 表示空槽。
struct SinkSlot {
    data: AtomicUsize,
    vtable: AtomicUsize,
}

const EMPTY_SLOT: SinkSlot = SinkSlot {
    data: AtomicUsize::new(0),
    vtable: AtomicUsize::new(0),
};

/// 已注册的 sink 表。
static SINKS: [SinkSlot; MAX_SINKS] = [EMPTY_SLOT; MAX_SINKS];

/// 已注册 sink 数量。
static SINK_COUNT: AtomicUsize = AtomicUsize::new(0);

/// `register(fn(&str))` 使用的静态包装池（初始化早期写入，之后只读）。
struct FnPool {
    slots: [core::cell::UnsafeCell<FnConsole>; MAX_SINKS],
}
unsafe impl Sync for FnPool {}

fn noop_sink(_: &str) {}

static FN_POOL: FnPool = FnPool {
    slots: [const { core::cell::UnsafeCell::new(FnConsole(noop_sink)) }; MAX_SINKS],
};

/// 注册一个 [`Console`] 输出端。表满时返回 `false` 且不注册。
///
/// 应在内核初始化早期调用（如架构串口就绪后、framebuffer 终端初始化后）。
pub fn register_console(c: &'static dyn Console) -> bool {
    let idx = SINK_COUNT.fetch_add(1, Ordering::SeqCst);
    if idx >= MAX_SINKS {
        // 表满，回滚计数
        SINK_COUNT.fetch_sub(1, Ordering::SeqCst);
        return false;
    }
    let (data, vtable) = unsafe { core::mem::transmute::<&'static dyn Console, (usize, usize)>(c) };
    SINKS[idx].data.store(data, Ordering::SeqCst);
    SINKS[idx].vtable.store(vtable, Ordering::SeqCst);
    true
}

/// 注册一个 `fn(&str)` 输出端（兼容便捷版，内部包装为 [`FnConsole`]）。
pub fn register(f: SinkFn) -> bool {
    let idx = SINK_COUNT.fetch_add(1, Ordering::SeqCst);
    if idx >= MAX_SINKS {
        SINK_COUNT.fetch_sub(1, Ordering::SeqCst);
        return false;
    }
    unsafe { *FN_POOL.slots[idx].get() = FnConsole(f) };
    let c: &'static dyn Console = unsafe {
        // 池槽在注册后不再被写入，可安全提升为 'static。
        &*(&FN_POOL.slots[idx] as *const core::cell::UnsafeCell<FnConsole>).cast::<FnConsole>()
    };
    let (data, vtable) = unsafe { core::mem::transmute::<&'static dyn Console, (usize, usize)>(c) };
    SINKS[idx].data.store(data, Ordering::SeqCst);
    SINKS[idx].vtable.store(vtable, Ordering::SeqCst);
    true
}

/// 当前已注册的 sink 数量（调试/统计用）。
pub fn sink_count() -> usize {
    SINK_COUNT.load(Ordering::Acquire)
}

/// 把整串文本输出到所有已注册 sink。
///
/// 遍历时若某 sink 尚未注册则跳过。每个 sink 内部须原子（自行持锁），
/// 本函数只做转发，不跨 sink 持锁。
pub fn write_str(s: &str) {
    let n = SINK_COUNT.load(Ordering::Acquire);
    for i in 0..n {
        let data = SINKS[i].data.load(Ordering::Acquire);
        if data != 0 {
            let vtable = SINKS[i].vtable.load(Ordering::Acquire);
            // 仅初始化期写入了真实指针，此处读取安全。
            let c: &'static dyn Console = unsafe {
                core::mem::transmute::<(usize, usize), &'static dyn Console>((data, vtable))
            };
            c.write_str(s);
        }
    }
}

/// 把**原始字节流**输出到所有已注册 sink（K5 完全体：stdout 字节路径）。
///
/// 字节透明 sink（串口）原样发出；文本 sink 经各自 lossy 缺省转换。
/// 转发纪律与 [`write_str`] 一致：只转发、不跨 sink 持锁。
pub fn write_bytes(bytes: &[u8]) {
    let n = SINK_COUNT.load(Ordering::Acquire);
    for i in 0..n {
        let data = SINKS[i].data.load(Ordering::Acquire);
        if data != 0 {
            let vtable = SINKS[i].vtable.load(Ordering::Acquire);
            let c: &'static dyn Console = unsafe {
                core::mem::transmute::<(usize, usize), &'static dyn Console>((data, vtable))
            };
            c.write_bytes(bytes);
        }
    }
}

/// 把 `fmt::Arguments` 格式化后输出到所有 sink。
///
/// 用栈缓冲承载格式化结果（`no_std` 友好），超长内容**显式截断**：
/// 追加 `...[truncated]` 标记并使 [`truncation_count`] 计数（KM1/KM3
/// 溢出治理——静默蒸发不可接受）。结果经 [`write_bytes`] 原始字节路径
/// 下发：即使历史遗留的切点落在多字节字符内部，串口也按字节透明转发，
/// 绝不因 UTF-8 校验失败而丢弃整段输出。
pub fn write_fmt(args: fmt::Arguments) {
    let mut buf = [0u8; FMT_CAP];
    let mut w = StackWriter {
        buf: &mut buf,
        len: 0,
        truncated: false,
    };
    let _ = fmt::Write::write_fmt(&mut w, args);
    let (raw_len, truncated) = (w.len, w.truncated);
    drop(w); // 结束对 buf 的可变借用，收尾需要重借
    let len = truncate_finish(&mut buf, raw_len, truncated, 0);
    write_bytes(&buf[..len]);
}

/// `write_fmt` 的栈缓冲容量。
///
/// 默认值理由（S17）：1024 B 覆盖现有全部 stdout 单次写调用且栈开销
/// 可忽略；stdout 是用户数据通路，容量不足属调用方契约问题而非本层
/// 截断对象——超限仍会标记截断（见 [`truncation_count`]）。
pub const FMT_CAP: usize = 1024;

/// 截断标记（ASCII，保证标记自身永不落入多字节切点）。
pub(crate) const TRUNCATION_MARKER: &[u8] = b" ...[truncated]";

/// 输出管线截断总次数（log 行与 `write_fmt` 两条路径共用）。
static CONSOLE_TRUNCATIONS: AtomicUsize = AtomicUsize::new(0);

/// 已发生的输出截断总次数（诊断观测口：非零即有日志/输出曾被裁剪）。
pub fn truncation_count() -> usize {
    CONSOLE_TRUNCATIONS.load(Ordering::Relaxed)
}

/// 截断收尾（溢出治理的单点实现，[`write_fmt`] 与 `log::__log` 共用）。
///
/// 未截断时原样返回 `len`。发生截断时：
/// 1. 截断计数 +1（可见性纪律：静默丢弃即伪交付）；
/// 2. 长度回退到 UTF-8 字符边界（`buf[len]` 不是续字节为止，至多退 3 字节）；
/// 3. 追加 [`TRUNCATION_MARKER`]（`reserve` 为调用方要求保留的尾部空间，
///    如 log 行的换行符）。
pub(crate) fn truncate_finish(
    buf: &mut [u8],
    len: usize,
    truncated: bool,
    reserve: usize,
) -> usize {
    if !truncated && len <= buf.len().saturating_sub(reserve) {
        // 未截断且内容给收尾预留字节（reserve，如行尾换行符）留出了空间：
        // 原样返回，容量完全够用。
        return len;
    }
    CONSOLE_TRUNCATIONS.fetch_add(1, Ordering::Relaxed);
    debug_assert!(
        buf.len() >= reserve + TRUNCATION_MARKER.len(),
        "buffer too small for truncation marker"
    );
    let cap = buf.len().saturating_sub(reserve + TRUNCATION_MARKER.len());
    let mut n = len.min(cap);
    while n > 0 && buf[n] & 0xC0 == 0x80 {
        // 切点落在多字节字符内部：回退直到 buf[n] 是某字符的首字节。
        n -= 1;
    }
    buf[n..n + TRUNCATION_MARKER.len()].copy_from_slice(TRUNCATION_MARKER);
    n + TRUNCATION_MARKER.len()
}

/// 栈缓冲 `fmt::Write` 实现，供 [`write_fmt`] 与 `log` 使用。
///
/// 缓冲写满后继续写入只更新 [`StackWriter::truncated`] 标志而不 panic/
/// 报错——格式化结果的完整性由调用方经 [`truncate_finish`] 收尾声明，
/// 本类型只负责如实记录「发生过裁剪」这一事实。
pub struct StackWriter<'a> {
    pub buf: &'a mut [u8],
    pub len: usize,
    /// 是否有内容因缓冲不足被裁剪（KM1：截断必须可见）。
    pub truncated: bool,
}

impl fmt::Write for StackWriter<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let room = self.buf.len() - self.len;
        let n = core::cmp::min(s.len(), room);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        if n < s.len() {
            self.truncated = true;
        }
        Ok(())
    }
}
