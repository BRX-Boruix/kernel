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
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use crate::sync::spin::SpinMutex;

// S04：sink 表把 `&'static dyn Console` 胖指针拆成 (data, vtable) 两个 usize
// 原子槽，依赖 dyn trait 对象 = data+vtable 且各占一个 usize 的 ABI 内部结构。
// Rust 未官方保证，此处编译期断言固化：若目标移植到非此布局的 ABI，编译失败
// 而非运行期悬垂 vtable。
const _: () = {
    assert!(core::mem::size_of::<&'static dyn Console>() == 2 * core::mem::size_of::<usize>());
};

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
    // S21 发布协议：**先写 vtable（Release），再写 data（Release）**。
    // `data != 0` 是"发布完成"标志——读者（write_str）Acquire 读到 data != 0
    // 时，vtable 必已发布可见，杜绝 `(data≠0, vtable==0)` 半发布组合导致的
    // transmute 悬垂 vtable 崩溃。旧实现先写 data 后写 vtable，并发下可读到
    // 半发布状态。
    SINKS[idx].vtable.store(vtable, Ordering::Release);
    SINKS[idx].data.store(data, Ordering::Release);
    true
}
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
    // S21 发布协议：同 register_console——先 vtable（Release）后 data（Release）。
    SINKS[idx].vtable.store(vtable, Ordering::Release);
    SINKS[idx].data.store(data, Ordering::Release);
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

/// stdout **行缓冲**写入：攒到换行（或缓冲将满）才整体提交给所有 sink。
///
/// # 为什么需要（实测缺陷）
///
/// 用户程序普遍按"片段"写 stdout：`say(b"[x] msg")` 之后单独
/// `write(b"\n")`，甚至一行拆成文本/数字/换行三段。`write_bytes` 的原子性
/// 边界是**单次调用**而非"一行"——多核下另一核的输出恰好插在两段之间，
/// 产生 `boruix$ l[audiod] mixed …` 与"横幅被切成碎片"（实测）。
///
/// 行缓冲把原子性边界升到**行**：持锁累积，遇 `\n` 或缓冲将满才一次性下发。
/// 临界区只是一次 memcpy 或一次整行转发，串口写在内层自有串口锁，无自旋等外设。
///
/// # 契约
///
/// - 仅用于**进程 stdout**（syscall 路径）；内核日志不经此路径（它有自己的
///   行组装，且中断上下文不允许持有可能自旋的行锁）。
/// - 缓冲将满且仍无换行时立即整段下发：超长无换行输出（二进制数据）退化为
///   逐块，行完整性对它本就无意义；不静默丢弃，也不无限等待。
/// 每 CPU 行缓冲的 CPU 序号来源（内核启动早期注入一次；klib 不依赖 arch，
/// 与 `set_stdout_sink` 同一解耦模式）。
///
/// klib 无 `spin::Once` 依赖，手写一次性槽位：`SET` 保证只接受第一次注入，
/// 其后写入被丢弃（注入点是启动早期单核路径，无竞争窗口）。
static CPU_HINT_FN: AtomicUsize = AtomicUsize::new(0);
static CPU_HINT_SET: AtomicBool = AtomicBool::new(false);

/// 注入当前 CPU 序号函数（内核启动路径调用一次，重复注入被忽略）。
pub fn set_line_cpu_hint(f: fn() -> usize) {
    if !CPU_HINT_SET.swap(true, Ordering::AcqRel) {
        CPU_HINT_FN.store(f as usize, Ordering::Release);
    }
}

#[inline]
fn line_cpu_hint() -> Option<fn() -> usize> {
    if !CPU_HINT_SET.load(Ordering::Acquire) {
        return None;
    }
    let addr = CPU_HINT_FN.load(Ordering::Acquire);
    if addr == 0 {
        return None;
    }
    // SAFETY: 地址只由 `set_line_cpu_hint` 从真实 `fn() -> usize` 写入，
    // 类型与签名在注入点受编译器检查，此处还原是安全的。
    Some(unsafe { core::mem::transmute::<usize, fn() -> usize>(addr) })
}

pub fn write_line_buffered(bytes: &[u8]) {
    // 每 CPU 一份行缓冲（不是全局一份！）：
    //
    // 全局单缓冲 + 全局锁会让**不同进程**的片段在同一行里物理拼接——init
    // 的 "[init] volumed started (pid " 与 volumed 的 "[volumed] " 恰好
    // 在两次 write() 之间同入一个缓冲，实测拼出 "(pid 77[volumed] )"。
    // 行缓冲的正确语义是"**同一输出流**内片段重组"，而 stdout 流的边界
    // 就是 CPU（任务在让出前恒在单核上跑；同核抢占插行是下一层问题，
    // 属于分流的范围）。
    //
    // SAFETY: LINE_BUFS/LINE_LENS 仅被本 CPU 索引访问；中断上下文不会调用
    // 本函数（内核日志走 write_bytes），故不存在"中断打断半行再写入"的自锁。
    static LINE_BUFS: [SpinMutex<LineBufInner>; 64] = {
        #[allow(clippy::declare_interior_mutable_const)]
        const EMPTY: SpinMutex<LineBufInner> = SpinMutex::new(LineBufInner {
            data: [0; LINE_BUF_CAP],
            len: 0,
        });
        [EMPTY; 64]
    };
    let idx = match line_cpu_hint() {
        // 注入的 cpu 序号函数（内核启动早期接线，arch 槽位号恒 < 64）。
        Some(f) => {
            let n = f() as usize;
            if n < 64 { n } else { 0 }
        }
        // 未接线（极早启动期）：退化为 0 号缓冲。此时只有 BSP 在跑，
        // 不存在多核拼行问题。
        None => 0,
    };
    let mut line = LINE_BUFS[idx].lock();
    let mut consumed = 0usize;
    while consumed < bytes.len() {
        let chunk = &bytes[consumed..];
        match chunk.iter().position(|&b| b == b'\n') {
            Some(i) => {
                // 有换行：连同换行符一起提交，行边界清晰。极端超长单行先冲刷
                // 已有内容，仍超行容量则整段直发（不截断、不拆行）。
                let take = i + 1;
                if line.len + take > LINE_BUF_CAP {
                    flush_line_buf(&mut line);
                }
                if take <= LINE_BUF_CAP {
                    let start = line.len;
                    line.data[start..start + take].copy_from_slice(&chunk[..take]);
                    line.len = start + take;
                    flush_line_buf(&mut line);
                } else {
                    flush_line_buf(&mut line);
                    write_bytes(&chunk[..take]);
                }
                consumed += take;
            }
            None => {
                // 无换行：能塞多少塞多少；塞不下先冲刷腾地方。
                let free = LINE_BUF_CAP - line.len;
                if free == 0 {
                    flush_line_buf(&mut line);
                    continue;
                }
                let take = core::cmp::min(chunk.len(), free);
                let start = line.len;
                line.data[start..start + take].copy_from_slice(&chunk[..take]);
                line.len = start + take;
                consumed += take;
                if line.len == LINE_BUF_CAP {
                    flush_line_buf(&mut line);
                }
            }
        }
    }
}

/// 冲刷行缓冲（仅在持有 LINE 锁时调用）。
fn flush_line_buf(line: &mut LineBufInner) {
    if line.len > 0 {
        write_bytes(&line.data[..line.len]);
        line.len = 0;
    }
}


/// [`write_line_buffered`] 的 `fmt::Write` 适配：供 init 等用户进程日志的
/// 多段格式化复用同一行缓冲（`write_fmt` 会把 `{}` 展开成多次 `write_str`，
/// 直接用 `write_bytes` 会回到碎片原子性问题）。
struct LineFmtWriter;

impl core::fmt::Write for LineFmtWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        write_line_buffered(s.as_bytes());
        Ok(())
    }
}

/// 用行缓冲输出格式化参数。
pub fn write_fmt_line_buffered(args: core::fmt::Arguments) {
    let mut w = LineFmtWriter;
    let _ = core::fmt::Write::write_fmt(&mut w, args);
}
/// 行缓冲容量：与 [`FMT_CAP`] 同量级——容纳全部现有单行输出，静态区开销
/// 可忽略。超长无换行输出按块冲刷（见 [`write_line_buffered`]）。
const LINE_BUF_CAP: usize = 1024;

/// [`LineBuf`] 的去封装视图，供 [`flush_line_buf`] 以函数形式复用。
struct LineBufInner {
    data: [u8; LINE_BUF_CAP],
    len: usize,
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
