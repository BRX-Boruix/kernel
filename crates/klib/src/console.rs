//! 统一控制台输出层。
//!
//! 内核所有日志输出（串口、framebuffer 终端等）最终汇聚到这里。
//! 各架构/设备在初始化早期把各自的 `fn(&str)` 输出端注册为 sink，
//! 之后每次写操作把整串文本转发给所有已注册 sink。
//!
//! 设计约束：
//! - `no_std`、无堆分配：sink 表用静态定长数组存储。
//! - **不引入额外全局锁**：每个 sink 必须自行保证 `fn(&str)` 内部原子
//!   （架构层串口写、flanterm 终端已各自持锁整串写入）。若在此再加一把
//!   简单自旋锁，中断上下文重入时会自旋等自己而死锁。多 sink 之间只
//!   要求"各自完整"，相互顺序不作强保证。
//! - 注册只发生在初始化早期，之后只有读操作，无并发写竞争。

use core::fmt;
use core::sync::atomic::{AtomicUsize, Ordering};

/// 输出 sink：接收整串文本（含 `\n`，`\r\n` 转换由 sink 自行处理）。
pub type SinkFn = fn(&str);

/// sink 表容量上限（串口 + 屏幕 + 未来扩展，8 个足够）。
pub const MAX_SINKS: usize = 8;

/// 已注册的 sink（存裸函数指针，0 表示空槽）。
static SINKS: [AtomicUsize; MAX_SINKS] = [const { AtomicUsize::new(0) }; MAX_SINKS];

/// 已注册 sink 数量。
static SINK_COUNT: AtomicUsize = AtomicUsize::new(0);

/// 注册一个输出 sink。表满时返回 `false` 且不注册。
///
/// 应在内核初始化早期调用（如架构串口就绪后、framebuffer 终端初始化后）。
pub fn register(f: SinkFn) -> bool {
    let idx = SINK_COUNT.fetch_add(1, Ordering::SeqCst);
    if idx >= MAX_SINKS {
        // 表满，回滚计数
        SINK_COUNT.fetch_sub(1, Ordering::SeqCst);
        return false;
    }
    SINKS[idx].store(f as usize, Ordering::SeqCst);
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
        let v = SINKS[i].load(Ordering::Acquire);
        if v != 0 {
            // 仅初始化期写入了真实函数指针，此处读取安全。
            unsafe { core::mem::transmute::<usize, SinkFn>(v)(s) };
        }
    }
}

/// 把 `fmt::Arguments` 格式化后输出到所有 sink。
///
/// 用栈缓冲承载格式化结果（`no_std` 友好），超长内容截断。
/// 日志级别宏（`info!`/`warn!`/`error!`/`debug!`）与 `format_args!`
/// 调用方都经此转发。
pub fn write_fmt(args: fmt::Arguments) {
    let mut buf = [0u8; 1024];
    let mut w = StackWriter { buf: &mut buf, len: 0 };
    let _ = fmt::Write::write_fmt(&mut w, args);
    let len = w.len;
    write_str(core::str::from_utf8(&buf[..len]).unwrap_or(""));
}

/// 栈缓冲 `fmt::Write` 实现，供 [`write_fmt`] 使用。
struct StackWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl fmt::Write for StackWriter<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let n = core::cmp::min(s.len(), self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}
