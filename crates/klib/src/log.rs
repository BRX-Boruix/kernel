//! 内核日志级别宏 + 级别过滤 + 环形日志缓冲。
//!
//! 组成：
//! - 级别宏 `debug!`/`info!`/`warn!`/`error!`：统一经 [`__log`] 处理，
//!   调用点零改动即可获得级别过滤与崩溃回读能力；
//! - [`set_level`] 全局级别开关：低于当前级别的消息不输出（仍记录进环形缓冲）；
//! - 环形日志缓冲：`IrqSpinLock<RingBuffer>` 保存最后 N 条日志（所有级别），
//!   [`dump_crash_log`] 可回读（panic 时打印崩溃现场）。
//!
//! 级别划分：
//! - [`debug!`]：细节/调试信息（测试输出、寄存器状态等）
//! - [`info!`]：正常流程的关键节点（boot 进度、资源初始化完成等）
//! - [`warn!`]：可恢复的异常（降级、重试、资源不足但已处理）
//! - [`error!`]：错误（功能不可用、路径失败、硬件异常 dump 等）

use core::fmt;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::collections::ring::RingBuffer;
use crate::sync::irq::IrqSpinLock;

/// 日志级别（数字越小越紧急；`Off` 关闭全部输出）。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum LogLevel {
    /// 关闭所有日志输出（环形缓冲仍记录）。
    Off = 0,
    /// 错误。
    Error = 1,
    /// 可恢复的异常。
    Warn = 2,
    /// 正常流程的关键节点（默认级别）。
    Info = 3,
    /// 细节/调试信息。
    Debug = 4,
}

impl LogLevel {
    /// 展示名（`level!` 前缀用）。
    pub const fn as_str(self) -> &'static str {
        match self {
            LogLevel::Off => "OFF",
            LogLevel::Error => "ERR",
            LogLevel::Warn => "WRN",
            LogLevel::Info => "INF",
            LogLevel::Debug => "DBG",
        }
    }
}

/// 当前全局输出级别（默认 `Info`）。
static LEVEL: AtomicU8 = AtomicU8::new(LogLevel::Info as u8);

/// 设置全局输出级别：低于该级别的日志不输出（仍进入环形缓冲）。
pub fn set_level(l: LogLevel) {
    LEVEL.store(l as u8, Ordering::Relaxed);
}

/// 当前全局输出级别。
pub fn level() -> LogLevel {
    let v = LEVEL.load(Ordering::Relaxed);
    if v <= LogLevel::Debug as u8 {
        // SAFETY: 只有合法级别会被存储（[`set_level`] 的输入受 enum 约束）。
        unsafe { core::mem::transmute::<u8, LogLevel>(v) }
    } else {
        LogLevel::Info
    }
}

/// `l` 是否达到输出阈值。
#[inline]
fn enabled(l: LogLevel) -> bool {
    l <= level()
}

/// 环形日志缓冲行数（崩溃回读最后 N 条）。
pub const RING_LINES: usize = 64;
/// 每条日志最大字节数（超长截断）。
pub const LINE_CAP: usize = 256;

/// 环形日志缓冲：中断安全锁保护（多核 + 中断上下文安全）。
/// 行以 `[u8; LINE_CAP]` 存储，`\0` 结尾（多余部分为零填充）。
static LOG_RING: IrqSpinLock<RingBuffer<[u8; LINE_CAP], RING_LINES>> =
    IrqSpinLock::new(RingBuffer::new());

/// 所有级别宏的统一入口。
///
/// 1. 无论是否达到输出阈值，先把格式化结果记录进环形缓冲（崩溃回读需要）；
/// 2. 达到阈值才转发到统一 console。
pub fn __log(level: LogLevel, args: fmt::Arguments) {
    // 格式化进栈缓冲。行总是以 `\n` 结尾（内容过长时截断，
    // 为换行符保留 1 字节）；环形缓冲与 console 输出共用这份数据。
    let mut buf = [0u8; LINE_CAP];
    let mut w = crate::console::StackWriter {
        buf: &mut buf,
        len: 0,
    };
    let _ = fmt::Write::write_fmt(&mut w, args);
    let n = w.len.min(LINE_CAP - 1);
    buf[n] = b'\n';

    {
        let ring = LOG_RING.lock();
        if ring.is_full() {
            let _ = ring.pop(); // 淘汰最旧一条，保留最后 N 条
        }
        let mut line = [0u8; LINE_CAP];
        line[..=n].copy_from_slice(&buf[..=n]);
        let _ = ring.push(line);
    }

    if enabled(level) {
        // 输出到统一 console：复用已格式化的行（`buf[..=n]` 含 `\n`），
        // 避免二次格式化。注意不能直接用 `write_fmt(args)`——那会丢失
        // 行尾换行（T2 回归，串口日志全部挤成一行）。
        let s = core::str::from_utf8(&buf[..=n]).unwrap_or("");
        crate::console::write_str(s);
    }
}

/// 按从旧到新的顺序回读环形日志缓冲（读后清空）。
///
/// 用于 panic/崩溃时打印最后 N 条日志。输出到统一 console。
pub fn dump_crash_log() {
    use core::fmt::Write as _;
    let ring = LOG_RING.lock();
    let mut out = [0u8; LINE_CAP * 4];
    let mut w = crate::console::StackWriter {
        buf: &mut out,
        len: 0,
    };
    while let Some(line) = ring.pop() {
        let n = line.iter().position(|&b| b == 0).unwrap_or(line.len());
        let _ = w.write_str(core::str::from_utf8(&line[..n]).unwrap_or(""));
    }
    let len = w.len; // 先释放对 out 的借用再读取
    crate::console::write_str(core::str::from_utf8(&out[..len]).unwrap_or(""));
}

// ---------- 级别宏 ----------

/// `debug!`：细节/调试信息。
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        $crate::log::__log($crate::log::LogLevel::Debug, format_args!($($arg)*))
    };
}

/// `info!`：正常流程的关键节点。
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        $crate::log::__log($crate::log::LogLevel::Info, format_args!($($arg)*))
    };
}

/// `warn!`：可恢复的异常。
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        $crate::log::__log($crate::log::LogLevel::Warn, format_args!($($arg)*))
    };
}

/// `error!`：错误。
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        $crate::log::__log($crate::log::LogLevel::Error, format_args!($($arg)*))
    };
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;
    use std::format;
    use std::string::{String, ToString};
    use std::sync::Mutex;
    use std::vec::Vec;

    /// 全局测试锁：串行化涉及全局 `LOG_RING`/`LEVEL` 的测试。
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// 读空环形缓冲并返回各行文本。
    fn drain_lines() -> Vec<String> {
        let ring = LOG_RING.lock();
        let mut v = Vec::new();
        while let Some(line) = ring.pop() {
            let n = line.iter().position(|&b| b == 0).unwrap_or(line.len());
            v.push(String::from_utf8_lossy(&line[..n]).to_string());
        }
        v
    }

    #[test]
    fn level_filtering() {
        let _g = TEST_LOCK.lock().unwrap();
        set_level(LogLevel::Warn);
        assert!(!enabled(LogLevel::Info));
        assert!(!enabled(LogLevel::Debug));
        assert!(enabled(LogLevel::Warn));
        assert!(enabled(LogLevel::Error));
        set_level(LogLevel::Off);
        assert!(!enabled(LogLevel::Error));
        set_level(LogLevel::Info);
        assert!(enabled(LogLevel::Info));
    }

    #[test]
    fn ring_records_even_when_filtered() {
        let _g = TEST_LOCK.lock().unwrap();
        set_level(LogLevel::Off); // 输出全部关闭
        LOG_RING.lock().clear();
        __log(LogLevel::Debug, format_args!("hidden debug"));
        __log(LogLevel::Error, format_args!("visible error"));
        // 环形缓冲仍记录全部级别
        let lines = drain_lines();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("hidden debug"));
        assert!(lines[1].contains("visible error"));
        set_level(LogLevel::Info);
    }

    #[test]
    fn ring_evicts_oldest_when_full() {
        let _g = TEST_LOCK.lock().unwrap();
        LOG_RING.lock().clear();
        for i in 0..(RING_LINES + 10) {
            __log(LogLevel::Info, format_args!("line {}", i));
        }
        let lines = drain_lines();
        assert_eq!(lines.len(), RING_LINES);
        // 最旧的一条被淘汰，最后一条保留
        assert!(lines[0].contains(&format!("line {}", 10)));
        assert!(
            lines
                .last()
                .unwrap()
                .contains(&format!("line {}", RING_LINES + 9))
        );
    }

    #[test]
    fn macros_dispatch_to_ring() {
        let _g = TEST_LOCK.lock().unwrap();
        set_level(LogLevel::Debug);
        LOG_RING.lock().clear();
        info!("boot stage {} done", 1);
        warn!("degraded mode");
        error!("device {} failed", 3);
        debug!("detail {}", 0xAB);
        let lines = drain_lines();
        assert_eq!(lines.len(), 4);
        assert!(lines[0].contains("boot stage 1 done"));
        assert!(lines[1].contains("degraded mode"));
        assert!(lines[2].contains("device 3 failed"));
        assert!(lines[3].contains("detail 171"));
    }

    #[test]
    fn long_line_truncated() {
        let _g = TEST_LOCK.lock().unwrap();
        LOG_RING.lock().clear();
        let long = "x".repeat(LINE_CAP * 2);
        __log(LogLevel::Info, format_args!("{long}"));
        let lines = drain_lines();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].len() <= LINE_CAP);
        assert!(lines[0].ends_with('\n'));
    }

    #[test]
    fn dump_does_not_panic() {
        let _g = TEST_LOCK.lock().unwrap();
        set_level(LogLevel::Off);
        LOG_RING.lock().clear();
        __log(LogLevel::Warn, format_args!("pre-crash {}", 42));
        dump_crash_log(); // 只验证不 panic（无 sink 时空转）
        set_level(LogLevel::Info);
    }
}
