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
/// 每条日志最大字节数（超长**显式截断**：追加 `...[truncated]` 标记，
/// 经 [`crate::console::truncation_count`] 可观测——KM3：静默截断即伪交付）。
///
/// 默认值理由（S17）：512 B 为审查实测下游需求所定——mm/pci/vfs_init 的
/// 遥测 JSON 行、ata_pio 寄存器 dump 行普遍接近或超过旧值 256；环形缓冲
/// 静态代价 64×512B=32KiB `.bss`，对自检环境（-m 128M）与真实平台均可忽略。
pub const LINE_CAP: usize = 512;

/// 环形日志缓冲：中断安全锁保护（多核 + 中断上下文安全）。
/// 行以 `[u8; LINE_CAP]` 存储，`\0` 结尾（多余部分为零填充）。
static LOG_RING: IrqSpinLock<RingBuffer<[u8; LINE_CAP], RING_LINES>> =
    IrqSpinLock::new(RingBuffer::new());

/// 所有级别宏的统一入口。
///
/// 1. 无论是否达到输出阈值，先把格式化结果记录进环形缓冲（崩溃回读需要）；
/// 2. 达到阈值才转发到统一 console。
pub fn __log(level: LogLevel, args: fmt::Arguments) {
    // 格式化进栈缓冲；超长时由 truncate_finish 回退到字符边界并追加
    // 截断标记（KM1/KM3：截断必须可见、可观测，且绝不产生非法 UTF-8）。
    let mut buf = [0u8; LINE_CAP];
    let mut w = crate::console::StackWriter {
        buf: &mut buf,
        len: 0,
        truncated: false,
    };
    let _ = fmt::Write::write_fmt(&mut w, args);
    let (raw_len, truncated) = (w.len, w.truncated);
    drop(w); // 结束对 buf 的可变借用，收尾需要重借
    // 为行尾换行符保留 1 字节（reserve=1）。
    let n = crate::console::truncate_finish(&mut buf, raw_len, truncated, 1);
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
        // 避免二次格式化（T2 回归教训）。经原始字节路径下发——收尾已保证
        // 字符边界完整，文本 sink 的 lossy 转换走零分配 Borrowed 分支；
        // 此前 from_utf8().unwrap_or("") 在切点落进多字节字符时会整行蒸发。
        crate::console::write_bytes(&buf[..=n]);
    }
}

/// 按从旧到新的顺序**流式回放**环形日志缓冲（读后清空）。
///
/// 用于 panic/崩溃时打印最后 N 条日志。输出到统一 console。
/// KA2 修复：此前把全部行先聚合进 `LINE_CAP*4`（1KB）栈缓冲再一次性输出，
/// 只能装下最旧的 ~4 行——恰好丢掉被 panic 打断前最后发生、诊断价值最高
/// 的日志。现改为逐行弹出、逐行直写：不设聚合缓冲，行数再多也完整回放，
/// 时序天然保持从旧到新；每行字节在入环时已保证字符边界完整，经
/// [`crate::console::write_bytes`] 下发无校验丢失面。
/// 锁语义：环形缓冲被其它上下文持有时**跳过回读**而非自旋——panic 路径可能
/// 正是那个持锁者中断路径的受害者，自旋等自己 = 永久死锁（kernel1.md KA1）。
/// 代价是崩溃现场缺一段日志，可接受；主诊断（panic 消息 + 回溯）不经过此锁。
pub fn dump_crash_log() {
    let Some(ring) = LOG_RING.try_lock() else {
        crate::console::write_str("[crashlog] ring buffer lock held; skipping dump\n");
        return;
    };
    while let Some(line) = ring.pop() {
        let n = line.iter().position(|&b| b == 0).unwrap_or(line.len());
        crate::console::write_bytes(&line[..n]);
    }
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

    // ---- KM1/KM3/KA2：溢出治理与崩溃回读的回归面 ----

    /// console 捕获 sink：把全部输出字节收进进程内缓冲，供断言。
    static CAPTURE: Mutex<Vec<u8>> = Mutex::new(Vec::new());
    fn capture_sink(s: &str) {
        CAPTURE.lock().unwrap().extend_from_slice(s.as_bytes());
    }
    /// 注册捕获 sink（幂等；注册后全程驻留——console 无注销 API，
    /// 其余测试只清空 CAPTURE 不受残留影响）。
    fn ensure_capture_sink() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let registered: fn(&str) = capture_sink;
            assert!(crate::console::register(registered), "capture sink slot");
        });
    }

    #[test]
    fn truncation_carries_marker_and_counts() {
        let _g = TEST_LOCK.lock().unwrap();
        ensure_capture_sink();
        CAPTURE.lock().unwrap().clear();
        LOG_RING.lock().clear();
        set_level(LogLevel::Info); // 让 console 路径同步走一遍
        let before = crate::console::truncation_count();
        let long = "x".repeat(LINE_CAP * 2);
        __log(LogLevel::Info, format_args!("{long}"));
        // 截断计数恰好 +1（KM3 可观测性）
        assert_eq!(crate::console::truncation_count(), before + 1);
        // 环形缓冲内的行带标记、不超容量、以换行结尾
        let lines = drain_lines();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].ends_with(" ...[truncated]\n"), "got tail {:?}", &lines[0][lines[0].len() - 24..]);
        assert!(lines[0].len() <= LINE_CAP);
    }

    #[test]
    fn truncation_cut_lands_on_char_boundary() {
        let _g = TEST_LOCK.lock().unwrap();
        LOG_RING.lock().clear();
        // 多字节字符铺满超限：旧实现在任意字节位截断，切进字符内部时
        // console 路径整行蒸发；新实现必须回退到边界再打标记。
        let long = "你".repeat(LINE_CAP);
        __log(LogLevel::Info, format_args!("{long}"));
        let lines = drain_lines();
        assert_eq!(lines.len(), 1);
        let body = lines[0].strip_suffix('\n').unwrap();
        let prefix = body.strip_suffix(" ...[truncated]").expect("marker present");
        // 标记之前的前缀必须是合法 UTF-8（无半个字符的残骸）
        assert!(core::str::from_utf8(prefix.as_bytes()).is_ok());
    }

    #[test]
    fn dump_replays_every_line_oldest_to_newest() {
        let _g = TEST_LOCK.lock().unwrap();
        ensure_capture_sink();
        set_level(LogLevel::Off); // 输出全关：capture 里只应有 dump 回放内容
        LOG_RING.lock().clear();
        CAPTURE.lock().unwrap().clear();
        for i in 0..RING_LINES {
            __log(LogLevel::Debug, format_args!("crash-line-{:03}", i));
        }
        assert_eq!(LOG_RING.lock().len(), RING_LINES);
        dump_crash_log();
        let text = String::from_utf8(CAPTURE.lock().unwrap().clone()).unwrap();
        // KA2 核心：全部 N 行完整回放（不再被聚合缓冲裁掉最新现场），
        // 且时序从旧到新。
        for i in 0..RING_LINES {
            assert!(
                text.contains(&format!("crash-line-{i:03}")),
                "line {i} missing from replay"
            );
        }
        let first = text.find("crash-line-000").unwrap();
        let last = text.find("crash-line-063").unwrap();
        assert!(first < last, "replay must be oldest-to-newest");
        // 读后清空语义保持
        assert!(LOG_RING.lock().is_empty());
        set_level(LogLevel::Info);
    }

    #[test]
    fn within_cap_line_never_marked_or_counted() {
        let _g = TEST_LOCK.lock().unwrap();
        LOG_RING.lock().clear();
        let before = crate::console::truncation_count();
        let ok = "y".repeat(LINE_CAP - 32);
        __log(LogLevel::Info, format_args!("{ok}"));
        let lines = drain_lines();
        assert_eq!(lines.len(), 1);
        assert!(!lines[0].contains("[truncated]"));
        assert_eq!(crate::console::truncation_count(), before, "no spurious count");
    }
}
