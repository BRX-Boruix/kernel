//! 串口日志与格式化输出（兼容层）。
//!
//! 早期本模块是"注入单个输出函数"的间接层；现在统一输出由
//! [`crate::console`] 承担（可注册串口 + framebuffer 终端等多个 sink）。
//! 本模块保留同名 API（`set_output`/`write_str`/`print`/`log!` 等）作为
//! 兼容转发，所有输出最终汇聚到统一 console。

use core::fmt;

/// 输出函数类型（兼容旧名，实际为 [`crate::console::SinkFn`]）。
pub type OutputFn = crate::console::SinkFn;

/// 注册一个输出端（兼容旧名）。
///
/// 语义由"单次注入"变为"注册到统一 console"，可多次调用注册多个输出端
/// （例如先注册串口，再注册 framebuffer 终端）。表满时静默忽略。
pub fn set_output(f: OutputFn) {
    let _ = crate::console::register(f);
}

/// 写字符串到统一 console（`\n` 的 `\r\n` 转换由各 sink 自行处理）。
pub fn write_str(s: &str) {
    crate::console::write_str(s);
}

/// 格式化写入统一 console（Rust `format_args!` 风格）。
pub fn print(args: fmt::Arguments) {
    use fmt::Write as _;
    let mut w = SerialWriter;
    let _ = w.write_fmt(args);
}

struct SerialWriter;

impl fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write_str(s);
        Ok(())
    }
}

/// 以十六进制写 `value`（不含 0x 前缀，固定 16 位宽度）。
pub fn write_hex_raw(value: u64) {
    write_str(core::str::from_utf8(&crate::format::hex_bytes(value)).unwrap());
}

/// 以十进制写 `value`（无前导零，`0` 输出单个 `0`）。
pub fn write_dec(value: u128) {
    let (buf, len) = crate::format::dec_bytes(value);
    write_str(core::str::from_utf8(&buf[..len]).unwrap());
}

/// 以十六进制写 `value`，带 `0x` 前缀，固定 16 位宽度。
pub fn write_hex(value: u64) {
    write_str("0x");
    write_hex_raw(value);
}

/// 串口日志宏（Rust `format_args!` 风格，输出到统一 console）。
#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {
        $crate::serial::print(format_args!($($arg)*))
    };
}

/// 串口日志宏（自动换行，输出到统一 console）。
#[macro_export]
macro_rules! logln {
    () => { $crate::serial::print(format_args!("\n")) };
    ($($arg:tt)*) => {
        $crate::serial::print(format_args!("{}\n", format_args!($($arg)*)))
    };
}

/// 以十六进制打印 `$expr`（带换行，输出到统一 console）。
#[macro_export]
macro_rules! log_hex {
    ($prefix:expr, $value:expr) => {
        $crate::serial::write_str($prefix);
        $crate::serial::write_hex($value as u64);
        $crate::serial::write_str("\r\n");
    };
}

/// 以十进制打印 `$expr`（带换行，输出到统一 console）。
#[macro_export]
macro_rules! log_dec {
    ($prefix:expr, $value:expr) => {
        $crate::serial::write_str($prefix);
        $crate::serial::write_dec($value as u128);
        $crate::serial::write_str("\r\n");
    };
}
