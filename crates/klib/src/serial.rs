//! 串口日志与格式化输出。
//!
//! 底层的字节 I/O 通过一个可注入的输出函数完成，由入口 crate 在初始化时
//! 绑定到具体架构的实现，从而保持本模块架构无关。

use core::fmt;
use core::sync::atomic::{AtomicUsize, Ordering};

/// 全局输出函数指针（由入口 crate 注入，绑定具体架构的串口写）。
/// 接收整个字符串（含 \n，由架构层负责 \r\n 转换），一次调用完成整串输出，
/// 从而在架构层持锁整串原子写入，避免多核交错。
type OutputFn = fn(&str);
static OUTPUT: AtomicUsize = AtomicUsize::new(0);

/// 默认空输出（未注入前不输出任何内容）
fn no_output(_s: &str) {}

/// 绑定串口输出函数（应在内核早期初始化时调用）
pub fn set_output(f: OutputFn) {
    OUTPUT.store(f as usize, Ordering::SeqCst);
}

fn output() -> OutputFn {
    let v = OUTPUT.load(Ordering::SeqCst);
    if v == 0 {
        no_output
    } else {
        unsafe { core::mem::transmute::<usize, OutputFn>(v) }
    }
}

/// 写字符串到串口（\n 自动转 \r\n）。整串一次调用，原子输出。
pub fn write_str(s: &str) {
    output()(s);
}

/// 格式化写入串口
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

/// 以十六进制写 `value`（不含 0x 前缀，固定宽度，由调用方决定）。
fn write_hex_raw(value: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 16];
    for i in 0..16 {
        let shift = (15 - i) * 4;
        buf[i] = HEX[((value >> shift) & 0xF) as usize];
    }
    write_str(core::str::from_utf8(&buf).unwrap());
}

/// 以十进制写 `value` 到串口（无前导零，`0` 输出单个 `0`）。
pub fn write_dec(value: u128) {
    let mut buf = [0u8; 40];
    let mut n = 0;
    let mut v = value;
    if v == 0 {
        buf[n] = b'0';
        n += 1;
    }
    while v > 0 {
        buf[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    // 逆序后整串输出
    let mut out = [0u8; 40];
    let mut o = 0;
    while n > 0 {
        n -= 1;
        out[o] = buf[n];
        o += 1;
    }
    write_str(core::str::from_utf8(&out[..o]).unwrap());
}

/// 以十六进制写 `value` 到串口，带 `0x` 前缀，固定 16 位宽度。
pub fn write_hex(value: u64) {
    write_str("0x");
    write_hex_raw(value);
}

/// 串口日志宏
#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {
        $crate::serial::print(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! logln {
    () => { $crate::serial::print(format_args!("\n")) };
    ($($arg:tt)*) => {
        $crate::serial::print(format_args!("{}\n", format_args!($($arg)*)))
    };
}

/// 以十六进制打印 `$expr` 到串口（带换行）。
#[macro_export]
macro_rules! log_hex {
    ($prefix:expr, $value:expr) => {
        $crate::serial::write_str($prefix);
        $crate::serial::write_hex($value as u64);
        $crate::serial::write_str("\r\n");
    };
}

/// 以十进制打印 `$expr` 到串口（带换行）。
#[macro_export]
macro_rules! log_dec {
    ($prefix:expr, $value:expr) => {
        $crate::serial::write_str($prefix);
        $crate::serial::write_dec($value as u128);
        $crate::serial::write_str("\r\n");
    };
}
