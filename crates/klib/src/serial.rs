//! 串口日志与格式化输出。
//!
//! 底层的字节 I/O 通过一个可注入的输出函数完成，由入口 crate 在初始化时
//! 绑定到具体架构的实现，从而保持本模块架构无关。

use core::fmt;
use core::sync::atomic::{AtomicUsize, Ordering};

/// 全局输出函数指针（由入口 crate 注入，绑定具体架构的串口写）
type OutputFn = fn(u8);
static OUTPUT: AtomicUsize = AtomicUsize::new(0);

/// 默认空输出（未注入前不输出任何内容）
fn no_output(_b: u8) {}

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

/// 写字符串到串口（\n 自动转 \r\n）
pub fn write_str(s: &str) {
    let out = output();
    for &b in s.as_bytes() {
        if b == b'\n' {
            out(b'\r');
        }
        out(b);
    }
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
