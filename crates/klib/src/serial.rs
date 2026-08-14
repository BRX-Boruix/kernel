//! 简单的 COM1 串口输出，用于内核引导日志。

use core::fmt;

const COM1: u16 = 0x3F8;

/// 向串口发送一个字节
fn send(byte: u8) {
    unsafe {
        // 等待发送保持寄存器空（LSR bit 5）
        while inb(COM1 + 5) & 0x20 == 0 {}
        outb(COM1, byte);
    }
}

/// 读取 port（inb）
#[inline]
unsafe fn inb(port: u16) -> u8 {
    let result: u8;
    unsafe {
        core::arch::asm!(
            "in al, dx",
            out("al") result,
            in("dx") port,
            options(nomem, nostack, preserves_flags)
        );
    }
    result
}

/// 写入 port（outb）
#[inline]
unsafe fn outb(port: u16, byte: u8) {
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") byte,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// 初始化 COM1 串口（38400 波特，8N1）
pub fn init() {
    unsafe {
        outb(COM1 + 1, 0x00); // 禁用中断
        outb(COM1 + 3, 0x80); // DLAB 开，设置波特率
        outb(COM1 + 0, 0x03); // 除数低字节 (38400)
        outb(COM1 + 1, 0x00); // 除数高字节
        outb(COM1 + 3, 0x03); // 8 位数据，无校验，1 停止位
        outb(COM1 + 2, 0xC7); // 启用 FIFO，清空
        outb(COM1 + 4, 0x0B); // IRQ 使能，RTS/DSR
    }
}

/// 写字符串到串口（\n 自动转 \r\n）
pub fn write_str(s: &str) {
    for &b in s.as_bytes() {
        if b == b'\n' {
            send(b'\r');
        }
        send(b);
    }
}

/// 格式化写入串口
pub fn print(args: fmt::Arguments) {
    use core::fmt::Write as _;
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
