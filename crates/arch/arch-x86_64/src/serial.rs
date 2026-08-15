//! x86-64 COM1 串口实现（基于 port I/O）。

const COM1: u16 = 0x3F8;

/// 读取 port（inb）
#[inline]
fn inb(port: u16) -> u8 {
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
fn outb(port: u16, byte: u8) {
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
    outb(COM1 + 1, 0x00); // 禁用中断
    outb(COM1 + 3, 0x80); // DLAB 开，设置波特率
    outb(COM1 + 0, 0x03); // 除数低字节 (38400)
    outb(COM1 + 1, 0x00); // 除数高字节
    outb(COM1 + 3, 0x03); // 8 位数据，无校验，1 停止位
    outb(COM1 + 2, 0xC7); // 启用 FIFO，清空
    outb(COM1 + 4, 0x0B); // IRQ 使能，RTS/DSR
}

/// 发送单个字节
pub fn write_byte(byte: u8) {
    // 等待发送保持寄存器空（LSR bit 5）
    while inb(COM1 + 5) & 0x20 == 0 {}
    outb(COM1, byte);
}

/// 读取单个字节（无数据返回 None）
pub fn read_byte() -> Option<u8> {
    // LSR bit 0 表示数据就绪
    if inb(COM1 + 5) & 0x01 != 0 {
        Some(inb(COM1))
    } else {
        None
    }
}

/// 直接写入一串字节到串口（\n 转 \r\n）。
///
/// 无锁、不依赖 klib 的全局输出，适合在中断/异常上下文使用。
pub fn write_str(s: &str) {
    for &b in s.as_bytes() {
        if b == b'\n' {
            write_byte(b'\r');
        }
        write_byte(b);
    }
}

/// 写入一个 u32 的十进制表示到串口。
pub fn write_dec_u32(mut val: u32) {
    let mut buf = [0u8; 12];
    let mut i = 0;
    if val == 0 {
        write_byte(b'0');
        return;
    }
    while val > 0 {
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        write_byte(buf[i]);
    }
}

/// 写入一个 u64 的十进制表示到串口。
pub fn write_dec_u64(val: u64) {
    // 用 u128 避免大数溢出，分高位/低位打印
    if val > u64::from(u32::MAX) {
        let hi = (val >> 32) as u32;
        let lo = (val & 0xFFFF_FFFF) as u32;
        let base: u128 = u128::from(hi) * 4294967296u128 + u128::from(lo);
        write_dec_u128(base);
    } else {
        write_dec_u32(val as u32);
    }
}

/// 写入 u128 十进制（辅助）。
fn write_dec_u128(mut val: u128) {
    let mut buf = [0u8; 40];
    let mut i = 0;
    if val == 0 {
        write_byte(b'0');
        return;
    }
    while val > 0 {
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        write_byte(buf[i]);
    }
}
