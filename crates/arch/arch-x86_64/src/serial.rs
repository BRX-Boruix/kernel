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
