//! x86-64 COM1 串口实现（基于 port I/O）。
//!
//! 多核下用可重入自旋锁保护写操作，避免多个 CPU 并行写串口导致输出交错。
//! 锁设计：
//! - 基于"持有者 CPU（LAPIC id）+ 重入计数"实现同 CPU 可重入（中断嵌套安全）。
//! - 中断门会自动 `cli`，因此中断上下文与本 CPU 主线程的竞争靠重入计数化解；
//!   不同 CPU 之间靠自旋互斥。

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU32, Ordering};

use crate::port::{inb, outb};
use klib::error::Error;

/// 16550 UART 输入时钟经 16 倍采样后的标准波特率基准（1.8432MHz / 16）。
const UART_BAUD_BASE: u32 = 115_200;
/// 16550 divisor latch 是 16 位且零值无效。
const UART_DIVISOR_MAX: u32 = u16::MAX as u32;

const REG_DATA_OR_DLL: u16 = 0;
const REG_IER_OR_DLM: u16 = 1;
const REG_FIFO_CONTROL: u16 = 2;
const REG_LINE_CONTROL: u16 = 3;
const REG_MODEM_CONTROL: u16 = 4;
const REG_LINE_STATUS: u16 = 5;

const LCR_DLAB: u8 = 1 << 7;
const LCR_8N1: u8 = 0x03;
const MCR_LOOPBACK: u8 = 1 << 4;
const LSR_DATA_READY: u8 = 1 << 0;
const LSR_TX_EMPTY: u8 = 1 << 5;
/// 防止缺失/故障 UART 令验收永久自旋；这是寄存器轮询次数，不是伪造超时成功。
const LOOPBACK_POLL_LIMIT: usize = 1_000_000;
/// TX 空等待的轮询上限（arch1.md AM2）：与环回验收同哲学——UART 挂死时
/// 宁可丢弃本字节也不能持串口锁永久自旋（多核下会拖死全部 CPU）。
/// 这是寄存器轮询次数，不是伪造超时成功；耗尽即放弃该字节且不记日志
/// （warn! 会经 console 回到本写路径，构成递归）。
const TX_POLL_LIMIT: usize = 1_000_000;

/// 保存当前中断状态并关中断（写串口期间禁用本 CPU 中断）。
///
/// 防止"主线程写串口被 IRQ0 打断 → 中断处理也写串口"的竞争导致主线程饿死：
/// 写串口全程关中断，中断上下文（已 cli）重入时保存/恢复不变，安全。
#[inline]
fn irq_save() -> u64 {
    let flags: u64;
    unsafe {
        core::arch::asm!("pushfq; pop {}", out(reg) flags, options(nomem, nostack));
        core::arch::asm!("cli", options(nomem, nostack));
    }
    flags
}

/// 恢复中断状态（`popfq` 恢复 RFLAGS，含 IF）。
#[inline]
fn irq_restore(flags: u64) {
    unsafe {
        core::arch::asm!("push {}; popfq", in(reg) flags, options(nomem, nostack));
    }
}

/// 标准 COM 端口地址表（COM1~COM4）。
const COM_PORTS: [u16; 4] = [0x3F8, 0x2F8, 0x3E8, 0x2E8];

/// 当前使用的串口基址。默认 COM1，`init` 时探测后可能改为其他端口。
static COM_BASE: AtomicU16 = AtomicU16::new(0x3F8);

/// 串口锁：`LOCKED` 表示被某 CPU 占用，`OWNER` 记录占用者 LAPIC id，
/// `DEPTH` 记录同 CPU 重入深度。
static LOCKED: AtomicBool = AtomicBool::new(false);
static OWNER: AtomicU32 = AtomicU32::new(u32::MAX);
static DEPTH: AtomicU8 = AtomicU8::new(0);

/// LAPIC 是否已可用（多核启用后为 true）。早期为 false，此时单核无竞争，
/// 串口锁退化为穿行（owner 用 0，重入计数恒为 1，避免读未映射的 LAPIC）。
static LAPIC_READY: AtomicBool = AtomicBool::new(false);

/// 标记 LAPIC 已可用（由 lapic 初始化后调用）。
pub fn set_lapic_ready() {
    LAPIC_READY.store(true, Ordering::SeqCst);
}

/// 安全地获取当前 CPU id：LAPIC 可用时读 LAPIC id，否则返回 0。
#[inline]
fn safe_cpu_id() -> u32 {
    if LAPIC_READY.load(Ordering::Relaxed) {
        crate::lapic::current_lapic_id()
    } else {
        0
    }
}

struct SerialLock;

impl SerialLock {
    /// 获取串口锁。可重入。
    fn acquire(&self) {
        let cpu = safe_cpu_id();
        loop {
            // 同 CPU 重入
            if OWNER.load(Ordering::SeqCst) == cpu {
                DEPTH.fetch_add(1, Ordering::SeqCst);
                return;
            }
            // 尝试抢占
            if !LOCKED.swap(true, Ordering::SeqCst) {
                OWNER.store(cpu, Ordering::SeqCst);
                DEPTH.store(1, Ordering::SeqCst);
                return;
            }
            core::hint::spin_loop();
        }
    }

    /// 释放串口锁（递减重入计数，归零才真正释放）。
    fn release(&self) {
        if DEPTH.fetch_sub(1, Ordering::SeqCst) == 1 {
            OWNER.store(u32::MAX, Ordering::SeqCst);
            LOCKED.store(false, Ordering::SeqCst);
        }
    }
}

static LOCK: SerialLock = SerialLock;

/// 初始化串口（38400 波特，8N1）。
///
/// 探测 COM1~COM4，选择第一个存在的串口，避免真机上 COM1 不存在（例如
/// 固件把串口映射到其他端口）时输出到空端口行为未定义。
pub fn init() {
    let base = probe_serial();
    COM_BASE.store(base, Ordering::Relaxed);

    outb(base + REG_IER_OR_DLM, 0x00); // 禁用 UART 中断
    program_divisor_locked(base, 3); // 115200 / 3 = 38400
    outb(base + REG_FIFO_CONTROL, 0xC7); // 启用 FIFO，清空
    outb(base + REG_MODEM_CONTROL, 0x0B); // OUT2、RTS、DTR
}

/// 将请求速率转换为 16550 divisor。
///
/// 只接受能由标准 115200Hz 基准**精确表达**的速率；禁止悄悄取整为另一
/// 个实际速率。divisor 必须落在 1..=65535。
fn divisor_for_baudrate(baud: u32) -> Result<u16, Error> {
    if baud == 0 || UART_BAUD_BASE % baud != 0 {
        return Err(Error::InvalidParam);
    }
    let divisor = UART_BAUD_BASE / baud;
    if divisor == 0 || divisor > UART_DIVISOR_MAX {
        return Err(Error::InvalidParam);
    }
    Ok(divisor as u16)
}

/// 持锁且本 CPU 关中断时编程 DLL/DLM，最后恢复为固定 8N1。
fn program_divisor_locked(base: u16, divisor: u16) {
    outb(base + REG_LINE_CONTROL, LCR_DLAB);
    outb(base + REG_DATA_OR_DLL, divisor as u8);
    outb(base + REG_IER_OR_DLM, (divisor >> 8) as u8);
    outb(base + REG_LINE_CONTROL, LCR_8N1);
}

/// 从 UART divisor latch 回读当前**实际生效**的波特率。
///
/// 返回值来自 DLL/DLM 硬件寄存器，不维护软件影子副本。发现非法 divisor=0
/// 时返回 I/O 错误，避免伪造速率。
pub fn get_baudrate() -> Result<u32, Error> {
    let saved = irq_save();
    LOCK.acquire();
    let base = com_base();
    let lcr = inb(base + REG_LINE_CONTROL);
    outb(base + REG_LINE_CONTROL, lcr | LCR_DLAB);
    let divisor = u16::from_le_bytes([
        inb(base + REG_DATA_OR_DLL),
        inb(base + REG_IER_OR_DLM),
    ]);
    outb(base + REG_LINE_CONTROL, lcr & !LCR_DLAB);
    LOCK.release();
    irq_restore(saved);

    if divisor == 0 {
        Err(Error::Io)
    } else {
        Ok(UART_BAUD_BASE / u32::from(divisor))
    }
}

/// 运行时设置串口波特率，真实重编程 DLL/DLM，并保持 8N1。
///
/// 参数校验在触碰硬件前完成，失败不会改变现有配置。寄存器更新与普通串口
/// 写共享同一可重入锁并关本 CPU 中断，避免输出字节被误写入 divisor latch。
pub fn set_baudrate(baud: u32) -> Result<(), Error> {
    let divisor = divisor_for_baudrate(baud)?;
    let saved = irq_save();
    LOCK.acquire();
    program_divisor_locked(com_base(), divisor);
    LOCK.release();
    irq_restore(saved);
    Ok(())
}

/// 通过 16550 内部 loopback 路径做一次真实收发验收。
///
/// 测试会保存并恢复 MCR；成功仅在 LSR 声明数据就绪且 RBR 回读字节逐位相同
/// 时返回。轮询耗尽返回 `Error::Io`，绝不假成功。
pub fn loopback_test(byte: u8) -> Result<(), Error> {
    let saved = irq_save();
    LOCK.acquire();
    let base = com_base();
    let mcr = inb(base + REG_MODEM_CONTROL);
    outb(base + REG_MODEM_CONTROL, mcr | MCR_LOOPBACK);
    outb(base + REG_DATA_OR_DLL, byte);

    let mut ready = false;
    for _ in 0..LOOPBACK_POLL_LIMIT {
        if inb(base + REG_LINE_STATUS) & LSR_DATA_READY != 0 {
            ready = true;
            break;
        }
        core::hint::spin_loop();
    }
    let received = if ready {
        Some(inb(base + REG_DATA_OR_DLL))
    } else {
        None
    };
    outb(base + REG_MODEM_CONTROL, mcr);
    LOCK.release();
    irq_restore(saved);

    if received == Some(byte) {
        Ok(())
    } else {
        Err(Error::Io)
    }
}

/// 回环收发缓冲上限（K5 验收载荷长度界）。
const LOOPBACK_BURST_MAX: usize = 8;

/// K5 完全体验收：经 [`klib::console::Console::write_bytes`] 字节透明路径的
/// 真实回环收发。
///
/// 与 [`loopback_test`] 同一 loopback 纪律，但发送端是被测对象本身——
/// SerialConsole 的字节接口。非 UTF-8 序列（如 0xFF 0xFE）必须**原样**到达
/// 线路；旧 lossy 路径会把它替换成 U+FFFD（EF BF BD）而使本测试失败。
/// 载荷不得含 `\n`（字节路径按线路纪律展开为 `\r\n`，回读长度会变）。
pub fn write_bytes_loopback_test(bytes: &[u8]) -> Result<(), Error> {
    if bytes.is_empty() || bytes.len() > LOOPBACK_BURST_MAX {
        return Err(Error::InvalidParam);
    }
    let saved = irq_save();
    LOCK.acquire();
    let base = com_base();
    let mcr = inb(base + REG_MODEM_CONTROL);
    outb(base + REG_MODEM_CONTROL, mcr | MCR_LOOPBACK);
    LOCK.release(); // 让被测的字节路径自行持锁（LOCK 不可重入）

    // 被测对象：Console trait 的字节接口（SerialConsole 的覆写实现）。
    use klib::console::Console as _;
    SERIAL_CONSOLE.write_bytes(bytes);

    LOCK.acquire();
    let mut received = [0u8; LOOPBACK_BURST_MAX];
    let mut ok = true;
    for slot in received.iter_mut().take(bytes.len()) {
        let mut ready = false;
        for _ in 0..LOOPBACK_POLL_LIMIT {
            if inb(base + REG_LINE_STATUS) & LSR_DATA_READY != 0 {
                ready = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !ready {
            ok = false;
            break;
        }
        *slot = inb(base + REG_DATA_OR_DLL);
    }
    outb(base + REG_MODEM_CONTROL, mcr);
    LOCK.release();
    irq_restore(saved);

    if ok && &received[..bytes.len()] == bytes {
        Ok(())
    } else {
        Err(Error::Io)
    }
}

/// 探测可用的串口，返回其基址。找不到则回退 COM1。
///
/// 经典探测法：写 0xAE 到 SCR（scratch 寄存器，偏移 7），若可读回 0xAE
/// 说明端口存在；否则写 0x56 再试（部分实现只支持低 7 位）。
fn probe_serial() -> u16 {
    for &base in &COM_PORTS {
        // 用 SCR 寄存器回读检测端口存在性
        outb(base + 7, 0xAE);
        let mut ok = inb(base + 7) == 0xAE;
        if !ok {
            // 某些 UART 只保留低 7 位
            outb(base + 7, 0x56);
            ok = inb(base + 7) == 0x56;
        }
        if ok {
            return base;
        }
    }
    // 未探测到任何串口，回退 COM1（尽力而为）
    COM_PORTS[0]
}

/// 当前串口基址。
#[inline]
fn com_base() -> u16 {
    COM_BASE.load(Ordering::Relaxed)
}

/// 等待发送保持寄存器空（LSR bit 5），随后写一个字节。
///
/// 轮询上限 [`TX_POLL_LIMIT`]：耗尽说明 UART 硬件挂死，放弃本字节以释放
/// 串口锁（持锁永久自旋会让多核全部卡死，arch1.md AM2）。正常 UART 在
/// 波特率级别的时间内必然腾空，远达不到上限。
#[inline]
fn putc_wait(byte: u8) {
    let com = com_base();
    let mut polled = 0usize;
    while inb(com + REG_LINE_STATUS) & LSR_TX_EMPTY == 0 {
        polled += 1;
        if polled >= TX_POLL_LIMIT {
            return;
        }
        core::hint::spin_loop();
    }
    outb(com, byte);
}

/// 发送单个字节（带锁 + 关中断，防中断上下文重入死锁）。
pub fn write_byte(byte: u8) {
    let saved = irq_save();
    LOCK.acquire();
    putc_wait(byte);
    LOCK.release();
    irq_restore(saved);
}

/// 读取单个字节（无数据返回 None）。
///
/// 与调速共享串口锁，避免另一 CPU 在 DLAB 打开期间把 DLL 当作接收数据读取。
pub fn read_byte() -> Option<u8> {
    let saved = irq_save();
    LOCK.acquire();
    let com = com_base();
    let byte = if inb(com + REG_LINE_STATUS) & LSR_DATA_READY != 0 {
        Some(inb(com + REG_DATA_OR_DLL))
    } else {
        None
    };
    LOCK.release();
    irq_restore(saved);
    byte
}

/// 直接写入一串字节到串口（\n 转 \r\n）。带锁 + 关中断。
pub fn write_str(s: &str) {
    let saved = irq_save();
    LOCK.acquire();
    for &b in s.as_bytes() {
        if b == b'\n' {
            putc_wait(b'\r');
        }
        putc_wait(b);
    }
    LOCK.release();
    irq_restore(saved);
}

/// 直接写入原始字节流到串口（\n 转 \r\n）。带锁 + 关中断。**字节透明**：
/// 非 UTF-8 序列原样到达线路，零销毁（K5 完全体）。
pub fn write_bytes(bytes: &[u8]) {
    let saved = irq_save();
    LOCK.acquire();
    for &b in bytes {
        if b == b'\n' {
            putc_wait(b'\r');
        }
        putc_wait(b);
    }
    LOCK.release();
    irq_restore(saved);
}

/// 串口控制台：`klib::console::Console` 的实现（统一 console 的串口 sink）。
pub struct SerialConsole;

/// 全局串口控制台实例（供 `klib::console::register_console` 注册）。
pub static SERIAL_CONSOLE: SerialConsole = SerialConsole;

impl klib::console::Console for SerialConsole {
    fn name(&self) -> &'static str {
        "serial"
    }
    fn write_str(&self, s: &str) {
        crate::serial::write_str(s);
    }
    fn write_byte(&self, b: u8) {
        crate::serial::write_byte(b);
    }
    // K5 完全体：串口是字节透明设备——覆写缺省 lossy 转发，原始字节直达线路。
    fn write_bytes(&self, bytes: &[u8]) {
        crate::serial::write_bytes(bytes);
    }
    fn flush(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baudrate_to_divisor_accepts_exact_rates() {
        assert_eq!(divisor_for_baudrate(115_200), Ok(1));
        assert_eq!(divisor_for_baudrate(57_600), Ok(2));
        assert_eq!(divisor_for_baudrate(38_400), Ok(3));
        assert_eq!(divisor_for_baudrate(19_200), Ok(6));
        assert_eq!(divisor_for_baudrate(9_600), Ok(12));
        assert_eq!(divisor_for_baudrate(300), Ok(384));
    }

    #[test]
    fn baudrate_to_divisor_rejects_zero_rounding_and_overflow() {
        assert_eq!(divisor_for_baudrate(0), Err(Error::InvalidParam));
        assert_eq!(divisor_for_baudrate(10_000), Err(Error::InvalidParam));
        assert_eq!(divisor_for_baudrate(115_201), Err(Error::InvalidParam));
        assert_eq!(divisor_for_baudrate(1), Err(Error::InvalidParam));
        assert_eq!(divisor_for_baudrate(u32::MAX), Err(Error::InvalidParam));
    }
}
