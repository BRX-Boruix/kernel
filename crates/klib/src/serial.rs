//! 串口日志与格式化输出（兼容层）。
//!
//! 早期本模块是"注入单个输出函数"的间接层；现在统一输出由
//! [`crate::console`] 承担（可注册串口 + framebuffer 终端等多个 sink）。
//! 本模块保留同名 API（`set_output`/`write_str`/`print`/`log!` 等）作为
//! 兼容转发，所有输出最终汇聚到统一 console。
//!
//! KM4：本模块同时是十进制/十六进制字节助手的**唯一居所**——原
//! `format.rs` 的 C 风格 printf 引擎经全仓 grep 证实零外部消费者，
//! 已整体删除；仅存活的 [`dec_bytes`]/[`hex_bytes`] 随其唯一消费方
//! （本模块的 `write_dec`/`write_hex*`）迁入此处私有化。

use core::fmt;

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

/// 把 `value` 以十进制转成字节数组（无前导零，`0` 为单个 `0`）。
/// 返回 `(缓冲区, 有效长度)`。缓冲 40 字节恰好容纳 u128::MAX 的 39 位。
fn dec_bytes(value: u128) -> ([u8; 40], usize) {
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
    // 逆序后拷贝到输出缓冲
    let mut out = [0u8; 40];
    let mut o = 0;
    while n > 0 {
        n -= 1;
        out[o] = buf[n];
        o += 1;
    }
    (out, o)
}

/// 把 `value` 以十六进制转成固定 16 位字节数组（小写，高位在前）。
fn hex_bytes(value: u64) -> [u8; 16] {
    let mut buf = [0u8; 16];
    for i in 0..16 {
        let shift = (15 - i) * 4;
        buf[i] = HEX_LOWER[((value >> shift) & 0xF) as usize];
    }
    buf
}

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
    write_str(core::str::from_utf8(&hex_bytes(value)).unwrap());
}

/// 以十进制写 `value`（无前导零，`0` 输出单个 `0`）。
pub fn write_dec(value: u128) {
    let (buf, len) = dec_bytes(value);
    write_str(core::str::from_utf8(&buf[..len]).unwrap());
}

/// 以十六进制写 `value`，带 `0x` 前缀，固定 16 位宽度。
pub fn write_hex(value: u64) {
    write_str("0x");
    write_hex_raw(value);
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::{dec_bytes, hex_bytes};

    #[test]
    fn dec_basics_and_capacity() {
        assert_eq!(&dec_bytes(0).0[..1], b"0");
        let (b, n) = dec_bytes(7);
        assert_eq!(&b[..n], b"7");
        let (b, n) = dec_bytes(u128::MAX);
        assert_eq!(n, 39); // u128::MAX 恰 39 位，缓冲 40 字节不溢出
        assert_eq!(
            &b[..n],
            b"340282366920938463463374607431768211455"
        );
    }

    #[test]
    fn hex_fixed_width_lowercase() {
        assert_eq!(
            &hex_bytes(0xdead_beef),
            b"00000000deadbeef"
        );
        assert_eq!(&hex_bytes(u64::MAX), b"ffffffffffffffff");
        assert_eq!(&hex_bytes(0), b"0000000000000000");
    }
}
