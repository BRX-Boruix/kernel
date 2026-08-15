//! 诊断格式化输出（十进制/十六进制）。
//!
//! 基于 `serial::write_str`，供 lapic、mmio、interrupts、smp 等模块复用，
//! 避免各自手写整数转字符串。每次输出拼接成一段 `&str` 后整串写入，
//! 保证在 `serial` 锁下原子输出，避免多核交错。

use crate::serial;

/// 以十进制写 `value` 到串口（无前导零，`0` 输出单个 `0`）。
pub fn write_dec(value: u128) {
    let (buf, len) = klib::format::dec_bytes(value);
    let s = core::str::from_utf8(&buf[..len]).unwrap();
    serial::write_str(s);
}

/// 以十六进制写 `value` 到串口（不带 0x 前缀，固定 16 位宽度）。
pub fn write_hex_u64(value: u64) {
    let bytes = klib::format::hex_bytes(value);
    let s = core::str::from_utf8(&bytes).unwrap();
    serial::write_str(s);
}

/// 以十六进制写 `value` 到串口，带 `0x` 前缀。
pub fn write_hex(value: u64) {
    serial::write_str("0x");
    write_hex_u64(value);
}
