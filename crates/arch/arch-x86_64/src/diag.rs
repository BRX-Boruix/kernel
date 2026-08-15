//! 诊断格式化输出（十进制/十六进制）。
//!
//! 基于 `serial::write_str`，供 lapic、mmio、interrupts、smp 等模块复用，
//! 避免各自手写整数转字符串。每次输出拼接成一段 `&str` 后整串写入，
//! 保证在 `serial` 锁下原子输出，避免多核交错。

use crate::serial;

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
    // 逆序
    let mut out = [0u8; 40];
    let mut o = 0;
    while n > 0 {
        n -= 1;
        out[o] = buf[n];
        o += 1;
    }
    let s = core::str::from_utf8(&out[..o]).unwrap();
    serial::write_str(s);
}

/// 以十六进制写 `value` 到串口（不带 0x 前缀，固定 16 位宽度）。
pub fn write_hex_u64(value: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 16];
    for i in 0..16 {
        let shift = (15 - i) * 4;
        buf[i] = HEX[((value >> shift) & 0xF) as usize];
    }
    let s = core::str::from_utf8(&buf).unwrap();
    serial::write_str(s);
}

/// 以十六进制写 `value` 到串口，带 `0x` 前缀。
pub fn write_hex(value: u64) {
    serial::write_str("0x");
    write_hex_u64(value);
}
