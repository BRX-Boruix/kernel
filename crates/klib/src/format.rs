//! 架构无关的整数 → 字节数组格式化（十进制 / 十六进制）。
//!
//! 供 `klib::serial` 复用，避免各处手写相同的整数转字符串逻辑。

/// 把 `value` 以十进制转成字节数组（无前导零，`0` 为单个 `0`）。
/// 返回 `(缓冲区, 有效长度)`。
pub fn dec_bytes(value: u128) -> ([u8; 40], usize) {
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
pub fn hex_bytes(value: u64) -> [u8; 16] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 16];
    for i in 0..16 {
        let shift = (15 - i) * 4;
        buf[i] = HEX[((value >> shift) & 0xF) as usize];
    }
    buf
}
