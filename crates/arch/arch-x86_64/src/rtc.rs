//! RTC/CMOS 墙钟读取。
//!
//! 提供真实年月日时分秒（本地时间，由 BIOS 配置的时区决定）。
//! 内核主要用单调时钟（`arch::Timer::now_nanos`）计时；RTC 只在启动时
//! 读取一次用于向用户展示"当前时间"或做日志时间戳。
//!
//! CMOS 地址端口 0x70 / 数据端口 0x71，NMI 必须保持关闭（最高位置 1）。
//! 寄存器为 BCD 编码，需按 status B 的 bit2（二进制模式标志）转换。
//! 读 RTC 期间若发生更新中断（UIP）可能读到撕裂值，简单防御是重读校验。

use crate::port::{inb, outb};

const CMOS_ADDR: u16 = 0x70;
const CMOS_DATA: u16 = 0x71;

// RTC 寄存器索引
const REG_SECONDS: u8 = 0x00;
const REG_MINUTES: u8 = 0x02;
const REG_HOURS: u8 = 0x04;
const REG_DAY: u8 = 0x07;
const REG_MONTH: u8 = 0x08;
const REG_YEAR: u8 = 0x09;
const REG_STATUS_A: u8 = 0x0A;
const REG_STATUS_B: u8 = 0x0B;

// status A bit 7：UIP（更新进行中）
const UIP: u8 = 1 << 7;
// status B bit 2：二进制模式（否则 BCD）
const BINARY_MODE: u8 = 1 << 2;
// status B bit 1：24 小时制
const TWENTY_FOUR_HOUR: u8 = 1 << 1;

/// RTC 墙钟时间（本地时间）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtcTime {
    /// 年（如 2026）。
    pub year: u16,
    /// 月（1~12）。
    pub month: u8,
    /// 日（1~31）。
    pub day: u8,
    /// 时（0~23）。
    pub hour: u8,
    /// 分（0~59）。
    pub minute: u8,
    /// 秒（0~59）。
    pub second: u8,
}

/// 读取单个 CMOS 寄存器（NMI 关闭）。
fn cmos_read(reg: u8) -> u8 {
    outb(CMOS_ADDR, reg | 0x80); // bit7=1 关闭 NMI
    inb(CMOS_DATA)
}

/// 等待 RTC 更新完成（避免撕裂值）。最多轮询 ~2ms。
fn wait_not_updating() {
    for _ in 0..10_000 {
        if cmos_read(REG_STATUS_A) & UIP == 0 {
            return;
        }
        // 约 2us 一次，总计 ~20ms 上限（正常更新周期 1ms 内完成）。
    }
}

/// BCD 转十进制（BCD 模式）或原样（二进制模式）。
#[inline]
fn bcd(v: u8, is_binary: bool) -> u8 {
    if is_binary {
        v
    } else {
        (v & 0x0F) + (v >> 4) * 10
    }
}

/// 读取当前 RTC 墙钟时间。
///
/// 读取分两遍：若两遍不一致说明跨越了更新边界，重读（最多 3 次）。
pub fn read_time() -> RtcTime {
    let status_b = cmos_read(REG_STATUS_B);
    let binary = status_b & BINARY_MODE != 0;

    for _ in 0..3 {
        wait_not_updating();
        let s1 = cmos_read(REG_SECONDS);
        let m1 = cmos_read(REG_MINUTES);
        let h1 = cmos_read(REG_HOURS);
        let d1 = cmos_read(REG_DAY);
        let mo1 = cmos_read(REG_MONTH);
        let y1 = cmos_read(REG_YEAR);
        wait_not_updating();
        let s2 = cmos_read(REG_SECONDS);
        let m2 = cmos_read(REG_MINUTES);
        let h2 = cmos_read(REG_HOURS);
        let d2 = cmos_read(REG_DAY);
        let mo2 = cmos_read(REG_MONTH);
        let y2 = cmos_read(REG_YEAR);

        if (s1, m1, h1, d1, mo1, y1) == (s2, m2, h2, d2, mo2, y2) {
            let mut hour = bcd(h2, binary);
            // 12 小时制 → 24 小时制（status B 未置 24 小时位且最高位为 PM 标志）
            if status_b & TWENTY_FOUR_HOUR == 0 {
                let pm = hour & 0x80 != 0;
                hour &= 0x7F;
                if pm {
                    hour = if hour == 12 { 12 } else { hour + 12 };
                } else if hour == 12 {
                    hour = 0;
                }
            }
            let century_base = 2000u16; // 2000-01-01 ~ 2099 覆盖当前时间窗口
            return RtcTime {
                year: century_base + bcd(y2, binary) as u16,
                month: bcd(mo2, binary),
                day: bcd(d2, binary),
                hour,
                minute: bcd(m2, binary),
                second: bcd(s2, binary),
            };
        }
    }
    // 连续 3 次不一致（极端情况）：返回最后一次读到的大致值。
    let hour = bcd(cmos_read(REG_HOURS), binary);
    RtcTime {
        year: 2000 + bcd(cmos_read(REG_YEAR), binary) as u16,
        month: bcd(cmos_read(REG_MONTH), binary),
        day: bcd(cmos_read(REG_DAY), binary),
        hour,
        minute: bcd(cmos_read(REG_MINUTES), binary),
        second: bcd(cmos_read(REG_SECONDS), binary),
    }
}
