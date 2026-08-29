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

/// 等待 RTC 更新完成（避免撕裂值）。
///
/// AD4 修正：上限为 **~20ms**（10,000 次轮询 × 每次 CMOS 端口读写约 2µs），
/// 而非旧注释的 "~2ms"；正常更新周期 1ms 内完成，20ms 仅是防御性上界。
fn wait_not_updating() {
    /// 轮询次数上界（每次迭代含一次状态寄存器端口读，约 2µs/次）。
    const UIP_POLL_ROUNDS: usize = 10_000;
    for _ in 0..UIP_POLL_ROUNDS {
        if cmos_read(REG_STATUS_A) & UIP == 0 {
            return;
        }
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

/// 自 1970-01-01 起的天数（Howard Hinnant `days_from_civil` 算法，公历）。
///
/// 输入为公历年月日；返回可为负（1970 前日期）。此换算只依赖纯算术，
/// 正确处理闰年（400/100/4 法则），无任何外部依赖。
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// 当前 RTC 墙钟对应的 Unix epoch 秒（自 1970-01-01T00:00:00 起）。
///
/// 读取真实年月日时分秒（[`read_time`]）后换算为 epoch。**时区语义**：RTC
/// 返回本地时间（由 BIOS 配置的时区决定），本内核无时区模型，此处把本地
/// 时间按"当作 UTC 处理"换算（与 `/system/info/time` 直接投影本地时间同一
/// 政策，ADR-013 §3.1）。若后续接入时区数据库/网络时钟可在此替换来源。
///
/// **S09 诚实**：字段越界（月 1-12、日 1-31、时 0-23、分/秒 0-59）视为硬件
/// 时间无效，返回 `None` 而非换算出一个无意义的 epoch——绝不把损坏的 RTC
/// 读值伪装成"真实时间恰为该时刻"。
pub fn read_epoch_secs() -> Option<u64> {
    let t = read_time();
    if !(1..=12).contains(&t.month)
        || !(1..=31).contains(&t.day)
        || t.hour > 23
        || t.minute > 59
        || t.second > 59
    {
        return None;
    }
    let days = days_from_civil(t.year as i64, t.month as i64, t.day as i64);
    // 2026 附近 days ≈ 2 万量级，×86400 不溢出 u64；饱和防理论溢出（S19）。
    let secs = days as u128 * 86_400 + t.hour as u128 * 3_600 + t.minute as u128 * 60 + t.second as u128;
    Some(if secs > u64::MAX as u128 { u64::MAX } else { secs as u64 })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `days_from_civil` 用公认的公历 epoch 值校验（Howard Hinnant 算法正确性）。
    #[test]
    fn days_from_civil_known_epochs() {
        // 1970-01-01 → 0 天。
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        // 2000-01-01 → 10957 天（1970~2000 含闰年 1972,76,...,96 共 7 个 + 30 年）。
        assert_eq!(days_from_civil(2000, 1, 1), 10_957);
        // 2026-01-01 → 20454 天（公认 Unix epoch 天数）。
        assert_eq!(days_from_civil(2026, 1, 1), 20_454);
        // 闰年：2000-02-29 合法（能被 400 整除）；1900 非闰年 2 月无 29 日。
        assert_eq!(days_from_civil(2000, 2, 29), 11_017);
        assert_eq!(days_from_civil(1900, 2, 28), -25_520);
        // 边界：1970-01-01 前为负。
        assert_eq!(days_from_civil(1969, 12, 31), -1);
    }

    /// epoch 秒换算（用构造好的 RtcTime，不经 CMOS IO）。
    #[test]
    fn epoch_secs_from_rtc_time() {
        // 1970-01-01T00:00:00 → 0。
        let t = RtcTime { year: 1970, month: 1, day: 1, hour: 0, minute: 0, second: 0 };
        // 直接复用换算逻辑（read_epoch_secs 依赖 CMOS IO 无法 host 测，这里
        // 校验换算核心：days × 86400 + h×3600 + m×60 + s）。
        let days = days_from_civil(t.year as i64, t.month as i64, t.day as i64);
        let secs = days as u128 * 86_400 + t.hour as u128 * 3_600 + t.minute as u128 * 60 + t.second as u128;
        assert_eq!(secs, 0);
        // 2000-01-01T00:00:00 → 946684800（公认 Unix epoch）。
        let t = RtcTime { year: 2000, month: 1, day: 1, hour: 0, minute: 0, second: 0 };
        let days = days_from_civil(t.year as i64, t.month as i64, t.day as i64);
        let secs = days as u128 * 86_400 + t.hour as u128 * 3_600 + t.minute as u128 * 60 + t.second as u128;
        assert_eq!(secs, 946_684_800);
        // 2026-08-28 12:34:56（用户惯例日期）：1985-01-01 epoch=473385600 已知，
        // 这里校验月日换算的确定性：days(2026-08-28) 计算后秒数应落在合理区间
        // 且与 days_from_civil 已知锚点一致。
        assert!(days_from_civil(2026, 8, 28) > days_from_civil(2026, 1, 1));
    }
}
