//! 时间测量的**判据**（纯函数，与硬件无关，故可宿主单测）。
//!
//! 为什么单独成模块：这些判据此前散落在内核自检里，与硬件读取混在一起，**无法宿主验证**，
//! 于是同一个判据的两种写法（一种 warn、一种 panic）长期共存而没人发现（见 `classify_busy_wait`
//! 的说明）。把判据抽出来，红绿就都能在宿主上跑。

/// 一次「请求 N 纳秒的忙等」的实测结果判据。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusyWaitVerdict {
    /// 落在期望窗口内。
    Ok,
    /// **明显短于**请求：`now_nanos` 没有如实推进——这是**被测内核**的缺陷。
    TooShort,
    /// **长于**上界：TCG 虚拟时钟快进 / 宿主负载所致——这是**环境**属性，不是缺陷。
    Overrun,
}

/// 请求的忙等时长（纳秒）。
pub const BUSY_WAIT_REQUESTED_NS: u64 = 1_000_000;
/// 允许的下界：调度与时钟量化误差。低于它说明 `now_nanos` 没在如实推进。
pub const BUSY_WAIT_MIN_NS: u64 = 500_000;
/// 上界：超过它归因于环境（TCG 快进 / 宿主负载），**不判失败**。
pub const BUSY_WAIT_MAX_NS: u64 = 50_000_000;

/// 判定一次忙等的实测时长。
///
/// **为什么上界不判失败**：TCG（无 KVM 加速）下 QEMU 会在忙等期间快进虚拟时钟，宿主负载也会
/// 拉长真实耗时——两者都是**环境**属性。内核自检里对「反推频率越界」早已采用同一纪律
/// （`test_hpet` 第 1 步末尾的 warn），但**同一成因**的时长上界当时却写成硬断言，
/// 结果一次宿主负载就 panic。此函数把两种判定收敛到一处。
///
/// **下界仍判失败**：请求等 1 ms 却几乎没等，说明 `now_nanos` 没在推进——那是内核缺陷，
/// 必须报错而不是放过。
pub fn classify_busy_wait(n_delta_ns: u64) -> BusyWaitVerdict {
    if n_delta_ns < BUSY_WAIT_MIN_NS {
        return BusyWaitVerdict::TooShort;
    }
    if n_delta_ns > BUSY_WAIT_MAX_NS {
        return BusyWaitVerdict::Overrun;
    }
    BusyWaitVerdict::Ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requested_duration_is_ok() {
        assert_eq!(classify_busy_wait(BUSY_WAIT_REQUESTED_NS), BusyWaitVerdict::Ok);
    }

    #[test]
    fn boundaries_are_inclusive() {
        assert_eq!(classify_busy_wait(BUSY_WAIT_MIN_NS), BusyWaitVerdict::Ok);
        assert_eq!(classify_busy_wait(BUSY_WAIT_MAX_NS), BusyWaitVerdict::Ok);
    }

    #[test]
    fn just_below_min_is_too_short() {
        assert_eq!(classify_busy_wait(BUSY_WAIT_MIN_NS - 1), BusyWaitVerdict::TooShort);
        assert_eq!(classify_busy_wait(0), BusyWaitVerdict::TooShort);
    }

    #[test]
    fn just_above_max_is_overrun_not_failure() {
        assert_eq!(classify_busy_wait(BUSY_WAIT_MAX_NS + 1), BusyWaitVerdict::Overrun);
    }

    /// 回归锁：这是 2026-10 实测到、并导致一次 `--test` panic 的**真实数值**。
    /// 它必须被判为 `Overrun`（环境），而不是失败。
    #[test]
    fn observed_host_load_overrun_is_not_a_failure() {
        assert_eq!(classify_busy_wait(499_986_700), BusyWaitVerdict::Overrun);
    }
}