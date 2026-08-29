//! 熵池：把硬件熵源注入并混合，输出随机字节流（ADR-014：随机数统一走
//! `/devices/random`，无 `SYS_RANDOM` 系统调用）。
//!
//! 设计（选项 B：轻量熵池混合，非完整 DRBG）：
//! - 熵源：`rdseed64 → rdrand64 → 时钟扰动`，每次输出都重新采样并混入状态，
//!   保证 read 之间状态新鲜、不退化；
//! - 输出：从混合后的 64 位状态用 SplitMix64 确定性扩展成字节流——把"真随机
//!   种子"拉伸为所需长度的随机字节（现代系统"硬件 RNG 不直接透传"的共识，
//!   避免把单次 RDRAND 输出直接当长流）；
//! - 诚实披露：`source()` 如实返回当前熵源（`rdseed`/`rdrand`/`fallback_clock`）。
//!   时钟扰动是**确定性垫底**，不是密码学安全熵——`/devices/random/status`
//!   据此置 `crypto_safe:false`，由用户态决定是否用于密钥（S07/S09 宁缺毋假）。

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use crate::cpu;

/// 熵源枚举（诚实披露用，ADR-027 宁缺毋假：绝不把时钟垫底谎报成硬件熵）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropySource {
    /// RDSEED：真正的硬件熵（种子）。
    Rdseed,
    /// RDRAND：硬件 DRBG 输出（伪随机，但独立于本池）。
    Rdrand,
    /// 时钟扰动垫底：确定性，非密码学安全。
    FallbackClock,
}

impl EntropySource {
    /// 是否为密码学安全（真随机）来源。
    pub fn crypto_safe(&self) -> bool {
        matches!(self, EntropySource::Rdseed | EntropySource::Rdrand)
    }

    /// 用户态可见的名称（`/devices/random/status` 投影）。
    pub fn name(&self) -> &'static str {
        match self {
            EntropySource::Rdseed => "rdseed",
            EntropySource::Rdrand => "rdrand",
            EntropySource::FallbackClock => "fallback_clock",
        }
    }
}

/// 混合后的 64 位熵状态（SplitMix64 的推进状态）。
static STATE: AtomicU64 = AtomicU64::new(0);
/// 是否已做首次播种。
static INITIALIZED: AtomicBool = AtomicBool::new(false);
/// 当前熵源（最近一次采样得到）。
static SOURCE: AtomicU8 = AtomicU8::new(0);

/// SplitMix64 一步：把状态推进并返回下一个 64 位值。
#[inline]
fn splitmix_next(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut r = z;
    r = (r ^ (r >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    r = (r ^ (r >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    r ^ (r >> 31)
}

/// 采样一次熵源（rdseed → rdrand → 时钟扰动垫底），返回 64 位值并记录来源。
///
/// 与 `cpu::entropy_u64` 同源，但单独记录 `EntropySource` 以便诚实披露。
fn draw_source() -> u64 {
    if let Some(v) = cpu::rdseed64() {
        SOURCE.store(EntropySource::Rdseed as u8, Ordering::Relaxed);
        return v;
    }
    if let Some(v) = cpu::rdrand64() {
        SOURCE.store(EntropySource::Rdrand as u8, Ordering::Relaxed);
        return v;
    }
    // S09：无真熵时如实标记 fallback_clock（确定性），绝不谎报为硬件熵。
    SOURCE.store(EntropySource::FallbackClock as u8, Ordering::Relaxed);
    // 时钟扰动：与固定常数混合，避免空池时输出恒零；无时钟时用常量兜底
    //（仍是确定性，但 source() 已如实披露 fallback_clock）。
    let t = klib::time::now_nanos().unwrap_or(0);
    t.rotate_left(17) ^ 0x9E37_79B9_7F4A_7C15
}

/// 首次播种：用熵源初始化状态（保证非零且引入不确定性）。
fn seed_state() {
    let s = draw_source();
    // 再混入一个独立的熵值，降低初始状态可预测性。
    let s2 = draw_source();
    STATE.store(s ^ s2.rotate_left(37) ^ 1, Ordering::Relaxed);
}

/// 原子推进 SplitMix 状态，返回新状态的下一个输出值。
#[inline]
fn next_u64() -> u64 {
    let mut old = STATE.load(Ordering::Relaxed);
    loop {
        let new = splitmix_next(old);
        match STATE.compare_exchange_weak(old, new, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return new,
            Err(actual) => old = actual,
        }
    }
}

/// 往状态里再混入一注熵（每次输出后调用，保持状态新鲜）。
#[inline]
fn mix_reseed() {
    let e = draw_source();
    let mut old = STATE.load(Ordering::Relaxed);
    loop {
        let mixed = old ^ e.rotate_left(23) ^ 0xD1B5_4A32_D192_ED03;
        match STATE.compare_exchange_weak(old, mixed, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(actual) => old = actual,
        }
    }
}

/// 把 `buf` 填满随机字节。每次调用都会采样一次熵源混入状态，保证新鲜。
///
/// 调用方可用 [`source`] 查询本次熵源，判断是否密码学安全。
pub fn fill_bytes(buf: &mut [u8]) {
    if !INITIALIZED.swap(true, Ordering::Relaxed) {
        seed_state();
    }
    let mut i = 0;
    while i < buf.len() {
        let word = next_u64().to_le_bytes();
        let n = core::cmp::min(8, buf.len() - i);
        buf[i..i + n].copy_from_slice(&word[..n]);
        i += n;
    }
    mix_reseed();
}

/// 当前熵源（诚实披露）。
pub fn source() -> EntropySource {
    match SOURCE.load(Ordering::Relaxed) {
        0 => EntropySource::Rdseed,
        1 => EntropySource::Rdrand,
        _ => EntropySource::FallbackClock,
    }
}
