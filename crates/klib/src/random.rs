//! 伪随机数生成器与熵池。
//!
//! - [`SplitMix64`]：基础 64 位混合（种子扩展、状态混合）；
//! - [`Xoshiro256`]：现代高质量 PRNG（xoshiro256**），确定性、可种子，
//!   供 ASLR、哈希种子等场景；状态全零会退化为恒零输出（`from_state` 需非零）；
//! - 熵池：外部熵源（RDRAND/RDSEED 等）经 [`set_entropy_source`] 注入混合，
//!   为全局 RNG 播种。`klib` 保持零依赖，熵源以函数指针注入（与时钟源、
//!   irq_guard、console sink 同一模式）；
//! - 全局 RNG：[`rand_u64`]/[`rand_u32`]/[`rand_bytes`]/[`rand_range`]，
//!   `IrqSpinLock` 保护（中断安全、多核可用）。
//!
//! 生产环境应在架构熵源注入后调用 [`reseed`]（收集硬件熵 → 播种全局 RNG）；
//! 未 reseed 时全局 RNG 为固定种子（可预测，仅保证行为正确）。

use crate::sync::irq::IrqSpinLock;

// ---------- SplitMix64 ----------

/// SplitMix64：种子扩展 / 状态混合（无状态，输出高度扩散）。
pub struct SplitMix64(pub u64);

impl SplitMix64 {
    /// 下一个 64 位混合输出。
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

// ---------- Xoshiro256** ----------

/// xoshiro256** 伪随机数生成器（参考 https://prng.di.unimi.it/xoshiro256starstar.c）。
///
/// 周期 2^256-1，速度快，统计性质好（Rust `rand` crate 曾用同款）。
/// 状态全零时输出恒为零且不再变化，`from_state` 调用方须保证非全零。
pub struct Xoshiro256 {
    s: [u64; 4],
}

impl Xoshiro256 {
    /// 用单个种子构造（SplitMix64 扩展为 256 位状态，天然非全零）。
    pub fn new(seed: u64) -> Self {
        let mut sm = SplitMix64(seed);
        Self {
            s: [sm.next_u64(), sm.next_u64(), sm.next_u64(), sm.next_u64()],
        }
    }

    /// 用完整状态构造。**状态不能全零**（否则输出恒零）。
    pub const fn from_state(state: [u64; 4]) -> Self {
        Self { s: state }
    }

    /// 下一个 64 位随机数。
    pub fn next_u64(&mut self) -> u64 {
        // xoshiro256** 步进 + 双星形混淆。
        let result = self.s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }

    /// 下一个 32 位随机数（取高 32 位，避免低位的弱线性）。
    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// 填充字节缓冲区（按 8 字节块 + 尾部余数）。
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i + 8 <= buf.len() {
            let v = self.next_u64();
            buf[i..i + 8].copy_from_slice(&v.to_le_bytes());
            i += 8;
        }
        if i < buf.len() {
            let v = self.next_u64().to_le_bytes();
            let rem = buf.len() - i;
            buf[i..].copy_from_slice(&v[..rem]);
        }
    }

    /// 在 `[lo, hi)` 区间无偏采样（拒绝采样，避免取模偏差）。
    ///
    /// KD2：空区间断言是**无条件的**——`debug_assert` 在 release 下降级为
    /// `hi - lo == 0` 的 `% 0`，内核上下文即 #DE 异常停机；受控 panic 的
    /// 报错现场（含调用栈与区间值）远优于算术异常。每次调用的比较成本
    /// 相对拒绝采样循环可忽略。
    pub fn gen_range(&mut self, lo: u64, hi: u64) -> u64 {
        assert!(lo < hi, "gen_range requires lo < hi, got [{lo}, {hi})");
        let range = hi - lo;
        // 阈值：丢弃 r 使得 r % range 偏向的尾部区间（range 整除 2^64 时阈值为 0）。
        let threshold = range.wrapping_neg() % range;
        loop {
            let r = self.next_u64();
            if r >= threshold {
                return lo + (r % range);
            }
        }
    }
}

// ---------- 熵池 ----------

/// 熵源读取函数（由架构层注入，如 RDRAND/RDSEED 封装）。
/// 返回 `None` 表示当前无可用硬件熵——`collect_entropy` 跳过该轮。
pub type EntropySource = fn() -> Option<u64>;

/// 熵池：4 槽状态 + 轮转混合 + 计数器。加锁保护（中断安全）。
struct EntropyPool {
    state: [u64; 4],
    index: usize,
    added: u64,
    /// 熵源函数指针（0 = 未注入）。
    source: usize,
}

static POOL: IrqSpinLock<EntropyPool> = IrqSpinLock::new(EntropyPool {
    state: [0; 4],
    index: 0,
    added: 0,
    source: 0,
});

/// 注入架构熵源（如 `arch_x86_64::cpu::entropy_u64`）。
///
/// 可重复调用以切换。未注入时 [`collect_entropy`] 安全空转。
pub fn set_entropy_source(source: EntropySource) {
    POOL.lock().source = source as usize;
}

/// 熵源是否已注入。
pub fn entropy_source_ready() -> bool {
    POOL.lock().source != 0
}

/// 向熵池混合 64 位输入。
///
/// 输入先与计数器衍生的常数扰动异或，再做一轮 SplitMix64 扩散，
/// 最后轮转槽位——即使输入可预测（如固定 0），池状态也随时间演进。
pub fn add_entropy(value: u64) {
    let mut p = POOL.lock();
    let idx = p.index;
    let mixed = p.state[idx] ^ value.wrapping_add(p.added.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    let mut sm = SplitMix64(mixed);
    p.state[idx] = sm.next_u64();
    p.index = (p.index + 1) & 3;
    p.added = p.added.wrapping_add(1);
}

/// 批量混合字节（时间戳/栈内容等任意字节序列）。
pub fn add_entropy_bytes(bytes: &[u8]) {
    let mut i = 0;
    while i + 8 <= bytes.len() {
        let mut v = 0u64;
        for j in 0..8 {
            v |= (bytes[i + j] as u64) << (8 * j);
        }
        add_entropy(v);
        i += 8;
    }
    if i < bytes.len() {
        let mut v = 0u64;
        let mut k = 0;
        while i < bytes.len() {
            v |= (bytes[i] as u64) << (8 * k);
            i += 1;
            k += 1;
        }
        add_entropy(v);
    }
}

/// 从注入的熵源拉取并混合 `rounds` 次（每次 64 位）。返回实际混合次数。
///
/// 未注入熵源时返回 0（安全空转）。
pub fn collect_entropy(rounds: usize) -> usize {
    let mut got = 0;
    for _ in 0..rounds {
        let f = POOL.lock().source;
        if f == 0 {
            break;
        }
        let v = unsafe { core::mem::transmute::<usize, EntropySource>(f)() };
        if let Some(v) = v {
            add_entropy(v);
            got += 1;
        }
    }
    got
}

/// 熵池已混合的输入次数（调试/统计用）。
pub fn entropy_estimate() -> u64 {
    POOL.lock().added
}

// ---------- 全局 RNG ----------

/// 全局 PRNG。初始为固定种子（确定性）；`reseed` 后用熵池状态播种。
static GLOBAL: IrqSpinLock<Xoshiro256> = IrqSpinLock::new(Xoshiro256 {
    s: [
        0x243F_6A88_85A3_08D3,
        0x1319_8A2E_0370_7344,
        0xA409_3822_299F_31D0,
        0x082E_FA98_EC4E_6C89,
    ],
});

/// 用熵池状态重新播种全局 RNG（含计数器扰动，重复播种结果也不同）。
pub fn seed_global_rng() {
    let p = POOL.lock();
    let mut state = p.state;
    state[0] ^= p.added.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    state[1] ^= p.added.rotate_left(17).wrapping_mul(0x94D0_49BB_1331_11EB);
    state[2] ^= p.added.rotate_left(29).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    // from_state 可能全零（熵池初始未混入任何熵）；补一个非零常数兜底。
    if state[0] | state[1] | state[2] | state[3] == 0 {
        state[0] = 0x9E37_79B9_7F4A_7C15;
    }
    *GLOBAL.lock() = Xoshiro256::from_state(state);
}

/// 便捷接口：拉取 8 次硬件熵 → 播种全局 RNG。
pub fn reseed() {
    collect_entropy(8);
    seed_global_rng();
}

/// 下一个 64 位全局随机数。
pub fn rand_u64() -> u64 {
    GLOBAL.lock().next_u64()
}

/// 下一个 32 位全局随机数。
pub fn rand_u32() -> u32 {
    GLOBAL.lock().next_u32()
}

/// 填充字节缓冲区。
pub fn rand_bytes(buf: &mut [u8]) {
    GLOBAL.lock().fill_bytes(buf)
}

/// 在 `[lo, hi)` 区间无偏采样。
pub fn rand_range(lo: u64, hi: u64) -> u64 {
    GLOBAL.lock().gen_range(lo, hi)
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// 串行化涉及全局状态（熵池/全局 RNG）的测试。
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// 假熵源：确定性递增，便于验证 collect/seed 通路。
    static FAKE_ENTROPY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn fake_source() -> Option<u64> {
        Some(FAKE_ENTROPY.fetch_add(0x9E37_79B9_7F4A_7C15, std::sync::atomic::Ordering::Relaxed))
    }

    #[test]
    fn splitmix64_is_deterministic() {
        let mut a = SplitMix64(42);
        let mut b = SplitMix64(42);
        for _ in 0..10 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        // 输出不应恒为零。
        assert_ne!(SplitMix64(42).next_u64(), 0);
    }

    #[test]
    fn splitmix64_different_seeds_differ() {
        let mut a = SplitMix64(1);
        let mut b = SplitMix64(2);
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn xoshiro_same_seed_same_sequence() {
        let mut a = Xoshiro256::new(0x1234_5678);
        let mut b = Xoshiro256::new(0x1234_5678);
        for _ in 0..32 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn xoshiro_different_seeds_differ() {
        let mut a = Xoshiro256::new(1);
        let mut b = Xoshiro256::new(2);
        // 前 32 个输出中至少有一个不同。
        let mut differ = false;
        for _ in 0..32 {
            if a.next_u64() != b.next_u64() {
                differ = true;
                break;
            }
        }
        assert!(differ, "different seeds must diverge");
    }

    #[test]
    fn xoshiro_seed_zero_not_all_zero() {
        // 种子 0 的 splitmix 扩展状态非全零，输出不应恒零。
        let mut r = Xoshiro256::new(0);
        let mut nonzero = false;
        for _ in 0..64 {
            if r.next_u64() != 0 {
                nonzero = true;
                break;
            }
        }
        assert!(nonzero, "seed 0 must not produce all-zero output");
    }

    #[test]
    fn xoshiro_full_cycle_basic() {
        // 简单自洽：填充缓冲与直接 next 等价。
        let mut r1 = Xoshiro256::new(7);
        let mut r2 = Xoshiro256::new(7);
        let mut buf = [0u8; 16];
        r2.fill_bytes(&mut buf);
        let mut expect = [0u8; 16];
        expect[0..8].copy_from_slice(&r1.next_u64().to_le_bytes());
        expect[8..16].copy_from_slice(&r1.next_u64().to_le_bytes());
        assert_eq!(buf, expect);
    }

    #[test]
    fn gen_range_bounds() {
        let mut r = Xoshiro256::new(3);
        for _ in 0..10_000 {
            let v = r.gen_range(10, 20);
            assert!((10..20).contains(&v), "out of range: {v}");
        }
    }

    #[test]
    fn gen_range_uniformish() {
        // 4 个桶采样 4000 次，期望每桶 1000；允许宽裕波动（>700 即通过）。
        let mut r = Xoshiro256::new(5);
        let mut buckets = [0u64; 4];
        for _ in 0..4000 {
            buckets[r.gen_range(0, 4) as usize] += 1;
        }
        for b in buckets {
            assert!(b > 700, "bucket too small: {b} (distribution skewed?)");
        }
    }

    /// KD2 回归钉：空区间必须**无条件**受控 panic（含 release），
    /// 绝不允许降级为 `% 0` 的 #DE 算术异常停机。
    #[test]
    #[should_panic(expected = "gen_range requires lo < hi")]
    fn gen_range_empty_interval_panics() {
        let mut r = Xoshiro256::new(11);
        let _ = r.gen_range(5, 5);
    }

    #[test]
    fn fill_bytes_odd_length() {
        let mut r = Xoshiro256::new(9);
        let mut buf = [0u8; 33]; // 非 8 倍数
        r.fill_bytes(&mut buf);
        assert!(buf.iter().any(|&b| b != 0), "fill must not be all zero");
    }

    #[test]
    fn entropy_pool_mixes_inputs() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // 复位池状态。
        POOL.lock().state = [0; 4];
        POOL.lock().index = 0;
        POOL.lock().added = 0;
        POOL.lock().source = 0;

        add_entropy(1);
        add_entropy(2);
        add_entropy(3);
        add_entropy(4);
        let s1 = POOL.lock().state;
        assert_ne!(s1, [0; 4], "pool must mix inputs");

        // 相同输入但不同顺序 → 不同状态。
        POOL.lock().state = [0; 4];
        POOL.lock().index = 0;
        POOL.lock().added = 0;
        add_entropy(4);
        add_entropy(3);
        add_entropy(2);
        add_entropy(1);
        let s2 = POOL.lock().state;
        assert_ne!(s1, s2, "order of entropy inputs must matter");

        assert_eq!(entropy_estimate(), 4);
    }

    #[test]
    fn add_entropy_bytes_batches() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        POOL.lock().state = [0; 4];
        POOL.lock().index = 0;
        POOL.lock().added = 0;
        add_entropy_bytes(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]); // 10 字节 → 2 次混合
        assert_eq!(entropy_estimate(), 2);
        assert_ne!(POOL.lock().state, [0; 4]);
    }

    #[test]
    fn collect_entropy_without_source_is_safe() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        POOL.lock().source = 0;
        assert_eq!(collect_entropy(8), 0, "no source -> no collection");
        assert!(!entropy_source_ready());
    }

    #[test]
    fn collect_entropy_uses_injected_source() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // 复位池状态（测试自包含，避免并行测试残留）。
        POOL.lock().state = [0; 4];
        POOL.lock().index = 0;
        POOL.lock().added = 0;
        FAKE_ENTROPY.store(0x1000, std::sync::atomic::Ordering::Relaxed);
        set_entropy_source(fake_source);
        assert!(entropy_source_ready());
        assert_eq!(collect_entropy(4), 4);
        assert_eq!(entropy_estimate(), 4);
        // 池状态应被注入值影响。
        assert_ne!(POOL.lock().state, [0; 4]);
        POOL.lock().source = 0;
    }

    #[test]
    fn seed_global_rng_changes_sequence() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // 固定初始状态（确定性）。
        *GLOBAL.lock() = Xoshiro256::new(1);
        let a1 = rand_u64();
        let a2 = rand_u64();

        // 混入不同熵并重新播种。
        POOL.lock().state = [0xDEAD, 0xBEEF, 0xCAFE, 0x1234];
        POOL.lock().added = 99;
        seed_global_rng();
        let b1 = rand_u64();
        let b2 = rand_u64();

        // 播种后序列应变化（概率上几乎必然）。
        assert!(
            a1 != b1 || a2 != b2,
            "reseed must change the output sequence"
        );
    }

    #[test]
    fn global_rng_api_works() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _ = rand_u64();
        let _ = rand_u32();
        let v = rand_range(100, 200);
        assert!((100..200).contains(&v));
        let mut buf = [0u8; 16];
        rand_bytes(&mut buf);
        assert!(buf.iter().any(|&b| b != 0));
    }
}
