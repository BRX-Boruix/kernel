//! x86-64 CPU 特性探测与硬件熵（CPUID / RDRAND / RDSEED）。
//!
//! - [`cpuid`]：CPUID 指令原始封装（leaf/subleaf → 四个输出寄存器）；
//! - [`init`]：一次性探测并缓存厂商/品牌/特性位（BSP 单线程阶段调用）；
//! - [`has_feature`]：查缓存位判断特性，无需再执行 CPUID；
//! - [`rdrand64`]/[`rdseed64`]：硬件熵读取（指令不可用或连续失败返回 `None`）；
//! - [`entropy_u64`]：熵池注入源（rdseed → rdrand → 时钟/常数垫底）。
//!
//! 实现 [`arch::cpu::Cpu`] trait，供通用内核代码跨架构调用。

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use arch::cpu::CpuFeature;

/// CPUID 输出（四个寄存器）。
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuIdResult {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

/// 执行 CPUID（leaf/subleaf），返回 eax/ebx/ecx/edx。
///
/// `nomem, nostack`：CPUID 不改内存/栈。**不能**加 `preserves_flags`
/// （CPUID 会修改 EFLAGS 部分位）。
#[inline]
pub fn cpuid(leaf: u32, subleaf: u32) -> CpuIdResult {
    let mut eax = leaf;
    let mut ecx = subleaf;
    let mut tmp: u64;
    let mut ebx: u32;
    let edx: u32;
    unsafe {
        core::arch::asm!(
            // rbx 是 LLVM 保留寄存器，不能直接作操作数。先把它转存到通用
            // 寄存器（LLVM 分配时自动避开 rbx），CPUID 后再取出结果并恢复。
            "mov {tmp}, rbx",
            "cpuid",
            "mov {ebx:e}, ebx",
            "mov rbx, {tmp}",
            tmp = out(reg) tmp,
            ebx = out(reg) ebx,
            inout("eax") eax,
            inout("ecx") ecx,
            out("edx") edx,
            options(nomem, nostack),
        );
    }
    CpuIdResult { eax, ebx, ecx, edx }
}

// ---------- 探测结果缓存（init 填充，此后只读） ----------

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static MAX_BASIC: AtomicU32 = AtomicU32::new(0);
static MAX_EXT: AtomicU32 = AtomicU32::new(0);
/// 特性位图：bit i ↔ `CpuFeature` 枚举索引 i。
static FEATURES: AtomicU64 = AtomicU64::new(0);

/// 厂商字符串缓冲（12 字节 + NUL）。
static mut VENDOR_BUF: [u8; 16] = [0; 16];
/// 品牌字符串缓冲（48 字节 + NUL）。
static mut BRAND_BUF: [u8; 49] = [0; 49];

fn set_feat(feat: &mut u64, f: CpuFeature, on: bool) {
    if on {
        *feat |= 1u64 << (f as u32);
    }
}

/// 探测并缓存 CPU 特性。只允许在 BSP 单线程阶段调用（写 static mut）。
pub fn init() {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    // 基础 leaf 0：最大 leaf + 厂商字符串（ebx/edx/ecx 按小端拼接 12 字节）。
    let r0 = cpuid(0, 0);
    let max_basic = r0.eax;
    let mut vendor = [0u8; 16];
    vendor[0..4].copy_from_slice(&r0.ebx.to_le_bytes());
    vendor[4..8].copy_from_slice(&r0.edx.to_le_bytes());
    vendor[8..12].copy_from_slice(&r0.ecx.to_le_bytes());
    unsafe {
        core::ptr::copy_nonoverlapping(
            vendor.as_ptr(),
            core::ptr::addr_of_mut!(VENDOR_BUF).cast::<u8>(),
            16,
        );
    }
    MAX_BASIC.store(max_basic, Ordering::Relaxed);

    // 扩展 leaf 0x80000000：最大扩展 leaf。
    let max_ext = if max_basic >= 0x8000_0000 {
        cpuid(0x8000_0000, 0).eax
    } else {
        0
    };
    MAX_EXT.store(max_ext, Ordering::Relaxed);

    // ---- 特性位 ----
    let mut feat = 0u64;
    if max_basic >= 1 {
        let r1 = cpuid(1, 0);
        set_feat(&mut feat, CpuFeature::Mmx, r1.edx & (1 << 23) != 0);
        set_feat(&mut feat, CpuFeature::Sse, r1.edx & (1 << 25) != 0);
        set_feat(&mut feat, CpuFeature::Sse2, r1.edx & (1 << 26) != 0);
        set_feat(&mut feat, CpuFeature::Sse3, r1.ecx & (1 << 0) != 0);
        set_feat(&mut feat, CpuFeature::Pclmulqdq, r1.ecx & (1 << 1) != 0);
        set_feat(&mut feat, CpuFeature::Ssse3, r1.ecx & (1 << 9) != 0);
        set_feat(&mut feat, CpuFeature::Fma, r1.ecx & (1 << 12) != 0);
        set_feat(&mut feat, CpuFeature::Sse41, r1.ecx & (1 << 19) != 0);
        set_feat(&mut feat, CpuFeature::Sse42, r1.ecx & (1 << 20) != 0);
        set_feat(&mut feat, CpuFeature::Popcnt, r1.ecx & (1 << 23) != 0);
        set_feat(&mut feat, CpuFeature::Aes, r1.ecx & (1 << 25) != 0);
        set_feat(&mut feat, CpuFeature::Xsave, r1.ecx & (1 << 26) != 0);
        set_feat(&mut feat, CpuFeature::Avx, r1.ecx & (1 << 28) != 0);
        set_feat(&mut feat, CpuFeature::Rdrand, r1.ecx & (1 << 30) != 0);
    }
    if max_basic >= 7 {
        let r7 = cpuid(7, 0);
        set_feat(&mut feat, CpuFeature::Bmi1, r7.ebx & (1 << 3) != 0);
        set_feat(&mut feat, CpuFeature::Avx2, r7.ebx & (1 << 5) != 0);
        set_feat(&mut feat, CpuFeature::Bmi2, r7.ebx & (1 << 8) != 0);
        set_feat(&mut feat, CpuFeature::Rdseed, r7.ebx & (1 << 18) != 0);
        set_feat(&mut feat, CpuFeature::Adx, r7.ebx & (1 << 19) != 0);
        set_feat(&mut feat, CpuFeature::Sha, r7.ebx & (1 << 29) != 0);
    }
    if max_ext >= 0x8000_0001 {
        let rx = cpuid(0x8000_0001, 0);
        set_feat(&mut feat, CpuFeature::Syscall, rx.edx & (1 << 11) != 0);
        set_feat(&mut feat, CpuFeature::Nx, rx.edx & (1 << 20) != 0);
        set_feat(&mut feat, CpuFeature::Abm, rx.ecx & (1 << 5) != 0);
        set_feat(&mut feat, CpuFeature::Sse4a, rx.ecx & (1 << 6) != 0);
    }
    FEATURES.store(feat, Ordering::Relaxed);

    // ---- 品牌字符串（leaf 0x80000002..=0x80000004，共 48 字节）----
    if max_ext >= 0x8000_0004 {
        let mut brand = [0u8; 49];
        let leaves = [
            cpuid(0x8000_0002, 0),
            cpuid(0x8000_0003, 0),
            cpuid(0x8000_0004, 0),
        ];
        let mut off = 0;
        for l in &leaves {
            for reg in [l.eax, l.ebx, l.ecx, l.edx] {
                brand[off..off + 4].copy_from_slice(&reg.to_le_bytes());
                off += 4;
            }
        }
        unsafe {
            core::ptr::copy_nonoverlapping(
                brand.as_ptr(),
                core::ptr::addr_of_mut!(BRAND_BUF).cast::<u8>(),
                49,
            );
        }
    }
}

/// 最大基础 leaf（调试用）。
pub fn max_basic_leaf() -> u32 {
    MAX_BASIC.load(Ordering::Relaxed)
}

/// 最大扩展 leaf（调试用）。
pub fn max_extended_leaf() -> u32 {
    MAX_EXT.load(Ordering::Relaxed)
}

/// 是否支持指定特性（查缓存位）。
pub fn has_feature(feature: CpuFeature) -> bool {
    FEATURES.load(Ordering::Relaxed) & (1u64 << (feature as u32)) != 0
}

/// 厂商 ID（如 "GenuineIntel"、"AuthenticAMD"；未 init 时为空串）。
pub fn vendor_id() -> &'static str {
    let p = core::ptr::addr_of!(VENDOR_BUF).cast::<u8>();
    let mut n = 0;
    while n < 12 && unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    unsafe { core::str::from_utf8_unchecked(core::slice::from_raw_parts(p, n)) }
}

/// 品牌字符串（如 "QEMU Virtual CPU version 2.5+"；未 init 时为空串）。
pub fn brand_string() -> &'static str {
    let p = core::ptr::addr_of!(BRAND_BUF).cast::<u8>();
    let mut n = 0;
    while n < 48 && unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    // 尾部常有填充空格，去掉。
    while n > 0 && unsafe { *p.add(n - 1) } == b' ' {
        n -= 1;
    }
    unsafe { core::str::from_utf8_unchecked(core::slice::from_raw_parts(p, n)) }
}

// ---------- 硬件熵 ----------

/// 单次 RDRAND 尝试。`ok` 由 CF 置位表示成功（硬件熵就绪）。
#[inline]
fn rdrand_attempt() -> Option<u64> {
    let mut out: u64;
    let mut ok: u8;
    unsafe {
        core::arch::asm!(
            "rdrand {out}",
            "setc {ok}",
            out = out(reg) out,
            ok = lateout(reg_byte) ok,
            // 不能加 preserves_flags：RDRAND 会修改 CF。
            options(nomem, nostack),
        );
    }
    if ok != 0 {
        Some(out)
    } else {
        None
    }
}

/// 单次 RDSEED 尝试。
#[inline]
fn rdseed_attempt() -> Option<u64> {
    let mut out: u64;
    let mut ok: u8;
    unsafe {
        core::arch::asm!(
            "rdseed {out}",
            "setc {ok}",
            out = out(reg) out,
            ok = lateout(reg_byte) ok,
            options(nomem, nostack),
        );
    }
    if ok != 0 {
        Some(out)
    } else {
        None
    }
}

/// 读 64 位硬件真随机数（RDRAND）。指令不可用或连续 10 次失败返回 `None`。
///
/// 先查 CPUID 特性位再执行指令：不支持的 CPU 上执行 `rdrand` 会触发 #UD。
pub fn rdrand64() -> Option<u64> {
    if !has_feature(CpuFeature::Rdrand) {
        return None;
    }
    // Intel 建议：重试最多 10 次，仍失败按故障处理。
    for _ in 0..10 {
        if let Some(v) = rdrand_attempt() {
            return Some(v);
        }
    }
    None
}

/// 读 64 位硬件种子（RDSEED）。指令不可用或连续 10 次失败返回 `None`。
pub fn rdseed64() -> Option<u64> {
    if !has_feature(CpuFeature::Rdseed) {
        return None;
    }
    for _ in 0..10 {
        if let Some(v) = rdseed_attempt() {
            return Some(v);
        }
    }
    None
}

/// 熵池注入源：rdseed → rdrand → 时钟/常数垫底。
///
/// 无 RDRAND/RDSEED 的 CPU（或 QEMU 未开 `-cpu host` 的虚拟机）下，
/// 混合单调时钟扰动，保证熵池至少不是完全可预测的全零输入。
pub fn entropy_u64() -> u64 {
    if let Some(v) = rdseed64() {
        return v;
    }
    if let Some(v) = rdrand64() {
        return v;
    }
    klib::time::now_nanos().rotate_left(17) ^ 0x9E37_79B9_7F4A_7C15
}

// ---------- arch::cpu::Cpu 实现 ----------

/// x86-64 CPU 特性/熵实现（转发到本模块）。
pub struct X8664Cpu;

impl arch::cpu::Cpu for X8664Cpu {
    fn init() {
        crate::cpu::init();
    }

    fn vendor_id() -> &'static str {
        crate::cpu::vendor_id()
    }

    fn brand_string() -> &'static str {
        crate::cpu::brand_string()
    }

    fn max_basic_leaf() -> u32 {
        crate::cpu::max_basic_leaf()
    }

    fn has_feature(feature: CpuFeature) -> bool {
        crate::cpu::has_feature(feature)
    }

    fn rdrand64() -> Option<u64> {
        crate::cpu::rdrand64()
    }

    fn rdseed64() -> Option<u64> {
        crate::cpu::rdseed64()
    }

    fn entropy_u64() -> u64 {
        crate::cpu::entropy_u64()
    }
}
