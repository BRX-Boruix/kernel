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

use crate::mmio;
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
    let mut ebx: u32;
    let edx: u32;
    unsafe {
        core::arch::asm!(
            // rbx 是 LLVM 保留寄存器，不能直接作操作数。先把它转存到通用
            // 寄存器（LLVM 分配时自动避开 rbx），CPUID 后再取出结果并恢复。
            // `tmp` 只是中转，值不读 → 用 `_` 丢弃输出。
            "mov {tmp}, rbx",
            "cpuid",
            "mov {ebx:e}, ebx",
            "mov rbx, {tmp}",
            tmp = out(reg) _,
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
        set_feat(&mut feat, CpuFeature::Smep, r7.ebx & (1 << 20) != 0);
        set_feat(&mut feat, CpuFeature::Smap, r7.ebx & (1 << 7) != 0);
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
    if ok != 0 { Some(out) } else { None }
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
    if ok != 0 { Some(out) } else { None }
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

/// 熵池注入源：rdseed → rdrand → 时钟扰动保底。
///
/// 无 RDRAND/RDSEED 的 CPU（或 QEMU 未开 `-cpu host` 的虚拟机）下，
/// 混合单调时钟扰动，保证熵池至少不是完全可预测的全零输入。
/// 返回 `Some(v)` 始终有值（硬件熵或时钟扰动）；调用方通过 `Option`
/// 知晓这不是纯硬件熵，不可用于密钥种子等对真随机有要求的场景
/// （S07/S09/S10：有源时如实返回硬件熵，无源时返回确定性扰动而非
/// 静默 0 或伪造硬件熵）。
pub fn entropy_u64() -> Option<u64> {
    if let Some(v) = rdseed64() {
        return Some(v);
    }
    if let Some(v) = rdrand64() {
        return Some(v);
    }
    // S09：无真熵且时钟未就绪（now_nanos() 为 None）时如实返回 None，绝不
    // 把确定性时间戳当熵垫底——确定性数据不是随机熵，用于密钥会破坏安全性。
    klib::time::now_nanos().map(|n| n.rotate_left(17) ^ 0x9E37_79B9_7F4A_7C15)
}

// ---------- SMEP / SMAP 硬件防护 ----------

/// 开启 SMEP/SMAP（内核/用户地址空间严格隔离）。
///
/// - **SMEP**（`CR4.SMEP`, bit 20）：禁止内核态（CPL=0）执行用户页（U=1）代码，
///   杜绝"内核跳板到用户页"类提权；内核本就不执行用户代码（仅 `iretq` 切回
///   Ring 3 合法进入），故天然安全，开启即生效。
/// - **SMAP**（`CR4.SMAP`, bit 21）：禁止内核态读写用户页，仅经 [`mmio::stac`]
///   临时放行（内核访问用户缓冲区如 syscall 参数拷贝时必须包裹）。
///
/// 经 CPUID.7.0 `EBX` 检测支持性：SMEP=bit20、SMAP=bit7；不支持则跳过对应位，
/// 避免在未实现该特性的 CPU 上写 CR4 触发 #GP。SMAP 真正开启后调用
/// [`mmio::set_smap_active`] 标记，使 `stac`/`clac` 在非 SMAP 平台退化为 no-op
/// （防止在不支持 SMAP 的 CPU 上执行 `stac`/`clac` 触发 #UD）。
///
/// 须在分页已启用、长模式运行后调用（BSP 早期；AP 在各自启动路径也应调用）。
pub fn enable_smep_smap() {
    const SMEP: u64 = 1 << 20;
    const SMAP: u64 = 1 << 21;
    const FSGSBASE: u64 = 1 << 16;
    let smep_ok = has_feature(CpuFeature::Smep);
    let smap_ok = has_feature(CpuFeature::Smap);
    // FSGSBASE（用户态 RDFSBASE/WRFSBASE 等）支持位：CPUID.7.0:EBX[9]。
    // 使每线程 TLS/errno（threads.md T2-1）可在用户态经 RDFSBASE 读 FS base；
    // 不扩展共享 CpuFeature 枚举（避免跨架构 trait 同步），仅本 x86 直查。
    let fsgsbase_ok = max_basic_leaf() >= 7 && cpuid(7, 0).ebx & (1 << 9) != 0;

    let mut cr4 = mmio::read_cr4();
    if smep_ok {
        cr4 |= SMEP;
    }
    if smap_ok {
        cr4 |= SMAP;
        mmio::set_smap_active(true);
    }
    if fsgsbase_ok {
        cr4 |= FSGSBASE;
    }
    mmio::write_cr4(cr4);

    klib::info!(
        "[cpu] SMEP={} SMAP={} FSGSBASE={} enabled (CR4={:#x})",
        smep_ok,
        smap_ok,
        fsgsbase_ok,
        cr4
    );
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

    fn entropy_u64() -> Option<u64> {
        crate::cpu::entropy_u64()
    }
}
