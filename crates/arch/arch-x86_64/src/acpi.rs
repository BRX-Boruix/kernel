//! x86-64 ACPI 表获取与解析（limine RSDP + HHDM 物理映射）。
//!
//! - RSDP 由 limine `RsdpRequest` 提供（`Ptr<u8>` 可直接访问）；
//! - RSDT/XSDT 中的表条目是**物理地址**，经 HHDM（`arch::phys_to_virt`）
//!   映射后读取；
//! - 解析出 FADT 关键字段（DSDT 地址、PM1 控制块、reset 寄存器等），
//!   为 shutdown/reboot/电源管理铺路。

use core::mem::size_of;

use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU8, Ordering};

use arch::acpi::{
    Hpet, SDT_HEADER_LEN, SdtHeader, checksum_valid, entry_count, parse_hpet, parse_rsdp,
    parse_s5, parse_sdt_header,
};
use arch::phys_to_virt;

use crate::port;

/// limine RSDP 请求（启动时由 limine 填充）。
#[limine::limine_tag]
static RSDP_REQUEST: limine::RsdpRequest = limine::RsdpRequest::new(0);

/// 解析出的关键 ACPI 表信息。
#[derive(Debug, Clone, Copy)]
pub struct AcpiInfo {
    /// RSDP 版本（1 = ACPI 1.0，2 = ACPI 2.0+）。
    pub rsdp_revision: u8,
    /// FADT 物理地址（找到则非 0）。
    pub fadt_addr: u64,
    /// DSDT 物理地址（FADT 中给出）。
    pub dsdt_addr: u64,
    /// PM1a 控制寄存器块端口（FADT offset 116，16 位）。
    pub pm1a_cnt: u16,
    /// PM1b 控制寄存器块端口（FADT offset 120，16 位）。
    pub pm1b_cnt: u16,
    /// ACPI reset 寄存器信息（FADT offset 116 处的 GAS + 值）。
    pub reset_reg: Option<(u8, u16, u32)>, // (address_space, port, value)
    /// HPET 表关键字段（`None` = 未找到/无效，见 `arch::acpi::parse_hpet`）。
    pub hpet: Option<Hpet>,
}

// ---------- 电源管理（shutdown / reboot）运行时状态 ----------

/// PM1a 控制块 I/O 端口（0 = 未解析到）。
static PM1A_CNT: AtomicU16 = AtomicU16::new(0);
/// PM1b 控制块 I/O 端口（0 = 无 PM1b）。
static PM1B_CNT: AtomicU16 = AtomicU16::new(0);
/// DSDT `_S5` 解出的 SLP_TYPa（S5 睡眠类型 a）。
static S5_SLP_TYPA: AtomicU8 = AtomicU8::new(0);
/// DSDT `_S5` 解出的 SLP_TYPb（S5 睡眠类型 b）。
static S5_SLP_TYPB: AtomicU8 = AtomicU8::new(0);
/// 是否已成功解析出完整的 S5 电源关停信息（pm1a 端口非 0 且 `_S5` 可用）。
static S5_READY: AtomicBool = AtomicBool::new(false);
/// ACPI reset 寄存器 I/O 端口（0 = 无）。
static RESET_PORT: AtomicU16 = AtomicU16::new(0);
/// ACPI reset 寄存器写值。
static RESET_VALUE: AtomicU8 = AtomicU8::new(0);

/// PM1x_CNT 寄存器里 SLP_TYP 字段的位偏移（ACPI：bits 10-12）。
const SLP_TYP_SHIFT: u16 = 10;
/// PM1x_CNT 寄存器里 SLP_EN（sleep enable）位（ACPI：bit 13）。
const SLP_EN_BIT: u16 = 1 << 13;

/// ACPI PM1a_CNT I/O 端口是否已解析（非 0）。
pub fn pm1a_port() -> u16 { PM1A_CNT.load(Ordering::Acquire) }

/// S5 电源关停信息是否已就绪（pm1a 端口 + `_S5` 均可用）。
pub fn s5_ready() -> bool { S5_READY.load(Ordering::Acquire) }

/// 解析 DSDT 的 `_S5` 并把电源关停信息缓存到模块静态。
/// 由 `init()` 在 FADT 解析成功后调用；dsdt_addr 为 0 或解析失败时如实留空。
fn cache_s5(dsdt_addr: u64) {
    if dsdt_addr == 0 {
        klib::warn!("[acpi] no DSDT; S5 power-off unavailable");
        return;
    }
    let dsdt_va = phys_to_virt(dsdt_addr);
    // 直接读 DSDT 自身表头长度（S5 包可能在 4KB 之后，sdt_at 的 4KB 上限不适用）。
    let hdr = unsafe { core::slice::from_raw_parts(dsdt_va as *const u8, SDT_HEADER_LEN) };
    let Some(hdr) = parse_sdt_header(hdr) else {
        klib::warn!("[acpi] DSDT header parse failed; S5 power-off unavailable");
        return;
    };
    let len = hdr.length as usize;
    if len < SDT_HEADER_LEN || len > 0x100000 {
        klib::warn!("[acpi] DSDT length {:#x} out of range; S5 unavailable", len);
        return;
    }
    // SAFETY: dsdt 由 ACPI 表提供并经 HHDM 映射；长度来自其自身表头（已界上限）。
    let body = unsafe { core::slice::from_raw_parts(dsdt_va as *const u8, len) };
    match parse_s5(body) {
        Some(s5) => {
            S5_SLP_TYPA.store(s5.slp_typa, Ordering::Release);
            S5_SLP_TYPB.store(s5.slp_typb, Ordering::Release);
            // 就绪判定：需同时有 PM1a 控制块端口（供写入）与解析出的 `_S5`。
            S5_READY.store(PM1A_CNT.load(Ordering::Acquire) != 0, Ordering::Release);
            klib::info!(
                "[acpi] S5: pm1a={:#x} slp_typa={} slp_typb={}",
                PM1A_CNT.load(Ordering::Acquire),
                s5.slp_typa,
                s5.slp_typb
            );
        }
        None => {
            klib::warn!("[acpi] DSDT has no parseable _S5; S5 power-off unavailable");
        }
    }
}

/// 请求 ACPI 软关机（S5）：向 PM1a/PM1b 控制块写入 SLP_TYP 并置 SLP_EN。
/// 成功后机器断电、本函数永不返回；电源关停信息未就绪时返回 `false`。
///
/// 注意：调用方须已停止其它 CPU 并关闭中断；本函数最后在 `cli` + 忙等中
/// 等待断电生效（QEMU/真机通常在 SLP_EN 写入后即断电）。
pub fn power_off() -> bool {
    if !S5_READY.load(Ordering::Acquire) {
        return false;
    }
    let pm1a = PM1A_CNT.load(Ordering::Acquire);
    let pm1b = PM1B_CNT.load(Ordering::Acquire);
    let ta = S5_SLP_TYPA.load(Ordering::Acquire) as u16;
    let tb = S5_SLP_TYPB.load(Ordering::Acquire) as u16;
    klib::info!(
        "[acpi] power_off: PM1a={:#x} value={:#x} PM1b={:#x} value={:#x}",
        pm1a,
        (ta << SLP_TYP_SHIFT) | SLP_EN_BIT,
        pm1b,
        (tb << SLP_TYP_SHIFT) | SLP_EN_BIT
    );
    // 先写 SLP_TYP 字段（不置 SLP_EN），再一次性写入 SLP_EN——按 ACPI 语义
    // 一次写亦可，但分两步对部分固件更稳。此处直接写含 SLP_EN 的完整值。
    if pm1a != 0 {
        let v = (ta << SLP_TYP_SHIFT) | SLP_EN_BIT;
        port::outw(pm1a, v);
    }
    if pm1b != 0 {
        let v = (tb << SLP_TYP_SHIFT) | SLP_EN_BIT;
        port::outw(pm1b, v);
    }
    // 断电后 CPU 停止；若固件未立即断电（罕见），则在关中断忙等中等待。
    loop {
        unsafe { core::arch::asm!("cli", options(nomem, nostack, preserves_flags)) };
        core::hint::spin_loop();
    }
}

/// 请求系统重启。优先 ACPI reset 寄存器（若固件提供），否则回退 8042 控制器
/// 快速复位（写 0x64 端口 0xFE，QEMU/SeaBIOS 均支持）。成功后机器复位、本函数
/// 永不返回；返回 `false` 表示两种机制都不适用（调用方保留）。
pub fn reboot() -> bool {
    let rp = RESET_PORT.load(Ordering::Acquire);
    if rp != 0 {
        let rv = RESET_VALUE.load(Ordering::Acquire);
        klib::info!("[acpi] reboot via ACPI reset port {:#x} value {:#x}", rp, rv);
        port::outb(rp, rv);
    }
    // 8042 快速复位（写 0x64 = 0xFE 触发系统复位）。
    klib::info!("[acpi] reboot via 8042 (port 0x64 <- 0xFE)");
    port::outb(0x64, 0xFE);
    // 复位后 CPU 重启；若未生效则忙等。
    loop {
        unsafe { core::arch::asm!("cli", options(nomem, nostack, preserves_flags)) };
        core::hint::spin_loop();
    }
}

/// 初始化 ACPI：从 limine 获取 RSDP → 校验 → 遍历 RSDT/XSDT → 找 FADT。
///
/// 返回解析结果；任一环节缺失（无 RSDP / 表不存在 / 校验失败）返回 `None`
/// 并打印诊断。
pub fn init() -> Option<AcpiInfo> {
    let resp = RSDP_REQUEST.get_response().get()?;
    let rsdp_ptr = resp.address.as_ptr()? as *const u8;

    // S31/S19：不得无条件读 36 字节。ACPI 1.0 RSDP 仅 20 字节；ACPI 2.0+
    // 为 36 字节（或按 offset20 的 length 字段更长）。分两阶段读取：
    //   1) 先读 20 字节（两种版本的最小公共布局），从 offset15 取 revision；
    //   2) 若 revision >= 2，从 offset20 取 length 字段并按该值读取完整 RSDP。
    // 否则保持 20 字节 ACPI 1.0 布局。
    // SAFETY: limine 保证 RSDP 物理页已映射且长度至少 20 字节。
    let base20 = unsafe { core::slice::from_raw_parts(rsdp_ptr, 20) };
    let rev = base20[15];
    let total_len = if rev >= 2 {
        // 读取 length 字段（offset 20，u32 LE）。ACPI 2.0+ RSDP 长度恒 >= 36。
        let len_slice = unsafe { core::slice::from_raw_parts(rsdp_ptr.add(20), 4) };
        let len = u32::from_le_bytes([len_slice[0], len_slice[1], len_slice[2], len_slice[3]]) as usize;
        len.max(36)
    } else {
        20
    };
    let rsdp_bytes = unsafe { core::slice::from_raw_parts(rsdp_ptr, total_len) };
    let rsdp = parse_rsdp(rsdp_bytes)?;
    klib::info!(
        "[acpi] RSDP rev={} rsdt={:#x} xsdt={:#x}",
        rsdp.revision,
        rsdp.rsdt_address,
        rsdp.xsdt_address
    );

    // 遍历 XSDT（ACPI 2.0+）或 RSDT（ACPI 1.0）找 FADT。
    let (xsdt_vaddr, n_entries, entry_size) = if rsdp.revision >= 2 && rsdp.xsdt_address != 0 {
        let va = phys_to_virt(rsdp.xsdt_address);
        let header = sdt_at(va)?;
        let n = entry_count(&header, size_of::<u64>());
        klib::info!("[acpi] XSDT: {} entries", n);
        (va, n, size_of::<u64>())
    } else if rsdp.rsdt_address != 0 {
        let va = phys_to_virt(rsdp.rsdt_address as u64);
        let header = sdt_at(va)?;
        let n = entry_count(&header, size_of::<u32>());
        klib::info!("[acpi] RSDT: {} entries", n);
        (va, n, size_of::<u32>())
    } else {
        klib::warn!("[acpi] no RSDT/XSDT address in RSDP");
        return None;
    };

    // 逐个查找 FACP（FADT）与 HPET 表。FADT 必需；HPET 可选。
    let mut fadt_addr: u64 = 0;
    let mut hpet: Option<Hpet> = None;
    for i in 0..n_entries {
        // SAFETY: 表条目数组在 XSDT 表内（表长已验证）。
        let entry: u64 = unsafe {
            core::ptr::read_unaligned(
                (xsdt_vaddr as *const u8)
                    .add(SDT_HEADER_LEN + i * entry_size)
                    .cast::<u64>(),
            )
        };
        // RSDT 是 32 位条目。
        let addr = if entry_size == 8 {
            entry
        } else {
            (entry as u32) as u64
        };
        if addr == 0 {
            continue;
        }
        let va = phys_to_virt(addr);
        if let Some(hdr) = sdt_at(va) {
            if hdr.is(b"FACP") {
                fadt_addr = addr;
            } else if hdr.is(b"HPET") {
                // 读取 HPET 表关键字段（基址/周期/比较器数）。
                // SAFETY: `va` 指向已验证的 HPET 表（表长已由 sdt_at 校验）。
                let buf =
                    unsafe { core::slice::from_raw_parts(va as *const u8, hdr.length as usize) };
                hpet = parse_hpet(buf);
                if hpet.is_none() {
                    // 诊断：打印表长与关键偏移字节（Event Timer Block ID、
                    // 周期、QEMU 布局基址、GAS），便于排查布局差异。
                    let at = |i: usize| if i < buf.len() { buf[i] } else { 0 };
                    klib::warn!(
                        "[acpi] HPET table present but invalid: len={} id={:#x} period={:#x} base48={:#x} base56={:#x}",
                        buf.len(),
                        u32::from_le_bytes([at(36), at(37), at(38), at(39)]),
                        u32::from_le_bytes([at(44), at(45), at(46), at(47)]),
                        u64::from_le_bytes([
                            at(48),
                            at(49),
                            at(50),
                            at(51),
                            at(52),
                            at(53),
                            at(54),
                            at(55)
                        ]),
                        u64::from_le_bytes([
                            at(56),
                            at(57),
                            at(58),
                            at(59),
                            at(60),
                            at(61),
                            at(62),
                            at(63)
                        ]),
                    );
                }
            }
        }
    }

    if fadt_addr == 0 {
        klib::warn!("[acpi] FADT not found");
        return None;
    }
    klib::info!("[acpi] FADT at {:#x}", fadt_addr);
    if let Some(h) = &hpet {
        klib::info!(
            "[acpi] HPET: base={:#x} period={}fs comparators={} rev={:#x} page_protect={}",
            h.base_addr,
            h.counter_clock_period_fs,
            h.comparator_count,
            h.hardware_rev_id,
            h.page_protect
        );
    } else {
        klib::info!("[acpi] HPET: not present");
    }

    // 解析 FADT 关键字段（表过短等异常 → 整体放弃 ACPI 信息，绝不带垃圾值）。
    let fadt_va = phys_to_virt(fadt_addr);
    let fadt = parse_fadt(fadt_va)?;
    klib::info!(
        "[acpi] FADT: dsdt={:#x} pm1a_cnt={:#x} pm1b_cnt={:#x} reset={:?}",
        fadt.dsdt_addr,
        fadt.pm1a_cnt,
        fadt.pm1b_cnt,
        fadt.reset_reg
    );

    // 电源管理状态缓存：PM1 端口 + ACPI reset 寄存器 + DSDT `_S5` 解析。
    PM1A_CNT.store(fadt.pm1a_cnt, Ordering::Release);
    PM1B_CNT.store(fadt.pm1b_cnt, Ordering::Release);
    if let Some((space, port, value)) = fadt.reset_reg {
        // ACPI reset GAS：仅 System I/O 空间（space==1）可用；此时把端口与写值缓存。
        if space == 1 {
            RESET_PORT.store(port, Ordering::Release);
            RESET_VALUE.store(value as u8, Ordering::Release);
        }
    }
    cache_s5(fadt.dsdt_addr);

    Some(AcpiInfo {
        rsdp_revision: rsdp.revision,
        fadt_addr,
        dsdt_addr: fadt.dsdt_addr,
        pm1a_cnt: fadt.pm1a_cnt,
        pm1b_cnt: fadt.pm1b_cnt,
        reset_reg: fadt.reset_reg,
        hpet,
    })
}

/// 在物理地址对应的 HHDM 虚拟地址读取 SDT 表头。
fn sdt_at(va: u64) -> Option<SdtHeader> {
    // SAFETY: 表指针由 ACPI 表提供，limine/HHDM 保证该物理地址已映射；
    // 先读 36 字节表头判断长度，再校验整表。
    let slice = unsafe { core::slice::from_raw_parts(va as *const u8, SDT_HEADER_LEN) };
    let hdr = parse_sdt_header(slice)?;
    // 整表校验（表长来自表头，防御异常长度）。
    let len = hdr.length as usize;
    if len < SDT_HEADER_LEN || len > 0x1000 {
        return None;
    }
    let full = unsafe { core::slice::from_raw_parts(va as *const u8, len) };
    if !checksum_valid(full) {
        klib::warn!(
            "[acpi] checksum failed for '{}'",
            core::str::from_utf8(&hdr.signature).unwrap_or("????")
        );
        return None;
    }
    Some(hdr)
}

/// FADT 关键字段。
#[derive(Debug, Clone, Copy)]
struct Fadt {
    dsdt_addr: u64,
    pm1a_cnt: u16,
    pm1b_cnt: u16,
    reset_reg: Option<(u8, u16, u32)>,
}

/// 解析 FADT 关键字段（字段偏移按 ACPI 6.x FADT 布局）。
///
/// AM5：先读表头取**实际**长度，再按长度逐字段解析——遗留固件可能提供
/// 短于现代布局的 FADT（QEMU 实测为 ACPI 1.0 的 116 字节），按现代布局
/// 盲读会越过表尾读到相邻物理内存并把垃圾当真值上送 AcpiInfo。正确处置
/// 不是整表拒绝（那会把真实存在的 DSDT/PM1 控制块一并丢弃，导致 HPET/
/// 时钟精度连锁丢失——实测 sleep_us 精度断言失败），而是"字段存在才读取"：
/// - len ≥ 44：DSDT u32 @40；
/// - len ≥ 148：X_DSDT u64 @140（仅当 u32 字段为 0 时采用）；
/// - len ≥ 70：PM1a/PM1b_CNT_BLK u32 @64/@68；
/// - len ≥ 129：RESET_REG GAS @116 + RESET_VALUE @128。
fn parse_fadt(va: u64) -> Option<Fadt> {
    /// 各消费字段的最低表长要求（最深偏移 + 字段宽度）。
    const LEN_DSDT32: usize = 44;
    const LEN_PM1_CNT: usize = 70;
    const LEN_X_DSDT: usize = 148;
    const LEN_RESET: usize = 129;

    let hdr_slice =
        unsafe { core::slice::from_raw_parts(va as *const u8, SDT_HEADER_LEN) };
    let hdr = parse_sdt_header(hdr_slice)?;
    let actual_len = hdr.length as usize;
    if actual_len < LEN_DSDT32 {
        klib::warn!(
            "[acpi] FADT too short to contain any usable field: length={actual_len}, need>={LEN_DSDT32}"
        );
        return None;
    }

    // SAFETY: `va` 指向 HHDM 已映射物理页；以下每个 from_raw_parts 的长度
    // 都不超过表头声明的实际 length（逐段校验过），不越界。
    // DSDT 地址：offset 40 的 32 位字段优先；offset 140 的 64 位扩展字段
    // 只在 32 位字段为 0 且表足够长时才用（QEMU 的 64 位字段常为厂商字符
    // 串残留，如 "BXPC" 会被误读为地址）。
    let b32 = unsafe { core::slice::from_raw_parts(va as *const u8, LEN_DSDT32) };
    let dsdt32 = u32::from_le_bytes([b32[40], b32[41], b32[42], b32[43]]);
    let dsdt_addr = if actual_len >= LEN_X_DSDT {
        let b = unsafe { core::slice::from_raw_parts(va as *const u8, LEN_X_DSDT) };
        let dsdt64 = u64::from_le_bytes([
            b[140], b[141], b[142], b[143], b[144], b[145], b[146], b[147],
        ]);
        if dsdt32 != 0 { dsdt32 as u64 } else { dsdt64 }
    } else {
        dsdt32 as u64
    };

    if actual_len < LEN_PM1_CNT {
        klib::warn!(
            "[acpi] FADT lacks PM1a/PM1b_CNT_BLK (length={actual_len} < {LEN_PM1_CNT}); power management unavailable"
        );
        return Some(Fadt {
            dsdt_addr,
            pm1a_cnt: 0,
            pm1b_cnt: 0,
            reset_reg: None,
        });
    }
    let b = unsafe { core::slice::from_raw_parts(va as *const u8, LEN_PM1_CNT) };
    // PM1 控制块端口（4 字节字段，端口在低 16 位）：
    // offset 64 = PM1a_CNT_BLK，offset 68 = PM1b_CNT_BLK。
    let pm1a_cnt = u16::from_le_bytes([b[64], b[65]]);
    let pm1b_cnt = u16::from_le_bytes([b[68], b[69]]);

    // Reset 寄存器：offset 116 的 GAS（12 字节）+ offset 128 的 reset 值；
    // 仅当表实际包含该区域（len ≥ 129）时解析，短表一律 None。
    let reset_reg = if actual_len >= LEN_RESET {
        let b = unsafe { core::slice::from_raw_parts(va as *const u8, LEN_RESET) };
        let reg_space = b[116];
        let reg_port = u16::from_le_bytes([b[120], b[121]]);
        let reset_value = b[128];
        // GAS 的 address_space：0 = System Memory，1 = System I/O。
        if reg_space == 1 && reg_port != 0 {
            Some((reg_space, reg_port, reset_value as u32))
        } else {
            None
        }
    } else {
        None
    };

    Some(Fadt {
        dsdt_addr,
        pm1a_cnt,
        pm1b_cnt,
        reset_reg,
    })
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;

    /// 用测试用的静态缓冲模拟 FADT（不可直接跑真机测试，仅结构验证）。
    #[test]
    fn fadt_layout_constants() {
        // 与 ACPI 规范一致的偏移常量（防止后续误改）。
        assert_eq!(arch::acpi::SDT_HEADER_LEN, 36);
        assert_eq!(size_of::<u64>(), 8);
        assert_eq!(size_of::<u32>(), 4);
    }
}
