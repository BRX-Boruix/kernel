//! x86-64 ACPI 表获取与解析（limine RSDP + HHDM 物理映射）。
//!
//! - RSDP 由 limine `RsdpRequest` 提供（`Ptr<u8>` 可直接访问）；
//! - RSDT/XSDT 中的表条目是**物理地址**，经 HHDM（`arch::phys_to_virt`）
//!   映射后读取；
//! - 解析出 FADT 关键字段（DSDT 地址、PM1 控制块、reset 寄存器等），
//!   为 shutdown/reboot/电源管理铺路。

use core::mem::size_of;

use arch::acpi::{
    Hpet, SDT_HEADER_LEN, SdtHeader, checksum_valid, entry_count, parse_hpet, parse_rsdp,
    parse_sdt_header,
};
use arch::phys_to_virt;

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

/// 初始化 ACPI：从 limine 获取 RSDP → 校验 → 遍历 RSDT/XSDT → 找 FADT。
///
/// 返回解析结果；任一环节缺失（无 RSDP / 表不存在 / 校验失败）返回 `None`
/// 并打印诊断。
pub fn init() -> Option<AcpiInfo> {
    let resp = RSDP_REQUEST.get_response().get()?;
    let rsdp_ptr = resp.address.as_ptr()? as *const u8;

    // 读取 RSDP 前 36 字节（ACPI 2.0 布局）。
    // SAFETY: limine 保证 RSDP 可访问，长度 ≥ 36（revision 2）或 ≥ 20。
    let rsdp_bytes = unsafe { core::slice::from_raw_parts(rsdp_ptr, 36) };
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
