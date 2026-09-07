//! ACPI 表解析（纯数据结构 + 校验，ADR-007 可测风格）。
//!
//! 本模块只做**与访问机制无关**的解析与校验：
//! - [`parse_rsdp`]：RSDP（Root System Description Pointer）表头解析；
//! - [`parse_sdt_header`]：SDT（System Description Table）公共表头解析；
//! - [`checksum_valid`]：ACPI 校验和验证（表内所有字节和 ≡ 0 mod 256）；
//! - [`entry_count`]：RSDT/XSDT 中的表条目数；
//! - [`parse_hpet`]：HPET 表关键字段解析（高精度事件定时器）。
//!
//! 具体的内存访问（limine RSDP 请求、HHDM 物理映射）由架构实现
//! （`arch-x86_64::acpi`）负责，本模块输入字节切片即可单测。

/// RSDP 签名 `"RSD PTR "`。
pub const RSDP_SIGNATURE: [u8; 8] = *b"RSD PTR ";
/// SDT 公共表头长度（signature 4 + length 4 + revision 1 + checksum 1 +
/// oem_id 6 + oem_table_id 8 + oem_revision 4 + creator_id 4 + creator_rev 4）。
pub const SDT_HEADER_LEN: usize = 36;

/// 解析后的 RSDP。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rsdp {
    /// 1 = ACPI 1.0（仅 RSDT，32 位）；2+ = ACPI 2.0+（XSDT，64 位）。
    pub revision: u8,
    /// RSDT 物理地址（ACPI 1.0）。
    pub rsdt_address: u32,
    /// XSDT 物理地址（ACPI 2.0+）。
    pub xsdt_address: u64,
    /// RSDP 表总长（ACPI 2.0+ 才有；1.0 为 20）。
    pub length: u32,
}

/// SDT 公共表头。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SdtHeader {
    /// 4 字节签名（如 `FACP`、`APIC`、`DSDT`）。
    pub signature: [u8; 4],
    /// 表总长（含表头）。
    pub length: u32,
    pub revision: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
}

impl SdtHeader {
    /// 签名是否为 `sig`。
    pub const fn is(&self, sig: &[u8; 4]) -> bool {
        self.signature[0] == sig[0]
            && self.signature[1] == sig[1]
            && self.signature[2] == sig[2]
            && self.signature[3] == sig[3]
    }
}

/// 解析 RSDP（输入须 ≥ 20 字节；ACPI 2.0 需 ≥ 36 字节完整解析）。
///
/// 先校验签名，返回 `None` 表示非 RSDP 表或输入过短。
pub fn parse_rsdp(buf: &[u8]) -> Option<Rsdp> {
    if buf.len() < 20 {
        return None;
    }
    if &buf[0..8] != &RSDP_SIGNATURE {
        return None;
    }
    let revision = buf[15];
    let rsdt_address = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
    // ACPI 2.0+：offset 20 = length，offset 24 = XSDT 64 位地址。
    let (length, xsdt_address) = if buf.len() >= 36 {
        let l = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);
        let x = u64::from_le_bytes([
            buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
        ]);
        (l, x)
    } else {
        // ACPI 1.0：无 length/xsdt 字段。
        (0, 0)
    };
    Some(Rsdp {
        revision,
        rsdt_address,
        xsdt_address,
        length,
    })
}

/// 解析 SDT 公共表头（输入须 ≥ 36 字节）。
pub fn parse_sdt_header(buf: &[u8]) -> Option<SdtHeader> {
    if buf.len() < SDT_HEADER_LEN {
        return None;
    }
    let mut signature = [0u8; 4];
    signature.copy_from_slice(&buf[0..4]);
    let length = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let mut oem_id = [0u8; 6];
    oem_id.copy_from_slice(&buf[10..16]);
    let mut oem_table_id = [0u8; 8];
    oem_table_id.copy_from_slice(&buf[16..24]);
    Some(SdtHeader {
        signature,
        length,
        revision: buf[8],
        oem_id,
        oem_table_id,
    })
}

/// ACPI 校验和：表内所有字节和模 256 应为 0。
pub fn checksum_valid(data: &[u8]) -> bool {
    let mut sum: u32 = 0;
    for &b in data {
        sum += b as u32;
    }
    (sum & 0xFF) == 0
}

/// RSDT/XSDT 中的表条目数（表长减去公共表头后按条目大小整除）。
///
/// `entry_size`：RSDT 为 4（32 位物理地址），XSDT 为 8（64 位）。
pub fn entry_count(header: &SdtHeader, entry_size: usize) -> usize {
    // S31：entry_size==0 时除法除零 panic——调用方传 0 即视为无条目，
    // 绝不在不可信输入上做未守卫除法。
    if header.length as usize <= SDT_HEADER_LEN || entry_size == 0 {
        return 0;
    }
    (header.length as usize - SDT_HEADER_LEN) / entry_size
}

// ---------- HPET 表 ----------

/// HPET 表关键字段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hpet {
    /// 硬件修订 ID + 能力标志（bit15 = LEGACY_REPLACEMENT_IRQ_ROUTING）。
    pub hardware_rev_id: u32,
    /// 比较器个数（表中存 N-1，此处为实际 N）。
    pub comparator_count: u8,
    /// 计数器时钟周期（飞秒，fs）。14.31818MHz → 约 69_841_192 fs。
    /// 0 = 无效（QEMU 某些配置）。
    pub counter_clock_period_fs: u32,
    /// 硬件寄存器基址（System Memory 空间，如 0xFED00000）。
    pub base_addr: u64,
    /// 页保护属性（0 = 无保护，1 = 4KB 页，2 = 64KB 页）。
    pub page_protect: u8,
}

/// 解析 HPET 表（输入须 ≥ 60 字节）。
///
/// HPET 表存在两种主要布局：
/// - **旧式布局**（HPET 1.0 / QEMU，表长 60）：
///   - offset 36: Event Timer Block ID（4 字节，含修订号/厂商）；
///   - offset 40: Base Address（**8 字节裸地址**，如 0xFED00000）；
///   - offset 48: HPET Sequence Number（4 字节）；
///   - offset 52: Main Counter Minimum Clock Ticks（4 字节）；
///   - offset 56: Page Protection and OEM Attribute（4 字节）。
/// - **ACPI 3.0+ 布局**（真机常见，表长 76）：
///   - offset 36: Hardware Rev ID（4 字节）；
///   - offset 40: Comparator Count（4 字节，N-1）；
///   - offset 44: Counter Clock Period（4 字节，飞秒）；
///   - offset 48: Reserved（4 字节）；
///   - offset 52: 基址 GAS（12 字节：address_space 1B + bit_width 1B +
///     bit_offset 1B + access_size 1B + address 8B）；
///   - offset 64: HPET Sequence Number（4 字节）；
///   - offset 68: Minimum Clock Ticks Periodic Interrupt（4 字节）；
///   - offset 72: Page Protection and OEM Attribute（4 字节）。
///
/// 两种布局的**时钟周期均可能缺失/为 0**（QEMU 不填），真实周期放在
/// 硬件寄存器 `General Capabilities and ID Register`（offset 0x00）的
/// bit 32-63，由驱动读取。本函数不要求周期非 0。
///
/// 基址探测：先取旧式布局 offset 40 的 8 字节裸地址；为 0 时再取
/// ACPI 3.0+ GAS（offset 52 address_space=0 时 offset 56 的地址）。
pub fn parse_hpet(buf: &[u8]) -> Option<Hpet> {
    // 最小 52 字节：足以覆盖 QEMU 布局（表长 56，基址在 offset 44..52）。
    if buf.len() < 52 {
        return None;
    }
    let hardware_rev_id = u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]);
    let comparator_count = u8::from_le_bytes([buf[40]]) + 1; // 表中存 N-1
    let counter_clock_period_fs = u32::from_le_bytes([buf[44], buf[45], buf[46], buf[47]]);

    // 基址探测。按表长区分布局：
    // - **ACPI 3.0+ 布局**（表长 ≥ 76）：offset 52 为 GAS 的 address_space
    //   （0 = System Memory），地址在 offset 56（8 字节）；
    // - **QEMU 布局**（实测表长 56）：offset 44 为 8 字节裸基址
    //   （实测 0xfed00000）；
    // - **旧式 HPET 1.0 布局**（表长 60）：offset 40 为 8 字节裸基址。
    // 后两种均无 GAS。QEMU 布局的 offset 44 优先（其 offset 40-43 是
    // 保留/低地址字段恒 0），为 0 时回退旧式 offset 40。
    let mut base_addr: u64 = 0;
    if buf.len() >= 76 {
        if buf[52] == 0 {
            // ACPI 3.0+：GAS address_space=SystemMemory，地址在 offset 56。
            base_addr = u64::from_le_bytes([
                buf[56], buf[57], buf[58], buf[59], buf[60], buf[61], buf[62], buf[63],
            ]);
        }
        // S07：ACPI 3.0+ 表（≥76 字节）且 address_space!=0 时，GAS 地址
        // 不是 MMIO 基址，不可用。此时**不**回退到旧式 offset 44/40 裸地址
        // 解析——那会把周期字段（counter_clock_period_fs）误读为基址，
        // 输出伪造的非零基址（S07 高项）。如实返回 None，由上层降级。
    } else if buf.len() >= 52 {
        // 短表（<76 字节，QEMU 56 字节 / 旧式 HPET 1.0 60 字节）：
        // QEMU 布局：offset 44 起 8 字节裸基址。
        base_addr = u64::from_le_bytes([
            buf[44], buf[45], buf[46], buf[47], buf[48], buf[49], buf[50], buf[51],
        ]);
        if base_addr == 0 && buf.len() >= 60 {
            // 旧式 HPET 1.0：offset 40 起 8 字节裸基址。
            base_addr = u64::from_le_bytes([
                buf[40], buf[41], buf[42], buf[43], buf[44], buf[45], buf[46], buf[47],
            ]);
        }
    }
    let page_protect = if buf.len() >= 76 { buf[72] & 0x03 } else { 0 };

    // 基址必须非 0。这不是"拒绝魔法值"的形式主义：物理地址 0 是 x86 实模式
    // 中断向量表/BIOS 数据区（ACPI 规范中 HPET 基址合法域为 MMIO 空间，
    // 0xFED0_0000 起），基址解析为 0 = 三种布局全部探测失败的**信号**而非
    // 真实地址——如实 None，由上层走"HPET 缺席"降级路径（审计 B12 裁决）。
    // 时钟周期允许为 0（驱动从硬件寄存器读取）。
    if base_addr == 0 {
        return None;
    }

    Some(Hpet {
        hardware_rev_id,
        comparator_count,
        counter_clock_period_fs,
        base_addr,
        page_protect,
    })
}

// ---------- S5 (soft-off) sleep state ----------

/// S5 (soft-off) sleep-state package info, decoded from the DSDT `_S5` object.
/// Per ACPI, writing SLP_TYPa into the PM1x_CNT SLP_TYP field with SLP_EN set
/// transitions the machine to S5 (power off).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S5 {
    /// SLP_TYPa value for PM1a control block.
    pub slp_typa: u8,
    /// SLP_TYPb value for PM1b control block.
    pub slp_typb: u8,
}

/// AML NameOp opcode.
pub const AML_NAME_OP: u8 = 0x08;
/// AML PackageOp opcode.
pub const AML_PACKAGE_OP: u8 = 0x12;
/// AML Zero constant.
pub const AML_ZERO_OP: u8 = 0x00;
/// AML One constant.
pub const AML_ONE_OP: u8 = 0x01;
/// AML Ones constant.
pub const AML_ONES_OP: u8 = 0xff;
/// AML BytePrefix opcode (followed by 1 raw byte).
pub const AML_BYTE_PREFIX: u8 = 0x0a;
/// AML WordPrefix opcode (followed by 2 raw bytes, LE).
pub const AML_WORD_PREFIX: u8 = 0x0b;
/// AML DWordPrefix opcode (followed by 4 raw bytes, LE).
pub const AML_DWORD_PREFIX: u8 = 0x0c;
/// The ACPI NameSeg for `_S5` (4-char name with trailing pad `_`).
pub const S5_NAMESEG: [u8; 4] = [0x5f, 0x53, 0x35, 0x5f]; // '_' 'S' '5' '_'

/// Decode a single-byte/multi-byte AML PkgLength starting at `pos`.
/// Returns `(length, bytes_consumed)`. Bounds-guarded against untrusted input.
fn parse_pkg_length(buf: &[u8], pos: usize) -> Option<(u32, usize)> {
    let lead = *buf.get(pos)?;
    match lead & 0xC0 {
        0x00 => Some(((lead & 0x3F) as u32, 1)),
        0x40 => {
            let n = *buf.get(pos + 1)?;
            Some((((lead & 0x3F) as u32) | ((n as u32) << 6), 2))
        }
        0x80 => {
            let n1 = *buf.get(pos + 1)?;
            let n2 = *buf.get(pos + 2)?;
            Some((((lead & 0x3F) as u32) | ((n1 as u32) << 6) | ((n2 as u32) << 12), 3))
        }
        _ => {
            let n1 = *buf.get(pos + 1)?;
            let n2 = *buf.get(pos + 2)?;
            let n3 = *buf.get(pos + 3)?;
            Some((((lead & 0x3F) as u32) | ((n1 as u32) << 6) | ((n2 as u32) << 12) | ((n3 as u32) << 18), 4))
        }
    }
}

/// Decode an AML integer literal at `pos` (Zero/One/Ones/Byte/Word/DWord).
/// Returns `(value, next_pos)`. Bounds-guarded.
fn parse_aml_const_int(buf: &[u8], pos: usize) -> Option<(u64, usize)> {
    let b = *buf.get(pos)?;
    match b {
        AML_ZERO_OP => Some((0, pos + 1)),
        AML_ONE_OP => Some((1, pos + 1)),
        AML_ONES_OP => Some((u64::MAX, pos + 1)),
        AML_BYTE_PREFIX => Some((*buf.get(pos + 1)? as u64, pos + 2)),
        AML_WORD_PREFIX => {
            let lo = *buf.get(pos + 1)? as u64;
            let hi = *buf.get(pos + 2)? as u64;
            Some((lo | (hi << 8), pos + 3))
        }
        AML_DWORD_PREFIX => {
            let mut v: u64 = 0;
            for k in 0..4 { v |= (*buf.get(pos + 1 + k)? as u64) << (8 * k); }
            Some((v, pos + 5))
        }
        _ => None, // not a plain integer literal (method call, package, etc.)
    }
}

/// Scan the DSDT AML body for the `_S5` Name object and decode its S5 package.
///
/// QEMU (and common firmware) emit `Name(_S5, Package(N){ slp_typa, slp_typb, ... })`.
/// We locate the NameOp `_S5_` seg then interpret the object as a PackageOp whose
/// first two integer elements are SLP_TYPa / SLP_TYPb. Returns None on any ambiguity
/// or unsupported encoding (never fabricates a value).
pub fn parse_s5(dsdt: &[u8]) -> Option<S5> {
    // Skip the 36-byte SDT header; the AML body begins after it.
    let mut i = SDT_HEADER_LEN;
    while i + 4 < dsdt.len() {
        if dsdt[i] == AML_NAME_OP && dsdt[i + 1..].starts_with(&S5_NAMESEG) {
            if let Some(s5) = decode_s5_object(dsdt, i + 1 + 4) {
                return Some(s5);
            }
        }
        i += 1;
    }
    None
}

/// Decode a PackageOp element count at `pos`. ACPI CA emits the element count
/// as a raw small byte (2..=255); some firmware prefix it with BytePrefix (0x0a).
/// Handle the raw-byte form and the prefixed form; anything else returns None.
fn decode_count(buf: &[u8], pos: usize) -> Option<(u64, usize)> {
    let b = *buf.get(pos)?;
    if b == AML_BYTE_PREFIX {
        return Some((*buf.get(pos + 1)? as u64, pos + 2));
    }
    // Raw small byte count (ACPI CA emits Package(N) count as a bare byte).
    // Also covers the const forms Zero(0x00)/One(0x01) for empty/single packages.
    Some((b as u64, pos + 1))
}

/// Decode the object following `_S5_` (starting at `obj_pos`) into an S5.
fn decode_s5_object(dsdt: &[u8], obj_pos: usize) -> Option<S5> {
    if dsdt.get(obj_pos)? != &AML_PACKAGE_OP {
        // Firmware may express _S5 via a Method/Return; not handled -> refuse.
        return None;
    }
    let (len, len_bytes) = parse_pkg_length(dsdt, obj_pos + 1)?;
    let content_start = obj_pos + 1 + len_bytes;
    let content_end = content_start.checked_add(len as usize)?;
    if content_end > dsdt.len() { return None; }
    // First field is the element count. ACPI CA emits the count as a raw small
    // byte (e.g. Package(4) -> 0x04); some compilers use a prefixed integer.
    // Handle both: raw byte in [2,255], or an AML integer literal.
    let (count, mut p) = decode_count(dsdt, content_start)?;
    if count == 0 || count > 256 { return None; }
    let mut slp_typa: Option<u64> = None;
    let mut slp_typb: Option<u64> = None;
    for _ in 0..count {
        if p >= content_end { return None; }
        let (v, np) = parse_aml_const_int(dsdt, p)?;
        if slp_typa.is_none() { slp_typa = Some(v); }
        else if slp_typb.is_none() { slp_typb = Some(v); break; }
        p = np;
    }
    Some(S5 { slp_typa: slp_typa? as u8, slp_typb: slp_typb? as u8 })
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    /// 构造校验和正确的表（把 checksum 字节设为使总和为 0 的值）。
    fn with_valid_checksum(data: &mut [u8]) {
        let sum: u32 = data.iter().map(|&b| b as u32).sum();
        // 将 checksum 字节（offset 9）设为使总和对 256 取模为 0。
        data[9] = data[9].wrapping_sub((sum & 0xFF) as u8);
    }

    #[test]
    fn rsdp_v1_parse() {
        let mut buf = [0u8; 20];
        buf[0..8].copy_from_slice(&RSDP_SIGNATURE);
        buf[15] = 1; // revision 1
        buf[16..20].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let rsdp = parse_rsdp(&buf).unwrap();
        assert_eq!(rsdp.revision, 1);
        assert_eq!(rsdp.rsdt_address, 0xDEAD_BEEF);
        assert_eq!(rsdp.xsdt_address, 0);
        assert_eq!(rsdp.length, 0);
    }

    #[test]
    fn rsdp_v2_parse() {
        let mut buf = [0u8; 36];
        buf[0..8].copy_from_slice(&RSDP_SIGNATURE);
        buf[15] = 2;
        buf[16..20].copy_from_slice(&0x1111_1111u32.to_le_bytes());
        buf[20..24].copy_from_slice(&36u32.to_le_bytes());
        buf[24..32].copy_from_slice(&0x2222_3333_4444_5555u64.to_le_bytes());
        let rsdp = parse_rsdp(&buf).unwrap();
        assert_eq!(rsdp.revision, 2);
        assert_eq!(rsdp.rsdt_address, 0x1111_1111);
        assert_eq!(rsdp.length, 36);
        assert_eq!(rsdp.xsdt_address, 0x2222_3333_4444_5555);
    }

    #[test]
    fn rsdp_bad_signature_rejected() {
        let buf = [0u8; 20]; // 全零，签名不符
        assert!(parse_rsdp(&buf).is_none());
    }

    #[test]
    fn sdt_header_parse() {
        let mut buf = [0u8; 36];
        buf[0..4].copy_from_slice(b"FACP");
        buf[4..8].copy_from_slice(&64u32.to_le_bytes());
        buf[8] = 5;
        buf[10..16].copy_from_slice(b"OEMID ");
        buf[16..24].copy_from_slice(b"OEMTABID");
        let h = parse_sdt_header(&buf).unwrap();
        assert!(h.is(b"FACP"));
        assert_eq!(h.length, 64);
        assert_eq!(h.revision, 5);
        assert_eq!(&h.oem_id, b"OEMID ");
        assert_eq!(&h.oem_table_id, b"OEMTABID");
    }

    #[test]
    fn checksum_roundtrip() {
        let mut buf = [0u8; 36];
        buf[0..4].copy_from_slice(b"FACP");
        buf[4..8].copy_from_slice(&64u32.to_le_bytes());
        buf[10] = 0xAB;
        buf[30] = 0xCD;
        // 初值校验失败。
        assert!(!checksum_valid(&buf));
        with_valid_checksum(&mut buf);
        assert!(checksum_valid(&buf));
    }

    #[test]
    fn entry_counts() {
        // XSDT：表头 36 + 3 个 8 字节条目 = 60。
        let mut buf = [0u8; 36];
        buf[0..4].copy_from_slice(b"XSDT");
        buf[4..8].copy_from_slice(&60u32.to_le_bytes());
        let h = parse_sdt_header(&buf).unwrap();
        assert_eq!(entry_count(&h, 8), 3);
        assert_eq!(entry_count(&h, 4), 6);
    }

    #[test]
    fn hpet_parse_standard_layout() {
        // 标准布局：GAS 在 offset 52，周期字段在 offset 44。
        let mut buf = [0u8; 76];
        buf[0..4].copy_from_slice(b"HPET");
        buf[4..8].copy_from_slice(&76u32.to_le_bytes());
        buf[8] = 1; // revision
        // offset 36: Hardware Rev ID（bit15 = legacy routing capable）
        buf[36..40].copy_from_slice(&0x8001u32.to_le_bytes());
        // offset 40: Comparator Count（N-1 = 2 → 3 个比较器）
        buf[40] = 2;
        // offset 44: Counter Clock Period = 69_841_192 fs（14.31818MHz）
        buf[44..48].copy_from_slice(&69_841_192u32.to_le_bytes());
        // offset 52: GAS address_space = 0（System Memory）
        buf[52] = 0;
        // offset 56: GAS address = 0xFED00000
        buf[56..64].copy_from_slice(&0xFED0_0000u64.to_le_bytes());
        // offset 72: page protect = 0（无保护）
        buf[72] = 0;

        let h = parse_hpet(&buf).unwrap();
        assert_eq!(h.hardware_rev_id, 0x8001);
        assert_eq!(h.comparator_count, 3);
        assert_eq!(h.counter_clock_period_fs, 69_841_192);
        assert_eq!(h.base_addr, 0xFED0_0000);
        assert_eq!(h.page_protect, 0);
    }

    #[test]
    fn hpet_parse_qemu_layout() {
        // QEMU 布局（实测）：表长 56，offset 44 为 8 字节裸基址，
        // 无周期字段（恒 0，周期由硬件寄存器提供）。
        let mut buf = [0u8; 56];
        buf[0..4].copy_from_slice(b"HPET");
        buf[4..8].copy_from_slice(&56u32.to_le_bytes());
        buf[8] = 1;
        // offset 36: Event Timer Block ID（实测 0x8086a201：Intel vendor）
        buf[36..40].copy_from_slice(&0x8086_a201u32.to_le_bytes());
        // offset 44: 8 字节裸基址（offset 44-47 恰是基址低 32 位，
        // 会被 `counter_clock_period_fs` 字段读到——QEMU 表无周期字段，
        // 该值无意义，驱动从硬件寄存器读取真实周期）。
        buf[44..52].copy_from_slice(&0xFED0_0000u64.to_le_bytes());

        let h = parse_hpet(&buf).unwrap();
        assert_eq!(h.base_addr, 0xFED0_0000);
        // 表内无周期字段（offset 44-47 被基址占用），周期由硬件提供。
        assert_eq!(h.counter_clock_period_fs as u64, 0xFED0_0000);
        assert_eq!(h.page_protect, 0);
    }

    #[test]
    fn hpet_parse_legacy_layout() {
        // 旧式 HPET 1.0 布局：表长 60，offset 40 为 8 字节裸基址。
        let mut buf = [0u8; 60];
        buf[0..4].copy_from_slice(b"HPET");
        buf[4..8].copy_from_slice(&60u32.to_le_bytes());
        buf[8] = 1;
        // offset 36: Event Timer Block ID
        buf[36..40].copy_from_slice(&0x8001u32.to_le_bytes());
        // offset 40: 8 字节裸基址（offset 44 为高 32 位，故 offset 44 起 8 字节为 0，
        // 应回退到 offset 40）
        buf[40..48].copy_from_slice(&0xFED0_0000u64.to_le_bytes());

        let h = parse_hpet(&buf).unwrap();
        assert_eq!(h.base_addr, 0xFED0_0000);
        assert_eq!(h.counter_clock_period_fs, 0);
        assert_eq!(h.page_protect, 0);
    }

    #[test]
    fn hpet_rejects_bad_input() {
        // 过短
        assert!(parse_hpet(&[0u8; 40]).is_none());
        // 完整表但基址为 0 → None
        let mut buf = [0u8; 76];
        buf[0..4].copy_from_slice(b"HPET");
        buf[4..8].copy_from_slice(&76u32.to_le_bytes());
        buf[8] = 1;
        buf[52] = 0;
        buf[56..64].copy_from_slice(&0u64.to_le_bytes());
        assert!(parse_hpet(&buf).is_none());
        // 旧式布局但 offset 40 基址为 0 → None
        let mut buf = [0u8; 60];
        buf[0..4].copy_from_slice(b"HPET");
        buf[4..8].copy_from_slice(&60u32.to_le_bytes());
        buf[8] = 1;
        assert!(parse_hpet(&buf).is_none());
    }

    /// S07 回归：ACPI 3.0+ 表（≥76 字节）且 GAS address_space != 0 时，
    /// parse_hpet 必须返回 None，不得把周期字段（offset 44..47）误读为
    /// 伪造基址——旧实现在 address_space!=0 时跳过 GAS 分支后回退到
    /// offset 44 裸地址，若 counter_clock_period_fs 非零则输出假基址。
    #[test]
    fn hpet_acpi3_nonzero_address_space_returns_none() {
        let mut buf = [0u8; 76];
        buf[0..4].copy_from_slice(b"HPET");
        buf[4..8].copy_from_slice(&76u32.to_le_bytes());
        buf[8] = 1;
        // 周期字段 offset 44 设非零（修复前会被误读为基址裸地址）
        buf[44..48].copy_from_slice(&69_841_192u32.to_le_bytes());
        // GAS address_space = 1（SystemIO 等非 MMIO 类型）
        buf[52] = 1;
        // GAS 地址 offset 56 设 0（不可用）
        buf[56..64].copy_from_slice(&0u64.to_le_bytes());

        assert!(
            parse_hpet(&buf).is_none(),
            "S07: ACPI 3.0+ with address_space!=0 must return None, not fake base from period field"
        );
    }

    // Build a DSDT-sized buffer with the given AML body starting right after the
    // 36-byte SDT header, then call parse_s5.
    fn dsdt_with_body(body: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 36];
        b[0..4].copy_from_slice(b"DSDT");
        b[4..8].copy_from_slice(&((36 + body.len()) as u32).to_le_bytes());
        b.extend_from_slice(body);
        b
    }

    #[test]
    fn s5_parse_canonical_name_package() {
        // Name(_S5, Package(4){0x05, 0x05, Zero, Zero}), placed past the SDT header.
        let mut full: Vec<u8> = vec![0u8; 36];
        full[0..4].copy_from_slice(b"DSDT");
        full.extend_from_slice(&[0x08, 0x5f, 0x53, 0x35, 0x5f, 0x12, 0x07, 0x04, 0x0a, 0x05, 0x0a, 0x05, 0x00, 0x00]);
        let len = full.len();
        full[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        let s5 = parse_s5(&full).expect("canonical _S5 package should decode");
        assert_eq!(s5.slp_typa, 5);
        assert_eq!(s5.slp_typb, 5);
    }

    #[test]
    fn s5_parse_qemu_observed_layout() {
        // Bytes captured from the real QEMU DSDT around the _S5_ name:
        //   NameOp(08) _S5_  PackageOp(12) len(06) count(04) 00 00 00 00 ...
        // (element count emitted as a raw byte; elements are Zero).
        let mut full: Vec<u8> = vec![0u8; 36];
        full[0..4].copy_from_slice(b"DSDT");
        full.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // leading unrelated bytes
            0x08, 0x5f, 0x53, 0x35, 0x5f, // NameOp _S5_
            0x12, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00, 0x10, 0x3b,
        ]);
        let len = full.len();
        full[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        let s5 = parse_s5(&full).expect("QEMU observed _S5 layout should decode");
        assert_eq!(s5.slp_typa, 0);
        assert_eq!(s5.slp_typb, 0);
    }

    #[test]
    fn s5_rejects_non_package_or_truncated() {
        // _S5 defined as something other than a Package -> None (no fabrication).
        let mut full: Vec<u8> = vec![0u8; 36];
        full[0..4].copy_from_slice(b"DSDT");
        full.extend_from_slice(&[0x08, 0x5f, 0x53, 0x35, 0x5f, 0x14, 0x06]); // MethodOp 0x14
        let len = full.len();
        full[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        assert!(parse_s5(&full).is_none());
        // No _S5_ present at all -> None.
        let mut full2 = vec![0u8; 36];
        full2[0..4].copy_from_slice(b"DSDT");
        full2[4..8].copy_from_slice(&(40u32).to_le_bytes());
        full2.extend_from_slice(&[0x08, 0x5f, 0x53, 0x33, 0x5f]); // _S3_ not _S5_
        assert!(parse_s5(&full2).is_none());
    }
}

