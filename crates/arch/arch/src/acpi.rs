//! ACPI 表解析（纯数据结构 + 校验，ADR-007 可测风格）。
//!
//! 本模块只做**与访问机制无关**的解析与校验：
//! - [`parse_rsdp`]：RSDP（Root System Description Pointer）表头解析；
//! - [`parse_sdt_header`]：SDT（System Description Table）公共表头解析；
//! - [`checksum_valid`]：ACPI 校验和验证（表内所有字节和 ≡ 0 mod 256）；
//! - [`entry_count`]：RSDT/XSDT 中的表条目数。
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
    if header.length as usize <= SDT_HEADER_LEN {
        return 0;
    }
    (header.length as usize - SDT_HEADER_LEN) / entry_size
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;

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
}
