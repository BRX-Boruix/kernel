//! MBR 主引导记录分区表解析器（C13.1，纯逻辑、无 IO、宿主可测）。
//!
//! 布局事实源：`sdk/sdk_build/disk.py`——签名 `55 AA` @510，
//! 分区表 4 项 @0x1BE，每项 16 字节：+0 boot flag、+4 类型、
//! +8 起始 LBA（LE u32）、+12 扇区数（LE u32）。CHS 字段不参与解析。

/// 签名字节 @510。
pub const MBR_SIG_BYTE0: u8 = 0x55;
/// 签名字节 @511。
pub const MBR_SIG_BYTE1: u8 = 0xAA;
/// 分区表项数（MBR 规范固定 4）。
pub const PARTITION_ENTRY_COUNT: usize = 4;
/// 分区表起始偏移。
pub const PARTITION_TABLE_OFFSET: usize = 0x1BE;
/// 单个分区表项大小。
pub const PARTITION_ENTRY_SIZE: usize = 16;
/// MBR 磁盘签名偏移（4 字节 LE，Windows 磁盘签名 / Limine `mbr_disk_id` 来源）。
pub const MBR_DISK_SIG_OFFSET: usize = 0x1B8;

/// 解析错误。签名不符时整个扇区不能被信任为 MBR。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MbrError {
    BadSignature,
}

/// 单个分区表项。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartitionEntry {
    pub boot_flag: u8,
    /// 分区类型字节；0 表示空槽位（如 disk.py 只填第 1 项）。
    pub part_type: u8,
    pub start_lba: u32,
    pub sector_count: u32,
}

impl PartitionEntry {
    pub fn is_empty(&self) -> bool {
        self.part_type == 0
    }
}

/// 解析后的 MBR。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mbr {
    pub partitions: [PartitionEntry; PARTITION_ENTRY_COUNT],
    /// MBR 磁盘签名 @0x1B8（4 字节 LE）。0 表示未声明（boot 来源比对时
    /// 视为"无签名"而非"签名等于 0"，S09 宁缺毋假）。
    pub disk_signature: u32,
}

impl Mbr {
    /// 第一个非空分区（disk.py 的镜像即第 1 项）。
    pub fn first_partition(&self) -> Option<PartitionEntry> {
        self.partitions.iter().copied().find(|p| !p.is_empty())
    }
}

/// 解析 512 字节 LBA0 扇区。
///
/// 先校验 `55 AA` 签名（不符则整个扇区内容不可信，立即报错），
/// 再按固定偏移解码 4 个分区表项。CHS 字段被有意忽略——LBA 是唯一寻址事实。
pub fn parse_mbr(sector: &[u8; 512]) -> Result<Mbr, MbrError> {
    if sector[510] != MBR_SIG_BYTE0 || sector[511] != MBR_SIG_BYTE1 {
        return Err(MbrError::BadSignature);
    }
    let mut partitions = [PartitionEntry {
        boot_flag: 0,
        part_type: 0,
        start_lba: 0,
        sector_count: 0,
    }; PARTITION_ENTRY_COUNT];
    for (i, slot) in partitions.iter_mut().enumerate() {
        let base = PARTITION_TABLE_OFFSET + i * PARTITION_ENTRY_SIZE;
        slot.boot_flag = sector[base];
        slot.part_type = sector[base + 4];
        slot.start_lba = u32::from_le_bytes(
            sector[base + 8..base + 12].try_into().expect("fixed 4-byte slice"),
        );
        slot.sector_count = u32::from_le_bytes(
            sector[base + 12..base + 16].try_into().expect("fixed 4-byte slice"),
        );
    }
    let disk_signature = u32::from_le_bytes(
        sector[MBR_DISK_SIG_OFFSET..MBR_DISK_SIG_OFFSET + 4]
            .try_into()
            .expect("fixed 4-byte slice"),
    );
    Ok(Mbr {
        partitions,
        disk_signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个与 disk.py 完全一致的 LBA0：
    /// 签名 + 第 1 项 (active=0x80, type=0x83, start=2048, count=N-2048)。
    fn disk_py_sector(total_sectors: u32) -> [u8; 512] {
        let mut s = [0u8; 512];
        s[510] = 0x55;
        s[511] = 0xAA;
        let p = PARTITION_TABLE_OFFSET;
        s[p] = 0x80;
        s[p + 4] = 0x83;
        s[p + 8..p + 12].copy_from_slice(&2048u32.to_le_bytes());
        s[p + 12..p + 16].copy_from_slice(&(total_sectors - 2048).to_le_bytes());
        s
    }

    #[test]
    fn test_mbr_disk_signature_parsed() {
        // MBR 磁盘签名 @0x1B8（4 字节 LE）如实读回；全零即未声明。
        let mut s = disk_py_sector(131072);
        s[MBR_DISK_SIG_OFFSET..MBR_DISK_SIG_OFFSET + 4]
            .copy_from_slice(&0x424F5255u32.to_le_bytes());
        let mbr = parse_mbr(&s).expect("parse");
        assert_eq!(mbr.disk_signature, 0x424F5255);
        // 全零签名 = 未声明。
        let s2 = disk_py_sector(131072);
        let mbr2 = parse_mbr(&s2).expect("parse");
        assert_eq!(mbr2.disk_signature, 0);
    }

    #[test]
    fn test_mbr_parse_disk_py_layout() {
        let sector = disk_py_sector(131072); // 64MB 镜像
        let mbr = parse_mbr(&sector).expect("disk.py layout must parse");
        let p1 = mbr.first_partition().expect("partition 1 present");
        assert_eq!(p1.boot_flag, 0x80);
        assert_eq!(p1.part_type, 0x83);
        assert_eq!(p1.start_lba, 2048);
        assert_eq!(p1.sector_count, 131072 - 2048);
        // 其余三项为空
        assert!(mbr.partitions[1].is_empty());
        assert!(mbr.partitions[2].is_empty());
        assert!(mbr.partitions[3].is_empty());
    }

    #[test]
    fn test_mbr_bad_signature_rejected() {
        // 全零扇区：无签名
        let sector = [0u8; 512];
        assert_eq!(parse_mbr(&sector), Err(MbrError::BadSignature));
        // 只有半个签名也不行（对抗：字节序颠倒）
        let mut s = [0u8; 512];
        s[510] = 0xAA;
        s[511] = 0x55;
        assert_eq!(parse_mbr(&s), Err(MbrError::BadSignature));
    }

    #[test]
    fn test_mbr_all_empty_partitions() {
        let mut s = [0u8; 512];
        s[510] = 0x55;
        s[511] = 0xAA;
        let mbr = parse_mbr(&s).expect("signature valid");
        assert!(
            mbr.first_partition().is_none(),
            "no partition entries => no first partition"
        );
    }

    #[test]
    fn test_mbr_first_partition_skips_empty_slots() {
        let mut s = [0u8; 512];
        s[510] = 0x55;
        s[511] = 0xAA;
        // 仅第 3 槽位有值（对抗：非首槽位布局）
        let base = PARTITION_TABLE_OFFSET + 2 * PARTITION_ENTRY_SIZE;
        s[base + 4] = 0x0C;
        s[base + 8..base + 12].copy_from_slice(&4096u32.to_le_bytes());
        s[base + 12..base + 16].copy_from_slice(&1024u32.to_le_bytes());
        let mbr = parse_mbr(&s).expect("parse ok");
        let p = mbr.first_partition().expect("slot 3 is the first non-empty");
        assert_eq!(p.start_lba, 4096);
        assert_eq!(p.sector_count, 1024);
        assert_eq!(p.part_type, 0x0C);
    }

    #[test]
    fn test_mbr_four_entries_decode_independently() {
        let mut s = [0u8; 512];
        s[510] = 0x55;
        s[511] = 0xAA;
        for i in 0..PARTITION_ENTRY_COUNT {
            let base = PARTITION_TABLE_OFFSET + i * PARTITION_ENTRY_SIZE;
            s[base + 4] = 0x83;
            let start = (1000u32) * (i as u32 + 1);
            s[base + 8..base + 12].copy_from_slice(&start.to_le_bytes());
            s[base + 12..base + 16].copy_from_slice(&500u32.to_le_bytes());
        }
        let mbr = parse_mbr(&s).expect("parse ok");
        for (i, p) in mbr.partitions.iter().enumerate() {
            assert_eq!(p.start_lba, 1000 * (i as u32 + 1));
            assert_eq!(p.sector_count, 500);
        }
    }
}
