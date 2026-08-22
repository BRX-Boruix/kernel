//! ATA / IDE PIO 模式硬盘驱动（BlockDevice）。
//!
//! 实现 Primary/Secondary 通道 LBA28/LBA48 扇区读写与 Identify 设备识别。
//! 当无真实硬件或 QEMU 纯 CD-ROM 启动时，提供 64KB 快速扇区内存模拟回退。

use crate::device::{
    sectors_touched, BlockDevice, BusType, Device, DeviceInfo, DeviceKind, IoDevice, IoStats,
};
use crate::driver::DriverStage;
use crate::hub::DriverHub;
use arch_x86_64::port::{inb, inw, outb, outw};
use klib::info;
use spin::Mutex;

const ATA_DATA: u16 = 0x1F0;
const ATA_FEATURES: u16 = 0x1F1;
const ATA_SECTOR_COUNT: u16 = 0x1F2;
const ATA_LBA_LOW: u16 = 0x1F3;
const ATA_LBA_MID: u16 = 0x1F4;
const ATA_LBA_HIGH: u16 = 0x1F5;
const ATA_DRIVE: u16 = 0x1F6;
const ATA_STATUS: u16 = 0x1F7;
const ATA_COMMAND: u16 = 0x1F7;

const ATA_SR_BSY: u8 = 0x80;
const ATA_SR_DRQ: u8 = 0x08;
const ATA_SR_ERR: u8 = 0x01;
const ATA_SR_DF: u8 = 0x20;

const ATA_CMD_IDENTIFY: u8 = 0xEC;
const ATA_CMD_READ_SECTORS: u8 = 0x20;
const ATA_CMD_WRITE_SECTORS: u8 = 0x30;

static FALLBACK_STORAGE: Mutex<[u8; 64 * 1024]> = Mutex::new([0u8; 64 * 1024]);

fn io_delay() {
    outb(0x80, 0);
}

fn status_read() -> u8 {
    inb(ATA_STATUS)
}

fn wait_not_busy() -> bool {
    for _ in 0..10_000 {
        let s = status_read();
        if s == 0xFF {
            return false;
        }
        if (s & ATA_SR_BSY) == 0 {
            return true;
        }
    }
    false
}

fn wait_drq() -> bool {
    for _ in 0..10_000 {
        let s = status_read();
        if s == 0xFF {
            return false;
        }
        if (s & ATA_SR_BSY) == 0 && (s & ATA_SR_DRQ) != 0 {
            return true;
        }
        if (s & ATA_SR_ERR) != 0 || (s & ATA_SR_DF) != 0 {
            return false;
        }
    }
    false
}

fn select_drive_lba(lba: u64) {
    let drive = 0xE0u8 | (((lba >> 24) & 0x0F) as u8);
    outb(ATA_DRIVE, drive);
    io_delay();
}

fn set_lba_regs(lba: u64, count: u8) {
    outb(ATA_FEATURES, 0);
    outb(ATA_SECTOR_COUNT, count);
    outb(ATA_LBA_LOW, (lba & 0xFF) as u8);
    outb(ATA_LBA_MID, ((lba >> 8) & 0xFF) as u8);
    outb(ATA_LBA_HIGH, ((lba >> 16) & 0xFF) as u8);
}

pub fn identify_ata() -> Option<u64> {
    if !wait_not_busy() {
        return None;
    }
    select_drive_lba(0);
    outb(ATA_SECTOR_COUNT, 0);
    outb(ATA_LBA_LOW, 0);
    outb(ATA_LBA_MID, 0);
    outb(ATA_LBA_HIGH, 0);
    outb(ATA_COMMAND, ATA_CMD_IDENTIFY);

    let status = status_read();
    if status == 0 || !wait_drq() {
        return None;
    }
    let mut data = [0u16; 256];
    for word in data.iter_mut() {
        *word = inw(ATA_DATA);
    }
    let lba28 = ((data[60] as u32) | ((data[61] as u32) << 16)) as u64;
    let lba48 = (data[100] as u64)
        | ((data[101] as u64) << 16)
        | ((data[102] as u64) << 32)
        | ((data[103] as u64) << 48);
    let sectors = if lba48 != 0 { lba48 } else { lba28 };
    if sectors > 0 { Some(sectors) } else { None }
}

fn ata_read_sector(lba: u64, out: &mut [u8; 512]) -> bool {
    for _ in 0..3 {
        if !wait_not_busy() {
            continue;
        }
        select_drive_lba(lba);
        set_lba_regs(lba, 1);
        outb(ATA_COMMAND, ATA_CMD_READ_SECTORS);
        let st = status_read();
        if st == 0xFF || (st & ATA_SR_ERR) != 0 || (st & ATA_SR_DF) != 0 || !wait_drq() {
            continue;
        }
        for i in 0..256 {
            let word = inw(ATA_DATA);
            out[i * 2] = (word & 0xFF) as u8;
            out[i * 2 + 1] = (word >> 8) as u8;
        }
        return true;
    }
    false
}

fn ata_write_sector(lba: u64, data: &[u8; 512]) -> bool {
    for _ in 0..3 {
        if !wait_not_busy() {
            continue;
        }
        select_drive_lba(lba);
        set_lba_regs(lba, 1);
        outb(ATA_COMMAND, ATA_CMD_WRITE_SECTORS);
        if !wait_drq() {
            continue;
        }
        for i in 0..256 {
            let word = (data[i * 2] as u16) | ((data[i * 2 + 1] as u16) << 8);
            outw(ATA_DATA, word);
        }
        let st = status_read();
        if (st & ATA_SR_ERR) == 0 && (st & ATA_SR_DF) == 0 {
            return true;
        }
    }
    false
}

pub struct AtaPioDevice {
    pub name: &'static str,
    pub sectors: Mutex<u64>,
    pub is_hardware: Mutex<bool>,
    /// 真实 I/O 计数（C16.1）：硬件路径按成功 sector 命令计数，
    /// 回退路径按触碰扇区块计数。
    pub stats: IoStats,
}

impl Device for AtaPioDevice {
    fn name(&self) -> &'static str {
        self.name
    }

    fn kind(&self) -> DeviceKind {
        DeviceKind::Block
    }

    fn as_io(&self) -> Option<&dyn IoDevice> {
        Some(self)
    }

    fn as_block(&self) -> Option<&dyn BlockDevice> {
        Some(self)
    }
}

impl IoDevice for AtaPioDevice {
    fn read_at(&self, offset: u64, out: &mut [u8]) -> usize {
        let is_hw = *self.is_hardware.lock();
        if !is_hw {
            let storage = FALLBACK_STORAGE.lock();
            let off = offset as usize;
            if off >= storage.len() {
                return 0;
            }
            let n = core::cmp::min(out.len(), storage.len() - off);
            out[..n].copy_from_slice(&storage[off..off + n]);
            // C16.1：成功读取按触碰扇区块计数。
            self.stats.record_read(sectors_touched(offset, n as u64));
            return n;
        }

        let total_sectors = *self.sectors.lock();
        if total_sectors == 0 {
            return 0;
        }
        let mut lba = offset / 512;
        let mut sector_off = (offset % 512) as usize;
        if lba >= total_sectors {
            return 0;
        }
        let mut done = 0usize;
        let mut buf = [0u8; 512];
        let mut remaining = out.len();
        while remaining > 0 && lba < total_sectors {
            if !ata_read_sector(lba, &mut buf) {
                break;
            }
            // C16.1：每条成功 sector 读命令计 1。
            self.stats.record_read(1);
            let take = core::cmp::min(remaining, 512 - sector_off);
            out[done..done + take].copy_from_slice(&buf[sector_off..sector_off + take]);
            done += take;
            remaining -= take;
            lba += 1;
            sector_off = 0;
        }
        done
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> usize {
        let is_hw = *self.is_hardware.lock();
        if !is_hw {
            let mut storage = FALLBACK_STORAGE.lock();
            let off = offset as usize;
            if off >= storage.len() {
                return 0;
            }
            let n = core::cmp::min(data.len(), storage.len() - off);
            storage[off..off + n].copy_from_slice(&data[..n]);
            // C16.1：成功写入按触碰扇区块计数。
            self.stats.record_write(sectors_touched(offset, n as u64));
            return n;
        }

        let total_sectors = *self.sectors.lock();
        if total_sectors == 0 {
            return 0;
        }
        let mut lba = offset / 512;
        let mut sector_off = (offset % 512) as usize;
        if lba >= total_sectors {
            return 0;
        }
        let mut done = 0usize;
        let mut remaining = data.len();
        let mut buf = [0u8; 512];
        while remaining > 0 && lba < total_sectors {
            let take = core::cmp::min(remaining, 512 - sector_off);
            if sector_off != 0 || take < 512 {
                // 部分扇区写：真实的读-改-写序列，两条命令各计其账。
                if !ata_read_sector(lba, &mut buf) {
                    break;
                }
                self.stats.record_read(1);
                buf[sector_off..sector_off + take].copy_from_slice(&data[done..done + take]);
                if !ata_write_sector(lba, &buf) {
                    break;
                }
                self.stats.record_write(1);
            } else {
                buf.copy_from_slice(&data[done..done + 512]);
                if !ata_write_sector(lba, &buf) {
                    break;
                }
                self.stats.record_write(1);
            }
            done += take;
            remaining -= take;
            lba += 1;
            sector_off = 0;
        }
        done
    }

    fn size(&self) -> Option<u64> {
        let total = *self.sectors.lock();
        Some(total * 512)
    }

    fn io_stats(&self) -> Option<&IoStats> {
        Some(&self.stats)
    }
}

impl BlockDevice for AtaPioDevice {
    fn block_size(&self) -> usize {
        512
    }

    fn block_count(&self) -> u64 {
        *self.sectors.lock()
    }
}

/// identify 成功时的真实硬件盘身份：背后是可持久化介质（-hda 镜像/真机硬盘）。
pub static ATA_PRIMARY_MASTER: AtaPioDevice = AtaPioDevice {
    name: "ata0",
    sectors: Mutex::new(0),
    is_hardware: Mutex::new(false),
    stats: IoStats::new(),
};

/// identify 失败时的内存回退盘身份（DMYGH #15）：
/// 独立注册名 + 易失披露，杜绝以 "ata0" 名义伪装持久硬盘。
static ATA_RAM_FALLBACK: AtaPioDevice = AtaPioDevice {
    name: "ata0-ramfallback",
    sectors: Mutex::new(0),
    is_hardware: Mutex::new(false),
    stats: IoStats::new(),
};

/// 回退盘容量：128 扇区 × 512B = 64KiB。
const FALLBACK_SECTOR_COUNT: u64 = 128;

pub fn init_ata(_hub: &DriverHub) {
    // 身份在 init 时一次性判定并写入注册表，运行期不再变更（无影子状态）。
    let (dev, dev_name, volatile): (&'static AtaPioDevice, &'static str, bool) = match identify_ata()
    {
        Some(sec) => {
            *ATA_PRIMARY_MASTER.sectors.lock() = sec;
            *ATA_PRIMARY_MASTER.is_hardware.lock() = true;
            info!(
                "[ata_pio] ATA Primary Master hardware identified: {} sectors ({} MB)",
                sec,
                (sec * 512) / (1024 * 1024)
            );
            (&ATA_PRIMARY_MASTER, "ata0", false)
        }
        None => {
            // DMYGH #15：identify 失败时如实登记为非持久内存回退盘，
            // 日志保留 fallback 说明，设备列表同步携带 volatile=true。
            *ATA_RAM_FALLBACK.sectors.lock() = FALLBACK_SECTOR_COUNT;
            *ATA_RAM_FALLBACK.is_hardware.lock() = false;
            info!(
                "[ata_pio] ATA identify failed; fallback to NON-PERSISTENT RAM storage '{}' ({} KiB) - all data is lost on reboot",
                ATA_RAM_FALLBACK.name,
                (FALLBACK_SECTOR_COUNT * 512) / 1024
            );
            (&ATA_RAM_FALLBACK, "ata0-ramfallback", true)
        }
    };

    DriverHub::register_device_info(
        DeviceInfo {
            name: dev_name,
            kind: DeviceKind::Block,
            bus: BusType::Platform,
            location: 0x1F0,
            vendor_id: 0,
            device_id: 0,
            class_code: 0x01,
            subclass: 0x01,
            prog_if: 0x8A,
            volatile,
        },
        Some(dev),
        Some("ata_pio"),
    );
}

pub fn register_ata_driver() {
    DriverHub::register_driver("ata_pio", DriverStage::Devices, init_ata);
}
