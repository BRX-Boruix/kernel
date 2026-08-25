//! ATA / IDE PIO 模式硬盘驱动（BlockDevice）。
//!
//! 实现 Primary/Secondary 通道 **LBA28** 扇区读写与 Identify 设备识别
//! （命令字 `0x20`/`0x30`，28 位寻址域）。LBA48（`0x24`/`0x34` 双寄存器
//! 命令序列）**未实现**，文档与实现就此对齐（drv1 DA2：宣称未实现的能力
//! 与静默回卷同样致命——前者可见，后者腐蚀数据）。
//!
//! 超域守卫：identify 报告的容量超过 [`LBA28_MAX_SECTORS`] 时拒绝硬件模式
//! （ADR-022 §3），杜绝高位偏移被截断到低位 LBA 的静默数据损坏。
//! 当无真实硬件或 QEMU 纯 CD-ROM 启动时，提供 64KB 快速扇区内存模拟回退。

use crate::device::{
    sectors_touched, BlockDevice, BusType, Device, DeviceInfo, DeviceKind, IoDevice, IoStats,
};
use crate::driver::DriverStage;
use crate::hub::DriverHub;
use arch_x86_64::port::{inb, inw, outb, outw};
use klib::{error::Error, info};
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

/// LBA28 可寻址扇区上限（28 位寻址域，drv1 DA2）。
///
/// 本驱动命令字 0x20/0x30 + `(lba>>24)&0x0F` 高位口只覆盖 28 位 LBA；
/// identify 报告容量超过此值的盘必须拒绝硬件访问——超域偏移会被硬件
/// 截断回卷到低位 LBA，等于把写操作静默投递到错误扇区（数据损坏），
/// 宁可拒绝也不带病服务。0x14/0xEB 见 [`ATAPI_SIG_LBA_MID`]/[`ATAPI_SIG_LBA_HIGH`]。
pub const LBA28_MAX_SECTORS: u64 = 0x0FFF_FFFF;

/// ATAPI 设备在 IDENTIFY DEVICE 失败路径上的签名值（LBA Mid / High 口），
/// ATA/ATAPI 规范定义；用于把"包设备"从"无设备"中显式区分出来（drv1 DD3）。
const ATAPI_SIG_LBA_MID: u8 = 0x14;
const ATAPI_SIG_LBA_HIGH: u8 = 0xEB;

/// Identify 结果分类（drv1 DD3）：不再用超时兜底含混表达三种完全不同的
/// 硬件事实（ADR-022 §3）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtaIdentify {
    /// 真实 ATA 盘（identify 报告的总扇区数）。
    Ata(u64),
    /// ATAPI 包设备（CD-ROM 等）：本驱动只做 LBA28 块读写，不支持包设备。
    AtapiPacket,
    /// 主驱动位上没有可识别设备。
    Absent,
}

static FALLBACK_STORAGE: Mutex<[u8; 64 * 1024]> = Mutex::new([0u8; 64 * 1024]);

fn io_delay() {
    outb(0x80, 0);
}

fn status_read() -> u8 {
    inb(ATA_STATUS)
}

fn wait_not_busy() -> bool {
    // 预算依据：每次轮询是一次 VM exit 级 inb；QEMU 对冷文件首次回写
    // （新建镜像首启）可能超过 1 万次窗口，20 万次给出数百毫秒上限。
    for _ in 0..200_000 {
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
    // 预算依据（drv1 DD2）：与 [`wait_not_busy`] 同一 VM-exit 级论证——
    // 每次轮询是一次 VM exit 级 inb，QEMU 对冷文件首次回写可能超过 1 万次
    // 窗口，20 万次给出数百毫秒上限。ERR/DF 早退分支保证真实故障路径的
    // 成本不受预算放宽影响，放宽只作用于"慢但健康"的数据相位等待。
    for _ in 0..200_000 {
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
    // 高 4 位口承载 LBA28 的 bits[27:24]——寻址域就此封顶于 28 位，
    // 超域容量由 init_ata 的 LBA28_MAX_SECTORS 守卫拒绝，不在此静默截断。
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

/// 识别 Primary Master 上的设备（drv1 DA2/DD3）。
///
/// - `status == 0` → [`AtaIdentify::Absent`]；
/// - IDENTIFY 完成 → 读容量：LBA28 字（word 60/61）为唯一权威
///   （本驱动 LBA28-only，不采信 LBA48 字段——宣称读取却无法寻址等于埋雷）；
/// - 命令失败且 LBA Mid/High 呈 ATAPI 签名（0x14/0xEB）→
///   [`AtaIdentify::AtapiPacket`]，把包设备从"无设备"中显式区分。
pub fn identify_ata() -> AtaIdentify {
    if !wait_not_busy() {
        return AtaIdentify::Absent;
    }
    select_drive_lba(0);
    outb(ATA_SECTOR_COUNT, 0);
    outb(ATA_LBA_LOW, 0);
    outb(ATA_LBA_MID, 0);
    outb(ATA_LBA_HIGH, 0);
    outb(ATA_COMMAND, ATA_CMD_IDENTIFY);

    let status = status_read();
    if status == 0 {
        return AtaIdentify::Absent;
    }
    if !wait_drq() {
        // 命令失败：读签名口区分 ATAPI 包设备与真缺席（规范定义，
        // IDENTIFY DEVICE 对包设备报错后签名口保持 0x14/0xEB）。
        let mid = inb(ATA_LBA_MID);
        let high = inb(ATA_LBA_HIGH);
        if mid == ATAPI_SIG_LBA_MID && high == ATAPI_SIG_LBA_HIGH {
            return AtaIdentify::AtapiPacket;
        }
        klib::error!(
            "[ata_pio] identify failed: status={:#04x} sig_mid={:#04x} sig_high={:#04x}",
            status,
            mid,
            high
        );
        return AtaIdentify::Absent;
    }
    let mut data = [0u16; 256];
    for word in data.iter_mut() {
        *word = inw(ATA_DATA);
    }
    let lba28 = ((data[60] as u32) | ((data[61] as u32) << 16)) as u64;
    if lba28 > 0 {
        AtaIdentify::Ata(lba28)
    } else {
        // 容量为 0 的"成功"identify 是自相矛盾的盘上事实，按缺席处理并留痕。
        klib::error!("[ata_pio] identify reported zero capacity; treating as absent");
        AtaIdentify::Absent
    }
}

fn ata_read_sector(lba: u64, out: &mut [u8; 512]) -> bool {
    for attempt in 0..3 {
        if !wait_not_busy() {
            klib::error!(
                "[ata_pio] read lba={} attempt={} failed: device stuck BSY (10k polls)",
                lba,
                attempt
            );
            continue;
        }
        select_drive_lba(lba);
        set_lba_regs(lba, 1);
        outb(ATA_COMMAND, ATA_CMD_READ_SECTORS);
        let st = status_read();
        let drq_ok = wait_drq();
        if st == 0xFF || (st & ATA_SR_ERR) != 0 || (st & ATA_SR_DF) != 0 || !drq_ok {
            // 失败诊断：status 原值 + 各标志位拆解（ERR=0x01 DF=0x20 DRQ=0x08）。
            klib::error!(
                "[ata_pio] read lba={} attempt={} failed: status={:#04x} err={} df={} drq_wait={}",
                lba,
                attempt,
                st,
                st & ATA_SR_ERR != 0,
                st & ATA_SR_DF != 0,
                drq_ok
            );
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
        // 完成等待：最后一个数据字写出后，设备置 BSY 把缓冲落盘
        // （QEMU 经异步下半区提交宿主文件）。必须等到命令真正结束再返回，
        // 否则紧随其后的读命令会在 BSY 上撞车——这正是“末端 LBA 读返回 0”
        // 的真实根因：与 LBA 位置无关，任何写后立即读都可能触发。
        if !wait_not_busy() {
            klib::error!(
                "[ata_pio] write lba={} failed: device stuck BSY after data phase",
                lba
            );
            continue;
        }
        let st = status_read();
        if (st & ATA_SR_ERR) == 0 && (st & ATA_SR_DF) == 0 {
            return true;
        }
        klib::error!(
            "[ata_pio] write lba={} failed: status={:#04x} err={} df={}",
            lba,
            st,
            st & ATA_SR_ERR != 0,
            st & ATA_SR_DF != 0
        );
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
    // ADR-022 §3：Ata 超域容量拒绝硬件模式（不钳制——钳制是对介质容量的
    // 说谎）；AtapiPacket 不落回退盘（硬件存在而伪造 RAM 盘会掩盖可支持的
    // 未来目标）；Absent 维持 DMYGH #15 披露式回退政策。
    let registration: Option<(&'static AtaPioDevice, &'static str, bool)> = match identify_ata() {
        AtaIdentify::Ata(sec) if sec <= LBA28_MAX_SECTORS => {
            *ATA_PRIMARY_MASTER.sectors.lock() = sec;
            *ATA_PRIMARY_MASTER.is_hardware.lock() = true;
            info!(
                "[ata_pio] ATA Primary Master hardware identified: {} sectors ({} MB), LBA28 domain",
                sec,
                (sec * 512) / (1024 * 1024)
            );
            Some((&ATA_PRIMARY_MASTER, "ata0", false))
        }
        AtaIdentify::Ata(sec) => {
            klib::error!(
                "[ata_pio] refusing unsafe hardware access: disk capacity {} sectors exceeds LBA28 addressing limit {} (offsets would silently wrap and corrupt data)",
                sec,
                LBA28_MAX_SECTORS
            );
            *ATA_RAM_FALLBACK.sectors.lock() = FALLBACK_SECTOR_COUNT;
            *ATA_RAM_FALLBACK.is_hardware.lock() = false;
            info!(
                "[ata_pio] falling back to NON-PERSISTENT RAM storage '{}' ({} KiB) - all data is lost on reboot",
                ATA_RAM_FALLBACK.name,
                (FALLBACK_SECTOR_COUNT * 512) / 1024
            );
            Some((&ATA_RAM_FALLBACK, "ata0-ramfallback", true))
        }
        AtaIdentify::AtapiPacket => {
            info!(
                "[ata_pio] ATAPI packet device detected on Primary Master; LBA28 PIO block driver does not support packet devices - no block device registered"
            );
            None
        }
        AtaIdentify::Absent => {
            // DMYGH #15：identify 失败时如实登记为非持久内存回退盘，
            // 日志保留 fallback 说明，设备列表同步携带 volatile=true。
            *ATA_RAM_FALLBACK.sectors.lock() = FALLBACK_SECTOR_COUNT;
            *ATA_RAM_FALLBACK.is_hardware.lock() = false;
            info!(
                "[ata_pio] ATA identify failed; fallback to NON-PERSISTENT RAM storage '{}' ({} KiB) - all data is lost on reboot",
                ATA_RAM_FALLBACK.name,
                (FALLBACK_SECTOR_COUNT * 512) / 1024
            );
            Some((&ATA_RAM_FALLBACK, "ata0-ramfallback", true))
        }
    };

    let Some((dev, dev_name, volatile)) = registration else {
        return;
    };

    if let Err(e) = DriverHub::register_device_info(
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
    ) {
        klib::error!("[ata_pio] device registration failed: {:?}", e);
    }
}

pub fn register_ata_driver() -> Result<(), Error> {
    DriverHub::register_driver("ata_pio", DriverStage::Devices, init_ata)
}
