//! ATAPI CD-ROM 包设备驱动（B2 载体迁移第一步：介质块层）。
//!
//! **数据链路真实性（S06）**：包设备的字节来自 SCSI/ATAPI PACKET 命令的 PIO
//! 数据相位——`READ(12)` 把 LBA 起的 `transfer_length` 个**逻辑块**（2KiB）
//! 经 0x1F0 数据口逐字读出。本驱动只做「块层事实」：把字节偏移翻译成
//! 逻辑块序号、按块读、如实短读；`ISO9660` 文件系统层是独立后续件。
//!
//! **为何独立于 ata_pio.rs**（S15）：包设备与 ATA 盘共享物理端口但协议完全
//! 不同（PACKET 命令两阶段：命令包 12 字节写相位 + 数据相位；块大小 2048
//! 非 512；IDENTIFY PACKET DEVICE 字段布局不同）。强塞进 ata_pio 的 512B
//! LBA28 形态会让两套语义互相渗透——独立成件，仅复用底座原语（端口读写、
//! 等待、总线锁、软复位）。
//!
//! **只读边界（S17）**：CD-ROM 介质物理只读——本驱动不实现 write_at，
//! `write_at` 继承 IoDevice 默认（0 字节），调用方把 0 解释为不可写而非伪成功。
//! `GET EVENT`/弹出等控制命令不在块层范围（无调用方，不预造）。

use core::sync::atomic::AtomicBool;

use crate::device::{BlockDevice, BusType, Device, DeviceInfo, DeviceKind, IoDevice, IoStats};
use crate::hub::DriverHub;
use arch_x86_64::port::{inb, outb};
use klib::{error, info};
use spin;

// ---------- 端口层（与 ata_pio.rs 同一物理通道，原语级复用） ----------
// 两个文件共用 0x1F0/0x170 通道与 ata_lock 总线锁（同一物理总线上的设备，
// 并发互斥必须跨驱动一致——锁在 ata_lock 单点，S13）。
use super::ata_pio::{
    data_read, data_write, io_delay, status_read, wait_not_busy, ATA_SR_BSY, ATA_SR_DF,
    ATA_SR_DRQ, ATA_SR_ERR, REG_COMMAND, REG_DRIVE, REG_FEATURES, REG_LBA_HIGH, REG_LBA_LOW,
    REG_LBA_MID, REG_SECTOR_COUNT,
};

/// ATAPI 命令：识别包设备（字段布局与 IDENTIFY DEVICE 不同）。
const ATAPI_CMD_IDENTIFY_PACKET: u8 = 0xA1;
/// ATAPI 命令：PACKET（命令包发射；包本身经数据口写入）。
const ATAPI_CMD_PACKET: u8 = 0xA0;
/// SCSI 命令：TEST UNIT READY（介质状态轻量探测，无数据相位）。
const SCSI_TEST_UNIT_READY: u8 = 0x00;
/// SCSI 命令：READ(12)（CD 块读；READ(10) 块计数字段 16bit 上限 65535，
/// READ(12) 为 32bit——CD 容量内一次到位，避免多次命令拼装）。
const SCSI_READ_12: u8 = 0xA8;

/// ATAPI 逻辑块大小（CD-ROM/MMC 规范：单一逻辑块大小 = 2048 字节）。
pub const ATAPI_BLOCK_SIZE: usize = 2048;

/// 命令包就绪等待（设备置 CoD=1/IO=0 清除 BSY）。复用 wait_drq 的预算论证：
/// 每次轮询是 VM-exit 级 inb，20 万次=数百毫秒上限（drv1 DD2 同源）。
fn wait_packet_ready(channel: u16) -> bool {
    for _ in 0..200_000 {
        let s = status_read(channel);
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

/// 等待数据相位结束（BSY 清零即命令完成；DRQ 已清表示包内数据全部交付）。
fn wait_command_done(channel: u16) -> bool {
    for _ in 0..200_000 {
        let s = status_read(channel);
        if s == 0xFF {
            return false;
        }
        if (s & ATA_SR_BSY) == 0 {
            return (s & ATA_SR_ERR) == 0 && (s & ATA_SR_DF) == 0;
        }
    }
    false
}

/// 发射 12 字节命令包并执行数据相位（PIO）。
///
/// `expect_bytes` = 设备将交付的字节数（ATAPI 字节计数字段）；`out` 接收
/// 数据相位（长度不足的部分**如实丢弃**并计入诊断——调用方保证缓冲足够）。
/// 返回整条命令（含数据相位与完成相位）是否成功。
fn atapi_send_packet(
    channel: u16,
    slave: bool,
    packet: &[u8; 12],
    expect_bytes: u16,
    out: &mut [u8],
) -> bool {
    // 整个 PACKET 事务（设备选择 → 命令发射 → 数据相位 → 完成相位）在总线锁
    // 内：寄存器是物理共享的，两步之间被并发写入即破坏事务（S13 同一单点——
    // ata_lock 可重入，复合入口安全）。
    let _bus = super::ata_lock::lock();
    // 包设备选择：DEV 位与 ATA 相同；但 LBA 域位无意义（bit6 不置——
    // 包设备的 DRIVE/HEAD 除 bit4/bit5 外应清零，MSDN/osdev 同一口径）。
    let dev = if slave { 0x10 } else { 0x00 };
    outb_port(channel + REG_DRIVE, 0xA0 | dev);
    io_delay();
    // 特征口 0：PIO 模式（Overlap/DMA 不用——本驱动同步 PIO）。
    outb_port(channel + REG_FEATURES, 0);
    // 字节计数：数据相位的期望交付量。
    outb_port(channel + REG_LBA_MID, (expect_bytes & 0xFF) as u8);
    outb_port(channel + REG_LBA_HIGH, (expect_bytes >> 8) as u8);
    outb_port(channel + REG_COMMAND, ATAPI_CMD_PACKET);

    if !wait_packet_ready(channel) {
        return false;
    }
    // 命令包经数据口按 16 位字写出（12 字节 = 6 字，低字节在前）。
    for w in 0..6 {
        let lo = packet[w * 2] as u16;
        let hi = packet[w * 2 + 1] as u16;
        data_write(channel, lo | (hi << 8));
    }

    // 数据相位：逐块等到 DRQ 后读出。READ(12) 多块传输时设备可能分多次
    // DRQ 交付（每块一次），故循环消费直到 expect_bytes 交付完或相位结束。
    let mut received = 0usize;
    while received < expect_bytes as usize {
        let s = status_read(channel);
        if s == 0xFF || (s & ATA_SR_ERR) != 0 || (s & ATA_SR_DF) != 0 {
            return false;
        }
        if (s & ATA_SR_BSY) != 0 {
            continue;
        }
        if (s & ATA_SR_DRQ) == 0 {
            break; // 相位提前结束（短交付）
        }
        // 本次 DRQ 窗口的字节数在 Byte Count 寄存器（LBA_MID/HIGH 回读）。
        let bc_lo = inb_port(channel + REG_LBA_MID) as usize;
        let bc_hi = inb_port(channel + REG_LBA_HIGH) as usize;
        let bc = bc_lo | (bc_hi << 8);
        if bc == 0 {
            break;
        }
        let mut words = bc / 2;
        while words > 0 {
            let word = data_read(channel);
            let i = received;
            if i + 1 < out.len() {
                out[i] = (word & 0xFF) as u8;
                out[i + 1] = (word >> 8) as u8;
            }
            received += 2;
            words -= 1;
        }
    }
    wait_command_done(channel)
}

// 端口原语：arch 层统一封装（与 ata_pio 同源）。
fn outb_port(port: u16, val: u8) {
    outb(port, val);
}
fn inb_port(port: u16) -> u8 {
    inb(port)
}

/// IDENTIFY PACKET DEVICE：确认包设备在场（发命令、等相位、读满 256 字）。
///
/// 失败语义与 ata_pio::identify_ata 同口径：识别失败=设备不可服务，如实报错。
/// 返回 `true` = 设备在场且命令完成（容量不在此取——见 atapi_read_capacity）。
fn atapi_identify(channel: u16, slave: bool) -> bool {
    let _bus = super::ata_lock::lock();
    if !wait_not_busy(channel) {
        return false;
    }
    let dev = if slave { 0x10 } else { 0x00 };
    outb_port(channel + REG_DRIVE, 0xA0 | dev);
    io_delay();
    outb_port(channel + REG_SECTOR_COUNT, 0);
    outb_port(channel + REG_LBA_LOW, 0);
    outb_port(channel + REG_LBA_MID, 0);
    outb_port(channel + REG_LBA_HIGH, 0);
    outb_port(channel + REG_COMMAND, ATAPI_CMD_IDENTIFY_PACKET);

    let status = status_read(channel);
    if status == 0 {
        return false;
    }
    if !wait_packet_ready(channel) {
        return false;
    }
    let mut data = [0u16; 256];
    for word in data.iter_mut() {
        *word = data_read(channel);
    }
    // 读满 256 字即确认设备在场。容量**不取自 identify**：实测 QEMU ATAPI
    //（diag 证据：gen=0x85c0、w49=0x300 数据真实读到，但 w57-61/w100-103
    // 全 0）不同代设备的 identify 容量字段披露不一致。唯一跨设备可靠真值
    // 是 SCSI READ CAPACITY(10)（MMC/SBC 标准，8 字节返回：last LBA + 块
    // 大小）——identify 只确认在场，容量由 atapi_read_capacity 独立查询。
    true
}

/// 读 `count` 个 2048B 逻辑块到 `out`（out 长度须 ≥ count*2048）。
/// 一次 PACKET 命令带一个块区间（READ(12) 32bit 块计数）；QEMU/真实光驱
/// 对一次多块 READ(12) 交付完整数据相位。
pub fn atapi_read_blocks(
    channel: u16,
    slave: bool,
    lba: u64,
    count: u32,
    out: &mut [u8],
) -> bool {
    if count == 0 {
        return true;
    }
    if out.len() < count as usize * ATAPI_BLOCK_SIZE {
        return false; // 调用方契约违约：缓冲不足
    }
    // 完整 READ(12) 命令包（SCSI SBC-3/MMC）：
    // [0]=0xA8 [1]=flags(RelAddr/Stream) [2..6]=LBA(BE) [6..10]=块数(BE)
    // [10]=控制 [11]=保留。
    let mut packet = [0u8; 12];
    packet[0] = SCSI_READ_12;
    packet[2] = (lba >> 24) as u8;
    packet[3] = (lba >> 16) as u8;
    packet[4] = (lba >> 8) as u8;
    packet[5] = lba as u8;
    packet[6] = (count >> 24) as u8;
    packet[7] = (count >> 16) as u8;
    packet[8] = (count >> 8) as u8;
    packet[9] = count as u8;
    let expect = count as u16 * ATAPI_BLOCK_SIZE as u16;
    atapi_send_packet(channel, slave, &packet, expect, out)
}

/// SCSI READ CAPACITY(10)：介质容量的**标准真值源**（MMC/SBC-3）。
///
/// 返回 `(last_lba, block_bytes)`；8 字节数据：`[0..4]`=last LBA（BE）、
/// `[4..8]`=块字节数（BE）。QEMU/真实光驱一致支持——identify 的容量字段
/// 在不同设备代上披露不一致（QEMU 实测全 0），本命令是唯一可靠源。
pub fn atapi_read_capacity(channel: u16, slave: bool) -> Option<(u64, u32)> {
    let mut packet = [0u8; 12];
    packet[0] = 0x25; // SCSI READ CAPACITY(10)
    let mut buf = [0u8; 8];
    if !atapi_send_packet(channel, slave, &packet, 8, &mut buf) {
        return None;
    }
    let last_lba = ((buf[0] as u64) << 24)
        | ((buf[1] as u64) << 16)
        | ((buf[2] as u64) << 8)
        | (buf[3] as u64);
    let block_bytes = ((buf[4] as u32) << 24)
        | ((buf[5] as u32) << 16)
        | ((buf[6] as u32) << 8)
        | (buf[7] as u32);
    if block_bytes == 0 {
        return None;
    }
    Some((last_lba.saturating_add(1), block_bytes))
}

/// ATAPI CD-ROM 块设备（DriverHub/DevFS/volumed 通道与 AtaPioDevice 同构接入）。
pub struct AtapiCdromDevice {
    pub name: &'static str,
    /// 通道寄存器基址。
    pub channel: u16,
    /// 驱动位。
    pub slave: bool,
    pub location: u32,
    /// 逻辑块数（2048B/块）。
    pub blocks: spin::Mutex<u64>,
    /// 真实 I/O 计数（按成功 READ(12) 命令计）。
    pub stats: IoStats,
    /// 热插拔一次性守卫（同 AtaPioDevice.gone 语义）。
    pub gone: AtomicBool,
}

impl Device for AtapiCdromDevice {
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

impl IoDevice for AtapiCdromDevice {
    fn read_at(&self, offset: u64, out: &mut [u8]) -> usize {
        let total_blocks = *self.blocks.lock();
        if total_blocks == 0 {
            return 0;
        }
        // 字节偏移 → 逻辑块对齐读取（2048B 块边界内偏移=0：介质块粒度对齐，
        // 非对齐偏移由调用方分层处理——EXT2/ISO9660 层按块读后自行切）。
        let lba = offset / ATAPI_BLOCK_SIZE as u64;
        let mut sector_off = (offset % ATAPI_BLOCK_SIZE as u64) as usize;
        if lba >= total_blocks {
            return 0;
        }
        let mut done = 0usize;
        let mut remaining = out.len();
        let mut cur = lba;
        // 单次 PACKET 命令交付多少块：对齐块数（跨块请求一次 READ(12) 多块）。
        while remaining > 0 && cur < total_blocks {
            // 本次覆盖的块数：受三重约束——请求剩余、单命令上限（ATAPI 字节
            // 计数字段 16 位宽 → 每命令 ≤ 0xFFFF 字节 = 31 块）、暂存缓冲容量。
            let max_by_cmd = 0xFFFFusize / ATAPI_BLOCK_SIZE; // 31 块
            let max_by_buf = 8usize; // buf 容量
            let want_blocks = remaining
                .div_ceil(ATAPI_BLOCK_SIZE)
                .min(max_by_cmd)
                .min(max_by_buf)
                .min((total_blocks - cur) as usize);
            let nblocks = want_blocks; // 本命令实际读的块数（名字沿用语义层）
            let mut buf = [0u8; ATAPI_BLOCK_SIZE * 8];
            let mut rd_ok = false;
            for _ in 0..3 {
                if atapi_read_blocks(self.channel, self.slave, cur, nblocks as u32, &mut buf) {
                    rd_ok = true;
                    break;
                }
            }
            if !rd_ok {
                break;
            }
            self.stats.record_read(nblocks as u64);
            let take = core::cmp::min(remaining, nblocks * ATAPI_BLOCK_SIZE - sector_off);
            out[done..done + take]
                .copy_from_slice(&buf[sector_off..sector_off + take]);
            done += take;
            remaining -= take;
            cur += nblocks as u64;
            sector_off = 0;
        }
        done
    }

    fn size(&self) -> Option<u64> {
        Some(*self.blocks.lock() * ATAPI_BLOCK_SIZE as u64)
    }

    fn io_stats(&self) -> Option<&IoStats> {
        Some(&self.stats)
    }

    /// 轻量存活探测：TEST UNIT READY（无数据相位，毫秒级）。
    fn probe_alive(&self) -> Option<bool> {
        let mut packet = [0u8; 12];
        packet[0] = SCSI_TEST_UNIT_READY;
        Some(atapi_send_packet(self.channel, self.slave, &packet, 0, &mut []))
    }
}

impl BlockDevice for AtapiCdromDevice {
    fn block_size(&self) -> usize {
        ATAPI_BLOCK_SIZE
    }
    fn block_count(&self) -> u64 {
        *self.blocks.lock()
    }
}

pub static ATAPI_CD0: AtapiCdromDevice = AtapiCdromDevice {
    name: "cd0",
    channel: 0x1F0,
    slave: false,
    location: 0x1F0,
    blocks: spin::Mutex::new(0),
    stats: IoStats::new(),
    gone: AtomicBool::new(false),
};

pub static ATAPI_CD1: AtapiCdromDevice = AtapiCdromDevice {
    name: "cd1",
    channel: 0x170,
    slave: false,
    location: 0x170,
    blocks: spin::Mutex::new(0),
    stats: IoStats::new(),
    gone: AtomicBool::new(false),
};

/// ata_pio::init_ata 的 AtapiPacket 分支调用：登记 CD 设备。
///
/// **为何没有独立 hub 驱动条目**（S07 反空壳）：包设备的识别由 ata_pio 的
/// `identify_ata` 一次性完成（签名区分），登记挂在该调用的 AtapiPacket 分支；
/// `late_storage_init`（ahci → ata_pio）天然覆盖本驱动的启用时序。独立注册
/// 一个空 init 只会给 hub 列举制造无行为的条目。
pub fn register_atapi_device(channel: u16, slave: bool) {
    let (dev, name): (&AtapiCdromDevice, &str) = match (channel, slave) {
        (0x1F0, false) => (&ATAPI_CD0, "cd0"),
        (0x170, false) => (&ATAPI_CD1, "cd1"),
        // slave 槽位与 secondary-master 命名延展（cd2/cd3）待真实设备出现再开，
        // 现在只有两个命名槽位（QEMU -cdrom 挂 Primary Master）。
        _ => return,
    };
    if !atapi_identify(channel, slave) {
        klib::error!("[atapi] {} identify packet failed after signature match", name);
        return;
    }
    // 容量走 READ CAPACITY(10)（identify 容量字段跨设备不可靠，见上）。
    let Some((blocks, block_bytes)) = atapi_read_capacity(channel, slave) else {
        klib::error!("[atapi] {} READ CAPACITY failed; medium absent?", name);
        return;
    };
    if block_bytes != ATAPI_BLOCK_SIZE as u32 {
        // MMC 规范单一逻辑块 2048；非此值=非 CD 形态介质，如实拒绝不硬掰。
        klib::error!(
            "[atapi] {} unexpected block size {}B; refusing non-CD medium",
            name,
            block_bytes
        );
        return;
    }
    *dev.blocks.lock() = blocks;
    info!(
        "[atapi] {} ATAPI CD-ROM: {} blocks x {}B ({} MB), read-only medium",
        name,
        blocks,
        ATAPI_BLOCK_SIZE,
        (blocks * ATAPI_BLOCK_SIZE as u64) / (1024 * 1024)
    );
    if let Err(e) = DriverHub::register_device_info(
        DeviceInfo {
            name,
            kind: DeviceKind::Block,
            bus: BusType::Platform,
            location: dev.location,
            vendor_id: 0,
            device_id: 0,
            class_code: 0x01,
            subclass: 0x05, // ATAPI CD-ROM（MMC）
            prog_if: 0x00,
            volatile: false, // 真硬件、非易失——但介质只读（FS 层只读挂载）
            irq_line: 0,
        },
        Some(dev),
        Some("atapi_cdrom"),
    ) {
        klib::error!("[atapi] {} registration failed: {:?}", name, e);
    }
}
