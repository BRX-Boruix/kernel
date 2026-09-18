//! ATA / IDE PIO 模式硬盘驱动（BlockDevice）。
//!
//! 实现 Primary/Secondary 通道 × Master/Slave 四设备 **LBA28** 扇区读写与
//! Identify 设备识别（命令字 `0x20`/`0x30`，28 位寻址域）。LBA48
//! （`0x24`/`0x34` 双寄存器命令序列）**未实现**，文档与实现就此对齐
//! （drv1 DA2：宣称未实现的能力与静默回卷同样致命——前者可见，后者腐蚀数据）。
//!
//! 超域守卫：identify 报告的容量超过 [`LBA28_MAX_SECTORS`] 时拒绝硬件模式
//! （ADR-022 §3），杜绝高位偏移被截断到低位 LBA 的静默数据损坏。
//! 当无真实硬件或 QEMU 纯 CD-ROM 启动时，提供 64KB 快速扇区内存模拟回退。
//!
//! ## 多盘支持（M0.4，ADR-030 §决策5）
//!
//! 本驱动探测 Primary/Secondary 两个通道各 Master/Slave 两个驱动位，共四个
//! 设备槽：`ata0`（Primary Master）、`ata1`（Primary Slave）、`ata2`
//! （Secondary Master）、`ata3`（Secondary Slave）。每块识别到的真实 ATA 盘
//! 分别登记 `DriverHub`，使"系统盘 + 卷盘"可同时存在（ADR-029 两块盘场景）。
//! ATAPI 包设备（CD-ROM）如实跳过（不伪造 RAM 盘）。

use crate::device::{
    sectors_touched, BlockDevice, BusType, Device, DeviceInfo, DeviceKind, IoDevice, IoStats,
};
use crate::driver::DriverStage;
use crate::hub::DriverHub;
use arch_x86_64::port::{inb, inw, outb, outw};
use klib::{error::Error, info};
use spin::Mutex;
use core::sync::atomic::{AtomicBool, Ordering};

/// Primary 通道寄存器基址（0x1F0 系列）。
const ATA_PRIMARY_BASE: u16 = 0x1F0;
/// Secondary 通道寄存器基址（0x170 系列，M0.4）。
const ATA_SECONDARY_BASE: u16 = 0x170;

/// 通道内寄存器偏移（Primary 与 Secondary 同构，仅基址不同）。
const REG_DATA: u16 = 0x00; // 16 位数据口
const REG_FEATURES: u16 = 0x01;
const REG_SECTOR_COUNT: u16 = 0x02;
const REG_LBA_LOW: u16 = 0x03;
const REG_LBA_MID: u16 = 0x04;
const REG_LBA_HIGH: u16 = 0x05;
const REG_DRIVE: u16 = 0x06;
const REG_STATUS: u16 = 0x07;
const REG_COMMAND: u16 = 0x07;

const ATA_SR_BSY: u8 = 0x80;
const ATA_SR_DRQ: u8 = 0x08;
const ATA_SR_ERR: u8 = 0x01;
const ATA_SR_DF: u8 = 0x20;

const ATA_CMD_IDENTIFY: u8 = 0xEC;
const ATA_CMD_READ_SECTORS: u8 = 0x20;
const ATA_CMD_WRITE_SECTORS: u8 = 0x30;

/// 通道控制寄存器基址（Primary 0x3F6 / Secondary 0x376）。
///
/// 与命令块基址不同口：Device Control 寄存器（SRST/nIEN）在独立的控制块上。
const CTRL_PRIMARY: u16 = 0x3F6;
const CTRL_SECONDARY: u16 = 0x376;

/// Device Control 寄存器位 2：Software Reset（SRST）。
const CTRL_SRST: u8 = 0x04;

/// LBA28 可寻址扇区上限（28 位寻址域，drv1 DA2）。
///
/// 本驱动命令字 0x20/0x30 + `(lba>>24)&0x0F` 高位口只覆盖 28 位 LBA；
/// identify 报告容量超过此值的盘必须拒绝硬件访问——超域偏移会被硬件
/// 截断回卷到低位 LBA，等于把写操作静默投递到错误扇区（数据损坏），
/// 宁可拒绝也不带病服务。0x14/0xEB 见 [`ATAPI_SIG_LBA_MID`]/[`ATAPI_SIG_LBA_HIGH`]。
pub const LBA28_MAX_SECTORS: u64 = 0x0FFF_FFFF;

/// 单个扇区读/写的重试次数（PIO 事务级，在 [`ata_read_sector`] 内部还有
/// 一次 3 次命令重试之上）。
///
/// 取 4：并发的瞬时挤占通常 1~2 次内消失；真拔盘则 4 次全败后由
/// `is_device_gone` 判定。**不设为无限**——设备真消失时必须能退出。
const SECTOR_RETRIES: usize = 4;

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
    /// 该驱动位上没有可识别设备。
    Absent,
}

static FALLBACK_STORAGE: Mutex<[u8; 64 * 1024]> = Mutex::new([0u8; 64 * 1024]);

fn io_delay() {
    outb(0x80, 0);
}

/// 读通道状态寄存器。
#[inline]
fn status_read(channel: u16) -> u8 {
    inb(channel + REG_STATUS)
}

/// 读通道数据口 16 位字。
#[inline]
fn data_read(channel: u16) -> u16 {
    inw(channel + REG_DATA)
}

/// 写通道数据口 16 位字。
#[inline]
fn data_write(channel: u16, word: u16) {
    outw(channel + REG_DATA, word);
}

fn wait_not_busy(channel: u16) -> bool {
    // 预算依据：每次轮询是一次 VM exit 级 inb；QEMU 对冷文件首次回写
    // （新建镜像首启）可能超过 1 万次窗口，20 万次给出数百毫秒上限。
    for _ in 0..200_000 {
        let s = status_read(channel);
        if s == 0xFF {
            return false;
        }
        if (s & ATA_SR_BSY) == 0 {
            return true;
        }
    }
    false
}

/// 命令块基址 → 控制块基址（两通道同构映射；其它基址无控制口，返回 None）。
fn ctrl_base_of(channel: u16) -> Option<u16> {
    match channel {
        ATA_PRIMARY_BASE => Some(CTRL_PRIMARY),
        ATA_SECONDARY_BASE => Some(CTRL_SECONDARY),
        _ => None,
    }
}

/// 通道软复位（SRST）。
///
/// **为什么需要**（实测缺陷，用户报告）：命令重叠/宿主后端卡住会让设备停在
/// BSY=1，重试只是反复撞同一堵墙——primary 通道上 ata0/ata1 共享总线，一个
/// 驱动位卡死即全通道瘫痪，故障立刻在目录列表上可见（根目录列表缩水/报错）。
///
/// 注：该故障面**不因块缓存而消失**。块缓存（`fs::block_cache`，经
/// `vfs_init::cached_bridge_for` 包裹本驱动）只消除**重复读**；首次读
/// 未命中的元数据块仍要落盘，卡死的通道照样让该次读失败。
///
/// ATA 规范的恢复路径：Device Control 寄存器置 SRST≥5µs 后清除，设备自行
/// 内部复位并回到 READY。复位作用于**整个通道**（两个驱动位一起复位），
/// 这正是需要的语义：坏的是通道状态机，不是某一个驱动位。
///
/// `channel` 是命令块基址（状态口所在）；控制块基址由调用方按通道给出。
/// 返回复位后通道是否回到可服务状态（BSY 清除，从命令块状态口判定）。
fn soft_reset_channel(channel: u16, ctrl_base: u16) -> bool {
    // 置位 SRST（nIEN 位保持 0，与驱动的轮询模型无冲突）。
    outb(ctrl_base, CTRL_SRST);
    // 规范要求 SRST 保持至少 5µs；一次 io_delay ≈ 1µs，4 次留足余量。
    io_delay();
    io_delay();
    io_delay();
    io_delay();
    // 清除 SRST，设备开始内部复位。
    outb(ctrl_base, 0);
    // 复位完成判定：BSY 从命令块状态口读取。
    wait_not_busy(channel)
}

fn wait_drq(channel: u16) -> bool {
    // 预算依据（drv1 DD2）：与 [`wait_not_busy`] 同一 VM-exit 级论证——
    // 每次轮询是一次 VM exit 级 inb，QEMU 对冷文件首次回写可能超过 1 万次
    // 窗口，20 万次给出数百毫秒上限。ERR/DF 早退分支保证真实故障路径的
    // 成本不受预算放宽影响，放宽只作用于"慢但健康"的数据相位等待。
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

/// 选择通道上的驱动位并锁存 LBA 高位。
///
/// 驱动/磁头寄存器：bit6=LBA 模式（恒 1）、bit4=DEV（0=Master, 1=Slave）、
/// bit[3:0]=LBA bits[27:24]。寻址域就此封顶于 28 位，超域容量由 init_ata
/// 的 [`LBA28_MAX_SECTORS`] 守卫拒绝，不在此静默截断。
fn select_drive_lba(channel: u16, lba: u64, slave: bool) {
    let dev = if slave { 0x10 } else { 0x00 };
    let drive = 0xE0u8 | dev | (((lba >> 24) & 0x0F) as u8);
    outb(channel + REG_DRIVE, drive);
    io_delay();
}

fn set_lba_regs(channel: u16, lba: u64, count: u8) {
    outb(channel + REG_FEATURES, 0);
    outb(channel + REG_SECTOR_COUNT, count);
    outb(channel + REG_LBA_LOW, (lba & 0xFF) as u8);
    outb(channel + REG_LBA_MID, ((lba >> 8) & 0xFF) as u8);
    outb(channel + REG_LBA_HIGH, ((lba >> 16) & 0xFF) as u8);
}

/// 识别指定通道上指定驱动位的设备（drv1 DA2/DD3，M0.4 四设备探测）。
///
/// - `status == 0` → [`AtaIdentify::Absent`]；
/// - IDENTIFY 完成 → 读容量：LBA28 字（word 60/61）为唯一权威
///   （本驱动 LBA28-only，不采信 LBA48 字段——宣称读取却无法寻址等于埋雷）；
/// - 命令失败且 LBA Mid/High 呈 ATAPI 签名（0x14/0xEB）→
///   [`AtaIdentify::AtapiPacket`]，把包设备从"无设备"中显式区分。
pub fn identify_ata(channel: u16, slave: bool) -> AtaIdentify {
    // IDENTIFY 同样是一条完整的 PIO 命令（发 0xEC、等 DRQ、读 256 个字），
    // 与读写共用同一组端口。不加锁的话，启动期识别盘时会与已运行设备的
    // 并发 I/O 互相破坏（ADR-030 四槽位探测与卷挂载可能重叠）。
    let _bus = super::ata_lock::lock();
    if !wait_not_busy(channel) {
        return AtaIdentify::Absent;
    }
    select_drive_lba(channel, 0, slave);
    outb(channel + REG_SECTOR_COUNT, 0);
    outb(channel + REG_LBA_LOW, 0);
    outb(channel + REG_LBA_MID, 0);
    outb(channel + REG_LBA_HIGH, 0);
    outb(channel + REG_COMMAND, ATA_CMD_IDENTIFY);

    let status = status_read(channel);
    if status == 0 {
        return AtaIdentify::Absent;
    }
    if !wait_drq(channel) {
        // 命令失败：读签名口区分 ATAPI 包设备与真缺席（规范定义，
        // IDENTIFY DEVICE 对包设备报错后签名口保持 0x14/0xEB）。
        let mid = inb(channel + REG_LBA_MID);
        let high = inb(channel + REG_LBA_HIGH);
        if mid == ATAPI_SIG_LBA_MID && high == ATAPI_SIG_LBA_HIGH {
            return AtaIdentify::AtapiPacket;
        }
        klib::error!(
            "[ata_pio] identify failed (ch={:#x} slave={}): status={:#04x} sig_mid={:#04x} sig_high={:#04x}",
            channel,
            slave,
            status,
            mid,
            high
        );
        return AtaIdentify::Absent;
    }
    let mut data = [0u16; 256];
    for word in data.iter_mut() {
        *word = data_read(channel);
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

fn ata_read_sector(channel: u16, slave: bool, lba: u64, out: &mut [u8; 512]) -> bool {
    // 整个 PIO 事务在总线锁内：选驱动器 -> 发命令 -> 等 DRQ -> 读数据字。
    // 锁必须在**函数入口**取得并覆盖全程——只锁单条 outb 无法阻止另一 CPU
    // 在两次 outb 之间插入它自己的 LBA/COMMAND 写（那正是短读的成因）。
    // 可重入：write_at 的部分扇区写会在持有本锁时再调本函数（读-改-写）。
    let _bus = super::ata_lock::lock();
    let drive = if slave { "slave" } else { "master" };
    for attempt in 0..3 {
        if !wait_not_busy(channel) {
            klib::error!(
                "[ata_pio] read ch={:#x} {} lba={} attempt={} failed: device stuck BSY",
                channel,
                drive,
                lba,
                attempt
            );
            // 重试前软复位通道：卡死的 BSY 不会自愈，空转重试只是撞墙。
            // （attempt=0 不复位：瞬时挤占常见，复位成本（通道全体离线片刻）
            //  只该在确认卡死时支付。）
            if attempt > 0 {
                if let Some(ctrl) = ctrl_base_of(channel) {
                    let ok = soft_reset_channel(channel, ctrl);
                    if !ok {
                        klib::error!(
                            "[ata_pio] read ch={:#x} {}: soft reset did not clear BSY",
                            channel,
                            drive
                        );
                    }
                }
            }
            continue;
        }
        select_drive_lba(channel, lba, slave);
        set_lba_regs(channel, lba, 1);
        outb(channel + REG_COMMAND, ATA_CMD_READ_SECTORS);
        let st = status_read(channel);
        let drq_ok = wait_drq(channel);
        if st == 0xFF || (st & ATA_SR_ERR) != 0 || (st & ATA_SR_DF) != 0 || !drq_ok {
            // 失败诊断：status 原值 + 各标志位拆解（ERR=0x01 DF=0x20 DRQ=0x08）。
            klib::error!(
                "[ata_pio] read ch={:#x} {} lba={} attempt={} failed: status={:#04x} err={} df={} drq_wait={}",
                channel,
                drive,
                lba,
                attempt,
                st,
                st & ATA_SR_ERR != 0,
                st & ATA_SR_DF != 0,
                drq_ok
            );
            if let Some(ctrl) = ctrl_base_of(channel) {
                let _ = soft_reset_channel(channel, ctrl);
            }
            continue;
        }
        for i in 0..256 {
            let word = data_read(channel);
            out[i * 2] = (word & 0xFF) as u8;
            out[i * 2 + 1] = (word >> 8) as u8;
        }
        return true;
    }
    // 重试耗尽：兜底软复位，把通道留在干净状态——下一个 LBA/下一次调用
    // 从 attempt=0 开始，不复位就会先白撞三次 BSY。
    if let Some(ctrl) = ctrl_base_of(channel) {
        let _ = soft_reset_channel(channel, ctrl);
    }
    false
}

fn ata_write_sector(channel: u16, slave: bool, lba: u64, data: &[u8; 512]) -> bool {
    // 同 ata_read_sector：读写在**同一组端口**上，写与读并发一样会互相破坏
    // （尤其 write_at 的读-改-写序列本身就是读后立刻写）。
    let _bus = super::ata_lock::lock();
    let drive = if slave { "slave" } else { "master" };
    for attempt in 0..3 {
        if !wait_not_busy(channel) {
            klib::error!(
                "[ata_pio] write ch={:#x} {} lba={} attempt={} failed: device stuck BSY",
                channel,
                drive,
                lba,
                attempt
            );
            // 同 read：确认卡死才复位（attempt>0），通道级恢复。
            if attempt > 0 {
                if let Some(ctrl) = ctrl_base_of(channel) {
                    let _ = soft_reset_channel(channel, ctrl);
                }
            }
            continue;
        }
        select_drive_lba(channel, lba, slave);
        set_lba_regs(channel, lba, 1);
        outb(channel + REG_COMMAND, ATA_CMD_WRITE_SECTORS);
        if !wait_drq(channel) {
            continue;
        }
        for i in 0..256 {
            let word = (data[i * 2] as u16) | ((data[i * 2 + 1] as u16) << 8);
            data_write(channel, word);
        }
        // 完成等待：最后一个数据字写出后，设备置 BSY 把缓冲落盘
        // （QEMU 经异步下半区提交宿主文件）。必须等到命令真正结束再返回，
        // 否则紧随其后的读命令会在 BSY 上撞车——这正是"末端 LBA 读返回 0"
        // 的真实根因：与 LBA 位置无关，任何写后立即读都可能触发。
        if !wait_not_busy(channel) {
            klib::error!(
                "[ata_pio] write ch={:#x} {} lba={} attempt={} failed: device stuck BSY after data phase",
                channel,
                drive,
                lba,
                attempt
            );
            if let Some(ctrl) = ctrl_base_of(channel) {
                let _ = soft_reset_channel(channel, ctrl);
            }
            continue;
        }
        let st = status_read(channel);
        if (st & ATA_SR_ERR) == 0 && (st & ATA_SR_DF) == 0 {
            return true;
        }
        klib::error!(
            "[ata_pio] write ch={:#x} {} lba={} attempt={} failed: status={:#04x} err={} df={}",
            channel,
            drive,
            lba,
            attempt,
            st,
            st & ATA_SR_ERR != 0,
            st & ATA_SR_DF != 0
        );
        if let Some(ctrl) = ctrl_base_of(channel) {
            let _ = soft_reset_channel(channel, ctrl);
        }
    }
    // 耗尽兜底：同 read——把通道留在干净状态。
    if let Some(ctrl) = ctrl_base_of(channel) {
        let _ = soft_reset_channel(channel, ctrl);
    }
    false
}

pub struct AtaPioDevice {
    pub name: &'static str,
    /// 通道寄存器基址（Primary 0x1F0 / Secondary 0x170）。
    pub channel: u16,
    /// 驱动位：false=Master, true=Slave。
    pub slave: bool,
    /// 硬件 I/O 位置（登记用）：0x1F0/0x1F0/0x170/0x170。
    pub location: u32,
    pub sectors: Mutex<u64>,
    pub is_hardware: Mutex<bool>,
    /// 真实 I/O 计数（C16.1）：硬件路径按成功 sector 命令计数，
    /// 回退路径按触碰扇区块计数。
    pub stats: IoStats,
    /// 热插拔拔除通知一次性守卫（ADR-030 热插拔）：设备消失（IO 暴露
    /// status=0xFF）时触发一次 unregister + DeviceDeparted；`swap` 置 true
    /// 保证每个槽位只拔除一次，避免后续每次失败 IO 重复拔除。
    pub gone: AtomicBool,
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
            // S04：用 try_from 而非 as usize——as 在非 64 位目标上会截断 u64
            // 偏移；try_from 失败如实返回 0，不静默截断。
            let Ok(off) = usize::try_from(offset) else {
                return 0;
            };
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
            // **读失败先重试同一个 LBA，不要直接 break。**
            //
            // 此前失败即 break，把「读了一部分」当正常短读返回给上层——
            // 于是并发的瞬时故障被静默降级成 ShortRead，一路冒泡到 EXT2
            // 的根 inode 读取处炸成 panic。而 ATA 的瞬时失败（并发挤掉一次
            // 命令、设备短暂 BSY）与真拔盘在**单次**失败上无法区分。
            //
            // 重试到耗尽仍失败，才按「设备消失」处理——那时 is_device_gone
            // 的 3 次 status 重读才有判别力。
            let mut rd_ok = false;
            for _ in 0..SECTOR_RETRIES {
                if ata_read_sector(self.channel, self.slave, lba, &mut buf) {
                    rd_ok = true;
                    break;
                }
            }
            if !rd_ok {
                // 热插拔被动检测：IO 失败后总线飘高为 0xFF ⇒ 设备已消失
                // （拔盘/掉线）。触发一次 unregister + DeviceDeparted，使
                // volumed 卸载对应卷（ADR-030 热插拔闭环）。
                if is_device_gone(self.channel) {
                    notify_device_gone(self);
                }
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
            // S04：同 read_at——用 try_from 而非 as usize，防截断。
            let Ok(off) = usize::try_from(offset) else {
                return 0;
            };
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
                // 同 read_at：先重试同扇区，耗尽才按设备消失处理。
                let mut rd_ok = false;
                for _ in 0..SECTOR_RETRIES {
                    if ata_read_sector(self.channel, self.slave, lba, &mut buf) {
                        rd_ok = true;
                        break;
                    }
                }
                if !rd_ok {
                    if is_device_gone(self.channel) {
                        notify_device_gone(self);
                    }
                    break;
                }
                self.stats.record_read(1);
                buf[sector_off..sector_off + take].copy_from_slice(&data[done..done + take]);
                let mut wr_ok = false;
                for _ in 0..SECTOR_RETRIES {
                    if ata_write_sector(self.channel, self.slave, lba, &buf) {
                        wr_ok = true;
                        break;
                    }
                }
                if !wr_ok {
                    if is_device_gone(self.channel) {
                        notify_device_gone(self);
                    }
                    break;
                }
                self.stats.record_write(1);
            } else {
                buf.copy_from_slice(&data[done..done + 512]);
                let mut wr_ok = false;
                for _ in 0..SECTOR_RETRIES {
                    if ata_write_sector(self.channel, self.slave, lba, &buf) {
                        wr_ok = true;
                        break;
                    }
                }
                if !wr_ok {
                    if is_device_gone(self.channel) {
                        notify_device_gone(self);
                    }
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

    fn probe_alive(&self) -> Option<bool> {
        // 轻量存活探测：**只读 status 寄存器判定设备在不在，不触发完整 PIO 读**
        // （不发 read 命令、不忙等数据相位）。`is_device_gone` 只读 3 次 status，
        // 代价可忽略——与 `read_at` 的 20 万次 inb 忙等相比，对账/心跳用本方法
        // 不会阻塞调度与键盘 IRQ（本会话实测：read_at 探测导致输入积压）。
        // 已消失的设备在此触发拔除（unregister + DeviceDeparted），供 volumed 卸载。
        let is_hw = *self.is_hardware.lock();
        if !is_hw {
            // RAM 回退盘恒在（内存介质，无总线可拔）。
            return Some(true);
        }
        if is_device_gone(self.channel) {
            notify_device_gone(self);
            return Some(false);
        }
        Some(true)
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

/// identify 成功时的真实硬件盘身份（M0.4 四设备）：
/// 背后是可持久化介质（-hda/-hdb 镜像/真机硬盘）。
pub static ATA_PRIMARY_MASTER: AtaPioDevice = AtaPioDevice {
    name: "ata0",
    channel: ATA_PRIMARY_BASE,
    slave: false,
    location: ATA_PRIMARY_BASE as u32,
    sectors: Mutex::new(0),
    is_hardware: Mutex::new(false),
    stats: IoStats::new(),
    gone: AtomicBool::new(false),
};
pub static ATA_PRIMARY_SLAVE: AtaPioDevice = AtaPioDevice {
    name: "ata1",
    channel: ATA_PRIMARY_BASE,
    slave: true,
    location: ATA_PRIMARY_BASE as u32,
    sectors: Mutex::new(0),
    is_hardware: Mutex::new(false),
    stats: IoStats::new(),
    gone: AtomicBool::new(false),
};
pub static ATA_SECONDARY_MASTER: AtaPioDevice = AtaPioDevice {
    name: "ata2",
    channel: ATA_SECONDARY_BASE,
    slave: false,
    location: ATA_SECONDARY_BASE as u32,
    sectors: Mutex::new(0),
    is_hardware: Mutex::new(false),
    stats: IoStats::new(),
    gone: AtomicBool::new(false),
};
pub static ATA_SECONDARY_SLAVE: AtaPioDevice = AtaPioDevice {
    name: "ata3",
    channel: ATA_SECONDARY_BASE,
    slave: true,
    location: ATA_SECONDARY_BASE as u32,
    sectors: Mutex::new(0),
    is_hardware: Mutex::new(false),
    stats: IoStats::new(),
    gone: AtomicBool::new(false),
};

/// identify 失败时的内存回退盘身份（DMYGH #15）：
/// 独立注册名 + 易失披露，杜绝以 "ata0" 名义伪装持久硬盘。
static ATA_RAM_FALLBACK: AtaPioDevice = AtaPioDevice {
    name: "ata0-ramfallback",
    channel: ATA_PRIMARY_BASE,
    slave: false,
    location: ATA_PRIMARY_BASE as u32,
    sectors: Mutex::new(0),
    is_hardware: Mutex::new(false),
    stats: IoStats::new(),
    gone: AtomicBool::new(false),
};

/// 回退盘容量：128 扇区 × 512B = 64KiB。
const FALLBACK_SECTOR_COUNT: u64 = 128;

/// 四设备探测槽位表（M0.4）：(设备静态, 通道基址, 驱动位, 显示名)。
const DEVICE_SLOTS: [(&AtaPioDevice, u16, bool); 4] = [
    (&ATA_PRIMARY_MASTER, ATA_PRIMARY_BASE, false),
    (&ATA_PRIMARY_SLAVE, ATA_PRIMARY_BASE, true),
    (&ATA_SECONDARY_MASTER, ATA_SECONDARY_BASE, false),
    (&ATA_SECONDARY_SLAVE, ATA_SECONDARY_BASE, true),
];

pub fn init_ata(_hub: &DriverHub) {
    // 身份在 init 时一次性判定并写入注册表，运行期不再变更（无影子状态）。
    // ADR-022 §3：Ata 超域容量拒绝硬件模式（不钳制——钳制是对介质容量的
    // 说谎）；AtapiPacket 不落回退盘（硬件存在而伪造 RAM 盘会掩盖可支持的
    // 未来目标）；Absent 维持 DMYGH #15 披露式回退政策（仅当四设备全缺席时
    // 才落 RAM 回退，且只回退一块）。
    let mut found_hardware = false;

    for (dev, channel, slave) in DEVICE_SLOTS {
        match identify_ata(channel, slave) {
            AtaIdentify::Ata(sec) if sec <= LBA28_MAX_SECTORS => {
                *dev.sectors.lock() = sec;
                *dev.is_hardware.lock() = true;
                info!(
                    "[ata_pio] ATA {} hardware identified: {} sectors ({} MB), LBA28 domain",
                    dev.name,
                    sec,
                    (sec * 512) / (1024 * 1024)
                );
                register_device(dev, dev.name, false);
                found_hardware = true;
            }
            AtaIdentify::Ata(sec) => {
                klib::error!(
                    "[ata_pio] refusing unsafe hardware access on '{}': disk capacity {} sectors exceeds LBA28 addressing limit {} (offsets would silently wrap and corrupt data)",
                    dev.name,
                    sec,
                    LBA28_MAX_SECTORS
                );
                // 超域盘不可用，也不伪造回退；继续考察其余槽位。
            }
            AtaIdentify::AtapiPacket => {
                info!(
                    "[ata_pio] ATAPI packet device detected on '{}'; LBA28 PIO block driver does not support packet devices - no block device registered",
                    dev.name
                );
            }
            AtaIdentify::Absent => {
                // 该槽位无设备；不登记、不伪造。四槽全缺席时最后统一落回退。
            }
        }
    }

    if found_hardware {
        return;
    }

    // DMYGH #15：四设备全缺席（纯 CD-ROM 或无盘）时如实登记非持久内存
    // 回退盘，日志保留 fallback 说明，设备列表同步携带 volatile=true。
    *ATA_RAM_FALLBACK.sectors.lock() = FALLBACK_SECTOR_COUNT;
    *ATA_RAM_FALLBACK.is_hardware.lock() = false;
    info!(
        "[ata_pio] no ATA hardware found; fallback to NON-PERSISTENT RAM storage '{}' ({} KiB) - all data is lost on reboot",
        ATA_RAM_FALLBACK.name,
        (FALLBACK_SECTOR_COUNT * 512) / 1024
    );
    register_device(&ATA_RAM_FALLBACK, ATA_RAM_FALLBACK.name, true);
}

/// 设备是否已从 ATA 总线消失/不可用：status 持续为 `0xFF`（总线空闲飘高、
/// 设备无响应）或持续报 `ERR/DF`（设备报错且无法恢复），经短暂重读排除瞬时
/// 抖动。真实物理拔盘呈现 0xFF；后端移除（如 QEMU `drive_del`）呈现 ERR——
/// 两者都表示设备已不可服务，判定消失并触发热插拔拔除。
fn is_device_gone(channel: u16) -> bool {
    for _ in 0..3 {
        let s = status_read(channel);
        if s != 0xFF && (s & (ATA_SR_ERR | ATA_SR_DF)) == 0 {
            return false;
        }
    }
    true
}

/// 热插拔拔除通知（ADR-030 热插拔闭环）：IO 失败暴露设备无响应
/// （status=0xFF）时，判定设备已从总线消失，触发一次 unregister +
/// `DeviceDeparted`，使 volumed 卸载对应挂载点。**被动检测**——只在真实
/// IO 失败暴露总线飘高时判定，不做主动周期探测（ADR-030 §决策3 不做轮询）。
/// 一次性守卫：每个槽位 `gone` 经 `swap` 只置位一次，后续失败 IO 不再重复
/// 拔除（避免对已移除设备重复发布 departed 事件）。
fn notify_device_gone(dev: &AtaPioDevice) {
    if dev.gone.swap(true, Ordering::AcqRel) {
        return;
    }
    info!(
        "[ata_pio] device '{}' gone (IO status=0xFF, no response); hot-unplug",
        dev.name
    );
    DriverHub::unregister_device_by_name(dev.name);
}

/// 登记一块盘到 DriverHub（volatile 语义直通，无影子状态）。
fn register_device(dev: &'static AtaPioDevice, name: &'static str, volatile: bool) {
    if let Err(e) = DriverHub::register_device_info(
        DeviceInfo {
            name,
            kind: DeviceKind::Block,
            bus: BusType::Platform,
            location: dev.location,
            vendor_id: 0,
            device_id: 0,
            class_code: 0x01,
            subclass: 0x01,
            prog_if: 0x8A,
            volatile,
            // ATA PIO 为平台通道，此处不关联 PCI 中断线（走同步 PIO 忙等）。
            irq_line: 0,
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
