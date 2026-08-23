//! Core 阶段：CMOS RTC 硬件实时时钟驱动。
//!
//! AA1（双实现收敛）：墙钟读取的唯一实现是 arch 层的
//! [`arch_x86_64::rtc::read_time`]——双读一致性校验、UIP 轮询上界、BCD/二进制
//! 与 12/24 小时制处理都在那一处。本模块只保留设备注册与 DevFS 文本投影
//! （`YYYY-MM-DD HH:MM:SS`），不再维护第二套劣质 CMOS 读路径（原实现无
//! 撕裂防御、世纪寄存器缺失时凭空假设 2000 年代且不校验）。

use crate::device::{BusType, Device, DeviceInfo, DeviceKind, IoDevice};
use crate::driver::DriverStage;
use crate::hub::DriverHub;

pub struct CmosDevice;

impl Device for CmosDevice {
    fn name(&self) -> &'static str {
        "cmos-rtc"
    }

    fn kind(&self) -> DeviceKind {
        DeviceKind::Misc
    }

    fn as_io(&self) -> Option<&dyn IoDevice> {
        Some(self)
    }
}

impl IoDevice for CmosDevice {
    /// 读取当前墙钟，格式化为 `YYYY-MM-DD HH:MM:SS\n`。
    ///
    /// 读失败不可能：arch 实现两遍不一致时重试并在极端情况下返回最后一次
    /// 读到的大致值（成文行为）。输出缓冲不足按截断交付（与其它字符设备
    /// read 语义一致）。
    fn read(&self, out: &mut [u8]) -> usize {
        let t = arch_x86_64::rtc::read_time();
        let mut buf = [0u8; 20];
        let y = t.year as u32;
        buf[0] = b'0' + ((y / 1000) % 10) as u8;
        buf[1] = b'0' + ((y / 100) % 10) as u8;
        buf[2] = b'0' + ((y / 10) % 10) as u8;
        buf[3] = b'0' + (y % 10) as u8;
        buf[4] = b'-';
        buf[5] = b'0' + (t.month / 10);
        buf[6] = b'0' + (t.month % 10);
        buf[7] = b'-';
        buf[8] = b'0' + (t.day / 10);
        buf[9] = b'0' + (t.day % 10);
        buf[10] = b' ';
        buf[11] = b'0' + (t.hour / 10);
        buf[12] = b'0' + (t.hour % 10);
        buf[13] = b':';
        buf[14] = b'0' + (t.minute / 10);
        buf[15] = b'0' + (t.minute % 10);
        buf[16] = b':';
        buf[17] = b'0' + (t.second / 10);
        buf[18] = b'0' + (t.second % 10);
        buf[19] = b'\n';
        let n = core::cmp::min(out.len(), buf.len());
        out[..n].copy_from_slice(&buf[..n]);
        n
    }
}

pub static CMOS_DEV: CmosDevice = CmosDevice;

pub fn init_cmos(_hub: &DriverHub) {
    DriverHub::register_device_info(
        DeviceInfo {
            name: "cmos-rtc",
            kind: DeviceKind::Misc,
            bus: BusType::Platform,
            location: 0x70,
            vendor_id: 0,
            device_id: 0,
            class_code: 0x0C,
            subclass: 0x00,
            prog_if: 0x00,
            // C15.1：CMOS RTC 由主板电池供电，时钟状态在断电后依然持久。
            volatile: false,
        },
        Some(&CMOS_DEV),
        Some("cmos"),
    );
}

pub fn register_cmos_driver() {
    DriverHub::register_driver("cmos", DriverStage::Core, init_cmos);
}
