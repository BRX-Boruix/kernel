//! Core 阶段：CMOS RTC 硬件实时时钟驱动。

use crate::device::{BusType, CharDevice, Device, DeviceInfo, DeviceKind, DeviceOps, IoDevice};
use crate::driver::DriverStage;
use crate::hub::DriverHub;
use arch_x86_64::port::{inb, outb};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtcTime {
    pub sec: u8,
    pub min: u8,
    pub hour: u8,
    pub day: u8,
    pub month: u8,
    pub year: u8,
    pub century: u16,
}

fn read_cmos(register: u8) -> u8 {
    outb(0x70, register);
    inb(0x71)
}

fn bcd_to_binary(value: u8, is_bcd: bool) -> u8 {
    if is_bcd {
        ((value >> 4) * 10) + (value & 0xF)
    } else {
        value
    }
}

pub fn read_rtc_time() -> Option<RtcTime> {
    for _ in 0..5 {
        let status_a = read_cmos(0x0A);
        if status_a & 0x80 != 0 {
            // CMOS 正在更新时钟，重试
            continue;
        }

        let sec = read_cmos(0x00);
        let min = read_cmos(0x02);
        let hour = read_cmos(0x04);
        let day = read_cmos(0x07);
        let month = read_cmos(0x08);
        let year = read_cmos(0x09);
        let century = read_cmos(0x32);
        let register_b = read_cmos(0x0B);

        let is_bcd = (register_b & 0x04) == 0;
        let is_24h = (register_b & 0x02) != 0;

        let mut sec = bcd_to_binary(sec, is_bcd);
        let min = bcd_to_binary(min, is_bcd);
        let mut hour = bcd_to_binary(hour & 0x7F, is_bcd);
        let day = bcd_to_binary(day, is_bcd);
        let month = bcd_to_binary(month, is_bcd);
        let year = bcd_to_binary(year, is_bcd);
        let mut century_val = if century != 0 {
            bcd_to_binary(century, is_bcd) as u16
        } else {
            20
        };

        if !is_24h && (read_cmos(0x04) & 0x80 != 0) {
            hour = ((hour + 12) % 24);
        }

        if century_val == 0 {
            century_val = 20;
        }

        return Some(RtcTime {
            sec,
            min,
            hour,
            day,
            month,
            year,
            century: century_val * 100 + year as u16,
        });
    }
    None
}

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
    fn read(&self, out: &mut [u8]) -> usize {
        if let Some(t) = read_rtc_time() {
            let mut buf = [0u8; 32];
            // Format: YYYY-MM-DD HH:MM:SS\n
            let y = t.century;
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
            buf[14] = b'0' + (t.min / 10);
            buf[15] = b'0' + (t.min % 10);
            buf[16] = b':';
            buf[17] = b'0' + (t.sec / 10);
            buf[18] = b'0' + (t.sec % 10);
            buf[19] = b'\n';
            let n = core::cmp::min(out.len(), 20);
            out[..n].copy_from_slice(&buf[..n]);
            n
        } else {
            0
        }
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
