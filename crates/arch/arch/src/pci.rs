//! PCI 总线架构抽象（ADR-007）。
//!
//! 通用内核代码只依赖本 trait 完成 PCI 配置空间访问与设备枚举：
//! - [`Pci::read_u32`]/[`Pci::write_u32`]：配置空间 dword 读写（offset 自动
//!   对齐到 4 字节，调用方传 0x00..0x3C 范围内的原始偏移即可）；
//! - [`Pci::read_u16`]/[`Pci::read_u8`]：基于 dword 读的字节/字便捷访问；
//! - [`enumerate_bus`]：通用枚举（对指定 bus 扫描全部 device/function，
//!   逐个回调发现的设备），不依赖具体访问机制。
//!
//! 具体架构实现（x86 用 0xCF8/0xCFC 传统配置端口，RISC-V/AArch64 用
//! ECAM 内存映射）只需提供 dword 读写，枚举逻辑完全共享。

/// PCI 总线号范围（0..=255）。
pub const PCI_MAX_BUSES: usize = 256;
/// 每条总线设备号范围（0..31）。
pub const PCI_MAX_DEVICES: u8 = 32;
/// 每设备功能号范围（0..7）。
pub const PCI_MAX_FUNCTIONS: u8 = 8;

/// 配置空间常用偏移。
pub mod reg {
    /// vendor id（16 位）。
    pub const VENDOR_ID: u8 = 0x00;
    /// device id（16 位）。
    pub const DEVICE_ID: u8 = 0x02;
    /// revision（8 位）。
    pub const REVISION: u8 = 0x08;
    /// prog interface（8 位）。
    pub const PROG_IF: u8 = 0x09;
    /// subclass（8 位）。
    pub const SUBCLASS: u8 = 0x0A;
    /// base class（8 位）。
    pub const CLASS_CODE: u8 = 0x0B;
    /// header type（8 位）。
    pub const HEADER_TYPE: u8 = 0x0E;
}

/// 一个 PCI 设备（function）的标识信息。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciDeviceInfo {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    /// base class（如 0x06 = bridge）。
    pub class: u8,
    /// subclass（如 0x04 = PCI-PCI bridge）。
    pub subclass: u8,
    /// programming interface。
    pub prog_if: u8,
    /// header type（bit7 指示 multi-function）。
    pub header_type: u8,
}

impl PciDeviceInfo {
    /// 组合 class code（`class << 16 | subclass << 8 | prog_if`）。
    pub const fn class_code(&self) -> u32 {
        ((self.class as u32) << 16) | ((self.subclass as u32) << 8) | (self.prog_if as u32)
    }

    /// 是否 multi-function 设备（header type bit7）。
    pub const fn is_multifunction(&self) -> bool {
        self.header_type & 0x80 != 0
    }
}

/// PCI 配置空间访问抽象（全静态方法，风格与 [`crate::Platform`] 一致）。
pub trait Pci {
    /// 读配置空间一个 dword。`offset` 为原始偏移（0x00..0x3C），
    /// 实现方负责对齐（低 2 位清零）。偏移越界返回 0xFFFF_FFFF。
    fn read_u32(bus: u8, device: u8, function: u8, offset: u8) -> u32;

    /// 写配置空间一个 dword。`offset` 同上。
    fn write_u32(bus: u8, device: u8, function: u8, offset: u8, value: u32);

    /// 读配置空间一个字节（默认基于 dword 读实现）。
    fn read_u8(bus: u8, device: u8, function: u8, offset: u8) -> u8 {
        let shift = (offset & 3) * 8;
        (Self::read_u32(bus, device, function, offset & !3) >> shift) as u8
    }

    /// 读配置空间一个字（默认基于 dword 读实现）。
    fn read_u16(bus: u8, device: u8, function: u8, offset: u8) -> u16 {
        let shift = (offset & 2) * 8;
        (Self::read_u32(bus, device, function, offset & !3) >> shift) as u16
    }
}

/// 枚举指定 bus 上的全部 PCI 设备（function）。
///
/// 对每个发现的设备调用 `f`（按 device 号、function 号升序）。
/// 空槽（vendor = 0xFFFF）自动跳过；非 multi-function 设备只扫 function 0。
pub fn enumerate_bus<C: Pci>(bus: u8, mut f: impl FnMut(PciDeviceInfo)) {
    for dev in 0..PCI_MAX_DEVICES {
        // function 0 的 vendor id 决定该 device 是否存在。
        let vendor = C::read_u16(bus, dev, 0, reg::VENDOR_ID);
        if vendor == 0xFFFF {
            continue;
        }
        let header = C::read_u8(bus, dev, 0, reg::HEADER_TYPE);
        let multifunc = header & 0x80 != 0;
        let nfunc = if multifunc { PCI_MAX_FUNCTIONS } else { 1 };
        for func in 0..nfunc {
            let vendor = C::read_u16(bus, dev, func, reg::VENDOR_ID);
            if vendor == 0xFFFF {
                continue;
            }
            let info = PciDeviceInfo {
                bus,
                device: dev,
                function: func,
                vendor_id: vendor,
                device_id: C::read_u16(bus, dev, func, reg::DEVICE_ID),
                class: C::read_u8(bus, dev, func, reg::CLASS_CODE),
                subclass: C::read_u8(bus, dev, func, reg::SUBCLASS),
                prog_if: C::read_u8(bus, dev, func, reg::PROG_IF),
                header_type: C::read_u8(bus, dev, func, reg::HEADER_TYPE),
            };
            f(info);
        }
    }
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    /// 内存模拟配置空间：`[bus][dev][func][offset/4]`。
    struct FakePci {
        space: [[[u32; 16]; PCI_MAX_DEVICES as usize]; 1],
    }

    static FAKE: std::sync::Mutex<FakePci> = std::sync::Mutex::new(FakePci {
        space: [[[0xFFFF_FFFFu32; 16]; 32]; 1],
    });

    impl FakePci {
        fn set_u16(bus: u8, dev: u8, func: u8, offset: u8, v: u16) {
            let w = offset as usize / 4;
            let shift = (offset as usize & 2) * 8;
            let mut g = FAKE.lock().unwrap();
            let cur = g.space[bus as usize][dev as usize][func as usize * 2 + w];
            let mask = 0xFFFFu32 << shift;
            let nv = (cur & !mask) | ((v as u32) << shift);
            g.space[bus as usize][dev as usize][func as usize * 2 + w] = nv;
        }
        fn set_u8(bus: u8, dev: u8, func: u8, offset: u8, v: u8) {
            let w = offset as usize / 4;
            let shift = (offset as usize & 3) * 8;
            let mut g = FAKE.lock().unwrap();
            let cur = g.space[bus as usize][dev as usize][func as usize * 2 + w];
            let mask = 0xFFu32 << shift;
            let nv = (cur & !mask) | ((v as u32) << shift);
            g.space[bus as usize][dev as usize][func as usize * 2 + w] = nv;
        }
    }

    impl Pci for FakePci {
        fn read_u32(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
            let w = (offset & !3) as usize / 4;
            if w >= 16 {
                return 0xFFFF_FFFF;
            }
            let g = FAKE.lock().unwrap();
            g.space[bus as usize][device as usize][function as usize * 2 + w]
        }
        fn write_u32(bus: u8, device: u8, function: u8, offset: u8, value: u32) {
            let w = (offset & !3) as usize / 4;
            if w >= 16 {
                return;
            }
            let mut g = FAKE.lock().unwrap();
            g.space[bus as usize][device as usize][function as usize * 2 + w] = value;
        }
    }

    fn clear() {
        let mut g = FAKE.lock().unwrap();
        for d in g.space.iter_mut() {
            for f in d.iter_mut() {
                *f = [0xFFFF_FFFF; 16];
            }
        }
    }

    #[test]
    fn empty_bus_no_devices() {
        clear();
        let mut count = 0;
        enumerate_bus::<FakePci>(0, |_| count += 1);
        assert_eq!(count, 0);
    }

    #[test]
    fn finds_single_function_device() {
        clear();
        FakePci::set_u16(0, 3, 0, reg::VENDOR_ID, 0x8086);
        FakePci::set_u16(0, 3, 0, reg::DEVICE_ID, 0x1234);
        FakePci::set_u8(0, 3, 0, reg::CLASS_CODE, 0x02);
        FakePci::set_u8(0, 3, 0, reg::SUBCLASS, 0x00);
        FakePci::set_u8(0, 3, 0, reg::PROG_IF, 0x00);
        FakePci::set_u8(0, 3, 0, reg::HEADER_TYPE, 0x00);

        let mut found: Vec<PciDeviceInfo> = Vec::new();
        enumerate_bus::<FakePci>(0, |i| found.push(i));
        assert_eq!(found.len(), 1);
        let d = found[0];
        assert_eq!(d.vendor_id, 0x8086);
        assert_eq!(d.device_id, 0x1234);
        assert_eq!(d.class_code(), 0x0200_00);
        assert!(!d.is_multifunction());
    }

    #[test]
    fn skips_empty_slots_but_finds_later_device() {
        clear();
        // device 0..2 空，device 5 存在。
        FakePci::set_u16(0, 5, 0, reg::VENDOR_ID, 0x10EC);
        FakePci::set_u16(0, 5, 0, reg::DEVICE_ID, 0x8139);
        let mut count = 0;
        enumerate_bus::<FakePci>(0, |_| count += 1);
        assert_eq!(count, 1);
    }

    #[test]
    fn multifunction_enumerates_all_functions() {
        clear();
        for func in 0..4u8 {
            FakePci::set_u16(0, 8, func, reg::VENDOR_ID, 0x1022);
            FakePci::set_u16(0, 8, func, reg::DEVICE_ID, 0x1000 + func as u16);
        }
        FakePci::set_u8(0, 8, 0, reg::HEADER_TYPE, 0x80); // multi-function

        let mut ids: Vec<u16> = Vec::new();
        enumerate_bus::<FakePci>(0, |i| ids.push(i.device_id));
        assert_eq!(ids.len(), 4);
        assert_eq!(ids, vec![0x1000, 0x1001, 0x1002, 0x1003]);
    }

    #[test]
    fn non_multifunction_only_func0() {
        clear();
        // function 0 存在但 header 无 multifunc 位。
        FakePci::set_u16(0, 9, 0, reg::VENDOR_ID, 0x8086);
        // function 1 有 vendor（应被忽略）。
        FakePci::set_u16(0, 9, 1, reg::VENDOR_ID, 0x8086);
        FakePci::set_u8(0, 9, 0, reg::HEADER_TYPE, 0x00);

        let mut count = 0;
        enumerate_bus::<FakePci>(0, |_| count += 1);
        assert_eq!(count, 1);
    }

    #[test]
    fn partial_functions_skipped() {
        clear();
        // multi-function，但 function 1 为空。
        for func in [0u8, 2u8, 3u8] {
            FakePci::set_u16(0, 12, func, reg::VENDOR_ID, 0x1234);
        }
        FakePci::set_u8(0, 12, 0, reg::HEADER_TYPE, 0x80);

        let mut count = 0;
        enumerate_bus::<FakePci>(0, |_| count += 1);
        assert_eq!(count, 3);
    }

    #[test]
    fn byte_and_word_reads() {
        clear();
        FakePci::write_u32(0, 2, 0, 0x10, 0xDEAD_BEEF);
        assert_eq!(<FakePci as Pci>::read_u8(0, 2, 0, 0x10), 0xEF);
        assert_eq!(<FakePci as Pci>::read_u8(0, 2, 0, 0x13), 0xDE);
        assert_eq!(<FakePci as Pci>::read_u16(0, 2, 0, 0x10), 0xBEEF);
        assert_eq!(<FakePci as Pci>::read_u16(0, 2, 0, 0x12), 0xDEAD);
    }
}
