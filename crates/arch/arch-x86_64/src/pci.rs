//! x86-64 PCI 配置空间访问（传统 0xCF8/0xCFC 配置端口）。
//!
//! 实现 `arch::pci::Pci` trait：通过 I/O 端口访问配置空间。
//! - `0xCF8`（CONFIG_ADDRESS）：写访问地址（enable 位 + bus/dev/func + offset）；
//! - `0xCFC`（CONFIG_DATA）：读写配置数据。
//!
//! 这是 PCI 枚举最通用的访问机制（所有 x86 平台都有）；未来如需 ECAM
//! （内存映射配置空间）可另写一个实现，枚举逻辑不变（ADR-007）。

use arch::pci::Pci;

/// 配置空间地址端口。
const CONFIG_ADDRESS: u16 = 0xCF8;
/// 配置空间数据端口。
const CONFIG_DATA: u16 = 0xCFC;

/// x86-64 PCI 配置空间访问实现。
pub struct X8664Pci;

impl X8664Pci {
    /// 构造配置地址寄存器值：
    /// - bit31: enable（必须置 1）
    /// - bits 23..16: bus
    /// - bits 15..11: device
    /// - bits 10..8:  function
    /// - bits 7..2:  register offset（dword 对齐）
    #[inline]
    fn config_address(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
        0x8000_0000u32
            | ((bus as u32) << 16)
            | ((device as u32) << 11)
            | ((function as u32) << 8)
            | ((offset as u32) & 0xFC)
    }
}

impl Pci for X8664Pci {
    fn read_u32(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
        let addr = Self::config_address(bus, device, function, offset);
        crate::port::outl(CONFIG_ADDRESS, addr);
        crate::port::inl(CONFIG_DATA)
    }

    fn write_u32(bus: u8, device: u8, function: u8, offset: u8, value: u32) {
        let addr = Self::config_address(bus, device, function, offset);
        crate::port::outl(CONFIG_ADDRESS, addr);
        crate::port::outl(CONFIG_DATA, value);
    }
}
