//! 设备 id 约定（跨总线统一标识）。
//!
//! 一个设备由 [`BusType`]（它挂在哪条总线/按什么方式枚举）+ [`DeviceId`]
//! （总线内身份）共同标识。驱动用 `matches(&DeviceId)` 声明支持哪些设备，
//! 总线枚举（probe）用 id 匹配驱动。

/// 总线类型：设备通过哪种机制被发现/枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BusType {
    /// 系统总线：无标准发现机制（板载设备，如 legacy 串口、RTC）。
    System = 0,
    /// PCI 总线（配置空间枚举）。
    Pci = 1,
    /// 串行端口（COM1..4，legacy 编址）。
    Serial = 2,
    /// PS/2（8042 控制器）。
    Ps2 = 3,
    /// 显示输出（framebuffer）。
    Framebuffer = 4,
    /// ACPI 表枚举。
    Acpi = 5,
}

impl BusType {
    /// 总线名（调试打印用）。
    pub const fn name(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Pci => "pci",
            Self::Serial => "serial",
            Self::Ps2 => "ps2",
            Self::Framebuffer => "framebuffer",
            Self::Acpi => "acpi",
        }
    }
}

/// 设备 id：总线 + 总线内标识。
///
/// 字段约定（不同总线复用同一结构）：
/// - `System`/`Serial`/`Ps2`：`vendor` 一般为 0，`device` 为实例号/端口号
///   （如 COM1=1、COM2=2），`class` 为设备类别（见 [`DeviceClass`]）；
/// - `Pci`：`vendor`/`device` 为 PCI 厂商/设备号，`class` 为 PCI class code；
/// - `Framebuffer`/`Acpi`：预留，通常匹配整个总线类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId {
    pub bus: BusType,
    pub vendor: u32,
    pub device: u32,
    pub class: u32,
}

impl DeviceId {
    /// 常量构造。
    pub const fn new(bus: BusType, vendor: u32, device: u32, class: u32) -> Self {
        Self {
            bus,
            vendor,
            device,
            class,
        }
    }

    /// 系统总线设备（板载）：按设备类别 + 实例号标识。
    pub const fn system(class: DeviceClass, instance: u32) -> Self {
        Self::new(BusType::System, 0, instance, class as u32)
    }

    /// 串行端口设备：按端口编号（1=COM1..4=COM4）标识。
    pub const fn serial_port(com: u32) -> Self {
        Self::new(BusType::Serial, 0, com, DeviceClass::SerialPort as u32)
    }

    /// PS/2 设备：键盘/鼠标。
    pub const fn ps2(class: DeviceClass) -> Self {
        Self::new(BusType::Ps2, 0, 0, class as u32)
    }

    /// PCI 设备：vendor/device + PCI class code。
    pub const fn pci(vendor: u16, device: u16, class: u32) -> Self {
        Self::new(BusType::Pci, vendor as u32, device as u32, class)
    }

    /// framebuffer 设备（匹配整个总线类别）。
    pub const fn framebuffer() -> Self {
        Self::new(BusType::Framebuffer, 0, 0, 0)
    }

    /// ACPI 设备（按表类型标识，如 FADT）。
    pub const fn acpi(signature: [u8; 4]) -> Self {
        let v = u32::from_le_bytes(signature);
        Self::new(BusType::Acpi, v, 0, 0)
    }
}

/// 设备类别（`class` 字段语义；PCI 设备直接用 PCI class code 覆盖）。
///
/// 主要用于无标准 class 编码的系统/串口/PS2 总线。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum DeviceClass {
    /// 串口设备（UART 16550 等）。
    SerialPort = 0x01,
    /// 键盘。
    Keyboard = 0x02,
    /// 鼠标/指点设备。
    Pointer = 0x03,
    /// 图形显示设备（无 PCI class 时）。
    Display = 0x04,
    /// 定时器/时钟（RTC、PIT）。
    Timer = 0x05,
    /// 未知/通用类别（驱动可按总线+device 匹配）。
    Generic = 0xFF,
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_port_id() {
        let id = DeviceId::serial_port(1);
        assert_eq!(id.bus, BusType::Serial);
        assert_eq!(id.device, 1);
        assert_eq!(id.class, DeviceClass::SerialPort as u32);
        assert_eq!(id.vendor, 0);
    }

    #[test]
    fn pci_id_fields() {
        let id = DeviceId::pci(0x8086, 0x1234, 0x0106);
        assert_eq!(id.bus, BusType::Pci);
        assert_eq!(id.vendor, 0x8086);
        assert_eq!(id.device, 0x1234);
        assert_eq!(id.class, 0x0106);
    }

    #[test]
    fn ps2_keyboard() {
        let id = DeviceId::ps2(DeviceClass::Keyboard);
        assert_eq!(id.bus, BusType::Ps2);
        assert_eq!(id.class, DeviceClass::Keyboard as u32);
    }

    #[test]
    fn acpi_signature() {
        let id = DeviceId::acpi(*b"FACP");
        assert_eq!(id.bus, BusType::Acpi);
        assert_eq!(id.vendor, u32::from_le_bytes(*b"FACP"));
    }

    #[test]
    fn bus_names() {
        assert_eq!(BusType::Pci.name(), "pci");
        assert_eq!(BusType::System.name(), "system");
    }
}
