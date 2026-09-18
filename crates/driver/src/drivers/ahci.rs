//! AHCI (Advanced Host Controller Interface) SATA 块驱动（STORAGE-AHCI-2）。
//!
//! ## 为什么需要它（与 ata_pio 的关系）
//!
//! `ata_pio` 走 LBA28 + 每扇区 256 次 `inw`/`outw` 的 PIO 搬运，每次 `inb`
//! 在 QEMU 下都是一次 VM-exit；`wait_not_busy`/`wait_drq` 各轮询最多 20 万次。
//! 数据由设备直接写入内存。这是 STORAGE-AHCI 的核心目标。
//!
//! **两者并存**，不互相替换：探测到 AHCI 控制器就用它，否则回退 `ata_pio`。
//! 真实主板上两种控制器可能同时存在；并存也让 PIO vs AHCI 的量化对比
//! （STORAGE-AHCI-4）成为可能。
//!
//! ## 规范依据
//!
//! 实现依据 **AHCI 1.3.1** 规范与 **SATA 3.2** 的 Register Host-to-Device FIS。
//! 所有寄存器偏移与位定义均标注规范章节号（见各常量注释），不凭记忆写魔数。
//!
//! ## 结构总览（AHCI 1.3.1 §3）
//!
//! ```text
//!   HBA (BAR5 MMIO, 8 KiB 寄存器窗口, §3.1)
//!    ├─ Generic Host Control (CAP/GHC/IS/PI/VS,    偏移 0x00..0x2B)
//!    ├─ Port Register Set  (PxCLB/PxFB/PxCMD/PxTFD, 偏移 0x100 + 0x80*N)
//!    └─ 每端口两张表（物理地址在 PxCLB/PxFB）：
//!         Command List  (32 × 32B 命令头, §3.3.2)
//!         Received FIS  (256B, §3.4)
//!       命令头指向  Command Table (§3.3.3):
//!         CFIS(64B) + ACMD(16B) + Reserved(48B) + PRDT(可变)
//! ```
//!
//! ## 并发与锁序（S21 显式化）
//!
//! **每端口一把锁**（`Port::lock`），锁的粒度为「端口」而非「控制器」——
//! 两个端口可真正并行 DMA（真实 AHCI 控制器各有独立引擎）。
//!
//! 锁获取顺序：**只允许单层**——`Port::lock` 内部**不得**再获取任何其它
//! Port 的锁或全局锁。所有跨端口共享资源（HBA 寄存器基址、CAP 等）都是
//! **只读启动期常量**，无需加锁。此约束排除死锁（无环，因为不存在嵌套）。
//!
//! 中断上下文**不**取该锁：命令完成只靠轮询 PxCI 位清零 + PxIS 判定
//! （见 [`Port::wait_command`]），不着手实现中断驱动的完成路径——那需要
//! 与 DriverHub 的 IRQ 分发约定对齐，属独立工作。当前实现据此如实声明
//! 「同步轮询完成」，不假称支持中断。
//!
//! ## 失败模式（S20 优先设计）
//!
//! - 无 AHCI 控制器 / BAR5 缺失或为 IO 口 / MMIO 映射失败 → 不注册任何设备，
//!   如实留痕（**绝不**伪造 RAM 回退盘冒充 SATA 盘）；
//! - 端口未挂盘（PxSSTS.DET ≠ 3）/ 非 SATA 签名（ATAPI/PM）→ 跳过该端口；
//! - DMA 缓冲分配失败 → 端口禁用并如实报错；
//! - 命令超时 / PxTFD 报错（ERR/TF）→ 返回 `Error::Io`，不静默返回 0 长度；
//! - 容量超 LBA48 可寻址域 → 拒绝该盘（同 `ata_pio` 的超域守卫纪律）。
//!
//! ## 与 ata_pio 的命名互斥
//!
//! 本驱动沿用 `ata0`..`ata3` 命名（映射 AHCI 端口 0..3），**保证与 PIO
//! 路径的设备名一致**：`vfs_init` 的 `DEVICE_CACHES` 按设备名做键，改名的盘
//! 会丢掉块缓存单例。两驱动不会同时登记同名设备——`init_ahci` 在找到控制器
//! 时才登记，而 `init_ata` 只在四槽全缺席时才落回退盘（见各自实现）。

use crate::device::{
    sectors_touched, BlockDevice, BusType, Device, DeviceInfo, DeviceKind, IoDevice, IoStats,
};
use crate::driver::DriverStage;
use crate::hub::DriverHub;
use crate::drivers::pci_bus::{
    enable_bus_master, read_config_u16, read_config_u32, read_config_u8,
};
// PCI 类/子类常量（单点定义在 pci_bus，不在此重复字面量——S13）。
use crate::drivers::pci_bus::{PCI_CLASS_MASS_STORAGE, PCI_SUBCLASS_SATA};
use klib::{error, error::Error, info, warn};
use core::cell::UnsafeCell;
use mm::dma::{alloc_kernel_dma as alloc_kernel_dma_raw, KernelDmaBuffer};
use spin::Mutex;

// ===========================================================================
// HBA Generic Host Control 寄存器（AHCI 1.3.1 §3.1，偏移自 BAR5）
// ===========================================================================

/// 支持的能力（CAP, offset 0x00, RO）。
const HBA_CAP: u64 = 0x00;
/// 全局主机控制（GHC, offset 0x04）。bit0=HR 复位, bit1=IE 中断使能, bit31=AE。
const HBA_GHC: u64 = 0x04;
/// 全局中断状态（IS, offset 0x08, RWC）。bit N = 端口 N 有中断待服务。
///
/// 这是「控制器**是否真的**拉起了中断」的权威证据：端口 `PxIS` 置位后若
/// 汇聚到 `IS` 对应位，说明控制器侧正常；此后中断未到 CPU，问题就在
/// PCI/PIC 路由而非 AHCI。区分这两者是定位「中断不工作」的关键一刀。
const HBA_IS: u64 = 0x08;
/// 端口实现位图（PI, offset 0x0C, RO）：bit N = 端口 N 存在。
const HBA_PI: u64 = 0x0C;
/// 版本（VS, offset 0x10, RO）。
const HBA_VS: u64 = 0x10;

/// GHC.HR（§3.1.2）：HBA 复位请求。置 1 后控制器复位全部端口并把该位清 0。
const GHC_HR: u32 = 1 << 0;
/// GHC.AE（§3.1.2）：AHCI 使能。**必须在访问端口寄存器前置位**。
///
/// 注：GHC.HR（bit0，HBA 复位）本驱动**刻意不使用**——它是破坏性的，会清掉
/// 固件已建立的端口链路状态（实测在 QEMU ich9-ahci 上使 PxSIG 变为无效值
/// 0xffffffff 而无法识别盘）。详见 `init_controller` 的说明。
const GHC_AE: u32 = 1 << 31;
/// GHC.IE（§3.1.2，bit1）：全局中断使能。
///
/// 只有在 GHC.IE 与对应 `PxIE` 位**同时**置起时，端口事件才会向上汇聚到
/// HBA 的 `IS` 并经 PCI IRQ 投递到 CPU（§3.1.3）。二者缺一即静默丢弃——
/// 这也是「使能了中断却收不到」的常见错因，故自检对两者都做读回断言。
const GHC_IE: u32 = 1 << 1;
/// HBA 支持的最大端口数（§3.1.3 `CAP.NP` 是 5 位字段，规范上限 32）。
const MAX_PORTS: u32 = 32;

// ===========================================================================
// Port Register Set（AHCI 1.3.1 §3.3，偏移 0x100 + 0x80 * port）
// ===========================================================================

/// 端口寄存器块起始偏移。
const PORT_BASE: u64 = 0x100;
/// 每个端口寄存器块大小（§3.3）。
const PORT_STRIDE: u64 = 0x80;

/// 端口内寄存器偏移（§3.3.1 表 3-4）。
const PX_CLB: u64 = 0x00; // Command List Base Address (低 32 位)
const PX_CLBU: u64 = 0x04; // Command List Base Address 高 32 位
const PX_FB: u64 = 0x08; // FIS Base Address (低 32 位)
const PX_FBU: u64 = 0x0C; // FIS Base Address 高 32 位
const PX_IS: u64 = 0x10; // Interrupt Status (RWC)
const PX_CMD: u64 = 0x18; // Command and Status
const PX_TFD: u64 = 0x20; // Task File Data
const PX_SIG: u64 = 0x24; // Signature
const PX_SSTS: u64 = 0x28; // SATA Status (SCR0: SStatus)

const PX_SERR: u64 = 0x30; // SATA Error (SCR2, RWC)
const PX_CI: u64 = 0x38; // Command Issue
const PX_IE: u64 = 0x14; // Interrupt Enable (R/W)

/// `PxIE`（§3.3.1.4）使能位：与 `PXIS_COMPLETION_BITS` 同组。
///
/// 使能后，`PxIS` 中对应位置起会**向上汇聚**到 HBA 的 `IS`，在 `GHC.IE` 也
/// 使能时经 PCI IRQ 投递到 CPU。本驱动只使能「命令完成」相关位——不使能
/// `PxE`/错误位，避免磁盘错误把端口中断线淹在错误风暴里（S20）。
const PXIE_COMPLETION_BITS: u32 = PXIS_COMPLETION_BITS;

/// PxCMD（§3.3.1.4）位定义。
const PXCMD_ST: u32 = 1 << 0; // Start: 允许处理命令列表
const PXCMD_FRE: u32 = 1 << 4; // FIS Receive Enable
const PXCMD_FR: u32 = 1 << 14; // FIS Receive Running (RO)
const PXCMD_CR: u32 = 1 << 15; // Command List Running (RO)

/// PxTFD（§3.3.1.5）位定义：错误与忙状态。
const PXTFD_ERR: u32 = 1 << 0; // Task File Error 在 bit0

/// `PxIS` 中表示「一条命令已完成」的位（§3.3.1.4 表 3-3）：
/// `DHRS`(D2H Register FIS，bit0) | `PSS`(PIO Setup FIS，bit1) | `DSS`(DMA Setup FIS，bit2)。
///
/// 一条成功的 DMA 命令必然置 `DHRS`（命令完成 FIS），故这三位的并集
/// 足以表示「至少有一条命令已完成」，用作代际完成的判据。
const PXIS_COMPLETION_BITS: u32 = (1 << 0) | (1 << 1) | (1 << 2);

/// 单次等待命令完成的自旋上限（见 `wait_command` 的说明）。
///
/// 取 200_000：远大于正常硬件的数百次，又能让真正的挂死快速暴露，
/// 而不是像原实现那样把 300_000 次预算在**每条正常命令**上烧完。
const WAIT_SPINS: u32 = 200_000;

/// 等 IRQ 闩锁的自旋上限（STORAGE-AHCI-6b）。
///
/// 取值理由：这只是**中断到达前的短暂等待**，不是命令完成的全部预算——
/// 闩锁等不到时会退回 `WAIT_SPINS` 的有界轮询，故此处无需给足。
/// 取 `WAIT_SPINS / 8`：给中断投递留出合理窗口，同时保证中断失效时
/// 额外开销只占轮询预算的八分之一。
const IRQ_WAIT_SPINS: u32 = WAIT_SPINS / 8;
const PXTFD_BSY: u32 = 1 << 7;

/// PxSSTS（§3.3.1.7）位域：DET(0..3) / SPD(4..7) / IPM(8..11)。
const PXSSTS_DET_MASK: u32 = 0x0F;
/// DET = 3：设备已连接且链路已建立（可通信）。
const PXSSTS_DET_PRESENT: u32 = 0x03;
/// PxSIG 的 SATA 盘签名值（§3.3.1.6）：ATA 设备为 0x00000101。
const SATA_SIG_ATA: u32 = 0x0000_0101;

/// 单个命令头字节数（§3.3.2，8 个 DWORD）。
const CMD_HEADER_BYTES: usize = 32;
/// 命令表在 4KiB 页内，PRDT 起始偏移 = CFIS(64) + ACMD(16) + Reserved(48) = 128。
const CMD_TABLE_PRDT_OFF: usize = 128;
/// 单个 PRDT 表项字节数（§3.3.3）。
const PRDT_ENTRY_BYTES: usize = 16;
/// PRDT 最大表项数（§3.3.3）：32 项。
const PRDT_MAX_ENTRIES: usize = 32;

/// 本驱动单次命令使用第一个槽位（同步读写不排队）。
const CMD_SLOT: usize = 0;

/// 单次 AHCI 命令最大搬运扇区数 = PRDT 项数 × 每项扇区数。
///
/// 每 PRDT 项描述一段物理连续缓冲；本驱动每项搬 1 个扇区（512B），
/// 故单命令上限 32 扇区 = 16 KiB。这与 `ata_pio` 的逐扇区循环不同——
/// 单命令内由**硬件**连续搬运，CPU 不再逐字搬运。
const MAX_SECTORS_PER_CMD: usize = PRDT_MAX_ENTRIES;
// ===========================================================================
// 命令表内存布局（AHCI 1.3.1 §3.3.2 / §3.3.3）
// ===========================================================================

/// 命令头（Command Header，32 字节，§3.3.2 表 3-5）。
///
/// `#[repr(C)]` 是硬性要求：字段偏移必须与规范逐字节一致，否则控制器
/// 会按错误偏移解析（S04：布局不得依赖巧合，用编译期断言守卫）。
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CommandHeader {
    /// DW0 位域（AHCI 1.3.1 §3.3.2「Command Header」，表 3-5）：
    ///
    /// ```text
    ///  31              16 15   12 11 10  9  8  7  6  5  4        0
    /// +------------------+-------+-----+--+--+--+--+--+--+----------+
    /// |      PRDTL       |  PMP  | Rsv |C |B |R |P |W |A |   CFL    |
    /// +------------------+-------+-----+--+--+--+--+--+--+----------+
    /// ```
    ///
    /// - `CFL[4:0]`：命令 FIS 长度，以 DWORD 计（Register H2D = 64B = 16）。
    /// - `A[5]`：ATAPI。`W[6]`：**方向**，1 = 设备→主机（读），0 = 主机→设备（写）。
    /// - `P[7]`：预取。`R[8]`：复位。`B[9]`：BIST。`C[10]`：Clear Busy。
    /// - `PMP[15:12]`：端口复用器端口号（本驱动非 PM，写 0）。
    /// - **`PRDTL[31:16]`：PRDT 项数，位于 DW0 的**高半字**。**
    ///
    /// 位号是**规范事实**，不是可协商的实现细节：写错 `W` 会让控制器按反
    /// 方向搬运（读命令当写发）；写错 `PRDTL` 的位置会让控制器认为
    /// guest 没有提供 PRDT（`prdtl == 0`），命令直接失败。
    ///
    /// 规范之所以把 `PRDTL` 放在 DW0 的高半字，是为了让 DW0 的整个低半字
    /// 与 ATA 任务文件寄存器一一对应（CFL/A/W/P/R/B/C/PMP）。QEMU 的
    /// `AHCICmdHdr` 与之逐字节一致：`uint16_t opts; uint16_t prdtl;`。
    dw0: u32,
    /// DW1：`status`——命令完成时由 HBA 写入「已传输字节数」，软件初值写 0。
    ///
    /// **这里不是 PRDTL**。把 PRDTL 写到这里正是本驱动曾经的真实缺陷：
    /// 控制器从 DW0 高半字读到 `prdtl == 0`，直接判定「无 PRDT」并失败。
    dw1: u32,
    /// DW2..3：命令表物理地址（须 128 字节对齐，§3.3.2）低/高 32 位。
    ctba: u32,
    ctbau: u32,
    /// DW4..7：保留。
    reserved: [u32; 4],
}

/// 编译期布局守卫（S04）：命令头必须是 32 字节且对齐为 4。
const _: () = {
    assert!(core::mem::size_of::<CommandHeader>() == CMD_HEADER_BYTES);
    assert!(core::mem::align_of::<CommandHeader>() == 4);
};

/// 编译期位域守卫（S04）：把「规范规定的位号」钉死，防止再次写错位。
///
/// 这类错误的代价极高且难以察觉：`W` 写错时读命令被当写命令发出，控制器
/// 永不回报完成——现场只有「命令挂起」，没有任何直接的位级线索。
const _: () = {
    // CFL = 16 (0b10000) 必须落在 bit4..0，且不进位到 bit5(A)。
    assert!((16u32 << CH_DW0_CFL_SHIFT) & 0x1F == 16);
    assert!((16u32 << CH_DW0_CFL_SHIFT) & !0x1Fu32 == 0);
    // W 必须在 bit6，不得与 CFL/A(bit5)/P(bit7) 重叠。
    assert!(CH_DW0_W == 0x40);
    assert!(CH_DW0_W >> 6 == 1);
    // PRDTL 必须在 DW0 的**高半字**（bit31..16）——这是曾导致首条命令必然
    // 失败的位号错误，必须有编译期守卫把它钉死（S04）。
    assert!(CH_DW0_PRDTL_SHIFT == 16);
    assert!((1u32 << CH_DW0_PRDTL_SHIFT) == 0x0001_0000);
    // PRDTL 与 CFL/W/PMP 各占半字，不得互相渗透。
    assert!((CH_DW0_PRDTL_MASK & 0xFFFF) == 0);
    assert!((CH_DW0_PRDTL_MASK >> CH_DW0_PRDTL_SHIFT) == 0xFFFF);
    // 打包后的 DW0 高半字必须等于「独立算出的 PRDTL」，反证位移正确。
    assert!((((4u32 << CH_DW0_PRDTL_SHIFT) | 0x50) >> 16) == 4);
};

/// 命令头 DW0 的字段位定义（AHCI 1.3.1 §3.3.2，逐位对应上面的位域图）。
const CH_DW0_CFL_SHIFT: u32 = 0;
/// `W`：传输方向。1 = 设备到主机（读盘），0 = 主机到设备（写盘）。**bit 6**。
const CH_DW0_W: u32 = 1 << 6;
/// `PRDTL`：PRDT 项数。**位于 DW0 的高半字（bit31..16）**，不是 DW1。
const CH_DW0_PRDTL_SHIFT: u32 = 16;
/// `PRDTL` 字段掩码（已就位，可直接与 DW0 相与）。
const CH_DW0_PRDTL_MASK: u32 = 0xFFFF << CH_DW0_PRDTL_SHIFT;
/// Register H2D 命令 FIS 长度，以 DWORD 计：64 字节 / 4 = 16。
const CMD_CFIS_DWORDS: u32 = 16;

/// 按 §3.3.2 把命令头 DW0 打包出来（**唯一**的 DW0 构造点）。
///
/// 单独抽出成函数，是为了让生产路径与回归测试走**同一份**位运算实现：
/// 否则测试断言的是「测试里另写一遍的位运算」，而真正的缺陷（PRDTL 曾被
/// 写到 DW1）恰恰就是位运算放错位置——测试必须钉住生产代码本身。
///
/// - `cfl`：命令 FIS 长度（DWORD 数），落在 bit4..0。
/// - `write`：true = 写盘（主机→设备），false = 读盘（设备→主机）。
/// - `prdtl`：PRDT 项数，落在 **bit31..16**。
#[inline]
fn pack_dw0(cfl: u32, write: bool, prdtl: u32) -> u32 {
    let mut dw0 = (cfl << CH_DW0_CFL_SHIFT) & 0x1F;
    if !write {
        dw0 |= CH_DW0_W; // 读：设备到主机
    }
    dw0 | ((prdtl << CH_DW0_PRDTL_SHIFT) & CH_DW0_PRDTL_MASK)
}
/// Register Host-to-Device FIS（§3.3.3 / SATA 3.2 §10.3.1），64 字节。
///
/// 这是「寄存器型」命令 FIS：AHCI 用它与 ATA 命令寄存器一一对应。
// 注意：不 derive Default——`[u8; 48]` 超过 32 元素，Rust 不为它实现 Default
// （仅 0..=32 有）。本结构一律逐字段构造，不需要 Default。
#[repr(C)]
#[derive(Clone, Copy)]
struct FisRegH2d {
    /// byte0：FIS 类型 = 0x27（Register H2D）。
    fis_type: u8,
    /// byte1：bit7=C（1 表示命令，非控制）；bit0..3=PM Port。
    flags: u8,
    /// byte2：Command 寄存器值。
    command: u8,
    /// byte3：Feature 低字节。
    feature_low: u8,
    /// byte4..6：LBA 低 24 位。
    lba0: u8,
    lba1: u8,
    lba2: u8,
    /// byte7：Device 寄存器（bit6=LBA 模式）。
    device: u8,
    /// byte8..10：LBA 高 24 位。
    lba3: u8,
    lba4: u8,
    lba5: u8,
    /// byte11：Feature 高字节。
    feature_high: u8,
    /// byte12..13：Sector Count（16 位，支持大于 255 扇区的单命令）。
    count_low: u8,
    count_high: u8,
    /// byte14：ICC（Isochronous Command Completion），普通命令为 0。
    icc: u8,
    /// byte15：Control 寄存器。
    control: u8,
    /// byte16..63：保留（48 字节）。
    reserved: [u8; 48],
}

/// 编译期布局守卫：FIS 必须恰好 64 字节。
const _: () = {
    assert!(core::mem::size_of::<FisRegH2d>() == 64);
};

/// FIS 类型：Register Host-to-Device（SATA 3.2 §10.3.1）。
const FIS_TYPE_REG_H2D: u8 = 0x27;
/// FIS flags bit7：C = 1 表示这是 Command（而非 Control）。
const FIS_FLAG_C: u8 = 1 << 7;

/// ATA 命令字（本驱动支持的传输）。
const ATA_CMD_READ_DMA_EX: u8 = 0x25; // READ DMA EXT (48-bit LBA)
const ATA_CMD_WRITE_DMA_EX: u8 = 0x35; // WRITE DMA EXT (48-bit LBA)


/// Device 寄存器 bit6：LBA 模式（必须置位才能用 LBA 寻址）。
const ATA_DEV_LBA: u8 = 1 << 6;
/// PRDT 表项（Physical Region Descriptor Table entry，16 字节，§3.3.3）。
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PrdtEntry {
    /// DBA：数据基址物理地址低 32 位（须 2 字节对齐；本驱动用页对齐）。
    dba: u32,
    /// DBAU：高 32 位。
    dbau: u32,
    /// 保留。
    reserved: u32,
    /// DBC：字节数-1（0 表示 1 字节），bit31 = I（中断于此项）。
    dbc: u32,
}

const _: () = {
    assert!(core::mem::size_of::<PrdtEntry>() == PRDT_ENTRY_BYTES);
};

/// DBC 的 I 位：该项完成后置中断。
const PRDT_DBC_I: u32 = 1 << 31;

/// 命令表（Command Table，§3.3.3）：CFIS + ACMD + Reserved + PRDT。
///
/// 固定按最大 PRDT 项数布局，确保命令表**恰好在一页 4KiB 内**：
/// 128 + 32×16 = 640 字节 ≤ 4096，且 §3.3.3 要求命令表不跨页。
#[repr(C)]
#[derive(Clone, Copy)]
struct CommandTable {
    cfis: [u8; 64],
    acmd: [u8; 16],
    reserved: [u8; 48],
    prdt: [PrdtEntry; PRDT_MAX_ENTRIES],
}

const _: () = {
    // 命令表必须在一页内，且 PRDT 起始偏移与规范一致（S04）。
    assert!(core::mem::size_of::<CommandTable>() <= 4096);
    assert!(core::mem::offset_of!(CommandTable, prdt) == CMD_TABLE_PRDT_OFF);
};

/// 命令列表的槽位数（§3.3.2：固定 32）。
///
/// 用于**编译期校验**本驱动使用的 [`CMD_SLOT`] 落在合法槽位内——
/// 越界槽位会让 PxCI 位与命令头错位，控制器取到错误命令（§3.3.2）。
const CMD_SLOTS: usize = 32;

/// Received FIS 区字节数（§3.4：固定 256 B）。
const RX_FIS_BYTES: usize = 256;

const _: () = {
    // 本驱动只用第一个槽位；断言它在合法范围内（S19）。
    assert!(CMD_SLOT < CMD_SLOTS);
    // FIS 区必须能被分配到的 4 KiB 页完整容纳（§3.4 对齐要求）。
    assert!(RX_FIS_BYTES <= 4096);
};
// ===========================================================================
// 端口运行态
// ===========================================================================

/// 一个已初始化并挂盘的 AHCI 端口。
///
/// 所有 `Option<KernelDmaBuffer>` 字段在 [`Port::init_hardware`] 中分配；
/// 分配失败则整体回滚，已分配的 buffer 随 Drop 归还，错误路径不泄漏帧（S18）。
struct Port {
    /// HBA 寄存器基址（虚拟地址，MMIO）。
    hba: u64,
    /// 端口号（0..=31）。
    index: u8,
    /// 命令列表（32 头 × 32B = 1 KiB，须 1 KiB 对齐，§3.3.2）。
    cmd_list: Option<KernelDmaBuffer>,
    /// Received FIS 区（256 B，须 256 字节对齐，§3.4）。
    rx_fis: Option<KernelDmaBuffer>,
    /// 命令表（一页，§3.3.3）。
    cmd_table: Option<KernelDmaBuffer>,
    /// 数据缓冲（Bounce buffer）：设备 DMA 的落点。
    ///
    /// 为什么需要：PRDT 描述的是**物理地址**，而调用方传入的是任意
    /// `&mut [u8]`，其物理连续性无保证。故先把数据 DMA 进/出这块物理
    /// 连续的缓冲，再由 CPU 做一次内存拷贝。这仍远快于 PIO——拷贝发生在
    /// RAM 内（纳秒级），而 PIO 每次 `inw` 都是一次 VM-exit。
    data: Option<KernelDmaBuffer>,
    /// 盘容量（扇区数，来自 IDENTIFY）。
    sectors: u64,
    /// 端口锁（S21：粒度=端口，锁内不得再取任何锁）。
    lock: Mutex<()>,
}

impl Port {
    /// 端口寄存器虚拟地址（基址 + 0x100 + 0x80×index）。
    #[inline]
    fn reg(&self, off: u64) -> u64 {
        self.hba + PORT_BASE + PORT_STRIDE * (self.index as u64) + off
    }

    #[inline]
    fn read32(&self, off: u64) -> u32 {
        // SAFETY：reg() 落在 BAR5 MMIO 窗口内，且该窗口已在 init 期映射。
        // read_volatile 阻止编译器合并/消除 MMIO 读——MMIO 有副作用。
        unsafe { core::ptr::read_volatile(self.reg(off) as *const u32) }
    }

    #[inline]
    fn write32(&self, off: u64, value: u32) {
        // SAFETY：同 read32；write_volatile 保证写不被消除或重排。
        unsafe { core::ptr::write_volatile(self.reg(off) as *mut u32, value) }
    }
}
impl Port {
    /// 按 §3.3.1.4 的握手顺序初始化端口 DMA 结构并启动命令引擎。
    ///
    /// 顺序**不可调换**（规范强制）：
    ///   1. 确保 PxCMD.ST=0 且 PxCMD.FRE=0（否则改基址无效）；
    ///   2. 等 PxCMD.CR=0 与 PxCMD.FR=0（引擎真正停下）；
    ///   3. 写 PxCLB/PxFB 基址；
    ///   4. 置 PxCMD.FRE 与 PxCMD.ST。
    ///
    /// 反例：先置 ST 再改基址会让控制器用过期的基址取命令（§3.3.1.4 明确
    /// 禁止），症状是不确定的 DMA 到任意物理内存。
    fn init_hardware(&mut self) -> Result<(), Error> {
        let cmd = self.read32(PX_CMD);
        // 步骤 1：清 ST 与 FRE。
        self.write32(PX_CMD, cmd & !(PXCMD_ST | PXCMD_FRE));

        // 步骤 2：等待 CR 与 FR 清零（引擎停下）。超时即弃用该端口。
        if !self.wait_clear(PX_CMD, PXCMD_CR, 500_000) {
            warn!("[ahci] port {}: PxCMD.CR did not clear", self.index);
            return Err(Error::Io);
        }
        if !self.wait_clear(PX_CMD, PXCMD_FR, 500_000) {
            warn!("[ahci] port {}: PxCMD.FR did not clear", self.index);
            return Err(Error::Io);
        }

        // 步骤 3：写命令列表与 FIS 基址（低/高 32 位）。
        let cl = self.cmd_list.as_ref().ok_or(Error::Io)?;
        let cl_phys = cl.phys_addr();
        self.write32(PX_CLB, cl_phys as u32);
        self.write32(PX_CLBU, (cl_phys >> 32) as u32);
        let fb = self.rx_fis.as_ref().ok_or(Error::Io)?;
        let fb_phys = fb.phys_addr();
        self.write32(PX_FB, fb_phys as u32);
        self.write32(PX_FBU, (fb_phys >> 32) as u32);
        // 读回验证（S20）：AHCI §3.3.1.4 规定 PxCLB/PxFB 只在 PxCMD.ST=0 且
        // PxCMD.CR=0 时可写；违反时硬件**静默忽略**该写入，后续命令会去读一份
        // 软件从未写过的命令头，现场只表现为「命令超时」——极难反查。
        // 因此必须在此显式验证写入被接受，不接受就立刻失败，而不是继续。
        let clb_rb = self.read32(PX_CLB) as u64 | ((self.read32(PX_CLBU) as u64) << 32);
        let fb_rb = self.read32(PX_FB) as u64 | ((self.read32(PX_FBU) as u64) << 32);
        if clb_rb != cl_phys || fb_rb != fb_phys {
            error!(
                "[ahci] port {}: base-address write ignored: PxCLB {:#x}!={:#x} PxFB {:#x}!={:#x} PxCMD={:#x}",
                self.index, clb_rb, cl_phys, fb_rb, fb_phys, self.read32(PX_CMD)
            );
            return Err(Error::Io);
        }

        // 清端口中断状态与 SATA 错误，避免历史位干扰后续判定。
        self.write32(PX_IS, 0xFFFF_FFFF);
        self.write32(PX_SERR, 0xFFFF_FFFF);

        // STORAGE-AHCI-6b：使能**本端口**的命令完成中断。
        //
        // 只使能完成位（`PXIE_COMPLETION_BITS`，与 `PXIS_COMPLETION_BITS` 同组），
        // **不**使能错误位（S20）：磁盘错误若也走中断线，错误风暴会把端口 IRQ
        // 淹在重复投递里，反而掩盖真正的失败；错误仍由 `PxTFD` 在完成点判定。
        //
        // 顺序：先清 `PxIS`（上一行）再置 `PxIE`，避免使能瞬间把历史状态
        // 当作一次新事件投递出去。
        self.write32(PX_IE, PXIE_COMPLETION_BITS);
        let ie_rb = self.read32(PX_IE);
        if ie_rb & PXIE_COMPLETION_BITS != PXIE_COMPLETION_BITS {
            // 读回不一致：中断使能未生效。这不是致命错误（有界轮询兜底仍能工作），
            // 但必须留痕——否则「以为有中断、实际没有」会让性能判断失真（S39）。
            warn!("[ahci] port {}: PxIE not latched (wrote {:#x}, read {:#x})", self.index, PXIE_COMPLETION_BITS, ie_rb);
        }

        // 步骤 4：置 FRE 与 ST 启动命令引擎与 FIS 接收。
        //
        // 只动 ST 与 FRE 这两位的理由：它们是 §3.3.1.4 明确定义且本驱动
        // 依赖语义的位（ST=允许处理命令列表、FRE=允许接收 FIS）。其余位
        // （如 SUD 设备上电、POD）本驱动**没有可引用的规范依据**，且固件
        // 通常已把它们置为正确值——改写一个语义未经验证的位可能破坏固件
        // 建立的端口状态（S38：不臆测；S06：不做无依据的写）。
        //
        // 注：这正是前面「不做破坏性全控制器复位」的同一条纪律——保留固件
        // 已建立的正确状态，只改本驱动确实需要且依据明确的部分。
        //
        // 重读 PxCMD 而非复用入口处的 `cmd`：步骤 1~3 期间固件/硬件可能已
        // 改动该寄存器（CR/FR 的清除就是硬件在动），用过期快照做读-改-写会
        // 把已经消失的位重新写回去。
        let cur = self.read32(PX_CMD);
        self.write32(PX_CMD, (cur & !(PXCMD_ST | PXCMD_FRE)) | PXCMD_FRE | PXCMD_ST);
        Ok(())
    }

    /// 轮询等待 `(reg & mask) == 0`。超时返回 false（不无限等待）。
    fn wait_clear(&self, off: u64, mask: u32, spins: u32) -> bool {
        for _ in 0..spins {
            if self.read32(off) & mask == 0 {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    /// 命令失败后的端口恢复（§3.3.1.5 / §7.4.1「端口恢复流程」）。
    ///
    /// ## 为什么必须有这一步（真实缺陷，非防御性编程）
    ///
    /// 命令失败（设备回任务文件错误 / 超时）时，HBA 会把 `PxCI` 对应位
    /// **保持置位**直到软件显式清除。若不清，该槽位从此永久「忙」：
    /// 后续每次 `issue_dma` 都在前置门被判「slot still busy」而立刻返回，
    /// 整块盘再也不可用——实测表现为 `probe_capacity` 第一探测失败后，
    /// 后续 48 次二分探测全部刷屏「slot still busy」，盘被误判为 0 容量。
    ///
    /// 恢复序列（严格按 §7.4.1 的顺序，顺序本身就是正确性的一部分）：
    ///   1. 清 `PxCMD.ST` 停止命令引擎，等 `PxCMD.CR` 清零；
    ///   2. 清 `PxCMD.FRE`，等 `PxCMD.FR` 清零；
    ///   3. 清粘滞错误位 `PxSERR` 与 `PxIS`（W1C）；
    ///   4. 重新置 `PxFRE`/`PxST` 恢复工作。
    ///
    /// **绝不能对 `PxCI` 写 `0xFFFF_FFFF`**：`PxCI` 的位是「该槽位有未完成命令」
    /// 的状态位，写 1 到**没有未完成命令**的槽位会被硬件当作「软件请求提交
    /// 一个空命令」，反而把那些位**置起来**。实测：如此写之后 `PxCI` 从
    /// `0x1` 变成 `0xffffffff`，32 个槽位全被判忙，故障面从 1 个槽位扩大到
    /// 整端口。清除挂起槽位的正确途径是**停命令引擎**（步骤 1）——引擎停止时
    /// HBA 自行丢弃未完成的命令并清 `PxCI`。
    ///
    /// **不重置 `PxCLB`/`PxFB`**：它们是本驱动建立的、且与 `cmd_list`/`rx_fis`
    /// 缓冲一一对应；重写它们不会带来任何恢复效果，只会增加一次可能被
    /// 硬件忽略的写入。
    fn recover_after_error(&self) {
        // 1. 停命令引擎：HBA 在此丢弃未完成命令并清 PxCI。
        let cur = self.read32(PX_CMD);
        self.write32(PX_CMD, cur & !(PXCMD_ST | PXCMD_FRE));
        let _ = self.wait_clear(PX_CMD, PXCMD_CR, 500_000);
        let _ = self.wait_clear(PX_CMD, PXCMD_FR, 500_000);
        // 2. 清粘滞错误位（W1C）。
        self.write32(PX_SERR, 0xFFFF_FFFF);
        self.write32(PX_IS, 0xFFFF_FFFF);
        // 3. 重新使能。
        let cur = self.read32(PX_CMD);
        self.write32(PX_CMD, (cur & !PXCMD_FRE) | PXCMD_FRE | PXCMD_ST);
    }
}
impl Port {
    /// 命令头的虚拟地址（第 [`CMD_SLOT`] 槽）。
    fn header_ptr(&self) -> Option<*mut CommandHeader> {
        let cl = self.cmd_list.as_ref()?;
        Some((cl.virt_addr() as *mut u8).wrapping_add(CMD_SLOT * CMD_HEADER_BYTES) as *mut CommandHeader)
    }

    /// 命令表的虚拟地址。
    fn table_ptr(&self) -> Option<*mut CommandTable> {
        let ct = self.cmd_table.as_ref()?;
        Some(ct.virt_addr() as *mut CommandTable)
    }

    /// 按命令结果判定端口是否报错（§3.3.1.5 PxTFD）。
    fn task_file_error(&self) -> bool {
        let tfd = self.read32(PX_TFD);
        tfd & (PXTFD_ERR | PXTFD_BSY) != 0 || (tfd & 0xFF) == 0xFF
    }

    /// 等待第 [`CMD_SLOT`] 槽命令完成。
    ///
    /// ## 完成判据：等待 `PxIS` 本代完成位 + `PxCI` 位落下的双重证据
    ///
    /// ### 曾经的实现与它的真实代价（S32：这里的「慢」是实测出来的）
    ///
    /// 原实现分两阶段：阶段 1 自旋等 `PxCI` 位**被置起**（最多 300_000 次），
    /// 阶段 2 再等它**清零**。它基于一个错误假设——「HBA 会先置位、稍后才清除，
    /// 所以一定能在两次轮询之间观察到置位」。
    ///
    /// 该假设在真实硬件上**不成立**：QEMU 在软件写 `PxCI` 的 MMIO 动作内
    /// **同步完成整条命令**，等软件回到读取点第一次读 `PxCI` 时，位**早已清零**。
    /// 于是阶段 1 每次都把 300_000 次预算**全部烧完**才走「未观察到置位」分支。
    ///
    /// 实测（`test_storage_ahci4_pio_vs_ahci_benchmark`，rdtsc，修复前）：
    ///   - AHCI 单扇区读 22_661_758 cycles/扇区
    ///   - PIO  单扇区读    919_703 cycles/扇区
    /// DMA 比 PIO **慢 24 倍**——一个本该更快的路径被这段自旋拖垮。
    /// 该数字是本优化的全部依据（不靠推测，S32）。
    ///
    /// 修复后同口径实测：AHCI 单扇区 418_287、burst-32 13_242 cycles/扇区；
    /// 对照 PIO 为 839_671 / 625_587。即单扇区 **2.0×**、32 扇区突发 **47×**。
    ///
    /// ### 现在的做法：单次等待 + 双重证据
    ///
    /// `PxCI` 位为 0 有两种含义，必须区分：
    ///   (a) 本代命令已执行完毕并出队（可判成功）；
    ///   (b) 命令尚未被 HBA 取走，或看到的是**上一代**的残留（不可判成功）。
    ///
    /// 用**两条件同时成立**来消歧，不需要"观察中间态"：
    ///   1. `PxIS` 出现本代完成位（`DHRS`/`PSS`/`DSS`）——发命令前已清 `PxIS`，
    ///      故观察到的完成位必定由本代命令产生；
    ///   2. `PxCI` 槽位位已清零——命令确实已出队，DMA 缓冲内容已稳定。
    ///
    /// 两者都成立才返回成功；`PxTFD` 报错则返回失败。
    ///
    /// 超时预算从 300_000 降到 [`WAIT_SPINS`]：正常硬件上命令在数百次自旋内
    /// 完成，原先的巨额预算只是掩盖了阶段 1 的逻辑错误。
    fn wait_command(&self, log_failure: bool) -> Result<(), Error> {
        let bit = 1u32 << CMD_SLOT;

        // STORAGE-AHCI-6b（已修正）：**先查状态，未完成再等中断**。
        //
        // ## 为什么是这个顺序（一次真实的负收益教训）
        //
        // 最初写成「先等 IRQ 闩锁，等不到再轮询」。同启动 A/B 实测该顺序
        // **比纯轮询慢 1.88x**（23885782 vs 44810508 cycles/read），根因实测
        // 确认：**闩锁命中率 0%**（208 次尝试 0 次命中）——QEMU TCG 下命令在
        // 写 `PxCI` 的 MMIO 动作内**同步完成**，中断根本不投递。于是该顺序在
        // **每条正常命令**上先烧满 `IRQ_WAIT_SPINS`（25_000），再走完整
        // `WAIT_SPINS`（200_000）轮询——两头都付，比纯轮询更慢。
        //
        // 这与 STORAGE-AHCI-4 那次「阶段 1 自旋烧满预算」是**同一类缺陷**：
        // 把「等待某事件」放在「先看事件是否已经发生」之前。修正后的顺序是
        // **先做一次 MMIO 复检**：命令已完成（同步控制器、或中断早已投递并
        // 完成）时**零等待**返回；仅当确实未完成时才等中断。
        //
        // 正确性不依赖等待方式：完成判定（`PxIS` 完成位 + `PxCI` 出队
        // + `PxTFD` 无错）三条证据不变（S20）。
        let irq = CONTROLLER_IRQ_LINE.load(core::sync::atomic::Ordering::Relaxed);
        let irq_ok = irq >= 3
            && IRQ_COMPLETION_ENABLED.load(core::sync::atomic::Ordering::Relaxed);

        // 步骤 1：立即复检。同步完成的控制器在此处已返回，零自旋。
        let mut completed = self.read32(PX_IS) & PXIS_COMPLETION_BITS != 0;

        // 步骤 2：仅在**尚未**观察到完成时才等待。
        //   2a. 有可用中断线：等 IRQ 闩锁（真实硬件的常规路径）；
        //   2b. 等不到（中断未投递/无中断线）：退回有界轮询。
        // 两条路径都只是「等待方式」，不改变完成判定。
        if !completed {
            if irq_ok {
                let got = crate::irq_owner::wait_bounded_irq(irq, IRQ_WAIT_SPINS);
                if got {
                    LATCH_HITS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                }
                if !got {
                    // **自适应退让（S32：不付无收益的成本）**：闩锁一次都没等到，
                    // 说明本环境不投递该 IRQ（实测根因：8259 掩码屏蔽了 IRQ11，
                    // 见 `main.rs:849`；控制器侧 `HBA IS=0x1` 证明它确实拉起了中断）。
                    // 此时继续每条命令都等满预算是**纯浪费**——本条记录一次失败，
                    // 之后直接走轮询。这不是「关掉中断」，而是「不重复付已知无收益
                    // 的成本」；一旦某条命令真的等到闩锁，计数清零、中断路径恢复。
                    let n = IRQ_WAIT_MISSES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                    if n + 1 >= IRQ_WAIT_MISS_LIMIT {
                        // 只在**首次**切入退让时告警一次，避免每次重新使能都刷屏。
                        if !IRQ_FALLBACK_WARNED.swap(true, core::sync::atomic::Ordering::Relaxed) {
                            warn!(
                                "[ahci] IRQ {} not delivered; using bounded-polling completion \
                                 (interrupt path stays compiled and re-arms if an IRQ ever latches)",
                                irq
                            );
                        }
                        IRQ_COMPLETION_ENABLED.store(false, core::sync::atomic::Ordering::Relaxed);
                    }
                } else {
                    IRQ_WAIT_MISSES.store(0, core::sync::atomic::Ordering::Relaxed);
                }
                // 闩锁命中即视为**完成**——这不是「该来看了」的提示，而是权威
                // 判据之一。原因：中断 handler 会应答控制器（清 `PxIS`/`IS`，
                // W1C），所以此处再读 `PxIS` 可能已被清成 0。
                //
                // 实测教训：曾写成「闩锁只是提示，仍以 PxIS 为准」，结果
                // `ack_calls=209 latch_hits=0` —— 中断来了 209 次，每次应答
                // 都把 `PxIS` 清掉，等待方读到的永远是「没完成」，于是白等满
                // 预算。**闩锁是在应答之前置的**（见 device_irq_handler 的顺序
                // 说明），因此它才是不可能被自己清掉的可靠证据。
                completed = got || self.read32(PX_IS) & PXIS_COMPLETION_BITS != 0;
            }
            if !completed {
                for i in 0..WAIT_SPINS {
                    if self.read32(PX_IS) & PXIS_COMPLETION_BITS != 0 {
                        POLL_SPINS_BURNED.fetch_add(i as u64, core::sync::atomic::Ordering::Relaxed);
                        completed = true;
                        break;
                    }
                    core::hint::spin_loop();
                }
                if !completed {
                    // 预算耗尽仍未观察到完成位：如实把整段预算计入（S10：不美化）。
                    POLL_SPINS_BURNED.fetch_add(WAIT_SPINS as u64, core::sync::atomic::Ordering::Relaxed);
                }
            }
        }

        // 无论是否观察到完成位，都必须等 PxCI 位落下：位仍置起意味着 HBA
        // 还在处理，此时读 DMA 缓冲是未定义数据。
        let cleared = self.wait_clear(PX_CI, bit, WAIT_SPINS);

        if !cleared {
            // PxCI 位始终不落：命令真的挂死了（不是"太快"）。
            if log_failure {
                warn!(
                    "[ahci] port {}: command did not retire (PxCI={:#x} PxIS={:#x} PxTFD={:#x})",
                    self.index,
                    self.read32(PX_CI),
                    self.read32(PX_IS),
                    self.read32(PX_TFD)
                );
            }
            return Err(Error::Io);
        }

        // 命令已出队：PxTFD 此时报告真实结果。
        if self.task_file_error() {
            if log_failure {
                warn!("[ahci] port {}: command failed, PxTFD={:#x}", self.index, self.read32(PX_TFD));
            }
            return Err(Error::Io);
        }

        // 位已落、无任务文件错误。若连完成位也未观察到，说明命令在极短时间内
        // 完成（完成位与本代轮询错过），此时 PxCI 已清且 PxTFD 无错，两项独立
        // 证据都指向「已执行完毕」，同样判成功。
        let _ = completed;
        Ok(())
    }

    /// 发起一次 DMA 读或写。
    ///
    /// `write` 为 true 表示主机到设备（写盘）。`sectors` 必须 ≤
    /// [`MAX_SECTORS_PER_CMD`]（由调用方保证，PRDT 项数上限）。
    fn issue_dma(&self, lba: u64, sectors: usize, write: bool) -> Result<(), Error> {
        self.issue_dma_inner(lba, sectors, write, true)
    }

    /// 同 [`Self::issue_dma`]，但 `log_failure=false` 时不打印失败告警。
    ///
    /// 供**容量探测**使用：探测的本质就是「故意发一个可能超出盘的 LBA」
    /// 并观察设备是否报错，失败是**预期结果**而非故障。若照常打 warn，
    /// 每次启动会刷出 ~45 行「command timed out / failed」，把真实故障
    /// 淹没在噪声里（S20：告警必须指向真正的异常）。
    fn issue_dma_quiet(&self, lba: u64, sectors: usize, write: bool) -> Result<(), Error> {
        self.issue_dma_inner(lba, sectors, write, false)
    }

    /// [`Self::issue_dma`] 的实现体；`log_failure` 控制失败路径是否告警。
    fn issue_dma_inner(&self, lba: u64, sectors: usize, write: bool, log_failure: bool) -> Result<(), Error> {
        if sectors == 0 || sectors > MAX_SECTORS_PER_CMD {
            return Err(Error::InvalidParam);
        }

        // 前置状态门（§3.3.1.4/§3.3.1.5）：发起新命令前，槽位必须空闲。
        //
        // 若不检查，在上一命令仍挂起（PxCI 位未清）时再次置位同一槽位，
        // 控制器看到的是一次**重复提交**：命令不会被执行，PxCI 位永远不
        // 清零，随后 `wait_command` 只能靠自旋上限退出——表现为真盘 I/O
        // 整体挂死（实测：m72 的 scratch 写触发了这一路径）。
        let bit = 1u32 << CMD_SLOT;
        if !self.wait_clear(PX_CI, bit, 300_000) {
            if log_failure {
                warn!("[ahci] port {}: slot still busy (PxCI={:#x}) before issue", self.index, self.read32(PX_CI));
            }
            return Err(Error::Io);
        }
        // 清中断状态与 SATA 错误：本次命令的完成判定不得受历史位影响
        // （§3.3.1.5：PxIS 是 RWC，须由软件显式写 1 清零）。
        self.write32(PX_IS, 0xFFFF_FFFF);
        self.write32(PX_SERR, 0xFFFF_FFFF);

        let data = self.data.as_ref().ok_or(Error::Io)?;
        let hdr_ptr = self.header_ptr().ok_or(Error::Io)?;
        let tbl_ptr = self.table_ptr().ok_or(Error::Io)?;
        let data_phys = data.phys_addr();
        let cmd = if write { ATA_CMD_WRITE_DMA_EX } else { ATA_CMD_READ_DMA_EX };

        // ---- 填命令表：FIS ----
        // SAFETY：tbl_ptr 指向本端口独有的命令表帧（所有权在 self 内，
        // 无别名），且 entry API 保证独占访问（&self 但命令表不被共享读）。
        unsafe {
            let tbl = &mut *tbl_ptr;
            // 清零 FIS 与 PRDT 区，避免上次命令的残留被控制器误读。
            tbl.cfis = [0u8; 64];
            tbl.prdt = [PrdtEntry::default(); PRDT_MAX_ENTRIES];

            let fis = FisRegH2d {
                fis_type: FIS_TYPE_REG_H2D,
                flags: FIS_FLAG_C, // 命令（非控制）
                command: cmd,
                feature_low: 0,
                lba0: (lba & 0xFF) as u8,
                lba1: ((lba >> 8) & 0xFF) as u8,
                lba2: ((lba >> 16) & 0xFF) as u8,
                device: ATA_DEV_LBA,
                lba3: ((lba >> 24) & 0xFF) as u8,
                lba4: ((lba >> 32) & 0xFF) as u8,
                lba5: ((lba >> 40) & 0xFF) as u8,
                feature_high: 0,
                count_low: (sectors & 0xFF) as u8,
                count_high: ((sectors >> 8) & 0xFF) as u8,
                icc: 0,
                control: 0,
                reserved: [0u8; 48],
            };
            // 逐字节拷贝 FIS 结构到命令表的 CFIS 区。
            let src = &fis as *const FisRegH2d as *const u8;
            for i in 0..64 {
                tbl.cfis[i] = *src.add(i);
            }

            // ---- 填 PRDT：单个表项描述整段传输 ----
            //
            // 数据缓冲是**物理连续**的（buddy 分配的 2^order 页块，见
            // `mm::dma::KernelDmaBuffer`），因此整个 `bytes` 传输可用**一个**
            // PRDT 项描述（§3.3.3.2：单项上限 4 MiB，本驱动单命令 ≤ 16 KiB，
            // 远在限内）。这比每扇区一项更省表项、更少硬件遍历。
            let bytes = sectors * 512;
            tbl.prdt[0] = PrdtEntry {
                dba: data_phys as u32,
                dbau: (data_phys >> 32) as u32,
                reserved: 0,
                // DBC = 字节数 - 1；置 I 位：该项完成时置 PxIS.DHRS，
                // 为将来的中断驱动路径留出正确的描述符语义（§3.3.3）。
                dbc: ((bytes - 1) as u32) | PRDT_DBC_I,
            };
            let prdt_len = 1u32;

            // ---- 填命令头 ----
            let hdr = &mut *hdr_ptr;
            hdr.dw0 = pack_dw0(CMD_CFIS_DWORDS, write, prdt_len);
            // DW1 是 status（HBA 在完成时写入已传输字节数），软件初值写 0。
            hdr.dw1 = 0;
            let ct_phys = self.cmd_table.as_ref().ok_or(Error::Io)?.phys_addr();
            hdr.ctba = ct_phys as u32;
            hdr.ctbau = (ct_phys >> 32) as u32;
        }

        // ---- 清 PxIS 代际标记，再敲 PxCI 启动命令 ----
        //
        // 必须先清 PxIS：`wait_command` 用「PxIS 出现完成位」判定**本代**命令
        // 已完成。若不清，上一代命令残留的完成位会被误认为本代已完成，
        // 于是可能在命令尚未执行时就返回成功（读 DMA 缓冲得到残留/全零），
        // 也可让失败命令被误判为成功（假阳性成功，比假阴性更危险）。
        //
        // 清 PxIS 必须在填写命令头**之后**、启动命令**之前**：填表期间不产生
        // 完成位，而启动后到 `wait_command` 首次读之间若恰好有完成位置起，
        // 清除动作会把本代完成位一并清掉——故清除点紧贴启动点。
        self.write32(PX_IS, 0xFFFF_FFFF);
        self.write32(PX_CI, 1u32 << CMD_SLOT);
        match self.wait_command(log_failure) {
            Ok(()) => Ok(()),
            Err(e) => {
                // 失败时留下完整端口现场：没有这些寄存器值，现场只剩
                // 「命令超时」一句，无法区分是链路断、FIS 错还是 PRDT 错。
                if log_failure {
                    warn!(
                        "[ahci] port {}: {} LBA {} x{} failed: PxCI={:#x} PxIS={:#x} PxTFD={:#x} PxSERR={:#x} PxSSTS={:#x}",
                        self.index,
                        if write { "WRITE" } else { "READ" },
                        lba,
                        sectors,
                        self.read32(PX_CI),
                        self.read32(PX_IS),
                        self.read32(PX_TFD),
                        self.read32(PX_SERR),
                        self.read32(PX_SSTS)
                    );
                }
                // 失败必须恢复端口，否则该槽位永久置忙、整块盘不可用
                // （§7.4.1 端口恢复流程；见 `recover_after_error` 的说明）。
                self.recover_after_error();
                Err(e)
            }
        }
    }
}
// ===========================================================================
// 对外设备
// ===========================================================================

/// 一个 AHCI SATA 盘（实现 `BlockDevice`）。
pub struct AhciDevice {
    pub name: &'static str,
    /// 端口号（登记 `location` 用）。
    pub port_index: u8,
    /// 端口运行态。`None` = 该槽位未探测到盘（不登记）。
    port: Option<Port>,
    /// 盘容量（扇区数）。此处存一份供无锁快路径读取：
    /// `block_count` 在 `&self` 上被调用，不应抢端口锁。
    sectors: Mutex<u64>,
    /// 真实 I/O 计数（C16.1）。
    pub stats: IoStats,
}

impl Device for AhciDevice {
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

impl BlockDevice for AhciDevice {
    fn block_size(&self) -> usize {
        512
    }

    fn block_count(&self) -> u64 {
        *self.sectors.lock()
    }
}

/// 从盘读入 `out.len()` 字节（按扇区粒度 DMA，再拷贝到调用方缓冲）。
fn read_sectors(port: &Port, offset: u64, out: &mut [u8]) -> usize {
    let total = port.sectors;
    if total == 0 {
        return 0;
    }
    let mut lba = offset / 512;
    let mut sector_off = (offset % 512) as usize;
    if lba >= total {
        return 0;
    }
    let data = match port.data.as_ref() {
        Some(d) => d,
        None => return 0,
    };
    let buf_cap = data.capacity() as usize;
    let mut done = 0usize;
    let mut remaining = out.len();
    while remaining > 0 && lba < total {
        let avail = core::cmp::min(total - lba, MAX_SECTORS_PER_CMD as u64) as usize;
        let want = core::cmp::min(avail, (remaining + sector_off + 511) / 512);
        let max_by_cap = buf_cap / 512;
        let n = core::cmp::min(want, max_by_cap);
        if n == 0 {
            break;
        }
        if port.issue_dma(lba, n, false).is_err() {
            break;
        }
        // 从 DMA 落点拷贝到调用方缓冲（RAM 内拷贝，成本远低于逐字 PIO）。
        let src = data.as_slice();
        let bytes = n * 512;
        let take = core::cmp::min(remaining, bytes - sector_off);
        out[done..done + take].copy_from_slice(&src[sector_off..sector_off + take]);
        done += take;
        remaining -= take;
        lba += n as u64;
        sector_off = 0;
    }
    done
}

/// 写出 `data_in.len()` 字节（按扇区粒度 DMA）。
///
/// 非整扇区或非扇区对齐的写需要**读-改-写**（保留扇区内未被覆盖的字节），
/// 否则会破坏同一扇区内相邻数据。本实现如实执行 RMW，不假设调用方对齐。
fn write_sectors(port: &Port, offset: u64, data_in: &[u8]) -> usize {
    let total = port.sectors;
    if total == 0 {
        return 0;
    }
    let mut lba = offset / 512;
    let mut sector_off = (offset % 512) as usize;
    if lba >= total {
        return 0;
    }
    let data = match port.data.as_ref() {
        Some(d) => d,
        None => return 0,
    };
    let buf_cap = data.capacity() as usize;
    let mut done = 0usize;
    let mut remaining = data_in.len();
    while remaining > 0 && lba < total {
        let max_by_cap = buf_cap / 512;
        let avail = core::cmp::min(total - lba, MAX_SECTORS_PER_CMD as u64) as usize;
        let per = (remaining + sector_off + 511) / 512;
        let want = core::cmp::min(avail, core::cmp::min(max_by_cap, per));
        if want == 0 {
            break;
        }
        // 是否需要 RMW：起始非扇区对齐，或本批覆盖不满 want 个扇区。
        let covered = sector_off + remaining;
        let need_rmw = sector_off != 0 || covered < want * 512;
        if need_rmw {
            // 先整批读出，改后再整批写回。
            if port.issue_dma(lba, want, false).is_err() {
                break;
            }
        }
        let bytes = want * 512;
        let take = core::cmp::min(remaining, bytes - sector_off);
        // 数据缓冲是所有端口状态的一部分，而本函数只拿 `&Port`（命令表/
        // 缓冲区经由内部原始指针访问，与 issue_dma 一致）。此处用原始指针
        // 写入同一块缓冲：独占性由**调用方的端口锁**保证（read_at/write_at
        // 均持锁调用本函数），不存在别名写。
        //
        // SAFETY：virt_addr() 指向本端口独有的 DMA 帧（所有权在 Port 内，
        // 不可复制），capacity() 给出其真实长度；调用期间持端口锁，
        // 无并发访问同一缓冲。
        unsafe {
            let dst = core::slice::from_raw_parts_mut(data.virt_addr() as *mut u8, buf_cap);
            for (i, b) in data_in[done..done + take].iter().enumerate() {
                dst[sector_off + i] = *b;
            }
            // 非 RMW 路径（整扇区全覆盖）时把本批剩余字节清零，
            // 避免把上一命令的残留数据写盘。RMW 路径已由上面的读填满。
            if !need_rmw {
                for b in dst[sector_off + take..bytes].iter_mut() {
                    *b = 0;
                }
            }
        }
        if port.issue_dma(lba, want, true).is_err() {
            break;
        }
        done += take;
        remaining -= take;
        lba += want as u64;
        sector_off = 0;
    }
    done
}
impl IoDevice for AhciDevice {
    fn read_at(&self, offset: u64, out: &mut [u8]) -> usize {
        let port = match self.port.as_ref() {
            Some(p) => p,
            None => return 0,
        };
        // S21：端口锁为唯一锁层，内部不再取任何锁。
        let _guard = port.lock.lock();
        let n = read_sectors(port, offset, out);
        if n > 0 {
            self.stats.record_read(sectors_touched(offset, n as u64));
        }
        n
    }

    fn write_at(&self, offset: u64, data_in: &[u8]) -> usize {
        let port = match self.port.as_ref() {
            Some(p) => p,
            None => return 0,
        };
        let _guard = port.lock.lock();
        let n = write_sectors(port, offset, data_in);
        if n > 0 {
            self.stats.record_write(sectors_touched(offset, n as u64));
        }
        n
    }

    fn size(&self) -> Option<u64> {
        Some(*self.sectors.lock() * 512)
    }

    fn io_stats(&self) -> Option<&IoStats> {
        Some(&self.stats)
    }

    fn probe_alive(&self) -> Option<bool> {
        // 轻量存活探测：只读 PxSSTS 的 DET 字段，不发起任何命令。
        // 与 ata_pio 的 probe_alive 同纪律——对账/心跳不得触发完整 IO。
        let port = self.port.as_ref()?;
        let ssts = port.read32(PX_SSTS);
        Some(ssts & PXSSTS_DET_MASK == PXSSTS_DET_PRESENT)
    }
}
/// 用**已验证的 DMA 通路**探测盘容量（扇区数）。
///
/// ## 为什么不用 IDENTIFY DEVICE
///
/// `IDENTIFY DEVICE`(0xEC) 是 **PIO** 命令：数据经 PIO Setup FIS + PIO
/// 数据端口传送，**不经过 PRDT**。本驱动只实现 PRDT/DMA 数据通路，因此
/// 0xEC 拿不到数据；实测在本环境返回任务文件错误（`PxIS.TFES` 与
/// `PxTFD.ERR` 置位）。`IDENTIFY DEVICE DMA`(0xEE) 亦不被设备支持（同样
/// 报任务文件错误）。
///
/// ## 做法：用 READ DMA EXT 做 LBA48 二分探测
///
/// `READ DMA EXT`(0x25) 是本驱动**已经由 ext2 挂载证明可用**的通路。
/// 容量探测不需要读取真实数据语义，只需要「该 LBA 是否可寻址」这一个
/// 布尔信息：设备对超出容量的 LBA 会回任务文件错误。于是对 LBA48 的
/// 可寻址上界做二分即可。
///
/// 二分区间取 `[1, 2^48)`——LBA48 的规范最大可寻址域，**不假设**任何
/// 具体盘容量（不硬编码「60MB」「120GB」之类的经验值）。探测次数为
/// log2(2^48) = 48 次量级，每次一条 DMA 命令，启动期一次性开销可忽略。
///
/// 失败模式（S20）：任一探测命令失败即把该侧判为「不可寻址」并继续；
/// 二分必然终止。若连 LBA 0 都不可寻址，返回 0（调用方拒绝登记该盘）。
fn probe_capacity(port: &Port) -> Result<u64, Error> {
    // LBA 0 必须可寻址，否则这块「盘」根本不响应 DMA——不登记。
    if port.issue_dma_quiet(0, 1, false).is_err() {
        info!("[ahci] port {}: LBA0 not addressable; not a usable disk", port.index);
        return Ok(0);
    }

    // 二分：lo 恒为「已知可寻址」，hi 恒为「已知不可寻址」。
    // 不变量使每次迭代都能安全收缩区间。
    let mut lo: u64 = 0;
    let mut hi: u64 = u64::MAX;
    // 上限收敛到 LBA48 域（2^48 - 1 扇区）。
    const LBA48_LIMIT: u64 = 1u64 << 48;
    if port.issue_dma_quiet(LBA48_LIMIT - 1, 1, false).is_ok() {
        // 极端情况：整个 LBA48 域都可寻址（不合常理，但如实返回）。
        return Ok(LBA48_LIMIT);
    }
    hi = LBA48_LIMIT - 1;

    // 二分收缩：直到 hi - lo <= 1，此时 lo 即可寻址的最大 LBA。
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if port.issue_dma_quiet(mid, 1, false).is_ok() {
            lo = mid;
        } else {
            hi = mid;
        }
    }

    // 可寻址的最大 LBA 为 lo，故扇区总数 = lo + 1。
    info!("[ahci] port {}: capacity probed via READ DMA EXT: {} sectors", port.index, lo + 1);
    Ok(lo + 1)
}

// ===========================================================================
// 发现与初始化
// ===========================================================================

/// 本驱动登记的槽位数（端口 0..4）。
const SLOT_COUNT: usize = 4;

/// 四个设备槽（与 ata_pio 的 ata0..ata3 命名对齐，保证块缓存键不变）。
///
/// ## 为什么是 `UnsafeCell` 而不是裸 `static` + 指针转换
///
/// 端口运行态（`Port`，内含命令表等 DMA 帧所有权与互斥锁）只能在**运行时**
/// 填入，但设备必须具有 `'static` 生命周期才能登记进 DriverHub。早期实现把
/// `&AHCI_SLOTS[i] as *const _ as *mut _` 后直接写入——这是**未定义行为**：
/// `AhciDevice` 不含 `UnsafeCell`，编译器有权假定该 static 的内容恒定不变
/// （它确实可以把这个 `static` 的内容提升/缓存到寄存器或别名到只读段）。
///
/// 实测症状：初始化看似成功（identify、容量、登记日志全部正确），但之后**任何**
/// 一次盘 I/O 都在 `port.lock.lock()` 上永久自旋——因为被写入的 `Mutex`（及
/// 其它字段）与编译器假定看到的那份不是同一处内存。这类失效只在「写入槽位后
/// 再读回」时暴露，是典型的 UB-only 缺陷。
///
/// 用 `UnsafeCell` 显式声明「这些字节会被运行时改写」，由类型系统承载该事实；
/// 并发安全由每个 `Port` 自带的 `Mutex` 与「仅启动期单线程写入」的纪律保证。
struct SlotCell(UnsafeCell<AhciDevice>);

// SAFETY：`AhciDevice` 的所有可变状态都经内部同步原语访问——`port`（`Port`）
// 只在启动期一次性写入（单线程，见 `init_port` 的 SAFETY 注释），此后只读地
// 被 `&` 借用；其内部的 `Mutex<()>` 串行化所有端口寄存器/DMA 访问。
// `sectors` 是 `Mutex<u64>`，`stats` 用原子计数。故跨线程共享 `&SlotCell` 安全。
unsafe impl Sync for SlotCell {}

static AHCI_SLOTS: [SlotCell; SLOT_COUNT] = [
    SlotCell(UnsafeCell::new(new_slot("ata0", 0))),
    SlotCell(UnsafeCell::new(new_slot("ata1", 1))),
    SlotCell(UnsafeCell::new(new_slot("ata2", 2))),
    SlotCell(UnsafeCell::new(new_slot("ata3", 3))),
];

/// `const` 构造一个空槽（未探测到盘时 port = None，不登记）。
const fn new_slot(name: &'static str, index: u8) -> AhciDevice {
    AhciDevice {
        name,
        port_index: index,
        port: None,
        sectors: Mutex::new(0),
        stats: IoStats::new(),
    }
}

/// 已探测到的 SATA 控制器数（诊断/遥测用）。
static AHCI_CONTROLLERS: Mutex<u32> = Mutex::new(0);

/// 首个可用控制器的 HBA 寄存器虚拟基址（0 = 无）。
///
/// 由 `init_controller` 在成功初始化后写入；供中断完成路径与自检观测使用。
static CONTROLLER_HBA_BASE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// 是否允许 `wait_command` 走中断闩锁路径（默认 `true`）。
///
/// **为什么需要运行时开关**：STORAGE-AHCI-4 的轮询 vs DMA 对比是**两次独立
/// QEMU 启动**之间的横向比较（两条路径无法在一次启动内共存），这削弱了
/// 可比性。中断路径没有这个问题——同一份二进制、同一次启动内就能开关，
/// 故 6d 的对比可以做**真 A/B**（同进程、同盘、同缓存状态），这是更强的证据。
///
/// 生产语义不变：默认使能中断优先；关掉即退化为纯有界轮询（仍正确）。
pub static IRQ_COMPLETION_ENABLED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(true);

/// 连续多少次闩锁等待落空后放弃中断优先（见 `wait_command` 的自适应退让）。
///
/// 取 2：一次落空可能是该条命令恰好极快、中断尚未投递；连续两次则足以判定
/// 本环境不投递该 IRQ，继续等待是纯浪费。过大的值会让退让前的浪费变多，
/// 过小则可能在偶发抖动下过早放弃。
const IRQ_WAIT_MISS_LIMIT: u32 = 2;

/// 连续落空计数（成功等到闩锁即清零）。
static IRQ_WAIT_MISSES: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// 退让告警只报一次（避免重复刷屏）。
static IRQ_FALLBACK_WARNED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// TEMP-PROBE: ACK 回调调用次数与闩锁命中次数。
pub static ACK_COUNT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
pub static LATCH_HITS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// 累计应答开销（cycles，同口径相对值）。
pub static ACK_CYCLES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// 已烧掉的自旋次数（有界轮询路径）。用于**证明**机制而非假设：
/// 若中断路径为 0 而轮询路径接近预算，则「中断省掉了空转」是实测结论。
pub static POLL_SPINS_BURNED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// 控制器的真实 PCI 中断线（配置空间 0x3C；0 = 未分配/无中断）。
///
/// **不再硬编码 0**：`register_device` 曾写死 `irq_line: 0`，而 PCI 枚举其实
/// 已从 0x3C 读到真实值（QEMU `ich9-ahci` 实测为 11）。中断完成路径需要
/// 这个值才能把端口事件与 `irq_owner` 的 IRQ 槽对应起来。
static CONTROLLER_IRQ_LINE: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// 探测并初始化 AHCI。找到可用盘时逐块登记到 DriverHub。
///
/// 返回找到的盘数。**不注册任何伪造回退盘**——无控制器时如实返回 0，
/// 由 ata_pio 的回退政策接管（S09：宁可没有，也不返回伪数据）。
pub fn init_ahci(_hub: &DriverHub) -> usize {
    let mut found = 0usize;
    let mut controllers = 0u32;

    let candidates = scan_ahci_controllers();
    if candidates.is_empty() {
        info!("[ahci] no AHCI controller found on PCI bus");
        return 0;
    }

    for (bus, dev, func) in candidates {
        match init_controller(bus, dev, func) {
            Ok(n) => {
                found += n;
                controllers += 1;
            }
            Err(e) => {
                warn!("[ahci] controller {:02x}:{:02x}.{} init failed: {:?}", bus, dev, func, e);
            }
        }
    }

    *AHCI_CONTROLLERS.lock() = controllers;
    found
}

/// 注册 AHCI 驱动。
///
/// **为什么用 `Devices` 阶段却不在该阶段做实际初始化**：AHCI 需要分配物理
/// 连续帧（命令表/PRDT 数据缓冲）并把 ABAR 映射进内核地址空间，而这两项
/// 都依赖 `mm::init()` 与 `paging::init()`。而 `DriverHub` 的全部四个阶段
/// （Early/Core/Devices/Late）都由 `drivers::init()` 在 `main.rs:215` 触发——
/// **早于** `mm::init()`（`main.rs:253`）。因此在本阶段做硬件初始化必然
/// 撞上 `PHYS_OFFSET not initialized` panic（实测复现）。
///
/// 本函数只做**注册登记**（声明驱动存在、供 DriverHub 列举）；真实硬件
/// 初始化由内核在内存管理就绪后显式调用 [`late_storage_init`] 完成。
pub fn register_ahci_driver() -> Result<(), Error> {
    DriverHub::register_driver("ahci", DriverStage::Devices, |_hub| {
        // 故意为空：见上。真正的 init 在 late_storage_init。
    })
}

/// 内存管理就绪后的存储栈初始化（由内核在 `paging::init` 之后显式调用）。
///
/// 做两件事，顺序不可颠倒：
///   1. 先跑 AHCI（依赖 PCI 枚举 + 帧分配 + MMIO 映射）；
///   2. 再跑 ATA PIO（其 `init_ata` 会跳过 AHCI 已认领的槽位）。
///
/// 返回 AHCI 找到的盘数（0 = 无 SATA，此时 PIO 路径服务存储）。
pub fn late_storage_init() -> usize {
    // 先把「规范事实」在真实启动路径上自检一遍（失败即 panic，不静默降级）。
    run_builtin_asserts();
    let hub = DriverHub;
    let n = init_ahci(&hub);
    if n > 0 {
        info!("[ahci] {} SATA disk(s) registered via AHCI DMA", n);
    }
    // ATA PIO 必须在此之后：此时 device_exists 才能看到 AHCI 认领的名字。
    crate::drivers::ata_pio::init_ata(&hub);
    n
}
/// 扫描 PCI 总线找 AHCI 控制器，返回 (bus, device, function) 列表。
///
/// 判定条件（PCI 规范 + AHCI 1.3.1 §2.1.2）：
///   class = 0x01 (Mass Storage), subclass = 0x06 (SATA), prog_if = 0x01 (AHCI 1.0)
///
/// **prog_if 必须校验**：subclass 0x06 也可能是 RAID 或其它非 AHCI 编程接口
/// （prog_if 0x00/0x02/0x03/0x04/0x05/0x06/0x07/0x08）。只认 0x01 才保证
/// 寄存器布局是 AHCI 1.3.1 所定义的那套（否则按错误布局访问 MMIO）。
fn scan_ahci_controllers() -> alloc::vec::Vec<(u8, u8, u8)> {
    let mut out = alloc::vec::Vec::new();
    for bus in 0u16..=255 {
        for dev in 0u8..32 {
            for func in 0u8..8 {
                let vendor = read_config_u16(bus as u8, dev, func, 0x00);
                // 0xFFFF 表示该槽位无设备（PCI 规范）。
                if vendor == 0xFFFF {
                    if func == 0 {
                        break; // 多函数设备的 function 0 缺失 => 整个设备不存在
                    }
                    continue;
                }
                let class = read_config_u8(bus as u8, dev, func, 0x0B);
                let subclass = read_config_u8(bus as u8, dev, func, 0x0A);
                let prog_if = read_config_u8(bus as u8, dev, func, 0x09);
                if class == PCI_CLASS_MASS_STORAGE && subclass == PCI_SUBCLASS_SATA && prog_if == 0x01 {
                    if out.try_reserve(1).is_err() {
                        warn!("[ahci] OOM: cannot record further controllers");
                        return out;
                    }
                    out.push((bus as u8, dev, func));
                }
            }
        }
    }
    out
}

/// 读取指定 PCI 设备的 BAR5（AHCI 的 ABAR，§2.1.2），要求是 32 位或 64 位 MMIO。
///
/// AHCI 规范规定 ABAR 必须是内存空间 BAR；若为 IO 口则该控制器不合规，
/// 如实拒绝而不是按 MMIO 去读（那会访问到错误的地址空间）。
fn read_abar(bus: u8, dev: u8, func: u8) -> Result<u64, Error> {
    // BAR5 在配置空间偏移 0x24。
    let bar5 = read_config_u32(bus, dev, func, 0x24);
    if bar5 & 0x1 != 0 {
        // bit0 = 1 => IO 空间 BAR，AHCI 不合规。
        warn!("[ahci] ABAR is an IO-space BAR; controller is non-conformant");
        return Err(Error::InvalidParam);
    }
    let kind = (bar5 >> 1) & 0x3; // bit1..2: 0=32bit, 2=64bit
    let base = (bar5 & !0xF) as u64;
    if base == 0 {
        warn!("[ahci] ABAR is zero (BIOS did not assign); cannot map");
        return Err(Error::InvalidParam);
    }
    if kind == 0x2 {
        // 64 位 BAR：高 32 位在偏移 0x28（但 0x28 是 BAR6/保留位，64 位 BAR 占用它）。
        let hi = read_config_u32(bus, dev, func, 0x28) as u64;
        Ok(base | (hi << 32))
    } else {
        Ok(base)
    }
}
/// 初始化一个 AHCI 控制器：映射 ABAR、使能、逐端口探测并登记盘。
///
/// 返回找到的盘数。
fn init_controller(bus: u8, dev: u8, func: u8) -> Result<usize, Error> {
    let abar_phys = read_abar(bus, dev, func)?;
    // 使能 Memory Space + Bus Master（STORAGE-AHCI-1 明确驱动自行调用，
    // 不依赖上层代劳——DMA 要求 Bus Master 位，缺它则设备无法发起传输）。
    // DMA 的前提：PCI_COMMAND.BusMaster(bit2) + MemorySpace(bit1)。
    //
    // 这不是形式步骤：QEMU 的设备 DMA 走 `dev->bus_master_as`，该地址空间
    // 的可用性完全由 BusMaster 位决定；未使能时**设备发起的读写被直接丢弃**
    // （见 commit d1b882d 对 HDA 同类症状的记录）。因此这里显式**复核**
    // 使能结果，而不是「调用过就算」——读回的位是唯一可信凭据。
    let cmd_before = read_config_u16(bus, dev, func, 0x04);
    enable_bus_master(bus, dev, func);
    let cmd_after = read_config_u16(bus, dev, func, 0x04);
    const PCI_CMD_BUSMASTER: u16 = 1 << 2;
    const PCI_CMD_MEMSPACE: u16 = 1 << 1;
    info!(
        "[ahci] PCI cmd {:#06x} -> {:#06x} (MASTER={} MEM={})",
        cmd_before, cmd_after,
        cmd_after & PCI_CMD_BUSMASTER != 0,
        cmd_after & PCI_CMD_MEMSPACE != 0
    );
    if cmd_after & PCI_CMD_BUSMASTER == 0 {
        // 没有 Bus Master 能力就无法做 DMA：如实失败，不假装能跑。
        error!("[ahci] Bus Master enable failed on {:02x}:{:02x}.{}; refusing DMA", bus, dev, func);
        return Err(Error::Io);
    }

    // 映射 ABAR（8 KiB 寄存器窗口，§3.1）。
    let abar = map_mmio(abar_phys, 8192)?;

    // 使能 AHCI（§3.1.2）。
    //
    // **不做 GHC.HR 全控制器复位**：HR 是破坏性的——它会清掉所有端口的
    // PxSIG/PxSSTS 等由固件（BIOS/UEFI 或 QEMU 初始化）建立的链路状态，
    // 而重建这些状态需要完整的端口重协商流程。实测：在 QEMU ich9-ahci 上
    // 先 HR 再读端口，PxSIG 恒为 0xffffffff（无效），盘无法识别。
    //
    // 规范（§3.1.2）只要求「OS 在访问端口寄存器前置 GHC.AE」；HR 是**可选**
    // 的恢复手段，用于控制器处于未知状态时。固件已配置好的控制器不需要
    // 复位——保留固件状态反而更可靠（这也是 Linux ahci 驱动的默认选择：
    // 只在 `ahci_pci_reset_controller` 的特定 quirk 下才 HR）。
    let hba = HbaRegs { base: abar };
    // 使能 AHCI 模式（AE）——必须在访问端口寄存器之前。
    hba.write32(HBA_GHC, hba.read32(HBA_GHC) | GHC_AE);
    // 全控制器复位后，端口状态机才真正回到已知状态。
    hba.write32(HBA_GHC, hba.read32(HBA_GHC) | GHC_HR);
    let mut hr_cleared = false;
    for _ in 0..2_000_000 {
        if hba.read32(HBA_GHC) & GHC_HR == 0 {
            hr_cleared = true;
            break;
        }
        core::hint::spin_loop();
    }
    if !hr_cleared {
        error!("[ahci] GHC.HR did not clear; controller stuck");
        return Err(Error::Io);
    }
    // HR 清除后须重新置 AE（复位会清掉它）。
    hba.write32(HBA_GHC, hba.read32(HBA_GHC) | GHC_AE);

    // STORAGE-AHCI-6b：使能**全局中断**并使 HBA 定位可被中断路径复用。
    //
    // 规范（§3.1.3）：只有当 `GHC.IE` 与对应端口的 `PxIE` 位**同时**置起时，
    // 端口事件才会汇聚到 HBA 的 `IS` 并经 PCI IRQ 投递；缺一即静默丢弃。
    // 故两处都要使能——本处是全局闸门，端口级在 `init_port` 中置 `PxIE`。
    //
    // 保存 ABAR 与真实中断线：命令完成等待（`wait_command`）需据此把端口事件
    // 与 `irq_owner` 的 IRQ 槽对应。中断线来自 PCI 配置空间 0x3C，**不是**假定值。
    CONTROLLER_IRQ_LINE.store(
        read_config_u8(bus, dev, func, 0x3C),
        core::sync::atomic::Ordering::Relaxed,
    );
    let irq_line = CONTROLLER_IRQ_LINE.load(core::sync::atomic::Ordering::Relaxed);
    // **必须注册 arch handler**，否则中断到了也没人置闩锁——这是 6b 首版
    // 「中断路径反而慢 69 倍、闩锁命中率 0%」的真实根因（与 QEMU 无关，真机同样）。
    // 用 `claim_kernel_irq`（不占 pid 归属槽），与用户态驱动的 claim 互不冲突。
    if irq_line >= 3 {
        // **先解屏蔽，再注册 handler**：8259 掩码是系统级闸门，屏蔽时中断
        // 根本到不了 CPU（实测确认：控制器侧 `HBA IS=0x1` 已置位，但 CPU 侧
        // 闩锁 0% 命中）。`unmask_irq` 对 IRQ>=8 会自动一并打开级联线 IRQ2。
        let after = arch_x86_64::pic::unmask_irq(irq_line);
        info!(
            "[ahci] unmasked IRQ {} for SATA completion (PIC mask now {:#06x})",
            irq_line, after
        );
        // 注册设备侧应答：电平触发的中断**必须**清除控制器状态位才释放中断线，
        // 否则 8259 立即重投递（实测为中断风暴 + 挂载挂死）。在 claim 之前注册，
        // 避免「handler 已注册但应答未就绪」的窗口内触发风暴。
        crate::irq_owner::set_irq_ack_callback(irq_line, Some(ahci_irq_ack));
        match crate::irq_owner::claim_kernel_irq(irq_line) {
            Ok(()) => info!("[ahci] kernel IRQ handler registered on IRQ {}", irq_line),
            Err(e) => warn!(
                "[ahci] cannot register IRQ {} handler: {:?}; completion falls back to bounded polling",
                irq_line, e
            ),
        }
    }
    hba.write32(HBA_GHC, hba.read32(HBA_GHC) | GHC_IE);
    let ghc_now = hba.read32(HBA_GHC);
    info!(
        "[ahci] post-reset: GHC={:#x} PI={:#x} GHC.IE={} irq_line={}",
        ghc_now,
        hba.read32(HBA_PI),
        ghc_now & GHC_IE != 0,
        irq_line
    );

    // 控制器已可用：记下 ABAR 供中断路径与自检观测（0 = 无）。
    CONTROLLER_HBA_BASE.store(abar, core::sync::atomic::Ordering::Relaxed);

    let cap = hba.read32(HBA_CAP);
    let pi = hba.read32(HBA_PI);
    let vs = hba.read32(HBA_VS);
    let port_count = (cap & 0x1F) + 1; // CAP.NP(0..4) = 端口数 - 1
    info!(
        "[ahci] controller {:02x}:{:02x}.{} ABAR {:#x}: {} port(s), PI={:#010x}, VS={}.{}.{}",
        bus, dev, func, abar_phys, port_count, pi,
        (vs >> 16) & 0xFFFF, (vs >> 8) & 0xFF, vs & 0xFF
    );

    let mut found = 0usize;
    for slot in 0..SLOT_COUNT {
        let p = slot as u8;
        // PI 位图声明端口存在，且端口号在控制器支持范围内。
        if pi & (1u32 << p) == 0 || u32::from(p) >= port_count {
            continue;
        }
        match init_port(&abar, p) {
            Ok(true) => {
                found += 1;
            }
            Ok(false) => {
                // 端口存在但无盘：正常（未接线）。
            }
            Err(e) => {
                warn!("[ahci] port {} setup failed: {:?}", p, e);
            }
        }
    }
    Ok(found)
}

/// HBA 寄存器访问器（BAR5 MMIO 基址）。
struct HbaRegs {
    base: u64,
}

impl HbaRegs {
    #[inline]
    fn read32(&self, off: u64) -> u32 {
        // SAFETY：off 在 8 KiB ABAR 窗口内（调用方只传本文件定义的常量偏移）。
        unsafe { core::ptr::read_volatile((self.base + off) as *const u32) }
    }

    #[inline]
    fn write32(&self, off: u64, v: u32) {
        // SAFETY：同 read32。
        unsafe { core::ptr::write_volatile((self.base + off) as *mut u32, v) }
    }
}
/// 探测并初始化单个端口。返回 `Ok(true)` 表示该端口有可用 SATA 盘并已登记。
///
/// 失败模式（S20）：DMA 缓冲分配失败 → 端口保持禁用并返回错误，
/// 已分配的部分由 `Port` 的 `Option` 字段随作用域 Drop 归还（不泄漏帧）。
fn init_port(abar: &u64, index: u8) -> Result<bool, Error> {
    // 先用一个「裸」Port 读端口寄存器（此时尚无 DMA 结构，但寄存器可读）。
    let mut port = Port {
        hba: *abar,
        index,
        cmd_list: None,
        rx_fis: None,
        cmd_table: None,
        data: None,
        sectors: 0,
        lock: Mutex::new(()),
    };

    // 读 PxSSTS 判定链路状态（DET=3 表示设备已连接且通信建立）。
    // 这是**上电即有效**的寄存器（由链路层维护），可在端口启动前读。
    let ssts = port.read32(PX_SSTS);
    let det = ssts & PXSSTS_DET_MASK;
    if det != PXSSTS_DET_PRESENT {
        // 无盘：不分配任何缓冲（省内存），如实返回 false。
        info!("[ahci] port {}: no device (PxSSTS.DET={})", index, det);
        return Ok(false);
    }

    // 分配 DMA 结构（§3.3 对齐要求）。
    //   命令列表 1 KiB，须 1 KiB 对齐；
    //   Received FIS 256 B，须 256 字节对齐；
    //   命令表 1 页，须 128 字节对齐（页对齐自然满足）。
    // 分配 4 KiB 页块即可同时满足全部对齐要求（页对齐 >= 所有要求）。
    let cmd_list = alloc_dma(4096, "command list")?;
    let rx_fis = alloc_dma(4096, "received FIS")?;
    let cmd_table = alloc_dma(4096, "command table")?;
    // 数据缓冲：一次命令最多 32 扇区 = 16 KiB。
    let data = alloc_dma((MAX_SECTORS_PER_CMD * 512) as u64, "data buffer")?;
    // 命令列表与 FIS 区必须清零：控制器按 PxCI 位读命令头，未清零的
    // 随机内容会被当作有效命令（含野物理地址）从而 DMA 到任意内存。
    zero_buffer(&cmd_list);
    zero_buffer(&rx_fis);
    zero_buffer(&data);

    port.cmd_list = Some(cmd_list);
    port.rx_fis = Some(rx_fis);
    port.cmd_table = Some(cmd_table);
    port.data = Some(data);

    // 启动命令引擎（PxCMD 握手）。
    port.init_hardware()?;


    // 签名校验：只处理 SATA ATA 盘，跳过 ATAPI/端口复用器（§3.3.1.6）。
    //
    // **必须在端口启动之后读**：PxSIG 由设备在链路建立并完成签名 FIS 交换后
    // 才填充。实测：在 PxCMD.ST 置位前读，QEMU ich9-ahci 返回 0xffffffff
    // （无效值），导致真盘被误判为「非 ATA」而跳过。
    let sig = port.read32(PX_SIG);
    if sig != SATA_SIG_ATA {
        info!("[ahci] port {}: non-ATA signature {:#x} (ATAPI/PM); skipped", index, sig);
        return Ok(false);
    }

    // 在**持有端口锁**的前提下确认盘可寻址（避免与并发的 IO 争用命令槽）。
    //
    // ## 为什么用 READ DMA EXT 探测容量，而不是 IDENTIFY DEVICE
    //
    // `IDENTIFY DEVICE`(0xEC) 是 **PIO** 命令，其数据经 PIO Setup FIS + PIO
    // 数据端口传送，**不经过 PRDT**；而本驱动只实现 PRDT/DMA 数据通路。
    // 实测：0xEC 在本环境返回任务文件错误（`PxIS.TFES` 置位、`PxTFD.ERR`
    // 置位），`IDENTIFY DEVICE DMA`(0xEE) 亦不被该设备支持。
    //
    // 因此改用**本驱动唯一实现且已验证可用**的通路来确证盘：先做一次
    // LBA0 的 READ DMA EXT（0x25），成功即证明端口能真实收发 DMA；容量
    // 则用 LBA48 二分探测确定（见 `probe_capacity`）。
    //
    // 这是「只用已验证的通路」纪律（S09）：宁可多几次探测，也不引入一条
    // 未经验证的 PIO 数据通路。
    let cap = {
        let _g = port.lock.lock();
        probe_capacity(&port)?
    };
    if cap == 0 {
        warn!("[ahci] port {}: capacity probe reported 0 sectors; refusing", index);
        return Ok(false);
    }
    port.sectors = cap;

    // 登记（用静态槽，保证 'static 生命周期）。
    let cell = &AHCI_SLOTS[index as usize];
    // SAFETY：`cell` 是 `UnsafeCell`，写入合法。唯一的写入者是本函数，
    // 且 `late_storage_init` 在启动期单线程调用（此时尚无任何读者，驱动也
    // 尚未登记进 DriverHub）。此后 `port` 只被 `&` 只读访问，其内部 `Mutex`
    // 串行化全部寄存器/DMA 访问——写入与后续读取之间不存在数据竞争。
    let slot: &AhciDevice = unsafe {
        (*cell.0.get()).port = Some(port);
        &*cell.0.get()
    };
    *slot.sectors.lock() = cap;
    info!(
        "[ahci] {} on port {}: {} sectors ({} MB), LBA48 DMA",
        slot.name, index, cap, (cap * 512) / (1024 * 1024)
    );
    register_device(slot);
    Ok(true)
}
/// 分配一块内核态 DMA 缓冲，失败时如实上抛（不返回伪缓冲）。
fn alloc_dma(bytes: u64, what: &str) -> Result<KernelDmaBuffer, Error> {
    alloc_kernel_dma_raw(bytes).map_err(|e| {
        error!("[ahci] DMA buffer alloc failed for {} ({} bytes): {:?}", what, bytes, e);
        Error::OutOfMemory
    })
}

/// 把一块 DMA 缓冲清零（控制器会把未清零的命令头当作有效命令）。
fn zero_buffer(buf: &KernelDmaBuffer) {
    // SAFETY：buf 为本函数独占借用的 DMA 缓冲，容量由 capacity() 给出；
    // 用 write_bytes 批量清零，不产生别名引用。
    unsafe {
        core::ptr::write_bytes(buf.virt_addr() as *mut u8, 0, buf.capacity() as usize);
    }
}

/// 把物理 MMIO 窗口映射进内核地址空间，返回其虚拟地址。
///
/// 为什么需要显式映射：ABAR 指向的设备 MMIO 区域**不在** Limine 的 HHDM 内
/// （HHDM 只覆盖物理 RAM），故必须建立映射才能访问（同 LAPIC/HPET 的做法）。
/// 映射属性为设备内存（不可缓存），防止 CPU 缓存 MMIO 读到陈旧寄存器值。
fn map_mmio(phys: u64, len: u64) -> Result<u64, Error> {
    // 与 LAPIC/HPET 相同的模式：虚拟地址 = 物理地址 | 统一设备映射基址
    // （arch1.md AA2：不各文件硬编码 HHDM 形状的魔数）。
    let base_virt = phys | arch_x86_64::mmio::DEVICE_MMIO_VIRT_BASE;
    // ABAR 窗口按 4 KiB 页逐页映射（8 KiB = 2 页）。
    let pages = (len + 4095) / 4096;
    for i in 0..pages {
        let p = phys + i * 4096;
        let v = base_virt + i * 4096;
        if !arch_x86_64::mmio::map_phys_4k(p, v) {
            error!("[ahci] MMIO mapping failed at phys {:#x} (page {})", p, i);
            return Err(Error::NoSpace);
        }
    }
    Ok(base_virt)
}

/// 登记一块 SATA 盘到 DriverHub。
fn register_device(dev: &'static AhciDevice) {
    if let Err(e) = DriverHub::register_device_info(
        DeviceInfo {
            name: dev.name,
            kind: DeviceKind::Block,
            bus: BusType::Pci,
            location: dev.port_index as u32,
            vendor_id: 0,
            device_id: 0,
            class_code: 0x01,
            subclass: 0x06,
            prog_if: 0x01,
            volatile: false,
            irq_line: 0,
        },
        Some(dev),
        Some("ahci"),
    ) {
        error!("[ahci] device registration failed: {:?}", e);
    }
}

// ===========================================================================
// 编入二进制的自检（run_builtin_asserts）
// ===========================================================================
//
// ## 为什么不用 `#[cfg(test)] mod tests`
//
// 本 crate 是 `no_std`，且**没有任何测试宿主会编译它**：`cargo test` 在
// 裸机目标上连 `test` crate 都找不到（实测 `can't find crate for test`），
// 全仓库也没有任何地方调用 `driver::drivers::ahci::tests`。也就是说
// `#[cfg(test)]` 里的断言**永远不会执行**——它们既不会在 CI 失败，也不会
// 在启动时失败，只是一段会随时间腐烂的死代码（S08：不做无依据的验证声明）。
//
// 改用**编入二进制的自检**：`run_builtin_asserts` 由启动自检调用，在真实
// 硬件上执行，失败即 panic。这与本仓库 `arch_x86_64::mmio::test_map_phys_4k`
// 等既有做法同源。


/// AHCI 中断应答（中断上下文执行，**只做 MMIO 写，不取任何锁**）。
///
/// ## 为什么必须应答（实测根因）
///
/// PCI 中断是电平触发的：控制器置起 `PxIS.DHRS` 后拉高中断线。**只有写 1 到
/// `PxIS` 对应位（W1C）才会清除该位、进而释放中断线**。不应答的后果实测为
/// 中断风暴：`IRQ 11` 被 8259 反复重投递，卷挂载阶段永久挂死。
///
/// 必须同时清两处（§3.1.2 / §3.3.1.4）：
///   - 端口 `PxIS`（W1C）：完成位来源；
///   - HBA `IS`（W1C，offset 0x08）：端口状态的汇聚，它才是连到 PCI 中断线的
///     那一位。只清 `PxIS` 而留 `IS` 置位，中断线仍不释放。
///
/// 安全性：只对已映射的 BAR5 窗口做 volatile 写；写 1 到 W1C 位是规范定义的
/// 清除语义，对未置位的位写 1 无害（§3.1.2）。不读、不分配、不取锁，故在中断
/// 上下文严格安全（S21）。
fn ahci_irq_ack(_irq: u8) {
    ACK_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    // 采样累计应答开销（S32：优化前先量化）。rdtsc 在 QEMU TCG 下是「相对」
    // 计数而非墙上时间，故只用于**同口径比较**（应答开销 vs 总线时间）。
    let t0 = klib::time::read_cycle_counter();
    let base = CONTROLLER_HBA_BASE.load(core::sync::atomic::Ordering::Relaxed);
    if base == 0 {
        return; // 无控制器（不应发生：本回调只在探到控制器后注册）
    }
    let r = HbaRegs { base };
    // 先清端口完成位（各端口独立），再清 HBA 汇聚位——顺序对应「源 → 汇聚」。
    //
    // **只遍历 PI 中实际存在的端口**：`MAX_PORTS`=32 是规范的硬上限，但真实
    // 控制器（QEMU `ich9-ahci` 实测 NP=5，PI=0x3f，6 个端口）远小于它。遍历
    // 32 个端口意味着**每次中断多做 26 次 MMIO 读**，而 TCG 下每次 MMIO 访问
    // 都是较重的陷阱——实测每次应答的开销会被显著放大。按 PI 裁剪是纯粹的白赚，
    // 且不改变语义（PI 之外的端口本来就不存在）。
    let pi = r.read32(HBA_PI);
    for p in 0..MAX_PORTS {
        if pi & (1u32 << p) == 0 {
            continue;
        }
        let pr = HbaRegs {
            base: base + PORT_BASE + PORT_STRIDE * (p as u64),
        };
        let is = pr.read32(PX_IS);
        if is & PXIS_COMPLETION_BITS != 0 {
            pr.write32(PX_IS, is & PXIS_COMPLETION_BITS); // W1C：只清置起的完成位
        }
    }
    // HBA IS：清全部已置位（W1C），确保中断线释放。
    let hba_is = r.read32(HBA_IS);
    if hba_is != 0 {
        r.write32(HBA_IS, hba_is);
    }
    let dt = klib::time::read_cycle_counter().wrapping_sub(t0);
    ACK_CYCLES.fetch_add(dt, core::sync::atomic::Ordering::Relaxed);
}
/// 重新使能中断优先完成路径（在系统级 `sti` / LAPIC 初始化**之后**调用）。
///
/// ## 为什么需要这个再使能点（实测根因）
///
/// AHCI 的 `late_storage_init()` 在 `kmain` 中被调用时，**CPU 中断尚未开启**
/// （`sti` 在更晚的 `InterruptController::enable()`）。那段窗口内的容量探测等
/// I/O 必然等不到中断，于是自适应退让把中断路径**永久关掉**了——即使此后
/// `sti` 打开、中断完全可用，驱动也不会再尝试。
///
/// 实测证据：中断开启后 IRQ 11 **确实到达**（探针记录到连续投递），但驱动
/// 因早期退让而停留在轮询模式，`test-ahci6d` 仍报「not delivered」。
///
/// 故提供本函数：清除退让状态、重新开启中断优先，让中断路径在真正可用的
/// 阶段重新生效。幂等，可安全重复调用。
pub fn rearm_interrupt_completion() {
    if CONTROLLER_HBA_BASE.load(core::sync::atomic::Ordering::Relaxed) == 0 {
        return; // 无控制器：无需再使能
    }
    IRQ_WAIT_MISSES.store(0, core::sync::atomic::Ordering::Relaxed);
    IRQ_FALLBACK_WARNED.store(false, core::sync::atomic::Ordering::Relaxed);
    IRQ_COMPLETION_ENABLED.store(true, core::sync::atomic::Ordering::Relaxed);
    info!("[ahci] interrupt-first completion re-armed (interrupts now enabled)");
}
/// 取第 `index` 块已登记的盘对应的设备槽（未探测到盘时为 None）。
fn ahci_device(index: usize) -> Option<&'static AhciDevice> {
    if index >= SLOT_COUNT {
        return None;
    }
    // SAFETY：与 `AHCI_SLOTS` 的既有访问同源——槽只在启动期单线程写入，
    // 此后 `port` 只读借用（见 SlotCell 的 SAFETY 注释）。
    let dev = unsafe { &*AHCI_SLOTS[index].0.get() };
    if dev.port.is_some() {
        Some(dev)
    } else {
        None
    }
}
// ===========================================================================
// 中断驱动完成路径的观测接口（STORAGE-AHCI-6b 自检用）
// ===========================================================================

/// 中断驱动完成路径的状态快照（供自检断言，不参与生产逻辑）。
pub struct InterruptStatus {
    /// HBA 全局控制寄存器原值。
    pub ghc: u32,
    /// `GHC.IE` 是否使能（bit1）。
    pub ghc_ie: bool,
    /// 控制器的 PCI 中断线（来自配置空间 0x3C；0 = 未分配）。
    pub irq_line: u8,
    /// 控制器实现的端口数。
    pub port_count: usize,
    /// 其中**已使能命令完成中断**（`PxIE` 含完成位）的端口数。
    pub ports_with_completion_ie: usize,
    /// HBA 全局中断状态 `IS` 当前值：**控制器是否真的拉起过中断**的权威证据。
    ///
    /// 若端口 `PxIS` 有完成位而 `IS` 对应位为 0，说明中断在控制器内部就未能
    /// 汇聚（多为 GHC.IE/PxIE 未同时使能）；若 `IS` 置位而闩锁未置，则问题在
    /// CPU 侧投递（PIC 路由/EOI）。这条区分是定位中断问题的第一刀。
    pub is: u32,
}

/// 采集中断完成路径状态；无控制器时返回 `None`（调用方据此如实 SKIP）。
///
/// 只读 MMIO，不改变任何状态（幂等，可重复调用）。
pub fn interrupt_status() -> Option<InterruptStatus> {
    let hba_base = CONTROLLER_HBA_BASE.load(core::sync::atomic::Ordering::Relaxed);
    if hba_base == 0 {
        return None; // 无控制器：如实返回 None，调用方据此 SKIP
    }
    let r = HbaRegs { base: hba_base };
    let ghc = r.read32(HBA_GHC);
    let pi = r.read32(HBA_PI);
    let mut port_count = 0usize;
    let mut armed = 0usize;
    for p in 0..MAX_PORTS {
        if pi & (1u32 << p) == 0 {
            continue;
        }
        port_count += 1;
        // 端口寄存器块 = HBA 基址 + 0x100 + 0x80*p（与 `Port::reg` 同一算法）。
        let pr = HbaRegs {
            base: hba_base + PORT_BASE + PORT_STRIDE * (p as u64),
        };
        if pr.read32(PX_IE) & PXIE_COMPLETION_BITS != 0 {
            armed += 1;
        }
    }
    Some(InterruptStatus {
        ghc,
        ghc_ie: ghc & GHC_IE != 0,
        irq_line: CONTROLLER_IRQ_LINE.load(core::sync::atomic::Ordering::Relaxed),
        port_count,
        ports_with_completion_ie: armed,
        is: r.read32(HBA_IS),
    })
}

/// 容量探测的测试入口：对指定端口重新走一次 48 位二分，返回容量（扇区）。
///
/// 复用生产路径的探测实现，**不是**另写一份（S28：不得自造第二实现）；
/// 仅用于在中断模式下确认「真实 I/O 仍能完成」。
pub fn probe_capacity_for_test(index: usize) -> Option<u64> {
    let dev = ahci_device(index)?;
    // 与生产路径共用同一次探测实现（S28：不自造第二实现）。
    let port = dev.port.as_ref()?;
    probe_capacity(port).ok()
}

/// 编译进来的运行时自检：把「规范事实」在真实启动路径上再验证一遍。
///
/// 编译期断言（`const _: () = ...`）只能覆盖常量表达式；这里补上需要
/// 结构体偏移、函数求值等无法在 const 上下文中直接写出的检查。
pub fn run_builtin_asserts() {
    // ---- 结构布局：必须与规范逐字节一致（S04）----
    assert_eq!(core::mem::size_of::<CommandHeader>(), CMD_HEADER_BYTES);
    assert_eq!(core::mem::size_of::<FisRegH2d>(), 64);
    assert_eq!(core::mem::size_of::<PrdtEntry>(), PRDT_ENTRY_BYTES);
    assert_eq!(core::mem::offset_of!(CommandTable, prdt), CMD_TABLE_PRDT_OFF);
    assert_eq!(core::mem::offset_of!(CommandHeader, dw0), 0);
    assert_eq!(core::mem::offset_of!(CommandHeader, dw1), 4);
    assert_eq!(core::mem::offset_of!(CommandHeader, ctba), 8);
    // 命令表必须在命令头允许的 4 KiB 之内（§3.3.2：CTBA 指向单表）。
    assert!(core::mem::size_of::<CommandTable>() <= 4096);

    // ---- PRDTL 位号：本驱动最严重的一次真实缺陷的回归守卫 ----
    //
    // 最初实现把 PRDTL 写到 DW1。§3.3.2 与 QEMU 的 `AHCICmdHdr`
    // （`uint16_t opts; uint16_t prdtl;`）都把它放在 **DW0 的 bit31..16**，
    // 于是控制器读到 `prdtl == 0`，在 `ahci_populate_sglist` 阶段直接判
    // 「guest 未提供 PRDT」而失败——现场只表现为「命令超时」，完全看不出
    // 是位号问题。此处把打包结果钉死，任何回退都会在启动时立刻 panic。
    for prdtl in [1u32, 2, 16, 32, 0xFFFF] {
        // 用写方向（write=true）以便低半字只含 CFL，隔离出 PRDTL 的效果。
        let dw0 = pack_dw0(CMD_CFIS_DWORDS, true, prdtl);
        assert_eq!(dw0 >> CH_DW0_PRDTL_SHIFT, prdtl & 0xFFFF);
        // 低半字不得被 PRDTL 污染：写方向下低半字必须恰为 CFL(=16)。
        assert_eq!(dw0 & 0xFFFF, CMD_CFIS_DWORDS);
    }
    // 读方向（write=false）：W(bit6=0x40) 置位 → DW0 = CFL(16) | W | PRDTL<<16
    //                                        = 0x0010 | 0x0040 | 0x0001_0000
    //                                        = 0x0001_0050
    assert_eq!(pack_dw0(CMD_CFIS_DWORDS, false, 1), 0x0001_0050);
    // 写方向（write=true）：W 不置位 → DW0 = 0x0010 | 0x0001_0000 = 0x0001_0010
    assert_eq!(pack_dw0(CMD_CFIS_DWORDS, true, 1), 0x0001_0010);
    // PRDTL 字段完全落在 DW0 内，绝不跨越到 DW1。
    assert_eq!(CH_DW0_PRDTL_SHIFT, 16);
    assert!(CH_DW0_PRDTL_MASK <= 0xFFFF_0000);

    // ---- 单命令扇区上限必须与 PRDT 项数一致（否则会写出 PRDT 边界）----
    assert_eq!(MAX_SECTORS_PER_CMD, PRDT_MAX_ENTRIES);
    assert_eq!(MAX_SECTORS_PER_CMD, 32);
}
