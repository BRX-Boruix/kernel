//! x86-64 GDT（全局描述符表）与 TSS（任务状态段）。
//!
//! 手写实现，不依赖外部 crate：
//! - GDT 含：空段、内核代码段(0x08)、内核数据段(0x10)、用户代码段(0x28)、
//!   用户数据段(0x30)、TSS 段(0x18)。
//! - TSS 提供 ring3→ring0 切换时的内核栈（`rsp0`），为后续用户态/系统调用铺路。
//!
//! 为支持 SMP，每 CPU 拥有独立的 GDT/TSS/内核栈（`PerCpu` 里持有）。

use core::arch::global_asm;
use core::sync::atomic::{AtomicUsize, Ordering};

/// GDT 段选择子
pub const KCODE: u16 = 0x08;
pub const KDATA: u16 = 0x10;
pub const TSS_SEL: u16 = 0x18;
/// 用户代码段（DPL=3，Ring 3 可执行）。
/// 选择子 index = 0x28>>3 = 5，对应 GDT entries[5]。
pub const UCODE: u16 = 0x28;
/// 用户数据段（DPL=3，Ring 3 可读写）。
/// 选择子 index = 0x30>>3 = 6，对应 GDT entries[6]。
pub const UDATA: u16 = 0x30;

/// 单 CPU 内核栈大小（64KB）。BSP 与各 AP 各持一份。
pub const KSTACK_SIZE: usize = 0x10000;

/// Double Fault 专用中断栈大小（16KB）。
///
/// 当 CPU 在异常处理中再次触发异常（例如内核栈溢出导致保护错误）时，
/// 会触发 Double Fault。若无独立 IST 栈，Double Fault 会再次异常 →
/// Triple Fault，机器直接重启且无诊断输出。独立 IST 栈可容纳 Double Fault
/// 处理器打印错误并安全停机。
pub const DF_STACK_SIZE: usize = 16 * 1024;

/// Double Fault 使用的 IST 索引。
///
/// x86-64 TSS 的 IST 数组索引 0 表示"不使用 IST"，故有效索引从 1 开始。
/// 这里用 1 作为 Double Fault 的 IST 槽位。
pub const IST_DF: usize = 1;

/// TSS 结构（x86-64，共 104 字节）。
///
/// **必须用 `#[repr(C, packed)]`**：x86-64 硬件要求 RSP0 位于 TSS **offset 4**。
/// 若用普通 `#[repr(C)]`，`reserved1: u32` 后跟 `rsp: [u64; 3]` 会因 u64 的 8 字节
/// 对齐而插入 4 字节 padding，使 `rsp[0]` 错位到 offset 8，而硬件读 offset 4 得到的
/// 是 padding（=0）。用户态中断/软中断（如 `int 0x80`）切栈时用 RSP0=0 压栈到 -8
/// （非规范地址）→ #GP → #DF → Triple Fault。`packed` 使字段紧密排列，RSP0 落到
/// offset 4，与硬件布局一致。
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Tss {
    reserved1: u32,
    /// 特权级切换时的栈（rsp0/rsp1/rsp2）。rsp[0] 须位于 offset 4（硬件要求）。
    pub rsp: [u64; 3],
    reserved2: u64,
    /// IST（中断栈表）
    ist: [u64; 7],
    reserved3: u64,
    reserved4: u16,
    iomap_base: u16,
}

impl Tss {
    /// 新建一个全零 TSS。
    pub const fn new() -> Self {
        Self {
            reserved1: 0,
            rsp: [0; 3],
            reserved2: 0,
            ist: [0; 7],
            reserved3: 0,
            reserved4: 0,
            iomap_base: 0,
        }
    }

    /// 设置第 `index` 个 IST 栈顶指针（index 有效范围 1..=6，0 表示不使用）。
    pub fn set_ist(&mut self, index: usize, addr: u64) {
        if index >= 1 && index <= 6 {
            self.ist[index] = addr;
        }
    }
}

/// GDT 条目（8 字节，由 u64 表示）。
///
/// 布局：null, KCODE(1), KDATA(2), TSS_low(3), TSS_high(4), UCODE(5), UDATA(6)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Gdt {
    entries: [u64; 7],
}

impl Gdt {
    /// 新建 GDT，初始化内核/用户代码数据段。
    pub const fn new() -> Self {
        let mut g = Self { entries: [0; 7] };
        // 内核代码段：present, DPL0, 可读可执行, 64 位 (L=1)
        g.entries[1] = 0x00_A0_9A_00_0000_FFFF;
        // 内核数据段：present, DPL0, 可读写, 展开向上。
        // byte6 = 0x8C：G=1(bit7), D=0(bit6), L=0(bit5)，标准 64 位数据段。
        // 关键：不得用 0xCF（其 D=1 表示 32 位段、L=1 表示代码段标志）——
        // 用户态中断/软中断压帧时 CPU 切到 KDATA（内核栈段），若 KDATA 被标为
        // 32 位段（D=1）会触发 #GP。
        g.entries[2] = 0x00_8C_92_00_0000_FFFF;
        // 用户代码段：present, DPL3, 可读可执行, 64 位 (L=1)
        g.entries[5] = 0x00_A0_FA_00_0000_FFFF;
        // 用户数据段：present, DPL3, 可读写, 展开向上。
        // byte6 = 0x8C：G=1(bit7), D=0(bit6), L=0(bit5), limit[19:16]=0xC(bit3-0)。
        // 标准 64 位数据段（D=0, L=0）。不得用 0xCF（D=1 表示 32 位段）或 0xC8
        // （其 bit6=1 使 D=1，仍被标为 32 位段）——iretq 到 Ring3 恢复 SS 时，
        // 若 SS 被标为 32 位段（D=1）会触发 #SS。
        g.entries[6] = 0x00_8C_F2_00_0000_FFFF;
        g
    }

    /// 设置 TSS 段描述符（低/高 64 位），base 为 TSS 物理/虚拟地址。
    pub fn set_tss(&mut self, base: u64) {
        self.entries[3] = tss_low(base);
        self.entries[4] = tss_high(base);
    }
}

/// TSS 段描述符低 64 位。
///
/// 64 位 TSS 描述符在 GDT 占 16 字节（两个槽位）。低 8 字节（`tss_low`）：
/// - bit0-15: limit[15:0]
/// - bit16-31: base[15:0]
/// - bit32-39: base[23:16]
/// - bit40-47: access（type=0x9 available 64 位 TSS, P=1, DPL=0, S=0）
/// - bit48-51: limit[19:16]
/// - bit52-55: AVL/L/D/G（对 64 位 TSS 全为 0）
/// - bit56-63: base[31:24]
fn tss_low(base: u64) -> u64 {
    let limit = (core::mem::size_of::<Tss>() - 1) as u64;
    limit
        | ((base & 0xFFFF) << 16)                // base[15:0]
        | (((base >> 16) & 0xFF) << 32)          // base[23:16]
        | (0x89u64 << 40)                        // access: type=0x9, P=1, DPL=0, S=0
        | (((base >> 24) & 0xFF) << 56) // base[31:24]
}

/// TSS 段描述符高 64 位（存放 base 的 32~63 位，即 base 高 32 位）。
fn tss_high(base: u64) -> u64 {
    base >> 32
}

/// GDTR 结构（lgdt 需要：16 位 limit + 64 位 base）。
#[repr(C, packed)]
pub struct Gdtr {
    pub limit: u16,
    pub base: u64,
}

// 汇编入口（加载 GDT / 装载 TSS）。
unsafe extern "C" {
    fn x86_64_load_gdt(gdtr: *const Gdtr);
    fn x86_64_load_tss();
}

global_asm!(
    "
    .global x86_64_load_gdt
    x86_64_load_gdt:
        lgdt [rdi]              # rdi = &Gdtr
        mov ax, {kd}
        mov ds, ax
        mov es, ax
        mov ss, ax
        mov fs, ax
        mov gs, ax
        push {kc}               # 新的 CS
        lea rax, [rip + 1f]     # 下一条指令地址
        push rax
        retfq                   # 远跳转重载 CS
    1:
        ret
    .global x86_64_load_tss
    x86_64_load_tss:
        mov ax, {ts}
        ltr ax
        ret
    ",
    kd = const KDATA as usize,
    kc = const KCODE as usize,
    ts = const TSS_SEL as usize,
);

/// 页对齐栈存储（与 kernel::main 的 KMAIN_STACK 同族修复：裸 `[u8; N]`
/// 静态对齐为 1，链接器可落在奇地址；TSS.RSP0/IST 栈顶从非对齐地址出发
/// 会破坏 Rust ABI 栈对齐约定，且 Double Fault 栈错位会让本该兜底的 #DF
/// 处理器自身再次故障）。页对齐是栈存储的成文要求。
#[repr(C, align(4096))]
struct PageAlignedStack<const N: usize>([u8; N]);

/// BSP（引导核）使用的 GDT/TSS/内核栈。
static mut BSP_GDT: Gdt = Gdt::new();
static mut BSP_TSS: Tss = Tss::new();
static mut BSP_KSTACK: PageAlignedStack<KSTACK_SIZE> = PageAlignedStack([0; KSTACK_SIZE]);
/// BSP 的 Double Fault 中断栈。
static mut BSP_DF_STACK: PageAlignedStack<DF_STACK_SIZE> = PageAlignedStack([0; DF_STACK_SIZE]);

// A2: per-CPU idle/boot kernel-stack top + live TSS ptr registry (see full block below)
static BOOT_KSTACK_TOP: [AtomicUsize; MAX_CPU_SLOTS] = [const { AtomicUsize::new(0) }; MAX_CPU_SLOTS];
static CPU_TSS_PTR: [AtomicUsize; MAX_CPU_SLOTS] = [const { AtomicUsize::new(0) }; MAX_CPU_SLOTS];

/// 每 CPU 槽位上限（与 smp 紧凑槽位 & 0xFF 对齐；BSP=0, AP=1..n）。
pub const MAX_CPU_SLOTS: usize = 256;

/// 计算内核栈顶地址：栈起始地址 + 字节长度。
#[inline]
pub fn stack_top(addr: *const u8, len: usize) -> u64 {
    addr as u64 + len as u64
}

/// 为某个 CPU 配置并加载其 GDT/TSS。
///
/// `gdt` 与 `tss` 指向该 CPU 的 GDT/TSS，`kstack_top` 为该 CPU 的内核栈顶
/// （写入 TSS.rsp0），`df_stack_top` 为该 CPU 的 Double Fault 中断栈顶
/// （写入 TSS.IST[IST_DF]）。
pub fn setup_cpu(gdt: *mut Gdt, tss: *mut Tss, kstack_top: u64, df_stack_top: u64) {
    unsafe {
        (*tss).rsp[0] = kstack_top;
        (*tss).set_ist(IST_DF, df_stack_top);
        let base = tss as u64;
        (*gdt).set_tss(base);
        load_and_reload(&*gdt);
    }
}

/// 初始化 BSP 的 GDT 与 TSS。
///
/// 必须在允许使用全局静态变量的早期（堆初始化前即可）调用。
pub fn init() {
    // SAFETY：仅取静态栈存储的地址（不访问内容），字段投影按 2024 版规则入 unsafe。
    let kstack_top = stack_top(
        unsafe { core::ptr::addr_of!(BSP_KSTACK.0) } as *const u8,
        KSTACK_SIZE,
    );
    let df_stack_top = stack_top(
        unsafe { core::ptr::addr_of!(BSP_DF_STACK.0) } as *const u8,
        DF_STACK_SIZE,
    );
    let gdt_ptr = core::ptr::addr_of_mut!(BSP_GDT);
    let tss_ptr = core::ptr::addr_of_mut!(BSP_TSS);
    setup_cpu(gdt_ptr, tss_ptr, kstack_top, df_stack_top);
    // A2: BSP 恒为紧凑槽 0；登记其常驻内核栈顶（BSP_KSTACK 顶）与其 TSS 帧，
    // 供空闲停车路径把 rsp0/物理 RSP 切回本核安全栈（set_rsp0_for_slot 目标）。
    register_cpu_slot(0, kstack_top, tss_ptr);
}

/// 更新 BSP TSS 的 RSP0（ring3→ring0 中断切栈的内核栈顶）。
///
/// M4.2 调度器在进程切换时调用：把 TSS.RSP0 指向**目标进程的独立内核栈**，
/// 使该进程下一次从用户态中断/异常/软中断进入内核时切到自己的栈。仅 BSP
/// （M4.2 单核调度模型）；AP 的 TSS 不在此管理。
pub fn set_rsp0(kstack_top: u64) {
    unsafe {
        BSP_TSS.rsp[0] = kstack_top;
    }
}

/// 登记某 CPU 槽位的常驻内核栈顶与 TSS 指针 (gdt::init 对 BSP=槽0、smp::ap_entry 对各 AP 调用，每核启动早期各一次)。
/// boot_ktop = 该核引导/空闲内核栈顶 (TSS.rsp0 初始值)。tss = 该核实际 ltr 装载的 TSS 帧地址。
/// A2 空闲停车借这份登记把该核 rsp0/物理 RSP 切回本核安全栈。
pub fn register_cpu_slot(slot: usize, boot_ktop: u64, tss: *mut Tss) {
    let s = slot & (MAX_CPU_SLOTS - 1);
    BOOT_KSTACK_TOP[s].store(boot_ktop as usize, Ordering::Release);
    CPU_TSS_PTR[s].store(tss as usize, Ordering::Release);
}

/// 取某槽位核的常驻 (引导/空闲) 内核栈顶；未登记返回 0。
#[inline]
pub fn boot_kstack_top(slot: usize) -> u64 {
    BOOT_KSTACK_TOP[slot & (MAX_CPU_SLOTS - 1)].load(Ordering::Acquire) as u64
}

/// 写入指定槽位核的 TSS.rsp0。调度器进程切换把 rsp0 指向目标进程内核栈、
/// 或 A2 空闲路径把 rsp0 指回本核 idle 栈顶时使用；取代只写 BSP_TSS 的 set_rsp0。
pub fn set_rsp0_for_slot(slot: usize, kstack_top: u64) {
    let s = slot & (MAX_CPU_SLOTS - 1);
    let tss = CPU_TSS_PTR[s].load(Ordering::Acquire);
    if tss != 0 {
        // SAFETY: CPU_TSS_PTR[s] 由 register_cpu_slot 写入该核真实 TSS 帧地址。
        unsafe {
            (*(tss as *mut Tss)).rsp[0] = kstack_top;
        }
    }
}

/// 为当前 CPU 加载给定 GDT，并装载 TSS。
///
/// 供 BSP 初始化与 AP 启动时调用。`gdt` 需是有效的、含 TSS 段的 GDT。
pub fn load_and_reload(gdt: &Gdt) {
    let gdtr = Gdtr {
        limit: (core::mem::size_of::<Gdt>() - 1) as u16,
        base: core::ptr::addr_of!(*gdt) as u64,
    };
    unsafe {
        x86_64_load_gdt(&gdtr as *const Gdtr);
        x86_64_load_tss();
    }
}
