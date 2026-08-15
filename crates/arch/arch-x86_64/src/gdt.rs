//! x86-64 GDT（全局描述符表）与 TSS（任务状态段）。
//!
//! 手写实现，不依赖外部 crate：
//! - GDT 含：空段、内核代码段(0x08)、内核数据段(0x10)、TSS 段(0x18)。
//! - TSS 提供 ring3→ring0 切换时的内核栈（`rsp0`），为后续用户态/系统调用铺路。
//!
//! 为支持 SMP，每 CPU 拥有独立的 GDT/TSS/内核栈（`PerCpu` 里持有）。

use core::arch::global_asm;

/// GDT 段选择子
pub const KCODE: u16 = 0x08;
pub const KDATA: u16 = 0x10;
pub const TSS_SEL: u16 = 0x18;

/// 单 CPU 内核栈大小（64KB）。BSP 与各 AP 各持一份。
pub const KSTACK_SIZE: usize = 0x10000;

/// TSS 结构（x86-64，共 104 字节）。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Tss {
    reserved1: u32,
    /// 特权级切换时的栈（rsp0/rsp1/rsp2）
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
}

/// GDT 条目（8 字节，由 u64 表示）。
///
/// 布局：null, KCODE, KDATA, TSS_low, TSS_high
#[repr(C)]
pub struct Gdt {
    entries: [u64; 5],
}

impl Gdt {
    /// 新建 GDT，初始化内核代码/数据段。
    pub const fn new() -> Self {
        let mut g = Self { entries: [0; 5] };
        // 内核代码段：present, DPL0, 可读可执行, 64 位 (L=1)
        g.entries[1] = 0x00_A0_9A_00_0000_FFFF;
        // 内核数据段：present, DPL0, 可读写, 展开向上
        g.entries[2] = 0x00_CF_92_00_0000_FFFF;
        g
    }

    /// 设置 TSS 段描述符（低/高 64 位），base 为 TSS 物理/虚拟地址。
    pub fn set_tss(&mut self, base: u64) {
        self.entries[3] = tss_low(base);
        self.entries[4] = tss_high(base);
    }
}

/// TSS 段描述符低 64 位。
fn tss_low(base: u64) -> u64 {
    let limit = (core::mem::size_of::<Tss>() - 1) as u64;
    limit
        | ((base & 0xFFFF) << 16)
        | (((base >> 16) & 0xFF) << 32)
        // access: present, DPL0, 可用 64 位 TSS (type=0x9)
        | (0x89u64 << 40)
        | (((base >> 24) & 0xFF) << 56)
}

/// TSS 段描述符高 64 位（存放 base 的 32~63 位）。
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

/// BSP（引导核）使用的 GDT/TSS/内核栈。
static mut BSP_GDT: Gdt = Gdt::new();
static mut BSP_TSS: Tss = Tss::new();
static mut BSP_KSTACK: [u8; KSTACK_SIZE] = [0; KSTACK_SIZE];

/// 计算内核栈顶地址：栈起始地址 + 字节长度。
#[inline]
pub fn stack_top(addr: *const u8, len: usize) -> u64 {
    addr as u64 + len as u64
}

/// 为某个 CPU 配置并加载其 GDT/TSS。
///
/// `gdt` 与 `tss` 指向该 CPU 的 GDT/TSS，`kstack_top` 为该 CPU 的内核栈顶（写入 TSS.rsp0）。
pub fn setup_cpu(gdt: *mut Gdt, tss: *mut Tss, kstack_top: u64) {
    unsafe {
        (*tss).rsp[0] = kstack_top;
        let base = tss as u64;
        (*gdt).set_tss(base);
        load_and_reload(&*gdt);
    }
}

/// 初始化 BSP 的 GDT 与 TSS。
///
/// 必须在允许使用全局静态变量的早期（堆初始化前即可）调用。
pub fn init() {
    let kstack_top = stack_top(core::ptr::addr_of!(BSP_KSTACK) as *const u8, KSTACK_SIZE);
    let gdt_ptr = core::ptr::addr_of_mut!(BSP_GDT);
    let tss_ptr = core::ptr::addr_of_mut!(BSP_TSS);
    setup_cpu(gdt_ptr, tss_ptr, kstack_top);
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


