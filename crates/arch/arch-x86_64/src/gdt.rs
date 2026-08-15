//! x86-64 GDT（全局描述符表）与 TSS（任务状态段）。
//!
//! 手写实现，不依赖外部 crate：
//! - GDT 含：空段、内核代码段(0x08)、内核数据段(0x10)、TSS 段(0x18)。
//! - TSS 提供 ring3→ring0 切换时的内核栈（`rsp0`），为后续用户态/系统调用铺路。

use core::arch::global_asm;

/// GDT 段选择子
pub const KCODE: u16 = 0x08;
pub const KDATA: u16 = 0x10;
pub const TSS_SEL: u16 = 0x18;

/// 内核栈大小（4KB），供 ring0 中断/异常使用。
const KSTACK_SIZE: usize = 0x1000;

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
    const fn new() -> Self {
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
    const fn new() -> Self {
        let mut g = Self { entries: [0; 5] };
        // 内核代码段：present, DPL0, 可读可执行, 64 位 (L=1)
        g.entries[1] = 0x00_A0_9A_00_0000_FFFF;
        // 内核数据段：present, DPL0, 可读写, 展开向上
        g.entries[2] = 0x00_CF_92_00_0000_FFFF;
        g
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

static mut GDT: Gdt = Gdt::new();
static mut TSS: Tss = Tss::new();
static mut KSTACK: [u8; KSTACK_SIZE] = [0; KSTACK_SIZE];

// 加载 GDT 到 GDTR，并重新装载数据段与代码段。
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

/// GDTR 结构（lgdt 需要：16 位 limit + 64 位 base）。
#[repr(C, packed)]
struct Gdtr {
    limit: u16,
    base: u64,
}

/// 初始化 GDT 与 TSS。
///
/// 必须在允许使用全局静态变量的早期（堆初始化前即可）调用。
pub fn init() {
    unsafe {
        // 配置 TSS.rsp0 = 内核栈顶，供 ring0 使用
        let kstack_top = (&raw const KSTACK).cast::<u8>() as u64 + KSTACK_SIZE as u64;
        TSS.rsp[0] = kstack_top;

        let base = core::ptr::addr_of!(TSS) as u64;
        GDT.entries[3] = tss_low(base);
        GDT.entries[4] = tss_high(base);

        let gdtr = Gdtr {
            limit: (core::mem::size_of::<Gdt>() - 1) as u16,
            base: core::ptr::addr_of!(GDT) as u64,
        };
        x86_64_load_gdt(&gdtr as *const Gdtr);
        x86_64_load_tss();
    }
}
