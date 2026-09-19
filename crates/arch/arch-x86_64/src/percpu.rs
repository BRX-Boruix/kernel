//! per-CPU 数据与 `swapgs` 地基（SYSCALL-FAST-1）。
//!
//! ## 为什么需要它
//!
//! 现状：per-CPU 状态散落在各 crate 的静态数组里，靠 `my_cpu_slot()` 索引。而
//! `my_cpu_slot()` 的代价是 **一次 LAPIC MMIO 读**（`lapic.rs` 的
//! `lapic_read(LAPIC_ID)`）**加一次槽位反查表**——每次调度决策都要付。
//!
//! `syscall`/`sysret` 快速路径要的正是「廉价的『我是谁』」：`swapgs` 后从 GS base
//! 直接取 per-CPU 结构，一次内存访问替代 MMIO + 查表。
//!
//! ## `swapgs` 的危险性（本模块的设计中心）
//!
//! `swapgs` 是**无参数、无检查**的一条指令：它只是交换 `GS.base` 与
//! `IA32_KERNEL_GS_BASE` MSR。用错一次不会立刻崩，而是让后续所有 per-CPU 读取
//! 静默指向**别的核**的数据——症状是随机、难复现的数据错乱。
//!
//! 故本模块把三条不变式用类型与注释显式化：
//!
//! 1. **配对性**：每次进入内核 `swapgs` 一次，返回用户态前必须再 `swapgs` 一次，
//!    且**精确复原**（配对无残留）；
//! 2. **嵌套纪律**：中断/异常进入内核时，GS base **已经是内核值**，因此**绝不可
//!    再次 `swapgs`**——第二次交换会把 GS 换回用户值，per-CPU 访问立即错乱。
//!    判据：检查进入时的 CS 特权级（CPL）。来自用户态（CPL3）才 swapgs；
//!    来自内核态（CPL0）不 swapgs；
//! 3. **单源**：GS 路径与既有裸数组路径必须给出**相同**结果，迁移期间不得双源
//!    分叉（`my_cpu_slot_array_path` / `my_cpu_slot_gs_path` 供测试对拍）。
//!
//! ## 与 FSGSBASE 的区别（原评估的误解）
//!
//! `FSGSBASE`（`cpu.rs` 已启用）开启的是用户态 `RDFSBASE`/`WRFSBASE` 读 **FS** base，
//! 用于每线程 TLS/errno。`swapgs` 交换的是 **GS** base。两者是**不同寄存器**，
//! 原评估称「已有 FSGSBASE，swapgs 正好复用」是把两者搞混了。

use core::sync::atomic::{AtomicBool, Ordering};

/// per-CPU 结构。**必须**放在 GS base 指向的地址上。
///
/// 布局是 ABI：汇编入口偏移硬编码读取 `slot`/`kernel_stack_top`，改动即破坏
/// 入口代码。字段顺序与偏移不得随意调整（与 `InterruptFrame` 同理）。
#[repr(C)]
pub struct PerCpu {
    /// **自指针**（offset 0）。
    ///
    /// 存在意义：它是「GS base 是否真的指向本结构」的**可自证**证据——
    /// 比较 `gs:[0]` 与 `gs_base` 是否相等即可验证 GS 配置正确。
    /// 没有它，GS 配错时只能观察到「数据不对」而无法定位到「base 指错了」。
    pub self_ptr: u64,
    /// 本核的紧凑槽位（offset 8）。等价于 `my_cpu_slot()`，但无需 MMIO。
    pub slot: u64,
    /// 本核当前进程的内核栈顶（offset 16）。`syscall` 入口据此设置 RSP。
    ///
    /// **为什么必须在此**：`syscall` 指令**不切栈**（不像中断门会用 TSS.RSP0），
    /// 硬件把用户 RSP 留在 RSP 里。内核必须在入口立刻换到本核内核栈——
    /// 而取栈顶必须先知道「我是谁」，这正是 per-CPU 存在的首要理由。
    pub kernel_stack_top: u64,
    /// `syscall` 入口的用户 RSP 暂存槽（offset 24）。
    ///
    /// **为什么需要暂存**：`syscall` 进入时 RSP 还是用户栈，而构造帧又必须先
    /// 拿到内核栈。用户 RSP 一旦切栈就取不回了，故先存此处。
    ///
    /// 放 per-CPU 结构而非普通寄存器：入口阶段通用寄存器**全部尚未保存**
    /// （它们本身就是待构造帧的内容），没有空闲寄存器可用。
    pub syscall_user_rsp: u64,
    /// `syscall` 入口的用户 RIP 暂存槽（offset 32）。
    ///
    /// syscall 硬件把 RIP 存入 `rcx`，但构造帧时 `rcx` 还要作为通用寄存器入帧，
    /// 顺序上会互相覆盖，故同样先暂存。
    pub syscall_user_rip: u64,
    /// `syscall` 入口的用户 RFLAGS 暂存槽（offset 40）。
    pub syscall_user_rflags: u64,
}

/// 每核一个（256 = 与 `smp.rs` 槽位容量同源的上限）。
///
/// `AtomicU64` 而非 `Cell`：槽位在 AP 上线时由 BSP 写入、由本核读取，
/// 需要跨核发布语义（S21）。
struct PerCpuSlot {
    base_addr: core::sync::atomic::AtomicU64,
    initialized: AtomicBool,
}

const MAX_CPUS: usize = 256;

// **布局是 ABI**：`syscall_entry_stub` 用 `gs:[16]/[24]/[32]/[40]` 硬编码寻址。
// 用编译期断言把偏移钉死——字段顺序一旦变动就**编译失败**，而不是运行时静默错乱。
const _: () = {
    assert!(core::mem::offset_of!(PerCpu, self_ptr) == 0, "PerCpu.self_ptr must be at 0");
    assert!(core::mem::offset_of!(PerCpu, slot) == 8, "PerCpu.slot must be at 8");
    assert!(
        core::mem::offset_of!(PerCpu, kernel_stack_top) == 16,
        "PerCpu.kernel_stack_top must be at 16 (hardcoded in syscall stub)"
    );
    assert!(
        core::mem::offset_of!(PerCpu, syscall_user_rsp) == 24,
        "PerCpu.syscall_user_rsp must be at 24 (hardcoded in syscall stub)"
    );
    assert!(
        core::mem::offset_of!(PerCpu, syscall_user_rip) == 32,
        "PerCpu.syscall_user_rip must be at 32 (hardcoded in syscall stub)"
    );
    assert!(
        core::mem::offset_of!(PerCpu, syscall_user_rflags) == 40,
        "PerCpu.syscall_user_rflags must be at 40 (hardcoded in syscall stub)"
    );
};

static PERCPU_SLOTS: [PerCpuSlot; MAX_CPUS] = [const {
    PerCpuSlot {
        base_addr: core::sync::atomic::AtomicU64::new(0),
        initialized: AtomicBool::new(false),
    }
}; MAX_CPUS];

/// GS 地基是否已启用（`swapgs` 路径可用）。
static GS_ENABLED: AtomicBool = AtomicBool::new(false);

/// 供**裸汇编**读取的地基就绪标志（`0` = 未就绪，非 0 = 就绪）。
///
/// 为什么单独开一个 `AtomicU64` 而不是复用 `GS_ENABLED`：`AtomicBool` 的布局未
/// 承诺为可裸读的宽度；汇编里用 `cmp qword ptr [rip + sym], 0` 需要确定的 8 字节。
/// 用独立的 `AtomicU64` 把「汇编可读」变成显式契约（S21）。
pub static GS_READY_FLAG: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// 读 `IA32_KERNEL_GS_BASE`（0xC000_0102）。`swapgs` 的另一半。
#[inline]
pub fn read_kernel_gs_base() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!("rdmsr", in("ecx") 0xC000_0102u32, out("eax") lo, out("edx") hi,
            options(nostack, nomem, preserves_flags));
    }
    ((hi as u64) << 32) | lo as u64
}

/// 写 `IA32_KERNEL_GS_BASE`（0xC000_0102）。
#[inline]
pub fn write_kernel_gs_base(v: u64) {
    unsafe {
        core::arch::asm!("wrmsr", in("ecx") 0xC000_0102u32,
            in("eax") v as u32, in("edx") (v >> 32) as u32,
            options(nostack, nomem, preserves_flags));
    }
}

/// 读当前 `GS.base`（`IA32_GS_BASE`，0xC000_0101）。
#[inline]
pub fn read_gs_base() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!("rdmsr", in("ecx") 0xC000_0101u32, out("eax") lo, out("edx") hi,
            options(nostack, nomem, preserves_flags));
    }
    ((hi as u64) << 32) | lo as u64
}

/// 写当前 `GS.base`（`IA32_GS_BASE`，0xC000_0101）。
#[inline]
pub fn write_gs_base(v: u64) {
    unsafe {
        core::arch::asm!("wrmsr", in("ecx") 0xC000_0101u32,
            in("eax") v as u32, in("edx") (v >> 32) as u32,
            options(nostack, nomem, preserves_flags));
    }
}

/// 执行一次 `swapgs`。
///
/// **调用者必须保证配对**与**嵌套纪律**（见模块文档）。本函数不做检查——
/// 检查在入口汇编的特权级判断里，那是唯一能正确判断「该不该换」的位置。
#[inline]
pub unsafe fn swapgs() {
    core::arch::asm!("swapgs", options(nostack, nomem, preserves_flags));
}

/// 登记槽位 `slot` 的 per-CPU 结构地址（BSP 在 AP 上线时调用）。
///
/// **只写 MSR 与槽位表，不动当前 GS base**：调用方（本核）决定何时切换。
pub fn register_slot(slot: usize, base: *mut PerCpu) {
    if slot >= MAX_CPUS {
        return;
    }
    let addr = base as u64;
    // S21：先写结构内容，再置 initialized 并发布地址（Release 语义）。
    unsafe {
        (*base).self_ptr = addr;
        (*base).slot = slot as u64;
    }
    PERCPU_SLOTS[slot].base_addr.store(addr, Ordering::Release);
    PERCPU_SLOTS[slot].initialized.store(true, Ordering::Release);
}

/// 取槽位 `slot` 的 per-CPU 结构地址（未登记返回 None）。
pub fn base_of_slot(slot: usize) -> Option<u64> {
    if slot >= MAX_CPUS || !PERCPU_SLOTS[slot].initialized.load(Ordering::Acquire) {
        return None;
    }
    Some(PERCPU_SLOTS[slot].base_addr.load(Ordering::Acquire))
}

/// 当前核的 per-CPU 结构地址（由 `GS.base` 取得，**无 MMIO、无查表**）。
#[inline]
pub fn current() -> *mut PerCpu {
    read_gs_base() as *mut PerCpu
}

/// GS 地基是否已启用。
#[inline]
pub fn is_enabled() -> bool {
    GS_ENABLED.load(Ordering::Acquire)
}

/// 在当前核启用 GS 地基：把 per-CPU 结构地址装入 `GS.base`，
/// 并把**用户值**（0，用户态无 GS 需求）存入 `IA32_KERNEL_GS_BASE`。
///
/// 不变式（启用后成立）：
///   - 内核态：`GS.base` = per-CPU 结构地址，`KERNEL_GS_BASE` = 用户值；
///   - 用户态：`GS.base` = 用户值，`KERNEL_GS_BASE` = per-CPU 结构地址。
///
/// 即：**`swapgs` 在进入内核时把 per-CPU 地址换进来，退出时换回去**。
pub fn enable_on_current(slot: usize) -> bool {
    let Some(base) = base_of_slot(slot) else {
        return false;
    };
    write_gs_base(base);
    write_kernel_gs_base(0); // 用户态 GS 值：当前无用户 GS 需求，取 0
    GS_ENABLED.store(true, Ordering::Release);
    // 裸汇编可见的就绪标志：**最后**置位，确保前面的 MSR 写入都已生效。
    GS_READY_FLAG.store(1, Ordering::Release);
    true
}

/// 停用（仅供测试构造反向场景）。
pub fn disable_for_test() {
    GS_ENABLED.store(false, Ordering::Release);
    GS_READY_FLAG.store(0, Ordering::Release);
}

// ---------- 静态 per-CPU 存储（BSP 用；AP 上线的对称分配留待后续） ----------

/// per-CPU 结构静态存储。
///
/// `#[repr(C, align(64))]`：结构须**缓存行对齐**——`swapgs` 后每次 per-CPU 访问
/// 都落在此地址，跨缓存行会平白多一次访存；且对齐可避免伪共享。
#[repr(C, align(64))]
pub struct PerCpuStorage {
    pub inner: PerCpu,
}

impl PerCpuStorage {
    const fn new() -> Self {
        Self {
            inner: PerCpu {
                self_ptr: 0,
                slot: 0,
                kernel_stack_top: 0,
                syscall_user_rsp: 0,
                syscall_user_rip: 0,
                syscall_user_rflags: 0,
            },
        }
    }
}

/// 256 核槽位的静态存储（与 `smp.rs` 槽位容量同源）。
///
/// 用 `static mut` 数组 + 稳定地址：per-CPU 结构的地址**必须终身不变**
/// （GS base 存的是裸地址，移动即失效）。
static mut PERCPU_STORAGE: [PerCpuStorage; MAX_CPUS] = [const { PerCpuStorage::new() }; MAX_CPUS];

/// 取槽位 `slot` 的静态存储地址（永不移动）。
pub fn storage_of_slot(slot: usize) -> *mut PerCpu {
    if slot >= MAX_CPUS {
        return core::ptr::null_mut();
    }
    unsafe { core::ptr::addr_of_mut!(PERCPU_STORAGE[slot].inner) }
}

/// 初启当前核的 per-CPU 地基（BSP/AP 上线时各调用一次）。
///
/// `kernel_stack_top` 由调用方给出（本核内核栈顶，`syscall` 入口据此切栈）。
/// 返回是否成功。
pub fn init_current(slot: usize, kernel_stack_top: u64) -> bool {
    let base = storage_of_slot(slot);
    if base.is_null() {
        return false;
    }
    register_slot(slot, base);
    unsafe {
        (*base).kernel_stack_top = kernel_stack_top;
    }
    enable_on_current(slot)
}