//! 8259 可编程中断控制器（PIC）。
//!
//! 与 APIC 不同，8259 通过 port I/O 编程，无需内存映射，适合当前
//! 尚未建立虚拟内存映射的阶段。将 IRQ0~15 重映射到 IDT 向量 32~47，
//! 避免与 CPU 异常向量 0~31 冲突。

use crate::port::{inb, outb};

/// 掩码位运算与语义常量的**唯一事实源**在 `klib::pic_mask`（S15）。
///
/// 那里是纯逻辑、无 I/O，`cargo test -p klib` 可穷举验证（含并发丢更新的
/// 交错场景）。本模块只负责「把算好的掩码写到 8259 端口」这一件事。
/// 此前这段位运算内联在这里，因 `arch-x86_64` 无法宿主编译（no_std + 内联
/// 汇编），**一个测试都没有**——而中断丢失的根因恰在其中。
pub use klib::pic_mask::{
    PIC_CASCADE_IRQ, PIC_IRQ_COUNT, PIC_KEYBOARD_IRQ, PIC_TIMER_IRQ,
};

// 8259 端口（x86 硬件标准，非温室假设）。
// 主片（master）命令/数据端口 0x20/0x21，从片（slave）0xA0/0xA1。
const PIC1_COMMAND: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_COMMAND: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

// ICW 常量
const ICW1_INIT: u8 = 0x11; // 初始化 + 级联
const ICW4_8086: u8 = 0x01; // 8086 模式

/// IMR 读-改-写的**全局串行化锁**（S21 并发显式化）。
///
/// ## 为什么必须有这把锁
///
/// 8259 的 IMR 只能通过「读端口 -> 改一位 -> 写端口」修改，**硬件本身不提供
/// 原子的位置位/位清除**。而调用方分布在两个不同的上下文里：
///
///   * **中断上下文**：`device_irq_handler` 交付中断后调 `mask_irq`（IRQ1 键盘、
///     IRQ11 HDA 等都会走这条路径）；
///   * **进程上下文**：`sys_driver_irq_wait` 每次等待入口调 `unmask_irq`，
///     用户态驱动在 4 核 SMP 上运行。
///
/// 两者并发时会丢失更新：两个 CPU 各自读到同一份旧掩码，各自改自己那一位，
/// 后写者覆盖先写者。**实测症状**：intel-hda 的 BCIS 事件持续产生
/// （bcis_total 单调上涨），但交付到用户态的次数只有产生次数的 ~1.7%
/// （irq_hits=34 / bcis_total=35，同时 irq_timeouts=1967），
/// 即绝大多数「解屏蔽 IRQ11+级联」被并发的「屏蔽 IRQ1」覆盖回屏蔽态。
///
/// ## 锁的纪律
///
/// * 仅保护 IMR 的读-改-写序列，临界区是两次 `outb`，极短；
/// * **必须是中断安全锁**（[`klib::sync::irq::IrqSpinLock`]：加锁时关中断并
///   保存/恢复 FLAGS）。理由：`device_irq_handler` 会在**中断上下文**调用
///   `mask_irq`，而 `unmask_irq` 在**进程上下文**调用。若用不关中断的纯自旋锁，
///   同一 CPU 上「持锁的进程上下文被中断打断，中断 handler 又要拿同一把锁」
///   即自死锁。IrqSpinLock 关中断后该 CPU 不可能在临界区内被中断重入；
///   跨 CPU 仍靠自旋互斥。
/// * **不得**在持锁期间调用任何可能阻塞或切换的函数（临界区内不得睡眠）。
static IMR_LOCK: klib::sync::irq::IrqSpinLock<()> = klib::sync::irq::IrqSpinLock::new(());

/// 重新映射 IRQ0~15 到 IDT 向量 32~47。
pub fn remap() {
    let mask1 = inb(PIC1_DATA);
    let mask2 = inb(PIC2_DATA);

    // 向两个 PIC 发送初始化命令
    outb(PIC1_COMMAND, ICW1_INIT);
    outb(PIC2_COMMAND, ICW1_INIT);

    // 中断向量偏移：主片 0x20 (32)，从片 0x28 (40)
    outb(PIC1_DATA, 0x20);
    outb(PIC2_DATA, 0x28);

    // 级联配置：主片 IRQ2 接从片；从片级联到主片 IRQ2
    outb(PIC1_DATA, 0x04);
    outb(PIC2_DATA, 0x02);

    // 8086 模式
    outb(PIC1_DATA, ICW4_8086);
    outb(PIC2_DATA, ICW4_8086);

    // 恢复原中断掩码
    outb(PIC1_DATA, mask1);
    outb(PIC2_DATA, mask2);
}

/// 屏蔽所有 IRQ（除了掩码参数中为 0 的位）。
///
/// `mask` 为 16 位：bit i = 0 表示使能 IRQ i（8259 IMR 硬件语义）。
///
/// **这是整字覆盖，不参与读-改-写**。用于「把 8259 置到一个已知的完整状态」
/// （初始化、启动基线）。增量修改一律用 [`mask_irq`]/[`unmask_irq`]，
/// 它们在 [`IMR_LOCK`] 内基于**端口回读的最新值**运算，不会丢失并发更新。
pub fn set_mask(mask: u16) {
    let _g = IMR_LOCK.lock();
    outb(PIC1_DATA, (mask & 0xFF) as u8);
    outb(PIC2_DATA, ((mask >> 8) & 0xFF) as u8);
}

/// 读取当前中断掩码（主片低 8 位、从片高 8 位）。
///
/// **不得**用它自行做读-改-写：两次 `inb` 之间可能有别的 CPU 写 IMR。
/// 需要增量修改请用 [`mask_irq`]/[`unmask_irq`]，它们在锁内完成整个序列。
/// 本函数只用于观测与整字覆盖前的取值。
pub fn get_mask() -> u16 {
    let _g = IMR_LOCK.lock();
    read_mask_locked()
}

/// 无锁读掩码（**调用方必须已持有 [`IMR_LOCK`]**）。
fn read_mask_locked() -> u16 {
    (inb(PIC1_DATA) as u16) | ((inb(PIC2_DATA) as u16) << 8)
}

/// 无锁写掩码（**调用方必须已持有 [`IMR_LOCK`]**）。
fn write_mask_locked(mask: u16) {
    outb(PIC1_DATA, (mask & 0xFF) as u8);
    outb(PIC2_DATA, ((mask >> 8) & 0xFF) as u8);
}

/// 位运算与语义常量的唯一事实源（S15）：纯逻辑在 `klib::pic_mask`。
use klib::pic_mask::{boot_baseline as pm_boot_baseline, is_masked, mask as pm_mask, unmask as pm_unmask};

/// 解除某条 IRQ 的屏蔽，**保持其它位不变**。
///
/// 为什么需要它而不是让调用方直接 `set_mask`：`set_mask` 是**整字覆盖**，
/// 调用方必须自己知道当前所有已解屏蔽位，否则会误屏蔽键盘等已工作的中断。
/// 「按位解除」把这件事收敛到一处，调用方只需声明自己需要哪条线。
///
/// **从片级联自动处理**：IRQ 8~15 挂在从片上，其输出经主片 IRQ2 送到 CPU。
/// 屏蔽 IRQ2 等于屏蔽整条从片——因此对 IRQ>=8 的请求，本函数一并解屏蔽
/// IRQ2（见 `klib::pic_mask::unmask`，该规则已在那里被测试钉死）。
///
/// **并发纪律**（S21）：整个「读端口 -> 位运算 -> 写端口」在 [`IMR_LOCK`] 内
/// 完成。此前无锁的读-改-写会造成丢失更新——实测 intel-hda 的 IRQ11 解屏蔽被
/// 并发的键盘 `mask_irq` 覆盖，中断交付率跌到 ~1.7%。
///
/// 返回：变更后的掩码（供调用方日志/断言）。`irq >= 16` 时不变更并原样返回。
pub fn unmask_irq(irq: u8) -> u16 {
    let _g = IMR_LOCK.lock();
    let cur = read_mask_locked();
    let next = pm_unmask(cur, irq);
    if next != cur {
        write_mask_locked(next);
    }
    next
}

/// 屏蔽单条 IRQ（保持其它位不变）。与 [`unmask_irq`] 成对，构成**用户态驱动
/// 电平中断的 half-drop 交付纪律**：中断 handler 唤醒归属驱动后立即屏蔽该线
/// （电平触发的设备在用户态驱动完成 MMIO 应答前不会释放该线；若不屏蔽，中断
/// 门重开 irq_restore/sti 的瞬间即重投递，CPU 全程困在中断上下文，用户态驱动
/// 永远得不到运行——QEMU intel-hda 实测整系统冻结于 irq_restore+6，IF=0，
/// 两秒采样 RIP 纹丝不动）。驱动下一次进入 `driver_irq_wait` 时再解屏蔽。
///
/// **并发纪律**（S21）：同 [`unmask_irq`]，整个读-改-写在 [`IMR_LOCK`] 内完成。
/// 本函数在**中断上下文**被调用，锁的临界区只有两次端口写，可安全获取。
pub fn mask_irq(irq: u8) -> u16 {
    let _g = IMR_LOCK.lock();
    let cur = read_mask_locked();
    let next = pm_mask(cur, irq);
    if next != cur {
        write_mask_locked(next);
    }
    next
}

/// 某条 IRQ 当前是否已被屏蔽（供诊断/断言观测真值，不修改硬件）。
pub fn irq_is_masked(irq: u8) -> bool {
    is_masked(get_mask(), irq)
}
/// 发送 EOI（中断结束）给主片（和从片）。
pub fn end_of_interrupt(irq: u8) {
    if irq >= 8 {
        outb(PIC2_COMMAND, 0x20);
    }
    outb(PIC1_COMMAND, 0x20);
}

/// 初始化 8259 PIC。
///
/// 无条件重映射 8259 到向量 32~47（避免与 CPU 异常向量 0~31 冲突），并**仅解除
/// 键盘 IRQ1 屏蔽**（bit1=0），其余（含 IRQ0 timer、IRQ2 级联）保持屏蔽。
///
/// 本项目键盘走 **8259 → LAPIC LINT0 (ExtINT)** 路径（QEMU `pc` 机器最可靠的
/// 外部中断源）：`imcr::switch_to_pic_mode` 把 IMCR 切到 PIC 模式使 8259 输出
/// 连 LINT0，`lapic::init` 把 LINT0 配为 ExtINT 接收；此处解屏蔽 IRQ1 才能让
/// 其到达 CPU。IRQ0（timer）由 LAPIC 自身定时器接管，故保持屏蔽。
pub fn init() {
    remap();
    // **启动基线只有键盘**（`klib::pic_mask::boot_baseline`，单点定义）。
    //
    // IRQ2（级联线）**不在此常开**：它由从片设备驱动按需打开——`unmask_irq`
    // 对 `irq >= 8` 会自动一并解屏蔽 IRQ2（该规则已在 `klib::pic_mask` 的测试
    // 里钉死）。启动时无条件常开 IRQ2 会在没有任何从片驱动就位时放行从片的
    // 杂散请求。
    //
    // IRQ0（timer）由 LAPIC 自身定时器接管，保持屏蔽。
    //
    // 【历史】此前这里硬编码 `!((1<<1)|(1<<2))` 常开 IRQ2，用来绕过
    // `kmain` 之后那次整字覆盖 `set_mask(PIC_MASK_ALL_EXCEPT_IRQ1)` 把级联位
    // 清掉的问题。真正的修法是消除那次整字覆盖（见 `kernel/src/main.rs`），
    // 而不是在此处用魔法值对冲另一个魔法值。
    set_mask(pm_boot_baseline());
    klib::info!("[pic] 8259 remapped, IRQ1 (kbd) unmasked (cascade IRQ2 opened on demand)");
}
