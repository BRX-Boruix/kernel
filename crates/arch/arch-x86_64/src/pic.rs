//! 8259 可编程中断控制器（PIC）。
//!
//! 与 APIC 不同，8259 通过 port I/O 编程，无需内存映射，适合当前
//! 尚未建立虚拟内存映射的阶段。将 IRQ0~15 重映射到 IDT 向量 32~47，
//! 避免与 CPU 异常向量 0~31 冲突。

use crate::port::{inb, outb};

// 8259 端口（x86 硬件标准，非温室假设）。
// 主片（master）命令/数据端口 0x20/0x21，从片（slave）0xA0/0xA1。
const PIC1_COMMAND: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_COMMAND: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

// ICW 常量
const ICW1_INIT: u8 = 0x11; // 初始化 + 级联
const ICW4_8086: u8 = 0x01; // 8086 模式

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
/// `mask` 为 16 位：bit i = 0 表示使能 IRQ i。
pub fn set_mask(mask: u16) {
    outb(PIC1_DATA, (mask & 0xFF) as u8);
    outb(PIC2_DATA, ((mask >> 8) & 0xFF) as u8);
}

/// 读取当前中断掩码。
pub fn get_mask() -> u16 {
    (inb(PIC1_DATA) as u16) | ((inb(PIC2_DATA) as u16) << 8)
}

/// 解除某条 IRQ 的屏蔽，**保持其它位不变**（读-改-写掩码）。
///
/// 为什么需要它而不是让调用方直接 `set_mask`：`set_mask` 是**整字覆盖**，
/// 调用方必须自己知道当前所有已解屏蔽位，否则会误屏蔽键盘等已工作的中断。
/// 「按位解除」把这件事收敛到一处，调用方只需声明自己需要哪条线。
///
/// **从片级联自动处理**：IRQ 8~15 挂在从片上，其输出经主片 IRQ2 送到 CPU。
/// 屏蔽 IRQ2 等于屏蔽整条从片——因此对 IRQ>=8 的请求，本函数**一并解屏蔽
/// IRQ2**。这是「明明解了掩码却收不到中断」最经典的坑，在此自动兜住。
///
/// 返回：变更后的掩码（供调用方日志/断言）。`irq >= 16` 时不变更并原样返回。
pub fn unmask_irq(irq: u8) -> u16 {
    if irq as usize >= 16 {
        return get_mask(); // 越界：如实不动作（不静默改别的位）
    }
    let mut mask = get_mask();
    mask &= !(1u16 << irq);
    if irq >= 8 {
        // 从片中断必须同时打开级联线 IRQ2，否则它的输出到不了主片。
        mask &= !(1u16 << 2);
    }
    set_mask(mask);
    mask
}

/// 【本仓修订】屏蔽单条 IRQ（读-改-写，其它位不变）。与 unmask_irq 成对：
/// 用于**用户态驱动电平中断的交付纪律**——中断 handler 唤醒归属驱动后立即屏蔽该线（电平触发的设备在用户态驱动完成 MMIO 应答前不会释放该线；若
/// 不屏蔽，中断门重开 irq_restore/sti 的瞬间即重投递，CPU 全程困在中断
/// 上下文，用户态驱动永远得不到运行——QEMU intel-hda 实测整系统冻结于
/// irq_restore+6，IF=0，两秒采样 RIP 纹丝不动）。驱动下一次进入
/// driver_irq_wait 时再解屏蔽（彼时设备状态已在其服务例程中清掉，或驱动
/// 本就要重新等待新事件）。
pub fn mask_irq(irq: u8) -> u16 {
    if irq as usize >= 16 {
        return get_mask();
    }
    let mut mask = get_mask();
    mask |= 1u16 << irq;
    set_mask(mask);
    mask
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
    // 使能 IRQ1（键盘）+ IRQ2（级联线）。
    //
    // 【本仓修订】IRQ2 必须常开：IRQ8-15 全部走 8259 从片，从片输出接在主片
    // IRQ2 上——IRQ2 被屏蔽 = 从片所有中断（含 PCI 设备常用的 IRQ11）永远
    // 到不了 CPU。旧掩码只开 IRQ1：用户态驱动认领 IRQ11 后，即便等待端解屏
    // 蔽了 IRQ11 本身，从片出来的中断仍被主片级联位挡住。实测：35 秒内设备
    // 侧拉线 321 次、CPU 只收到 2 次（都是解屏蔽写 IMR 的竞态窗口恰好撞上
    // 线为高的瞬间），音频流转 2 轮后永久断流。IRQ0（LAPIC 定时器）保持屏蔽。
    const MASK_ALL_EXCEPT_IRQ1_IRQ2: u16 = !((1u16 << 1) | (1u16 << 2));
    set_mask(MASK_ALL_EXCEPT_IRQ1_IRQ2);
    klib::info!("[pic] 8259 remapped, IRQ1 (kbd) + IRQ2 (cascade) unmasked");
}
