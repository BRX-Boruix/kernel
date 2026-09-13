//! ATA PIO 总线锁：串行化同一 CPU/多 CPU 之间的通道寄存器访问。
//!
//! ## 为什么需要（真实缺陷，非预防性设计）
//!
//! ATA PIO 的读/写是一个**跨多个 I/O 端口的多步时序**：
//!
//! ```text
//! select_drive_lba -> set_lba_regs -> outb(REG_COMMAND) -> wait_drq -> 读/写 256 个字
//! ```
//!
//! 通道寄存器（`0x1F0`/`0x170` 系列）是**物理共享**的：两个 CPU 同时走这段
//! 时序，一方写的 LBA/COMMAND 会被另一方覆盖，`wait_drq` 可能在错误的
//! 时刻返回，最终 `ata_read_sector` 失败。
//!
//! 此前该时序**完全无锁**：`read_at`/`write_at` 里的 6 处 `.lock()` 都只是
//! 取 `is_hardware`/`sectors` 这类**取完即释放**的短锁，没有任何锁覆盖 PIO 事务
//! 本身。多核下两个进程同时做盘 I/O 即可互相破坏，表现为**随机短读**。
//!
//! 实测症状：`volumed` 启动触发路径解析 → `fs.root()` 读 EXT2 根 inode →
//! 撞上并发的盘 I/O → `read_inode` 短读 → `expect` panic。两次内核崩溃落在
//! **不同 CPU**（cpu:0 / cpu:1），是竞态而非确定性损坏；且此前 `init` 已成功
//! 读入 74824 字节，证明镜像本身完好。
//!
//! ## 设计要点
//!
//! - **可重入**：按 LAPIC id 识别同 CPU（与 `serial.rs` 的串口锁同一模式）。
//!   当前三个加锁点（`ata_read_sector`/`ata_write_sector`/`identify_ata`）
//!   互不调用，因此**今天并不存在**嵌套获取；保留可重入是为了将来出现
//!   读-改-写复合操作（如 `write_at` 的部分扇区写路径）时不会自死锁——
//!   那种路径下同 CPU 重入是正确语义。**注意**：身份无法识别（LAPIC 未映射）
//!   时本锁**不启用**重入，见 [`lock`] 的不变量说明。
//! - **关中断**：持锁期间禁止本 CPU 中断。中断处理若也碰盘，未关中断时会
//!   在持锁时重入并自旋死锁（同 CPU 上等一把自己持有的锁）。
//! - **锁粒度是整个 PIO 事务**，不是单次 `outb`——时序的原子性才是要保护的
//!   对象。

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

/// 无主哨兵（LAPIC id 不可能取到该值的合法 CPU）。
const NO_OWNER: u32 = u32::MAX;

static LOCKED: AtomicBool = AtomicBool::new(false);
static OWNER: AtomicU32 = AtomicU32::new(NO_OWNER);
static DEPTH: AtomicU8 = AtomicU8::new(0);

/// 当前 CPU 的身份标识，供可重入判定使用。
///
/// **绝不能把「LAPIC 未映射」折叠成 0。** LAPIC id 0 是合法的 BSP 身份，
/// 若未知时也返回 0，则当 BSP（真 id 0）持锁、另一个尚未拿到 LAPIC 映射的
/// CPU 进来时，它会看到 `OWNER == 0 == 自己`，判定为「同 CPU 重入」而直接
/// 放行——**跨 CPU 互斥静默消失**，锁形同虚设。这类失效比崩溃更难发现：
/// 系统照常运行，只在并发下偶发短读。
///
/// 因此返回值用 `Option`：`None` 明确表示「无法识别本 CPU」，此时**不启用**
/// 可重入优化，一律走互斥路径（见 [`lock`]）。安全侧优先——识别不了身份时
/// 宁可多等，也不放过一次真正的并发。
///
/// 读 `LAPIC_ID` 必须经 [`arch_x86_64::lapic::is_mapped`] 守卫：映射建立前
/// 直接读会访问虚拟地址 0 附近并触发二次页错误（该函数文档已明文警告）。
#[inline]
fn cpu_id() -> Option<u32> {
    if arch_x86_64::lapic::is_mapped() {
        Some(arch_x86_64::lapic::current_lapic_id())
    } else {
        None
    }
}

/// 保存中断状态并关中断，返回原 RFLAGS 供恢复。
///
/// 与 `arch_x86_64::serial` 的 `irq_save` 同构——该模式已在本项目验证可用，
/// 不另造一套。
#[inline]
fn irq_save() -> u64 {
    let flags: u64;
    unsafe {
        core::arch::asm!("pushfq; pop {}", out(reg) flags, options(nomem, nostack));
        core::arch::asm!("cli", options(nomem, nostack));
    }
    flags
}

#[inline]
fn irq_restore(flags: u64) {
    unsafe {
        core::arch::asm!("push {}; popfq", in(reg) flags, options(nomem, nostack));
    }
}

/// 持锁守卫：Drop 时释放锁并恢复中断状态。
///
/// 用 RAII 而非手工配对，是为了让**任何**提前返回路径（`?`、`return`、`break`）
/// 都不会漏放锁——手工 `release()` 在 `ata_read_sector` 的多条错误分支上极易漏写，
/// 漏一次就是全局死锁。
pub struct AtaBusGuard {
    saved_flags: u64,
}

impl Drop for AtaBusGuard {
    fn drop(&mut self) {
        // 先释放锁再恢复中断：反过来的话，恢复中断后到释放锁之间有一个
        // 窗口，中断处理可在此刻重入并看到"锁仍被自己持有"，虽因可重入
        // 不会死锁，但会让临界区语义变得难以推理。
        if DEPTH.fetch_sub(1, Ordering::SeqCst) == 1 {
            OWNER.store(NO_OWNER, Ordering::SeqCst);
            LOCKED.store(false, Ordering::SeqCst);
        }
        irq_restore(self.saved_flags);
    }
}

/// 获取 ATA 总线锁（可重入 + 关中断）。
///
/// 必须覆盖**整个** PIO 事务（从选驱动器到最后的数据字），而不是单条 outb。
///
/// # 不变量：置 `NO_OWNER` 的持有者不得重入
///
/// `OWNER == NO_OWNER`（身份未知时写入，见下）不等于任何真实的 `cpu_id`，
/// 因此该持有者**无法**再次进入重入分支。若将来出现「同一未知身份 CPU 在
/// 持锁期间再次调用 [`lock`]」的路径，它会自旋到死。
///
/// 当前**不存在**这样的路径：三个加锁点（`ata_read_sector`、`ata_write_sector`、
/// `identify_ata`）互不调用，`read_at`/`write_at` 本身不加锁（只在内部调用
/// 上述三者），且 `irq_save` 关中断排除了中断上下文重入。**新增调用方必须
/// 重新审视本不变量**——持有本锁时不得再调 [`lock`] 的未知身份场景，
/// 否则是静默死锁。
pub fn lock() -> AtaBusGuard {
    let saved_flags = irq_save();
    let cpu = cpu_id();
    loop {
        // 同 CPU 重入：读-改-写路径（write_at 内部调 ata_read_sector）走这里。
        //
        // **仅在能识别本 CPU 时**才允许重入。`cpu == None` 表示身份未知，
        // 此时不做重入判定——否则两个未知身份的 CPU 会互相误认为同一核而
        // 同时进入临界区（见 [`cpu_id`] 的说明）。
        if let Some(c) = cpu {
            if OWNER.load(Ordering::SeqCst) == c {
                DEPTH.fetch_add(1, Ordering::SeqCst);
                return AtaBusGuard { saved_flags };
            }
        }
        if !LOCKED.swap(true, Ordering::SeqCst) {
            // 身份未知时写 NO_OWNER：`OWNER == NO_OWNER` 永不等于任何真实
            // cpu_id，因此后续无人能把它误判成自己的重入。
            OWNER.store(cpu.unwrap_or(NO_OWNER), Ordering::SeqCst);
            DEPTH.store(1, Ordering::SeqCst);
            return AtaBusGuard { saved_flags };
        }
        core::hint::spin_loop();
    }
}
