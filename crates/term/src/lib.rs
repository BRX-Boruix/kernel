//! framebuffer 终端（flanterm）初始化与输出（独立表现层 Crate）。
//!
//! 负责从引导协议提供的 framebuffer 创建 flanterm 终端上下文，并在屏幕上打印文本。
//! 上下文被全局持有（`'static`），供 `panic` 等场景在任意时刻向屏幕输出。
//!
//! 本 crate 不依赖任何具体引导协议：调用方把 [`FbInfo`] 值结构转换好后传入，
//! 引导协议类型留在内核侧（term1 T9，S14 抽象接口层）。
//!
//! 并发契约（term1 T1）：`klib::console` 要求每个 sink 自行保证 `write_str`
//! 内部原子——本 crate 经 [`TERM_LOCK`] 履约；自愈式补丁已随 term1 T2 整改
//! 移除，绘制异常只观测、不静默修补。

#![no_std]

#[cfg(test)]
extern crate std;

extern crate alloc;

use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use flanterm_rust::FlantermContext;
use klib::error::Error;
use klib::sync::irq::IrqSpinLock;
use klib::{error, info};

/// Limine framebuffer 协议的线性 RGB 内存模型编号。
///
/// 来源：Limine Boot Protocol 规范 §Framebuffer，`memory_model` 字段
/// 取值 1 表示 packed-RGB（像素布局由各通道 mask 完整描述）。
pub const LIMINE_MEMORY_MODEL_RGB: u8 = 1;

/// 全局 framebuffer 终端上下文指针（由 `init` 保存，未初始化时为 0）。
///
/// 发布方 `init` 以 Release 写入、消费方以 Acquire 读取（配对完整，
/// 见审查记录 §四）；指针本身指向 `Box::leak` 的 `'static` 上下文，
/// 其内部状态的所有变更都在 [`TERM_LOCK`] 内串行化。
static TERMINAL_PTR: AtomicUsize = AtomicUsize::new(0);

/// 终端串行化锁（term1 T1：并发契约履约）。
///
/// `klib::console` 的设计约束要求每个 sink 自行保证 `write_str` 内部原子
/// （klib/console.rs 头注「已各自持锁整串写入」）。串口侧以
/// `irq_save + LOCK.acquire()` 履约，本 crate 此前零锁是全内核唯一违约方：
/// 中断上下文日志重入即可打断进行中的 `flanterm_write` 打乱 ctx 状态，
/// SMP（arch-x86_64/smp.rs 已具备 AP 启动）下跨核并发同理。
///
/// **锁序纪律（S21，单向嵌套，反向即自死锁）**：
/// - 允许方向：`日志环形缓冲锁 → TERM_LOCK`（log 转发到本 sink 时自然嵌套）；
///   与串口侧 `SERIAL_LOCK ← console 转发` 同构。
/// - 禁止方向：持 `TERM_LOCK` 期间调用任何 klib 日志宏——`IrqSpinLock`
///   不可重入，warn!→console→本 sink→TERM_LOCK 会自旋等自己。
///   因此锁内只做终端状态机操作与绘制，所有告警在锁外发出。
///
/// panic 路径论证：panic 入口先关中断（KA1），随后屏幕输出走本锁——同核
/// 场景持锁者必已关中断、不可能被 panic 打断；跨核场景其它核要么在自旋
/// 等锁（关中断中收不到 IPI，但 flanterm_write 有界、释放后即响应停机）、
/// 要么已被 cross-halt 停住；最坏情形（持锁核现场损坏）诊断已在更早的
/// 串口阶段完整落盘，屏幕缺失不损失信息。
static TERM_LOCK: IrqSpinLock<()> = IrqSpinLock::new(());

/// 终端未就绪期间被丢弃的 `write_str` 调用次数。
///
/// term1 T14：静默丢弃即伪交付——早期 panic 屏幕输出发生在 `init` 之前时，
/// 调用被跳过但必须留下可观测痕迹（诊断计数，非零即可追查丢失窗口）。
static DROPPED_WRITE_CALLS: AtomicUsize = AtomicUsize::new(0);

/// 已被终端拒绝的 framebuffer 描述参数（诊断观测口）。
///
/// 非 `Err` 时表示自本次启动以来没有任何写入因「终端未就绪」而被丢弃；
/// 非零则说明存在一段输出只到达了串口、从未上屏。
pub fn dropped_write_calls() -> usize {
    DROPPED_WRITE_CALLS.load(Ordering::Relaxed)
}

/// 表现层自有的 framebuffer 描述值结构（term1 T9）。
///
/// 字段类型镜像 Limine 协议定义（u64 几何 + u16 bpp + u8 mask），避免边界
/// 处有损截断；校验算术全部使用 checked 运算（S19）。本结构由内核侧从
/// 具体引导协议描述符转换而来，term 不认识任何协议类型。
#[derive(Debug, Clone, Copy)]
pub struct FbInfo {
    /// framebuffer 起始虚拟地址（字节地址，bootloader 已完成 HHDM 映射）。
    pub addr: usize,
    /// 可见像素宽度。
    pub width: u64,
    /// 可见像素高度。
    pub height: u64,
    /// 行距（字节）。硬件常插入 padding，故不等于 `width * 4`。
    pub pitch: u64,
    /// 每像素位数。
    pub bpp: u16,
    /// 内存模型编号（[`LIMINE_MEMORY_MODEL_RGB`] = packed RGB）。
    pub memory_model: u8,
    /// 红通道位宽与位偏移（像素内布局由 mask 完整描述）。
    pub red_mask_size: u8,
    pub red_mask_shift: u8,
    /// 绿通道位宽与位偏移。
    pub green_mask_size: u8,
    pub green_mask_shift: u8,
    /// 蓝通道位宽与位偏移。
    pub blue_mask_size: u8,
    pub blue_mask_shift: u8,
}

/// framebuffer 参数被拒绝的原因（term1 T3：零校验进 unsafe 的反面——
/// 每个 unsafe 前提都有具名、可测的检查点）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RejectReason {
    /// 地址为 0：无内存可写。
    NullAddress,
    /// 每像素位数不是 32：绘制路径按 `*mut u32` 寻址像素。
    BppNot32,
    /// 宽或高为 0：空面无法承载字符网格。
    ZeroGeometry,
    /// 行距不足以容纳一行像素（`pitch < width * 4`）：相邻行会互相覆盖。
    PitchTooShort,
    /// 行距不是 4 的倍数：u32 步进寻址会跨行错位。
    PitchUnaligned,
    /// 几何字段大到乘法溢出或超出 usize 承载力：拒绝猜测而非绕过检查。
    GeometryOverflow,
    /// 内存模型不是 packed RGB：mask 描述对非 packed 模型无意义。
    MemoryModelNotRgb,
    /// 三通道位宽不一致（vendor 要求等宽通道）。
    MaskChannelMismatch,
    /// 通道位宽越界：<8 时颜色退化，>16 时 vendor 颜色换算发生减法下溢。
    MaskSizeOutOfRange,
    /// 通道布局越界（shift + size > 32）：颜色位移超出像素宽度。
    MaskShiftOutOfRange,
}

/// 校验 framebuffer 参数是否满足「按 u32 线性像素面绘制」的全部前提。
///
/// 检查顺序按依赖排列：地址/位深/几何（寻址前提）→ 行距（行间不重叠）→
/// 内存模型与 mask（颜色语义）→ mask 布局边界。任何一条不满足都给出具名
/// 拒绝（term1 T3），调用方据此降级为纯串口并留下结构化日志。
fn reject_reason(info: &FbInfo) -> Option<RejectReason> {
    /// 本 crate 绘制路径的像素粒度（vendor 以 `*mut u32` 寻址像素）。
    const PIXEL_BYTES: u64 = 4;
    /// vendor 绘制路径要求的每像素位数（`*mut u32` ⇒ 32bpp）。
    const REQUIRED_BPP: u16 = 32;

    if info.addr == 0 {
        return Some(RejectReason::NullAddress);
    }
    if info.bpp != REQUIRED_BPP {
        return Some(RejectReason::BppNot32);
    }
    if info.width == 0 || info.height == 0 {
        return Some(RejectReason::ZeroGeometry);
    }
    // S04/S19：usize 承载力守卫——窄指针平台上 u64 几何可能超出 usize，
    // 截断会静默改变语义，必须具名拒绝（64 位平台此检查恒通过）。
    if usize::try_from(info.width).is_err()
        || usize::try_from(info.height).is_err()
        || usize::try_from(info.pitch).is_err()
    {
        return Some(RejectReason::GeometryOverflow);
    }
    // S19：几何字段来自引导协议，不做可信假设——width*4 用 checked 乘法，
    // 溢出给具名拒绝而非绕过比较或 panic。
    let row_bytes = match info.width.checked_mul(PIXEL_BYTES) {
        Some(v) => v,
        None => return Some(RejectReason::GeometryOverflow),
    };
    if info.pitch < row_bytes {
        return Some(RejectReason::PitchTooShort);
    }
    if info.pitch % PIXEL_BYTES != 0 {
        return Some(RejectReason::PitchUnaligned);
    }
    if info.memory_model != LIMINE_MEMORY_MODEL_RGB {
        return Some(RejectReason::MemoryModelNotRgb);
    }
    // 逐通道位宽界限先于等宽校验：给出最精确的拒绝原因。
    for (size, shift) in [
        (info.red_mask_size, info.red_mask_shift),
        (info.green_mask_size, info.green_mask_shift),
        (info.blue_mask_size, info.blue_mask_shift),
    ] {
        // 下限 8：vendor flanterm_fb_init 拒绝 size<8；上限 16：vendor
        // convert_colour_fb 在 size>16 时计算 `16 - size` 发生减法下溢。
        if size < 8 || size > 16 {
            return Some(RejectReason::MaskSizeOutOfRange);
        }
        // 布局界限：通道必须完整落在 u32 像素内（shift+size ≤ 32），
        // 否则颜色位移越出像素宽度产生静默花屏。以 u32 承载和值避免
        // u8 加法回绕（S19）。
        if (shift as u32) + (size as u32) > u32::BITS {
            return Some(RejectReason::MaskShiftOutOfRange);
        }
    }
    if info.red_mask_size != info.green_mask_size || info.red_mask_size != info.blue_mask_size {
        return Some(RejectReason::MaskChannelMismatch);
    }
    None
}

/// 初始化 framebuffer 终端。
///
/// 参数不合格时返回 [`Error::InvalidParam`] 并经 `error!` 记录具体拒绝原因
/// （ADR-010：错误码可程序化处理，动态上下文走日志）；调用方据此诚实降级
/// 为纯串口且**不得**注册本终端 sink（死 sink 即伪装全功能）。
pub fn init(fb_info: &FbInfo) -> Result<(), Error> {
    // T3：unsafe 前提逐条具名校验，先于任何指针使用。
    if let Some(reason) = reject_reason(fb_info) {
        error!(
            "[terminal] ERROR: framebuffer rejected ({reason:?}): addr={:#x} {}x{} pitch={} bpp={} model={}",
            fb_info.addr, fb_info.width, fb_info.height, fb_info.pitch, fb_info.bpp, fb_info.memory_model
        );
        return Err(Error::InvalidParam);
    }
    info!(
        "[terminal] init fb={:#x} {}x{} pitch={} bpp={}",
        fb_info.addr, fb_info.width, fb_info.height, fb_info.pitch, fb_info.bpp
    );
    // SAFETY：以上校验保证 addr 非零、bpp=32、pitch 对齐且容得下全部像素行；
    // 地址由 bootloader 完成页映射且生命周期覆盖整个内核运行期。
    let ctx = unsafe {
        flanterm_rust::flanterm_fb_init(
            fb_info.addr as *mut u32,
            fb_info.width as usize,
            fb_info.height as usize,
            fb_info.pitch as usize,
            fb_info.red_mask_size,
            fb_info.red_mask_shift,
            fb_info.green_mask_size,
            fb_info.green_mask_shift,
            fb_info.blue_mask_size,
            fb_info.blue_mask_shift,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            0,
            0,
            0,
            1,
            1,
            0,
            flanterm_rust::FLANTERM_FB_ROTATE_0,
        )
    };
    match ctx {
        Some(ctx) => {
            let ctx: &'static mut FlantermContext = Box::leak(ctx);
            TERMINAL_PTR.store(ctx as *mut FlantermContext as usize, Ordering::Release);
            info!("[terminal] flanterm_fb_init done");
            Ok(())
        }
        None => {
            error!("[terminal] ERROR: flanterm_fb_init returned None");
            Err(Error::InvalidParam)
        }
    }
}

/// 向 framebuffer 终端写文本（`\n` 自动转 `\r\n`）。未初始化则计数丢弃。
pub fn write_str(s: &str) {
    let p = TERMINAL_PTR.load(Ordering::Acquire);
    if p == 0 {
        // T14：未就绪期间的丢弃必须留痕——非零计数即存在「只到串口、
        // 未上屏」的输出窗口（典型：init 之前的早期 panic 屏幕输出）。
        DROPPED_WRITE_CALLS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    // 锁内只做终端状态机操作与绘制；告警统一在锁外发（锁序纪律见 TERM_LOCK）。
    let null_seen = {
        let _guard = TERM_LOCK.lock();
        let ctx = unsafe { &mut *(p as *mut FlantermContext) };
        write_split(s.as_bytes(), |seg| flanterm_rust::flanterm_write(ctx, seg));
        flanterm_rust::fb_null_seen()
    };
    if null_seen && !NULL_FB_WARNED.swap(true, Ordering::Relaxed) {
        // T2 整改后唯一保留的异常路径观测：绘制被 vendor 的 null 守卫跳过
        // 时如实告警一次——不修补、不伪装，输出缺失持续可见（degradation.md D11）。
        klib::warn!(
            "[terminal] framebuffer draws skipped: pointer NULL during draw; \
             screen output lost until reboot (heap corruption suspected)"
        );
    }
}

/// 一次性告警闩：绘制时发现 framebuffer 指针为 NULL（T12/T14 观测口）。
static NULL_FB_WARNED: AtomicBool = AtomicBool::new(false);

/// 跨调用 ONLCR 流式状态：上一段输出以孤立 `\r` 结尾且尚未落笔时置位。
///
/// audit-r4 F1：`\r` 的去留由其后继字节决定——紧随 `\n` 则合并为单次
/// CRLF，否则原样落笔。该判定天然要求一字节前瞻，跨调用分片（如逐字节
/// 写路径）必须把未决 CR 带入下一段。仅在 [`TERM_LOCK`] 内读写；
/// Relaxed 原子性仅为满足静态 `Sync`，互斥由锁保证。
static PENDING_CR: AtomicBool = AtomicBool::new(false);

/// 把字节流按行切分并应用 ONLCR 式换行翻译，逐段回调 `emit` 直写终端。
///
/// 翻译规则（term1 T6 契约 + audit-r4 F1 流式化修订，与 POSIX ONLCR
/// 同义且**跨调用保持状态**）：
/// - 输入 `\n` 输出 `\r\n`；
/// - 输入 `\r` 的呈现由其后继字节决定：紧随 `\n`（无论同调用还是下一
///   调用）只产出一次 `\r\n`；后继非 `\n` 则原样落笔；
/// - 调用末尾的悬挂 `\r` 保持未决至下一调用的首字节或 [`drain_pending_cr`]，
///   孤立 CR 至多延迟呈现、不丢失；
/// - 空 chunk 不产生任何输出（连续换行、结尾换行均安全）。
///
/// 安全性：多字节 UTF-8 序列的续字节恒 ≥ 0x80，`0x0A`/`0x0D` 不可能出现
/// 在字符内部，按字节处理不会撕裂字符。
fn write_split<F: FnMut(&[u8])>(bytes: &[u8], mut emit: F) {
    let mut pending = PENDING_CR.load(Ordering::Relaxed);
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        if pending {
            // 解析上一段遗留的悬挂 CR：紧随 LF 合并为单次 CRLF，否则补发。
            pending = false;
            if bytes[i] == b'\n' {
                emit(b"\r\n");
                start = i + 1;
                i += 1;
                continue;
            }
            emit(b"\r");
        }
        match bytes[i] {
            b'\r' => {
                if i > start {
                    emit(&bytes[start..i]);
                }
                pending = true;
                start = i + 1;
            }
            b'\n' => {
                if i > start {
                    emit(&bytes[start..i]);
                }
                emit(b"\r\n");
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if i > start {
        emit(&bytes[start..i]);
    }
    PENDING_CR.store(pending, Ordering::Relaxed);
}

/// 强制落笔悬挂中的孤立 CR（[`Console::flush`](klib::console::Console::flush)
/// 的底层动作；须在 [`TERM_LOCK`] 内调用）。
fn drain_pending_cr<F: FnMut(&[u8])>(mut emit: F) {
    if PENDING_CR.swap(false, Ordering::Relaxed) {
        emit(b"\r");
    }
}

/// framebuffer 终端控制台：`klib::console::Console` 的实现
pub struct TerminalConsole;

/// 全局终端控制台实例（供 `klib::console::register_console` 注册）。
pub static TERMINAL_CONSOLE: TerminalConsole = TerminalConsole;

impl klib::console::Console for TerminalConsole {
    fn name(&self) -> &'static str {
        "framebuffer"
    }
    fn write_str(&self, s: &str) {
        write_str(s);
    }
    // write_byte 不覆写：trait 默认实现即「单字节自足文本」语义，
    // 契约成文见 klib::console::Console::write_byte（term1 T5 去重）。
    fn flush(&self) {
        // audit-r4 F1：强制落笔跨调用悬挂的孤立 CR（锁内禁日志，见 TERM_LOCK）。
        let p = TERMINAL_PTR.load(Ordering::Acquire);
        if p == 0 {
            return;
        }
        let _guard = TERM_LOCK.lock();
        let ctx = unsafe { &mut *(p as *mut FlantermContext) };
        drain_pending_cr(|seg| flanterm_rust::flanterm_write(ctx, seg));
    }
}

// ---------- 单元测试（host；term1 T10：纯逻辑回归锁定） ----------

#[cfg(test)]
mod tests {
    use super::*;

    /// 触及 [`PENDING_CR`] 进程级状态的用例必须经此串行化：Rust 测试
    /// 默认多线程并行，全局悬挂状态在交错执行下互相污染——结构性竞争
    /// （audit-r4 F2；同库先例 klib/log.rs TEST_LOCK）。
    /// 纪律：持锁期间不得再调任何会取同一把锁的助手。
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// 把多段喂入的完整输出流拼回来（末尾强制落笔悬挂 CR）——同时锁定
    /// chunk 内容、CRLF 插入位置与跨调用状态三个维度，是流式 ONLCR 的
    /// 直接 oracle。用例间重置 PENDING_CR 保证互不污染。
    fn rendered(segments: &[&[u8]]) -> std::vec::Vec<u8> {
        PENDING_CR.store(false, Ordering::Relaxed);
        let mut out = std::vec::Vec::new();
        for seg in segments {
            write_split(seg, |s| out.extend_from_slice(s));
        }
        drain_pending_cr(|s| out.extend_from_slice(s));
        out
    }

    #[test]
    fn split_plain_text_passes_through_without_newline() {
        let _g = TEST_LOCK.lock().unwrap();
        assert_eq!(rendered(&[b"abc"]), b"abc");
        assert_eq!(rendered(&[b""]), b"");
    }

    #[test]
    fn split_lone_lf_becomes_crlf() {
        let _g = TEST_LOCK.lock().unwrap();
        assert_eq!(rendered(&[b"a\nb"]), b"a\r\nb");
        assert_eq!(rendered(&[b"\na"]), b"\r\na");
        assert_eq!(rendered(&[b"a\n"]), b"a\r\n");
    }

    #[test]
    fn split_consecutive_lf_emit_bare_crlf_pairs() {
        let _g = TEST_LOCK.lock().unwrap();
        assert_eq!(rendered(&[b"\n\n"]), b"\r\n\r\n");
        assert_eq!(rendered(&[b"a\n\nb"]), b"a\r\n\r\nb");
    }

    #[test]
    fn split_crlf_emits_single_crlf_no_double_cr() {
        let _g = TEST_LOCK.lock().unwrap();
        // T6 病灶锁定：旧实现对 "\r\n" 产出 "\r\r\n"（CR 叠加）。
        assert_eq!(rendered(&[b"a\r\nb"]), b"a\r\nb");
        assert_eq!(rendered(&[b"x\r\n"]), b"x\r\n");
        assert_eq!(rendered(&[b"\r\n"]), b"\r\n");
    }

    #[test]
    fn split_lone_cr_is_preserved_verbatim() {
        let _g = TEST_LOCK.lock().unwrap();
        // 含末尾 drain：孤立 CR 至多延迟到 drain，总输出不变。
        assert_eq!(rendered(&[b"a\rb"]), b"a\rb");
        assert_eq!(rendered(&[b"\r"]), b"\r");
        assert_eq!(rendered(&[b"a\r\rb"]), b"a\r\rb");
    }

    #[test]
    fn streamed_crlf_across_calls_yields_single_crlf() {
        let _g = TEST_LOCK.lock().unwrap();
        // audit-r4 F1 病灶锁定：CR 与 LF 分片到达时，旧无状态实现产出
        // "a\r" + "\r\n" + "b" = a\r\r\n（T6 声称修掉的病灶形态）。
        assert_eq!(rendered(&[b"a\r", b"\nb"]), b"a\r\nb");
        assert_eq!(rendered(&[b"x\r", b"\n"]), b"x\r\n");
        assert_eq!(rendered(&[b"\r", b"\n"]), b"\r\n");
    }

    #[test]
    fn streamed_pending_cr_resolved_by_nonlf_continuation() {
        let _g = TEST_LOCK.lock().unwrap();
        // 悬挂 CR 遇非 LF 后继：原样落笔，后续内容不受影响；空段保持悬挂。
        assert_eq!(rendered(&[b"x\r", b"y"]), b"x\ry");
        assert_eq!(rendered(&[b"x\r", b""]), b"x\r");
        assert_eq!(rendered(&[b"x\r", b"", b"\nq"]), b"x\r\nq");
    }

    #[test]
    fn streamed_mixed_fragments_match_stream_semantics() {
        let _g = TEST_LOCK.lock().unwrap();
        // 切分无关性：同一字节流无论怎么切，最终输出恒等。
        let whole = rendered(&[b"foo\r\nbar\r\rbaz\nqux\r"]);
        // 末尾孤立 CR 经 drain 原样收尾：foo␍␊bar␍␍baz␍␊qux␍
        assert_eq!(whole, b"foo\r\nbar\r\rbaz\r\nqux\r");
        assert_eq!(rendered(&[b"foo\r", b"\nbar\r", b"\rbaz\nqux\r"]), whole);
        assert_eq!(
            rendered(&[b"f", b"o", b"o", b"\r", b"\n", b"b", b"a", b"r"]),
            b"foo\r\nbar"
        );
    }

    #[test]
    fn pending_cr_is_held_until_drained() {
        let _g = TEST_LOCK.lock().unwrap();
        // 悬挂语义的直接证明：不含 drain 的裸输出在段尾保持未决，
        // drain 原样释放且幂等。
        PENDING_CR.store(false, Ordering::Relaxed);
        let mut out = std::vec::Vec::new();
        write_split(b"x\r", |s| out.extend_from_slice(s));
        assert_eq!(out, b"x", "trailing lone CR must be held, not emitted");
        drain_pending_cr(|s| out.extend_from_slice(s));
        assert_eq!(out, b"x\r", "drain must release the held CR verbatim");
        let mut again = std::vec::Vec::new();
        drain_pending_cr(|s| again.extend_from_slice(s));
        assert!(again.is_empty(), "drain is idempotent once resolved");
    }

    /// 构造一份可通过全部校验的基准参数（QEMU/Bochs 常见 1024x768x32 BGRX）。
    fn fb_ok() -> FbInfo {
        FbInfo {
            addr: 0xffff_8000_0000_0000,
            width: 1024,
            height: 768,
            pitch: 4096,
            bpp: 32,
            memory_model: LIMINE_MEMORY_MODEL_RGB,
            red_mask_size: 8,
            red_mask_shift: 16,
            green_mask_size: 8,
            green_mask_shift: 8,
            blue_mask_size: 8,
            blue_mask_shift: 0,
        }
    }

    #[test]
    fn validate_accepts_well_formed_framebuffer() {
        assert_eq!(reject_reason(&fb_ok()), None);
    }

    #[test]
    fn validate_rejects_each_bad_parameter_by_name() {
        // (字段篡改, 预期拒绝原因) 表：每个 unsafe 前提对应一条具名拒绝。
        let cases: [(fn(&mut FbInfo), RejectReason); 10] = [
            (|f: &mut FbInfo| f.addr = 0, RejectReason::NullAddress),
            (|f: &mut FbInfo| f.bpp = 24, RejectReason::BppNot32),
            (|f: &mut FbInfo| f.width = 0, RejectReason::ZeroGeometry),
            (|f: &mut FbInfo| f.height = 0, RejectReason::ZeroGeometry),
            (|f: &mut FbInfo| f.pitch = 4095, RejectReason::PitchTooShort),
            (|f: &mut FbInfo| f.pitch = 4097, RejectReason::PitchUnaligned),
            (
                |f: &mut FbInfo| f.memory_model = 2,
                RejectReason::MemoryModelNotRgb,
            ),
            (
                // 4 < 8：逐通道位宽界限先于等宽校验触发。
                |f: &mut FbInfo| f.blue_mask_size = 4,
                RejectReason::MaskSizeOutOfRange,
            ),
            (
                // 9 在合法位宽区间内，但与红/绿的 8 不等宽。
                |f: &mut FbInfo| f.green_mask_size = 9,
                RejectReason::MaskChannelMismatch,
            ),
            (
                |f: &mut FbInfo| f.red_mask_shift = 30,
                RejectReason::MaskShiftOutOfRange,
            ),
        ];
        for (i, (mutate, want)) in cases.into_iter().enumerate() {
            let mut f = fb_ok();
            mutate(&mut f);
            assert_eq!(
                reject_reason(&f),
                Some(want),
                "case #{i} must reject with {want:?}"
            );
        }
    }

    #[test]
    fn validate_rejects_overflowing_geometry_without_panicking() {
        // S19：u64 极值下 width*4 溢出必须走 checked 路径给出具名拒绝，
        // 而不是 debug panic 或 release 静默绕过。
        let mut f = fb_ok();
        f.width = u64::MAX;
        f.height = 1;
        f.pitch = u64::MAX;
        assert_eq!(reject_reason(&f), Some(RejectReason::GeometryOverflow));
    }

    #[test]
    fn validate_rejects_oversized_mask_width_avoiding_vendor_underflow() {
        // vendor convert_colour 在 size > 16 时计算 16-size 下溢：
        // 校验层必须先行拦截（宁可报错，不放行已知病态参数）。
        let mut f = fb_ok();
        f.red_mask_size = 20;
        f.green_mask_size = 20;
        f.blue_mask_size = 20;
        assert_eq!(reject_reason(&f), Some(RejectReason::MaskSizeOutOfRange));
    }

    #[test]
    fn uninit_write_is_counted_not_silent() {
        // T14：host 测试进程从不调用 init 成功路径（TERMINAL_PTR 恒为 0），
        // 此路径的每次丢弃都必须留下计数痕迹。
        let before = dropped_write_calls();
        write_str("should be counted as dropped");
        assert!(
            dropped_write_calls() > before,
            "dropped-write counter must advance when terminal is not ready"
        );
    }

    #[test]
    fn init_rejects_invalid_fb_before_touching_hardware() {
        // T3 接线锁定：参数不合格时 init 在进入 unsafe 前即以类型化错误
        // 返回（ADR-010 InvalidParam），绝不触碰显存。
        let mut f = fb_ok();
        f.bpp = 24;
        assert_eq!(init(&f), Err(Error::InvalidParam));
    }
}
