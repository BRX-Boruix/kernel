//! 内核同步原语库（零外部依赖，手写实现）。
//!
//! 组成：
//! - [`spin::SpinMutex`]：纯自旋互斥锁（地基）；
//! - [`irq::IrqSpinLock`]：中断安全锁（关中断 + 保存/恢复 FLAGS），
//!   FLAGS 保存/恢复由架构层经 [`irq::set_irq_guard`] 注入；
//! - [`rwlock::RwLock`]：读写锁（写者优先）；
//! - [`semaphore::Semaphore`]：计数信号量（自旋忙等版）；
//! - [`barrier::Barrier`]：屏障（多轮复用）；
//! - [`mpmc::MpmcQueue`]：无锁有界 MPMC 环形队列（覆盖 SPSC/MPSC）。
//!
//! 设计原则：
//! - `klib` 不依赖 `arch`/`mm`/任何第三方 crate，同步原语全部自包含；
//! - 平台相关能力（中断开关、FLAGS 保存）通过函数指针运行时注入，
//!   未注入时退化为纯自旋语义（单 CPU / 测试环境安全）；
//! - 所有锁均为忙等（当前无调度器）。接入调度器后，等待路径可替换为
//!   "挂起线程"而不改调用点。

pub mod barrier;
pub mod irq;
pub mod mpmc;
pub mod rwlock;
pub mod semaphore;
pub mod spin;
