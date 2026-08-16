//! 内核数据结构库（零依赖、通用地基）。
//!
//! 组成：
//! - [`ring::RingBuffer`]：无锁 SPSC 环形缓冲区（串口 RX / 键盘输入缓冲复用）；
//! - [`bitmap::Bitmap`]：固定容量位图（帧 / 资源管理复用）；
//! - [`intrusive::IntrusiveList`]：侵入式双向链表（调度器就绪队列 / 定时器轮盘地基）。
//!
//! 设计原则：
//! - 全部 `no_std`、零外部依赖，与 `sync` 模块一样自成一体；
//! - 位图、侵入式链表为单线程访问版（共享时外部加锁），环形缓冲为无锁 SPSC；
//! - 全部支持 `const` 构造，可直接放入 `static`。

pub mod bitmap;
pub mod intrusive;
pub mod ring;
