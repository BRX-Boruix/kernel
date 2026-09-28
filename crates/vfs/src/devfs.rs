//! DevFS 设备虚拟文件系统（挂载于 `/devices`，彻底消灭 `ioctl`，M10.1 & M10.2 深度自省与全景遥测）。
//!
//! 遵循 ADR-005（RESTful 资源观）、ADR-011（属性子文件控制）与 ADR-013（JSON 第一公民）：
//! - `/devices/list`：枚举所有已注册设备的 JSON 数组；
//! - `/devices/random`：随机数字符设备（`read` 取随机字节流；ADR-014：无
//!   `SYS_RANDOM`，随机数统一走此路径），`/devices/random/status` 如实披露
//!   熵源与是否密码学安全（JSON）；
//! - `/devices/serial-com1`：主数据通道，直接读写原始串口字节流；
//! - `/devices/serial-com1/baudrate`：纯文本属性（写入调速，读取查询）；
//! - `/devices/displays/primary/mode`：读取 JSON 分辨率配置（真实几何）；
//! - `/devices/pci/{bus:dev.func}/bars`：PCI BAR 寄存器结构化配置空间自省（JSON）；
//! - `/devices/storage/{dev}/status`：块存储硬件健康与读写扇区遥测（JSON）；
//! - `/devices/net/{dev}/stats`：网络设备收发包与带宽遥测（JSON）；
//! - `/devices/telemetry`：全系统硬件运行态健康全景遥测聚合点（JSON）。
//!
//! ## 固定子树契约（vfs1 M7 / ADR-023 §6）
//!
//! 上述子树是**稳定查询接口命名空间**，不是设备存在性声明：节点恒在、
//! 内容恒真。对应硬件缺席时读取得到显式 error JSON（如
//! `{"error":"no_display_info"}`），写入按能力如实拒绝——用户态以内容
//! 判断设备可用性，而非以节点是否存在判断。这使 DevFS 树形成为可编程
//! 的稳定 ABI；未来热插拔投影在此命名空间内增删**具体设备实例**节点。

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use klib::error::Error;
use klib::json::{JsonWriter, VecTarget};

use crate::dynamic::{DynamicDirNode, DynamicFileNode};
use crate::inode::{AccessPolicy, DirEntry, FileMetadata, FileSystem, INode, INodeType};

/// 总线名"PCI"（S13：devfs 按总线名划分子树，字面量集中定义，避免散落漂移
/// 静默漏设备；与 driver crate 的 `BusType::Pci` 语义对应，此处是字符串投影）。
const BUS_PCI: &str = "PCI";

/// 设备概要信息。
#[derive(Clone, Debug)]
pub struct DeviceInfo {
    pub name: String,
    pub bus: String,
    pub class: String,
    pub bound_driver: Option<String>,
    /// 数据易失性披露（DMYGH C15.1）：true 表示数据断电/重启后不持久。
    /// `/devices/list` 必须把该字段原样暴露给用户态。
    pub volatile: bool,
}

/// 设备系统回调 Provider Trait（由内核 drv 模块注入实现，支持 M10 深度自省与遥测）。
pub trait DeviceInfoProvider: Send + Sync {
    fn list_devices(&self) -> Vec<DeviceInfo>;
    fn serial_read(&self, buf: &mut [u8]) -> Result<usize, Error>;
    fn serial_write(&self, buf: &[u8]) -> Result<usize, Error>;
    /// 返回 UART divisor latch 对应的实际速率；硬件回读失败必须返回错误。
    fn get_serial_baudrate(&self) -> Result<u32, Error>;
    fn set_serial_baudrate(&self, baud: u32) -> Result<(), Error>;
    /// `/devices/input/events`（I-EVENTS 阶段 1，ADR-047）：取走至多填满 `buf` 的
    /// 事件记录字节。返回实际字节数（16 的倍数，或 0 = 无事件）；**不半条切割**——
    /// 每次恰好取整条 16 字节记录（§2.5 原子入流的读侧对偶）。
    /// 默认实现返回 0：无事件源时节点如实表现为「恒空」，不伪造事件。
    fn input_event_read(&self, _buf: &mut [u8]) -> usize {
        0
    }

    // ----- 事件流多读者缝（I-EVENTS P1，§6.15；vfs 不直连 arch_x86_64，KM1 同纪律）-----
    //
    // 语义契约（真实内核经 `KernelDeviceProvider` 反射到 `arch_x86_64::keyboard`
    // 的 EVQ 环视图；FakeProvider 反射到仿真环——见 vfs::stream 模块文档）：
    //
    // * `stream_peek_event`：读游标 `cursor` 处的记录**但不消费**。可用判据：
    //   `cursor ∈ [读墙, 写指针)` 且环已就绪——越过读墙的槽位可能已被覆盖
    //   （交付覆盖中的槽位 = 伪造数据，S09）；越过写指针 = 尚未就绪。
    //   内存序与 `pop_event` 同纪律：先 Acquire 写指针，再读槽。
    // * `stream_advance_read(n)`：推进全局读指针至多 `n` 条（绝不越过写指针；
    //   CAS 防并发重推）。由 `vfs::stream` 的最慢读者下界单点驱动。
    // * `stream_push_event`：投递一条记录（测试/自检注流；走真实流控与唤醒
    //   路径）。生产投递路径是 IRQ1，从不经过这里。
    // * 两个索引读取器 + 容量：诊断/游标铸造/满判定用，只读不推进。
    //
    // 默认实现全为「不可用」：未接线的 Provider 如实表现为空流（宁缺毋假，
    // S09），与既有 `input_event_read` 默认实现同一纪律。
    /// 读 `cursor` 处记录但不消费；不可用返回 `false`（out 不被触碰）。
    fn stream_peek_event(&self, _cursor: u64, _out: &mut [u8]) -> bool {
        false
    }
    /// 推进全局读指针至多 `n` 条（不可越过写指针）。
    fn stream_advance_read(&self, _n: u64) {}
    /// 投递一条 16 字节记录（测试/自检注流；走真实流控与唤醒路径）。
    fn stream_push_event(&self, _rec: &[u8; 16]) -> bool {
        false
    }
    /// 全局读指针（回收墙下游）；环不存在时 `None`。
    fn stream_ring_read_index(&self) -> Option<u64> {
        None
    }
    /// 全局写指针（已投递记录总数）；环不存在时 `None`。
    fn stream_ring_write_index(&self) -> Option<u64> {
        None
    }
    /// 环容量（记录数）；环不存在时 `None`。
    fn stream_ring_capacity(&self) -> Option<u64> {
        None
    }
    /// `/devices/input/events/status` JSON：如实披露事件缓冲遥测
    /// （丢弃计数等）。默认实现显式 error（宁缺毋假，S09）。
    fn input_events_status_json(&self) -> String {
        alloc::string::String::from(r#"{"error":"no_input_event_source"}"#)
    }
    fn telemetry_json(&self) -> String {
        // vfs1 R2：无真实健康数据源时禁止断言 "healthy"——与 storage/net 默认
        // 实现同一诚实化策略，未覆写的 Provider 得到显式错误而非伪状态。
        alloc::string::String::from(r#"{"error":"no_telemetry_source"}"#)
    }
    fn pci_bars_json(&self, dev_name: &str) -> String {
        // DMYGH #16：无真实 BAR 数据源时必须显式报错，禁止编造端口/大小。
        alloc::format!(
            r#"{{"error":"no_pci_info","device":"{}"}}"#,
            dev_name
        )
    }
    /// 存储状态由 Provider 自行解析真实主块设备（含 #15 双身份），
    /// 无计数来源时输出显式错误，绝不返回健康假值或编造计数器。
    fn storage_status_json(&self) -> String {
        alloc::string::String::from(r#"{"error":"no_counter"}"#)
    }
    /// 网络统计在真实 NIC 数据路径落地前只允许显式 unsupported。
    fn net_stats_json(&self) -> String {
        alloc::string::String::from(r#"{"error":"no_net_stats"}"#)
    }
    /// 显示模式必须是真实 framebuffer 几何（来自注册的显示设备真值）；
    /// 无真实数据源时显式报错，禁止编造缺省分辨率（vfs1 R1 / kernel1 KM12）。
    ///
    /// 行尾契约（审计 #9）：**provider 返回裸内容、不带尾换行**；读取闭包
    /// 统一追加单个 `\n`。任何一侧自行追加即双换行——字节级测试锁定此契约。
    fn display_mode_json(&self) -> String {
        alloc::string::String::from(r#"{"error":"no_display_info"}"#)
    }

    /// `/devices/disks` 子树枚举：返回全部**块设备**的注册名（ADR-005/012 的
    /// `/devices/disks/{name}` 集合）。真实数据源 = DriverHub 中
    /// `DeviceKind::Block` 设备；无块设备时返回空（不伪造）。默认空，由
    /// 内核 provider 覆写。
    fn list_disk_names(&self) -> alloc::vec::Vec<alloc::string::String> {
        alloc::vec::Vec::new()
    }

    /// 单块设备真实信息 JSON（ADR-012 §4 `/devices/disks/{name}/info`）。
    /// 容量必须来自真实 `as_io().size()`，无真实数据源时显式报错，禁止编造。
    /// 默认返回显式 not_supported，由内核 provider 覆写。
    fn disk_info_json(&self, name: &str) -> String {
        alloc::format!(r#"{{"error":"no_disk_info","device":"{}"}}"#, name)
    }

    /// 单块设备真实 MBR 分区表 JSON（ADR-012 §4 `/devices/disks/{name}/partitions`）。
    /// 签名/解析失败或非块设备须显式报错，绝不编造分区。默认显式 not_supported，
    /// 由内核 provider 覆写。
    fn disk_partitions_json(&self, name: &str) -> String {
        alloc::format!(r#"{{"error":"no_disk_partitions","device":"{}"}}"#, name)
    }

    /// 单块设备真实 MBR 分区 id 枚举（ADR-012 §4 逐分区投影
    /// `/devices/disks/{name}/partitions/{part_id}`）。id 形如 `partition-1`、
    /// `partition-2`（1-based 真实 MBR 槽位序）。签名/解析失败或无分区返回空。
    /// 默认空，由内核 provider 覆写。
    fn list_disk_partition_ids(&self, name: &str) -> alloc::vec::Vec<alloc::string::String> {
        let _ = name;
        alloc::vec::Vec::new()
    }

    /// 单块设备单个真实分区信息 JSON（ADR-012 §4 逐分区投影
    /// `/devices/disks/{name}/partitions/{part_id}/info`）。输出真实
    /// `start_lba`/`sector_count`/`type`/`bootable`；id 不在分区表内或设备
    /// 不可读须显式报错，绝不编造。默认显式 not_supported，由内核 provider 覆写。
    fn disk_partition_info_json(&self, name: &str, part_id: &str) -> String {
        alloc::format!(
            r#"{{"error":"no_disk_partition","device":"{}","part":"{}"}}"#,
            name,
            part_id
        )
    }

    /// `/devices/random` 主节点：把 `buf` 填满随机字节（ADR-014：随机数统一走
    /// `STREAM_READ("/devices/random")`，无 `SYS_RANDOM`）。默认显式
    /// NotSupported，由内核 provider 覆写。
    fn random_bytes(&self, buf: &mut [u8]) -> Result<usize, Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        Err(Error::NotSupported)
    }

    /// `/devices/random/status` JSON：如实披露当前熵源（硬件熵 / 时钟垫底）与
    /// 是否密码学安全（S07/S09 宁缺毋假——绝不把确定性时钟垫底谎报为安全熵）。
    /// 默认显式 not_supported，由内核 provider 覆写。
    fn random_status_json(&self) -> String {
        alloc::string::String::from(r#"{"error":"no_random_source"}"#)
    }
}

/// 串口主数据流与属性子目录复合节点。
pub struct SerialDeviceNode {
    provider: Arc<dyn DeviceInfoProvider>,
    children: DynamicDirNode,
}

impl SerialDeviceNode {
    pub fn new(provider: Arc<dyn DeviceInfoProvider>) -> Self {
        let children = DynamicDirNode::new();

        // 1. baudrate 属性子文件
        let p_baud_get = provider.clone();
        let p_baud_set = provider.clone();
        let baud_node = DynamicFileNode::read_write(
            move || match p_baud_get.get_serial_baudrate() {
                Ok(baud) => alloc::format!("{}\n", baud).into_bytes(),
                Err(err) => alloc::format!("error:{}\n", err.to_errno()).into_bytes(),
            },
            move |buf| {
                let s = core::str::from_utf8(buf).map_err(|_| Error::InvalidParam)?;
                let baud: u32 = s.trim().parse().map_err(|_| Error::InvalidParam)?;
                // M9（ADR-023 §6）：UART divisor 0 硬件非法——解析层显式
                // 拒绝，绝不把"写了个 0"翻译成对硬件的未定义操作。
                if baud == 0 {
                    return Err(Error::InvalidParam);
                }
                p_baud_set.set_serial_baudrate(baud)?;
                Ok(buf.len())
            },
        );
        children.add_child("baudrate", Arc::new(baud_node));

        // 2. config JSON 子文件
        let p_cfg = provider.clone();
        let cfg_node = DynamicFileNode::read_only(move || {
            let baud = p_cfg.get_serial_baudrate();
            let mut target = VecTarget::new();
            let mut writer = JsonWriter::new(&mut target);
            if let Ok(mut obj) = writer.start_object() {
                let _ = obj.field_str("port", "COM1");
                match baud {
                    Ok(value) => {
                        let _ = obj.field_u64("baudrate", value as u64);
                    }
                    Err(_err) => {
                        // M11（ADR-023 §6）：JSON 域错误统一字符串码；
                        // 数值 errno 细节由 Provider 侧日志承担。
                        let _ = obj.field_null("baudrate");
                        let _ = obj.field_str("error", "no_serial_baudrate");
                    }
                }
                // S10/S07：data_bits/parity/stop_bits 此前硬编码为
                // `8/"none"/1`——伪装成真实设备配置（伪配置）。Provider
                // 接口不提供这些线设置的读取，故不得编造；与 telemetry_json
                // 同一诚实化策略，显式标 not_supported 而非伪值。
                let _ = obj.field_str("data_bits", "not_supported");
                let _ = obj.field_str("parity", "not_supported");
                let _ = obj.field_str("stop_bits", "not_supported");
                let _ = obj.end();
            }
            let mut bytes = target.into_bytes();
            bytes.push(b'\n');
            bytes
        });
        children.add_child("config", Arc::new(cfg_node));

        Self { provider, children }
    }
}

impl INode for SerialDeviceNode {
    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        self.provider.serial_read(buf)
    }

    fn write_at(&self, _offset: u64, buf: &[u8]) -> Result<usize, Error> {
        self.provider.serial_write(buf)
    }

    fn metadata(&self) -> Result<FileMetadata, Error> {
        Ok(FileMetadata {
            size: 0,
            node_type: INodeType::CharacterDevice,
            permissions: AccessPolicy::read_write(),
            created_time: 0,
            modified_time: 0,
            changed_time: 0,
        })
    }

    /// A5：字符设备判型零成本。
    fn node_type(&self) -> Result<INodeType, Error> {
        Ok(INodeType::CharacterDevice)
    }

    /// M17（ADR-023 §6）：串口是字符流，截断语义不存在——成功码会掩盖
    /// "什么都没发生"，如实 NotSupported。
    fn truncate(&self, _size: u64) -> Result<(), Error> {
        Err(Error::NotSupported)
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn INode>, Error> {
        self.children.lookup(name)
    }

    fn create(&self, _name: &str, _mode: u32, _owner: (u32, u32)) -> Result<Arc<dyn INode>, Error> {
        Err(Error::PermissionDenied)
    }

    fn mkdir(&self, _name: &str, _mode: u32, _owner: (u32, u32)) -> Result<Arc<dyn INode>, Error> {
        Err(Error::PermissionDenied)
    }

    fn unlink(&self, _name: &str) -> Result<(), Error> {
        Err(Error::PermissionDenied)
    }

    fn list_dir(&self) -> Result<Vec<DirEntry>, Error> {
        self.children.list_dir()
    }
}

/// 随机数设备节点（ADR-014：随机数统一走 `/devices/random`，无 `SYS_RANDOM`）。
///
/// 主节点是只读字符设备：`read` 每次返回新的随机字节（provider 从内核熵池
/// 填充）；`status` 子文件如实披露当前熵源与是否密码学安全（S07/S09 宁缺毋假）。
/// 写路径如实拒绝（用户态喂熵对当前系统是过度设计，且无真实入口）。
pub struct RandomDeviceNode {
    provider: Arc<dyn DeviceInfoProvider>,
    children: DynamicDirNode,
}

impl RandomDeviceNode {
    pub fn new(provider: Arc<dyn DeviceInfoProvider>) -> Self {
        let children = DynamicDirNode::new();
        let p_status = provider.clone();
        let status_node = DynamicFileNode::read_only(move || {
            let mut json = p_status.random_status_json().into_bytes();
            json.push(b'\n');
            json
        });
        children.add_child("status", Arc::new(status_node));
        Self { provider, children }
    }
}

impl INode for RandomDeviceNode {
    /// 忽略 offset（随机流无定位语义），每次读返回新随机字节。
    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.provider.random_bytes(buf)
    }

    /// 只读字符设备：写随机流没有语义，如实 NotSupported（M17 同串口）。
    fn write_at(&self, _offset: u64, _buf: &[u8]) -> Result<usize, Error> {
        Err(Error::NotSupported)
    }

    fn metadata(&self) -> Result<FileMetadata, Error> {
        Ok(FileMetadata {
            size: 0,
            node_type: INodeType::CharacterDevice,
            // 0555（read_exec）而非 0444：本节点是 `status` 子文件的**遍历父级**，
            // A2-3 要求每级父目录有 x 位——0444 使 `/devices/random/status` 的
            // resolve 在遍历检查处报 InvalidParam（实测 errno 22）。读内容语义
            // 由 read_at 保留；x 只放行「穿过本节点找子文件」。
            permissions: AccessPolicy::read_exec(),
            created_time: 0,
            modified_time: 0,
            changed_time: 0,
        })
    }

    fn node_type(&self) -> Result<INodeType, Error> {
        Ok(INodeType::CharacterDevice)
    }

    /// 字符流无截断语义（M17）。
    fn truncate(&self, _size: u64) -> Result<(), Error> {
        Err(Error::NotSupported)
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn INode>, Error> {
        self.children.lookup(name)
    }

    fn create(&self, _name: &str, _mode: u32, _owner: (u32, u32)) -> Result<Arc<dyn INode>, Error> {
        Err(Error::PermissionDenied)
    }

    fn mkdir(&self, _name: &str, _mode: u32, _owner: (u32, u32)) -> Result<Arc<dyn INode>, Error> {
        Err(Error::PermissionDenied)
    }

    fn unlink(&self, _name: &str) -> Result<(), Error> {
        Err(Error::PermissionDenied)
    }

    fn list_dir(&self) -> Result<Vec<DirEntry>, Error> {
        self.children.list_dir()
    }
}

/// 输入事件流节点（I-EVENTS 阶段 1，[ADR-047]；P1 起升级为**每读者流**）。
///
/// 主节点是**只读字符设备**：`read` 返回 16 字节定长事件记录流（ADR-047 §2.1
/// 布局；§2.5 记录流语义——读侧按整条取，不半条切割）。事件→字节的转换
/// （keymap/转义/折叠）**不在本节点**——那是用户态转换层的事（ADR-045 决策 3）。
/// 写路径如实拒绝：内核不接受「伪造事件」（S09）。
/// `status` 子文件如实披露缓冲遥测（丢弃计数等，S09 可观察）。
///
/// **P1 多读者（§6.15）**：有句柄读者（shell/evsrcdemo/未来的 consoled）经
/// `event_stream_reader()` 钩子铸造 [`crate::stream::EventReaderToken`]——
/// 游标即句柄的读位置，dup2 继承同一游标、关闭即收敛（见 `vfs::stream`）。
/// **无句柄读**（`read_at`）是 **backlog 一次性读者**：从全局读墙向前消费、
/// 不注册、不占等待者（`cat`/自检「一口吃掉历史」），且绝不越过最慢有句柄
/// 读者（偷读即违约）。两种读者共用同一环，互不偷记录。
pub struct InputEventsNode {
    provider: Arc<dyn DeviceInfoProvider>,
    children: DynamicDirNode,
}

impl InputEventsNode {
    pub fn new(provider: Arc<dyn DeviceInfoProvider>) -> Self {
        let children = DynamicDirNode::new();
        let p_status = provider.clone();
        let status_node = DynamicFileNode::read_only(move || {
            let mut json = p_status.input_events_status_json().into_bytes();
            json.push(b'\n');
            json
        });
        children.add_child("status", Arc::new(status_node));
        Self { provider, children }
    }
}

impl INode for InputEventsNode {
    /// 忽略 offset（事件流无定位语义——过去的事件不可重放，ADR-047 §2.5）。
    ///
    /// **P1 起：backlog 一次性读者**——经 [`crate::stream::stream_pop_next`]
    /// 从全局读墙逐条交付（把**此刻已投递且无读者认领**的记录一次读走）。
    /// 不注册读者、不参与最慢下界、不占事件等待者（`cat events.bin` 与自检
    /// 工具的形态）。返回 16 的倍数；空流返回 0（此后由阻塞分支接管等待语义）。
    /// 有句柄读者不走此路（它们读自己的游标）——见类型文档。
    ///
    /// **回退**：Provider 未接环视图（`stream_ring_write_index` 为 `None`，
    /// 如只实现了阶段 1 pop 缝的 Fake/旧实现）时退回 [`DeviceInfoProvider::
    /// input_event_read`] 单读者 pop——S17 保守侧，绝不因新缝缺失而假装空流。
    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        if buf.len() < 16 {
            // 装不下一整条：不是错误而是「读走 0 条」（消费者给对齐缓冲即可）。
            return Ok(0);
        }
        let stream_mode = self.provider.stream_ring_write_index().is_some();
        let mut total = 0usize;
        while total + 16 <= buf.len() {
            if stream_mode {
                let mut rec = [0u8; 16];
                if !crate::stream::stream_pop_next(&self.provider, &mut rec) {
                    break; // 源空，或有句柄读者把读墙钉在此刻之前
                }
                buf[total..total + 16].copy_from_slice(&rec);
            } else {
                let n = self.provider.input_event_read(&mut buf[total..total + 16]);
                if n == 0 {
                    break; // 源空（阶段 1 pop 缝）
                }
            }
            total += 16;
        }
        Ok(total)
    }

    /// 只读：事件由硬件产生，用户态写入伪造事件没有语义（S09）。
    fn write_at(&self, _offset: u64, _buf: &[u8]) -> Result<usize, Error> {
        Err(Error::NotSupported)
    }

    /// 本节点是键盘**事件记录流**（I-EVENTS 阶段 2 的节点真值）：空读
    /// 表示「此刻无键事件」而**非**「永久不可读」——等待源是 IRQ1 的 EVQ 环，
    /// 记录到达由 `push_event` → `task::wake_input_event` 唤醒。syscall 层的
    /// `read` 据此在空读时登记等待者并挂起，而不是退回用户态轮询
    /// （轮询会让事件消费者在忙等的调度环境里被饿死，实测缺陷）。
    fn input_event_stream(&self) -> bool {
        true
    }

    /// P1（§6.15）：本节点是每读者事件流——流后端就是本节点持有的
    /// Provider 克隆（真实内核 = 反射到 EVQ 的 KernelDeviceProvider）。
    fn event_stream_reader(
        &self,
    ) -> Option<alloc::sync::Arc<dyn DeviceInfoProvider>> {
        Some(self.provider.clone())
    }

    fn metadata(&self) -> Result<FileMetadata, Error> {
        Ok(FileMetadata {
            size: 0,
            node_type: INodeType::CharacterDevice,
            // 0555（read_exec）而非 0444：本节点是 `status` 子文件的**遍历父级**，
            // A2-3 要求每级父目录有 x 位——0444 使 `/devices/input/events/status`
            // 的 resolve 在遍历检查处报 InvalidParam（实测 errno 22，与本文件
            // RandomDeviceNode 同病，一并修复）。
            permissions: AccessPolicy::read_exec(),
            created_time: 0,
            modified_time: 0,
            changed_time: 0,
        })
    }

    fn node_type(&self) -> Result<INodeType, Error> {
        Ok(INodeType::CharacterDevice)
    }

    /// 字符流无截断语义（M17）。
    fn truncate(&self, _size: u64) -> Result<(), Error> {
        Err(Error::NotSupported)
    }

    /// 可穿越性零成本覆写：与 `DspNode` 同型——**容器型字符设备**，
    /// `/devices/random/status` 必须可达。
    ///
    /// 它是本缺陷的第二个实例：`node_type()` 如实报 `CharacterDevice`，
    /// 同时又 `add_child("status")` 并覆写了 `lookup`/`list_dir`。
    /// 修 `dsp` 时一并修此处，避免同一形态的错误在别处复发（S41）。
    fn allows_traversal(&self) -> bool {
        true
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn INode>, Error> {
        self.children.lookup(name)
    }

    fn create(&self, _name: &str, _mode: u32, _owner: (u32, u32)) -> Result<Arc<dyn INode>, Error> {
        Err(Error::PermissionDenied)
    }

    fn mkdir(&self, _name: &str, _mode: u32, _owner: (u32, u32)) -> Result<Arc<dyn INode>, Error> {
        Err(Error::PermissionDenied)
    }

    fn unlink(&self, _name: &str) -> Result<(), Error> {
        Err(Error::PermissionDenied)
    }

    fn list_dir(&self) -> Result<Vec<DirEntry>, Error> {
        self.children.list_dir()
    }
}

/// DevFS 文件系统实现。
pub struct DevFS {
    root: Arc<DynamicDirNode>,
}

impl DevFS {
    pub fn new(provider: Arc<dyn DeviceInfoProvider>) -> Self {
        let root = Arc::new(DynamicDirNode::new());

        // 1. /devices/list (JSON)
        let p_list = provider.clone();
        let list_node = Arc::new(DynamicFileNode::read_only(move || {
            let devs = p_list.list_devices();
            let mut target = VecTarget::new();
            let mut writer = JsonWriter::new(&mut target);
            if let Ok(mut arr) = writer.start_array() {
                for d in devs {
                    let _ = arr.push_object(|obj| {
                        let _ = obj.field_str("name", &d.name);
                        let _ = obj.field_str("bus", &d.bus);
                        let _ = obj.field_str("class", &d.class);
                        if let Some(drv) = d.bound_driver {
                            let _ = obj.field_str("driver", &drv);
                        } else {
                            let _ = obj.field_null("driver");
                        }
                        let _ = obj.field_str("uri", &alloc::format!("/devices/{}", d.name));
                        // C15.1：逐设备易失性披露，禁止省略字段。
                        let _ = obj.field_bool("volatile", d.volatile);
                        Ok(())
                    });
                }
                let _ = arr.end();
            }
            let mut bytes = target.into_bytes();
            bytes.push(b'\n');
            bytes
        }));
        root.add_child("list", list_node);

        // 2. /devices/serial-com1
        let serial_node = Arc::new(SerialDeviceNode::new(provider.clone()));
        root.add_child("serial-com1", serial_node);

        // 3. /devices/displays/primary/mode
        // KM12/vfs1 R1：mode 内容整体透传 Provider 的真实几何——DevFS 层
        // 不再持有任何编造的 1024x768 缺省值。写路径如实拒绝：内核未实现
        // 模式切换，接受任意 JSON 并谎报成功是伪承诺。构造用 read_only——
        // 节点无写能力即只读节点（write_at 得 EACCES），名实相符（审计 B28；
        // 旧 read_write+恒拒闭包让权限位与真实能力相矛盾）。
        let displays_dir = Arc::new(DynamicDirNode::new());
        let primary_dir = Arc::new(DynamicDirNode::new());
        let p_mode = provider.clone();
        let mode_node = Arc::new(DynamicFileNode::read_only(move || {
            let mut json = p_mode.display_mode_json().into_bytes();
            json.push(b'\n');
            json
        }));
        primary_dir.add_child("mode", mode_node);
        displays_dir.add_child("primary", primary_dir);
        root.add_child("displays", displays_dir);

        // 4. /devices/telemetry (M10.2 全景遥测聚合点)
        let p_telemetry = provider.clone();
        let telemetry_node = Arc::new(DynamicFileNode::read_only(move || {
            let mut json = p_telemetry.telemetry_json().into_bytes();
            json.push(b'\n');
            json
        }));
        root.add_child("telemetry", telemetry_node);

        // 4.5 /devices/random (ADR-014 随机数设备：字符流 + status 诚实披露)
        let random_node = Arc::new(RandomDeviceNode::new(provider.clone()));
        root.add_child("random", random_node);

        // 4.55 /devices/input/events（I-EVENTS 阶段 1，ADR-047：字符流 + status 遥测）
        let input_dir = Arc::new(DynamicDirNode::new());
        let events_node = Arc::new(InputEventsNode::new(provider.clone()));
        input_dir.add_child("events", events_node);
        root.add_child("input", input_dir);

        // 4.55.5 /devices/console（I-EVENTS 阶段 3 P2，§6.15 甲-a：字节端）。
        // 读端 = 切换后的 fd 0（stdin 源），写端 = consoled（P3）喂入经
        // 用户态 keymap 转换的字节。SPSC 环单例；status 如实披露水位与
        // 丢弃计数。切换（P4）前无任何既有读者/写者，纯新增、零回归面。
        let console_node = Arc::new(crate::console::ConsoleNode::new());
        root.add_child("console", console_node.clone());

        // 4.55.6 /devices/consoles/N（ADR-048 决策 1，T1：实例族挂载）。
        // 实例 0 = 上面 console 节点**同一个 Arc**（别名，单会话行为零变化——
        // consoled/login/shell 的既有路径零改动）；实例 1..CONSOLES_N-1 为
        // 独立环的纯新增节点（T1 时无读者/写者；T2 接焦点路由、T4 接守护）。
        // N=4（ADR-048 §3.2：够用且可枚举）。audio/stream/0..N-1 同款先例。
        let consoles_dir = Arc::new(DynamicDirNode::new());
        // 别名 = **同一个 Arc**（不是复制节点）：`/devices/console` 与
        // `/devices/consoles/0` 打开的是同一环、同一 owner 真值（S13 单一事实源）。
        consoles_dir.add_child("0", console_node.clone());
        for i in 1..crate::console::CONSOLES_N {
            let name: alloc::string::String = alloc::format!("{}", i);
            consoles_dir.add_child(
                name.as_str(),
                Arc::new(crate::console::ConsoleNode::new_instance(i)),
            );
        }
        // B3-C1：把目录句柄交给 console 模块——运行期 create_instance 的
        // 挂载点（节点挂载 + 环登记同事务，S20）。启动期只此一次。
        // 先 attach 再 add_child（后者 move consoles_dir）。
        crate::console::attach_consoles_dir(consoles_dir.clone());
        root.add_child("consoles", consoles_dir);

        // 4.6 /devices/audio/dsp（plan_audio_vfs.md 批次一 A1）
        // 音频 PCM 哑管道：内核对音频零知识，只搬字节。写者与音频驱动
        // 通过本节点耦合，互不认识。无消费者附加时写入如实失败
        // （NotSupported），绝不接受后丢弃。
        let audio_dir = Arc::new(DynamicDirNode::new());
        let dsp_node = Arc::new(crate::audio::DspNode::new());
        audio_dir.add_child("dsp", dsp_node);
        // 4.6.1 /devices/audio/stream/0..N-1（批次四 M1）
        //
        // 混音器的**输入**端：每个 `stream/N` 是独立的 PCM ring，由生产者
        // （播放器/测试程序）写入，由用户态 `audiod` 读走后混音并写入 `dsp`。
        //
        // **为何走普通 VFS 而非 AUDIO syscall 域**：AUDIO 域表达的是"独占消费者
        // 流控"（attach/fetch/commit），而 `stream/N` 的写入者可以有多个、且不需要
        // attach——它就是输入缓冲。故这里只需 open/read/write，内核不加新 syscall。
        let streams_dir = Arc::new(DynamicDirNode::new());
        for i in 0..crate::audio::AUDIO_STREAM_COUNT {
            // 名字用 `alloc::format!` 生成（非硬编码字符串表）：路数是常量，
            // 增删只需改常量一处（S13/S15）。
            let name: alloc::string::String = alloc::format!("{}", i);
            streams_dir.add_child(name.as_str(), Arc::new(crate::audio::DspNode::stream()));
        }
        audio_dir.add_child("stream", streams_dir);
        root.add_child("audio", audio_dir);

        // 5. /devices/pci (M10.1 PCI 深度自省目录)
        // C5.1/#5：按设备名参数化 BAR 查询。为每个已注册 PCI 设备创建
        // `{name}/bars` 子目录；查不到的设备返回错误 JSON，不回退到固定设备。
        let pci_dir = Arc::new(DynamicDirNode::new());
        for dev in provider.list_devices() {
            if dev.bus == BUS_PCI {
                let p_pci = provider.clone();
                let dev_name = dev.name.clone();
                let dev_dir = Arc::new(DynamicDirNode::new());
                let bars_node = Arc::new(DynamicFileNode::read_only(move || {
                    let mut json = p_pci.pci_bars_json(&dev_name).into_bytes();
                    json.push(b'\n');
                    json
                }));
                dev_dir.add_child("bars", bars_node);
                pci_dir.add_child(&dev.name, dev_dir);
            }
        }
        // 兼容：保留 /devices/pci/bars 作为无设备名查询入口，返回 not_found 错误。
        let p_pci_err = provider.clone();
        let pci_bars_fallback = Arc::new(DynamicFileNode::read_only(move || {
            let mut json = p_pci_err.pci_bars_json("").into_bytes();
            json.push(b'\n');
            json
        }));
        pci_dir.add_child("bars", pci_bars_fallback);
        root.add_child("pci", pci_dir);

        // 6. /devices/storage/primary/status (M10.2 块存储遥测)
        let storage_dir = Arc::new(DynamicDirNode::new());
        let primary_storage_dir = Arc::new(DynamicDirNode::new());
        let p_storage = provider.clone();
        let storage_status_node = Arc::new(DynamicFileNode::read_only(move || {
            // DMYGH #16：设备名解析权在 Provider（经 DriverHub 反查真实主块设备），
            // DevFS 不再硬编码 "ata0"。
            let mut json = p_storage.storage_status_json().into_bytes();
            json.push(b'\n');
            json
        }));
        primary_storage_dir.add_child("status", storage_status_node);
        storage_dir.add_child("primary", primary_storage_dir);
        root.add_child("storage", storage_dir);

        // 7. /devices/net/primary/stats (M10.2 网络设备遥测)
        let net_dir = Arc::new(DynamicDirNode::new());
        let primary_net_dir = Arc::new(DynamicDirNode::new());
        let p_net = provider.clone();
        let net_stats_node = Arc::new(DynamicFileNode::read_only(move || {
            // DMYGH #16：不再硬编码 "eth0"；Provider 无真实 NIC 统计时输出显式错误。
            let mut json = p_net.net_stats_json().into_bytes();
            json.push(b'\n');
            json
        }));
        primary_net_dir.add_child("stats", net_stats_node);
        net_dir.add_child("primary", primary_net_dir);
        root.add_child("net", net_dir);

        // 8. /devices/disks/{name}/{info,partitions} (ADR-005/012 块设备子树)
        // 按 Provider 真实枚举的块设备建条目；每个磁盘目录暴露 info（真实容量、
        // 易失性、驱动绑定）与 partitions（真实 MBR 分区表）。命名沿用注册名
        //（与 /devices/{name} 投影一致），如实反映设备真值，不伪造硬件槽位名。
        let disks_dir = Arc::new(DynamicDirNode::new());
        for disk_name in provider.list_disk_names() {
            let p_info = provider.clone();
            let n_info = disk_name.clone();
            let info_node = Arc::new(DynamicFileNode::read_only(move || {
                let mut json = p_info.disk_info_json(&n_info).into_bytes();
                json.push(b'\n');
                json
            }));
            let p_parts = provider.clone();
            let n_parts = disk_name.clone();
            let parts_node = Arc::new(DynamicFileNode::read_only(move || {
                let mut json = p_parts.disk_partitions_json(&n_parts).into_bytes();
                json.push(b'\n');
                json
            }));
            let disk_dir = Arc::new(DynamicDirNode::new());
            disk_dir.add_child("info", info_node);

            // 逐分区投影（ADR-012 §4）：partitions/ 为目录，既保留原
            // `partitions` JSON 文件（数组真值），又为每个真实 MBR 分区建
            // `partition-{n}/info` 独立路径节点。无分区/解析失败则仅剩 JSON 文件。
            let partitions_dir = Arc::new(DynamicDirNode::new());
            partitions_dir.add_child("partitions", parts_node);
            for part_id in provider.list_disk_partition_ids(&disk_name) {
                let p_part = provider.clone();
                let n_disk = disk_name.clone();
                let n_part = part_id.clone();
                let part_info_node = Arc::new(DynamicFileNode::read_only(move || {
                    let mut json = p_part
                        .disk_partition_info_json(&n_disk, &n_part)
                        .into_bytes();
                    json.push(b'\n');
                    json
                }));
                let part_dir = Arc::new(DynamicDirNode::new());
                part_dir.add_child("info", part_info_node);
                partitions_dir.add_child(&part_id, part_dir);
            }
            disk_dir.add_child("partitions", partitions_dir);
            disks_dir.add_child(&disk_name, disk_dir);
        }
        root.add_child("disks", disks_dir);

        Self { root }
    }
}

impl FileSystem for DevFS {
    fn root(&self) -> Arc<dyn INode> {
        self.root.clone()
    }

    fn name(&self) -> &'static str {
        "devfs"
    }
}
