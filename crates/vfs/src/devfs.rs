//! DevFS 设备虚拟文件系统（挂载于 `/devices`，彻底消灭 `ioctl`，M10.1 & M10.2 深度自省与全景遥测）。
//!
//! 遵循 ADR-005（RESTful 资源观）、ADR-011（属性子文件控制）与 ADR-013（JSON 第一公民）：
//! - `/devices/list`：枚举所有已注册设备的 JSON 数组；
//! - `/devices/serial-com1`：主数据通道，直接读写原始串口字节流；
//! - `/devices/serial-com1/baudrate`：纯文本属性（写入调速，读取查询）；
//! - `/devices/displays/primary/mode`：写入/读取 JSON 分辨率配置；
//! - `/devices/pci/{bus:dev.func}/bars`：PCI BAR 寄存器结构化配置空间自省（JSON）；
//! - `/devices/storage/{dev}/status`：块存储硬件健康与读写扇区遥测（JSON）；
//! - `/devices/net/{dev}/stats`：网络设备收发包与带宽遥测（JSON）；
//! - `/devices/telemetry`：全系统硬件运行态健康全景遥测聚合点（JSON）。

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use klib::error::Error;
use klib::json::{JsonObject, JsonWriter, VecTarget};

use crate::dynamic::{DynamicDirNode, DynamicFileNode};
use crate::inode::{DirEntry, FileMetadata, FileSystem, INode, INodeType, Permissions};

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
                    Err(err) => {
                        let _ = obj.field_null("baudrate");
                        let _ = obj.field_i64("error", -(err.to_errno() as i64));
                    }
                }
                let _ = obj.field_u64("data_bits", 8);
                let _ = obj.field_str("parity", "none");
                let _ = obj.field_u64("stop_bits", 1);
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
            permissions: Permissions::read_write(),
            created_time: 0,
            modified_time: 0,
            changed_time: 0,
        })
    }

    fn truncate(&self, _size: u64) -> Result<(), Error> {
        Ok(())
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn INode>, Error> {
        self.children.lookup(name)
    }

    fn create(&self, _name: &str, _permissions: Permissions) -> Result<Arc<dyn INode>, Error> {
        Err(Error::PermissionDenied)
    }

    fn mkdir(&self, _name: &str, _permissions: Permissions) -> Result<Arc<dyn INode>, Error> {
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

        // 5. /devices/pci (M10.1 PCI 深度自省目录)
        // C5.1/#5：按设备名参数化 BAR 查询。为每个已注册 PCI 设备创建
        // `{name}/bars` 子目录；查不到的设备返回错误 JSON，不回退到固定设备。
        let pci_dir = Arc::new(DynamicDirNode::new());
        for dev in provider.list_devices() {
            if dev.bus == "PCI" {
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
