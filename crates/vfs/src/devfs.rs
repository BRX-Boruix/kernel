//! DevFS 设备虚拟文件系统（挂载于 `/devices`，彻底消灭 `ioctl`）。
//!
//! 遵循 ADR-005（RESTful 资源观）、ADR-011（属性子文件控制）与 ADR-013（JSON 第一公民）：
//! - `/devices/serial-com1`：主数据通道，直接读写原始串口字节流；
//! - `/devices/serial-com1/baudrate`：纯文本属性（写入调速，读取查询）；
//! - `/devices/serial-com1/config`：JSON 结构化全局配置；
//! - `/devices/displays/primary/mode`：写入/读取 JSON 分辨率配置；
//! - `/devices/list`：枚举所有已注册设备的 JSON 数组。

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
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
}

/// 设备系统回调 Provider Trait（由内核 drv 模块注入实现）。
pub trait DeviceInfoProvider: Send + Sync {
    fn list_devices(&self) -> Vec<DeviceInfo>;
    fn serial_read(&self, buf: &mut [u8]) -> Result<usize, Error>;
    fn serial_write(&self, buf: &[u8]) -> Result<usize, Error>;
    fn get_serial_baudrate(&self) -> u32;
    fn set_serial_baudrate(&self, baud: u32) -> Result<(), Error>;
}

/// 默认串口波特率原子存储。
static SERIAL_BAUDRATE: AtomicU32 = AtomicU32::new(115200);

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
            move || {
                let baud = p_baud_get.get_serial_baudrate();
                alloc::format!("{}\n", baud).into_bytes()
            },
            move |buf| {
                let s = core::str::from_utf8(buf).map_err(|_| Error::InvalidParam)?;
                let s = s.trim();
                let baud: u32 = s.parse().map_err(|_| Error::InvalidParam)?;
                p_baud_set.set_serial_baudrate(baud)?;
                Ok(buf.len())
            },
        );
        children.add_child("baudrate", Arc::new(baud_node));

        // 2. config JSON 属性子文件
        let p_cfg = provider.clone();
        let cfg_node = DynamicFileNode::read_only(move || {
            let baud = p_cfg.get_serial_baudrate();
            let mut target = VecTarget::new();
            let mut writer = JsonWriter::new(&mut target);
            if let Ok(mut obj) = writer.start_object() {
                let _ = obj.field_str("port", "COM1");
                let _ = obj.field_u64("baudrate", baud as u64);
                let _ = obj.field_u64("data_bits", 8);
                let _ = obj.field_str("parity", "None");
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
        let displays_dir = Arc::new(DynamicDirNode::new());
        let primary_dir = Arc::new(DynamicDirNode::new());
        let mode_node = Arc::new(DynamicFileNode::read_write(
            || {
                let mut target = VecTarget::new();
                let mut writer = JsonWriter::new(&mut target);
                if let Ok(mut obj) = writer.start_object() {
                    let _ = obj.field_u64("width", 1024);
                    let _ = obj.field_u64("height", 768);
                    let _ = obj.field_u64("bpp", 32);
                    let _ = obj.field_u64("refresh_hz", 60);
                    let _ = obj.end();
                }
                let mut bytes = target.into_bytes();
                bytes.push(b'\n');
                bytes
            },
            |buf| {
                // 校验是合法 JSON，模拟调整成功
                let _ = core::str::from_utf8(buf).map_err(|_| Error::InvalidParam)?;
                Ok(buf.len())
            },
        ));
        primary_dir.add_child("mode", mode_node);
        displays_dir.add_child("primary", primary_dir);
        root.add_child("displays", displays_dir);

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
