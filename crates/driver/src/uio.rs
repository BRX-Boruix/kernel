//! 用户态驱动沙箱（Userspace I/O & Driver Sandbox Subsystem，M11）。
//!
//! 提供用户态驱动注册、设备硬件认领（Claim）、异常隔离守护。
//!
//! ## 授权模型（KA4 定案）
//!
//! - **注册即唯一认领声明**：`uio_register_driver` 以 (pid, 设备名) 建立
//!   归属记录并返回 `uio_id`；同一设备的活跃认领全局唯一（重复注册返回
//!   `AlreadyExists`）——"任意进程可认领任意设备"的重复占位面被结构性关闭。
//!   注册不再接受任何 MMIO 坐标参数：设备物理资源属内核登记事实，不是
//!   用户可以自报的字段（旧签名 `(pid,name,0,0)` 的魔数占位已废除）。
//! - **claim 先验归属**：`uio_claim_device` 以 `uio_id` 精确定位记录并校验
//!   `entry.pid == caller_pid`——不存在的 id 报 `NotFound`，他人 id 报
//!   `PermissionDenied`。名字字符串只用于全局设备身份，从不用于归属判定。
//! - **隔离**：进程退出时其全部认领自动失效（`uio_on_process_exit`）。
//! - **映射半程已闭环**（K2 完全体）：授权通过的 claim 由 syscall 层接续
//!   `uio_device_window_of` 取登记窗口 → mm `UserAddressSpace::map_mmio_user`
//!   真实映射（PCD 不可缓存）→ 返回用户 VA。无登记窗口的设备如实返回
//!   `NotSupported`，绝不以匿名内存伪装映射成功。

use crate::hub::DriverHub;
use klib::error::Error;
use klib::info;
use klib::warn;
use spin::Mutex;

pub const MAX_UIO_DRIVERS: usize = 16;

/// 设备名字段容量（含结尾 NUL 余量；超长名字在注册入口被拒）。
pub const UIO_DEV_NAME_MAX: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UioDriverEntry {
    /// 认领者进程 id（归属判定的唯一依据，KA4）。
    pub pid: usize,
    pub claimed_device: [u8; UIO_DEV_NAME_MAX],
    pub claimed_len: usize,
    pub is_alive: bool,
}

impl UioDriverEntry {
    pub const EMPTY: Self = Self {
        pid: 0,
        claimed_device: [0u8; UIO_DEV_NAME_MAX],
        claimed_len: 0,
        is_alive: false,
    };
}

static UIO_DRIVERS: Mutex<[UioDriverEntry; MAX_UIO_DRIVERS]> =
    Mutex::new([UioDriverEntry::EMPTY; MAX_UIO_DRIVERS]);

/// 设备 MMIO 窗口登记表（K2：设备物理资源是**内核登记事实**）。
///
/// PCI 枚举时从 BAR 配置空间解析出真实物理窗口并按注册名发布；UIO claim
/// 只允许映射这里登记过的窗口——用户自报的 phys/size 从不具效力。
pub struct DeviceMmioWindow {
    pub name: &'static str,
    /// 物理基址（4KiB 对齐由发布方保证）。
    pub phys: u64,
    /// 字节长度。
    pub len: u64,
}

/// 窗口容量：PCI 扫描的每个设备至多发布一个主 MMIO 窗口，上限与
/// DriverHub 设备量级一致。
const MAX_DEVICE_WINDOWS: usize = 32;
/// 单窗口字节上限（KA7 限额纪律）。
const MAX_WINDOW_BYTES: u64 = 64 * 1024 * 1024;

/// 设备窗口物理基址对齐要求（字节）。与 mm `map_mmio_user` 的页对齐一致：
/// 4KiB 是 x86-64 页粒度，未按页对齐的窗口无法逐页建立 PCD 映射。
const WINDOW_ALIGN_BYTES: u64 = 0x1000;

static DEVICE_WINDOWS: Mutex<[Option<DeviceMmioWindow>; MAX_DEVICE_WINDOWS]> =
    Mutex::new([const { None }; MAX_DEVICE_WINDOWS]);

/// 发布设备的 MMIO 物理窗口（PCI 枚举路径调用，每设备至多一次）。
///
/// 非法输入（空名/零长/未对齐/超限）如实拒绝并告警——发布方是内核自身，
/// 拒绝即内核缺陷信号，不静默吞掉。
pub fn publish_device_window(name: &'static str, phys: u64, len: u64) -> Result<(), Error> {
    if name.is_empty() || len == 0 || phys % WINDOW_ALIGN_BYTES != 0 || len > MAX_WINDOW_BYTES {
        warn!(
            "[uio] reject device window publish: name={} phys={:#x} len={}",
            name, phys, len
        );
        return Err(Error::InvalidParam);
    }
    let mut windows = DEVICE_WINDOWS.lock();
    if windows
        .iter()
        .any(|w| matches!(w, Some(w) if w.name == name))
    {
        return Err(Error::AlreadyExists);
    }
    let Some(slot) = windows.iter_mut().find(|w| w.is_none()) else {
        return Err(Error::NoSpace);
    };
    *slot = Some(DeviceMmioWindow { name, phys, len });
    info!(
        "[uio] device window published: {} phys={:#x} len={:#x}",
        name, phys, len
    );
    Ok(())
}

/// 查询设备的已登记 MMIO 窗口。
pub fn device_mmio_window(name: &str) -> Option<(u64, u64)> {
    let windows = DEVICE_WINDOWS.lock();
    windows.iter().find_map(|w| {
        w.as_ref()
            .filter(|w| w.name == name)
            .map(|w| (w.phys, w.len))
    })
}

/// claim 映射半程（K2）：按 `uio_id` 取其认领设备的已登记 MMIO 窗口。
///
/// id 不存在/记录已失效 → `None`；设备未发布窗口 → `None`。归属校验由
/// [`uio_claim_device`] 负责，本函数只做 id→窗口解析。
pub fn uio_device_window_of(uio_id: usize) -> Option<(u64, u64)> {
    let list = UIO_DRIVERS.lock();
    let entry = list.get(uio_id)?;
    if !entry.is_alive {
        return None;
    }
    let name = core::str::from_utf8(&entry.claimed_device[..entry.claimed_len]).ok()?;
    device_mmio_window(name)
}

/// 查询某设备名当前是否已有**活跃**认领。
fn slot_of_live_claim(list: &[UioDriverEntry; MAX_UIO_DRIVERS], dev_name: &str) -> Option<usize> {
    list.iter().position(|e| {
        e.is_alive
            && core::str::from_utf8(&e.claimed_device[..e.claimed_len]).is_ok_and(|n| n == dev_name)
    })
}

/// 用户态进程注册为驱动实例并声明对某设备的认领（UIO Register，M11.1）。
///
/// 同一设备的活跃认领全局唯一；重复注册返回 [`Error::AlreadyExists`]。
/// 表满返回 [`Error::NoSpace`]（KA7 语义：上限内资源如实报满，不再借用
/// OutOfMemory）。
pub fn uio_register_driver(pid: usize, dev_name: &str) -> Result<usize, Error> {
    if dev_name.is_empty() || dev_name.len() >= UIO_DEV_NAME_MAX {
        return Err(Error::InvalidParam);
    }
    // S08：认领的设备必须在 DriverHub 真实注册，否则接受任意名即成"幽灵
    // 设备"认领记录。表内不存在的名字如实 NotFound。
    if !DriverHub::device_exists(dev_name) {
        return Err(Error::NotFound);
    }
    let mut list = UIO_DRIVERS.lock();
    if slot_of_live_claim(&list, dev_name).is_some() {
        return Err(Error::AlreadyExists);
    }
    let Some(free_idx) = list.iter().position(|e| !e.is_alive) else {
        return Err(Error::NoSpace);
    };
    let mut name_buf = [0u8; UIO_DEV_NAME_MAX];
    name_buf[..dev_name.len()].copy_from_slice(dev_name.as_bytes());
    list[free_idx] = UioDriverEntry {
        pid,
        claimed_device: name_buf,
        claimed_len: dev_name.len(),
        is_alive: true,
    };
    info!(
        "[uio] driver registered: pid={} claiming dev={}",
        pid, dev_name
    );
    Ok(free_idx)
}

/// 认领校验（UIO Claim 授权半程，KA4）：以 `uio_id` 精确定位记录并验证
/// 调用者归属。
///
/// - id 越界或记录不存在/已失效 → [`Error::NotFound`]
/// - 记录存在但属于其它进程 → [`Error::PermissionDenied`]
/// - 校验通过即返回 Ok：授权效果 = 本次调用内的 id+pid 判定本身，不落
///   存储状态（无读取点的 authorized 字段已按零死代码移除，审计 B26）
pub fn uio_claim_device(uio_id: usize, caller_pid: usize) -> Result<(), Error> {
    let mut list = UIO_DRIVERS.lock();
    let Some(entry) = list.get_mut(uio_id) else {
        return Err(Error::NotFound);
    };
    if !entry.is_alive {
        return Err(Error::NotFound);
    }
    if entry.pid != caller_pid {
        return Err(Error::PermissionDenied);
    }
    let dev_str = core::str::from_utf8(&entry.claimed_device[..entry.claimed_len])
        .unwrap_or("unknown");
    info!(
        "[uio] claim authorized: pid={} uio_id={} dev={}",
        caller_pid, uio_id, dev_str
    );
    Ok(())
}

/// 进程退出或异常终止时，自动隔离并释放其认领的硬件资源（M11.2 Fault Isolation）。
pub fn uio_on_process_exit(pid: usize) -> bool {
    let mut list = UIO_DRIVERS.lock();
    let mut found = false;
    for entry in list.iter_mut() {
        if entry.is_alive && entry.pid == pid {
            entry.is_alive = false;
            found = true;
            let dev_str = core::str::from_utf8(&entry.claimed_device[..entry.claimed_len])
                .unwrap_or("unknown");
            info!(
                "[uio] isolated crashed driver: pid={} claimed_dev={} (kernel protected, 0 Panic)",
                pid, dev_str
            );
        }
    }
    found
}

/// 查询指定设备是否被活跃的用户态驱动认领。
///
/// 设备的全局身份就是注册名（与 DriverHub 同一命名空间）；归属判定不经
/// 本函数——claim 路径的 id+pid 校验见 [`uio_claim_device`]。
pub fn uio_is_device_claimed(dev_name: &str) -> bool {
    let list = UIO_DRIVERS.lock();
    slot_of_live_claim(&list, dev_name).is_some()
}

/// 注销驱动（UIO Unregister，ADR-014 0x54）：释放注册槽位并解绑其设备。
///
/// 与 [`uio_claim_device`] 同源授权：以 `uio_id` 精确定位记录并校验调用者
/// 归属——不存在的 id 报 [`Error::NotFound`]，他人 id 报
/// [`Error::PermissionDenied`]。注销后槽位 `is_alive=false`，该设备名恢复
/// 可注册状态（`slot_of_live_claim` 不再命中）。
pub fn uio_unregister_driver(uio_id: usize, caller_pid: usize) -> Result<(), Error> {
    let mut list = UIO_DRIVERS.lock();
    let Some(entry) = list.get_mut(uio_id) else {
        return Err(Error::NotFound);
    };
    if !entry.is_alive {
        return Err(Error::NotFound);
    }
    if entry.pid != caller_pid {
        return Err(Error::PermissionDenied);
    }
    let dev_str = core::str::from_utf8(&entry.claimed_device[..entry.claimed_len])
        .unwrap_or("unknown");
    entry.is_alive = false;
    info!(
        "[uio] driver unregistered: pid={} uio_id={} released dev={}",
        caller_pid, uio_id, dev_str
    );
    Ok(())
}
