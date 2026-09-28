# kernel

BORUIX 的内核：用 Rust 从零实现的 x86_64 操作系统内核。

[English](README.en.md)

启动后内核初始化内存管理、中断、调度器与虚拟文件系统，加载用户态驱动并把控制权交给初始化
进程。设备驱动的大部分实现在用户态运行，内核负责地址空间、进程、系统调用、文件系统与设备
授权的收口。

## 功能

- 物理与虚拟内存管理，含内核堆分配器
- 中断与异常处理，本地 APIC 与 SMP 多核启动
- 调度器与进程、线程模型：用户态按时间片抢占，内核态不可抢占
- 系统调用入口与参数校验
- 虚拟文件系统，含 devfs、ramfs、procfs、sysfs 与挂载点管理
- 页缓存与块缓存
- ISO9660 与 EXT2 文件系统
- ELF 加载器与用户态程序启动
- 共享内存与管道
- 设备分类与统一设备操作抽象，驱动按四阶段时序启动；设备认领供用户态驱动附加
- 帧缓冲终端，基于 Flanterm
- AHCI、ATAPI 光驱、ATA PIO 磁盘、PCI 总线与 PS/2 键盘驱动

## 已知限制

- 仅在 QEMU 与 x86_64 上验证，未在真实硬件运行
- 需要 Nightly 工具链：部分 crate 使用不稳定特性
- 没有交换分区；内存承诺上限为物理内存的一半，超过即拒绝
- 多用户模型（uid/gid 与能力位）已具备，但没有图形登录界面

## 构建

环境要求：Rust Nightly 工具链（含 `rust-src` 与 `llvm-tools` 组件）、QEMU。

```bash
# 运行单元测试
cargo test

# 针对裸机目标构建内核
cargo build --target x86_64-unknown-none
```

构建产物需要引导加载器装载才能在虚拟机中运行。完整的镜像组装流程在
[`tools`](https://github.com/BRX-Boruix/tools) 中。

### 一站式构建（计划中）

[`brxos`](https://github.com/BRX-Boruix/brxos) 计划提供一个取得全部仓库并一键构建的入口，
目前尚未实现。该脚本将来用于把各个仓库拉到同一工作区，并用 `tools` 组装出可运行的镜像。

## 文件结构

```
kernel/
├── Cargo.toml          # 工作区配置
├── NOTICE.md           # 第三方组件声明
├── crates/
│   ├── kernel/         # 内核核心：入口、系统调用、ELF 加载、VFS 初始化
│   ├── arch/
│   │   ├── arch/       # 硬件架构抽象
│   │   └── arch-x86_64/# x86_64 平台实现
│   ├── klib/           # 内核基础库：分配器、日志、同步原语、时间
│   ├── mm/             # 物理与虚拟内存管理
│   ├── task/           # 进程、线程与调度器
│   ├── ipc/            # 进程间通信：共享内存与管道
│   ├── vfs/            # 虚拟文件系统
│   ├── fs/             # 文件系统实现，如 ISO9660
│   ├── driver/         # 设备驱动
│   ├── loader/         # ELF 与可执行镜像加载
│   └── term/           # 帧缓冲终端
└── vendor/             # 第三方组件，见 NOTICE.md
```

## 相关项目

- [`tools`](https://github.com/BRX-Boruix/tools) —— 内核构建、镜像组装与虚拟机验收
- [`libsys`](https://github.com/BRX-Boruix/libsys) —— 用户态系统调用封装
- [`init`](https://github.com/BRX-Boruix/init) —— 内核加载后的第一个用户态进程

## 许可

MIT License，版权归 Yang Borui 所有。详见 [LICENSE](LICENSE)。
本仓库包含的第三方组件另有其许可，见 [NOTICE.md](NOTICE.md)。
