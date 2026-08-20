# BORUIX Kernel

BORUIX 是一个使用 Rust 语言从零构建的玩具内核

---

## 项目结构

```text
kernel/
├── crates/
│   ├── arch/       # 硬件架构抽象与具体平台实现 (x86_64 等)
│   ├── drv/        # 设备驱动框架与设备注册管理
│   ├── klib/       # 内核基础工具库 (分配器、日志、同步原语等)
│   ├── mm/         # 物理与虚拟内存管理
│   ├── vfs/        # 虚拟文件系统
│   └── kernel/     # 内核核心 (入口引导、进程调度、系统调用、ELF 加载)
├── Cargo.toml      # 工作区配置
└── README.md
```

---

## 快速上手

### 环境要求

- Rust 工具链（Nightly 版本）
- `rust-src` 与 `llvm-tools` 组件
- QEMU（用于虚拟机调试与运行）

### 构建与测试

在项目根目录下执行：

```bash
# 运行单元测试
cargo test

# 针对裸机目标构建内核
cargo build --target x86_64-unknown-none
```

或

```bash
# 克隆 boruix brxos
git clone https://github.com/brx-boruix/brxos
# 然后 cd 进brxos
cd brxos
# 使用如下命令获取全部存储库
python get.py
# 到env配置你的 qemu 地址
# 然后cd到sdk
cd sdk
# 编译内核与相关组件至ISO
python main.py build --release
# 直接构建并运行
python main.py br --release

```