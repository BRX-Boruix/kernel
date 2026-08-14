# aarch64 支持（已归档）

> 状态：已归档。aarch64 相关代码保留在此目录供参考，但**不参与当前构建**（代码库只编译 x86-64）。

## 归档原因

aarch64 支持已完成代码层面（`arch-aarch64` 实现 `Platform` trait，一套代码双平台编译），
但在 QEMU 运行时调试阶段，内核未被 Limine 成功跳转执行（指令跟踪 859MB 无内核地址），
排查成本高，暂缓。先聚焦 x86-64 主线。

## 归档内容

- `arch-aarch64/` — aarch64 架构实现（`Platform` trait：PL011 UART、wfi 停机）
- `linker-aarch64.ld` — aarch64 链接脚本（higher-half `0xffffffff80000000`）

## 归档时已知的关键点（供日后恢复参考）

1. **base revision**：aarch64 要求 `BaseRevision >= 6`（Limine 12.5.2 最大支持 6）。
2. **请求识别**：`Requests count: 2` 是正常的（base revision 单独处理，framebuffer+HHDM 是普通请求）。
3. **HHDM**：访问 MMIO UART 需通过 Limine 的 `HhdmRequest.offset`，不能硬编码基址。
4. **QEMU virt 机器**：默认无显卡，需 `-device virtio-gpu-pci` 才能有 framebuffer。
5. **UEFI 固件**：需要 AAVMF（EDK2）固件，官方 `qemu-efi-aarch64` 包提供 `QEMU_EFI.fd`。
6. **入口**：`Requests count` 显示 Limine 识别了 ELF 入口，但运行时未跳转执行（待查）。

## 恢复步骤（未来）

1. 把 `arch-aarch64/` 移回 `crates/arch/arch-aarch64/`
2. `Cargo.toml` workspace members 加回 `crates/arch/arch-aarch64`
3. `crates/kernel/Cargo.toml` 加回 `arch-aarch64` 依赖
4. `build.rs` 加回 aarch64 target 分支
5. `main.rs` 加回 `#[cfg(target_arch = "aarch64")]` 相关代码
6. `sdk.py` 加回 aarch64 支持
