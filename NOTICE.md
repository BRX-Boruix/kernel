# 第三方组件声明

本仓库包含或链接以下第三方组件。各组件的版权归其原作者所有，使用条款以组件自带的许可文件为准。

## brxlimine-rs

- **位置**：`vendor/brxlimine-rs/`
- **来源**：[limine-rs](https://github.com/limine-bootloader/limine-rs) 0.1.12
- **版权**：Copyright (c) 2021 Anhad Singh；Copyright (c) 2026 Yang Borui and contributors
  （BORUIX fork 的修改部分）
- **许可**：MIT 或 Apache-2.0 双许可，使用者可任选其一
- **许可文件**：`vendor/brxlimine-rs/LICENSE-MIT`、`vendor/brxlimine-rs/LICENSE-APACHE`
- **修改**：本仓库使用的是改名后的 fork（原包名 `limine`），并修改了 `File.media_type` 字段的
  类型以匹配 brxLimine 的引导协议。fork 的版权声明已加在原作者的版权声明下方，两份许可文件与
  `Cargo.toml.orig` 的 `authors` 字段均已标注。

## flanterm_rust

- **位置**：`vendor/flanterm_rust/`
- **来源**：flanterm 的 Rust 重写版
- **版权**：Copyright (C) 2022-2026 Mintsuki and contributors；Copyright (C) 2022-2026 yang borui
  and contributors
- **许可**：BSD-2-Clause
- **许可文件**：`vendor/flanterm_rust/LICENSE`
- **说明**：在本仓库中作为本地依赖使用，保留了完整的许可与版权声明。

## 关于本仓库自身的许可

本仓库自身代码的许可见根目录 [LICENSE](LICENSE)。第三方组件的条款独立于该许可，不受其影响。
