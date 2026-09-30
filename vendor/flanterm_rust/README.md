# flanterm rust

如你所见，BORUIX PROJECT 我们吧 flanterm 原版重写为RUST了。

就没别的了，就跟原版差不多。

## Licensing

- 本项目新增/改写的 Rust 代码：MIT，见 `LICENSE-MIT`。
- 派生自上游 flanterm (C) 的部分——`src/generated.rs`、`src/unicode_map.rs`
  的生成段、`src/flanterm.rs` 中为兼容 C ABI 保留的常量与接口结构：
  BSD-2-Clause，见 `LICENSE-BSD-2`，原作者版权声明随附。
