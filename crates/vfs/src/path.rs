//! 流式路径规范化与解析工具（ADR-011）。

use alloc::string::String;
use alloc::vec::Vec;

/// 路径解析辅助结构。
pub struct Path<'a> {
    raw: &'a str,
}

impl<'a> Path<'a> {
    pub const fn new(raw: &'a str) -> Self {
        Self { raw }
    }

    /// 是否为绝对路径。
    pub fn is_absolute(&self) -> bool {
        self.raw.starts_with('/')
    }

    /// 流式组件迭代器（自动消除连续 `/` 和 `.`）。
    pub fn components(&self) -> impl Iterator<Item = &'a str> {
        self.raw.split('/').filter(|&c| !c.is_empty() && c != ".")
    }

    /// 路径规范化（解析 `..`，严格消除多余层次）。
    pub fn canonicalize(path_str: &str) -> String {
        let mut stack: Vec<&str> = Vec::new();
        let is_abs = path_str.starts_with('/');

        for comp in path_str.split('/') {
            if comp.is_empty() || comp == "." {
                continue;
            }
            if comp == ".." {
                stack.pop();
            } else {
                stack.push(comp);
            }
        }

        if stack.is_empty() {
            return if is_abs {
                String::from("/")
            } else {
                String::from(".")
            };
        }

        let mut res = String::new();
        if is_abs {
            res.push('/');
        }
        for (i, c) in stack.iter().enumerate() {
            if i > 0 {
                res.push('/');
            }
            res.push_str(c);
        }
        res
    }
}
