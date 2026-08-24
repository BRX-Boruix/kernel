//! 流式路径规范化与解析工具（ADR-011 / ADR-023 §2）。

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

    /// 流式组件迭代器（自动消除连续 `/` 和 `.`）。
    pub fn components(&self) -> impl Iterator<Item = &'a str> {
        self.raw.split('/').filter(|&c| !c.is_empty() && c != ".")
    }

    /// 纯词法路径规范化（ADR-023 §2 成文契约）：
    ///
    /// - 逐组件消除空段与 `.`；`..` 词法弹出上一组件（ADR-011 第 8 条：
    ///   dot-dot 是文本消解，不做文件系统查询，因此不穿透符号链接/挂载点）；
    /// - **绝对输入**（`/` 开头）：栈底即根，越根的 `..` 在根截断
    ///   （`"/a/../../.." == "/"`，POSIX getcwd 同款语义）；结果恒以 `/` 开头，
    ///   根为 `"/"`；
    /// - **相对输入**：同样词法化，但越过起点的 `..` 静默丢弃会伪造位置——
    ///   因此保留为相对形式（`"../x"` 保持 `"../x"`），由调用方决定是否拒绝。
    ///   [`crate::mount::MountTable`] 的公共操作只接受绝对路径并显式报错
    ///   （vfs1 M1：禁止把相对路径静默当绝对路径解析）；
    /// - 本函数零分配上限约束：输出长度 ≤ 输入长度 + 1。
    pub fn canonicalize(path_str: &str) -> String {
        let mut stack: Vec<&str> = Vec::new();
        let is_abs = path_str.starts_with('/');

        for comp in path_str.split('/') {
            if comp.is_empty() || comp == "." {
                continue;
            }
            if comp == ".." {
                // 绝对路径的栈底是根：越根的 .. 在根截断。相对路径允许负
                // 深度：栈顶若为真实组件则弹出，否则把前导 .. 逐个累加保留
                // （"../../x" 必须保持两级，不能让相邻 .. 互相抵消伪造深度）。
                match stack.last() {
                    Some(&"..") => stack.push(".."),
                    Some(_) => {
                        stack.pop();
                    }
                    None if !is_abs => stack.push(".."),
                    None => {}
                }
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
