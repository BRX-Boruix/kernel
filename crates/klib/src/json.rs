//! 轻量流式 JSON 构造器（支持栈/堆双模与流式生成）。
//!
//! 面向 `no_std` 内核与用户态（ADR-013 JSON 第一公民）：
//! - 支持零动态内存分配（基于固定栈缓冲区或 `Write` 目标）；
//! - 支持 Key-Value 键值对、数组列表、嵌套对象；
//! - 自动处理字符串转义（`"`, `\`, `\n`, `\r`, `\t` 等）；
//! - 数值面：布尔、无符号/有符号整型、null、已格式化的 raw json 片段。
//!   **不支持浮点**（KD3 头文档如实化：内核遥测以整型/字符串表达，
//!   实现中不存在任何浮点方法，头文档不得超卖）。

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

/// JSON 写入目标 Trait。
pub trait JsonTarget {
    fn write_str(&mut self, s: &str) -> Result<(), ()>;
    fn write_char(&mut self, c: char) -> Result<(), ()> {
        let mut buf = [0u8; 4];
        let encoded = c.encode_utf8(&mut buf);
        self.write_str(encoded)
    }
}

/// 栈缓冲区写入目标（固定容量，零堆分配）。
pub struct StackTarget<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> StackTarget<N> {
    pub const fn new() -> Self {
        Self {
            buf: [0u8; N],
            len: 0,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or("")
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }
}

impl<const N: usize> JsonTarget for StackTarget<N> {
    fn write_str(&mut self, s: &str) -> Result<(), ()> {
        let bytes = s.as_bytes();
        if self.len + bytes.len() > N {
            return Err(());
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }
}

/// 堆动态 `Vec<u8>` 写入目标。
pub struct VecTarget {
    vec: Vec<u8>,
}

impl VecTarget {
    pub fn new() -> Self {
        Self { vec: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            vec: Vec::with_capacity(cap),
        }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.vec
    }

    pub fn into_string(self) -> Result<String, alloc::string::FromUtf8Error> {
        String::from_utf8(self.vec)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.vec
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.vec).unwrap_or("")
    }
}

impl JsonTarget for VecTarget {
    fn write_str(&mut self, s: &str) -> Result<(), ()> {
        self.vec.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

/// 堆动态 `String` 写入目标。
impl JsonTarget for String {
    fn write_str(&mut self, s: &str) -> Result<(), ()> {
        self.push_str(s);
        Ok(())
    }
}

/// 支持可变引用作为写入目标。
impl<T: JsonTarget + ?Sized> JsonTarget for &mut T {
    fn write_str(&mut self, s: &str) -> Result<(), ()> {
        (**self).write_str(s)
    }

    fn write_char(&mut self, c: char) -> Result<(), ()> {
        (**self).write_char(c)
    }
}

/// 写入转义后的 JSON 字符串内容（带两端双引号）。
pub fn write_escaped_str<T: JsonTarget + ?Sized>(target: &mut T, s: &str) -> Result<(), ()> {
    target.write_char('"')?;
    for c in s.chars() {
        match c {
            '"' => target.write_str("\\\"")?,
            '\\' => target.write_str("\\\\")?,
            '\n' => target.write_str("\\n")?,
            '\r' => target.write_str("\\r")?,
            '\t' => target.write_str("\\t")?,
            '\x08' => target.write_str("\\b")?,
            '\x0C' => target.write_str("\\f")?,
            c if (c as u32) < 0x20 => {
                let val = c as u32;
                target.write_str("\\u00")?;
                let h1 = (val >> 4) & 0xf;
                let h0 = val & 0xf;
                let hex_char = |n: u32| -> char {
                    if n < 10 {
                        (b'0' + n as u8) as char
                    } else {
                        (b'a' + (n - 10) as u8) as char
                    }
                };
                target.write_char(hex_char(h1))?;
                target.write_char(hex_char(h0))?;
            }
            c => target.write_char(c)?,
        }
    }
    target.write_char('"')?;
    Ok(())
}

/// 流式 JSON 写入器。
pub struct JsonWriter<T: JsonTarget> {
    target: T,
}

impl<T: JsonTarget> JsonWriter<T> {
    pub fn new(target: T) -> Self {
        Self { target }
    }

    pub fn into_target(self) -> T {
        self.target
    }

    pub fn target_ref(&self) -> &T {
        &self.target
    }

    pub fn target_mut(&mut self) -> &mut T {
        &mut self.target
    }

    /// 开始写入根对象 `{`
    pub fn start_object(&mut self) -> Result<JsonObject<'_, T>, ()> {
        self.target.write_char('{')?;
        Ok(JsonObject {
            target: &mut self.target,
            first: true,
        })
    }

    /// 开始写入根数组 `[`
    pub fn start_array(&mut self) -> Result<JsonArray<'_, T>, ()> {
        self.target.write_char('[')?;
        Ok(JsonArray {
            target: &mut self.target,
            first: true,
        })
    }
}

/// JSON 对象构建器。
pub struct JsonObject<'a, T: JsonTarget> {
    target: &'a mut T,
    first: bool,
}

impl<'a, T: JsonTarget> JsonObject<'a, T> {
    fn write_key(&mut self, key: &str) -> Result<(), ()> {
        if !self.first {
            self.target.write_char(',')?;
        }
        self.first = false;
        write_escaped_str(self.target, key)?;
        self.target.write_char(':')?;
        Ok(())
    }

    /// 写入字符串属性 `"key":"value"`
    pub fn field_str(&mut self, key: &str, val: &str) -> Result<&mut Self, ()> {
        self.write_key(key)?;
        write_escaped_str(self.target, val)?;
        Ok(self)
    }

    /// 写入整型属性 `"key":123`
    pub fn field_i64(&mut self, key: &str, val: i64) -> Result<&mut Self, ()> {
        self.write_key(key)?;
        let mut buf = [0u8; 32];
        let s = i64_to_str(val, &mut buf);
        self.target.write_str(s)?;
        Ok(self)
    }

    /// 写入无符号整型属性 `"key":123`
    pub fn field_u64(&mut self, key: &str, val: u64) -> Result<&mut Self, ()> {
        self.write_key(key)?;
        let mut buf = [0u8; 32];
        let s = u64_to_str(val, &mut buf);
        self.target.write_str(s)?;
        Ok(self)
    }

    /// 写入布尔属性 `"key":true`
    pub fn field_bool(&mut self, key: &str, val: bool) -> Result<&mut Self, ()> {
        self.write_key(key)?;
        self.target.write_str(if val { "true" } else { "false" })?;
        Ok(self)
    }

    /// 写入 null 属性 `"key":null`
    pub fn field_null(&mut self, key: &str) -> Result<&mut Self, ()> {
        self.write_key(key)?;
        self.target.write_str("null")?;
        Ok(self)
    }

    /// 写入原始未经转义的 JSON 片段 `"key":{...}` 或 `"key":[...]`
    pub fn field_raw(&mut self, key: &str, raw_json: &str) -> Result<&mut Self, ()> {
        self.write_key(key)?;
        self.target.write_str(raw_json)?;
        Ok(self)
    }

    /// 开启嵌套子对象 `"key":{`
    pub fn sub_object<F>(&mut self, key: &str, f: F) -> Result<&mut Self, ()>
    where
        F: FnOnce(&mut JsonObject<'_, T>) -> Result<(), ()>,
    {
        self.write_key(key)?;
        self.target.write_char('{')?;
        let mut sub = JsonObject {
            target: self.target,
            first: true,
        };
        f(&mut sub)?;
        sub.end()?;
        Ok(self)
    }

    /// 开启嵌套子数组 `"key":[`
    pub fn sub_array<F>(&mut self, key: &str, f: F) -> Result<&mut Self, ()>
    where
        F: FnOnce(&mut JsonArray<'_, T>) -> Result<(), ()>,
    {
        self.write_key(key)?;
        self.target.write_char('[')?;
        let mut sub = JsonArray {
            target: self.target,
            first: true,
        };
        f(&mut sub)?;
        sub.end()?;
        Ok(self)
    }

    /// 结束并闭合对象 `}`
    pub fn end(self) -> Result<(), ()> {
        self.target.write_char('}')
    }
}

/// JSON 数组构建器。
pub struct JsonArray<'a, T: JsonTarget> {
    target: &'a mut T,
    first: bool,
}

impl<'a, T: JsonTarget> JsonArray<'a, T> {
    fn write_comma(&mut self) -> Result<(), ()> {
        if !self.first {
            self.target.write_char(',')?;
        }
        self.first = false;
        Ok(())
    }

    /// 写入字符串元素
    pub fn push_str(&mut self, val: &str) -> Result<&mut Self, ()> {
        self.write_comma()?;
        write_escaped_str(self.target, val)?;
        Ok(self)
    }

    /// 写入无符号整型元素
    pub fn push_u64(&mut self, val: u64) -> Result<&mut Self, ()> {
        self.write_comma()?;
        let mut buf = [0u8; 32];
        let s = u64_to_str(val, &mut buf);
        self.target.write_str(s)?;
        Ok(self)
    }

    /// 写入有符号整型元素
    pub fn push_i64(&mut self, val: i64) -> Result<&mut Self, ()> {
        self.write_comma()?;
        let mut buf = [0u8; 32];
        let s = i64_to_str(val, &mut buf);
        self.target.write_str(s)?;
        Ok(self)
    }

    /// 写入布尔元素
    pub fn push_bool(&mut self, val: bool) -> Result<&mut Self, ()> {
        self.write_comma()?;
        self.target.write_str(if val { "true" } else { "false" })?;
        Ok(self)
    }

    /// 写入 null 元素
    pub fn push_null(&mut self) -> Result<&mut Self, ()> {
        self.write_comma()?;
        self.target.write_str("null")?;
        Ok(self)
    }

    /// 写入 raw JSON 元素
    pub fn push_raw(&mut self, raw_json: &str) -> Result<&mut Self, ()> {
        self.write_comma()?;
        self.target.write_str(raw_json)?;
        Ok(self)
    }

    /// 开启子对象元素 `{`
    pub fn push_object<F>(&mut self, f: F) -> Result<&mut Self, ()>
    where
        F: FnOnce(&mut JsonObject<'_, T>) -> Result<(), ()>,
    {
        self.write_comma()?;
        self.target.write_char('{')?;
        let mut sub = JsonObject {
            target: self.target,
            first: true,
        };
        f(&mut sub)?;
        sub.end()?;
        Ok(self)
    }

    /// 开启子数组元素 `[`
    pub fn push_array<F>(&mut self, f: F) -> Result<&mut Self, ()>
    where
        F: FnOnce(&mut JsonArray<'_, T>) -> Result<(), ()>,
    {
        self.write_comma()?;
        self.target.write_char('[')?;
        let mut sub = JsonArray {
            target: self.target,
            first: true,
        };
        f(&mut sub)?;
        sub.end()?;
        Ok(self)
    }

    /// 结束并闭合数组 `]`
    pub fn end(self) -> Result<(), ()> {
        self.target.write_char(']')
    }
}

/// u64 转字符串（零分配）。
fn u64_to_str(mut val: u64, buf: &mut [u8; 32]) -> &str {
    if val == 0 {
        buf[0] = b'0';
        return core::str::from_utf8(&buf[..1]).unwrap_or("0");
    }
    let mut pos = 32;
    while val > 0 {
        pos -= 1;
        buf[pos] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    core::str::from_utf8(&buf[pos..32]).unwrap_or("")
}

/// i64 转字符串（零分配）。
fn i64_to_str(val: i64, buf: &mut [u8; 32]) -> &str {
    if val >= 0 {
        return u64_to_str(val as u64, buf);
    }
    let mut uval = val.unsigned_abs();
    let mut pos = 32;
    while uval > 0 {
        pos -= 1;
        buf[pos] = b'0' + (uval % 10) as u8;
        uval /= 10;
    }
    pos -= 1;
    buf[pos] = b'-';
    core::str::from_utf8(&buf[pos..32]).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stack_json_object() {
        let mut target = StackTarget::<256>::new();
        {
            let mut writer = JsonWriter::new(&mut target);
            let mut obj = writer.start_object().unwrap();
            obj.field_str("name", "borui-kernel").unwrap();
            obj.field_u64("version", 1).unwrap();
            obj.field_bool("active", true).unwrap();
            obj.field_null("parent").unwrap();
            obj.end().unwrap();
        }
        assert_eq!(
            target.as_str(),
            r#"{"name":"borui-kernel","version":1,"active":true,"parent":null}"#
        );
    }

    #[test]
    fn test_vec_json_nested() {
        let mut target = VecTarget::new();
        {
            let mut writer = JsonWriter::new(&mut target);
            let mut obj = writer.start_object().unwrap();
            obj.field_str("status", "ok").unwrap();
            obj.sub_object("cpu", |sub| {
                sub.field_str("arch", "x86_64")?;
                sub.field_u64("cores", 4)?;
                Ok(())
            })
            .unwrap();
            obj.sub_array("tags", |arr| {
                arr.push_str("kernel")?;
                arr.push_str("vfs")?;
                arr.push_u64(42)?;
                Ok(())
            })
            .unwrap();
            obj.end().unwrap();
        }
        assert_eq!(
            target.as_str(),
            r#"{"status":"ok","cpu":{"arch":"x86_64","cores":4},"tags":["kernel","vfs",42]}"#
        );
    }

    #[test]
    fn test_string_escape() {
        let mut target = StackTarget::<128>::new();
        {
            let mut writer = JsonWriter::new(&mut target);
            let mut obj = writer.start_object().unwrap();
            obj.field_str("msg", "hello \"world\"\nnewline\ttab")
                .unwrap();
            obj.end().unwrap();
        }
        assert_eq!(
            target.as_str(),
            r#"{"msg":"hello \"world\"\nnewline\ttab"}"#
        );
    }
}
