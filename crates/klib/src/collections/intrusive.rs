//! 侵入式双向链表（`IntrusiveList`）。
//!
//! 节点内嵌在对象中（`IntrusiveNode`），链表只持有裸指针，零分配、
//! 无所有权，是调度器就绪队列、定时器轮盘的理想地基。
//!
//! 语义与安全：
//! - 对象加入链表后，其生命周期必须长于链表持有期；`pop`/`remove`/`clear`
//!   摘除节点后对象方可释放；
//! - 同一对象不能同时挂接两个链表（节点已链接时再插入会 panic）；
//! - 对象 ↔ 节点的互转由调用者负责（[`container_of!`] 宏 + [`Intrusible`]）。
//!
//! 多线程共享时由外部锁保护（本实现非线程安全）。

use core::marker::PhantomData;
use core::ptr;

/// 由容器对象内部节点指针反推出容器指针。
///
/// `$node`：`*mut IntrusiveNode`；`$ty`：容器类型；`$field`：节点字段名。
#[macro_export]
macro_rules! container_of {
    ($node:expr, $ty:ty, $field:ident) => {
        {
            let node_ptr = $node as usize;
            let offset = core::mem::offset_of!($ty, $field);
            (node_ptr - offset) as *mut $ty
        }
    };
}

/// 侵入式链表节点，内嵌于容器对象中。
pub struct IntrusiveNode {
    prev: *mut IntrusiveNode,
    next: *mut IntrusiveNode,
}

impl IntrusiveNode {
    /// 未链接节点（常量构造）。
    pub const fn new() -> Self {
        Self {
            prev: ptr::null_mut(),
            next: ptr::null_mut(),
        }
    }

    /// 当前是否已挂接在某个链表上。
    pub fn is_linked(&self) -> bool {
        !self.next.is_null()
    }
}

/// 容器对象接入侵入式链表所需实现的接口。
pub trait Intrusible {
    /// 节点不可变引用。
    fn node(&self) -> &IntrusiveNode;
    /// 节点可变引用。
    fn node_mut(&mut self) -> &mut IntrusiveNode;
    /// 由节点指针反推容器指针（节点必须属于该容器）。
    ///
    /// 通常用 [`container_of!`] 宏实现。
    unsafe fn from_node(node: *mut IntrusiveNode) -> *mut Self;
}

/// 侵入式双向链表（带头哨兵，惰性初始化）。
pub struct IntrusiveList<T: Intrusible> {
    head: IntrusiveNode,
    len: usize,
    _marker: PhantomData<T>,
}

impl<T: Intrusible> IntrusiveList<T> {
    /// 空链表（常量构造）。
    pub const fn new() -> Self {
        Self {
            head: IntrusiveNode::new(),
            len: 0,
            _marker: PhantomData,
        }
    }

    /// 链表长度（O(1)）。
    pub fn len(&self) -> usize {
        self.len
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 惰性初始化哨兵（首次操作时使其自环）。
    #[inline]
    fn sentinel(&mut self) -> *mut IntrusiveNode {
        let s = ptr::addr_of_mut!(self.head);
        if self.head.next.is_null() {
            self.head.next = s;
            self.head.prev = s;
        }
        s
    }

    /// 尾部插入（O(1)）。节点已链接时 panic。
    pub fn push_back(&mut self, item: &mut T) {
        let s = self.sentinel();
        let node = item.node_mut() as *mut IntrusiveNode;
        assert!(
            !unsafe { (*node).is_linked() },
            "node already linked to a list"
        );
        let last = unsafe { (*s).prev };
        unsafe {
            (*node).prev = last;
            (*node).next = s;
            (*last).next = node;
            (*s).prev = node;
        }
        self.len += 1;
    }

    /// 头部插入（O(1)）。节点已链接时 panic。
    pub fn push_front(&mut self, item: &mut T) {
        let s = self.sentinel();
        let node = item.node_mut() as *mut IntrusiveNode;
        assert!(
            !unsafe { (*node).is_linked() },
            "node already linked to a list"
        );
        let first = unsafe { (*s).next };
        unsafe {
            (*node).prev = s;
            (*node).next = first;
            (*first).prev = node;
            (*s).next = node;
        }
        self.len += 1;
    }

    /// 弹出头部节点（O(1)）；空链表返回 `None`。
    pub fn pop_front(&mut self) -> Option<&mut T> {
        let s = self.sentinel();
        let first = unsafe { (*s).next };
        if first == s {
            return None;
        }
        unsafe {
            (*((*first).next)).prev = s;
            (*s).next = (*first).next;
            (*first).prev = ptr::null_mut();
            (*first).next = ptr::null_mut();
        }
        self.len -= 1;
        Some(unsafe { &mut *T::from_node(first) })
    }

    /// 弹出尾部节点（O(1)）；空链表返回 `None`。
    pub fn pop_back(&mut self) -> Option<&mut T> {
        let s = self.sentinel();
        let last = unsafe { (*s).prev };
        if last == s {
            return None;
        }
        unsafe {
            (*((*last).prev)).next = s;
            (*s).prev = (*last).prev;
            (*last).prev = ptr::null_mut();
            (*last).next = ptr::null_mut();
        }
        self.len -= 1;
        Some(unsafe { &mut *T::from_node(last) })
    }

    /// 摘除指定对象（O(n) 校验在链表中）。不在本链表返回 `false`。
    pub fn remove(&mut self, item: &mut T) -> bool {
        let s = self.sentinel();
        let node = item.node_mut() as *mut IntrusiveNode;
        if !unsafe { (*node).is_linked() } {
            return false;
        }
        // 从哨兵遍历确认节点确属本链表（防御误删别链表对象）。
        let mut cur = unsafe { (*s).next };
        while cur != s && cur != node {
            cur = unsafe { (*cur).next };
        }
        if cur != node {
            return false;
        }
        unsafe {
            (*((*node).prev)).next = (*node).next;
            (*((*node).next)).prev = (*node).prev;
            (*node).prev = ptr::null_mut();
            (*node).next = ptr::null_mut();
        }
        self.len -= 1;
        true
    }

    /// 摘除全部节点（不调用 drop，仅解除链接）。
    pub fn clear(&mut self) {
        let s = self.sentinel();
        let mut cur = unsafe { (*s).next };
        while cur != s {
            let nxt = unsafe { (*cur).next };
            unsafe {
                (*cur).prev = ptr::null_mut();
                (*cur).next = ptr::null_mut();
            }
            cur = nxt;
        }
        unsafe {
            (*s).next = ptr::null_mut();
            (*s).prev = ptr::null_mut();
        }
        self.len = 0;
    }

    /// 不可变迭代。
    pub fn iter(&self) -> Iter<'_, T> {
        let s = ptr::addr_of!(self.head);
        let next = if self.head.next.is_null() { s } else { self.head.next };
        Iter {
            head: s,
            cur: next,
            _marker: PhantomData,
        }
    }

    /// 可变迭代。
    pub fn iter_mut(&mut self) -> IterMut<'_, T> {
        let s = ptr::addr_of_mut!(self.head);
        let next = if self.head.next.is_null() { s } else { self.head.next };
        IterMut {
            head: s,
            cur: next,
            _marker: PhantomData,
        }
    }
}

/// 不可变迭代器。
pub struct Iter<'a, T: Intrusible> {
    head: *const IntrusiveNode,
    cur: *const IntrusiveNode,
    _marker: PhantomData<&'a T>,
}

impl<'a, T: Intrusible> Iterator for Iter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        if self.cur == self.head {
            return None;
        }
        let node = self.cur;
        self.cur = unsafe { (*node).next };
        let ptr = unsafe { T::from_node(node as *mut IntrusiveNode) };
        Some(unsafe { &*ptr })
    }
}

/// 可变迭代器。
pub struct IterMut<'a, T: Intrusible> {
    head: *mut IntrusiveNode,
    cur: *mut IntrusiveNode,
    _marker: PhantomData<&'a mut T>,
}

impl<'a, T: Intrusible> Iterator for IterMut<'a, T> {
    type Item = &'a mut T;

    fn next(&mut self) -> Option<&'a mut T> {
        if self.cur == self.head {
            return None;
        }
        let node = self.cur;
        self.cur = unsafe { (*node).next };
        let ptr = unsafe { T::from_node(node) };
        Some(unsafe { &mut *ptr })
    }
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    struct Item {
        node: IntrusiveNode,
        val: u32,
    }

    impl Item {
        fn new(val: u32) -> Self {
            Self {
                node: IntrusiveNode::new(),
                val,
            }
        }
    }

    impl Intrusible for Item {
        fn node(&self) -> &IntrusiveNode {
            &self.node
        }
        fn node_mut(&mut self) -> &mut IntrusiveNode {
            &mut self.node
        }
        unsafe fn from_node(node: *mut IntrusiveNode) -> *mut Self {
            crate::container_of!(node, Item, node)
        }
    }

    #[test]
    fn push_back_pop_front_fifo() {
        let mut list = IntrusiveList::<Item>::new();
        assert!(list.is_empty());
        let mut a = Item::new(1);
        let mut b = Item::new(2);
        let mut c = Item::new(3);
        list.push_back(&mut a);
        list.push_back(&mut b);
        list.push_back(&mut c);
        assert_eq!(list.len(), 3);
        assert_eq!(list.pop_front().unwrap().val, 1);
        assert_eq!(list.pop_front().unwrap().val, 2);
        assert_eq!(list.pop_front().unwrap().val, 3);
        assert!(list.pop_front().is_none());
        assert!(list.is_empty());
    }

    #[test]
    fn push_front_pop_front_lifo() {
        let mut list = IntrusiveList::<Item>::new();
        let mut a = Item::new(1);
        let mut b = Item::new(2);
        list.push_front(&mut a);
        list.push_front(&mut b);
        assert_eq!(list.pop_front().unwrap().val, 2);
        assert_eq!(list.pop_front().unwrap().val, 1);
    }

    #[test]
    fn push_back_pop_back() {
        let mut list = IntrusiveList::<Item>::new();
        let mut a = Item::new(1);
        let mut b = Item::new(2);
        let mut c = Item::new(3);
        list.push_back(&mut a);
        list.push_back(&mut b);
        list.push_back(&mut c);
        assert_eq!(list.pop_back().unwrap().val, 3);
        assert_eq!(list.pop_back().unwrap().val, 2);
        assert_eq!(list.pop_back().unwrap().val, 1);
        assert!(list.pop_back().is_none());
    }

    #[test]
    fn remove_middle_and_foreign() {
        let mut list = IntrusiveList::<Item>::new();
        let mut a = Item::new(1);
        let mut b = Item::new(2);
        let mut c = Item::new(3);
        let mut d = Item::new(4);
        list.push_back(&mut a);
        list.push_back(&mut b);
        list.push_back(&mut c);
        list.push_back(&mut d);
        assert!(list.remove(&mut b));
        assert_eq!(list.len(), 3);
        let vals: Vec<u32> = list.iter().map(|it| it.val).collect();
        assert_eq!(vals, vec![1, 3, 4]);
        // 已移除节点再删返回 false；不在链表中的对象也返回 false。
        assert!(!list.remove(&mut b));
        let mut x = Item::new(9);
        assert!(!list.remove(&mut x));
        // 原链表顺序不变。
        let vals: Vec<u32> = list.iter().map(|it| it.val).collect();
        assert_eq!(vals, vec![1, 3, 4]);
    }

    #[test]
    fn iter_and_iter_mut() {
        let mut list = IntrusiveList::<Item>::new();
        let mut a = Item::new(10);
        let mut b = Item::new(20);
        list.push_back(&mut a);
        list.push_back(&mut b);
        let vals: Vec<u32> = list.iter().map(|it| it.val).collect();
        assert_eq!(vals, vec![10, 20]);
        for it in list.iter_mut() {
            it.val += 1;
        }
        let vals: Vec<u32> = list.iter().map(|it| it.val).collect();
        assert_eq!(vals, vec![11, 21]);
    }

    #[test]
    fn empty_list_iter() {
        let list = IntrusiveList::<Item>::new();
        assert_eq!(list.iter().count(), 0);
    }

    #[test]
    fn clear_unlinks_all() {
        let mut list = IntrusiveList::<Item>::new();
        let mut a = Item::new(1);
        let mut b = Item::new(2);
        list.push_back(&mut a);
        list.push_back(&mut b);
        list.clear();
        assert!(list.is_empty());
        assert!(!a.node.is_linked());
        assert!(!b.node.is_linked());
        // 清理后可重新入链（对象仍有效）。
        list.push_back(&mut a);
        assert_eq!(list.pop_front().unwrap().val, 1);
    }

    #[test]
    #[should_panic]
    fn double_insert_panics() {
        let mut list = IntrusiveList::<Item>::new();
        let mut a = Item::new(1);
        list.push_back(&mut a);
        list.push_back(&mut a); // 重复插入 → panic
    }

    #[test]
    fn pop_front_reusable() {
        let mut list = IntrusiveList::<Item>::new();
        let mut a = Item::new(7);
        list.push_back(&mut a);
        let popped = list.pop_front().unwrap();
        assert_eq!(popped.val, 7);
        assert!(!a.node.is_linked());
        // 弹出后对象可再次入链。
        list.push_back(&mut a);
        assert_eq!(list.pop_front().unwrap().val, 7);
    }

    #[test]
    fn move_between_lists() {
        let mut l1 = IntrusiveList::<Item>::new();
        let mut l2 = IntrusiveList::<Item>::new();
        let mut a = Item::new(5);
        l1.push_back(&mut a);
        l1.remove(&mut a);
        l2.push_back(&mut a);
        assert_eq!(l2.pop_front().unwrap().val, 5);
    }
}
