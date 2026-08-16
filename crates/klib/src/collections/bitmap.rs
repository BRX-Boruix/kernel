//! 固定容量位图（`Bitmap`）。
//!
//! 供帧分配器、资源管理等"标记占用/空闲"场景复用。位图以 `usize` 字数组
//! 存储，容量固定为 `WORDS * usize::BITS` 位。
//!
//! 并发：非原子实现，多核共享时由外部锁保护（如帧分配器自持自旋锁）。
//! 原子/无锁版本按需再提供。
//!
//! 位图总位数恰为 `WORDS` 的整数倍（无"超长余位"），`set_all`/`all_set`
//! 语义与 `find_*` 扫描保持一致。

/// 每个 `usize` 字包含的位数。
const WORD_BITS: usize = usize::BITS as usize;

/// 固定容量位图：`WORDS` 个 `usize` 字，共 `WORDS * usize::BITS` 位。
pub struct Bitmap<const WORDS: usize> {
    words: [usize; WORDS],
}

impl<const WORDS: usize> Bitmap<WORDS> {
    /// 全零位图（常量构造，可用于 `static`）。
    pub const fn new() -> Self {
        Self { words: [0; WORDS] }
    }

    /// 位图总位数。
    pub const fn bits() -> usize {
        WORDS * WORD_BITS
    }

    /// 读取第 `i` 位。
    pub fn get(&self, i: usize) -> bool {
        assert!(i < Self::bits(), "bit index out of range: {i}");
        (self.words[i / WORD_BITS] >> (i % WORD_BITS)) & 1 == 1
    }

    /// 置位第 `i` 位（标记占用）。
    pub fn set(&mut self, i: usize) {
        assert!(i < Self::bits(), "bit index out of range: {i}");
        self.words[i / WORD_BITS] |= 1 << (i % WORD_BITS);
    }

    /// 清零第 `i` 位（标记空闲）。
    pub fn clear(&mut self, i: usize) {
        assert!(i < Self::bits(), "bit index out of range: {i}");
        self.words[i / WORD_BITS] &= !(1 << (i % WORD_BITS));
    }

    /// 按值置位 / 清零第 `i` 位。
    pub fn set_to(&mut self, i: usize, v: bool) {
        if v {
            self.set(i)
        } else {
            self.clear(i)
        }
    }

    /// 从 `from` 起查找第一个空闲（0）位；没有返回 `None`。
    pub fn find_first_zero(&self, from: usize) -> Option<usize> {
        self.find(from, false)
    }

    /// 从 `from` 起查找第一个占用（1）位；没有返回 `None`。
    pub fn find_first_set(&self, from: usize) -> Option<usize> {
        self.find(from, true)
    }

    /// 统计置位总数。
    pub fn count_set(&self) -> usize {
        self.words.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// 是否全零。
    pub fn all_zero(&self) -> bool {
        self.words.iter().all(|&w| w == 0)
    }

    /// 是否全置位。
    pub fn all_set(&self) -> bool {
        self.words.iter().all(|&w| w == !0)
    }

    /// 全部清零。
    pub fn clear_all(&mut self) {
        self.words = [0; WORDS];
    }

    /// 全部置位。
    pub fn set_all(&mut self) {
        self.words = [!0; WORDS];
    }

    /// 从 `from` 起扫描第一个满足 `want` 的位。
    fn find(&self, from: usize, want: bool) -> Option<usize> {
        if WORDS == 0 || from >= Self::bits() {
            return None;
        }
        let w0 = from / WORD_BITS;
        let off = from % WORD_BITS;
        for wi in w0..WORDS {
            // 候选集：want=true 看置位，want=false 看零位。
            let mut hit = if want {
                self.words[wi]
            } else {
                !self.words[wi]
            };
            if wi == w0 {
                // 屏蔽 `from` 之前的位（mask 是 safe 的：off < WORD_BITS）。
                hit &= !((1usize << off) - 1);
            }
            if hit != 0 {
                let bit = hit.trailing_zeros() as usize;
                return Some(wi * WORD_BITS + bit);
            }
        }
        None
    }
}

impl<const WORDS: usize> Default for Bitmap<WORDS> {
    fn default() -> Self {
        Self::new()
    }
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_clear() {
        let mut bm = Bitmap::<4>::new(); // 256 位
        assert_eq!(Bitmap::<4>::bits(), 256);
        assert!(!bm.get(100));
        bm.set(100);
        assert!(bm.get(100));
        bm.clear(100);
        assert!(!bm.get(100));
    }

    #[test]
    #[should_panic]
    fn out_of_range_panics() {
        let mut bm = Bitmap::<1>::new();
        bm.set(64); // 越界 → panic
    }

    #[test]
    fn find_first_zero_sequential() {
        let mut bm = Bitmap::<2>::new(); // 128 位
        assert_eq!(bm.find_first_zero(0), Some(0));
        for i in 0..5 {
            bm.set(i);
        }
        assert_eq!(bm.find_first_zero(0), Some(5));
        assert_eq!(bm.find_first_zero(3), Some(5));
        assert_eq!(bm.find_first_zero(5), Some(5));
        assert_eq!(bm.find_first_zero(6), Some(6));
        assert_eq!(bm.find_first_zero(100), Some(100));
    }

    #[test]
    fn find_first_set_and_scan() {
        let mut bm = Bitmap::<2>::new();
        bm.set(10);
        bm.set(11);
        bm.set(70); // 第二个字
        assert_eq!(bm.find_first_set(0), Some(10));
        assert_eq!(bm.find_first_set(10), Some(10));
        assert_eq!(bm.find_first_set(11), Some(11));
        assert_eq!(bm.find_first_set(12), Some(70));
        assert_eq!(bm.find_first_set(71), None);
    }

    #[test]
    fn find_with_offset_in_word() {
        let mut bm = Bitmap::<2>::new();
        bm.set(5);
        bm.set(6);
        bm.set(9);
        // 从 word 内非 0 偏移开始找
        assert_eq!(bm.find_first_zero(6), Some(7));
        assert_eq!(bm.find_first_zero(10), Some(10));
        assert_eq!(bm.find_first_set(7), Some(9));
    }

    #[test]
    fn count_and_all() {
        let mut bm = Bitmap::<3>::new(); // 192 位
        assert!(bm.all_zero());
        assert!(!bm.all_set());
        bm.set(0);
        bm.set(1);
        bm.set(2);
        assert_eq!(bm.count_set(), 3);
        bm.set_all();
        assert!(bm.all_set());
        assert_eq!(bm.count_set(), 192);
        assert_eq!(bm.find_first_zero(0), None);
        bm.clear_all();
        assert!(bm.all_zero());
        assert_eq!(bm.find_first_zero(0), Some(0));
        assert_eq!(bm.find_first_set(0), None);
    }

    #[test]
    fn set_to_switch() {
        let mut bm = Bitmap::<1>::new();
        bm.set_to(10, true);
        assert!(bm.get(10));
        bm.set_to(10, false);
        assert!(!bm.get(10));
        assert_eq!(bm.count_set(), 0);
    }

    #[test]
    fn single_word_bitmap() {
        let mut bm = Bitmap::<1>::new();
        assert_eq!(Bitmap::<1>::bits(), usize::BITS as usize);
        bm.set(usize::BITS as usize - 1);
        assert!(bm.get(usize::BITS as usize - 1));
        assert_eq!(bm.find_first_set(0), Some(usize::BITS as usize - 1));
        assert_eq!(bm.find_first_zero(0), Some(0));
    }
}
