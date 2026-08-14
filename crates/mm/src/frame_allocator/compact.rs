use super::ALLOCATOR;

pub fn compact_now() {
    ALLOCATOR.compact();
}
