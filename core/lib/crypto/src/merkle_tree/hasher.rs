/// Definition of hasher suitable for calculating state hash.
/// 适合计算状态散列的散列器的定义
pub trait Hasher<Hash> {
    /// Gets the hash of the bit sequence.
    fn hash_bits<I: IntoIterator<Item = bool>>(&self, value: I) -> Hash;
    /// Get the hash of the hashes sequence.
    fn hash_elements<I: IntoIterator<Item = Hash>>(&self, elements: I) -> Hash;
    /// Merges two hashes into one.
    fn compress(&self, lhs: &Hash, rhs: &Hash, i: usize) -> Hash;
}
