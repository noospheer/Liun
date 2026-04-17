//! # XOR distance on 384-bit NodeIds
//!
//! `d(a, b) = a ⊕ b`. The metric has these key properties used throughout
//! Kademlia:
//!
//! - **Symmetry**: `d(a, b) = d(b, a)` (required for well-defined routing).
//! - **Identity**: `d(a, a) = 0`, and `d(a, b) ≠ 0` for `a ≠ b`.
//! - **Unidirectionality**: for any `a` and distance `d`, there is exactly
//!   one `b` such that `d(a, b) = d`. This is what makes k-buckets stable —
//!   a node at distance `2^i..2^(i+1)` from us stays in bucket `i` forever.
//!
//! The "bucket index" is the position of the highest set bit of the XOR,
//! counted from the MSB. Nodes closer to us land in higher-indexed buckets;
//! the single node identical to us would land in bucket 384 (special-cased).

use liuproto_core::identity::NodeId;

/// A 384-bit XOR distance.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Distance(pub [u8; 48]);

impl Distance {
    /// Compute XOR distance between two node IDs.
    pub fn between(a: &NodeId, b: &NodeId) -> Self {
        let ab = a.as_bytes();
        let bb = b.as_bytes();
        let mut out = [0u8; 48];
        for i in 0..48 {
            out[i] = ab[i] ^ bb[i];
        }
        Self(out)
    }

    /// Bucket index: position of the highest set bit from the MSB.
    /// Returns `None` when the distance is zero (same node).
    ///
    /// For 384-bit IDs, returns values in `0..384`. The closest bucket
    /// (bit 0 differs, e.g., d = 0x80...00) is index 0; the farthest
    /// (only the last bit differs) is index 383.
    pub fn bucket_index(&self) -> Option<usize> {
        for (byte_i, byte) in self.0.iter().enumerate() {
            if *byte != 0 {
                let bit_i = byte.leading_zeros() as usize;
                return Some(byte_i * 8 + bit_i);
            }
        }
        None
    }

    /// Is this the zero distance (identical IDs)?
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl std::fmt::Debug for Distance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Distance(")?;
        for (i, b) in self.0.iter().enumerate() {
            if i > 0 && i % 4 == 0 { write!(f, " ")?; }
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id_from_bytes(bytes: [u8; 48]) -> NodeId {
        NodeId::from_bytes(bytes)
    }

    #[test]
    fn test_zero_distance() {
        let id = NodeId::generate();
        let d = Distance::between(&id, &id);
        assert!(d.is_zero());
        assert_eq!(d.bucket_index(), None);
    }

    #[test]
    fn test_symmetry() {
        let a = NodeId::generate();
        let b = NodeId::generate();
        assert_eq!(Distance::between(&a, &b), Distance::between(&b, &a));
    }

    #[test]
    fn test_bucket_index_msb() {
        // First bit differs → bucket 0.
        let mut a = [0u8; 48];
        let mut b = [0u8; 48];
        a[0] = 0x80; // 1000_0000
        b[0] = 0x00;
        let d = Distance::between(&id_from_bytes(a), &id_from_bytes(b));
        assert_eq!(d.bucket_index(), Some(0));
    }

    #[test]
    fn test_bucket_index_lsb() {
        // Only last bit differs → bucket 383.
        let mut a = [0u8; 48];
        let mut b = [0u8; 48];
        a[47] = 0x01;
        b[47] = 0x00;
        let d = Distance::between(&id_from_bytes(a), &id_from_bytes(b));
        assert_eq!(d.bucket_index(), Some(383));
    }

    #[test]
    fn test_bucket_index_middle() {
        // Differ at bit 100 (= byte 12, bit 4).
        let mut a = [0u8; 48];
        let mut b = [0u8; 48];
        a[12] = 0x08; // 0000_1000 → bit 4 from MSB
        let d = Distance::between(&id_from_bytes(a), &id_from_bytes(b));
        assert_eq!(d.bucket_index(), Some(12 * 8 + 4));
    }

    #[test]
    fn test_distance_ordering() {
        // Closer distances compare less.
        let mut near = [0u8; 48];
        near[47] = 1;
        let mut far = [0u8; 48];
        far[0] = 0x80;
        assert!(Distance(near) < Distance(far));
    }
}
