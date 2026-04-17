//! # Node Identity
//!
//! A node ID is 384 bits of randomness generated at first run.
//! Collision probability across 10¹² nodes: ~10⁻⁹³.
//! No coordination needed. No network check. No registry.

use std::fmt;

/// A 384-bit node identity.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId([u8; 48]);

impl NodeId {
    /// Generate a new random node ID.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 48];
        crate::rng::fill_expect(&mut bytes);
        Self(bytes)
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 48]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 48] {
        &self.0
    }

    /// Short display: first 8 hex chars.
    pub fn short(&self) -> String {
        hex_encode(&self.0[..4])
    }

    /// Encode as hex string (96 chars).
    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }

    /// Decode from hex string.
    pub fn from_hex(s: &str) -> Option<Self> {
        let bytes = hex_decode(s)?;
        if bytes.len() != 48 { return None; }
        let mut arr = [0u8; 48];
        arr.copy_from_slice(&bytes);
        Some(Self(arr))
    }

    /// Encode as base58 string using the Bitcoin alphabet (~65 chars).
    /// Better than hex for human display: shorter, no `0/O/I/l` confusion,
    /// no special chars (URL-safe and shell-safe).
    pub fn to_base58(&self) -> String {
        base58_encode(&self.0)
    }

    /// Decode from base58 string.
    pub fn from_base58(s: &str) -> Option<Self> {
        let bytes = base58_decode(s)?;
        if bytes.len() != 48 { return None; }
        let mut arr = [0u8; 48];
        arr.copy_from_slice(&bytes);
        Some(Self(arr))
    }

    /// Decode from either base58 or hex (auto-detected by character set).
    /// Useful for accepting both old and new format identifiers.
    pub fn parse(s: &str) -> Option<Self> {
        let trimmed = s.trim();
        // Hex is 96 chars, only [0-9a-fA-F]. Base58 is shorter and includes
        // non-hex letters. Try hex first if the length matches and it's all hex.
        if trimmed.len() == 96 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            Self::from_hex(trimmed)
        } else {
            Self::from_base58(trimmed)
        }
    }

    /// Convert to a u64 for backward compatibility with code that uses u64 IDs.
    /// Uses first 8 bytes. NOT collision-resistant as u64 — only for internal indexing.
    pub fn to_u64(&self) -> u64 {
        u64::from_le_bytes(self.0[0..8].try_into().unwrap())
    }
}

impl fmt::Display for NodeId {
    /// Display uses base58 (Bitcoin alphabet) — shorter and friendlier than hex.
    /// Use `to_hex()` explicitly when you need the long-form canonical encoding.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", self.short())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 { return None; }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58_encode(bytes: &[u8]) -> String {
    // Count leading zero bytes — each becomes a leading '1'.
    let leading_zeros = bytes.iter().take_while(|&&b| b == 0).count();
    // Treat the byte slice as a big-endian integer; divide repeatedly by 58.
    let mut buf: Vec<u8> = bytes.to_vec();
    let mut digits: Vec<u8> = Vec::with_capacity(bytes.len() * 138 / 100 + 1);
    let mut start = leading_zeros;
    while start < buf.len() {
        let mut remainder: u32 = 0;
        for byte in &mut buf[start..] {
            let acc = (remainder << 8) | (*byte as u32);
            *byte = (acc / 58) as u8;
            remainder = acc % 58;
        }
        digits.push(BASE58_ALPHABET[remainder as usize]);
        // Skip leading zero quotient bytes for next round.
        while start < buf.len() && buf[start] == 0 {
            start += 1;
        }
    }
    let mut out = Vec::with_capacity(leading_zeros + digits.len());
    out.extend(std::iter::repeat(b'1').take(leading_zeros));
    out.extend(digits.into_iter().rev());
    String::from_utf8(out).expect("base58 alphabet is ASCII")
}

fn base58_decode(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() { return None; }
    let bytes = s.as_bytes();
    // Each char must be in alphabet.
    let mut indexes: Vec<u8> = Vec::with_capacity(bytes.len());
    let leading_ones = bytes.iter().take_while(|&&b| b == b'1').count();
    for &c in bytes {
        let pos = BASE58_ALPHABET.iter().position(|&a| a == c)?;
        indexes.push(pos as u8);
    }
    // Now interpret as base-58 integer, build base-256 output.
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len() * 733 / 1000 + 1);
    let mut start = leading_ones;
    while start < indexes.len() {
        let mut remainder: u32 = 0;
        for d in &mut indexes[start..] {
            let acc = (remainder * 58) + (*d as u32);
            *d = (acc / 256) as u8;
            remainder = acc % 256;
        }
        out.push(remainder as u8);
        while start < indexes.len() && indexes[start] == 0 {
            start += 1;
        }
    }
    let mut result = Vec::with_capacity(leading_ones + out.len());
    result.extend(std::iter::repeat(0u8).take(leading_ones));
    result.extend(out.into_iter().rev());
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_unique() {
        let a = NodeId::generate();
        let b = NodeId::generate();
        assert_ne!(a, b, "two generated IDs should differ");
    }

    #[test]
    fn test_hex_roundtrip() {
        let id = NodeId::generate();
        let hex = id.to_hex();
        assert_eq!(hex.len(), 96);
        let recovered = NodeId::from_hex(&hex).unwrap();
        assert_eq!(id, recovered);
    }

    #[test]
    fn test_short_display() {
        let id = NodeId::generate();
        let short = id.short();
        assert_eq!(short.len(), 8);
    }

    #[test]
    fn test_from_bytes() {
        let mut bytes = [0u8; 48];
        bytes[0] = 0xAB;
        bytes[47] = 0xCD;
        let id = NodeId::from_bytes(bytes);
        assert_eq!(id.as_bytes()[0], 0xAB);
        assert_eq!(id.as_bytes()[47], 0xCD);
    }

    #[test]
    fn test_to_u64() {
        let id = NodeId::generate();
        let n = id.to_u64();
        // Should be deterministic for same ID
        assert_eq!(n, id.to_u64());
    }

    #[test]
    fn test_bad_hex_rejected() {
        assert!(NodeId::from_hex("not_hex").is_none());
        assert!(NodeId::from_hex("abcd").is_none()); // too short
        assert!(NodeId::from_hex("zz").is_none()); // invalid chars
    }

    #[test]
    fn test_base58_roundtrip() {
        let id = NodeId::generate();
        let s = id.to_base58();
        // Should be ~65 chars (66 in worst case).
        assert!(s.len() >= 64 && s.len() <= 67, "base58 len {} out of range", s.len());
        let recovered = NodeId::from_base58(&s).expect("decode");
        assert_eq!(id, recovered);
    }

    #[test]
    fn test_base58_no_ambiguous_chars() {
        let id = NodeId::generate();
        let s = id.to_base58();
        for c in s.chars() {
            assert!(!matches!(c, '0' | 'O' | 'I' | 'l'),
                "base58 string contains ambiguous char: {c}");
        }
    }

    #[test]
    fn test_base58_known_vector() {
        // All-zero bytes encode to all '1's (Bitcoin convention: leading zero byte → '1').
        let id = NodeId::from_bytes([0u8; 48]);
        let s = id.to_base58();
        assert_eq!(s, "1".repeat(48));
        let recovered = NodeId::from_base58(&s).unwrap();
        assert_eq!(id, recovered);
    }

    #[test]
    fn test_base58_rejects_bad_chars() {
        // '0' is excluded from base58 alphabet.
        assert!(NodeId::from_base58("0000000000000000000000000000000000000000000000000000000000000000").is_none());
        assert!(NodeId::from_base58("").is_none());
    }

    #[test]
    fn test_parse_accepts_both() {
        let id = NodeId::generate();
        let from_hex = NodeId::parse(&id.to_hex()).expect("hex parse");
        let from_b58 = NodeId::parse(&id.to_base58()).expect("base58 parse");
        assert_eq!(id, from_hex);
        assert_eq!(id, from_b58);
    }

    #[test]
    fn test_display_is_base58() {
        let id = NodeId::generate();
        assert_eq!(format!("{}", id), id.to_base58());
    }
}
