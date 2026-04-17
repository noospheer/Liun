//! # Peer Introduction
//!
//! Establish new ITS channels via existing ones. Three introducers
//! each generate a PSK component; the XOR is the new channel's PSK.
//! One honest introducer suffices for perfect secrecy.
//!
//! ITS property: proved in Lean (PeerIntro.lean, MultiPathXOR.lean).

/// Generate a new PSK from m introducer components via XOR.
/// If ≥1 component is from an honest introducer (unknown to Eve),
/// the result is perfectly secret.
pub fn combine_psk_components(components: &[Vec<u8>]) -> Vec<u8> {
    assert!(!components.is_empty(), "need at least one component");
    let len = components[0].len();
    assert!(components.iter().all(|c| c.len() == len), "mismatched component lengths");

    let mut result = vec![0u8; len];
    for component in components {
        for (i, &byte) in component.iter().enumerate() {
            result[i] ^= byte;
        }
    }
    result
}

/// Minimum number of introducers for peer introduction.
pub const MIN_INTRODUCERS: usize = 3;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_combine() {
        let c1 = vec![0xAA, 0xBB, 0xCC];
        let c2 = vec![0x11, 0x22, 0x33];
        let c3 = vec![0xFF, 0x00, 0xFF];
        let psk = combine_psk_components(&[c1, c2, c3]);
        assert_eq!(psk, vec![0xAA ^ 0x11 ^ 0xFF, 0xBB ^ 0x22 ^ 0x00, 0xCC ^ 0x33 ^ 0xFF]);
    }

    #[test]
    fn test_xor_with_zero_is_identity() {
        let c1 = vec![42, 99, 7];
        let c2 = vec![0, 0, 0];
        let psk = combine_psk_components(&[c1.clone(), c2]);
        assert_eq!(psk, c1);
    }

    #[test]
    fn test_xor_self_cancels() {
        let c = vec![42, 99, 7];
        let psk = combine_psk_components(&[c.clone(), c]);
        assert_eq!(psk, vec![0, 0, 0]);
    }
}
