//! Property-based fuzz of the DHT wire parser.
//!
//! Gives random bytes to `Message::decode` and asserts:
//! - It never panics on arbitrary input.
//! - Every well-formed encoding roundtrips through decode.
//!
//! Not coverage-guided (that would require `cargo-fuzz` + nightly + libFuzzer);
//! `proptest` does structured random search on stable with shrinking.

use liun_dht::message::{Message, MessageKind, WireContact};
use liuproto_core::identity::NodeId;
use proptest::prelude::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

fn any_node_id() -> impl Strategy<Value = NodeId> {
    prop::array::uniform32(any::<u8>()).prop_flat_map(|_| {
        // NodeId is 48 bytes — we just want generators that produce valid IDs.
        prop::collection::vec(any::<u8>(), 48).prop_map(|v| {
            let mut arr = [0u8; 48];
            arr.copy_from_slice(&v);
            NodeId::from_bytes(arr)
        })
    })
}

fn any_socket_addr() -> impl Strategy<Value = SocketAddr> {
    prop_oneof![
        (any::<[u8; 4]>(), any::<u16>()).prop_map(|(oct, port)| {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(oct)), port)
        }),
        (any::<[u8; 16]>(), any::<u16>()).prop_map(|(oct, port)| {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(oct)), port)
        }),
    ]
}

fn any_wire_contact() -> impl Strategy<Value = WireContact> {
    (any_node_id(), any_socket_addr(), any::<u16>()).prop_map(|(id, dht_addr, channel_port)| {
        WireContact { id, dht_addr, channel_port }
    })
}

fn any_message_kind() -> impl Strategy<Value = MessageKind> {
    prop_oneof![
        Just(MessageKind::Ping),
        Just(MessageKind::Pong),
        any_node_id().prop_map(|target| MessageKind::Find { target }),
        // NODES: 0..=20 contacts (K=20 is the wire max).
        prop::collection::vec(any_wire_contact(), 0..=20)
            .prop_map(|contacts| MessageKind::Nodes { contacts }),
    ]
}

fn any_message() -> impl Strategy<Value = Message> {
    (any::<u32>(), any_node_id(), any::<u16>(), any_message_kind()).prop_map(
        |(txn_id, sender_id, sender_channel_port, kind)| Message {
            txn_id, sender_id, sender_channel_port, kind,
        },
    )
}

proptest! {
    /// Random bytes must never panic the decoder.
    #[test]
    fn random_bytes_never_panic(
        bytes in prop::collection::vec(any::<u8>(), 0..=4096),
    ) {
        let _ = Message::decode(&bytes);
        // No assertion — absence of panic is the property.
    }

    /// Any valid-structure message roundtrips encode → decode.
    #[test]
    fn well_formed_messages_roundtrip(msg in any_message()) {
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).expect("encode output must decode");
        prop_assert_eq!(decoded.txn_id, msg.txn_id);
        prop_assert_eq!(decoded.sender_id, msg.sender_id);
        prop_assert_eq!(decoded.sender_channel_port, msg.sender_channel_port);
        // kind equality depends on variant; check via encode-then-compare.
        prop_assert_eq!(decoded.encode(), encoded);
    }

    /// Truncation of a valid encoding must not panic.
    #[test]
    fn truncated_encodings_never_panic(
        msg in any_message(),
        truncate_at in 0usize..200,
    ) {
        let encoded = msg.encode();
        let cutoff = truncate_at.min(encoded.len());
        let _ = Message::decode(&encoded[..cutoff]);
    }

    /// Single-byte corruption of a valid encoding must not panic.
    #[test]
    fn single_byte_corruption_never_panics(
        msg in any_message(),
        position in 0usize..1000,
        xor_mask in any::<u8>(),
    ) {
        let mut encoded = msg.encode();
        if encoded.is_empty() || position >= encoded.len() { return Ok(()); }
        encoded[position] ^= xor_mask;
        let _ = Message::decode(&encoded);
    }
}
