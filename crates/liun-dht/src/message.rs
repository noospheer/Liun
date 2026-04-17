//! # DHT wire protocol
//!
//! Binary messages over UDP. **No signatures** — authenticity is not claimed
//! at this layer. DHT entries are hints to be validated later by an ITS
//! handshake with the contacted node. This makes the protocol trivially
//! survivable past a computational-crypto break: there's nothing computational
//! to break at this layer.
//!
//! Frame format (v2):
//!   [version: 1][kind: 1][txn_id: 4][sender_id: 48][sender_channel_port: 2][payload...]
//!
//! The `sender_channel_port` is the TCP port on which the sender listens for
//! Liun channel handshakes. The DHT-side UDP port is observed from the packet
//! source address. The IP is shared between transports.
//!
//! Types:
//!   0x01 PING     — payload empty
//!   0x02 PONG     — payload empty
//!   0x03 FIND     — payload: target_id[48]
//!   0x04 NODES    — payload: count[1] + count * Contact
//!
//! Contact on the wire:
//!   [id: 48][family: 1][addr: 4 or 16][udp_port: 2][channel_port: 2]
//!   family = 4 for IPv4, 6 for IPv6.

use liuproto_core::identity::NodeId;
use std::net::{IpAddr, SocketAddr, Ipv4Addr, Ipv6Addr};
use crate::routing::Contact;
use std::time::Instant;

pub const VERSION: u8 = 2;
pub const HEADER_SIZE: usize = 1 + 1 + 4 + 48 + 2; // 56

pub const KIND_PING: u8 = 0x01;
pub const KIND_PONG: u8 = 0x02;
pub const KIND_FIND: u8 = 0x03;
pub const KIND_NODES: u8 = 0x04;

/// A parsed DHT message.
#[derive(Debug, Clone)]
pub struct Message {
    pub txn_id: u32,
    pub sender_id: NodeId,
    /// TCP port the sender listens on for Liun channel handshakes.
    pub sender_channel_port: u16,
    pub kind: MessageKind,
}

/// One entry in a NODES response: the peer's id, its DHT-side address, and
/// its channel-side TCP port (IP is shared).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireContact {
    pub id: NodeId,
    pub dht_addr: SocketAddr,
    pub channel_port: u16,
}

/// Message body by kind.
#[derive(Debug, Clone)]
pub enum MessageKind {
    Ping,
    Pong,
    Find { target: NodeId },
    Nodes { contacts: Vec<WireContact> },
}

/// Errors parsing a message.
#[derive(Debug)]
pub enum ParseError {
    TooShort,
    BadVersion(u8),
    BadKind(u8),
    BadAddressFamily(u8),
    TooManyContacts(usize),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "message too short"),
            Self::BadVersion(v) => write!(f, "unsupported protocol version {v}"),
            Self::BadKind(k) => write!(f, "unknown message kind 0x{k:02x}"),
            Self::BadAddressFamily(af) => write!(f, "bad address family {af}"),
            Self::TooManyContacts(n) => write!(f, "too many contacts: {n}"),
        }
    }
}

impl std::error::Error for ParseError {}

impl Message {
    /// Serialize to bytes for UDP transmission.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.push(VERSION);
        match &self.kind {
            MessageKind::Ping => buf.push(KIND_PING),
            MessageKind::Pong => buf.push(KIND_PONG),
            MessageKind::Find { .. } => buf.push(KIND_FIND),
            MessageKind::Nodes { .. } => buf.push(KIND_NODES),
        }
        buf.extend_from_slice(&self.txn_id.to_be_bytes());
        buf.extend_from_slice(self.sender_id.as_bytes());
        buf.extend_from_slice(&self.sender_channel_port.to_be_bytes());
        match &self.kind {
            MessageKind::Ping | MessageKind::Pong => {}
            MessageKind::Find { target } => {
                buf.extend_from_slice(target.as_bytes());
            }
            MessageKind::Nodes { contacts } => {
                assert!(contacts.len() <= 255, "too many contacts: {}", contacts.len());
                buf.push(contacts.len() as u8);
                for c in contacts {
                    buf.extend_from_slice(c.id.as_bytes());
                    encode_addr(&c.dht_addr, &mut buf);
                    buf.extend_from_slice(&c.channel_port.to_be_bytes());
                }
            }
        }
        buf
    }

    /// Parse bytes received on the wire.
    pub fn decode(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < HEADER_SIZE { return Err(ParseError::TooShort); }
        let version = data[0];
        if version != VERSION { return Err(ParseError::BadVersion(version)); }
        let kind_byte = data[1];
        let txn_id = u32::from_be_bytes(data[2..6].try_into().unwrap());
        let mut id_bytes = [0u8; 48];
        id_bytes.copy_from_slice(&data[6..54]);
        let sender_id = NodeId::from_bytes(id_bytes);
        let sender_channel_port = u16::from_be_bytes(data[54..56].try_into().unwrap());

        let payload = &data[HEADER_SIZE..];
        let kind = match kind_byte {
            KIND_PING => MessageKind::Ping,
            KIND_PONG => MessageKind::Pong,
            KIND_FIND => {
                if payload.len() < 48 { return Err(ParseError::TooShort); }
                let mut t = [0u8; 48];
                t.copy_from_slice(&payload[..48]);
                MessageKind::Find { target: NodeId::from_bytes(t) }
            }
            KIND_NODES => {
                if payload.is_empty() { return Err(ParseError::TooShort); }
                let count = payload[0] as usize;
                if count > 255 { return Err(ParseError::TooManyContacts(count)); }
                let mut offset = 1;
                let mut contacts = Vec::with_capacity(count);
                for _ in 0..count {
                    if offset + 48 + 1 > payload.len() { return Err(ParseError::TooShort); }
                    let mut id = [0u8; 48];
                    id.copy_from_slice(&payload[offset..offset + 48]);
                    offset += 48;
                    let dht_addr = decode_addr(&payload, &mut offset)?;
                    if offset + 2 > payload.len() { return Err(ParseError::TooShort); }
                    let channel_port = u16::from_be_bytes(payload[offset..offset + 2].try_into().unwrap());
                    offset += 2;
                    contacts.push(WireContact { id: NodeId::from_bytes(id), dht_addr, channel_port });
                }
                MessageKind::Nodes { contacts }
            }
            other => return Err(ParseError::BadKind(other)),
        };

        Ok(Message { txn_id, sender_id, sender_channel_port, kind })
    }
}

fn encode_addr(addr: &SocketAddr, buf: &mut Vec<u8>) {
    match addr.ip() {
        IpAddr::V4(ip) => {
            buf.push(4);
            buf.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            buf.push(6);
            buf.extend_from_slice(&ip.octets());
        }
    }
    buf.extend_from_slice(&addr.port().to_be_bytes());
}

fn decode_addr(buf: &[u8], offset: &mut usize) -> Result<SocketAddr, ParseError> {
    if *offset + 1 > buf.len() { return Err(ParseError::TooShort); }
    let family = buf[*offset];
    *offset += 1;
    let ip = match family {
        4 => {
            if *offset + 4 > buf.len() { return Err(ParseError::TooShort); }
            let octets: [u8; 4] = buf[*offset..*offset + 4].try_into().unwrap();
            *offset += 4;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        6 => {
            if *offset + 16 > buf.len() { return Err(ParseError::TooShort); }
            let octets: [u8; 16] = buf[*offset..*offset + 16].try_into().unwrap();
            *offset += 16;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        other => return Err(ParseError::BadAddressFamily(other)),
    };
    if *offset + 2 > buf.len() { return Err(ParseError::TooShort); }
    let port = u16::from_be_bytes(buf[*offset..*offset + 2].try_into().unwrap());
    *offset += 2;
    Ok(SocketAddr::new(ip, port))
}

/// Helper: serialize routing-table Contacts for a NODES response.
pub fn contacts_to_wire(contacts: &[Contact]) -> Vec<WireContact> {
    contacts.iter().take(255).map(|c| WireContact {
        id: c.id,
        dht_addr: c.dht_addr,
        channel_port: c.channel_port,
    }).collect()
}

/// Helper: turn decoded WireContacts back into Contacts with a fresh
/// last_seen timestamp.
pub fn wire_to_contacts(wire: Vec<WireContact>) -> Vec<Contact> {
    let now = Instant::now();
    wire.into_iter().map(|w| Contact {
        id: w.id,
        dht_addr: w.dht_addr,
        channel_port: w.channel_port,
        last_seen: now,
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn rt_id() -> NodeId { NodeId::generate() }

    fn roundtrip(m: &Message) -> Message {
        let enc = m.encode();
        Message::decode(&enc).expect("decode")
    }

    fn mk(kind: MessageKind) -> Message {
        Message {
            txn_id: 1,
            sender_id: rt_id(),
            sender_channel_port: 7770,
            kind,
        }
    }

    #[test]
    fn test_ping_pong_roundtrip() {
        let m = Message { txn_id: 0xDEADBEEF, sender_id: rt_id(), sender_channel_port: 12345, kind: MessageKind::Ping };
        let r = roundtrip(&m);
        assert_eq!(r.txn_id, 0xDEADBEEF);
        assert_eq!(r.sender_channel_port, 12345);
        assert!(matches!(r.kind, MessageKind::Ping));

        let r2 = roundtrip(&mk(MessageKind::Pong));
        assert!(matches!(r2.kind, MessageKind::Pong));
    }

    #[test]
    fn test_find_roundtrip() {
        let target = rt_id();
        let r = roundtrip(&mk(MessageKind::Find { target }));
        match r.kind {
            MessageKind::Find { target: t } => assert_eq!(t, target),
            _ => panic!("expected Find"),
        }
    }

    #[test]
    fn test_nodes_roundtrip_v4() {
        let contacts = vec![
            WireContact { id: rt_id(), dht_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 7770), channel_port: 9000 },
            WireContact { id: rt_id(), dht_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080), channel_port: 9001 },
        ];
        let r = roundtrip(&mk(MessageKind::Nodes { contacts: contacts.clone() }));
        match r.kind {
            MessageKind::Nodes { contacts: c } => assert_eq!(c, contacts),
            _ => panic!("expected Nodes"),
        }
    }

    #[test]
    fn test_nodes_roundtrip_v6() {
        let addr6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9000);
        let contacts = vec![WireContact { id: rt_id(), dht_addr: addr6, channel_port: 7777 }];
        let r = roundtrip(&mk(MessageKind::Nodes { contacts: contacts.clone() }));
        match r.kind {
            MessageKind::Nodes { contacts: c } => assert_eq!(c, contacts),
            _ => panic!("expected Nodes"),
        }
    }

    #[test]
    fn test_decode_rejects_bad_version() {
        let mut bad = vec![99, KIND_PING, 0, 0, 0, 0];
        bad.extend_from_slice(&[0u8; 48]);
        bad.extend_from_slice(&[0u8; 2]);
        assert!(matches!(Message::decode(&bad), Err(ParseError::BadVersion(99))));
    }

    #[test]
    fn test_decode_rejects_unknown_kind() {
        let mut bad = vec![VERSION, 0xFF, 0, 0, 0, 0];
        bad.extend_from_slice(&[0u8; 48]);
        bad.extend_from_slice(&[0u8; 2]);
        assert!(matches!(Message::decode(&bad), Err(ParseError::BadKind(0xFF))));
    }

    #[test]
    fn test_decode_rejects_too_short() {
        assert!(matches!(Message::decode(&[1, 2, 3]), Err(ParseError::TooShort)));
    }
}
