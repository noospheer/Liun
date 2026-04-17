//! # Peer Handshake Protocol
//!
//! When a TCP connection arrives, both sides need to:
//! 1. Identify themselves (node ID)
//! 2. Determine if they have an existing channel
//! 3. If yes: resume with existing pool state
//! 4. If no: decide whether to bootstrap or reject
//!
//! Wire format:
//! ```text
//! → HELLO: [magic: 4 bytes][version: 2][node_id: 8][channel_idx: 2][nonce: 16]
//! ← HELLO: [magic: 4 bytes][version: 2][node_id: 8][channel_idx: 2][nonce: 16]
//! → READY / REJECT: [1 byte status]
//! ← READY / REJECT: [1 byte status]
//! ```
//! After mutual READY, the Liu exchange begins.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Protocol magic bytes: "LIUN"
const MAGIC: [u8; 4] = [0x4C, 0x49, 0x55, 0x4E];

/// Protocol version.
const VERSION: u16 = 1;

/// Handshake message size: 4 + 2 + 8 + 2 + 16 = 32 bytes.
const HELLO_SIZE: usize = 32;

/// Status codes.
const STATUS_READY: u8 = 0x01;
const STATUS_REJECT: u8 = 0x00;

/// The hello message sent at connection start.
#[derive(Debug, Clone)]
pub struct Hello {
    pub node_id: u64,
    pub channel_idx: u16,
    pub nonce: [u8; 16],
}

impl Hello {
    /// Encode to bytes.
    pub fn encode(&self) -> [u8; HELLO_SIZE] {
        let mut buf = [0u8; HELLO_SIZE];
        buf[0..4].copy_from_slice(&MAGIC);
        buf[4..6].copy_from_slice(&VERSION.to_be_bytes());
        buf[6..14].copy_from_slice(&self.node_id.to_be_bytes());
        buf[14..16].copy_from_slice(&self.channel_idx.to_be_bytes());
        buf[16..32].copy_from_slice(&self.nonce);
        buf
    }

    /// Decode from bytes. Returns None if magic or version mismatch.
    pub fn decode(buf: &[u8; HELLO_SIZE]) -> Option<Self> {
        if buf[0..4] != MAGIC {
            return None;
        }
        let version = u16::from_be_bytes([buf[4], buf[5]]);
        if version != VERSION {
            return None;
        }
        let node_id = u64::from_be_bytes(buf[6..14].try_into().ok()?);
        let channel_idx = u16::from_be_bytes([buf[14], buf[15]]);
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&buf[16..32]);
        Some(Self { node_id, channel_idx, nonce })
    }
}

/// Result of a handshake attempt.
#[derive(Debug)]
pub enum HandshakeResult {
    /// Peer identified, channel exists, ready to exchange.
    Ready {
        peer_id: u64,
        channel_idx: u16,
        nonce: [u8; 16],
    },
    /// Peer identified but no channel exists. Could bootstrap.
    NeedBootstrap {
        peer_id: u64,
    },
    /// Protocol error or version mismatch.
    Failed(String),
}

/// Perform the handshake as the initiator (outgoing connection).
/// Sends our hello first, then reads the peer's hello.
pub async fn handshake_initiate(
    stream: &mut TcpStream,
    our_id: u64,
    channel_idx: u16,
    known_peers: &[u64],
) -> Result<HandshakeResult, Box<dyn std::error::Error + Send + Sync>> {
    // Generate session nonce
    let nonce_bytes = liuproto_core::noise::random_bytes(16);
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&nonce_bytes);

    // Send our hello
    let hello = Hello { node_id: our_id, channel_idx, nonce };
    stream.write_all(&hello.encode()).await?;

    // Read peer's hello
    let mut buf = [0u8; HELLO_SIZE];
    stream.read_exact(&mut buf).await?;
    let peer_hello = Hello::decode(&buf)
        .ok_or("invalid hello from peer")?;

    // Check if we have a channel with this peer
    let have_channel = known_peers.contains(&peer_hello.node_id);

    if have_channel {
        // Send READY
        stream.write_all(&[STATUS_READY]).await?;

        // Read peer's status
        let mut status = [0u8; 1];
        stream.read_exact(&mut status).await?;

        if status[0] == STATUS_READY {
            Ok(HandshakeResult::Ready {
                peer_id: peer_hello.node_id,
                channel_idx: peer_hello.channel_idx,
                nonce: peer_hello.nonce,
            })
        } else {
            Ok(HandshakeResult::Failed("peer rejected".into()))
        }
    } else {
        // Send REJECT (or could initiate bootstrap)
        stream.write_all(&[STATUS_REJECT]).await?;
        Ok(HandshakeResult::NeedBootstrap {
            peer_id: peer_hello.node_id,
        })
    }
}

/// Perform the handshake as the responder (incoming connection).
/// Reads the peer's hello first, then sends ours.
pub async fn handshake_respond(
    stream: &mut TcpStream,
    our_id: u64,
    channel_idx: u16,
    known_peers: &[u64],
) -> Result<HandshakeResult, Box<dyn std::error::Error + Send + Sync>> {
    // Read peer's hello
    let mut buf = [0u8; HELLO_SIZE];
    stream.read_exact(&mut buf).await?;
    let peer_hello = Hello::decode(&buf)
        .ok_or("invalid hello from peer")?;

    // Send our hello
    let nonce_bytes = liuproto_core::noise::random_bytes(16);
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&nonce_bytes);
    let hello = Hello { node_id: our_id, channel_idx, nonce };
    stream.write_all(&hello.encode()).await?;

    // Check if we have a channel with this peer
    let have_channel = known_peers.contains(&peer_hello.node_id);

    if have_channel {
        // Read peer's status
        let mut status = [0u8; 1];
        stream.read_exact(&mut status).await?;

        if status[0] == STATUS_READY {
            // Send READY back
            stream.write_all(&[STATUS_READY]).await?;
            Ok(HandshakeResult::Ready {
                peer_id: peer_hello.node_id,
                channel_idx: peer_hello.channel_idx,
                nonce: peer_hello.nonce,
            })
        } else {
            stream.write_all(&[STATUS_REJECT]).await?;
            Ok(HandshakeResult::NeedBootstrap {
                peer_id: peer_hello.node_id,
            })
        }
    } else {
        // Read whatever status peer sends
        let mut status = [0u8; 1];
        stream.read_exact(&mut status).await?;
        // Reject — we don't know this peer
        stream.write_all(&[STATUS_REJECT]).await?;
        Ok(HandshakeResult::NeedBootstrap {
            peer_id: peer_hello.node_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_handshake_known_peers() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Node 1 knows node 2, and vice versa
        let responder = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            handshake_respond(&mut stream, 2, 0, &[1]).await.unwrap()
        });

        let initiator = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            handshake_initiate(&mut stream, 1, 0, &[2]).await.unwrap()
        });

        let init_result = initiator.await.unwrap();
        let resp_result = responder.await.unwrap();

        match init_result {
            HandshakeResult::Ready { peer_id, .. } => assert_eq!(peer_id, 2),
            other => panic!("initiator expected Ready, got {:?}", other),
        }
        match resp_result {
            HandshakeResult::Ready { peer_id, .. } => assert_eq!(peer_id, 1),
            other => panic!("responder expected Ready, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_handshake_unknown_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Node 1 knows node 2, but node 3 is unknown to node 1
        let responder = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            handshake_respond(&mut stream, 3, 0, &[1]).await.unwrap()
        });

        let initiator = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            handshake_initiate(&mut stream, 1, 0, &[2]).await.unwrap()
        });

        let init_result = initiator.await.unwrap();
        let resp_result = responder.await.unwrap();

        // Initiator doesn't know node 3 → NeedBootstrap
        match init_result {
            HandshakeResult::NeedBootstrap { peer_id } => assert_eq!(peer_id, 3),
            other => panic!("expected NeedBootstrap, got {:?}", other),
        }
        // Responder gets NeedBootstrap because initiator rejected
        match resp_result {
            HandshakeResult::NeedBootstrap { peer_id } => assert_eq!(peer_id, 1),
            other => panic!("expected NeedBootstrap, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_hello_encode_decode() {
        let hello = Hello {
            node_id: 42,
            channel_idx: 7,
            nonce: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        };
        let encoded = hello.encode();
        let decoded = Hello::decode(&encoded).unwrap();
        assert_eq!(decoded.node_id, 42);
        assert_eq!(decoded.channel_idx, 7);
        assert_eq!(decoded.nonce, hello.nonce);
    }

    #[tokio::test]
    async fn test_bad_magic_rejected() {
        let mut buf = [0u8; HELLO_SIZE];
        buf[0..4].copy_from_slice(b"FAKE");
        assert!(Hello::decode(&buf).is_none());
    }
}
