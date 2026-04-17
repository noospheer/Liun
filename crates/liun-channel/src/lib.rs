//! # liun-channel: Liu ITS Channel Management
//!
//! Manages persistent Liu protocol channels over async TCP.
//! Each channel continuously generates ITS key material between
//! two nodes via Gaussian noise exchange + privacy amplification.
//!
//! Architecture:
//! - `Channel`: one bidirectional ITS key stream between two peers
//! - `ChannelManager`: maintains all channels for a node, handles reconnection
//! - `KeyBuffer`: thread-safe FIFO of extracted key material

pub mod wire;
pub mod channel;
pub mod manager;
pub mod exchange;
pub mod handshake;
