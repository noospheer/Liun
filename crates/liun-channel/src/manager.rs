//! # Channel Manager
//!
//! Maintains all Liu channels for a node. Handles:
//! - Connection lifecycle (connect, reconnect, close)
//! - Parallel channels per peer (configurable multiplier for throughput)
//! - Key material distribution to consumers (DKG, USS, MAC)
//! - Peer introduction (establish new channels over existing ITS overlay)

use std::collections::HashMap;
use tokio::net::TcpListener;
use tracing::{info, warn};
use crate::channel::{Channel, ChannelConfig, ChannelStatus};

/// Manages all channels for a single node.
/// Supports multiple parallel channels per peer for higher throughput.
pub struct ChannelManager {
    /// Our node ID.
    pub node_id: u64,
    /// Channels keyed by (peer_id, channel_index).
    channels: HashMap<(u64, usize), Channel>,
    /// Default channel configuration.
    config: ChannelConfig,
    /// Number of parallel channels per peer.
    pub parallel_per_peer: usize,
}

impl ChannelManager {
    /// Create a new channel manager with 1 channel per peer.
    pub fn new(node_id: u64, config: ChannelConfig) -> Self {
        Self {
            node_id,
            channels: HashMap::new(),
            config,
            parallel_per_peer: 1,
        }
    }

    /// Create a channel manager with N parallel channels per peer.
    pub fn with_parallel(node_id: u64, config: ChannelConfig, parallel: usize) -> Self {
        Self {
            node_id,
            channels: HashMap::new(),
            config,
            parallel_per_peer: parallel.max(1),
        }
    }

    /// Add channels to a peer (spawns parallel_per_peer channels).
    /// Each channel gets the same PSK but a different nonce suffix
    /// so their pool states are independent.
    pub fn add_channel(&mut self, peer_id: u64, psk: &[u8], nonce: &[u8; 16]) {
        for idx in 0..self.parallel_per_peer {
            // Derive a unique nonce per parallel channel by XORing index
            let mut channel_nonce = *nonce;
            let idx_bytes = (idx as u64).to_le_bytes();
            for i in 0..8 {
                channel_nonce[i] ^= idx_bytes[i];
            }
            let channel = Channel::new(peer_id, psk, &channel_nonce, self.config.clone());
            self.channels.insert((peer_id, idx), channel);
        }
        info!(node = self.node_id, peer = peer_id,
            parallel = self.parallel_per_peer, "channels added");
    }

    /// Get a reference to a specific channel.
    pub fn get(&self, peer_id: u64, idx: usize) -> Option<&Channel> {
        self.channels.get(&(peer_id, idx))
    }

    /// Get a mutable reference to a specific channel.
    pub fn get_mut(&mut self, peer_id: u64, idx: usize) -> Option<&mut Channel> {
        self.channels.get_mut(&(peer_id, idx))
    }

    /// Get first channel to a peer (convenience for single-channel use).
    pub fn get_peer(&self, peer_id: u64) -> Option<&Channel> {
        self.get(peer_id, 0)
    }

    /// Number of active channels (across all peers and parallel instances).
    pub fn active_count(&self) -> usize {
        self.channels.values()
            .filter(|ch| ch.status == ChannelStatus::Active)
            .count()
    }

    /// Total channels (all states).
    pub fn total_count(&self) -> usize {
        self.channels.len()
    }

    /// Unique peer IDs.
    pub fn peers(&self) -> Vec<u64> {
        let mut ids: Vec<u64> = self.channels.keys().map(|&(id, _)| id).collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    /// Number of unique peers.
    pub fn peer_count(&self) -> usize {
        self.peers().len()
    }

    /// Close all channels to a peer.
    pub fn close_peer(&mut self, peer_id: u64) {
        for idx in 0..self.parallel_per_peer {
            if let Some(ch) = self.channels.get_mut(&(peer_id, idx)) {
                ch.close();
            }
        }
    }

    /// Aggregate throughput: total Mbps across all active channels.
    /// Each channel produces ~6 Mbps.
    pub fn estimated_throughput_mbps(&self) -> f64 {
        self.active_count() as f64 * 6.0
    }

    /// Accept an incoming connection for a known peer.
    pub fn accept_connection(&mut self, peer_id: u64, stream: tokio::net::TcpStream) {
        if let Some(ch) = self.channels.get_mut(&(peer_id, 0)) {
            ch.accept(stream);
            info!(node = self.node_id, peer = peer_id, "connection accepted");
        } else {
            warn!(node = self.node_id, peer = peer_id, "no channel for peer");
        }
    }

    /// Run all active channels for one batch each.
    /// Returns total key bits generated.
    pub async fn run_all_batches(&mut self) -> u64 {
        let mut total = 0u64;
        let active_keys: Vec<(u64, usize)> = self.channels.iter()
            .filter(|(_, ch)| ch.status == ChannelStatus::Active)
            .map(|(&key, _)| key)
            .collect();

        for key in active_keys {
            if let Some(ch) = self.channels.get_mut(&key) {
                match ch.run_batch().await {
                    Ok(bits) => total += bits as u64,
                    Err(e) => {
                        warn!(peer = key.0, idx = key.1, error = %e, "batch failed");
                        ch.close();
                    }
                }
            }
        }
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_channel() {
        let mut mgr = ChannelManager::new(1, ChannelConfig::default());
        let psk = vec![0u8; 1032];
        let nonce = [0u8; 16];
        mgr.add_channel(2, &psk, &nonce);
        assert_eq!(mgr.total_count(), 1);
        assert_eq!(mgr.peer_count(), 1);
    }

    #[test]
    fn test_parallel_channels() {
        let mut mgr = ChannelManager::with_parallel(1, ChannelConfig::default(), 10);
        let psk = vec![0u8; 1032];
        let nonce = [0u8; 16];
        mgr.add_channel(2, &psk, &nonce);
        mgr.add_channel(3, &psk, &nonce);
        // 2 peers × 10 parallel = 20 channels
        assert_eq!(mgr.total_count(), 20);
        assert_eq!(mgr.peer_count(), 2);
        assert_eq!(mgr.parallel_per_peer, 10);
        // Estimated throughput: 20 channels × 6 Mbps = 120 Mbps
        // (but none are active yet — they're idle)
    }

    #[test]
    fn test_independent_nonces() {
        let mut mgr = ChannelManager::with_parallel(1, ChannelConfig::default(), 3);
        let psk = vec![0u8; 1032];
        let nonce = [0u8; 16];
        mgr.add_channel(2, &psk, &nonce);
        // Each parallel channel should exist independently
        assert!(mgr.get(2, 0).is_some());
        assert!(mgr.get(2, 1).is_some());
        assert!(mgr.get(2, 2).is_some());
        assert!(mgr.get(2, 3).is_none()); // only 3 parallel
    }

    #[test]
    fn test_close_peer() {
        let mut mgr = ChannelManager::with_parallel(1, ChannelConfig::default(), 5);
        let psk = vec![0u8; 1032];
        let nonce = [0u8; 16];
        mgr.add_channel(2, &psk, &nonce);
        mgr.add_channel(3, &psk, &nonce);
        assert_eq!(mgr.total_count(), 10);
        mgr.close_peer(2);
        // Channels still exist but are closed
        assert_eq!(mgr.total_count(), 10);
        assert_eq!(mgr.peer_count(), 2);
    }

    #[test]
    fn test_throughput_estimate() {
        let mgr = ChannelManager::with_parallel(1, ChannelConfig::default(), 100);
        // No channels yet
        assert_eq!(mgr.estimated_throughput_mbps(), 0.0);
        // After adding peers, channels are idle (not active), so still 0
        // Active channels only exist after connect/accept
    }
}
