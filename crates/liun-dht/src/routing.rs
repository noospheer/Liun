//! # Kademlia routing table
//!
//! For each bucket index 0..384, keep up to K=20 contacts seen at that
//! distance. Buckets are ordered by recency (most-recently-seen at the
//! back). When a bucket is full and a new node arrives:
//!
//! - If the front (least-recently-seen) has been inactive past a threshold,
//!   the caller should ping it; if responsive it goes to the back, else the
//!   new node replaces it.
//! - Standard Kademlia pessimism: *existing* contacts are preferred over
//!   new ones (established liveness is evidence of future liveness).
//!
//! The pure data structure here exposes `insert` and `remove` without I/O;
//! the async ping-eviction loop lives in `node.rs`.

use crate::distance::Distance;
use liuproto_core::identity::NodeId;
use std::net::SocketAddr;
use std::time::Instant;

/// Kademlia replication parameter.
pub const K: usize = 20;

/// A routing table entry.
///
/// `dht_addr` is where this peer answers DHT (UDP) queries.
/// `channel_port` is the TCP port for the Liun channel handshake; the IP is
/// assumed to be the same as `dht_addr.ip()` (most deployments bind both
/// transports to the same interface, even though they're different sockets).
#[derive(Clone, Debug)]
pub struct Contact {
    pub id: NodeId,
    pub dht_addr: SocketAddr,
    pub channel_port: u16,
    pub last_seen: Instant,
}

impl Contact {
    pub fn new(id: NodeId, dht_addr: SocketAddr, channel_port: u16) -> Self {
        Self { id, dht_addr, channel_port, last_seen: Instant::now() }
    }

    /// The TCP address for the Liun channel handshake (same IP, channel port).
    pub fn channel_addr(&self) -> SocketAddr {
        SocketAddr::new(self.dht_addr.ip(), self.channel_port)
    }
}

/// A single k-bucket: up to K contacts, ordered by recency.
/// Front = oldest (least-recently-seen); back = newest.
#[derive(Default)]
struct Bucket {
    entries: Vec<Contact>,
}

impl Bucket {
    fn insert_or_refresh(&mut self, contact: Contact) -> InsertResult {
        if let Some(pos) = self.entries.iter().position(|c| c.id == contact.id) {
            // Move to back (most recent).
            let mut existing = self.entries.remove(pos);
            existing.dht_addr = contact.dht_addr;
            existing.channel_port = contact.channel_port;
            existing.last_seen = Instant::now();
            self.entries.push(existing);
            InsertResult::Refreshed
        } else if self.entries.len() < K {
            self.entries.push(contact);
            InsertResult::Inserted
        } else {
            // Full. Caller should decide whether to ping the front and evict.
            InsertResult::BucketFull { oldest: self.entries[0].clone() }
        }
    }

    fn remove(&mut self, id: &NodeId) -> bool {
        if let Some(pos) = self.entries.iter().position(|c| &c.id == id) {
            self.entries.remove(pos);
            true
        } else {
            false
        }
    }

    fn contacts(&self) -> &[Contact] {
        &self.entries
    }
}

/// Result of trying to insert a contact.
#[derive(Debug, Clone)]
pub enum InsertResult {
    /// New contact added.
    Inserted,
    /// Existing contact refreshed (moved to back).
    Refreshed,
    /// Bucket full; the caller should ping the oldest and decide whether
    /// to evict. The `oldest` field is the candidate for eviction.
    BucketFull { oldest: Contact },
}

/// Kademlia routing table: 384 buckets.
pub struct RoutingTable {
    our_id: NodeId,
    buckets: Vec<Bucket>,
}

impl RoutingTable {
    /// Create an empty routing table for a node with ID `our_id`.
    pub fn new(our_id: NodeId) -> Self {
        let mut buckets = Vec::with_capacity(384);
        for _ in 0..384 { buckets.push(Bucket::default()); }
        Self { our_id, buckets }
    }

    /// Our own node ID.
    pub fn our_id(&self) -> &NodeId { &self.our_id }

    /// Try to insert a contact. Returns the result so the caller (async layer)
    /// can act on BucketFull with a ping-to-oldest eviction.
    pub fn insert(&mut self, contact: Contact) -> InsertResult {
        if contact.id == self.our_id {
            // Don't store ourselves.
            return InsertResult::Refreshed;
        }
        let d = Distance::between(&self.our_id, &contact.id);
        match d.bucket_index() {
            Some(i) => self.buckets[i].insert_or_refresh(contact),
            None => InsertResult::Refreshed, // shouldn't reach — guarded above
        }
    }

    /// Remove a contact by ID. Returns true if removed.
    pub fn remove(&mut self, id: &NodeId) -> bool {
        let d = Distance::between(&self.our_id, id);
        match d.bucket_index() {
            Some(i) => self.buckets[i].remove(id),
            None => false,
        }
    }

    /// Return up to `n` contacts closest to `target`, ordered by ascending
    /// distance. This is the core lookup primitive.
    pub fn closest(&self, target: &NodeId, n: usize) -> Vec<Contact> {
        let mut all: Vec<Contact> = self.buckets.iter()
            .flat_map(|b| b.contacts().iter().cloned())
            .collect();
        all.sort_by_key(|c| Distance::between(&c.id, target));
        all.truncate(n);
        all
    }

    /// Total contact count across all buckets.
    pub fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.contacts().len()).sum()
    }

    /// True if the table has no contacts.
    pub fn is_empty(&self) -> bool { self.len() == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    #[test]
    fn test_empty_table() {
        let t = RoutingTable::new(NodeId::generate());
        assert_eq!(t.len(), 0);
        assert!(t.is_empty());
        assert!(t.closest(&NodeId::generate(), 10).is_empty());
    }

    #[test]
    fn test_insert_self_is_noop() {
        let our_id = NodeId::generate();
        let mut t = RoutingTable::new(our_id);
        let _ = t.insert(Contact::new(our_id, addr(1), 7770));
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn test_insert_refresh() {
        let mut t = RoutingTable::new(NodeId::generate());
        let peer = NodeId::generate();
        let r1 = t.insert(Contact::new(peer, addr(1), 7770));
        assert!(matches!(r1, InsertResult::Inserted));
        let r2 = t.insert(Contact::new(peer, addr(2), 7770));
        assert!(matches!(r2, InsertResult::Refreshed));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn test_closest_returns_nearest() {
        let our_id = NodeId::from_bytes([0u8; 48]);
        let mut t = RoutingTable::new(our_id);
        for i in 1..=10 {
            let mut bytes = [0u8; 48];
            bytes[0] = i as u8;
            t.insert(Contact::new(NodeId::from_bytes(bytes), addr(1000 + i as u16), 7770));
        }
        let mut target_bytes = [0u8; 48];
        target_bytes[0] = 5;
        let target = NodeId::from_bytes(target_bytes);
        let closest = t.closest(&target, 3);
        assert_eq!(closest.len(), 3);
        // #5 is distance 0 from target → must be first.
        assert_eq!(closest[0].id.as_bytes()[0], 5);
    }

    #[test]
    fn test_bucket_full_reports_oldest() {
        let our_id = NodeId::from_bytes([0u8; 48]);
        let mut t = RoutingTable::new(our_id);
        // Force many into one bucket by keeping the same first bit (all in bucket 0).
        // Easy way: set byte 0 to 0x80..=0x80+20, all share bucket_index=0.
        for i in 0..K {
            let mut bytes = [0u8; 48];
            bytes[0] = 0x80;
            bytes[47] = i as u8; // differ in low bits to make IDs distinct
            let c = Contact::new(NodeId::from_bytes(bytes), addr(9000 + i as u16), 7770);
            t.insert(c);
        }
        // Insert one more — should return BucketFull with the oldest = first inserted.
        let mut bytes = [0u8; 48];
        bytes[0] = 0x80;
        bytes[47] = 200;
        let c = Contact::new(NodeId::from_bytes(bytes), addr(9100), 7770);
        let r = t.insert(c);
        match r {
            InsertResult::BucketFull { oldest } => assert_eq!(oldest.dht_addr.port(), 9000),
            other => panic!("expected BucketFull, got {other:?}"),
        }
    }

    #[test]
    fn test_remove() {
        let mut t = RoutingTable::new(NodeId::generate());
        let peer = NodeId::generate();
        t.insert(Contact::new(peer, addr(1), 7770));
        assert_eq!(t.len(), 1);
        assert!(t.remove(&peer));
        assert_eq!(t.len(), 0);
        assert!(!t.remove(&peer)); // second remove is false
    }
}
