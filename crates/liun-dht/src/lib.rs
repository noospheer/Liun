//! # liun-dht: Kademlia DHT for node discovery
//!
//! Node-ID → IP:port lookups via XOR-distance routing.
//!
//! **Security model:** DHT entries are *unauthenticated hints*. Authenticity
//! is validated later by the Liun ITS handshake — if a DHT lookup returns the
//! wrong address, the handshake simply fails and the caller retries with the
//! next candidate. The DHT itself uses no signatures, so it survives the
//! post-computational-crypto transition: poisoning becomes a discoverability
//! nuisance, never a confidentiality or impersonation attack.
//!
//! **Scaling:** O(log N) lookup via iterative parallel queries. 384-bit IDs
//! (inherited from `liuproto_core::identity::NodeId`) give 384 k-buckets.
//! With K=20 per bucket, routing table size is O(K · log N) — ~400 entries
//! in a million-node network.

pub mod distance;
pub mod message;
pub mod node;
pub mod routing;

pub use distance::Distance;
pub use message::{Message, MessageKind};
pub use node::{DhtConfig, DhtNode, DhtRecorderHook};
pub use routing::{Contact, RoutingTable, K};
