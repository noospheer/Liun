//! # DHT node: server + iterative lookup client
//!
//! A `DhtNode` owns a UDP socket, a routing table, and an in-flight
//! request table. It runs a server task that handles incoming queries,
//! and exposes `find_node(target)` which performs an iterative Kademlia
//! lookup.
//!
//! ## Iterative FIND_NODE
//!
//! Given a target ID:
//! 1. Start with the α=3 closest known contacts.
//! 2. Send FIND to each in parallel.
//! 3. Each responds with up to K closer contacts.
//! 4. Add any new contacts to the candidate set.
//! 5. Pick the α closest un-queried candidates.
//! 6. Repeat until a round completes with no closer contact discovered.
//! 7. Return the K closest nodes seen.
//!
//! This converges in O(log N) rounds.

use crate::distance::Distance;
use crate::message::{contacts_to_wire, wire_to_contacts, Message, MessageKind};
use crate::routing::{Contact, InsertResult, RoutingTable, K};
use liun_receipts::{OpRecorder, Role, OP_DHT_QUERY};
use liuproto_core::identity::NodeId;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex};

/// Per-IP rate-limit window.
const RATE_WINDOW: Duration = Duration::from_secs(10);
/// Max incoming DHT queries per IP per RATE_WINDOW. 1000 / 10s = 100 qps —
/// far above legitimate steady-state (refresh is 1 per 5 min per peer),
/// tight enough to deter amplification + DoS.
const RATE_LIMIT_PER_WINDOW: u64 = 1000;
/// Cap on rate-limiter map size (LRU-evicted to prevent unbounded growth
/// under source-IP flooding).
const RATE_MAP_MAX_ENTRIES: usize = 10_000;

/// Kademlia parallelism parameter: how many queries per round.
pub const ALPHA: usize = 3;

/// Timeout for an individual RPC.
pub const RPC_TIMEOUT: Duration = Duration::from_secs(2);

/// Max datagram we'll accept.
const MAX_DATAGRAM: usize = 2048;

/// Runtime configuration for a DHT node.
#[derive(Clone)]
pub struct DhtConfig {
    pub our_id: NodeId,
    pub bind_addr: SocketAddr,
    /// TCP port on which we listen for Liun channel handshakes. Announced
    /// to peers in every DHT message so they can reach us at the right port.
    pub channel_port: u16,
}

impl DhtConfig {
    pub fn new(our_id: NodeId, bind_addr: SocketAddr, channel_port: u16) -> Self {
        Self { our_id, bind_addr, channel_port }
    }
}

/// Per-IP rate limit tracker entry.
struct RateEntry {
    window_start: Instant,
    count: u64,
}

/// Optional recorder hook. If set, the DHT credits each handled
/// PING/FIND query to a long-running session with the requester.
#[derive(Clone)]
pub struct DhtRecorderHook {
    pub recorder: Arc<OpRecorder>,
    pub epoch: u32,
}

/// Shared state between the server task and the client API.
struct Shared {
    table: Mutex<RoutingTable>,
    /// Map from txn_id to the waiting responder.
    pending: Mutex<HashMap<u32, oneshot::Sender<Message>>>,
    /// Per-source-IP rate limit state.
    rate_limit: Mutex<HashMap<IpAddr, RateEntry>>,
    socket: UdpSocket,
    /// Optional receipt tracking.
    recorder_hook: Option<DhtRecorderHook>,
    our_id: NodeId,
    our_channel_port: u16,
}

/// A DHT node handle. Clone to share across tasks; the server runs in the
/// background until the process exits (no shutdown channel yet — add if needed).
#[derive(Clone)]
pub struct DhtNode {
    shared: Arc<Shared>,
    next_txn: Arc<Mutex<u32>>,
}

impl DhtNode {
    /// Bind a UDP socket and start the server task. Returns the running node.
    pub async fn start(config: DhtConfig) -> std::io::Result<Self> {
        Self::start_with_recorder(config, None).await
    }

    /// Same as `start` but with a receipt recorder hook. Every handled
    /// query is credited to a long-running session with the requester;
    /// call `hook.recorder.flush_long_sessions(epoch)` on rollover.
    pub async fn start_with_recorder(
        config: DhtConfig,
        recorder_hook: Option<DhtRecorderHook>,
    ) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(config.bind_addr).await?;
        let shared = Arc::new(Shared {
            table: Mutex::new(RoutingTable::new(config.our_id)),
            pending: Mutex::new(HashMap::new()),
            rate_limit: Mutex::new(HashMap::new()),
            socket,
            recorder_hook,
            our_id: config.our_id,
            our_channel_port: config.channel_port,
        });
        let node = DhtNode {
            shared: shared.clone(),
            next_txn: Arc::new(Mutex::new(1)),
        };
        tokio::spawn(server_loop(shared));
        Ok(node)
    }

    /// The address we're bound to.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.shared.socket.local_addr()
    }

    /// Our node ID.
    pub fn our_id(&self) -> NodeId { self.shared.our_id }

    /// Manually add a bootstrap peer (someone we were told about out of band).
    /// Fires a PING to learn their real addr / confirm liveness. The seed's
    /// channel_port comes back via the PONG; we patch the routing table entry
    /// when it arrives (server_loop handles that).
    pub async fn bootstrap(&self, peer_id: NodeId, dht_addr: SocketAddr) -> Result<(), DhtError> {
        // Speculative insert with channel_port=0; will be corrected by PONG.
        self.shared.table.lock().await.insert(Contact::new(peer_id, dht_addr, 0));
        let _pong = self.send_ping(dht_addr).await?;
        Ok(())
    }

    /// Current routing-table size.
    pub async fn routing_size(&self) -> usize {
        self.shared.table.lock().await.len()
    }

    /// Snapshot all known contacts: `(id, dht_addr, channel_port)`. Use for persistence.
    pub async fn known_contacts(&self) -> Vec<(NodeId, SocketAddr, u16)> {
        let table = self.shared.table.lock().await;
        let snapshot = table.closest(&self.shared.our_id, usize::MAX);
        snapshot.into_iter().map(|c| (c.id, c.dht_addr, c.channel_port)).collect()
    }

    /// Seed the routing table with a batch of known peers (e.g. loaded from disk).
    /// Inserts without a network roundtrip — these are taken on faith. The next
    /// PING/FIND to each will confirm or evict them naturally.
    pub async fn seed_contacts(&self, peers: &[(NodeId, SocketAddr, u16)]) {
        let mut table = self.shared.table.lock().await;
        for (id, dht_addr, channel_port) in peers {
            let _ = table.insert(Contact::new(*id, *dht_addr, *channel_port));
        }
    }

    /// Insert a contact directly (e.g. after a successful Liun handshake at
    /// the channel layer — we now know this peer is alive at this addr).
    pub async fn note_contact(&self, id: NodeId, dht_addr: SocketAddr, channel_port: u16) {
        let mut table = self.shared.table.lock().await;
        table.insert(Contact::new(id, dht_addr, channel_port));
    }

    /// Iterative FIND_NODE: locate the K closest nodes to `target`.
    pub async fn find_node(&self, target: NodeId) -> Result<Vec<Contact>, DhtError> {
        // Seed the candidate set with what we already know.
        let mut candidates: Vec<Contact> = self.shared.table.lock().await.closest(&target, K * 2);
        if candidates.is_empty() {
            return Err(DhtError::RoutingTableEmpty);
        }

        let mut queried: HashSet<NodeId> = HashSet::new();
        queried.insert(self.shared.our_id);

        loop {
            // Pick α closest un-queried.
            candidates.sort_by_key(|c| Distance::between(&c.id, &target));
            let round: Vec<Contact> = candidates.iter()
                .filter(|c| !queried.contains(&c.id))
                .take(ALPHA)
                .cloned()
                .collect();
            if round.is_empty() { break; }

            // Record closest distance at start of round to detect convergence.
            let closest_before = Distance::between(&candidates[0].id, &target);

            // Send FIND to each in parallel.
            let mut handles = Vec::with_capacity(round.len());
            for c in &round {
                queried.insert(c.id);
                let me = self.clone();
                let target_copy = target;
                let addr = c.dht_addr;
                handles.push(tokio::spawn(async move {
                    me.send_find(addr, target_copy).await
                }));
            }

            // Collect responses.
            for h in handles {
                if let Ok(Ok(resp)) = h.await {
                    if let MessageKind::Nodes { contacts: wire } = resp.kind {
                        let new_contacts = wire_to_contacts(wire);
                        // Insert each into routing table + candidate set.
                        for nc in &new_contacts {
                            self.shared.table.lock().await.insert(nc.clone());
                            if !candidates.iter().any(|c| c.id == nc.id) {
                                candidates.push(nc.clone());
                            }
                        }
                    }
                }
                // Failed query: silently drop (responder will age out of routing).
            }

            // Convergence check: if the closest candidate didn't get closer, we're done.
            candidates.sort_by_key(|c| Distance::between(&c.id, &target));
            let closest_after = Distance::between(&candidates[0].id, &target);
            if closest_after >= closest_before {
                break;
            }
        }

        candidates.sort_by_key(|c| Distance::between(&c.id, &target));
        candidates.truncate(K);
        Ok(candidates)
    }

    async fn send_ping(&self, addr: SocketAddr) -> Result<Message, DhtError> {
        let txn_id = self.next_txn().await;
        let msg = Message {
            txn_id,
            sender_id: self.shared.our_id,
            sender_channel_port: self.shared.our_channel_port,
            kind: MessageKind::Ping,
        };
        self.send_and_await_response(addr, txn_id, msg).await
    }

    async fn send_find(&self, addr: SocketAddr, target: NodeId) -> Result<Message, DhtError> {
        let txn_id = self.next_txn().await;
        let msg = Message {
            txn_id,
            sender_id: self.shared.our_id,
            sender_channel_port: self.shared.our_channel_port,
            kind: MessageKind::Find { target },
        };
        self.send_and_await_response(addr, txn_id, msg).await
    }

    async fn send_and_await_response(
        &self,
        addr: SocketAddr,
        txn_id: u32,
        msg: Message,
    ) -> Result<Message, DhtError> {
        let (tx, rx) = oneshot::channel();
        self.shared.pending.lock().await.insert(txn_id, tx);
        let bytes = msg.encode();
        if let Err(e) = self.shared.socket.send_to(&bytes, addr).await {
            self.shared.pending.lock().await.remove(&txn_id);
            return Err(DhtError::Io(e));
        }
        match tokio::time::timeout(RPC_TIMEOUT, rx).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(_)) => {
                // responder dropped — shouldn't happen unless server_loop exited
                Err(DhtError::Timeout)
            }
            Err(_) => {
                self.shared.pending.lock().await.remove(&txn_id);
                Err(DhtError::Timeout)
            }
        }
    }

    async fn next_txn(&self) -> u32 {
        let mut t = self.next_txn.lock().await;
        *t = t.wrapping_add(1);
        if *t == 0 { *t = 1; }
        *t
    }
}

/// Errors from DHT operations.
#[derive(Debug)]
pub enum DhtError {
    Io(std::io::Error),
    Timeout,
    RoutingTableEmpty,
}

impl std::fmt::Display for DhtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Timeout => write!(f, "rpc timeout"),
            Self::RoutingTableEmpty => write!(f, "routing table empty — no peers to query"),
        }
    }
}

impl std::error::Error for DhtError {}

impl From<std::io::Error> for DhtError {
    fn from(e: std::io::Error) -> Self { Self::Io(e) }
}

/// Background task: read from the UDP socket, dispatch based on message kind.
async fn server_loop(shared: Arc<Shared>) {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let (n, src) = match shared.socket.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(_) => continue,
        };

        // Rate-limit per source IP before doing any parsing work.
        if rate_limit_check(&shared, src.ip()).await {
            continue; // drop silently — attacker learns nothing from drops
        }

        let msg = match Message::decode(&buf[..n]) {
            Ok(m) => m,
            Err(_) => continue,
        };

        // Observed-address insert: UDP source for dht_addr, claimed channel
        // port from the message body. The IP we observed; the channel port we
        // trust as a hint (worst case the dial fails and we retry).
        let contact = Contact::new(msg.sender_id, src, msg.sender_channel_port);
        if contact.id != shared.our_id {
            let _ = shared.table.lock().await.insert(contact);
        }

        match msg.kind {
            MessageKind::Ping => {
                let reply = Message {
                    txn_id: msg.txn_id,
                    sender_id: shared.our_id,
                    sender_channel_port: shared.our_channel_port,
                    kind: MessageKind::Pong,
                };
                let _ = shared.socket.send_to(&reply.encode(), src).await;
                credit_query(&shared, msg.sender_id);
            }
            MessageKind::Find { target } => {
                let closest = shared.table.lock().await.closest(&target, K);
                let reply = Message {
                    txn_id: msg.txn_id,
                    sender_id: shared.our_id,
                    sender_channel_port: shared.our_channel_port,
                    kind: MessageKind::Nodes { contacts: contacts_to_wire(&closest) },
                };
                let _ = shared.socket.send_to(&reply.encode(), src).await;
                credit_query(&shared, msg.sender_id);
            }
            MessageKind::Pong | MessageKind::Nodes { .. } => {
                // Response to a pending request — route to the waiting channel.
                if let Some(tx) = shared.pending.lock().await.remove(&msg.txn_id) {
                    let _ = tx.send(msg);
                }
            }
        }
    }
}

/// Credit one DHT query served to the requester under a long-running
/// session. No wire exchange; server side just bumps a counter.
/// Caller must periodically `flush_long_sessions(epoch)` on rollover.
fn credit_query(shared: &Arc<Shared>, requester: NodeId) {
    if let Some(hook) = &shared.recorder_hook {
        hook.recorder
            .observe_peer(requester, Role::Server, OP_DHT_QUERY, 1);
    }
}

/// Expose the recorder hook so callers (the node binary) can flush it
/// on epoch rollover and build batches.
impl DhtNode {
    pub fn recorder_hook(&self) -> Option<DhtRecorderHook> {
        self.shared.recorder_hook.clone()
    }
}

/// Unused; silence the dead_code warning for InsertResult re-export until we
/// use it in a higher layer.
#[allow(dead_code)]
fn _use_insert_result(ir: InsertResult) -> InsertResult { ir }

/// Check whether a packet from `src_ip` should be rate-limited. Returns
/// `true` to drop, `false` to process. Updates the per-IP window state.
///
/// Silently evicts old entries if the map grows beyond RATE_MAP_MAX_ENTRIES.
async fn rate_limit_check(shared: &Arc<Shared>, src_ip: IpAddr) -> bool {
    let now = Instant::now();
    let mut map = shared.rate_limit.lock().await;

    // Periodic eviction to prevent unbounded growth under source-IP flood.
    if map.len() > RATE_MAP_MAX_ENTRIES {
        map.retain(|_, e| now.duration_since(e.window_start) < RATE_WINDOW);
        // If eviction didn't help (all entries fresh), drop half by
        // walking the map — crude but bounded.
        if map.len() > RATE_MAP_MAX_ENTRIES {
            let drop_count = map.len() / 2;
            let to_remove: Vec<IpAddr> = map.keys().take(drop_count).copied().collect();
            for k in to_remove { map.remove(&k); }
        }
    }

    let entry = map.entry(src_ip).or_insert(RateEntry {
        window_start: now,
        count: 0,
    });
    if now.duration_since(entry.window_start) >= RATE_WINDOW {
        entry.window_start = now;
        entry.count = 1;
        false
    } else if entry.count >= RATE_LIMIT_PER_WINDOW {
        true // over limit, drop
    } else {
        entry.count += 1;
        false
    }
}
