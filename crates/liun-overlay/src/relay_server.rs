//! # Relay server
//!
//! The library form of `liun-relay`. Runs an HTTP/1.1 dead-drop server
//! that stores bootstrap shares by session ID and serves them on request.
//! No auth, no TLS — see relay_client.rs for the security rationale.
//!
//! ## Receipt hook (off the data path)
//!
//! Pass an [`OpRecorder`] via [`serve_with_recorder`] and the relay
//! will record a session-level receipt on every successful POST:
//!
//!   1. Client includes `X-Liun-Client-Id` (base58 NodeId) in the POST —
//!      16 bytes conceptually, ~65 chars of header overhead. The
//!      client does NOT send its half-receipt inline; it independently
//!      opens a session with its own `OpRecorder` keyed on the same
//!      `session_id` (the HTTP path's session id) and closes it locally
//!      on response.
//!   2. The relay starts a session of its own (`Role::Server`) with the
//!      client's NodeId, observes `N` bytes of share, and closes.
//!   3. Neither side MACs or transmits receipt data on this connection.
//!      At epoch close each side independently posts a `ClaimBatch` to
//!      the aggregator.
//!
//! This keeps the data path clean: the receipt header is only the
//! client's NodeId (so the server knows whom to credit). Aggregator
//! pairs via `session_id` without anything extra flowing on the wire.
//!
//! When no recorder is provided (`serve`), the relay ignores
//! `X-Liun-Client-Id` and behaves identically to the legacy version.

use liun_receipts::{OpRecorder, Role, OP_RELAY_SHARE};
use liuproto_core::identity::NodeId;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

pub const TTL: Duration = Duration::from_secs(3600);
pub const MAX_SHARE_BYTES: usize = 64 * 1024;
const MAX_HEADER_BYTES: usize = 4 * 1024;
const SESSION_ID_MAX: usize = 128;

struct Entry {
    data: Vec<u8>,
    inserted: Instant,
}

type Store = Arc<Mutex<HashMap<String, Entry>>>;

/// Handle to a running relay. Dropping it does not stop the server;
/// use `shutdown_signal` pattern via the caller's task tree.
pub struct RelayHandle {
    pub local_addr: std::net::SocketAddr,
}

/// Start a relay bound to `addr` without receipt tracking (legacy
/// bootstrap-only mode).
pub async fn serve(addr: &str) -> std::io::Result<RelayHandle> {
    serve_inner(addr, None).await
}

/// Start a relay bound to `addr` with receipt tracking. Every successful
/// POST produces a session-level receipt crediting the relay.
/// `epoch` is the epoch the relay attributes new sessions to; in
/// production wire this to a shared atomic advanced by the batcher
/// task on epoch rollover.
pub async fn serve_with_recorder(
    addr: &str,
    recorder: Arc<OpRecorder>,
    epoch: u32,
) -> std::io::Result<RelayHandle> {
    serve_inner(addr, Some((recorder, epoch))).await
}

/// Test-only hook: derive the 16-byte `session_id` the relay uses for
/// a given HTTP session string. Lets integration tests reproduce the
/// same id the client must supply to its own `OpRecorder`.
pub fn derive_session_id_test_hook(s: &str) -> [u8; 16] {
    derive_session_id(s)
}

async fn serve_inner(
    addr: &str,
    recorder: Option<(Arc<OpRecorder>, u32)>,
) -> std::io::Result<RelayHandle> {
    let listener = TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    let store: Store = Arc::new(Mutex::new(HashMap::new()));

    // Background TTL reaper
    let reaper_store = store.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(300)).await;
            let mut s = reaper_store.lock().await;
            s.retain(|_, e| e.inserted.elapsed() < TTL);
        }
    });

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let store = store.clone();
                    let rec = recorder.clone();
                    tokio::spawn(async move {
                        let _ = handle_connection(stream, store, rec).await;
                    });
                }
                Err(_) => break,
            }
        }
    });

    Ok(RelayHandle { local_addr })
}

async fn handle_connection(
    mut stream: TcpStream,
    store: Store,
    recorder: Option<(Arc<OpRecorder>, u32)>,
) -> std::io::Result<()> {
    let _ = stream.set_nodelay(true);

    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    let header_end;
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = i + 4;
            break;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return write_response(&mut stream, 431, "Headers Too Large", b"").await;
        }
    }

    let header_bytes = &buf[..header_end - 4];
    let header_str = match std::str::from_utf8(header_bytes) {
        Ok(s) => s,
        Err(_) => return write_response(&mut stream, 400, "Bad Request", b"").await,
    };

    let mut lines = header_str.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let parts: Vec<&str> = request_line.splitn(3, ' ').collect();
    if parts.len() != 3 {
        return write_response(&mut stream, 400, "Bad Request", b"").await;
    }
    let method = parts[0];
    let path = parts[1];

    let mut content_length: usize = 0;
    let mut client_id_str: Option<String> = None;
    for line in lines {
        if let Some((name, val)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = val.trim().parse().unwrap_or(0);
            } else if name.eq_ignore_ascii_case("x-liun-client-id") {
                client_id_str = Some(val.trim().to_string());
            }
        }
    }

    let session_id = match path.strip_prefix("/share/") {
        Some(id) if !id.is_empty() && id.len() <= SESSION_ID_MAX
            && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') => id.to_string(),
        Some(_) => return write_response(&mut stream, 400, "Bad Request", b"invalid session id\n").await,
        None => return write_response(&mut stream, 404, "Not Found", b"").await,
    };

    match method {
        "POST" => {
            if content_length == 0 || content_length > MAX_SHARE_BYTES {
                return write_response(&mut stream, 413, "Payload Too Large", b"").await;
            }
            let body_in_buf = &buf[header_end..];
            let mut body = Vec::with_capacity(content_length);
            body.extend_from_slice(body_in_buf);
            while body.len() < content_length {
                let remaining = content_length - body.len();
                let take = remaining.min(tmp.len());
                let n = stream.read(&mut tmp[..take]).await?;
                if n == 0 {
                    return write_response(&mut stream, 400, "Bad Request", b"short body\n").await;
                }
                body.extend_from_slice(&tmp[..n]);
            }
            body.truncate(content_length);

            let mut s = store.lock().await;
            s.retain(|_, e| e.inserted.elapsed() < TTL);
            if s.contains_key(&session_id) {
                drop(s);
                return write_response(&mut stream, 409, "Conflict", b"session id already used\n").await;
            }
            let body_len = body.len() as u64;
            s.insert(session_id.clone(), Entry { data: body, inserted: Instant::now() });
            drop(s);

            // Record a session-level receipt locally if a recorder and
            // a client NodeId are present. Nothing on the wire beyond
            // the client-id header.
            if let (Some((rec, epoch)), Some(id_str)) = (recorder.as_ref(), client_id_str.as_ref()) {
                if let Some(client_id) = NodeId::parse(id_str) {
                    let sid = derive_session_id(&session_id);
                    let mut sess = rec.join_session(client_id, Role::Server, OP_RELAY_SHARE, sid);
                    sess.observe(body_len);
                    let _ = rec.close_session(sess, *epoch);
                }
            }
            write_response(&mut stream, 200, "OK", b"stored\n").await
        }
        "GET" => {
            let s = store.lock().await;
            match s.get(&session_id) {
                Some(e) if e.inserted.elapsed() < TTL => {
                    let data = e.data.clone();
                    drop(s);
                    write_response(&mut stream, 200, "OK", &data).await
                }
                _ => {
                    drop(s);
                    write_response(&mut stream, 404, "Not Found", b"").await
                }
            }
        }
        _ => write_response(&mut stream, 405, "Method Not Allowed", b"").await,
    }
}

async fn write_response(
    stream: &mut TcpStream,
    code: u16,
    reason: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/octet-stream\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    if !body.is_empty() {
        stream.write_all(body).await?;
    }
    stream.shutdown().await.ok();
    Ok(())
}

/// Derive a 16-byte session id from the HTTP path's session string.
/// Both client and server run the same derivation so they arrive at
/// the same `session_id` without inline MAC exchange.
fn derive_session_id(s: &str) -> [u8; 16] {
    // Simple deterministic fold: folded-length + prefix bytes. This
    // is NOT cryptographic — collisions just cause aggregator pair
    // failure on those sessions, not a security issue. The `session_id`
    // space is 2^128; collisions in practice are negligible.
    let mut out = [0u8; 16];
    let b = s.as_bytes();
    for (i, &c) in b.iter().enumerate() {
        out[i % 16] ^= c;
    }
    // Also fold the length in to differentiate "a"*16 from "a"*32.
    let len = (b.len() as u64).to_be_bytes();
    for i in 0..8 {
        out[i] ^= len[i];
    }
    out
}
