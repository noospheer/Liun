//! # Admin HTTP interface
//!
//! Minimal built-in HTTP server for operational observability:
//! - `GET /health` → JSON `{status, uptime_s, identity, fingerprint, rng, its, dht_size}`
//! - `GET /metrics` → Prometheus text-format metrics
//!
//! By design this binds only when `--admin-listen <addr>` is passed; default
//! is off. Intended for local or tightly-scoped binding (e.g. `127.0.0.1:9090`
//! behind a monitoring agent, or a private container network).
//!
//! **No authentication on this endpoint.** Never bind it to a public interface
//! without a reverse proxy that enforces access control.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Shared, process-wide counters and gauges for observability.
pub struct Metrics {
    pub start_time: Instant,
    pub identity_b58: String,
    pub fingerprint: String,
    pub rng_mode: String,
    pub its: bool,

    // Counters (monotonic)
    pub dht_queries_received: AtomicU64,
    pub dht_responses_sent: AtomicU64,
    pub chat_messages_sent: AtomicU64,
    pub chat_messages_received: AtomicU64,
    pub chat_mac_failures: AtomicU64,
    pub liu_rounds_completed: AtomicU64,
    pub liu_round_failures: AtomicU64,
    pub rdseed_retries: AtomicU64,
    /// Total send attempts blocked by `PoolError::Exhausted`. Alert on
    /// growth: under steady-state traffic + correctly-sized pools this
    /// should stay at 0. Non-zero means users are seeing paused traffic.
    pub pool_exhausted_total: AtomicU64,

    // Gauges (live queries via closures/atomics where practical)
    pub dht_routing_size: AtomicU64,
    pub send_pool_bytes: AtomicU64,
    pub recv_pool_bytes: AtomicU64,
}

impl Metrics {
    pub fn new(identity_b58: String, fingerprint: String, rng_mode: &str, its: bool) -> Arc<Self> {
        Arc::new(Self {
            start_time: Instant::now(),
            identity_b58,
            fingerprint,
            rng_mode: rng_mode.to_string(),
            its,
            dht_queries_received: AtomicU64::new(0),
            dht_responses_sent: AtomicU64::new(0),
            chat_messages_sent: AtomicU64::new(0),
            chat_messages_received: AtomicU64::new(0),
            chat_mac_failures: AtomicU64::new(0),
            liu_rounds_completed: AtomicU64::new(0),
            liu_round_failures: AtomicU64::new(0),
            rdseed_retries: AtomicU64::new(0),
            pool_exhausted_total: AtomicU64::new(0),
            dht_routing_size: AtomicU64::new(0),
            send_pool_bytes: AtomicU64::new(0),
            recv_pool_bytes: AtomicU64::new(0),
        })
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    pub fn render_health_json(&self) -> String {
        format!(
            "{{\"status\":\"ok\",\"uptime_s\":{},\"identity\":\"{}\",\"fingerprint\":\"{}\",\
             \"rng\":\"{}\",\"its\":{},\"dht_routing_size\":{},\
             \"send_pool_bytes\":{},\"recv_pool_bytes\":{}}}",
            self.uptime_seconds(),
            self.identity_b58,
            self.fingerprint,
            self.rng_mode,
            self.its,
            self.dht_routing_size.load(Ordering::Relaxed),
            self.send_pool_bytes.load(Ordering::Relaxed),
            self.recv_pool_bytes.load(Ordering::Relaxed),
        )
    }

    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();
        out.push_str("# TYPE liun_uptime_seconds gauge\n");
        out.push_str(&format!("liun_uptime_seconds {}\n", self.uptime_seconds()));
        out.push_str("# TYPE liun_its gauge\n");
        out.push_str(&format!("liun_its {}\n", if self.its { 1 } else { 0 }));
        out.push_str("# TYPE liun_dht_routing_size gauge\n");
        out.push_str(&format!("liun_dht_routing_size {}\n",
            self.dht_routing_size.load(Ordering::Relaxed)));
        out.push_str("# TYPE liun_send_pool_bytes gauge\n");
        out.push_str(&format!("liun_send_pool_bytes {}\n",
            self.send_pool_bytes.load(Ordering::Relaxed)));
        out.push_str("# TYPE liun_recv_pool_bytes gauge\n");
        out.push_str(&format!("liun_recv_pool_bytes {}\n",
            self.recv_pool_bytes.load(Ordering::Relaxed)));
        out.push_str("# TYPE liun_pool_exhausted_total counter\n");
        out.push_str(&format!("liun_pool_exhausted_total {}\n",
            self.pool_exhausted_total.load(Ordering::Relaxed)));
        out.push_str("# TYPE liun_dht_queries_received_total counter\n");
        out.push_str(&format!("liun_dht_queries_received_total {}\n",
            self.dht_queries_received.load(Ordering::Relaxed)));
        out.push_str("# TYPE liun_dht_responses_sent_total counter\n");
        out.push_str(&format!("liun_dht_responses_sent_total {}\n",
            self.dht_responses_sent.load(Ordering::Relaxed)));
        out.push_str("# TYPE liun_chat_messages_sent_total counter\n");
        out.push_str(&format!("liun_chat_messages_sent_total {}\n",
            self.chat_messages_sent.load(Ordering::Relaxed)));
        out.push_str("# TYPE liun_chat_messages_received_total counter\n");
        out.push_str(&format!("liun_chat_messages_received_total {}\n",
            self.chat_messages_received.load(Ordering::Relaxed)));
        out.push_str("# TYPE liun_chat_mac_failures_total counter\n");
        out.push_str(&format!("liun_chat_mac_failures_total {}\n",
            self.chat_mac_failures.load(Ordering::Relaxed)));
        out.push_str("# TYPE liun_liu_rounds_total counter\n");
        out.push_str(&format!("liun_liu_rounds_total {}\n",
            self.liu_rounds_completed.load(Ordering::Relaxed)));
        out.push_str("# TYPE liun_liu_round_failures_total counter\n");
        out.push_str(&format!("liun_liu_round_failures_total {}\n",
            self.liu_round_failures.load(Ordering::Relaxed)));
        out.push_str("# TYPE liun_rdseed_retries_total counter\n");
        out.push_str(&format!("liun_rdseed_retries_total {}\n",
            self.rdseed_retries.load(Ordering::Relaxed)));
        out
    }
}

/// Start the admin HTTP server on `addr`. Returns immediately; serves on
/// spawned tasks until the process exits or the shutdown signal fires.
pub async fn serve(addr: &str, metrics: Arc<Metrics>) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    eprintln!("  admin: http://{local}/health  http://{local}/metrics");

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let m = metrics.clone();
                    tokio::spawn(async move {
                        let _ = handle_request(stream, m).await;
                    });
                }
                Err(_) => break,
            }
        }
    });

    Ok(())
}

async fn handle_request(mut stream: TcpStream, metrics: Arc<Metrics>) -> std::io::Result<()> {
    let _ = stream.set_nodelay(true);
    // Read request line + headers (bounded).
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 512];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 { return Ok(()); }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") { break; }
        if buf.len() > 4096 {
            return write_response(&mut stream, 431, "Headers Too Large",
                "text/plain", b"").await;
        }
    }

    let req = std::str::from_utf8(&buf).unwrap_or("");
    let first_line = req.lines().next().unwrap_or("");
    let path = first_line.split_whitespace().nth(1).unwrap_or("/");

    match path {
        "/health" => {
            let body = metrics.render_health_json();
            write_response(&mut stream, 200, "OK", "application/json", body.as_bytes()).await
        }
        "/metrics" => {
            let body = metrics.render_prometheus();
            write_response(&mut stream, 200, "OK", "text/plain; version=0.0.4",
                body.as_bytes()).await
        }
        _ => write_response(&mut stream, 404, "Not Found", "text/plain",
                b"liun-node admin: /health, /metrics\n").await,
    }
}

async fn write_response(
    stream: &mut TcpStream,
    code: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {content_type}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    if !body.is_empty() {
        stream.write_all(body).await?;
    }
    stream.shutdown().await.ok();
    Ok(())
}
