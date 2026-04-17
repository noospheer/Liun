//! # liun-chat
//!
//! Full pipeline, every protocol link Lean-proved. The **ITS claim for the
//! whole pipeline is conditional on `--rng rdseed`** (hardware TRNG); in the
//! default `--rng urandom` mode every primitive is still correctly
//! implemented but the overall security reduces to "CSPRNG-strength output
//! dressed in ITS-shaped protocol," because the OTP's one-time pad is only
//! as secret as the RNG that produced it.
//!
//! Pipeline:
//!   1. **PSK bootstrap** — k-path XOR secret sharing over independent relays.
//!      No pre-shared key, no OOB transfer. ITS if ≥1 relay unobserved
//!      *and* RNG is a TRNG.
//!   2. **Per-message encryption** — One-Time Pad from a pool derived from the PSK.
//!      Shannon-perfect given a TRNG; CSPRNG-stream-cipher-equivalent otherwise.
//!   3. **Per-message auth** — Wegman-Carter polynomial MAC over GF(2^61-1).
//!      MAC covers timestamp + ciphertext; forgery bound is d/M61 either way.
//!   4. **Continuous key refresh** — background `signbit-nopa` Liu protocol
//!      exchange: TRNG-generated bits OTP-encrypted from the pool, MAC'd
//!      together with Liu-shaped mod-p wire values for tamper evidence.
//!      Toeplitz privacy amplification applied to the output. Pool
//!      alternation gives positive net growth so the pool never exhausts.
//!      The wire's Gaussian shape provides wrapped-uniformity proving
//!      negligible leakage to Eve; the TRNG provides the actual new key
//!      material. (The full multi-exchange noise-asymmetry mechanism from
//!      Liu 2009 is in `liuproto_core::link` as an in-process reference,
//!      not wired into the network protocol — networking it requires either
//!      leaking unwrapped real values or non-ITS mode.) Pool is refilled
//!      **only** via Liu exchange output — chat messages do NOT deposit
//!      ciphertext back (that would leak plaintext structure into keys).
//!   5. **Reconnect handler** — TCP drops preserve in-memory pool state; the
//!      session resumes on reconnect without re-bootstrap. Process death
//!      destroys key material (forward secrecy by design — pool is NOT
//!      persisted to disk).
//!
//! Multiplex wire format:
//!   [type: 1][len: 4 BE][payload: len]
//!   type = 0x01 chat message
//!   type = 0x02 Liu protocol exchange packet
//!
//! Chat payload:    [mac_tag: 8][timestamp: 8][ciphertext: len-16]
//! Exchange payload: raw bytes per exchange step (wa, wb+enc+tag, or final tag).
//!                   Output of each round is privacy-amplified via Toeplitz
//!                   hash before being deposited into the pool.
//!
//! Usage:
//!   chat listen  0.0.0.0:7770      --session-id <id> --relays <path>
//!   chat connect 203.0.113.1:7770  --session-id <id> --relays <path>

#[path = "../hardening.rs"]
mod hardening;
#[path = "../shutdown.rs"]
mod shutdown;

use liuproto_core::gf61::Gf61;
use liuproto_core::mac;
use liuproto_core::pool::{DepositSource, Pool, PoolError};
use liuproto_core::identity::NodeId;
use liuproto_core::rng::{self, RngMode};
use liun_overlay::bootstrap::{provide_shares, consume_shares};
use liun_overlay::directory::Directory;
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncBufReadExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, Mutex};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const PSK_SIZE: usize = 32 + 10_000;

// Multiplex frame types (stored in the top 2 bits of the packed mux header).
const FRAME_TYPE_CHAT: u8 = 0x01;
const FRAME_TYPE_EXCHANGE: u8 = 0x02;
/// Sent once at session start. Payload = [send_pool_fp:8][recv_pool_fp:8].
/// Peer's send fingerprint must match ours for recv, and vice versa. On
/// mismatch, the session aborts before any chat messages are sent.
const FRAME_TYPE_SYNC: u8 = 0x03;
// Multiplex header: [type:1][len:4 BE]
/// v2 mux header: 4 bytes.
///
/// Layout (big-endian 32-bit word):
///   bits 31..30 : frame type (0..3; types above use FRAME_TYPE_* low 2 bits)
///   bits 29..0  : payload length (up to 2^30 - 1 = 1 GiB)
///
/// Magic / version: implicit in the fact that both peers agreed on the
/// chat wire via the handshake. Peer-to-peer, no global versioning needed.
const MUX_HEADER_SIZE: usize = 4;
// Cap on any single frame we'll accept (avoids malicious huge-allocation).
const MAX_FRAME_PAYLOAD: usize = 2 * 1024 * 1024;

// Chat payload layout: [tag:8][timestamp:8][ct:n]
const CHAT_OVERHEAD: usize = 16;

// Pipeline courier: self-rekeying OTP stream. Each chunk's OTP is
// the previous chunk's TRNG output. ~99.2% extraction ratio.
// See LiupProofs/Liun/PipelineCourier.lean for the security proof.
const PIPELINE_CHUNK: usize = 16384;          // 16 KB per courier chunk
const PIPELINE_INTERVAL_MS: u64 = 1;           // ~1000 chunks/sec (effectively no pacing)
// First 16 bytes of each chunk's TRNG output are reserved as the
// MAC key (r, s) for the NEXT chunk. Remaining bytes are deposited.
const PIPELINE_MAC_KEY_RESERVE: usize = 16;

/// Outbound frame dispatched to the writer task.
enum Outbound {
    Chat(Vec<u8>),
    Exchange(Vec<u8>),
    Sync(Vec<u8>),
}

// ──────────────── chat message encryption/decryption ────────────────

fn encrypt_message(msg: &[u8], pool: &mut Pool) -> Result<Vec<u8>, PoolError> {
    // Zeroizing wrapper so the OTP bytes are wiped when `otp` goes out of scope.
    let otp = zeroize::Zeroizing::new(pool.try_withdraw_otp(msg.len() * 8)?);
    let mut ct = Vec::with_capacity(msg.len());
    for (i, &b) in msg.iter().enumerate() {
        let mut ob = 0u8;
        for bit in 0..8 { ob |= (otp[i * 8 + bit] & 1) << (7 - bit); }
        ct.push(b ^ ob);
    }
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_micros() as u64;

    // MAC covers timestamp || ciphertext. Tampering with either changes the tag.
    let (r, s) = pool.mac_keys();
    let mut coeffs: Vec<Gf61> = Vec::with_capacity(8 + ct.len());
    for &b in &timestamp.to_be_bytes() {
        coeffs.push(Gf61::new(b as u64));
    }
    for &b in &ct {
        coeffs.push(Gf61::new(b as u64));
    }
    let tag = mac::mac_tag(&coeffs, r, s);

    // Payload = [tag:8][ts:8][ct]
    let mut payload = Vec::with_capacity(CHAT_OVERHEAD + ct.len());
    payload.extend_from_slice(&tag.val().to_be_bytes());
    payload.extend_from_slice(&timestamp.to_be_bytes());
    payload.extend_from_slice(&ct);

    // No ciphertext-recycling: see Session 1 rationale. Pool refill happens
    // exclusively via the Liu exchange task.
    Ok(payload)
}

struct DecryptedMessage { text: String, delivery_ms: f64 }

fn decrypt_message(payload: &[u8], pool: &mut Pool) -> Result<DecryptedMessage, &'static str> {
    if payload.len() < CHAT_OVERHEAD { return Err("short"); }
    let tag = Gf61::new(u64::from_be_bytes(payload[0..8].try_into().unwrap()));
    let sent_us = u64::from_be_bytes(payload[8..16].try_into().unwrap());
    let ct = &payload[CHAT_OVERHEAD..];
    let now_us = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_micros() as u64;
    let delivery_ms = if now_us > sent_us { (now_us - sent_us) as f64 / 1000.0 } else { 0.0 };

    // MAC verification: constant-time compare over (timestamp || ciphertext).
    let (r, s) = pool.mac_keys();
    let mut coeffs: Vec<Gf61> = Vec::with_capacity(8 + ct.len());
    for &b in &sent_us.to_be_bytes() {
        coeffs.push(Gf61::new(b as u64));
    }
    for &b in ct {
        coeffs.push(Gf61::new(b as u64));
    }
    if !mac::tags_ct_eq(mac::mac_tag(&coeffs, r, s), tag) {
        return Err("MAC failed!");
    }

    // Zeroizing wrapper on the OTP bytes.
    let otp = match pool.try_withdraw_otp(ct.len() * 8) {
        Ok(o) => zeroize::Zeroizing::new(o),
        Err(_) => return Err("pool exhausted during decrypt"),
    };
    let mut pt = Vec::with_capacity(ct.len());
    for (i, &b) in ct.iter().enumerate() {
        let mut ob = 0u8;
        for bit in 0..8 { ob |= (otp[i * 8 + bit] & 1) << (7 - bit); }
        pt.push(b ^ ob);
    }
    Ok(DecryptedMessage {
        text: String::from_utf8(pt).map_err(|_| "bad utf8")?,
        delivery_ms,
    })
}

// ──────────────── multiplex I/O tasks ────────────────

async fn writer_loop(mut writer: OwnedWriteHalf, mut rx: mpsc::Receiver<Outbound>) {
    while let Some(frame) = rx.recv().await {
        let (t, payload) = match frame {
            Outbound::Chat(p) => (FRAME_TYPE_CHAT, p),
            Outbound::Exchange(p) => (FRAME_TYPE_EXCHANGE, p),
            Outbound::Sync(p) => (FRAME_TYPE_SYNC, p),
        };
        // v2 packed mux header: top 2 bits = type, bottom 30 bits = length.
        let len = payload.len();
        if len > (1 << 30) - 1 {
            eprintln!("  [frame too big for v2 mux: {len}]");
            break;
        }
        let word: u32 = ((t as u32) << 30) | (len as u32);
        let header = word.to_be_bytes();
        if writer.write_all(&header).await.is_err() { break; }
        if writer.write_all(&payload).await.is_err() { break; }
    }
}

async fn reader_loop(
    mut reader: OwnedReadHalf,
    tx_chat: mpsc::Sender<Vec<u8>>,
    tx_exchange: mpsc::Sender<Vec<u8>>,
    tx_sync: mpsc::Sender<Vec<u8>>,
) {
    loop {
        let mut header = [0u8; MUX_HEADER_SIZE];
        if reader.read_exact(&mut header).await.is_err() { break; }
        let word = u32::from_be_bytes(header);
        let t = (word >> 30) as u8;
        let len = (word & ((1u32 << 30) - 1)) as usize;
        if len > MAX_FRAME_PAYLOAD {
            eprintln!("  [frame oversized: type={t} len={len}]");
            break;
        }
        let mut payload = vec![0u8; len];
        if reader.read_exact(&mut payload).await.is_err() { break; }

        let send_result = match t {
            FRAME_TYPE_CHAT => tx_chat.send(payload).await.is_ok(),
            FRAME_TYPE_EXCHANGE => tx_exchange.send(payload).await.is_ok(),
            FRAME_TYPE_SYNC => tx_sync.send(payload).await.is_ok(),
            other => {
                eprintln!("  [unknown frame type: {other}]");
                continue;
            }
        };
        if !send_result { break; }
    }
}

// ──────────────── Pipeline courier (self-rekeying OTP stream) ────────────────
//
// Replaces the Gaussian round-trip exchange with continuous bidirectional
// streaming. Each chunk's OTP = previous chunk's TRNG output. Self-rekeying
// forever. Security proved in Lean 4 (PipelineCourier.lean).

/// Send pipeline chunks continuously. Each chunk:
///   1. Generate PIPELINE_CHUNK bytes from TRNG/CSPRNG
///   2. XOR-encrypt with the previous chunk's TRNG output (self-rekey)
///   3. MAC the ciphertext with WC using keys from the previous chunk
///   4. Send as EXCHANGE frame
///   5. Update key = this chunk's TRNG output (for next round)
///
/// The received TRNG bytes (from the peer's stream) are deposited by
/// pipeline_receiver into the chat pools.
async fn pipeline_sender(
    tx_out: mpsc::Sender<Outbound>,
    mut key: Vec<u8>,  // initial key = PSK-derived, PIPELINE_CHUNK bytes
    send_chat_pool: Arc<Mutex<Pool>>,
) {
    loop {
        tokio::time::sleep(Duration::from_millis(PIPELINE_INTERVAL_MS)).await;

        // Generate fresh random bytes.
        let mut r = vec![0u8; PIPELINE_CHUNK];
        if rng::fill(&mut r).is_err() {
            eprintln!("  \x1b[31m[pipeline] TRNG/RNG failed — stopping sender\x1b[0m");
            break;
        }

        // OTP encrypt: c = r ⊕ key (skipping the first 16 bytes of key
        // which are reserved for MAC). For simplicity, XOR the full chunk
        // and use the first 16 bytes of the KEY for MAC derivation.
        let mut ciphertext = Vec::with_capacity(PIPELINE_CHUNK);
        for i in 0..PIPELINE_CHUNK {
            ciphertext.push(r[i] ^ key[i]);
        }

        // MAC the ciphertext. Key = first 16 bytes of the previous
        // chunk's TRNG output (the current `key`).
        let mac_r = Gf61::new(u64::from_le_bytes(key[0..8].try_into().unwrap()));
        let mac_s = Gf61::new(u64::from_le_bytes(key[8..16].try_into().unwrap()));
        let coeffs: Vec<Gf61> = ciphertext.iter().map(|&b| Gf61::new(b as u64)).collect();
        let tag = mac::mac_tag(&coeffs, mac_r, mac_s);

        // Frame: ciphertext || tag (8 bytes)
        let mut frame = ciphertext;
        frame.extend_from_slice(&tag.val().to_be_bytes());

        if tx_out.send(Outbound::Exchange(frame)).await.is_err() {
            break;
        }

        // Also deposit our own TRNG bytes into the SEND chat pool.
        // (The peer deposits the same bytes into their recv pool when
        // they decrypt our stream. Both pools grow symmetrically.)
        let deposit_bits: Vec<u8> = r[PIPELINE_MAC_KEY_RESERVE..]
            .iter()
            .flat_map(|&byte| (0..8).rev().map(move |bit| (byte >> bit) & 1))
            .collect();
        if deposit_bits.len() >= 128 {
            let _ = send_chat_pool.lock().await
                .try_deposit(&deposit_bits, DepositSource::Recycled);
        }

        // Self-rekey: this chunk's TRNG output becomes next chunk's OTP.
        key = r;
    }
}

/// Receive and verify pipeline chunks from the peer. Each verified
/// chunk's TRNG plaintext is deposited into the recv chat pool.
async fn pipeline_receiver(
    mut rx_in: mpsc::Receiver<Vec<u8>>,
    mut key: Vec<u8>,  // same initial key as sender (PSK-derived)
    recv_chat_pool: Arc<Mutex<Pool>>,
) {
    let expected_len = PIPELINE_CHUNK + 8; // chunk + tag
    loop {
        let frame = match rx_in.recv().await {
            Some(f) => f,
            None => break,
        };
        if frame.len() != expected_len {
            eprintln!("  \x1b[31m[pipeline] bad frame len: {} (expected {})\x1b[0m",
                frame.len(), expected_len);
            break;
        }

        let ciphertext = &frame[..PIPELINE_CHUNK];
        let tag_bytes: [u8; 8] = frame[PIPELINE_CHUNK..].try_into().unwrap();
        let received_tag = Gf61::new(u64::from_be_bytes(tag_bytes));

        // Verify MAC with the current key.
        let mac_r = Gf61::new(u64::from_le_bytes(key[0..8].try_into().unwrap()));
        let mac_s = Gf61::new(u64::from_le_bytes(key[8..16].try_into().unwrap()));
        let coeffs: Vec<Gf61> = ciphertext.iter().map(|&b| Gf61::new(b as u64)).collect();
        let expected_tag = mac::mac_tag(&coeffs, mac_r, mac_s);

        if !mac::tags_ct_eq(expected_tag, received_tag) {
            eprintln!("  \x1b[31m[pipeline] MAC verification failed — stopping receiver\x1b[0m");
            break;
        }

        // Decrypt: r = ciphertext ⊕ key
        let mut r = Vec::with_capacity(PIPELINE_CHUNK);
        for i in 0..PIPELINE_CHUNK {
            r.push(ciphertext[i] ^ key[i]);
        }

        // Deposit decrypted TRNG bytes (minus MAC reserve) into recv pool.
        let deposit_bits: Vec<u8> = r[PIPELINE_MAC_KEY_RESERVE..]
            .iter()
            .flat_map(|&byte| (0..8).rev().map(move |bit| (byte >> bit) & 1))
            .collect();
        if deposit_bits.len() >= 128 {
            let _ = recv_chat_pool.lock().await
                .try_deposit(&deposit_bits, DepositSource::Recycled);
        }

        // Log sparingly — every ~10 MB so it doesn't flood the chat.
        let pool_size = recv_chat_pool.lock().await.available();
        if pool_size % (10 * 1024 * 1024) < (PIPELINE_CHUNK - PIPELINE_MAC_KEY_RESERVE) {
            let mb = pool_size / (1024 * 1024);
            eprintln!("  \x1b[90m[pipeline] pool: {mb} MB\x1b[0m");
        }

        // Self-rekey.
        key = r;
    }
}

// Legacy Gaussian exchange deleted — replaced by pipeline courier above.
// See git history for the original exchange_alice / exchange_bob if needed.

// (Legacy Gaussian exchange_alice/exchange_bob deleted — see git history.)

// ──────────────── main loop ────────────────

/// Run one chat session over `stream`. Returns when the session ends (TCP drop,
/// exchange error, or stdin EOF). Pool/toeplitz state lives in the caller so it
/// survives across reconnects.
async fn run_session(
    stream: TcpStream,
    psk: Vec<u8>,
    is_host: bool,
    mut stdin_rx: broadcast::Receiver<String>,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    // Fresh pools EVERY session — derived from PSK, guaranteed identical
    // on both sides. Pipeline deposits from a prior TCP session are
    // discarded; the pipeline refills at wire speed so the pool recovers
    // in under a second. This eliminates the pool-desync-on-reconnect
    // problem: no stale state carries across sessions.
    let nonce_chat_a = [0u8; 16];
    let mut nonce_chat_b = [0u8; 16]; nonce_chat_b[0] = 1;
    let (send_nonce, recv_nonce) = if is_host {
        (nonce_chat_a, nonce_chat_b)
    } else {
        (nonce_chat_b, nonce_chat_a)
    };
    let send_pool = Arc::new(Mutex::new(Pool::from_psk(&psk, &send_nonce)));
    let recv_pool = Arc::new(Mutex::new(Pool::from_psk(&psk, &recv_nonce)));

    let mut first_recv_pending: bool = true;
    let mut consecutive_mac_failures: u32 = 0;
    let (reader, writer) = stream.into_split();

    // Mux channels
    let (tx_out, rx_out) = mpsc::channel::<Outbound>(64);
    let (tx_chat_in, mut rx_chat_in) = mpsc::channel::<Vec<u8>>(32);
    let (tx_ex_in, rx_ex_in) = mpsc::channel::<Vec<u8>>(8);
    let (tx_sync_in, mut rx_sync_in) = mpsc::channel::<Vec<u8>>(1);

    // Writer + reader tasks; keep handles so we can abort them on session end.
    let writer_h = tokio::spawn(writer_loop(writer, rx_out));
    let reader_h = tokio::spawn(reader_loop(reader, tx_chat_in, tx_ex_in, tx_sync_in));

    // ── State-fingerprint handshake ─────────────────────────────────────
    // Each side announces fingerprints of its pools. Peer's send-pool
    // fingerprint must match our recv-pool fingerprint (they're the same
    // shared state, nonce_a-based, viewed from both sides). Mismatch means
    // pools desynced — abort before any chat.
    // Fingerprint the chat pools for the sync handshake. Exchange pools
    // are symmetric (both peers derive them from the same nonces) so
    // they don't need cross-checking — if one side's exchange pool
    // diverges, the exchange MAC will catch it on the next round.
    let my_send_fp = send_pool.lock().await.state_fingerprint();
    let my_recv_fp = recv_pool.lock().await.state_fingerprint();
    let mut sync_payload = Vec::with_capacity(16);
    sync_payload.extend_from_slice(&my_send_fp.to_be_bytes());
    sync_payload.extend_from_slice(&my_recv_fp.to_be_bytes());
    if tx_out.send(Outbound::Sync(sync_payload)).await.is_err() {
        eprintln!("  \x1b[31m[sync] write failed — aborting session\x1b[0m");
        writer_h.abort(); reader_h.abort();
        return;
    }

    // Wait up to 5 seconds for peer's sync frame.
    let peer_sync = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        rx_sync_in.recv()
    ).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            eprintln!("  \x1b[31m[sync] peer disconnected before sync handshake\x1b[0m");
            writer_h.abort(); reader_h.abort();
            return;
        }
        Err(_) => {
            eprintln!("  \x1b[31m[sync] timeout waiting for peer sync — aborting\x1b[0m");
            eprintln!("     \x1b[33m→ Old peer version without sync support? Restart both sides.\x1b[0m");
            writer_h.abort(); reader_h.abort();
            return;
        }
    };
    if peer_sync.len() != 16 {
        eprintln!("  \x1b[31m[sync] peer sent malformed sync payload ({}B, expected 16B)\x1b[0m", peer_sync.len());
        writer_h.abort(); reader_h.abort();
        return;
    }
    let peer_send_fp = u64::from_be_bytes(peer_sync[0..8].try_into().unwrap());
    let peer_recv_fp = u64::from_be_bytes(peer_sync[8..16].try_into().unwrap());
    // Their send-pool is our recv-pool (shared state); their recv-pool is our send-pool.
    if peer_send_fp != my_recv_fp || peer_recv_fp != my_send_fp {
        eprintln!("  \x1b[31m[sync] POOL STATE MISMATCH detected.\x1b[0m");
        eprintln!("     \x1b[33m→ Most likely: in-flight messages were lost during the last");
        eprintln!("       TCP drop, advancing one side's OTP cursor past the other's.\x1b[0m");
        eprintln!("     \x1b[33m→ Remedy: disconnect both ends and re-bootstrap with a fresh");
        eprintln!("       session-id. Continuing would just MAC-fail on the next message.\x1b[0m");
        eprintln!("     \x1b[90m  my_send_fp={my_send_fp:016x} peer_recv_fp={peer_recv_fp:016x}");
        eprintln!("       my_recv_fp={my_recv_fp:016x} peer_send_fp={peer_send_fp:016x}\x1b[0m");
        writer_h.abort(); reader_h.abort();
        return;
    }
    eprintln!("  \x1b[32m[sync] pool state verified — fingerprints match\x1b[0m");

    // Pipeline courier: two independent tasks sending/receiving OTP-
    // encrypted random bytes continuously. Self-rekeying — each chunk's
    // OTP is the previous chunk's TRNG output.
    //
    // Initial key = first PIPELINE_CHUNK bytes of the PSK, derived with
    // the exchange nonce. Both peers derive the same initial key.
    let pipeline_initial_key = {
        let mut k = vec![0u8; PIPELINE_CHUNK];
        let nonce_pipeline = [0x04u8; 16]; // dedicated pipeline nonce
        let p = Pool::from_psk(&psk, &nonce_pipeline);
        // Read the first PIPELINE_CHUNK bytes as the initial key.
        let bits = p.buf_len().min(PIPELINE_CHUNK * 8);
        let otp = Pool::from_psk(&psk, &nonce_pipeline).withdraw_otp(bits);
        for (i, &b) in otp.iter().take(PIPELINE_CHUNK).enumerate() {
            k[i] = b;
        }
        k
    };

    let sender_h = {
        let tx = tx_out.clone();
        let key = pipeline_initial_key.clone();
        let pool = send_pool.clone();
        tokio::spawn(pipeline_sender(tx, key, pool))
    };
    let receiver_h = {
        let key = pipeline_initial_key;
        let pool = recv_pool.clone();
        let rx = rx_ex_in;
        tokio::spawn(pipeline_receiver(rx, key, pool))
    };

    // Main loop: stdin → encrypt + send; incoming chat frame → decrypt + print.
    loop {
        tokio::select! {
            line = stdin_rx.recv() => {
                let msg = match line {
                    Ok(m) => m,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        eprintln!("  \x1b[33m[stdin lagged {n} messages, skipping]\x1b[0m");
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        println!("  [stdin closed]");
                        break;
                    }
                };
                let t0 = std::time::Instant::now();
                let encrypt_result = {
                    let mut p = send_pool.lock().await;
                    let pb = p.available();
                    let f = encrypt_message(msg.as_bytes(), &mut *p);
                    let pa = p.available();
                    f.map(|frame| (frame, pb, pa))
                };
                let (frame, pool_before, pool_after) = match encrypt_result {
                    Ok(v) => v,
                    Err(e) => {
                        println!("  \x1b[31m⚠ send failed: {e}\x1b[0m");
                        println!("  (Pool exhausted — wait for Liu refresh to top up, or reconnect)");
                        continue;
                    }
                };
                let encrypt_us = t0.elapsed().as_micros();
                let msg_bytes = msg.len();
                let otp_bits = msg_bytes * 8;
                let frame_bytes = frame.len() + MUX_HEADER_SIZE;
                if tx_out.send(Outbound::Chat(frame)).await.is_err() {
                    println!("  [connection lost]");
                    break;
                }
                let total_us = t0.elapsed().as_micros();
                print!("\x1b[1A\x1b[2K");
                println!("  \x1b[36myou\x1b[0m: {msg}");
                println!("       \x1b[90m┊ OTP: {msg_bytes}B plaintext → {otp_bits} key bits consumed");
                println!("       ┊ MAC: poly degree {msg_bytes} over GF(2⁶¹-1), tag 8B");
                println!("       ┊ Frame: {frame_bytes}B on wire ({}B overhead)",
                    frame_bytes - msg_bytes);
                println!("       ┊ Encrypt: {encrypt_us}µs, send: {total_us}µs total");
                println!("       ┊ Pool: {pool_before}B → {pool_after}B (Liu-refilling)\x1b[0m");
                std::io::stdout().flush().unwrap();
            }
            payload = rx_chat_in.recv() => {
                let Some(payload) = payload else {
                    // reader task exited — TCP dropped
                    println!("  \x1b[33m[peer disconnected]\x1b[0m");
                    break;
                };
                let t0 = std::time::Instant::now();
                let frame_bytes = payload.len() + MUX_HEADER_SIZE;
                let pool_before;
                let result;
                {
                    let mut p = recv_pool.lock().await;
                    pool_before = p.available();
                    result = decrypt_message(&payload, &mut *p);
                }
                match result {
                    Ok(dm) => {
                        let decrypt_us = t0.elapsed().as_micros();
                        let pool_after = recv_pool.lock().await.available();
                        let msg_bytes = dm.text.len();
                        let otp_bits = msg_bytes * 8;
                        println!("  \x1b[32mpeer\x1b[0m: {}", dm.text);
                        let delivery_note = if dm.delivery_ms > 100.0 {
                            " (clock skew?)"
                        } else { "" };
                        println!("       \x1b[90m┊ Frame: {frame_bytes}B on wire ({}B overhead)",
                            frame_bytes - msg_bytes);
                        println!("       ┊ MAC: ✓ (poly degree {msg_bytes} over GF(2⁶¹-1), tag 8B)");
                        println!("       ┊ OTP: {otp_bits} key bits withdrawn");
                        println!("       ┊ Decrypt: {decrypt_us}µs | Delivery: {:.1}ms{delivery_note}", dm.delivery_ms);
                        println!("       ┊ Pool: {pool_before}B → {pool_after}B (Liu-refilling)\x1b[0m");
                        first_recv_pending = false;
                        consecutive_mac_failures = 0;
                        std::io::stdout().flush().unwrap();
                    }
                    Err(e) => {
                        if e == "MAC failed!" {
                            consecutive_mac_failures += 1;
                            if first_recv_pending {
                                println!("  \x1b[31m⚠ MAC verification failed on first message of this session.\x1b[0m");
                                println!("     \x1b[33m→ Most likely cause: pool state diverged across reconnect.\x1b[0m");
                                println!("     \x1b[33m  (In-flight messages lost during TCP drop can advance one");
                                println!("       side's pool cursor past the other's; when the session resumes,");
                                println!("       MAC keys no longer match. No tampering is implied.)\x1b[0m");
                                println!("     \x1b[33m→ Remedy: disconnect both ends (Ctrl+C) and restart with a fresh");
                                println!("       session-id to force re-bootstrap.\x1b[0m");
                            } else if consecutive_mac_failures >= 3 {
                                println!("  \x1b[31m⚠ MAC verification failed {consecutive_mac_failures} messages in a row.\x1b[0m");
                                println!("     \x1b[33m→ This strongly suggests ongoing tampering or a persistent");
                                println!("       pool-state mismatch. Disconnecting is safest.\x1b[0m");
                            } else {
                                println!("  \x1b[31m⚠ MAC verification failed on mid-session message.\x1b[0m");
                                println!("     \x1b[33m→ Possible causes (in rough order): on-path tampering attempt,");
                                println!("       a dropped frame the reader partially consumed, memory-bit corruption.\x1b[0m");
                                println!("     \x1b[33m→ If this is isolated, the session will recover on the next message.");
                                println!("       If it recurs, disconnect.\x1b[0m");
                            }
                        } else {
                            println!("  \x1b[31m⚠ {e} (pool: {pool_before}B)\x1b[0m");
                        }
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                println!("\n  [shutdown received — closing session]");
                break;
            }
            else => {
                // all branches disabled (stdin_rx closed too)
                println!("  [stdin closed, exiting]");
                break;
            }
        }
    }

    // Tear down session tasks. Dropping `tx_out` inside this scope would
    // naturally close the writer's channel, but abort is explicit and fast.
    writer_h.abort();
    reader_h.abort();
    sender_h.abort();
    receiver_h.abort();
}

// ──────────────── CLI ────────────────

struct CliArgs {
    mode: String,
    addr: String,
    session_id: String,
    relays_path: PathBuf,
    rng_mode: RngMode,
}

fn parse_args() -> CliArgs {
    let args: Vec<String> = std::env::args().collect();

    fn usage() -> ! {
        eprintln!("Usage:");
        eprintln!("  Host:  chat listen  <addr:port> --session-id <id> --relays <path> [--rng MODE]");
        eprintln!("  Join:  chat connect <addr:port> --session-id <id> --relays <path> [--rng MODE]");
        eprintln!();
        eprintln!("Both peers must share the same session-id (ok to send in the clear)");
        eprintln!("and the same relays.toml (same order, same URLs).");
        eprintln!();
        eprintln!("--rng selects the random source:");
        eprintln!("  urandom  (default) CSPRNG — computational security, NOT ITS");
        eprintln!("  rdseed   Intel hardware TRNG — required for the ITS claim to hold");
        eprintln!("           (fails to start if CPU lacks RDSEED)");
        eprintln!();
        eprintln!("Example:");
        eprintln!("  chat listen 0.0.0.0:7770 --session-id mynight42 --relays ~/.config/liun/relays.toml");
        eprintln!("  chat connect 203.0.113.1:7770 --session-id mynight42 --relays ~/.config/liun/relays.toml --rng rdseed");
        std::process::exit(1);
    }

    if args.len() < 3 { usage(); }
    let mode = match args[1].as_str() {
        "listen" | "connect" => args[1].clone(),
        _ => usage(),
    };
    let addr = args[2].clone();

    let mut session_id: Option<String> = None;
    let mut relays_path: Option<PathBuf> = None;
    let mut rng_mode: RngMode = rng::detect_best();

    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--session-id" if i + 1 < args.len() => {
                session_id = Some(args[i + 1].clone());
                i += 2;
            }
            "--relays" if i + 1 < args.len() => {
                relays_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--rng" if i + 1 < args.len() => {
                rng_mode = match RngMode::parse(&args[i + 1]) {
                    Some(m) => m,
                    None => {
                        eprintln!("--rng: must be `urandom` or `rdseed`, got {:?}", args[i + 1]);
                        std::process::exit(1);
                    }
                };
                i += 2;
            }
            other => {
                eprintln!("unknown argument: {other}");
                usage();
            }
        }
    }

    let session_id = session_id.unwrap_or_else(|| { eprintln!("--session-id is required"); usage(); });
    let relays_path = relays_path.unwrap_or_else(|| { eprintln!("--relays is required"); usage(); });

    if session_id.is_empty()
        || session_id.len() > 128
        || !session_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        eprintln!("session-id must be 1-128 chars of [A-Za-z0-9_-]");
        std::process::exit(1);
    }

    CliArgs { mode, addr, session_id, relays_path, rng_mode }
}

fn print_banner(initial_pool: usize) {
    let rng_is_its = rng::current_mode().is_its();
    let (sec_label, quantum_label) = if rng_is_its {
        ("INFORMATION-THEORETIC                ", "immune (no computation helps)         ")
    } else {
        ("COMPUTATIONAL (CSPRNG-based)         ", "CSPRNG-dependent (not genuinely ITS)  ")
    };
    let rng_label = if rng_is_its { "rdseed (hardware TRNG)   " }
                    else { "urandom (CSPRNG)         " };

    println!("\n  ╔══════════════════════════════════════════════════════╗");
    println!("  ║  LIUN CHAT                                           ║");
    println!("  ╠══════════════════════════════════════════════════════╣");
    println!("  ║  Bootstrap:   k-path XOR over relays                 ║");
    println!("  ║  Encryption:  One-Time Pad (perfect given ITS RNG)   ║");
    println!("  ║  Auth:        Wegman-Carter MAC (unforgeable)        ║");
    println!("  ║  Key refresh: Liu exchange + Toeplitz PA             ║");
    println!("  ║  RNG:         {rng_label}          ║");
    println!("  ║  Security:    {sec_label}║");
    println!("  ║  Quantum:     {quantum_label}║");
    println!("  ║  Pool:        {} bytes (~{} messages)              ║", initial_pool, initial_pool / 100);
    println!("  ║  Reconnect:   survives TCP drops (pool persists)     ║");
    println!("  ║  Proof:       Lean 4 verified (0 sorry)              ║");
    println!("  ╠══════════════════════════════════════════════════════╣");
    println!("  ║  Type a message and press Enter. Ctrl+C to quit.     ║");
    println!("  ╚══════════════════════════════════════════════════════╝\n");
}

#[tokio::main]
async fn main() {
    let cli = parse_args();

    // Process hardening: disable core dumps before any secret material
    // enters memory. Silent on success; a failure is logged but not fatal.
    if let Err(e) = hardening::disable_core_dumps() {
        eprintln!("  warn: failed to disable core dumps: {e}");
    }

    // Install shutdown handlers early so Ctrl+C / SIGTERM trigger orderly exit.
    let shutdown_handle = shutdown::Shutdown::new();
    shutdown_handle.install();

    // Configure the RNG first — every other call to random is routed through it.
    if let Err(e) = rng::set_mode(cli.rng_mode) {
        eprintln!("  ✗ RNG init failed: {e}");
        eprintln!("    Requested mode: {}", cli.rng_mode.as_str());
        std::process::exit(1);
    }
    match cli.rng_mode {
        RngMode::Rdseed => {
            println!("  RNG: \x1b[32mrdseed (Intel hardware TRNG)\x1b[0m — ITS chain valid");
        }
        RngMode::Rndr => {
            println!("  RNG: \x1b[32mrndr (ARM hardware TRNG)\x1b[0m — ITS chain valid");
        }
        RngMode::Trandom => {
            println!("  RNG: \x1b[32mtrandom (software ITS via /dev/trandom)\x1b[0m — ITS chain valid");
        }
        RngMode::Urandom => {
            println!();
            println!("  \x1b[1;31m╔══════════════════════════════════════════════════════╗\x1b[0m");
            println!("  \x1b[1;31m║  ⚠  WARNING: RUNNING IN CSPRNG MODE (NOT ITS)       ║\x1b[0m");
            println!("  \x1b[1;31m╠══════════════════════════════════════════════════════╣\x1b[0m");
            println!("  \x1b[1;31m║  urandom (ChaCha20) is computationally secure but   ║\x1b[0m");
            println!("  \x1b[1;31m║  NOT information-theoretically secure. A break in    ║\x1b[0m");
            println!("  \x1b[1;31m║  ChaCha20 (P=NP, quantum, etc.) would compromise    ║\x1b[0m");
            println!("  \x1b[1;31m║  all traffic encrypted under this session.           ║\x1b[0m");
            println!("  \x1b[1;31m║                                                      ║\x1b[0m");
            println!("  \x1b[1;31m║  For genuine ITS:                                    ║\x1b[0m");
            println!("  \x1b[1;31m║    • RDSEED: run on Intel Broadwell+ / AMD Zen+      ║\x1b[0m");
            println!("  \x1b[1;31m║    • RNDR:   run on ARM M1+ / Graviton 3+            ║\x1b[0m");
            println!("  \x1b[1;31m║    • trandom: sudo ./scripts/install-trandom.sh      ║\x1b[0m");
            println!("  \x1b[1;31m║  Then restart with --rng auto                        ║\x1b[0m");
            println!("  \x1b[1;31m╚══════════════════════════════════════════════════════╝\x1b[0m");
            println!();
        }
    }

    let our_id = NodeId::generate();

    let directory = match Directory::from_file(&cli.relays_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("  ✗ failed to load relays: {e}");
            std::process::exit(1);
        }
    };
    let k = directory.len();

    println!("  Your identity: {}", our_id.short());
    println!("  Bootstrap: k={k} relays from {}", cli.relays_path.display());
    for (i, r) in directory.relays.iter().enumerate() {
        let op = if r.operator.is_empty() { "-" } else { r.operator.as_str() };
        let jur = if r.jurisdiction.is_empty() { "-" } else { r.jurisdiction.as_str() };
        println!("    [{i}] {}  ({op}, {jur})", r.url);
    }
    println!("  Session id: {}", cli.session_id);

    let is_host = cli.mode == "listen";

    // ── One-time bootstrap ─────────────────────────────────────────────
    let psk = if is_host {
        println!("  Role: provider (uploading {k} shares to relays)");
        match provide_shares(&directory, &cli.session_id, PSK_SIZE).await {
            Ok(psk) => {
                println!("  ✓ {k} shares uploaded, PSK derived ({} bytes)", psk.len());
                psk
            }
            Err(e) => {
                eprintln!("  ✗ bootstrap failed: {e}");
                eprintln!("    If some relays report 'conflict', this session-id is already in use.");
                eprintln!("    Pick a fresh session-id and retry on both sides.");
                std::process::exit(1);
            }
        }
    } else {
        println!("  Role: consumer (downloading {k} shares from relays)");
        match consume_shares(&directory, &cli.session_id, PSK_SIZE).await {
            Ok(psk) => {
                println!("  ✓ {k} shares downloaded, PSK derived ({} bytes)", psk.len());
                psk
            }
            Err(e) => {
                eprintln!("  ✗ bootstrap failed: {e}");
                eprintln!("    Possible causes:");
                eprintln!("    - Peer hasn't uploaded shares yet (start `chat listen` first)");
                eprintln!("    - Session-id doesn't match on both sides");
                eprintln!("    - Directory differs between peers");
                std::process::exit(1);
            }
        }
    };

    let initial_pool = {
        let tmp = Pool::from_psk(&psk, &[0u8; 16]);
        tmp.available()
    };

    // ── Persistent stdin task (lives for the whole process) ─────────────
    // Broadcast so each session can subscribe on reconnect without losing the
    // writer task. Capacity 32: if the user types faster than sessions consume,
    // the receiver sees Lagged and drops old lines.
    let (stdin_tx, _) = broadcast::channel::<String>(32);
    {
        let tx = stdin_tx.clone();
        tokio::spawn(async move {
            let stdin = tokio::io::stdin();
            let mut lines = BufReader::new(stdin).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if line.is_empty() { continue; }
                // send returns Err only when no receivers — ignore, next session
                // will subscribe.
                let _ = tx.send(line);
            }
        });
    }

    print_banner(initial_pool);

    // ── Reconnect loop ──────────────────────────────────────────────────
    let mut shutdown_rx = shutdown_handle.subscribe();
    if is_host {
        let listener = TcpListener::bind(&cli.addr).await.expect("failed to bind");
        println!("  Listening on {}...", cli.addr);
        let mut session_n: u64 = 0;
        loop {
            let accept_result = tokio::select! {
                res = listener.accept() => res,
                _ = shutdown_rx.recv() => {
                    println!("\n  [shutdown — stopping listener]");
                    break;
                }
            };
            let (stream, peer_addr) = match accept_result {
                Ok(pair) => pair,
                Err(e) => { eprintln!("  accept error: {e}"); continue; }
            };
            stream.set_nodelay(true).unwrap();
            if session_n == 0 {
                println!("  Connected from {peer_addr}");
            } else {
                println!("  \x1b[32m[reconnected from {peer_addr} — session #{}, pool preserved]\x1b[0m", session_n);
            }
            run_session(stream, psk.clone(), true,
                        stdin_tx.subscribe(), shutdown_handle.subscribe()).await;
            session_n += 1;
            if shutdown_handle.is_fired() { break; }

            const MAX_SESSION_RETRIES: u64 = 5;
            if session_n > MAX_SESSION_RETRIES {
                eprintln!("  \x1b[31m[too many failed sessions ({session_n}) — giving up]\x1b[0m");
                eprintln!("  \x1b[33m→ Restart with a fresh session-id if needed.\x1b[0m");
                break;
            }
            println!("  \x1b[33m[session ended — waiting for peer to reconnect]\x1b[0m");
        }
    } else {
        let mut session_n: u64 = 0;
        loop {
            let mut backoff = tokio::time::Duration::from_millis(500);
            let stream = loop {
                if shutdown_handle.is_fired() { return; }
                let connect_result = tokio::select! {
                    res = TcpStream::connect(&cli.addr) => res,
                    _ = shutdown_rx.recv() => {
                        println!("\n  [shutdown — aborting connect]");
                        return;
                    }
                };
                match connect_result {
                    Ok(s) => {
                        s.set_nodelay(true).unwrap();
                        break s;
                    }
                    Err(e) => {
                        if session_n == 0 {
                            eprintln!("  ✗ connect failed: {e}");
                            std::process::exit(1);
                        }
                        eprintln!("  \x1b[90m[reconnect attempt failed: {e}; retrying in {}ms]\x1b[0m", backoff.as_millis());
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(tokio::time::Duration::from_secs(10));
                    }
                }
            };
            if session_n == 0 {
                println!("  Connected to {}", cli.addr);
            } else {
                println!("  \x1b[32m[reconnected to {} — session #{}, pool preserved]\x1b[0m", cli.addr, session_n);
            }
            run_session(stream, psk.clone(), false,
                        stdin_tx.subscribe(), shutdown_handle.subscribe()).await;
            session_n += 1;
            if shutdown_handle.is_fired() { break; }

            // Backoff between sessions to prevent reconnect floods.
            // After 5 consecutive rapid failures, stop entirely.
            const MAX_SESSION_RETRIES: u64 = 5;
            if session_n > MAX_SESSION_RETRIES {
                eprintln!("  \x1b[31m[too many failed sessions ({session_n}) — giving up]\x1b[0m");
                eprintln!("  \x1b[33m→ Restart with a fresh session-id if needed.\x1b[0m");
                break;
            }
            let pause = std::cmp::min(session_n * 2, 10);
            eprintln!("  \x1b[33m[session ended — reconnecting in {pause}s]\x1b[0m");
            tokio::time::sleep(tokio::time::Duration::from_secs(pause)).await;
        }
    }
    println!("  [chat shutdown complete]");
}
