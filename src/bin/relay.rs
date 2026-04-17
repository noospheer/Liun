//! # liun-relay: Bootstrap Dead-Drop Server
//!
//! A stateless relay that holds k-path bootstrap shares for retrieval.
//! See `liun_overlay::relay_server` for protocol details and security rationale.
//!
//! Usage:
//!   liun-relay --listen 0.0.0.0:8080

use liun_overlay::relay_server;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let addr = match args.iter().position(|a| a == "--listen") {
        Some(i) if i + 1 < args.len() => args[i + 1].clone(),
        _ => {
            eprintln!("Usage: liun-relay --listen <addr:port>");
            eprintln!("Example: liun-relay --listen 0.0.0.0:8080");
            std::process::exit(1);
        }
    };

    let handle = match relay_server::serve(&addr).await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("failed to bind {addr}: {e}");
            std::process::exit(1);
        }
    };

    eprintln!("liun-relay listening on {}", handle.local_addr);
    eprintln!("  POST /share/{{session_id}}  upload a share");
    eprintln!("  GET  /share/{{session_id}}  retrieve a share");
    eprintln!("  TTL: {}s", relay_server::TTL.as_secs());

    // Block forever; the server runs in spawned tasks.
    std::future::pending::<()>().await;
}
