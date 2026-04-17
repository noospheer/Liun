//! # Parallel Channel Throughput Test
//!
//! Runs N parallel Liu channels between two nodes simultaneously
//! and measures aggregate key generation rate.

use liuproto_core::pool::Pool;
use liun_channel::exchange::{ExchangeParams, run_as_alice, run_as_bob};
use liun_overlay::bootstrap::{BootstrapConfig, bootstrap_psk};
use tokio::net::{TcpListener, TcpStream};
use std::time::Instant;

async fn run_one_channel(
    psk: Vec<u8>,
    nonce: [u8; 16],
    params: ExchangeParams,
    addr: std::net::SocketAddr,
    is_server: bool,
) -> usize {
    if is_server {
        let listener = TcpListener::bind(addr).await.unwrap();
        let (mut stream, _) = listener.accept().await.unwrap();
        stream.set_nodelay(true).unwrap();
        let mut pool = Pool::from_psk(&psk, &nonce);
        let result = run_as_bob(&mut stream, &mut pool, &params).await.unwrap();
        assert!(result.verified);
        result.sign_bits.len()
    } else {
        // Small delay to let server bind
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.set_nodelay(true).unwrap();
        let mut pool = Pool::from_psk(&psk, &nonce);
        let result = run_as_alice(&mut stream, &mut pool, &params).await.unwrap();
        assert!(result.verified);
        result.sign_bits.len()
    }
}

#[tokio::test]
async fn test_parallel_throughput() {
    let parallel_counts = [1, 2, 5, 10, 20];
    let batch_size = 5000; // larger batch for meaningful measurement
    let params = ExchangeParams::new(batch_size, 0.1, 0.5);

    println!("\n═══════════════════════════════════════════");
    println!("  PARALLEL CHANNEL THROUGHPUT TEST");
    println!("═══════════════════════════════════════════\n");

    for &n_parallel in &parallel_counts {
        let config = BootstrapConfig { k: 5, psk_size: 2048 };

        // Generate independent PSKs for each parallel channel
        let channel_data: Vec<(Vec<u8>, [u8; 16], std::net::SocketAddr)> = (0..n_parallel)
            .map(|i| {
                let (psk, _) = bootstrap_psk(&config);
                let mut nonce = [0u8; 16];
                nonce[0] = i as u8;
                // Bind to port 0 to get a random port
                let addr: std::net::SocketAddr = format!("127.0.0.1:0").parse().unwrap();
                (psk, nonce, addr)
            })
            .collect();

        // Pre-bind all listeners to get real addresses
        let mut listeners = Vec::new();
        let mut addrs = Vec::new();
        for _ in 0..n_parallel {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            addrs.push(listener.local_addr().unwrap());
            listeners.push(listener);
        }

        let start = Instant::now();

        // Spawn all Bob tasks (servers)
        let mut bob_handles = Vec::new();
        for i in 0..n_parallel {
            let psk = channel_data[i].0.clone();
            let nonce = channel_data[i].1;
            let params = params.clone();
            let listener = listeners.remove(0); // take ownership

            bob_handles.push(tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                stream.set_nodelay(true).unwrap();
                let mut pool = Pool::from_psk(&psk, &nonce);
                let result = run_as_bob(&mut stream, &mut pool, &params).await.unwrap();
                assert!(result.verified);
                result.sign_bits.len()
            }));
        }

        // Spawn all Alice tasks (clients)
        let mut alice_handles = Vec::new();
        for i in 0..n_parallel {
            let psk = channel_data[i].0.clone();
            let nonce = channel_data[i].1;
            let params = params.clone();
            let addr = addrs[i];

            alice_handles.push(tokio::spawn(async move {
                let mut stream = TcpStream::connect(addr).await.unwrap();
                stream.set_nodelay(true).unwrap();
                let mut pool = Pool::from_psk(&psk, &nonce);
                let result = run_as_alice(&mut stream, &mut pool, &params).await.unwrap();
                assert!(result.verified);
                result.sign_bits.len()
            }));
        }

        // Wait for all to complete
        let mut total_bits = 0usize;
        for h in alice_handles {
            total_bits += h.await.unwrap();
        }
        for h in bob_handles {
            let _ = h.await.unwrap();
        }

        let elapsed = start.elapsed();
        let bits_per_sec = total_bits as f64 / elapsed.as_secs_f64();
        let mbps = bits_per_sec / 1_000_000.0;

        println!("  {:>2} parallel channels: {:>6} bits in {:>6.1}ms = {:>8.2} Mbps",
            n_parallel, total_bits, elapsed.as_secs_f64() * 1000.0, mbps);
    }

    println!("\n═══════════════════════════════════════════\n");
}
