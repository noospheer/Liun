//! End-to-end test of k-path bootstrap against real relays.
//!
//! Spawns k relays on localhost on distinct ports, runs provider + consumer
//! against them, asserts both derive the same PSK.

use liun_overlay::bootstrap::{consume_shares, provide_shares, BootstrapError};
use liun_overlay::directory::{Directory, RelayEntry};
use liun_overlay::relay_server;

async fn spawn_k_relays(k: usize) -> Vec<String> {
    let mut urls = Vec::with_capacity(k);
    for _ in 0..k {
        let h = relay_server::serve("127.0.0.1:0").await.unwrap();
        urls.push(format!("http://{}", h.local_addr));
    }
    urls
}

fn directory_from_urls(urls: &[String]) -> Directory {
    Directory {
        relays: urls.iter().map(|u| RelayEntry {
            url: u.clone(),
            operator: String::new(),
            jurisdiction: String::new(),
        }).collect(),
    }
}

#[tokio::test]
async fn k3_bootstrap_end_to_end() {
    let urls = spawn_k_relays(3).await;
    let dir = directory_from_urls(&urls);
    let sid = "integ_test_k3";
    let psk_size = 10_032;

    // Provider side generates + uploads shares.
    let provider_psk = provide_shares(&dir, sid, psk_size).await.unwrap();
    assert_eq!(provider_psk.len(), psk_size);

    // Consumer side downloads + XORs.
    let consumer_psk = consume_shares(&dir, sid, psk_size).await.unwrap();
    assert_eq!(consumer_psk.len(), psk_size);

    // Both must match.
    assert_eq!(provider_psk, consumer_psk, "bootstrap PSKs disagree");

    // PSK should not be all zeros (statistically impossible with good RNG).
    assert!(provider_psk.iter().any(|&b| b != 0));
}

#[tokio::test]
async fn consume_without_provider_fails() {
    let urls = spawn_k_relays(3).await;
    let dir = directory_from_urls(&urls);

    match consume_shares(&dir, "no_provider_here", 1024).await {
        Err(BootstrapError::PartialDownload(errs)) => {
            assert_eq!(errs.len(), 3, "all 3 relays should 404");
        }
        other => panic!("expected PartialDownload, got {other:?}"),
    }
}

#[tokio::test]
async fn double_provide_conflicts() {
    let urls = spawn_k_relays(3).await;
    let dir = directory_from_urls(&urls);
    let sid = "double_provide_test";

    provide_shares(&dir, sid, 512).await.unwrap();

    match provide_shares(&dir, sid, 512).await {
        Err(BootstrapError::PartialUpload(errs)) => {
            assert_eq!(errs.len(), 3, "second provide should 409 on all 3");
        }
        other => panic!("expected PartialUpload, got {other:?}"),
    }
}

#[tokio::test]
async fn mismatched_session_ids_fail() {
    let urls = spawn_k_relays(3).await;
    let dir = directory_from_urls(&urls);

    provide_shares(&dir, "provider_sid", 512).await.unwrap();

    // Consumer uses a different session id — should 404 on every relay.
    match consume_shares(&dir, "consumer_sid", 512).await {
        Err(BootstrapError::PartialDownload(_)) => {}
        other => panic!("expected PartialDownload, got {other:?}"),
    }
}
