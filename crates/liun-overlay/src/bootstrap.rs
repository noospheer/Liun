//! # Multi-Path Bootstrap
//!
//! Join the network by sending secret shares via k independent routes.
//! If ≥1 route is unobserved, the resulting PSK is perfectly secret.
//!
//! ITS property: proved in Lean (Bootstrap.lean).

use liuproto_core::noise;
use crate::directory::Directory;
use crate::relay_client::{self, RelayError};

/// Bootstrap configuration.
#[derive(Debug, Clone)]
pub struct BootstrapConfig {
    /// Number of bootstrap paths (k).
    pub k: usize,
    /// PSK size in bytes per path.
    pub psk_size: usize,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            k: 20,
            psk_size: 2048, // large enough for pool: 32 header + pool bytes
        }
    }
}

/// A bootstrap session: generates secrets for k paths.
pub struct BootstrapSession {
    pub config: BootstrapConfig,
    pub secrets: Vec<Vec<u8>>,
}

impl BootstrapSession {
    /// Start a new bootstrap session with k random secrets.
    pub fn new(config: BootstrapConfig) -> Self {
        let secrets: Vec<Vec<u8>> = (0..config.k)
            .map(|_| noise::random_bytes(config.psk_size))
            .collect();
        Self { config, secrets }
    }

    /// Get the secret for path i.
    pub fn secret(&self, i: usize) -> &[u8] {
        &self.secrets[i]
    }

    /// Derive PSK from a received secret.
    pub fn derive_psk(secret: &[u8]) -> Vec<u8> {
        secret.to_vec()
    }

    /// Number of paths.
    pub fn num_paths(&self) -> usize {
        self.config.k
    }

    /// Simulate the bootstrap: Alice generates secrets, sends via k paths.
    /// Returns the secrets that arrived (unobserved by Eve) and the
    /// derived PSK (XOR of all secrets = perfectly secret if ≥1 unobserved).
    ///
    /// In a real network: each secret goes via a different TCP route.
    /// Eve must tap ALL k routes to learn the combined PSK.
    pub fn derive_combined_psk(&self) -> Vec<u8> {
        let len = self.config.psk_size;
        let mut combined = vec![0u8; len];
        for secret in &self.secrets {
            for (i, &byte) in secret.iter().enumerate() {
                combined[i] ^= byte;
            }
        }
        combined
    }
}

/// Simulate a multi-path bootstrap between two nodes.
/// Both nodes end up with the same PSK without any prior shared secret.
///
/// Protocol:
/// 1. Alice generates k random secrets
/// 2. Alice sends secret[i] to Bob via path i
/// 3. Bob receives all k secrets (each via independent route)
/// 4. Both compute PSK = XOR of all k secrets
/// 5. If Eve missed even one path, PSK is perfectly secret
pub fn bootstrap_psk(config: &BootstrapConfig) -> (Vec<u8>, Vec<u8>) {
    let session = BootstrapSession::new(config.clone());

    // Alice's PSK: XOR of all secrets she generated
    let alice_psk = session.derive_combined_psk();

    // Bob receives the same secrets (via k independent TCP routes)
    // and computes the same XOR
    let mut bob_psk = vec![0u8; config.psk_size];
    for secret in &session.secrets {
        for (i, &byte) in secret.iter().enumerate() {
            bob_psk[i] ^= byte;
        }
    }

    // Both have the same PSK — no prior shared secret needed
    assert_eq!(alice_psk, bob_psk);
    (alice_psk, bob_psk)
}

/// Errors from a real-network bootstrap.
#[derive(Debug)]
pub enum BootstrapError {
    /// One or more relays failed during upload. The Vec pairs (relay_index, error).
    PartialUpload(Vec<(usize, RelayError)>),
    /// One or more relays failed during download.
    PartialDownload(Vec<(usize, RelayError)>),
    /// A retrieved share had the wrong size.
    ShareSizeMismatch { relay_index: usize, expected: usize, got: usize },
    /// Directory has no relays.
    EmptyDirectory,
}

impl std::fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PartialUpload(errs) => {
                write!(f, "bootstrap upload failed on {} relay(s):", errs.len())?;
                for (i, e) in errs {
                    write!(f, "\n  relay #{i}: {e}")?;
                }
                Ok(())
            }
            Self::PartialDownload(errs) => {
                write!(f, "bootstrap download failed on {} relay(s):", errs.len())?;
                for (i, e) in errs {
                    write!(f, "\n  relay #{i}: {e}")?;
                }
                Ok(())
            }
            Self::ShareSizeMismatch { relay_index, expected, got } => {
                write!(f, "relay #{relay_index} returned wrong share size: expected {expected}B, got {got}B")
            }
            Self::EmptyDirectory => write!(f, "relay directory is empty"),
        }
    }
}

impl std::error::Error for BootstrapError {}

/// Role: provider generates k shares and uploads one to each relay.
/// The derived PSK is XOR of all shares the provider generated.
pub async fn provide_shares(
    directory: &Directory,
    session_id: &str,
    psk_size: usize,
) -> Result<Vec<u8>, BootstrapError> {
    if directory.is_empty() {
        return Err(BootstrapError::EmptyDirectory);
    }

    let shares: Vec<Vec<u8>> = (0..directory.len())
        .map(|_| noise::random_bytes(psk_size))
        .collect();

    // Upload in parallel
    let mut handles = Vec::with_capacity(directory.len());
    for (i, relay) in directory.relays.iter().enumerate() {
        let url = relay.url.clone();
        let sid = session_id.to_string();
        let share = shares[i].clone();
        handles.push(tokio::spawn(async move {
            (i, relay_client::post_share(&url, &sid, &share).await)
        }));
    }

    let mut errors = Vec::new();
    for h in handles {
        let (i, res) = h.await.expect("relay upload task panicked");
        if let Err(e) = res {
            errors.push((i, e));
        }
    }

    if !errors.is_empty() {
        return Err(BootstrapError::PartialUpload(errors));
    }

    Ok(xor_shares(&shares, psk_size))
}

/// Role: consumer downloads one share from each relay and XORs them.
/// If the provider used the same session_id and the same directory order,
/// consumer's PSK equals provider's PSK.
pub async fn consume_shares(
    directory: &Directory,
    session_id: &str,
    psk_size: usize,
) -> Result<Vec<u8>, BootstrapError> {
    if directory.is_empty() {
        return Err(BootstrapError::EmptyDirectory);
    }

    let mut handles = Vec::with_capacity(directory.len());
    for (i, relay) in directory.relays.iter().enumerate() {
        let url = relay.url.clone();
        let sid = session_id.to_string();
        handles.push(tokio::spawn(async move {
            (i, relay_client::get_share(&url, &sid).await)
        }));
    }

    let mut shares: Vec<Option<Vec<u8>>> = vec![None; directory.len()];
    let mut errors = Vec::new();
    for h in handles {
        let (i, res) = h.await.expect("relay download task panicked");
        match res {
            Ok(s) => {
                if s.len() != psk_size {
                    return Err(BootstrapError::ShareSizeMismatch {
                        relay_index: i,
                        expected: psk_size,
                        got: s.len(),
                    });
                }
                shares[i] = Some(s);
            }
            Err(e) => errors.push((i, e)),
        }
    }

    if !errors.is_empty() {
        return Err(BootstrapError::PartialDownload(errors));
    }

    let shares: Vec<Vec<u8>> = shares.into_iter().map(|o| o.unwrap()).collect();
    Ok(xor_shares(&shares, psk_size))
}

/// XOR a set of equal-length byte vectors.
fn xor_shares(shares: &[Vec<u8>], psk_size: usize) -> Vec<u8> {
    let mut psk = vec![0u8; psk_size];
    for share in shares {
        for (i, &b) in share.iter().enumerate() {
            psk[i] ^= b;
        }
    }
    psk
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bootstrap_session() {
        let session = BootstrapSession::new(BootstrapConfig::default());
        assert_eq!(session.num_paths(), 20);
        assert_eq!(session.secret(0).len(), 2048);
        assert_ne!(session.secret(0), session.secret(1));
    }

    #[test]
    fn test_bootstrap_psk_agreement() {
        let config = BootstrapConfig { k: 5, psk_size: 2048 };
        let (alice_psk, bob_psk) = bootstrap_psk(&config);
        assert_eq!(alice_psk, bob_psk);
        assert_eq!(alice_psk.len(), 2048);
        // PSK should not be all zeros (with overwhelming probability)
        assert!(alice_psk.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_bootstrap_no_preshared_key() {
        // The whole point: two parties who share NOTHING beforehand
        // end up with the same PSK, derived purely from the multi-path
        // secret exchange. No USB stick. No meeting. Just TCP routes.
        let config = BootstrapConfig { k: 20, psk_size: 2048 };
        let (psk_a, psk_b) = bootstrap_psk(&config);
        assert_eq!(psk_a, psk_b, "bootstrap failed: PSKs don't match");
    }
}
