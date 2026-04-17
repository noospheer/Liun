//! # Liu Protocol Exchange
//!
//! The actual bidirectional signbit_nopa protocol between two peers.
//! Alice and Bob each generate Gaussian noise, exchange mod-p wire values,
//! agree on sign bits via OTP + MAC, and produce shared key material.

use liuproto_core::gf61::Gf61;
use liuproto_core::mac;
use liuproto_core::noise;
use liuproto_core::pool::Pool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Parameters for a single exchange run.
#[derive(Clone)]
pub struct ExchangeParams {
    pub batch_size: usize, // B: sign bits per run
    pub sigma_z: f64,
    pub modulus: f64,
}

impl ExchangeParams {
    pub fn new(batch_size: usize, cutoff: f64, mod_mult: f64) -> Self {
        let sigma_z = (2.0 * cutoff).sqrt();
        Self {
            batch_size,
            sigma_z,
            modulus: mod_mult * sigma_z,
        }
    }
}

/// Result of one exchange run.
pub struct ExchangeResult {
    /// Agreed sign bits (shared between Alice and Bob).
    pub sign_bits: Vec<u8>,
    /// Whether the MAC verification passed.
    pub verified: bool,
}

/// Run one batch as Alice (initiator / first mover).
/// Returns the agreed sign bits if MAC verification passes.
pub async fn run_as_alice(
    stream: &mut TcpStream,
    pool: &mut Pool,
    params: &ExchangeParams,
) -> Result<ExchangeResult, Box<dyn std::error::Error + Send + Sync>> {
    let b = params.batch_size;

    // Step 1: Generate Gaussian noise, compute wire values
    let z_a: Vec<f64> = noise::batch_gaussian(b)
        .into_iter().map(|z| z * params.sigma_z).collect();
    let wa: Vec<f64> = z_a.iter().map(|&z| noise::mod_reduce(z, params.modulus)).collect();

    // Step 2: Send wire values to Bob
    let mut send_buf = Vec::with_capacity(b * 8);
    for &w in &wa {
        send_buf.extend_from_slice(&w.to_be_bytes());
    }
    stream.write_all(&send_buf).await?;

    // Step 3: Receive Bob's response: wire values + encrypted signs + MAC tag
    let resp_size = b * 8 + (b + 7) / 8 + 8; // wire + sign_enc bytes + tag
    let mut resp_buf = vec![0u8; resp_size];
    stream.read_exact(&mut resp_buf).await?;

    // Parse Bob's wire values
    let mut wb = Vec::with_capacity(b);
    for i in 0..b {
        let bytes: [u8; 8] = resp_buf[i * 8..(i + 1) * 8].try_into()?;
        wb.push(f64::from_be_bytes(bytes));
    }

    // Parse encrypted sign bits
    let sign_enc_start = b * 8;
    let sign_enc_bytes = (b + 7) / 8;
    let sign_enc_raw = &resp_buf[sign_enc_start..sign_enc_start + sign_enc_bytes];
    let mut bob_sign_enc = Vec::with_capacity(b);
    for &byte in sign_enc_raw {
        for bit in (0..8).rev() {
            if bob_sign_enc.len() < b {
                bob_sign_enc.push((byte >> bit) & 1);
            }
        }
    }

    // Parse MAC tag
    let tag_start = sign_enc_start + sign_enc_bytes;
    let tag_bytes: [u8; 8] = resp_buf[tag_start..tag_start + 8].try_into()?;
    let bob_tag = Gf61::new(u64::from_be_bytes(tag_bytes));

    // Step 4: Verify Bob's MAC
    let (r, s) = pool.mac_keys();
    let mut combined_wire: Vec<f64> = wa.clone();
    combined_wire.extend_from_slice(&wb);
    let mut coeffs = mac::quantize_to_coeffs(&combined_wire, params.sigma_z, 4, 4.0);
    for chunk in bob_sign_enc.chunks(8) {
        let mut byte_val = 0u64;
        for &bit in chunk {
            byte_val = byte_val * 2 + bit as u64;
        }
        coeffs.push(Gf61::new(byte_val));
    }
    let expected_tag = mac::mac_tag(&coeffs, r, s);
    let verified = expected_tag == bob_tag;

    if !verified {
        return Ok(ExchangeResult { sign_bits: Vec::new(), verified: false });
    }

    // Step 5: Decrypt Bob's sign bits using OTP from pool
    let otp = pool.withdraw_otp(b);
    let sign_bits: Vec<u8> = bob_sign_enc.iter().zip(otp.iter())
        .map(|(&enc, &otp)| enc ^ otp)
        .collect();

    // Step 6: Compute Alice's MAC and send
    let alice_tag = mac::mac_tag(&coeffs, r, s);
    stream.write_all(&alice_tag.val().to_be_bytes()).await?;

    // Step 7: Deposit sign bits and recycle MAC key
    if sign_bits.len() >= 128 {
        pool.deposit(&sign_bits);
    }

    Ok(ExchangeResult { sign_bits, verified: true })
}

/// Run one batch as Bob (responder / second mover).
pub async fn run_as_bob(
    stream: &mut TcpStream,
    pool: &mut Pool,
    params: &ExchangeParams,
) -> Result<ExchangeResult, Box<dyn std::error::Error + Send + Sync>> {
    let b = params.batch_size;

    // Step 1: Receive Alice's wire values
    let mut recv_buf = vec![0u8; b * 8];
    stream.read_exact(&mut recv_buf).await?;
    let mut wa = Vec::with_capacity(b);
    for i in 0..b {
        let bytes: [u8; 8] = recv_buf[i * 8..(i + 1) * 8].try_into()?;
        wa.push(f64::from_be_bytes(bytes));
    }

    // Step 2: Generate Bob's noise, compute wire values and sign bits
    let z_b: Vec<f64> = noise::batch_gaussian(b)
        .into_iter().map(|z| z * params.sigma_z).collect();
    let wb: Vec<f64> = z_b.iter().map(|&z| noise::mod_reduce(z, params.modulus)).collect();
    let sign_raw: Vec<u8> = z_b.iter().map(|&z| noise::sign_bit(z)).collect();

    // Step 3: Encrypt sign bits with OTP
    let otp = pool.withdraw_otp(b);
    let sign_enc: Vec<u8> = sign_raw.iter().zip(otp.iter())
        .map(|(&s, &o)| s ^ o)
        .collect();

    // Step 4: Compute MAC over (wa, wb, sign_enc)
    let (r, s) = pool.mac_keys();
    let mut combined_wire: Vec<f64> = wa.clone();
    combined_wire.extend_from_slice(&wb);
    let mut coeffs = mac::quantize_to_coeffs(&combined_wire, params.sigma_z, 4, 4.0);
    for chunk in sign_enc.chunks(8) {
        let mut byte_val = 0u64;
        for &bit in chunk {
            byte_val = byte_val * 2 + bit as u64;
        }
        coeffs.push(Gf61::new(byte_val));
    }
    let bob_tag = mac::mac_tag(&coeffs, r, s);

    // Step 5: Send response: wb + sign_enc + tag
    let sign_enc_bytes = (b + 7) / 8;
    let mut resp = Vec::with_capacity(b * 8 + sign_enc_bytes + 8);
    for &w in &wb {
        resp.extend_from_slice(&w.to_be_bytes());
    }
    // Pack sign_enc bits into bytes
    let mut packed = Vec::with_capacity(sign_enc_bytes);
    for chunk in sign_enc.chunks(8) {
        let mut byte = 0u8;
        for (i, &bit) in chunk.iter().enumerate() {
            byte |= (bit & 1) << (7 - i);
        }
        packed.push(byte);
    }
    resp.extend_from_slice(&packed);
    resp.extend_from_slice(&bob_tag.val().to_be_bytes());
    stream.write_all(&resp).await?;

    // Step 6: Receive and verify Alice's MAC tag
    let mut tag_buf = [0u8; 8];
    stream.read_exact(&mut tag_buf).await?;
    let alice_tag = Gf61::new(u64::from_be_bytes(tag_buf));
    let verified = alice_tag == bob_tag; // Both should compute same tag

    if !verified {
        return Ok(ExchangeResult { sign_bits: Vec::new(), verified: false });
    }

    // Step 7: Deposit and recycle
    if sign_raw.len() >= 128 {
        pool.deposit(&sign_raw);
    }

    Ok(ExchangeResult { sign_bits: sign_raw, verified: true })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn make_psk() -> Vec<u8> {
        let mut psk = vec![0u8; 2048];
        for (i, byte) in psk.iter_mut().enumerate() {
            *byte = ((i * 7 + 3) % 256) as u8;
        }
        psk
    }

    #[tokio::test]
    async fn test_exchange_end_to_end() {
        let psk = make_psk();
        let nonce = [0u8; 16];
        let params = ExchangeParams::new(1000, 0.1, 0.5); // small batch for test

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let psk_clone = psk.clone();
        let params_clone = params.clone();

        // Bob: accept and run
        let bob_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut pool = Pool::from_psk(&psk_clone, &nonce);
            run_as_bob(&mut stream, &mut pool, &params_clone).await.unwrap()
        });

        // Alice: connect and run
        let alice_handle = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            let mut pool = Pool::from_psk(&psk, &nonce);
            run_as_alice(&mut stream, &mut pool, &params).await.unwrap()
        });

        let alice_result = alice_handle.await.unwrap();
        let bob_result = bob_handle.await.unwrap();

        assert!(alice_result.verified, "Alice MAC verification failed");
        assert!(bob_result.verified, "Bob MAC verification failed");
        assert_eq!(alice_result.sign_bits.len(), 1000);
        assert_eq!(bob_result.sign_bits.len(), 1000);

        // Alice decrypted Bob's sign bits; Bob has his own sign bits.
        // They should agree (Alice sees Bob's signs via OTP decryption).
        assert_eq!(alice_result.sign_bits, bob_result.sign_bits,
            "sign bits disagree — key agreement failed");
    }
}
