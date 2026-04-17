//! # Binary Wire Protocol
//!
//! Compact binary framing for Liu channel exchanges.
//! Each frame carries wire values, authenticated real values, and z samples.
//!
//! Frame format: [2 bytes wire][6 bytes encrypted (2 auth + 4 z_float32)]
//! Total: 8 bytes per exchange step.

use bytes::{Buf, BufMut, BytesMut};

/// Frame size in bytes.
pub const FRAME_SIZE: usize = 8;

/// A single exchange frame.
#[derive(Debug, Clone, Copy)]
pub struct Frame {
    /// Wire value (mod-p wrapped), quantized to i16.
    pub wire: i16,
    /// Authenticated real value, quantized to i16.
    pub auth: i16,
    /// Z noise sample as f32.
    pub z_sample: f32,
}

impl Frame {
    /// Encode frame to bytes.
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_i16(self.wire);
        buf.put_i16(self.auth);
        buf.put_f32(self.z_sample);
    }

    /// Decode frame from bytes. Returns None if insufficient data.
    pub fn decode(buf: &mut BytesMut) -> Option<Self> {
        if buf.len() < FRAME_SIZE {
            return None;
        }
        let wire = buf.get_i16();
        let auth = buf.get_i16();
        let z_sample = buf.get_f32();
        Some(Self { wire, auth, z_sample })
    }
}

/// Encode a wire value (mod-p reduced float) to i16.
/// Range: (-p/2, p/2] mapped to (-32768, 32767].
pub fn encode_wire(value: f64, modulus: f64) -> i16 {
    let normalized = value / modulus * 2.0; // map to (-1, 1]
    (normalized * 32767.0).round().clamp(-32768.0, 32767.0) as i16
}

/// Decode i16 back to wire value.
pub fn decode_wire(encoded: i16, modulus: f64) -> f64 {
    (encoded as f64) / 32767.0 * modulus / 2.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_roundtrip() {
        let frame = Frame { wire: 1234, auth: -567, z_sample: 3.14 };
        let mut buf = BytesMut::with_capacity(FRAME_SIZE);
        frame.encode(&mut buf);
        let decoded = Frame::decode(&mut buf).unwrap();
        assert_eq!(decoded.wire, 1234);
        assert_eq!(decoded.auth, -567);
        assert!((decoded.z_sample - 3.14).abs() < 1e-5);
    }

    #[test]
    fn test_wire_encode_decode() {
        let modulus = 5.0;
        let value = 1.5;
        let encoded = encode_wire(value, modulus);
        let decoded = decode_wire(encoded, modulus);
        assert!((decoded - value).abs() < 0.01);
    }
}
