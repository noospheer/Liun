//! # Persistent State Storage
//!
//! Stores node state to disk so channels survive restarts.
//! Uses a simple directory layout — one file per concern:
//!
//! ```text
//! ~/.liun/
//!   node.toml          Node ID, config
//!   peers/
//!     {peer_id}.pool   Pool state (binary: cursor + buffer)
//!     {peer_id}.meta   Channel metadata (TOML: status, total_bits)
//!   trust.bin          Trust graph edges (binary)
//!   committee.toml     Current committee state
//! ```
//!
//! Security: pool state is the sensitive material. It's written
//! to disk encrypted... actually no. The pool IS the key material.
//! If Eve reads the disk, she has the OTP. This is the same as
//! any cryptographic key on disk. Protect with OS file permissions
//! and disk encryption (LUKS, FileVault, etc.).

use std::path::{Path, PathBuf};
use std::fs;
use std::io::{Read, Write};

/// CRC-32/IEEE (polynomial 0xEDB88320). Small table-driven implementation;
/// used only for local file integrity — not a cryptographic primitive.
fn crc32_ieee(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in bytes {
        let mut c = (crc ^ b as u32) & 0xFF;
        for _ in 0..8 {
            c = if c & 1 == 1 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
        }
        crc = (crc >> 8) ^ c;
    }
    crc ^ 0xFFFF_FFFF
}

/// The base directory for node state.
#[derive(Clone)]
pub struct StateDir {
    base: PathBuf,
}

impl StateDir {
    /// Open or create a state directory.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let base = path.as_ref().to_path_buf();
        fs::create_dir_all(&base)?;
        fs::create_dir_all(base.join("peers"))?;
        Ok(Self { base })
    }

    /// Default state directory: ~/.liun
    pub fn default_path() -> PathBuf {
        dirs_next().join(".liun")
    }

    // ── Node identity ──

    /// Save node ID (u64 legacy format).
    pub fn save_node_id(&self, node_id: u64) -> std::io::Result<()> {
        let content = format!("node_id = {}\n", node_id);
        fs::write(self.base.join("node.toml"), content)
    }

    /// Load node ID (u64 legacy format).
    pub fn load_node_id(&self) -> std::io::Result<Option<u64>> {
        let path = self.base.join("node.toml");
        if !path.exists() { return Ok(None); }
        let content = fs::read_to_string(path)?;
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("node_id = ") {
                if let Ok(id) = val.trim().parse() {
                    return Ok(Some(id));
                }
            }
        }
        Ok(None)
    }

    /// Save 384-bit node identity (canonical: base58).
    pub fn save_identity(&self, id: &crate::identity::NodeId) -> std::io::Result<()> {
        let content = format!("identity = \"{}\"\n", id.to_base58());
        fs::write(self.base.join("identity.toml"), content)
    }

    /// Load 384-bit node identity. Accepts either base58 (canonical) or hex
    /// (legacy) for backward compat with files written by older versions.
    pub fn load_identity(&self) -> std::io::Result<Option<crate::identity::NodeId>> {
        let path = self.base.join("identity.toml");
        if !path.exists() { return Ok(None); }
        let content = fs::read_to_string(path)?;
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("identity = ") {
                let s = val.trim().trim_matches('"');
                if let Some(id) = crate::identity::NodeId::parse(s) {
                    return Ok(Some(id));
                }
            }
        }
        Ok(None)
    }

    /// Load or generate identity. If no identity exists on disk,
    /// generates a new 384-bit random ID and saves it.
    pub fn load_or_generate_identity(&self) -> std::io::Result<crate::identity::NodeId> {
        if let Some(id) = self.load_identity()? {
            return Ok(id);
        }
        let id = crate::identity::NodeId::generate();
        self.save_identity(&id)?;
        Ok(id)
    }

    // ── Pool state (binary) ──

    /// Save pool state for a peer channel.
    /// Format: [cursor: 8 bytes LE][buffer length: 8 bytes LE][buffer bytes]
    pub fn save_pool(&self, peer_id: u64, cursor: usize, buf: &[u8]) -> std::io::Result<()> {
        let path = self.base.join("peers").join(format!("{}.pool", peer_id));
        let mut file = fs::File::create(path)?;
        file.write_all(&(cursor as u64).to_le_bytes())?;
        file.write_all(&(buf.len() as u64).to_le_bytes())?;
        file.write_all(buf)?;
        file.flush()
    }

    /// Load pool state for a peer channel.
    /// Returns (cursor, buffer).
    pub fn load_pool(&self, peer_id: u64) -> std::io::Result<Option<(usize, Vec<u8>)>> {
        let path = self.base.join("peers").join(format!("{}.pool", peer_id));
        if !path.exists() { return Ok(None); }
        let mut file = fs::File::open(path)?;
        let mut header = [0u8; 16];
        file.read_exact(&mut header)?;
        let cursor = u64::from_le_bytes(header[0..8].try_into().unwrap()) as usize;
        let buf_len = u64::from_le_bytes(header[8..16].try_into().unwrap()) as usize;
        let mut buf = vec![0u8; buf_len];
        file.read_exact(&mut buf)?;
        Ok(Some((cursor, buf)))
    }

    // ── Pool v2: NodeId-keyed, integrity-checked, atomic write ──
    //
    // File layout:
    //   magic[4]  = b"LPL2"
    //   version[1] = 2
    //   flags[3]  = reserved (0)
    //   cursor[8] LE u64
    //   buf_len[8] LE u64
    //   buf[buf_len]
    //   crc32[4] LE — CRC-32 (IEEE) over everything above (magic..buf).
    //
    // CRC-32 is a non-cryptographic checksum. It catches disk rot and
    // truncated writes. It does NOT protect against an adversary with
    // write access to the state dir — the ITS threat model already
    // requires the state directory to be a trusted local resource
    // (see THREAT_MODEL.md). An attacker with write access to the
    // pool file has already broken Liun's assumption of a trusted
    // local FS; keyed MAC would be theatre here.

    fn pool_path(&self, node_id: &crate::identity::NodeId) -> PathBuf {
        self.base
            .join("peers")
            .join(format!("{}.pool2", node_id.to_hex()))
    }

    /// Save pool state keyed by NodeId, atomically (write to `.tmp` then rename).
    pub fn save_pool_by_node(
        &self,
        node_id: &crate::identity::NodeId,
        cursor: usize,
        buf: &[u8],
    ) -> std::io::Result<()> {
        let peers_dir = self.base.join("peers");
        fs::create_dir_all(&peers_dir)?;
        let path = self.pool_path(node_id);
        let tmp = path.with_extension("pool2.tmp");

        let mut payload: Vec<u8> = Vec::with_capacity(24 + buf.len() + 4);
        payload.extend_from_slice(b"LPL2");
        payload.push(2); // version
        payload.extend_from_slice(&[0u8, 0, 0]); // flags reserved
        payload.extend_from_slice(&(cursor as u64).to_le_bytes());
        payload.extend_from_slice(&(buf.len() as u64).to_le_bytes());
        payload.extend_from_slice(buf);
        let crc = crc32_ieee(&payload);
        payload.extend_from_slice(&crc.to_le_bytes());

        {
            let mut file = fs::File::create(&tmp)?;
            file.write_all(&payload)?;
            file.flush()?;
            file.sync_all()?;
        }
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Load pool state keyed by NodeId. Returns `Ok(None)` if the file
    /// doesn't exist. Returns an error on CRC mismatch, truncation, or
    /// unrecognized magic/version — corrupt files must never silently
    /// present stale pool bytes, as that would desync key material.
    pub fn load_pool_by_node(
        &self,
        node_id: &crate::identity::NodeId,
    ) -> std::io::Result<Option<(usize, Vec<u8>)>> {
        let path = self.pool_path(node_id);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&path)?;
        if bytes.len() < 24 + 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "pool file truncated",
            ));
        }
        if &bytes[0..4] != b"LPL2" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "pool file bad magic",
            ));
        }
        if bytes[4] != 2 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "pool file unknown version",
            ));
        }
        let buf_len =
            u64::from_le_bytes(bytes[16..24].try_into().unwrap()) as usize;
        let expected_total = 24 + buf_len + 4;
        if bytes.len() != expected_total {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "pool file length mismatch",
            ));
        }
        let stored_crc =
            u32::from_le_bytes(bytes[bytes.len() - 4..].try_into().unwrap());
        let computed_crc = crc32_ieee(&bytes[..bytes.len() - 4]);
        if stored_crc != computed_crc {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "pool file crc mismatch (corrupt)",
            ));
        }
        let cursor =
            u64::from_le_bytes(bytes[8..16].try_into().unwrap()) as usize;
        let buf = bytes[24..24 + buf_len].to_vec();
        Ok(Some((cursor, buf)))
    }

    // ── Channel metadata ──

    /// Save channel metadata.
    pub fn save_channel_meta(&self, peer_id: u64, total_bits: u64, status: &str) -> std::io::Result<()> {
        let content = format!("peer_id = {}\ntotal_bits = {}\nstatus = \"{}\"\n",
            peer_id, total_bits, status);
        let path = self.base.join("peers").join(format!("{}.meta", peer_id));
        fs::write(path, content)
    }

    /// Load channel metadata. Returns (total_bits, status).
    pub fn load_channel_meta(&self, peer_id: u64) -> std::io::Result<Option<(u64, String)>> {
        let path = self.base.join("peers").join(format!("{}.meta", peer_id));
        if !path.exists() { return Ok(None); }
        let content = fs::read_to_string(path)?;
        let mut total_bits = 0u64;
        let mut status = String::from("idle");
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("total_bits = ") {
                total_bits = val.trim().parse().unwrap_or(0);
            }
            if let Some(val) = line.strip_prefix("status = ") {
                status = val.trim().trim_matches('"').to_string();
            }
        }
        Ok(Some((total_bits, status)))
    }

    /// List all peer IDs with saved state.
    pub fn list_peers(&self) -> std::io::Result<Vec<u64>> {
        let peers_dir = self.base.join("peers");
        let mut ids = Vec::new();
        if peers_dir.exists() {
            for entry in fs::read_dir(peers_dir)? {
                let entry = entry?;
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if let Some(id_str) = name_str.strip_suffix(".pool") {
                    if let Ok(id) = id_str.parse::<u64>() {
                        ids.push(id);
                    }
                }
            }
        }
        ids.sort();
        Ok(ids)
    }

    // ── Trust graph ──

    /// Save trust graph edges.
    /// Format: [n_edges: 8 LE][for each: node_a: 8 LE, node_b: 8 LE, weight: 8 LE f64]
    pub fn save_trust_edges(&self, edges: &[(u64, u64, f64)]) -> std::io::Result<()> {
        let path = self.base.join("trust.bin");
        let mut file = fs::File::create(path)?;
        file.write_all(&(edges.len() as u64).to_le_bytes())?;
        for &(a, b, w) in edges {
            file.write_all(&a.to_le_bytes())?;
            file.write_all(&b.to_le_bytes())?;
            file.write_all(&w.to_le_bytes())?;
        }
        file.flush()
    }

    /// Load trust graph edges.
    pub fn load_trust_edges(&self) -> std::io::Result<Option<Vec<(u64, u64, f64)>>> {
        let path = self.base.join("trust.bin");
        if !path.exists() { return Ok(None); }
        let mut file = fs::File::open(path)?;
        let mut header = [0u8; 8];
        file.read_exact(&mut header)?;
        let n = u64::from_le_bytes(header) as usize;
        let mut edges = Vec::with_capacity(n);
        for _ in 0..n {
            let mut buf = [0u8; 24];
            file.read_exact(&mut buf)?;
            let a = u64::from_le_bytes(buf[0..8].try_into().unwrap());
            let b = u64::from_le_bytes(buf[8..16].try_into().unwrap());
            let w = f64::from_le_bytes(buf[16..24].try_into().unwrap());
            edges.push((a, b, w));
        }
        Ok(Some(edges))
    }

    /// Save the DHT routing table to disk for restoration after restart.
    /// Format (binary, little-endian):
    ///   [count: u64][entry × count]
    /// Entry: [id: 48][family: 1][addr: 4 or 16][udp_port: 2][channel_port: 2]
    pub fn save_dht_peers(
        &self,
        peers: &[(crate::identity::NodeId, std::net::SocketAddr, u16)],
    ) -> std::io::Result<()> {
        use std::io::Write;
        let path = self.base.join("dht_peers.bin");
        let mut file = fs::File::create(path)?;
        file.write_all(&(peers.len() as u64).to_le_bytes())?;
        for (id, addr, channel_port) in peers {
            file.write_all(id.as_bytes())?;
            match addr.ip() {
                std::net::IpAddr::V4(ip) => {
                    file.write_all(&[4])?;
                    file.write_all(&ip.octets())?;
                }
                std::net::IpAddr::V6(ip) => {
                    file.write_all(&[6])?;
                    file.write_all(&ip.octets())?;
                }
            }
            file.write_all(&addr.port().to_le_bytes())?;
            file.write_all(&channel_port.to_le_bytes())?;
        }
        Ok(())
    }

    /// Load DHT peers from disk (None if file doesn't exist).
    pub fn load_dht_peers(
        &self,
    ) -> std::io::Result<Option<Vec<(crate::identity::NodeId, std::net::SocketAddr, u16)>>> {
        use std::io::Read;
        let path = self.base.join("dht_peers.bin");
        if !path.exists() { return Ok(None); }
        let mut file = fs::File::open(path)?;
        let mut header = [0u8; 8];
        file.read_exact(&mut header)?;
        let n = u64::from_le_bytes(header) as usize;
        let mut peers = Vec::with_capacity(n);
        for _ in 0..n {
            let mut id_bytes = [0u8; 48];
            file.read_exact(&mut id_bytes)?;
            let id = crate::identity::NodeId::from_bytes(id_bytes);
            let mut family = [0u8; 1];
            file.read_exact(&mut family)?;
            let ip = match family[0] {
                4 => {
                    let mut b = [0u8; 4];
                    file.read_exact(&mut b)?;
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(b))
                }
                6 => {
                    let mut b = [0u8; 16];
                    file.read_exact(&mut b)?;
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(b))
                }
                other => return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("bad address family in dht_peers.bin: {other}"),
                )),
            };
            let mut udp_port_bytes = [0u8; 2];
            file.read_exact(&mut udp_port_bytes)?;
            let mut ch_port_bytes = [0u8; 2];
            file.read_exact(&mut ch_port_bytes)?;
            let addr = std::net::SocketAddr::new(ip, u16::from_le_bytes(udp_port_bytes));
            let channel_port = u16::from_le_bytes(ch_port_bytes);
            peers.push((id, addr, channel_port));
        }
        Ok(Some(peers))
    }

    /// Delete all state (for testing).
    pub fn clear(&self) -> std::io::Result<()> {
        if self.base.exists() {
            fs::remove_dir_all(&self.base)?;
            fs::create_dir_all(&self.base)?;
            fs::create_dir_all(self.base.join("peers"))?;
        }
        Ok(())
    }
}

/// Get the home directory (cross-platform).
fn dirs_next() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn test_dir() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = env::temp_dir().join(format!("liun_test_{}_{}", std::process::id(), id));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn test_node_id_roundtrip() {
        let dir = test_dir();
        let state = StateDir::open(&dir).unwrap();
        state.save_node_id(42).unwrap();
        assert_eq!(state.load_node_id().unwrap(), Some(42));
        state.clear().unwrap();
    }

    #[test]
    fn test_pool_roundtrip() {
        let dir = test_dir();
        let state = StateDir::open(&dir).unwrap();

        let buf = vec![1, 2, 3, 4, 5, 6, 7, 8];
        state.save_pool(99, 3, &buf).unwrap();

        let (cursor, loaded) = state.load_pool(99).unwrap().unwrap();
        assert_eq!(cursor, 3);
        assert_eq!(loaded, buf);

        state.clear().unwrap();
    }

    #[test]
    fn pool_v2_roundtrip_by_nodeid() {
        let dir = test_dir();
        let state = StateDir::open(&dir).unwrap();
        let id = crate::identity::NodeId::from_bytes([0xAB; 48]);
        let buf: Vec<u8> = (0..4096).map(|i| (i & 0xFF) as u8).collect();
        state.save_pool_by_node(&id, 1234, &buf).unwrap();
        let (cursor, loaded) = state.load_pool_by_node(&id).unwrap().unwrap();
        assert_eq!(cursor, 1234);
        assert_eq!(loaded, buf);
        state.clear().unwrap();
    }

    #[test]
    fn pool_v2_missing_returns_none() {
        let dir = test_dir();
        let state = StateDir::open(&dir).unwrap();
        let id = crate::identity::NodeId::from_bytes([0x77; 48]);
        assert!(state.load_pool_by_node(&id).unwrap().is_none());
        state.clear().unwrap();
    }

    #[test]
    fn pool_v2_detects_corruption() {
        let dir = test_dir();
        let state = StateDir::open(&dir).unwrap();
        let id = crate::identity::NodeId::from_bytes([0x12; 48]);
        state.save_pool_by_node(&id, 7, &[9u8; 64]).unwrap();
        // Flip a byte in the middle of the buffer.
        let path = state.pool_path(&id);
        let mut bytes = fs::read(&path).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        fs::write(&path, &bytes).unwrap();
        // Load should refuse.
        let err = state.load_pool_by_node(&id).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        state.clear().unwrap();
    }

    #[test]
    fn pool_v2_detects_truncation() {
        let dir = test_dir();
        let state = StateDir::open(&dir).unwrap();
        let id = crate::identity::NodeId::from_bytes([0x34; 48]);
        state.save_pool_by_node(&id, 7, &[9u8; 64]).unwrap();
        let path = state.pool_path(&id);
        let bytes = fs::read(&path).unwrap();
        fs::write(&path, &bytes[..bytes.len() - 10]).unwrap();
        let err = state.load_pool_by_node(&id).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        state.clear().unwrap();
    }

    #[test]
    fn pool_v2_atomic_overwrite() {
        // Successive saves should end up with only the latest content —
        // no partial file from an interrupted write.
        let dir = test_dir();
        let state = StateDir::open(&dir).unwrap();
        let id = crate::identity::NodeId::from_bytes([0x56; 48]);
        for i in 0..10u8 {
            let buf = vec![i; 32 * (i as usize + 1)];
            state.save_pool_by_node(&id, i as usize, &buf).unwrap();
            let (cur, loaded) = state.load_pool_by_node(&id).unwrap().unwrap();
            assert_eq!(cur, i as usize);
            assert_eq!(loaded, buf);
        }
        state.clear().unwrap();
    }

    #[test]
    fn crc32_known_vector() {
        // CRC32/IEEE of "123456789" is 0xCBF43926 (standard test vector).
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32_ieee(b""), 0);
    }

    #[test]
    fn test_channel_meta_roundtrip() {
        let dir = test_dir();
        let state = StateDir::open(&dir).unwrap();

        state.save_channel_meta(7, 100000, "active").unwrap();
        let (bits, status) = state.load_channel_meta(7).unwrap().unwrap();
        assert_eq!(bits, 100000);
        assert_eq!(status, "active");

        state.clear().unwrap();
    }

    #[test]
    fn test_list_peers() {
        let dir = test_dir();
        let state = StateDir::open(&dir).unwrap();

        state.save_pool(5, 0, &[0; 10]).unwrap();
        state.save_pool(3, 0, &[0; 10]).unwrap();
        state.save_pool(8, 0, &[0; 10]).unwrap();

        let peers = state.list_peers().unwrap();
        assert_eq!(peers, vec![3, 5, 8]);

        state.clear().unwrap();
    }

    #[test]
    fn test_trust_edges_roundtrip() {
        let dir = test_dir();
        let state = StateDir::open(&dir).unwrap();

        let edges = vec![(1, 2, 1.0), (2, 3, 0.5), (3, 1, 0.75)];
        state.save_trust_edges(&edges).unwrap();

        let loaded = state.load_trust_edges().unwrap().unwrap();
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded[0].0, 1);
        assert_eq!(loaded[0].1, 2);
        assert!((loaded[0].2 - 1.0).abs() < 1e-10);
        assert!((loaded[2].2 - 0.75).abs() < 1e-10);

        state.clear().unwrap();
    }

    #[test]
    fn test_missing_files_return_none() {
        let dir = test_dir();
        let state = StateDir::open(&dir).unwrap();
        assert_eq!(state.load_node_id().unwrap(), None);
        assert!(state.load_pool(999).unwrap().is_none());
        assert!(state.load_channel_meta(999).unwrap().is_none());
        assert!(state.load_trust_edges().unwrap().is_none());
        state.clear().unwrap();
    }
}
