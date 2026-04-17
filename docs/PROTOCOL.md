# Wire protocol reference

All wire formats used by this codebase, with versioning discipline.

## 1. DHT (UDP, binary, big-endian)

Source: `liun-dht/src/message.rs`. Used for peer discovery.

```
Frame header (56 bytes):
  [version: 1] [kind: 1] [txn_id: 4] [sender_id: 48] [sender_channel_port: 2]
  [payload...]

Kinds:
  0x01 PING        — empty payload
  0x02 PONG        — empty payload
  0x03 FIND        — payload: target_id[48]
  0x04 NODES       — payload: count[1] + count × WireContact

WireContact (per entry in NODES):
  [id: 48] [family: 1] [addr: 4 or 16] [udp_port: 2] [channel_port: 2]
    family = 4 for IPv4, 6 for IPv6
```

**Versioning**: the leading byte is the protocol version, currently **2**.
Decode fails with `BadVersion(N)` on mismatch; the packet is silently
dropped, no response sent. No fallback path — a future version would
have a different constant and reject v2 packets.

**Authentication**: none at this layer. Entries are hints; the Liun
channel handshake + MAC at the TCP layer provides all authentication.
(See `docs/DHT.md` for the rationale.)

## 2. Chat multiplex (TCP, binary, big-endian)

Source: `src/bin/chat.rs`. Used for the per-session chat stream.

```
Frame:
  [type: 1] [len: 4 BE] [payload: len]

Types:
  0x01 FRAME_TYPE_CHAT      — chat message payload
  0x02 FRAME_TYPE_EXCHANGE  — Liu protocol exchange packet
  0x03 FRAME_TYPE_SYNC      — pool state fingerprint handshake (first frame)

Limits:
  len ≤ MAX_FRAME_PAYLOAD (2 MiB). Exceeding → connection dropped.

Chat payload (type 0x01):
  [mac_tag: 8] [timestamp: 8] [ciphertext: len - 16]
  MAC covers (timestamp || ciphertext).

Exchange payload (type 0x02):
  Variable — one of the three exchange-step formats in liun-channel.

Sync payload (type 0x03), sent once per session as the first frame:
  [my_send_pool_fp: 8] [my_recv_pool_fp: 8]
  Peer's send-pool fingerprint must match our recv-pool fingerprint, and
  vice versa, or the session aborts with a POOL STATE MISMATCH error.
```

**Versioning**: no explicit version byte. Forward extension is done by
adding new type codes. Unknown type codes are logged and skipped
(forward-compatible). MAC-authenticated types (0x01) reject tampered
content.

A future breaking change would need a new type code + a coordinated
rollout, since old versions would silently skip the new type.

## 3. Bootstrap relay (HTTP/1.1)

Source: `liun-overlay/src/relay_server.rs`. Used for PSK bootstrap
dead-drops.

```
POST /share/{session_id}    body = share bytes → 200 stored / 409 conflict / 413 too large
GET  /share/{session_id}                      → 200 share bytes / 404 not found
```

Constraints:
- `session_id` ∈ `[A-Za-z0-9_-]{1,128}`; 400 on violation.
- Share body ≤ 64 KiB; 413 on violation.
- TTL 1 hour; entries auto-evicted.
- No authentication: shares are individually uniform-random bytes;
  only the XOR of all k reveals the PSK, and an adversary must observe
  ≥ all relays to reconstruct. See `docs/RELAY.md`.

**Versioning**: plain HTTP/1.1, no application version. Path format is
the extension point: `/share/v2/...` would be a new API.

## 4. Pool state fingerprint (inside chat sync frames)

Used for reconnect divergence detection. Spec in `liuproto-core/src/pool.rs`:

```
fingerprint = SipHash(cursor : u64, buf_len : u64, mac_r : u64, mac_s : u64)
             (via std::collections::hash_map::DefaultHasher)
```

**Not cryptographic-grade collision-resistant** — purpose is detection
of accidental pool desync. Hash output is 64-bit; a collision requires
~2³² work, and produces only a brief MAC-fail delay (one message). MAC
keys don't leak through the hash: preimage resistance of SipHash is
~2⁶⁴, already higher than brute-forcing the 61-bit field.

## Downgrade-attack resistance summary

For each protocol layer, an on-path adversary who strips or rewrites
version / type bytes can:

| Protocol | Attack | Outcome |
|---|---|---|
| DHT | Strip/rewrite version byte | Packet dropped; no fallback; DoS only |
| Chat mux | Rewrite type byte | MAC fails; session aborts after 3 consecutive fails |
| Sync handshake | Corrupt payload | Session aborts with explicit mismatch message |
| Relay HTTP | Rewrite path/method | 400 / 404 / 413; no fallback |

**No silent downgrade path exists in any layer.** Each version mismatch
surfaces as an error to the operator, never as a silent re-negotiation
to a weaker protocol.
