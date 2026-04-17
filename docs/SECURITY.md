# Security

This document covers the operational security discipline of the
`liun-node` codebase — supply-chain hygiene, hardening, known gaps.

For the *protocol* security (what the Lean proofs cover, what the ITS
claim assumes), see `README.md` and the Lean proofs in `LiupProofs/`.

## Supply-chain discipline

### `cargo audit` — RustSec advisories

Install once:
```bash
cargo install --locked cargo-audit
```

Run manually:
```bash
cargo audit
```

Pinned to `Cargo.lock` — will flag any dep with a known vulnerability in
the [RustSec advisory database](https://rustsec.org/). Run before every
release, and ideally daily via CI (see `.github/workflows/audit.yml`).

### `cargo deny` — license + duplicate policy

Install once:
```bash
cargo install --locked cargo-deny
```

Run manually:
```bash
cargo deny check
```

Enforces the policy in `deny.toml`:
- Reject yanked crates
- Only OSI-approved permissive licenses (MIT, Apache-2.0, BSD, ISC, …)
- No wildcard (`"*"`) version specifiers — always pin
- Only crates.io as registry; no unreviewed git dependencies

### Reproducible builds

Building the same `Cargo.lock` + source tree on two machines should
produce byte-identical `liun-node` binaries. The CI workflow runs
`cargo build --locked` twice and diffs the SHA-256. A mismatch blocks
the release.

This lets downstream users verify they got the binary the release
claimed — trust-on-first-use for the binary signature equivalent to the
source review.

### Lockfile discipline

- `Cargo.lock` is checked in — all builds pin to exact versions.
- Never `cargo update` without reviewing the diff (new transitive deps
  are new trust surface).
- `cargo update --package X` for targeted bumps; avoid `cargo update`
  alone.

## Process hardening

### What `liun-node` and `chat` do themselves

On Linux, every binary at startup (unless `--debug-allow-core-dumps`):
- `prctl(PR_SET_DUMPABLE, 0)` — no core dumps on crash, no ptrace
  attach by same-uid processes. `/proc/<pid>/` entries become
  root-owned.

With `--mlock-memory` (opt-in; requires `CAP_IPC_LOCK`):
- `mlockall(MCL_CURRENT | MCL_FUTURE)` — no process page ever swaps.

### What the systemd unit provides on top

See `deploy/liun-node.service`:
- `MemorySwapMax=0` — process cgroup can't use swap. Complements
  `mlockall` (belt + suspenders).
- `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes` —
  standard systemd sandbox.
- `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectControlGroups=yes`.
- `RestrictSUIDSGID=yes`, `RestrictRealtime=yes`, `RestrictNamespaces=yes`.
- `LockPersonality=yes`, `MemoryDenyWriteExecute=yes`.
- `ReadWritePaths=/var/lib/liun`, `ReadOnlyPaths=/etc/liun`.
- `AmbientCapabilities=CAP_IPC_LOCK` so the process can mlock.

### In-process memory hygiene

- `Pool`, `Gf61`, `OTP` outputs are zeroized on `Drop` via the `zeroize`
  crate.
- MAC comparison uses `subtle::ConstantTimeEq` — no branch on tag value.
- GF(M61) arithmetic is branchless on secret inputs — the mod reduction
  step is written as a CMOV-style mask rather than `if x >= M61 {…}`.

## Wire protocol versioning

All wire formats are explicitly versioned:

| Protocol | Current version | Rejection behavior |
|---|---|---|
| DHT messages (`liun-dht::message`) | v2 (added `channel_port`) | `BadVersion(N)` error returned; packet dropped silently |
| Chat mux frames (`src/bin/chat.rs`) | v1 (implicit, frame type encodes protocol) | Unknown frame type logs and skips |
| Relay HTTP (`liun-overlay::relay_server`) | HTTP/1.1 | Non-HTTP/1.x returns 400 |
| Pool state fingerprint handshake (`FRAME_TYPE_SYNC`) | v1 (8+8 bytes) | Mismatch aborts session with diagnostics |

A downgrade attack (adversary stripping or rewriting a version byte) is
not possible because mismatched versions refuse to decode. An adversary
could cause a *denial of service* by corrupting packets, but not a
silent fallback to a weaker protocol.

## Known gaps (not yet closed)

Honest list — these are real and worth fixing for a production
deployment, but are explicitly out of scope for the current codebase:

- **No fuzz corpus**: the proptest-based parser fuzz covers the DHT
  wire format, but there's no coverage-guided corpus stored. Would
  want `cargo-fuzz` harnesses for the HTTP parser (relay) and chat
  frame parser, persistent corpus in `fuzz/corpus/`.
- **No cross-language bit-exactness tests**: spec vectors ensure Rust
  matches the math. They don't automatically check Rust against
  running Python Liup.
- **No formal Rust ↔ Lean correspondence**: Lean proofs cover the
  algorithm; the Rust implementation is by-hand correspondence.
  Machine-verified correspondence via Kani / Creusot would be a
  strong next step.
- **No hardware memory encryption**: against a cold-boot adversary
  with physical RAM access, we rely on process-level hardening plus
  systemd restrictions. SGX / SEV would raise the bar further but
  require hardware we can't assume.
- **No TRNG failover**: `--rng rdseed` refuses to start if RDSEED
  isn't available; we don't try a different TRNG source. Hardware
  TRNG cards (ChaosKey, TrueRNG) exist and could be wired in via a
  kernel entropy pool path.

## Reporting vulnerabilities

Security issues → open a private GitHub security advisory rather than a
public issue. Non-security bugs → regular issue tracker.
