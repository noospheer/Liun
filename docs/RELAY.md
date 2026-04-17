# Bootstrap Relays

How the k-path bootstrap works, what a relay is, how to run one, and what
diversity actually means for security.

## Why relays exist

The Liu protocol generates information-theoretically secure key material,
**given** a pre-shared key of ~12 KB. The chat binary uses k-path bootstrap
to produce that PSK over the network without a USB stick, in-person meetup,
or any other out-of-band channel.

The math:

- One peer generates k random shares `s_1 ... s_k`, each the size of the PSK.
- Each share is uploaded to a different relay.
- The other peer downloads all k shares.
- Both peers compute `PSK = s_1 ⊕ s_2 ⊕ ... ⊕ s_k`.

Each individual share is uniform-random bytes. Leaking one share reveals
**zero** about the resulting PSK — XOR with unknown-uniform is uniform.
Only an adversary who observes (or compromises) **every** relay can
reconstruct the PSK. Missing even one collapses her to guessing.

This is proved in Lean (`Bootstrap.lean`): **if ≥1 relay is unobserved,
the derived PSK is perfectly secret.**

## What a relay does

`liun-relay` is a stateless HTTP dead drop:

```
POST /share/{session_id}    → stores the body (first POST wins, 409 on re-POST)
GET  /share/{session_id}    → returns the stored body, or 404
```

- No auth. Shares are individually uniform-random; there's nothing to protect
  at the per-relay level.
- No TLS. The XOR structure already protects the reconstructed PSK; TLS would
  only add computational assumptions and CA trust roots.
- 1-hour TTL. After that the slot is reclaimable for a fresh session.
- Max share size: 64 KB.

Running one:

```bash
./target/release/relay --listen 0.0.0.0:8080
```

The binary is ~1 MB, statically linked (musl target), and uses a few MB
of RAM. It will run on a $3/month VPS, a Raspberry Pi, or a home router
with Rust cross-compiled for it.

## The relays.toml directory

Both peers in a bootstrap session must have **the same directory in the
same order**. Share `i` goes to `relays[i]`, and the XOR is position-independent
but the HTTP addressing is not — a directory mismatch means downloads fail
and bootstrap aborts with a clear error.

Example `~/.config/liun/relays.toml`:

```toml
[[relay]]
url = "http://relay-de.example.com:8080"
operator = "alice"
jurisdiction = "DE"

[[relay]]
url = "http://relay-us.example.org:8080"
operator = "bob"
jurisdiction = "US"

[[relay]]
url = "http://relay-jp.example.net:8080"
operator = "carol"
jurisdiction = "JP"
```

`operator` and `jurisdiction` are informational only — they help humans reason
about diversity. The code doesn't enforce them.

## What diversity actually means

The security guarantee is **"at least one relay unobserved by the adversary."**
This is not a property of the relay software — it's a property of who runs
the relays and where they sit on the network.

**20 relays all hosted on AWS give you k≈1 security against AWS, DHS, or
anyone with AWS-wide visibility.** A cloud provider seeing all traffic learns
every share.

A credible k=3 deployment has shares go to:

- **Different operators.** Not three VPSs you rent. Three *different people*
  running relays. Their server compromises are independent.
- **Different networks.** Different ASNs, different transit paths. A
  router-level attacker on one ISP can't see the others.
- **Different jurisdictions.** If legal compulsion is in the threat model,
  relays in different countries raise the bar.

Ideal:
- One relay run by you.
- One relay run by someone you know, on infrastructure they control.
- One relay run by an unrelated party (community list, paid service, Tor hidden
  service, another project's operator).

**Marginal:**
- Three relays all on cloud providers you don't admin (blind trust).
- Three relays in one country with one legal regime.
- Three relays run by the same person on different hosts.

The Lean proof still covers the math (if ≥1 unobserved, secret). What changes
is whether the "≥1 unobserved" assumption actually holds in your threat model.

## Session IDs

A session ID is the rendezvous key that tags shares at each relay. It is
**not secret** — both peers exchange it in the clear through any channel
(SMS, email, spoken aloud). Its job is to prevent collision between
concurrent bootstrap sessions on the same relays, not to authenticate
anything.

Choose a new session ID for each bootstrap. Reusing an old one will collide
with the cached entry at the relay (TTL: 1 hour) and return 409. On collision,
pick a different session ID and retry.

Format: 1-128 chars of `[A-Za-z0-9_-]`. Not case-sensitive by convention.

## Failure modes and errors

| Symptom | Likely cause |
|---|---|
| `PartialUpload: 409 conflict` on all relays | Session ID already used within the last hour. Pick a new one. |
| `PartialDownload: 404` on all relays | Consumer ran before provider uploaded. Start `listen` first, `connect` second. |
| `PartialDownload: mixed 404 / network error` | A relay is down. Either wait for it, or edit the directory and retry. |
| MAC fails on first chat message | PSKs don't match. Most likely: the two peers have different `relays.toml` (different order or different URLs). |
| `connection refused` to a relay | Relay process down, or firewall blocking the port. |

## Running your own relay — deployment sketch

On a publicly routable host:

```bash
# Option 1: direct
./liun-relay --listen 0.0.0.0:8080

# Option 2: systemd unit (see docs/liun-relay.service.example, if present)
systemctl --user enable --now liun-relay
```

Open the port in your firewall. The relay has no config file — it listens
on whatever you pass. Logs go to stderr.

Publish your relay's URL + operator + jurisdiction and let peers add it to
their `relays.toml`. Two peers who both trust your relay can use it as
*one of their k*; they'd be reckless to use it as their *only* relay.

## What this does NOT protect against

- **Global passive adversary who observes every relay.** The k=3 defaults are
  a demo baseline; for adversaries at the TLA/nation-state level, k=20 and
  geographically diverse relays are the intended deployment.
- **Active MITM on the TCP chat connection itself.** The attacker can drop or
  corrupt packets, but cannot decrypt — they don't have the PSK unless they
  also observed all k relays. MAC failures will surface any tampering.
- **Relays that collude.** k-of-k secret sharing: ALL k relays together
  recover the PSK. Diversity of operators is what makes collusion hard.
- **Keylogged session ID or compromised endpoint.** These are endpoint
  security problems, not bootstrap ones.

## What happens after bootstrap

Once both peers derive the PSK, the relays are no longer involved. The
chat binary multiplexes two things on a single TCP connection:

- **Chat messages** — OTP-encrypted, Wegman-Carter MAC-authenticated from
  a pool seeded by the PSK.
- **Liu protocol exchange** — Gaussian noise exchange + Toeplitz privacy
  amplification continuously deposits fresh provably-ITS key material
  into the pool, so it never exhausts. Pool alternation across rounds
  gives positive net growth (+0.5 B/round per pool).

TCP drops are survived in-process: pool state lives in RAM, both peers
reconnect and resume without touching the relays or re-bootstrapping.
Process death destroys key material — this is a feature (forward secrecy),
not a bug. To recover after a restart, do a fresh bootstrap with a new
session ID.

## Future work

- **k=20 default with community directory.** Requires published set of
  trusted relays. Coordination problem, not a code problem.
- **Tor hidden service transport for relays.** Would add a genuinely
  independent path diversity layer (Tor's anonymity + the k-path XOR).
- **Short-lived session IDs via client-side HMAC.** Would allow both peers
  to derive a fresh session ID per reconnect attempt without manual
  coordination, reducing the 409-on-reuse friction.
