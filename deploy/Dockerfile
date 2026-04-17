# ── Build stage ────────────────────────────────────────────────────────
FROM rust:1.83-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /src
COPY . .

# Build the three shipped binaries statically for musl.
RUN rustup target add x86_64-unknown-linux-musl && \
    cargo build --release --target x86_64-unknown-linux-musl \
        --bin liun-node --bin chat --bin relay

# ── Runtime stage ──────────────────────────────────────────────────────
FROM alpine:3.20
LABEL org.opencontainers.image.title="liun-node"
LABEL org.opencontainers.image.source="https://github.com/YOUR-ORG/liun-node"
LABEL org.opencontainers.image.description="ITS-secure network node"

RUN addgroup -S liun && adduser -S -G liun liun && \
    mkdir -p /var/lib/liun /etc/liun && \
    chown liun:liun /var/lib/liun /etc/liun

COPY --from=builder /src/target/x86_64-unknown-linux-musl/release/liun-node /usr/local/bin/liun-node
COPY --from=builder /src/target/x86_64-unknown-linux-musl/release/chat /usr/local/bin/chat
COPY --from=builder /src/target/x86_64-unknown-linux-musl/release/relay /usr/local/bin/relay

USER liun
VOLUME ["/var/lib/liun", "/etc/liun"]

# DHT UDP (7767), Liun channel TCP (7767), admin HTTP (9090)
EXPOSE 7767/udp 7767/tcp 9090/tcp

CMD ["/usr/local/bin/liun-node", \
     "--data-dir", "/var/lib/liun", \
     "--listen", "0.0.0.0:7767", \
     "--dht-listen", "0.0.0.0:7767", \
     "--admin-listen", "0.0.0.0:9090", \
     "--config", "/etc/liun/config.toml"]
