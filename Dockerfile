# ── Stage 1: Build ───────────────────────────────────────────────────
FROM rust:1.88-alpine AS builder

RUN apk add --no-cache musl-dev pkgconf

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

RUN cargo build --release --bin arbiter && \
    strip target/release/arbiter

# ── Stage 2: Runtime ─────────────────────────────────────────────────
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tini

COPY --from=builder /build/target/release/arbiter /usr/local/bin/arbiter
COPY arbiter.example.toml /etc/arbiter/arbiter.toml

EXPOSE 8080 3000

ENTRYPOINT ["tini", "--"]
CMD ["arbiter", "--config", "/etc/arbiter/arbiter.toml"]
