# Multi-arch by design: no platform is pinned.
#   dev  (Apple Silicon): docker build .            -> native arm64
#   prod (x64 linux):     built on the server       -> native amd64
#   amd64 image from Mac: docker buildx build --platform linux/amd64 .

# ── 1. Frontend (Vite/React -> frontend/dist) ────────────────────
FROM node:22-bookworm-slim AS frontend
WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ── 2. Rust build ─────────────────────────────────────────────────
FROM rust:bookworm AS builder
WORKDIR /build

# pkg-config + libssl-dev: reqwest (via oauth2/openidconnect) uses native TLS
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Dependency-only build for layer caching: dummy targets + empty
# rust-embed folders (frontend/dist and template/email are embedded
# at compile time, so the folders must exist).
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src/bin frontend/dist template/email \
    && echo 'fn main() {}' > src/main.rs \
    && echo 'fn main() {}' > src/bin/openapi.rs \
    && touch src/lib.rs \
    && cargo build --release

# Real sources + built frontend; only the janux crate recompiles.
COPY build.rs ./
COPY src/ ./src/
COPY template/ ./template/
COPY --from=frontend /build/frontend/dist ./frontend/dist
RUN touch src/main.rs && cargo build --release

# ── 3. Runtime ────────────────────────────────────────────────────
FROM debian:bookworm-slim
# curl: HTTP health probes (compose healthcheck hits /api/v1/health/ready)
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /build/target/release/janux /usr/local/bin/janux

EXPOSE 8080

# Config (base.toml/seed.toml) is bind-mounted into /app; the default
# invocation loads "base" + "seed" from the working directory.
# data_dir (./data) must be a volume.
CMD ["janux"]
