# Multi-arch by design: no platform is pinned.
#   dev  (Apple Silicon): docker build .            -> native arm64
#   prod (x64 linux):     built on the server       -> native amd64
#   amd64 image from Mac: docker buildx build --platform linux/amd64 .

# Base images are pinned by manifest-list digest (M7): reproducible
# builds, no silent toolchain drift. Bump deliberately, e.g.:
#   https://hub.docker.com/_/node?tab=tags -> 22-bookworm-slim -> digest

# ── 1. Frontend (Vite/React -> frontend/dist) ────────────────────
FROM node:22-bookworm-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5 AS frontend
WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ── 2. Rust build ─────────────────────────────────────────────────
FROM rust:bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS builder
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
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
# curl: HTTP health probes (image HEALTHCHECK + compose healthcheck hit
# /api/v1/health/ready)
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 curl \
    && rm -rf /var/lib/apt/lists/* \
    # M7: an IdP must not run as root. Fixed UID/GID (no login shell, no
    # home) so volume ownership is portable across hosts.
    && groupadd --gid 10001 janux \
    && useradd --uid 10001 --gid janux --shell /usr/sbin/nologin --no-create-home janux \
    && mkdir -p /app/data \
    && chown -R janux:janux /app
WORKDIR /app
COPY --from=builder /build/target/release/janux /usr/local/bin/janux

# Tenant DBs, signing keys and the revocation store live here. An EMPTY
# named volume mounted at this path inherits the image ownership (UID
# 10001) on first use; a volume written by the old root-running image
# needs the one-off chown documented in the README (M7).
VOLUME /app/data

EXPOSE 8080

# M7: image-level healthcheck so plain `docker run` gets the same
# broken-volume detection as compose (readiness is 503 unless the server
# state is injected and the tenant data dir is present — src/ops.rs).
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/api/v1/health/ready || exit 1

USER janux

# Config (base.toml/seed.toml) is bind-mounted into /app; the default
# invocation loads "base" + "seed" from the working directory. Mounted
# config files must be readable by UID 10001.
# data_dir (./data) must be a volume.
CMD ["janux"]
