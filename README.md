# Janux

Multi-tenant passwordless authentication server and OpenID Connect provider.

Stack: Rust · Salvo (HTTP) · Toasty (ORM, per-tenant schema) · webauthn-rs · RSA-signed JWT · Vite/React hosted UI.

> **Status**: pre-1.0, single-instance by design (see [docs/DESIGN.md](docs/DESIGN.md) §6). The design rationale lives in [docs/DESIGN.md](docs/DESIGN.md); open issues and residuals in [gaps.md](gaps.md).

## Features

- **Passwordless factors** — magic-link email, SMS OTP, social/OIDC federation, passkeys (WebAuthn), TOTP as step-up MFA. One unified `request`/`verify` flow: signin and signup are the same ceremony ([design §1](docs/DESIGN.md)).
- **OIDC provider** — authorization code + PKCE, refresh rotation with reuse detection, `/userinfo`, JWKS, introspection/revocation (RFC 7662/7009), device flow, dynamic client registration (RFC 7591, opt-in), RP-initiated and back-channel logout.
- **Multi-tenancy** — tenants resolved from the request `Host`, each with its own database schema, signing keys, policies, and provider config.
- **RBAC** — bounded role hierarchy with a level gate that closes privilege escalation by construction; default-deny authorization on every endpoint.
- **SCIM 2.0** — `/scim/v2/*` provisioning surface driven by a `client_credentials` machine principal.
- **Hosted UI** — one unified login page (username → factor picker → verify), plus admin, consent, and device-login pages, generated from the OpenAPI spec.

## Quickstart (development)

Prerequisites: Rust (stable), Node 22, [just](https://github.com/casey/just).

```sh
cp base.example.toml base.toml      # edit bind/data_dir/encryption_key
cp seed.example.toml seed.toml      # bootstrap tenant; set the admin's `email` to an inbox you control (first sign-in)

just dev           # backend + frontend dev servers
just run           # build frontend, run server
just openapi       # regenerate frontend/openapi.json + TS client
just test          # unit + integration + e2e
```

With no providers configured in `seed.toml`, the corresponding factors simply don't activate; the server still runs and serves the OIDC/admin/SCIM surfaces. Provider credentials (mail, SMS, social OAuth) are per-tenant seed config — **not** environment variables; `.env.example` documents the only env vars the server reads (`JANUX_CONFIG_FILE`, `RUN_ENV`, `JANUX__*` field overrides) and nothing loads a `.env` file automatically.

## Docker

```sh
docker volume create auth_data      # required once — compose mounts it as an EXTERNAL volume
docker compose up --build           # builds and tags janux:latest locally
```

Published multi-arch images (linux/amd64 + linux/arm64) are built by the `Release Docker` workflow on version tags:

```sh
docker pull ghcr.io/afmkt/janux:latest                                        # global
docker pull crpi-zuhwpd6fwca3b0fc.cn-shanghai.personal.cr.aliyuncs.com/afmkt/janux:latest  # mainland China
```

Point a deployment at a published image via `JANUX_IMAGE` / `JANUX_PULL=always` (see `compose.yml`).

### Deployment notes

- Put the server behind a reverse proxy that overwrites `X-Forwarded-*` and flip `trust_forwarded_headers` to `true`, then name that proxy in `trusted_proxies` (IP/CIDR allow-list, G-149): header authority is restricted to those peers, so a directly reachable port can no longer be tenant-spoofed or limiter-bypassed. With the list empty and `true` set, every peer is trusted (boot logs a loud warning); if directly reachable, keep the shipped default `false`.
- Run **one instance** per data dir: ceremony state (magic links, OTP codes, challenges, rate limits) is process-local **by design** — it fails closed on loss, and only the revocation store is shared via `jwt.db` (DESIGN.md §6).
- Persist the `data/` volume — it holds every tenant schema and the signing keys.
- The container runs as non-root **UID/GID 10001** (`janux`). An empty `auth_data` volume inherits that ownership on first mount; bind-mounted config (`base.toml`/`seed.toml`) must be readable by UID 10001. Upgrading a volume written by the old root-running image needs a one-off chown:
  ```sh
  docker run --rm -v auth_data:/data debian:bookworm-slim chown -R 10001:10001 /data
  ```
- Base images are pinned by digest in the `Dockerfile`; bump them deliberately (the tag names sit next to each digest, and the Hub tag pages list the current index digest).

## Configuration

Layered TOML: `janux -c base -c seed` (later files override; `JANUX_*` env vars override everything).

| File | Purpose | Tracked? |
|---|---|---|
| `base.example.toml` / `base.toml` | bind address, data dir, encryption key, proxy trust | example tracked, local gitignored |
| `seed.example.toml` / `seed.toml` | bootstrap tenant (roles, users, policies, provider config) | example tracked, local gitignored |
| `.env.example` | documents the only env vars the server reads (`JANUX_CONFIG_FILE`, `RUN_ENV`, `JANUX__*` overrides) — not auto-loaded; provider credentials live in `seed.toml` (G-134) | example tracked |
| `tests/test_config.toml` | test config with dummy values | tracked |

The seed shape is pinned by the `seed_toml_bootstraps_builtin_roles` test, so a typo fails at `cargo test` time instead of as a lockout on first boot.

## Backup & restore

The data dir holds every tenant schema, all signing keys, and the revocation store. Backups are **cold** operations (the databases are exclusively locked while the server holds them — `janux backup` verifies this and refuses to copy a live tree):

```sh
# stop the server, then:
janux backup ./backups          # → backups/backup-<timestamp>/ + manifest.json
janux restore ./backups/backup-<timestamp>          # into an empty data dir
janux restore ./backups/backup-<timestamp> --force  # disaster recovery: replace the data dir
janux rekey <64-hex-new-key>    # rotate the encryption key: re-encrypts every at-rest secret
```

`janux rekey` re-encrypts signing-key privates, social provider secrets, TOTP secrets and the stored mail/SMS credentials under the new key (upgrading any legacy plaintext rows on the way); the current config `encryption_key` is the old key, and after a successful run you must put the new one in the config or the next boot cannot decrypt.

The complete restore set is the backup dir **plus** your config files (`base.toml`/`seed.toml`) **plus** the `encryption_key` — without the key, the at-rest secrets (signing-key privates, provider credentials, TOTP secrets) in the backup are unrecoverable. Delete-time tenant snapshots (`backups/` inside the data dir, retention 5) travel with the backup. Schedule it with cron/systemd timers; `just backup` wraps the common case.

## Testing

```sh
just unit          # lib suite + tests/unit (single-threaded, matches CI)
just integration   # integration tests against an auto-started server
just e2e           # HTTP-level e2e against an auto-started server
just compliant     # OIDC/SCIM conformance suite (Python, needs uv)
```

## Repository layout

| Path | Contents |
|---|---|
| `src/` | Server: `router.rs`, factors (`email`, `otp`, `totp`, `passkey`, `social`), OIDC IdP (`oidc.rs`, `oidc_ext.rs`), RBAC (`role.rs`, `policy.rs`), tenancy (`db.rs`, `domain.rs`, `seed.rs`) |
| `frontend/` | Vite + React multi-entry app (`login`, `admin`, `consent`, `device`) with a generated OpenAPI client (`src/api/`) |
| `tests/` | lib + `unit_tests`, `z_integration_tests`, HTTP-level e2e (`all_tests`), Python conformance suite (`compliant/`) |
| `docs/` | Design decisions, integration guide, reference specs (OIDC Core, RFC 6749/6750, SCIM, SAML) |

## Documentation

- [docs/DESIGN.md](docs/DESIGN.md) — the design decisions (unified passwordless flow, stateless JWTs, role hierarchy, tenancy, serialization guarantees, SCIM, OIDC extensions).
- [docs/INTEGRATION.md](docs/INTEGRATION.md) — hands-on walkthrough: run the server, get an admin session, register a relying party, build a sample OIDC client end-to-end.
- [gaps.md](gaps.md) — the current project review: open gaps (`G-*` IDs), closed items with fix notes, and the recommended fix order.

## License

Copyright 2026 the Janux authors. Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE).
