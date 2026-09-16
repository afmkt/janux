# Janux

A self-hosted, passwordless **auth server and OIDC provider** you run as a single binary. Give it a config, point a browser at it, and your users sign in with a magic link, SMS code, social login, or passkey — no passwords to manage.

Stack: Rust · Salvo · Toasty (per-tenant schemas) · webauthn-rs · RSA-signed JWT · Vite/React UI.

> **Status**: pre-1.0, single-instance by design (see [docs/DESIGN.md](docs/DESIGN.md) §6).

---

## Get started in 60 seconds

```sh
git clone https://github.com/afmkt/janux && cd janux
cp base.example.toml base.toml        # pick an admin email you control, set a real encryption_key
cp seed.example.toml seed.toml
just dev                               # starts the server + UI on http://localhost:8080
```

Then open **http://localhost:8080/login** in your browser. You'll see a unified login page that handles both first-time sign-up and return-user sign-in. Enter the admin username from `seed.toml`, pick **magic-link email**, and check your inbox. Click the link — you're signed in. Open `/admin` to manage roles, users, and register OIDC clients.

> **No email provider set up?** That's fine. With no providers in `seed.toml`, the corresponding factors simply don't appear on the login page. The server still runs and serves all its API surfaces. [docs/INTEGRATION.md](docs/INTEGRATION.md) walks through the full hands-on flow step by step.

---

## What it does

### Core

- **Passwordless authentication** — magic-link email, SMS OTP, social/OIDC federation, passkeys (WebAuthn), and TOTP as step-up MFA. One unified `request`/`verify` flow: sign-in and sign-up are the same ceremony.
- **OIDC / OAuth 2.0 provider** — authorization code + PKCE, refresh rotation with reuse detection, `/userinfo`, JWKS, introspection & revocation (RFC 7662/7009), device flow, dynamic client registration (RFC 7591, opt-in), RP-initiated logout, and back-channel logout.
- **Hosted UI** — one unified login page (username → factor picker → verify), plus admin, consent, and device-login pages, all generated from the OpenAPI spec.

### Advanced

- **Multi-tenancy** — tenants are resolved from the request `Host`; each has its own database schema, signing keys, policies, and provider config.
- **RBAC** — bounded role hierarchy with a level gate that closes privilege escalation by construction; default-deny on every endpoint.
- **SCIM 2.0** — `/scim/v2/*` provisioning driven by a `client_credentials` machine principal.
- **Forward-auth demo** — `examples/` ships two `docker compose` scenarios (single-host + split-hosts) that put Janux behind Caddy to gate a protected path.

---

## Quickstart (development)

Prerequisites: Rust (stable), Node 22, [just](https://github.com/casey/just).

```sh
# 1 — create local config from the shipped examples
cp base.example.toml base.toml       # set bind address, data dir, encryption_key
cp seed.example.toml seed.toml       # set the admin's `email` to an inbox you control

# 2 — run
just dev                              # backend + frontend dev servers (http://localhost:8080)
just run                              # build frontend, run server (production-like)

# 3 — open the browser
#    → http://localhost:8080/login    (sign in / sign up)
#    → http://localhost:8080/admin    (admin UI, after signing in)

# 4 — regenerate the frontend API client when the backend changes
just openapi                          # → frontend/openapi.json + TS client
```

**Want to see Janux gate a real web app?** The `examples/` directory has two self-contained demos:

```sh
cd examples
./up.py single-host up               # janux + Caddy + a protected /app page
open https://localhost/app            # (macOS: run ./up.py single-host trust-ca first)
```

See [examples/README.md](examples/README.md) for details.

With no providers configured in `seed.toml`, the corresponding factors simply don't activate; the server still runs and serves the OIDC/admin/SCIM surfaces. Provider credentials (mail, SMS, social OAuth) are per-tenant seed config — **not** environment variables. The only env vars the server reads are `JANUX_CONFIG_FILE`, `RUN_ENV`, and `JANUX__*` field overrides (documented in `.env.example`); nothing auto-loads a `.env` file.

---

## Docker

The `examples/` directory ships the recommended deployment patterns:

```sh
cd examples

# Single-host: janux + Caddy + a static app behind auth  (recommended to start)
./up.py single-host up
open https://localhost/app

# Split-hosts: auth.example.com + app.example.com (sub-domain SSO)
./up.py split-hosts up
./up.py split-hosts trust-ca        # macOS only
open https://app.example.com/app
```

Each setup renders config, maps hostnames to 127.0.0.1, and starts a 3-container stack (Caddy → janux → nginx). See [examples/README.md](examples/README.md) for the full walkthrough.

Published multi-arch images (linux/amd64 + linux/arm64) are built by the `Release Docker` workflow on version tags:

```sh
docker pull ghcr.io/afmkt/janux:latest                                                    # global
docker pull crpi-zuhwpd6fwca3b0fc.cn-shanghai.personal.cr.aliyuncs.com/afmkt/janux:latest # mainland China
```

### Deployment notes

**Minimum viable deploy:**

- **Run one instance per data dir** — ceremony state (magic links, OTP codes, challenges, rate limits) is process-local **by design**; it fails closed on loss, and only the revocation store is shared via `jwt.db` ([DESIGN.md §6](docs/DESIGN.md)).
- **Persist the `data/` volume** — it holds every tenant schema and the signing keys.
- **Replace the example `encryption_key`** — the shipped `base.example.toml` uses a well-known dummy value (`12345678…`). Generate a fresh one with `openssl rand -hex 32`. This key encrypts every at-rest secret (signing-key privates, social provider secrets, TOTP, mail/SMS credentials); deploying with the example key means anyone who reads the data dir can decrypt them.

**Production hardening:**

- **Run behind a reverse proxy** that overwrites `X-Forwarded-*`, then set `trust_forwarded_headers = true` and name that proxy in `trusted_proxies` (IP/CIDR allow-list, G-149). With the list empty and `true` set, every peer is trusted (boot logs a loud warning); if your port is directly reachable, keep the shipped default `false`.
- The container runs as non-root **UID/GID 10001** (`janux`). Bind-mounted config (`base.toml`/`seed.toml`) must be readable by UID 10001. Upgrading a volume written by the old root-running image needs a one-off chown:
   ```sh
  docker run --rm -v auth_data:/data debian:bookworm-slim chown -R 10001:10001 /data
   ```
- Base images are pinned by digest in the `Dockerfile`; bump them deliberately.

---

## Configuration

Layered TOML: `janux -c base -c seed` (later files override earlier; `JANUX__*` env vars override everything).

| File | Purpose | Tracked? |
|---|---|---|
| `base.example.toml` / `base.toml` | bind address, data dir, encryption key, proxy trust | example tracked, local gitignored |
| `seed.example.toml` / `seed.toml` | bootstrap tenant (roles, users, policies, provider config) | example tracked, local gitignored |
| `.env.example` | documents the env vars the server reads (not auto-loaded) | example tracked |
| `tests/test_config.toml` | test config with dummy values | tracked |

The seed shape is pinned by the `seed_toml_bootstraps_builtin_roles` test, so a typo fails at `cargo test` time instead of as a lockout on first boot.

---

## Backup & restore

The data dir holds every tenant schema, all signing keys, and the revocation store. Backups are **cold** operations (the databases are exclusively locked while the server holds them — `janux backup` verifies this and refuses to copy a live tree):

```sh
# stop the server, then:
janux backup ./backups                # → backups/backup-<timestamp>/ + manifest.json
janux restore ./backups/backup-<timestamp>    # into an empty data dir
janux restore ./backups/backup-<timestamp> --force   # disaster recovery: replace the data dir
janux rekey <64-hex-new-key>          # rotate the encryption key
```

`janux rekey` re-encrypts every at-rest secret under the new key. After a successful run, **put the new key in your config** or the next boot cannot decrypt.

The complete restore set is the backup dir **plus** your config files (`base.toml`/`seed.toml`) **plus** the `encryption_key` — without the key, the at-rest secrets in the backup are unrecoverable. Schedule with cron/systemd timers; `just backup` wraps the common case.

---

## Testing

```sh
just unit           # lib suite + tests/unit (single-threaded, matches CI)
just integration    # integration tests against an auto-started server
just e2e            # HTTP-level e2e against an auto-started server
just ui             # browser-driven UI e2e (needs just ui-deps first)
just ui-deps        # install Playwright + Chromium for the UI e2e suite
just compliant      # OIDC/SCIM conformance suite (Python, needs uv)
just test           # unit + integration + e2e (excludes UI e2e — needs a browser)
```

---

## Repository layout

| Path | Contents |
|---|---|
| `src/` | Server: `router.rs`, factors (`email`, `otp`, `totp`, `passkey`, `social`), OIDC IdP (`oidc.rs`, `oidc_ext.rs`), RBAC (`role.rs`, `policy.rs`), tenancy (`db.rs`, `domain.rs`, `seed.rs`) |
| `frontend/` | Vite + React multi-entry app (`login`, `admin`, `consent`, `device`) with a generated OpenAPI client (`src/api/`) |
| `examples/` | Caddy + nginx forward-auth demos (single-host, split-hosts) |
| `tests/` | lib + `unit_tests`, `z_integration_tests`, HTTP-level e2e (`all_tests`), Python conformance suite (`compliant/`) |
| `docs/` | Design decisions, integration guide, frontend architecture, reference specs |
| `scripts/` | Operator helpers |

---

## Documentation

- [docs/INTEGRATION.md](docs/INTEGRATION.md) — **start here**: hands-on walkthrough — run the server, get an admin session, register a relying party, build a sample OIDC client end-to-end.
- [docs/DESIGN.md](docs/DESIGN.md) — design decisions (unified passwordless flow, stateless JWTs, role hierarchy, tenancy, SCIM, OIDC extensions).
- [docs/FRONTEND.md](docs/FRONTEND.md) — frontend architecture, Tier-A discovery, and per-domain page overrides.
- [examples/README.md](examples/README.md) — Caddy forward-auth deployment scenarios.

---

## License

Copyright 2026 the Janux authors. Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE).
