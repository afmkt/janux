# Janux

Multi-tenant passwordless authentication server and OpenID Connect provider.

Stack: Rust · Salvo (HTTP) · Toasty (ORM, per-tenant schema) · webauthn-rs · RSA-signed JWT · Vite/React hosted UI.

> **Status**: pre-1.0, single-instance by design (see G-87). The design rationale lives in [docs/DESIGN.md](docs/DESIGN.md); open issues and residuals in [KNOWN_ISSUES.md](KNOWN_ISSUES.md).

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
cp seed.example.toml seed.toml      # bootstrap tenant: roles, users, policies, providers
cp .env.example .env                # provider credentials (mail, SMS, social OAuth)

just dev           # backend + frontend dev servers
just run           # build frontend, run server
just openapi       # regenerate frontend/openapi.json + TS client
just test          # unit + integration + e2e
```

With no providers configured in `.env`/`seed.toml`, the corresponding factors simply don't activate; the server still runs and serves the OIDC/admin/SCIM surfaces.

## Docker

```sh
docker compose up --build           # builds and tags janux:latest locally
```

Published multi-arch images (linux/amd64 + linux/arm64) are built by the `Release Docker` workflow on version tags:

```sh
docker pull ghcr.io/afmkt/janux:latest                                        # global
docker pull crpi-zuhwpd6fwca3b0fc.cn-shanghai.personal.cr.aliyuncs.com/afmkt/janux:latest  # mainland China
```

Point a deployment at a published image via `JANUX_IMAGE` / `JANUX_PULL=always` (see `compose.yml`).

### Deployment notes

- Put the server behind a reverse proxy that sets `X-Forwarded-*` and keep `trust_forwarded_headers = true`; if it is directly reachable, set it to `false` (a gitignored `janux.toml` override works well).
- Run **one instance** per data dir: ceremony state (magic links, OTP codes, challenges, rate limits) is process-local (G-87).
- Persist the `data/` volume — it holds every tenant schema and the signing keys.

## Configuration

Layered TOML: `janux -c base -c seed` (later files override; `JANUX_*` env vars override everything).

| File | Purpose | Tracked? |
|---|---|---|
| `base.example.toml` / `base.toml` | bind address, data dir, encryption key, proxy trust | example tracked, local gitignored |
| `seed.example.toml` / `seed.toml` | bootstrap tenant (roles, users, policies, provider config) | example tracked, local gitignored |
| `.env.example` / `.env` | provider credentials (Aliyun SMS/mail, Resend, GitHub OAuth, JWT secret) | example tracked, local gitignored |
| `tests/test_config.toml` | test config with dummy values | tracked |

The seed shape is pinned by the `seed_toml_bootstraps_builtin_roles` test, so a typo fails at `cargo test` time instead of as a lockout on first boot.

## Testing

```sh
just unit          # unit tests
just integration   # integration tests (single-threaded)
just e2e-setup     # once: install Playwright browsers
just e2e           # Playwright-driven e2e against an auto-started server
```

## Repository layout

| Path | Contents |
|---|---|
| `src/` | Server: `router.rs`, factors (`email`, `otp`, `totp`, `passkey`, `social`), OIDC IdP (`oidc.rs`, `oidc_ext.rs`), RBAC (`role.rs`, `policy.rs`), tenancy (`db.rs`, `domain.rs`, `seed.rs`) |
| `frontend/` | Vite + React multi-entry app (`login`, `admin`, `consent`, `device`) with a generated OpenAPI client (`src/api/`) |
| `tests/` | `unit_tests`, `z_integration_tests`, Playwright-driven e2e (`all_tests`) |
| `docs/` | Design decisions, integration guide, reference specs (OIDC Core, RFC 6749/6750, SCIM, SAML) |

## Documentation

- [docs/DESIGN.md](docs/DESIGN.md) — the design decisions (unified passwordless flow, stateless JWTs, role hierarchy, tenancy, serialization guarantees, SCIM, OIDC extensions).
- [docs/INTEGRATION.md](docs/INTEGRATION.md) — hands-on walkthrough: run the server, get an admin session, register a relying party, build a sample OIDC client end-to-end.
- [KNOWN_ISSUES.md](KNOWN_ISSUES.md) — open gaps (`G-*` IDs) and roadmap.

## License

Copyright 2026 the Janux authors. Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE).
