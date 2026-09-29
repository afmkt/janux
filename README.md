# Janux

A self-hosted, passwordless **auth server and OIDC provider** you run as a single binary. Give it a config, point a browser at it, and your users sign in with a magic link, SMS code, social login, or passkey — no passwords to manage.

Stack: Rust · Salvo · Toasty (per-tenant schemas) · webauthn-rs · RSA-signed JWT · Vite/React UI.




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


## Quickstart (development)


The `examples/` directory has two self-contained demos:

```sh
cd examples
./up.py single-host up               # janux + Caddy + a protected /app page
open https://localhost/app            # (macOS: run ./up.py single-host trust-ca first)
```

See [examples/README.md](examples/README.md) for details.

With no providers configured in `seed.toml`, the corresponding factors simply don't activate; the server still runs and serves the OIDC/admin/SCIM surfaces. Provider credentials (mail, SMS, social OAuth) are per-tenant seed config — **not** environment variables. The only env vars the server reads are `JANUX_CONFIG_FILE`, `RUN_ENV`, and `JANUX__*` field overrides (documented in `.env.example`); nothing auto-loads a `.env` file.




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

The data dir holds every tenant schema, all signing keys, and the revocation store. Because the databases are exclusively locked while the server runs, **stop the server first**, then back up the data dir as an ordinary file copy:

```sh
# stop the server, then copy the data dir:
tar czf backup-$(date +%s).tgz -C "$(dirname data)" data        # or:  cp -r data backups/data-$(date +%s)/
# on restore, extract into an empty data dir (disaster recovery overwrites it):
tar xzf backup-<ts>.tgz -C "$(dirname data)"                    # or:  cp -r backups/data-<ts> data
```

Schedule the copy with cron/systemd timers.

The complete restore set is the data dir **plus** your config files (`base.toml`/`seed.toml`) **plus** the `encryption_key` — without the key, the at-rest secrets (signing keys, provider credentials) are unrecoverable.

Rotate the encryption key with `janux rekey <64-hex-new-key>`, which re-encrypts every at-rest secret (signing-key privates, provider secrets, TOTP, stored mail/SMS credentials) under the new key. After a successful run, **put the new key in your config** or the next boot cannot decrypt.

Hand off the signing keys to an external verifier (e.g. PostgREST, which verifies but does **not** sign) with `janux jwks [DOMAIN]`, which prints the **public** JWKS to stdout — the private signing key is never emitted. With no `DOMAIN` it exports every tenant's set and warns that a combined multi-tenant JWKS mixes key namespaces (a `kid` is unique within a tenant, not globally); pass a `DOMAIN` to export just that domain's owning tenant. Wire PostgREST to it via `jwt-secret = "@jwks.json"` (it does not fetch JWKS over HTTP — unlike the live `GET /.well-known/jwks.json` endpoint).


## Repository layout

| Path | Contents |
|---|---|
| `src/` | Server: `router.rs`, factors (`email`, `otp`, `totp`, `passkey`, `social`), OIDC IdP (`oidc.rs`, `oidc_ext.rs`), RBAC (`role.rs`, `policy.rs`), tenancy (`db.rs`, `domain.rs`, `seed.rs`) |
| `frontend/` | Vite + React multi-entry app (`login`, `admin`, `consent`, `device`) with a generated OpenAPI client (`src/api/`) |
| `examples/` | Caddy + nginx forward-auth demos (single-host, split-hosts) |
| `tests/` | lib + `unit_tests`, `z_integration_tests`, HTTP-level e2e (`all_tests`), Python conformance suite (`compliant/`) |
| `docs/` | Design decisions, integration guide, frontend architecture, reference specs |
| `scripts/` | Operator helpers |



