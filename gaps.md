# Janux — Project Review Gaps

Fresh review conducted 2026-09-06 on a clean tree @ `31f73da`. `KNOWN_ISSUES.md` was explicitly excluded (obsolete); all findings below are verified against actual code.

**Verification snapshot:** `cargo fmt` ✅ · `cargo clippy --all-targets` ✅ 0 warnings · integration tests 30/30 ✅ · **lib suite: 248 passed, 1 FAILED** ❌

---

## 🔴 Critical — verified in code

### C1. Passkey login = full account takeover of any user
`src/passkey.rs:566-601`

`verify` mints a session JWT for the **client-supplied `rqst.username`**, while `finish_passkey_login` (`passkey.rs:277-296`) validates the assertion against a `LOGIN_CACHE` challenge keyed only by `(domain, token)` — never bound to a username. The cred-mismatch check at `:574` (`update_credential(...).unwrap_or(false)`) only *skips the counter update*; the session is still issued.

Exploit chain (all self-service):
1. Attacker signs up via magic link.
2. Registers their own passkey (registration is correctly session-gated).
3. `POST /api/v1/auth/passkey/request` with their own username → login challenge + flow token.
4. Signs with their own authenticator.
5. `POST /api/v1/auth/passkey/verify` with `"username": "<victim>"` → full session JWT for the victim including the victim's roles (incl. `root`).

The victim needs no passkey at all. The registration branch (`:503-509`) has the correct session-username check; the login branch has no equivalent.

**Fix:** store the username with the challenge and require it to match, and verify `auth_result.cred_id` belongs to `rqst.username`'s stored credentials before calling `render_passkey_auth_success`.

### C2. Any confidential client gets tenant-wide SCIM provisioning power
`src/oidc.rs:434-440`

`client_credentials` unconditionally embeds `roles: ["scim"]` (level 60) regardless of requested scope. Any machine client can create/rename/deactivate/delete users and rewrite emails tenant-wide via `/scim/v2/Users`.

**Fix:** scope→role mapping — only grant `scim` when a `scim` scope is requested *and* allowed for that client.

### C3. Lib test suite fails on the exact CI command
`src/otp.rs:1432-1462`

`otp::tests::request_throttles_per_mobile` fails in the full `cargo test --lib -- --test-threads=1` run (4th request returns 401, expected 429) but passes in isolation — an order/timing-dependent flake over the global `SEND_THROTTLE` state. CI is either intermittently red or hasn't gated recent commits.

---

## 🟠 High

### Security

- **H1.** OTP `request` returns the ceremony JWT in the body; its base64 `sub` leaks the resolved username → user enumeration + phone→username mapping on an unauthenticated endpoint (`src/otp.rs:312-331,352-359`). Email flow correctly returns `jwt: None` (`email.rs:370-377`).
- **H2.** RSA signing private keys stored as **plaintext PEM** in the tenant DB (`src/key.rs:71-94`) while TOTP/social/provider secrets are AES-GCM encrypted. DB or backup disclosure → forge any session/ID/refresh token. Compounded by tenant-delete backups that are unencrypted, never pruned, and miss WAL sidecars (`src/db.rs:560-590`).
- **H3.** Credential-removal admin endpoints bypass the role level ladder: `email/remove`, `otp/remove`, `social/remove`, `totp/remove` (`email.rs:554`, `otp.rs:543`, `social.rs:1045`, `totp.rs:684`) take a client-supplied `name` with no `require_above_user` gate — a lower admin can strip root's credentials/MFA.
- **H4.** Internal `/auth/refresh` detects reuse but doesn't poison the token family (`src/db.rs:357-366`); a stolen already-rotated token's successor keeps working. The OIDC path does this correctly (`oidc.rs:2673-2693`).
- **H5.** PKCE `plain` accepted (behind a TLS check) and advertised in discovery (`src/oidc.rs:735,964-1009`) — forbidden by OAuth 2.1 / RFC 9700.

### Architecture / robustness

- **H6.** Tenant `DashMap` **write lock held across `.await` on un-timed-out outbound HTTP**: `tenant_by_domain` returns `RefMut` (`db.rs:498-506`) held through Resend email (`email.rs:347`), Aliyun SMS (`aliclient.rs:337` — `Client::new()`, no timeout), and social IdP discovery/exchange (`social.rs:146,478,600-610`). One hung backend stalls every tenant on the same shard. The metric `janux_tenant_guard_wait_seconds` (`ops.rs:206-217`) already instruments this.
- **H7.** Zero-test modules on security-critical code: `verify.rs` (the default-deny `protect` gate), `role.rs` (level gate), `idp.rs` (client store/DCR), `crypto.rs` (`tests/unit/crypto_unit.rs` is **empty** — yet `tests/README.md:53` claims it covers tamper/round-trip), `config.rs`, `domain.rs`, `audit.rs`, `admin.rs`, `aliclient.rs`, all `src/bin/*`.

### Testing / CI / frontend

- **H8.** ~20 of 30 integration tests and most e2e tests assert only `resp.is_ok()` — an HTTP 500 passes (e.g. `z_integration_tests.rs` tenant lifecycle, admin CRUD; `e2e/oidc_flow.rs` has no full auth-code round trip). `e2e/fixtures.rs:15-46` `TestBrowser` is a stub; **no Playwright actually exists** despite README/tests-README claims and a CI step installing browsers (`ci.yml:150-151`).
- **H9.** The 49-test Python conformance suite (`tests/compliant/`) is **not in CI**, mostly skips on a fresh run (fixture-gated), and the flagship magic-link flow is `xfail(strict=True)` (`tests_op/test_magic_link.py:7-9`); seeded tenants ship an empty JWKS (also strict-xfail).
- **H10.** No supply-chain/security CI for an auth product: no `cargo audit`/`cargo deny`, no CodeQL/image scanning, no coverage reporting, no OpenAPI drift check; release binaries published with **zero tests, no checksums/signing**; macOS artifact attached manually from a dev machine; `provenance: false` + `sbom: false` on Docker releases.
- **H11.** Committed OpenAPI client is **stale**: `frontend/openapi.json` last regenerated at `9af9620`; 5 later commits changed the API surface. Sync is manual (`just openapi`) with no drift gate. Frontend: TS `strict` is **off**, 7 vitest cases total (~1800 lines of app code; `admin/App.tsx` is 1082 lines), lint/test never run in CI.
- **H12.** No `SECURITY.md` (no disclosure policy for an IdP), and the README quickstart is actively misleading: **the server never reads `.env`** (no dotenv dep; only `JANUX_*` env vars, `server.rs:318-327`) — every variable in `.env.example` is dead; real credentials live in `seed.toml`.

---

## 🟡 Medium

- **M1.** In-process ceremony state everywhere (auth codes, magic links, OTP, device codes, social sessions — `oidc.rs:25-40`, `email.rs:43`, `otp.rs:37`, `social.rs:63-77`) + per-instance rate limiters/throttles/lockouts (`router.rs:84-89`, `utils.rs:760-831`) → hard single-instance constraint; fleet-wide brute-force defense multiplies by replica count. (Single-instance is a documented design choice, but the rate-limit/lockout split is a real security degradation, not just a scaling one.)
- **M2.** Audit log records no **actor, tenant, or target** (`audit.rs:25-42`); OIDC protocol endpoints (token/authorize/consent/revoke) aren't audited at all (`router.rs:405-471`); the audit hoop logs full URIs — capturing upstream IdP `code`/`state` on the social callback and TOTP codes via GET `totp/verify` (`router.rs:188-213,208-213`).
- ~~**M3.** `UserInfo` asserts `email_verified: true` unconditionally (`oidc.rs:3134-3147`) but SCIM creates unverified emails (`scim.rs:481-484`) — RP account-linking risk.~~ **(fixed 2026-09-07)** `Email` gained a `verified: bool` column recording provenance: `email_create` (SCIM/admin attach) stays unverified; `email_create_verified` records a proof (magic-link signup/add-verify ceremonies, social provisioning — where the upstream IdP already asserted `email_verified`); `/userinfo` now reports the row's actual value. Rows converge to verified on the next ownership proof: magic-link signin (`signin_user_email` marks the row) and repeat social logins (owner-scoped `email_mark_verified_for` — never upgrades another user's row). Legacy tenant DBs are handled by an idempotent `ALTER TABLE emails ADD COLUMN verified … DEFAULT FALSE` micro-migration in `connect_tenant` (toasty's `push_schema` only CREATEs, never ALTERs); pre-M3 rows come back unverified — the honest default — and self-heal on the next ceremony. Regression tests: `email_verified_tracks_provenance`, `signin_ceremony_converges_unverified_row`, `verified_mark_is_owner_scoped`, `userinfo_email_verified_reflects_row_state`, `legacy_tenant_db_gains_email_verified_column_on_reload`, plus a SCIM-lifecycle assertion that provisioned emails stay unverified.
- **M4.** `base.example.toml` ships `encryption_key = "1234…"` + `trust_forwarded_headers = true` + `0.0.0.0`; copied verbatim → rate-limit bypass via spoofed XFF and tenant selection via spoofed `X-Forwarded-Host`. Single process-wide encryption key, no rotation, silent plaintext fallback (`crypto.rs:74-76`).
- **M5.** SCIM: only `userName eq` filtering (no `externalId`), no PATCH `remove`, list materializes the whole user table before paging (`scim.rs:339-405,636-645`), error mapping by substring match (`scim.rs:156-163`).
- **M6.** Wildcard `version = "*"` on ~27 deps incl. `salvo`, `webauthn-rs`, `oauth2`, `openidconnect`, `reqwest` (`Cargo.toml:8-40`) with no deny/audit guard; ~~`gix` and `toml` are entirely unused; `jiff`+`chrono` duplicated~~ **(partially fixed 2026-09-07)** Unused/duplicated deps removed: `gix`, `toml`, and the unused `globset` dev-dep are gone from the tree (Cargo.lock −1058 lines); the sole `chrono` use (the ACS `x-acs-date` render in `aliclient.rs`) migrated to `jiff::Timestamp::strftime` and `chrono` was dropped as a direct dep — it and `toml` now survive only as transitive deps (via salvo-acme's `certon` and `config`), so `jiff` is the single date crate. Regression test: `acs_date_format_matches_chrono_rendering` pins the wire format. Wildcard versions are deliberately retained for now (owner decision); the deny/audit guard remains open (tracked with H10).
- ~~**M7.** Docker image runs as **root**, no `HEALTHCHECK`, unpinned base tags (`Dockerfile:41-54`); compose requires a pre-created external `auth_data` volume not mentioned in README.~~ **(fixed 2026-09-07)** Runtime stage now runs as non-root `janux` (fixed UID/GID 10001, nologin, no home) with `/app/data` pre-owned and declared `VOLUME` so an empty named volume inherits the ownership on first mount; image-level `HEALTHCHECK` hits `/api/v1/health/ready` (same probe as compose, so plain `docker run` gets broken-volume detection too); all three base images are pinned by multi-arch manifest-list digest (`node:22-bookworm-slim`, `rust:bookworm`, `debian:bookworm-slim`) with bump instructions in-file. README documents the required `docker volume create auth_data` prerequisite, the UID-10001 readability requirement for bind-mounted config, and the one-off chown for volumes written by the old root-running image; compose.yml carries the same note at the `external: true` declaration. Verified with `docker build --check` (digests resolve, no lint warnings).
- ~~**M8.** `new_tenant` duplicate check inspects the wrong map (`db.rs:517` — `router` is domain-keyed); graceful shutdown has no timeout (`server.rs:247`).~~ **(fixed 2026-09-07)** `new_tenant` now checks `tenants` (the tenant-keyed map): a tenant name colliding with a registered domain is creatable again, and a real duplicate gets the honest "already exists" error instead of falling through to the misleading "directory exists but was not loaded" (regression test `new_tenant_duplicate_check_uses_the_tenant_map`). Graceful shutdown is bounded by `SHUTDOWN_GRACE` (9s, inside docker's default 10s stop-grace window) via `stop_graceful(Some(..))`, so a hung connection can no longer pin the process forever.

---

## 🟢 Low (condensed)

- Modulo bias in OTP-add digit generation (`otp.rs:647-657`).
- `render_email(...).unwrap()` panic path (`email.rs:689`).
- CORS "tenant" share-mode never matches — bare domain vs full Origin (`db.rs:429-446` / `cors.rs:38-44`).
- `/token` 200 responses missing `Cache-Control: no-store` (`oidc.rs:2582-2590`).
- Parked `callback_uri` not re-validated against current client registration (`oidc.rs:1300-1327`).
- Send-throttle keys not tenant-scoped — cross-tenant interference (`utils.rs:760-761`).
- Social callback errors echo internals with HTTP status 200 (`social.rs:847-936`).
- Provider list returns secret ciphertext (`social.rs:1176-1193`).
- DCR unbounded + `backchannel_logout_uri` SSRF surface when enabled (`oidc_ext.rs:185-342,529-566`).
- MFA policy semantics exclude passkey: `mfa.contains("totp") && mfa.len() > 1` (`policy.rs:188`).
- `validate_aud = false` globally in `jwt_decode` — callers compensate, fragile pattern (`jwt.rs:192-201`).
- Dead unrouted endpoints `all_configs` / `set_cors` (`config.rs:231`, `admin.rs:111`) — no runtime CORS management API exists.
- `OAuth2Client.domain_id` stores tenant name; FK-to-Domain relationship is dead (`idp.rs:279`).
- Unauthenticated `passkey/request` is a username oracle and discloses credential IDs (`passkey.rs:403-464`).
- Deliberate OTP lockout DoS: knowing a victim's phone allows 15-min→24-h lockout of the OTP factor (`utils.rs:817-885`, `otp.rs:262-309`).
- Stale hardcoded line-number references in `docs/INTEGRATION.md`.
- `justfile:44` `e2e-headed` filter (`env_filter=info::debug`) matches 0 tests.
- `build.rs` reruns on any `tests/` edit + dead Playwright browser detection.
- ~2.1MB of spec HTML/PDF committed in `docs/`.
- Empty untrackable `toasty/` dirs referenced by `Toasty.toml`.
- No `CONTRIBUTING.md` / `CHANGELOG.md` / `CODEOWNERS` / `rust-toolchain.toml` / dependabot.
- `base.example.toml:11` weak-pattern example encryption key (copy-paste-into-prod risk).
- Seed bootstrap creates a credential-less `root`/`admin` account; documented attach behavior is inaccurate (`seed.example.toml:62-65`).
- 3 `#[ignore]d` e2e tests with no reason/tracking; e2e helpers point at nonexistent `/signin.html`, `/signup.html`.
- `tests/compliant/README.md:35` stale path (`auth/test/compliant`).
- `grant_types_supported` omits `client_credentials` (pinned strict-xfail, `tests_op/test_discovery.py:102`).

---

## ✅ Done well

- Exact-string `redirect_uri` matching; single-use auth codes via atomic one-shot consumption.
- OIDC refresh rotation with family replay detection + poisoning per RFC 9700 §4.14.2; 30-day absolute cap.
- RS256-pinned JWT validation (no alg confusion), kid-routed verification, persistent revocation store with read-through.
- Argon2id for client secrets; AES-256-GCM with random nonces for secrets at rest (except signing keys, see H2).
- Social federation: PKCE S256 + state + nonce verified, upstream iss/aud/exp/at_hash checked, email trusted only when `email_verified`, identity keyed on `(provider, subject)` — never links by email.
- Textbook path-traversal defense in `pages.rs::confine`.
- Fail-closed default-deny policy engine; strict role ladder with undeletable builtins; root's policy set cannot be expanded even by root.
- HttpOnly/Secure/SameSite=Strict cookies with Bearer-only auth (CSRF N/A on state-changing endpoints).
- Layered per-IP rate limits, per-recipient dispatch throttles with digit-normalized keys, per-account exponential-backoff verify lockout.
- Clean secret hygiene in git history (`.env`, `seed.toml`, `base.toml` never committed).
- Device flow with fully atomic poll/approve state machine, `slow_down`, unbiased user codes.
- Back-channel logout client correctly bounded (10s timeout, bounded retries, detached).

---

## Recommended fix order

1. **C1** — passkey username binding (account takeover).
2. **C2** — scope-gate the `scim` role.
3. **C3** — fix the OTP flake so CI gates again.
4. **H3/H4** — level gate on credential removal + refresh-family poisoning.
5. **H2** — encrypt signing keys at rest (+ backup retention/WAL handling).
6. **H6** — outbound HTTP timeouts + drop the tenant guard before I/O.
7. **H1** — stop returning the OTP ceremony JWT in the response body.
8. **CI hardening** — audit/deny, conformance job, OpenAPI drift gate, frontend lint/test, coverage reporting.
9. **Docs truth-up** — SECURITY.md, dead `.env` path, false Playwright/crypto-test claims.
