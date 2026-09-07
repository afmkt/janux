# Janux — Project Review Gaps

Fresh review conducted 2026-09-07 on the working tree @ `0d0c780`. Supersedes the deleted `gaps.md` (review of 2026-09-06) and `KNOWN_ISSUES.md` (G-* tracker, last ID G-127); G-* numbering below continues from that tracker. Method: five parallel deep reviews — OIDC/OAuth surface, passwordless factors & user lifecycle, tenancy/RBAC/SCIM/ops, frontend, tests/CI/docs — with every High finding re-verified directly in code. Findings are code-verified only; no test-run snapshot is claimed.

---

## Legacy tracker reconciliation (G-28 … G-127)

### Closed since the last tracker (verified in code)

| ID | Evidence |
|---|---|
| G-98 PKCE `plain` accepted | Rejected outright; S256-only, constant-time compare, fail-closed exchange (`src/oidc.rs:1010-1063`, `:2488-2499`); discovery advertises `["S256"]` (`:811`) |
| G-91 health/readiness/metrics stubs | Real distinct live/ready probes + Prometheus registry, 10 collectors, bounded label cardinality (`src/ops.rs:36-75,116-242`); Docker/compose healthchecks wired. Residual: readiness checks only data-dir presence; `/admin/metrics` requires an admin JWT (no unauthenticated scrape port) |
| G-110 redirect_uri enforced client-side only | Server-side allowlist at `/authorize` before any session/consent step + re-validation at `/token` against registration and parked callback (`src/oidc.rs:982-1007`, `:2361-2386`); `post_logout_redirect_uri` exact-matched (`src/oidc_ext.rs:655-693`) |
| G-111 cookie attributes client-chosen | HttpOnly/Secure/SameSite=Strict/Path=/ hardcoded server-side at all four session-cookie sites (`src/email.rs:620-627`, `src/otp.rs:520-527`, `src/totp.rs:565-572`, `src/passkey.rs:340-347`); social bind cookie HttpOnly+Secure+Lax. Cookie *name* still client-chosen — documented as intentional (DESIGN.md:72) |
| G-109 seed test depends on gitignored files | Test falls back to tracked `base.example`/`seed.example` when `seed.toml` is absent (`src/seed.rs:183-189`). Residual: a local `seed.toml` shadows the example, so local and CI validate different inputs |
| G-92 no RP-initiated/back-channel logout (mostly) | `GET|POST /end_session` with `id_token_hint` validation, exact-matched post-logout redirects, presented-session revocation (`src/oidc_ext.rs:620-735`); back-channel fan-out from both logout paths with spec-correct events-JWT shape (`src/jwt.rs:118-150`, pinned by `logout_token_round_trip_matches_spec_shape`). No `sid`/session-management/front-channel — deliberate, advertised as such (`src/oidc.rs:800-801`, DESIGN.md:69-72). Durability residual = G-126 |

### Still open (confirmed unchanged)

- **G-88** — No backup/restore/DR story. Only mechanism is the delete-time tenant snapshot (retention 5) inside `delete_tenant` (`src/db.rs:665-731`); no scheduled backup, no restore tooling, no docs. The data dir holds every tenant schema, signing keys, and the revocation store.
- **G-89** — Audit trail is an access log: method/URI/status/duration/request_id only — no actor, tenant, target user, or old→new state; attached only to mutating routes; admin mutations record no who/what/when anywhere (`src/audit.rs:5-52`, `src/router.rs:227-382`).
- **G-90** — All token lifetimes are compile-time constants (session 15 min, OIDC access 60 min, ID 15 min, refresh family 30 d, client_credentials 90 d, device 1800 s); nothing per-tenant/per-client configurable (`src/utils.rs:820`, `src/oidc.rs:398,2266`, `src/server.rs:300-318`).
- **G-93** — `/authorize` ignores `prompt` and `max_age`; no `prompt_values_supported` in discovery; `auth_time` is carried faithfully so RPs can evaluate max_age after the fact, but the OP never enforces it (`src/oidc.rs:837-851`, `:1165-1174`).
- ~~**G-94** — `acr` vocabulary mismatch: discovery emits factor names (`email`/`otp`/`social`/`passkey`, `src/oidc.rs:734-818`), tokens emit `"1"`/`"2"` (`src/db.rs:80-89`). Nothing reconciles them.~~ **(fixed 2026-09-07)** Tokens now emit the discovery factor-name vocabulary: `acr_value` reports the *strongest factor achieved* (documented order `passkey > totp > otp > email > social`), mapping internal labels to external names (`oauth2`/legacy `Social` → `social`) with a deterministic first-sorted fallback for unknown labels so a non-empty factor set never loses the claim (`src/db.rs:80-110`). The canonical step-up session `{email, totp}` reports `"totp"`, preserving the old `"2"` = MFA semantics; the policy engine reads `mfa` directly (`src/policy.rs:188`) and `amr` still carries the full RFC 8176 method list, so nothing downstream depended on the numeric levels. Discovery now also advertises `"totp"` for provisioned tenants (`src/oidc.rs:776-786`) — step-up is always available there (session-gated, no provider config), so `acr_values_supported` covers every value a token can emit; the unprovisioned-host `[]` assertions are untouched. Tests: `tests/unit/amr_unit.rs` acr cases rewritten (single-factor names, strongest-wins multi-factor, legacy `Social`, unknown-label fallback) plus round-trip expectations; device-flow test derives its expectation via `acr_value` and adapts automatically. Verified: `cargo test --lib --test unit_tests -- --test-threads=1` → 289 + 90 passed, `cargo clippy --all-targets -- -D warnings` clean.
- **G-97** — Signing-key deletion invalidates every outstanding token carrying that `kid`; no retire/publish state, no last-key guard, arbitrary "active key" re-seat (`src/key.rs:138-165`, `src/jwt.rs:193-197`). Rotation = create-then-delete = forced domain-wide logout.
- **G-99** — Signup gating declared in DESIGN.md:23 but no config key, no policy path (auth endpoints run under the policy-free `session` hoop), provisioning unconditional in every bootstrap factor (`src/email.rs:592-600`, `src/otp.rs:491-499`, `src/social.rs:396-422`).
- **G-100** — DESIGN.md:22 still lists passkey as bootstrap-capable; code requires an existing same-user session (`src/passkey.rs:469-483`). INTEGRATION.md:144 documents the real behavior — DESIGN.md was never reconciled.
- **G-101** — No account recovery path. No backup/recovery codes; passkey deactivation is self-session-only and there is **no admin endpoint to deactivate another user's passkeys** (`src/router.rs:161-173`); admin can strip credentials but cannot attach a replacement first one (see G-131).
- **G-105** — No identifier normalization/validation: email stored/looked up verbatim (only the *throttle* key is lowercased, `src/email.rs:437` vs `:126`); the session-gated add flow *does* lowercase (`:872`) — add and login disagree on casing. Mobile not E.164-validated (`+8613800000000` ≠ `13800000000`). No NFKC/IDNA/punycode anywhere. Usernames get no charset validation.
- **G-106** — No session visibility or global revocation: no endpoint lists or kills a user's sessions; deactivation explicitly leaves issued tokens alive (`src/db.rs:274-281`); compounds with G-128/G-151.
- **G-112** — Zero security response headers on hosted pages: no CSP, X-Frame-Options/frame-ancestors, X-Content-Type-Options, HSTS, Referrer-Policy anywhere in `src/` or `frontend/`; `pages::prepare` sets only Content-Type + ETag (`src/pages.rs:151-160`). The built HTML is CSP-ready (no inline scripts/styles), so login/consent pages are framable today.
- **G-121** — Revocation "insert-wins" commit point still not atomic: `cache.insert` is moka `entry().or_insert()` — verified look-then-insert against moka 0.12.15 source; two racers on an absent key can both observe absence (`src/cache.rs:34-41`, `src/jwt.rs:342-373`). Masked in-process by the tenant write guard; the DB-failure rollback can poison a family over a transient error.
- **G-124** — SCIM never verified against a live external IdP/conformance suite: the Python SCIM track covers discovery docs + unauthenticated 401 only; the conformance tenant seeds no `scim` client/policies so black-box provisioning *cannot* run (`tests/compliant/harness/config.py:9-35`); no Rust HTTP test touches `/scim/v2/*`. In-process lib tests are strong (`src/scim.rs:1018-1244`) but that is not external verification.
- **G-125** — RFC 7592 read-only: only `POST /register` + `GET /register/{client_id}`; no PUT/PATCH/DELETE; no `registration_access_token`/`registration_client_uri` issued (`src/router.rs:452-456`, `src/oidc_ext.rs:152-171,385-466`).
- **G-126** — Back-channel logout delivery: detached `tokio::spawn`, 3 attempts, 2s/4s in-memory backoff, nothing persisted; restart or RP outage > ~16 s drops the notification permanently (logout tokens expire at 120 s); delivery sequential per target — one slow RP delays all others (`src/oidc_ext.rs:537-574`).

### Partially fixed

- **G-87** — Revocation store is now a persistent `jwt.db` singleton with cache read-through: logout/rotation revocations survive restarts and propagate between instances sharing the data dir (`src/jwt.rs:229-234,381-413`). Everything else remains process-local: magic links, OTP codes/flows, OIDC ceremony caches, social sessions, passkey challenges, TOTP enroll tokens, SEND_THROTTLE, verify-failure lockouts, and all four per-IP rate limiters. One-instance-per-data-dir constraint stands (README:54, DESIGN.md:55).
- **G-122** — `user.active` transitions now level-gated (`require_above_user`), self-reactivation blocked, activeness enforced at login/refresh boundaries (`src/user.rs:165-189,665-672`, `src/db.rs:280-282,364-378`). Still open: the write is an unconditional update (no CAS), and there is no actor-level audit of who deactivated whom (G-89).
- **G-28** — Integration tests now traverse the real `protect` hoop with real root/admin sessions and seeded policies (`tests/common.rs:139-155,404-458`). Still open: ~14 admin tests assert only `resp.is_ok()` (passes on 401/403/500 — `tests/z_integration_tests.rs:95,115,161,180-208,…`), `*_requires_auth` tests assert nothing about auth, and **no HTTP-level test asserts the 403 deny path for a valid session with an insufficient role**.
- **G-127** — CI single-threads the lib suite (`ci.yml:73-77`) and test envs pin singletons to process-lifetime runtimes; root cause remains: first-call-wins process globals (`ENCRYPTION_KEY: OnceLock` set with `let _ =` from 14 test sites; global revocation store). `tests/unit/crypto_unit.rs:3-4` documents key-validation tests *removed* because of the OnceLock.

### Worsened since filed

- **G-96** — Client lifecycle still create + soft-delete only (`src/idp.rs:376-389`; `secret_grace_until` declared but never set or checked), and the "delete + recreate" rotation workaround is now **impossible for the same identifiers**: the soft-deleted row squats the `client_id` PK and its `RedirectURI` rows are never removed (see G-143). No reactivation path exists.
- **G-123** — Client delete still doesn't revoke its 90-day machine tokens (`validate_token` never consults the `OAuth2Client` row, `src/utils.rs:540-623`), and the filed mitigation ("sweep them through `/revoke`") is a silent no-op — see G-130. The only admin-side kill switch today is signing-key deletion (G-97, tenant-wide collateral) or waiting 90 days.

---

## 🔴 New — High

### ~~G-128. Role revocation never propagates: refresh re-mints stale roles~~ (closed 2026-09-07)
`src/db.rs:380-381`

`Tenant::refresh_jwt` copied `JwtData` from the presented token and refreshed only `username` from the DB; `roles` were re-minted verbatim, and the policy engine reads roles exclusively from the token. Removing a role or demoting an admin had **no effect** on any session that kept calling `/api/v1/auth/refresh` — and the internal chain has no absolute cap (G-151), so a demoted admin retained admin API access indefinitely.

**(fixed 2026-09-07)** `refresh_jwt` now reloads roles from the DB on every rotation, exactly as the login path (`authenticate_jwt`) does — a revoked role stops propagating within one token lifetime (15 min), the same contract deactivation already had (`src/db.rs:296-301`), and fresh grants are picked up on the next refresh (`src/db.rs:401-412`). `mfa` deliberately stays as-minted: it is authentication *history* bound to `auth_time` (feeds `amr`/`acr`), not the current credential inventory — re-pulling it would misreport how the session actually authenticated. Scope check: `refresh_jwt` was the only stale re-mint point — OIDC tokens carry no roles (`OidcRefreshTokenData`/`OidcAccessTokenData` hold scope/mfa/family only), and every factor verify (incl. TOTP step-up) mints through `authenticate_jwt`, which always reloaded roles. Regression test `refresh_reloads_roles_so_revocation_propagates`: mint with `admin` → revoke `admin` + grant `guest` → rotate → assert the new token lost `admin` and gained `guest`. Verified: `cargo test --lib --test unit_tests -- --test-threads=1` → 290 + 90 passed, integration 31/31, clippy `-D warnings` clean. Residual: already-minted tokens keep their stale roles until natural expiry (stateless verification by design); the unbounded internal refresh chain remains tracked as G-151, and sessions-invisibility as G-106.

### ~~G-129. Privilege escalation: `policy_create` can bind root-only resources to any sub-level role~~ (closed 2026-09-07)
`src/policy.rs:295-297`, `src/role.rs:147-152,241-252`, `src/user.rs:368-385`, `src/admin.rs:93-106,218-242`

The level gate checked only the target *role's level*, never the *resource* being attached. An admin (80) could: create a custom role at level 79 → attach the root-only `/api/v1/admin/tenant/delete|create|list` policies to it → grant themselves that role → delete/create tenants (handlers act globally on `Storage` with no additional root check), contradicting DESIGN.md:33,37 ("a policy can widen *which* endpoints are callable, never *what power* they confer"; "tenant/* bound to root only").

**(fixed 2026-09-07)** Fixed on two axes, because during implementation a binder-only check proved trivially bypassable: the engine's resolver branch (`FromQuery`/`FromHeader` targets, and `source=Nothing` shapes) never matched `resource` against the request path at all — a policy with an innocent-looking resource applied to **every** path in the domain, so an admin could grant a sub-level role the tenant surface without ever naming it.
- **Binder (resource-power gate):** `Tenant::require_root_power_for` (`src/policy.rs`) refuses to bind a root-powered resource unless the caller's effective level reaches the apex — `Bootstrap` or a `root` (100) session. The check is template-aware: `{param}` segments cover literals, so evasions like `tenant/{op}` or `{surface}/delete` are caught, and leading-slash variants are normalized. Wired into both `policy_create` (R5) and `policy_delete` (R6), for allow and deny rows alike. `ROOT_LEVEL` is tied to `BUILTIN_ROLES[0].1` (`src/role.rs`) so catalog and gate cannot drift. Root may still delegate the lifecycle surface downward (e.g. `tenant/list` to a platform-auditor role); root's *own* policy set remains unalterable via the API (`require_below` unchanged).
- **Engine (path constraint):** `can_access` now requires the resource template to match the request path in **every** branch (`resource_matches_path`: equal segment count, `{param}` covers any value) — the documented self-scoped shapes (`User`+`FromQuery ?owner=…` etc.) keep working but are finally confined to their resource; the exact-match branch (Nothing+Nothing) is untouched, preserving the SCIM canonicalization contract ("matches exactly, no wildcards", `src/verify.rs:139-143`). All seeded/standard policies are Nothing+Nothing, so no shipped policy changes behavior.
- **Tests:** the HTTP-level expectation that codified the vuln (`policy_create_denies_own_and_superior_roles` asserting OK for admin binding `tenant/delete`→`user`) is inverted to FORBIDDEN with the downward-write case moved to a non-root resource; new lib gates `policy_create_root_resource_requires_root_power` (all three tenant paths, two template evasions, slash-less form, deny rows, resolver-shape smuggling, root/Bootstrap delegation, non-root resources unaffected) and `policy_delete_root_resource_requires_root_power`; new engine tests `test_query_target_policy_does_not_leak_to_other_paths`, `test_nothing_source_with_query_target_is_path_constrained`, `test_param_template_stays_within_its_shape`. Verified: 292 lib + 93 unit + 31 integration passed (`--test-threads=1`), clippy `-D warnings` clean.
- Residual (tracked elsewhere): `/api/v1/admin/metrics` is process-global yet bound to `admin` in the standard set — cross-tenant telemetry disclosure, filed as a separate Low finding; G-148 (no domain-ownership validation) still lets a tenant admin squat hostnames within its own tenant.

### G-130. Machine tokens are invisible to `/revoke` and `/introspect`
`src/oidc.rs:3372` (revoke), `:3640-3648` (introspect), `src/db.rs:140-150`, `src/oidc.rs:510-516`

Both endpoints bind the presented token to the calling client via `data.get("client_id")` — but `JwtData` has **no `client_id` field**; for `client_credentials` tokens the client id lives only in `aud`. The lookup yields `""` ≠ `client.id`, so `/revoke` returns RFC-7009 200 **without recording any revocation**, and `/introspect` reports `active: false` for a live token. Machine tokens are also never written to `OIDC_TOKEN_CACHE`, so the fast path can't rescue them. This kills the code's own documented contract ("expiry is a backstop and `/revoke` is the off switch", `src/oidc.rs:395-398`) and removes the only standards-based remedy for a leaked 90-day SCIM principal (G-123). Workaround that does work: presenting the raw token to `/api/v1/auth/logout` — but that requires possessing the token.

**Fix:** fall back to `claims.aud` when `data.client_id` is absent (one-line class fix in both handlers).

### G-131. Bootstrap lockout: seeded/admin-created users can never obtain a first credential
`src/email.rs:61-85`, `src/otp.rs:57-77`, `src/seed.rs:159-167`, `src/user.rs:451-467`, `src/router.rs:286-300`

Seeded `admin`/`demo`, `admin/user/create`, and `bootstrap_tenant`'s first admin are all created credential-less (seed `UserDTO` has no email field). Strict signup fails on the pre-existing `#[unique] name`; strict signin requires the credential to already be attached; there is **no admin endpoint to attach a first credential** (router exposes only removals); SCIM — the designed attach path — needs a `scim` client that only an admin session can register. Chicken-and-egg: pre-creating a username locks that user out; only direct DB surgery recovers. `seed.example.toml:32-35` and INTEGRATION.md:40 still document the removed attach-on-first-verify behavior (regression tests pin the strict behavior, `src/email.rs:1209-1235`).

**Fix:** an admin-gated `user/attach_credential` route (level-gated per G-122's pattern), or an email field on the seed/admin-create DTOs; update the stale docs either way.

### G-132. No step-up/re-auth for credential changes → persistent takeover from a hijacked session
`src/email.rs:846-862`, `src/otp.rs:727-743`, `src/social.rs:720-729`, `src/passkey.rs:475-477,669-692`, `src/verify.rs:194-205`

Adding a login credential (email/mobile/social/passkey) or deactivating **all** passkeys requires only a bearer session — never a fresh factor. The `session` hoop deliberately skips the policy engine, so a tenant cannot even configure an MFA requirement for these endpoints (`expect_mfa`/`X-MFA-Required` machinery unreachable). The session JWT is XSS-readable (G-139) with a 15-min refreshable lifetime: a stolen session can attach attacker-owned credentials and yield persistent access that survives revoking the stolen token.

**Fix:** route credential mutations through the policy engine (or a dedicated step-up hoop requiring a recent `auth_time` / second factor).

### G-133. Default magic links 404: seeded `verify_url` points at a nonexistent route
`seed.example.toml:153`, `seed.toml:138`, `docs/INTEGRATION.md:23,40`, `src/router.rs:124-142`

Both seed examples and the integration guide set `verify_url = "http://localhost/api/v1/auth/email/landing"` — no such route exists (email routes are `request|verify|add|add/verify`, POST-only); the static catch-all 404s. The real landing is the `/login` SPA reading `token/username/email` query params (`frontend/src/login/App.tsx:35-44,99-116`). Out of the box, the primary factor's emailed link is dead, and no test covers the landing-route contract.

**Fix:** point the examples/guide at `/login` (or add a server-side landing redirect route); add a test pinning the contract.

### G-134. `.env.example` is dead config; README directs live secrets into it
`.env.example:4-41`, `src/main.rs:89`, `src/server.rs:327,334`, `README.md:25,33,70`

The server reads only `JANUX_CONFIG_FILE`, `RUN_ENV`, and `JANUX__*` overrides; there is no dotenv dependency and zero `env::var` reads for any listed key (`RESEND_API_KEY`, `JWT_SECRET_KEY`, OAuth vars, …). Real provider credentials live in `seed.toml` → tenant Config store. README:25,70 nonetheless instructs operators to put provider credentials in `.env` — real secrets land in a file nothing consumes while the server silently runs on seed.toml's config. Roughly half of `.env.example` is config for an unrelated LLM/RAG product (DASHSCOPE/MODELSTUDIO/OSS/RAG_*). **Hygiene:** the local gitignored `.env` currently holds what appear to be live Aliyun/Resend/GitHub secrets for keys the server never reads — rotate and remove them (values not reproduced here).

**Fix:** delete `.env.example` (or reduce it to the three real vars), fix the README config table, rotate the dead secrets.

### G-135. Release pipelines publish unverified artifacts
`.github/workflows/release-binaries.yml:85-130`, `release-docker.yml:76-79,131-134,200`

Binaries: zero tests/lint before `cargo build --release`, no `needs:` on CI, no sha256 checksums, no signing, no post-build smoke check (not even `--version`); Windows amd64/arm64 published though no test ever runs on Windows; macOS artifacts attached manually from a dev machine. Docker: `provenance: false` + `sbom: false`, the built image is never run (no health probe), only verification is `imagetools inspect | head -20`. Tag pushes release regardless of CI state on that commit.

### G-136. Compliance suite is CI-invisible and structurally blocked
`tests/compliant/` (49 tests), `.github/workflows/ci.yml` (no Python step), `tests/compliant/conftest.py:14-19,82-89`, `tests_op/test_magic_link.py:7-14`, `tests_op/test_jwks.py:19-21`, `tests_op/test_discovery.py:102-110`

`tests/compliant` appears in no workflow. Locally, the code-flow/PKCE/refresh/revocation tracks skip or strict-xfail because four server-side enablers are unimplemented (`tests/compliant/README.md:57-76`): a rate-limit knob for tests, seed user emails (`UserDTO` is still `{id, active, roles}`, `src/user.rs:22-26`), a seed signing key (`TenantDTO::save` creates none, `src/seed.rs:25-51`), and `client_credentials` in `grant_types_supported` (`src/oidc.rs:804-808`). The OIDF driver is manual-only with placeholder secrets.

### G-137. Advertised crypto/key unit coverage is illusory
`tests/unit/key_unit.rs:56-58,87-91,108-130`, `tests/unit/crypto_unit.rs:1-4`, `tests/README.md:53,56`

`key_unit.rs` never imports `janux` — it re-implements `compute_at_hash` locally, defines its own params struct, and asserts tautologies (`EXPECTED_ALG.len() == 5`, `now + 900 >= now`, `KEY_HEX.len() == KEY_LENGTH`). `crypto_unit.rs` is a 4-line stub with zero tests. `tests/README.md` claims both as real coverage ("tampered ciphertext rejection", "RSA key management & at_hash"). Net: `src/crypto.rs` — the AES-256-GCM at-rest module everything recovery-critical depends on — has **zero direct tests** (only indirect exercise via `src/email.rs:1900-1920`).

### G-138. Frontend has no TOTP UI — MFA policies are a dead end
`frontend/src/login/App.tsx:129-133`, `src/router.rs:199-213`, `src/policy.rs:188`, `frontend/src/api/sdk.gen.ts:583-619`

The login app renders only `email`/`otp`/`passkey`/`social`. The admin UI can create `mfa: true` policies, but no shipped page can enroll TOTP or complete the step-up round — the generated SDK exports `openapiTotpEnroll`/`openapiTotpVerify` and nothing imports them. Any MFA-gated resource is permanently unreachable through the built-in frontend. (Discovery's `janux_factors` never advertises totp either, `src/oidc.rs:724-786`.)

### G-139. Session JWT stored in `sessionStorage`; the backend's HttpOnly-cookie option is never used
`frontend/src/shared/session.ts:1-13`, `src/email.rs:220-227,620-627`

Any XSS on the origin exfiltrates a 15-minute all-factors session JWT (compounding G-132 into persistent takeover). The server already sets HttpOnly/Secure/SameSite=Strict cookies and `VerifyRequest.cookie` exists in the wire contract — no frontend call site ever sets it (grep `cookie` in `frontend/src` matches only generated internals). CSRF exposure remains low either way (all API calls use `Authorization: Bearer`).

---

## 🟠 New — Medium

### Backend security & correctness

- **G-140.** One-shot secrets accepted as URL query params and logged verbatim by the audit hoop (full `req.uri()` at info level): magic-link tokens (`src/email.rs:547-558`), SMS tokens/codes (`src/otp.rs:420-433`), TOTP codes + 15-min enrollment JWTs (GET-routed, `src/router.rs:208-213`), social IdP `code`/`state` (`src/router.rs:188-193`). `extract`'s `parse_queries` fallback (`src/utils.rs:830-866`) + `src/audit.rs:27-31`.
- **G-141.** OIDC SPA endpoints compute the policy verdict and ignore it: `/authorize`, `/authorize/resume`, `/consent/info`, `/consent/submit` authenticate via `validate_jwt` (runs default-deny engine, `src/utils.rs:736-784`) but `can_access` is never consulted anywhere in `src/oidc.rs`; `domain_bound` not set on this path — a sibling-domain session drives another domain's authorize flow to a code; `expect_mfa` unenforceable here (`src/oidc.rs:1102,1270,1468,1540`).
- **G-142.** Auth-code replay returns `invalid_grant` (one-shot consumption) but never revokes tokens previously issued from that code — RFC 6749 §4.1.2 SHOULD-half absent; `AuthGrant.code_hash` is write-only, never read back (`src/oidc.rs:2388-2402`, `src/idp.rs:111-112`). A detected replay (canonical stolen-code indicator) leaves the attacker's tokens alive.
- **G-143.** `RedirectURI` PK is the URI string itself, **global across clients**: two clients can never share a callback; soft-deleted clients permanently squat URIs (blocking G-96 rotation); non-transactional client create leaves half-registered clients on conflict; with DCR enabled an anonymous registrant can squat a victim RP's callback (`src/idp.rs:72-88,279-298,376-389`; DCR rollback covers only the metadata save, `src/oidc_ext.rs:319-326`).
- **G-147.** `admin/provider/list` serializes `client_secret`: `SocialProvider` derives `Serialize` including the field and `all_providers` renders the raw model — legacy (pre-encryption) rows are readable **plaintext**, newer rows ciphertext; secrets should be write-only (`src/social.rs:132-142,1244-1259`).
- **G-148.** No domain-ownership validation on `add_domain`: only global uniqueness + tenant match; no DNS/HTTP challenge, no format validation. Any tenant admin can squat an unregistered hostname, and since tenant/issuer resolution is a pure Host lookup, any traffic arriving under that host is served — ceremonies and token issuance included — by the claiming tenant (`src/admin.rs:177-203`, `src/utils.rs:400-430`).
- **G-149.** `trust_forwarded_headers = true` ships as the example default with no boot validation or warning (`base.example.toml:14`, `src/main.rs:97-120`). If directly reachable in this mode: forged `X-Forwarded-Host` picks tenant/issuer context (first candidate wins), forged XFF (rightmost entry trusted) defeats every per-IP limiter and the audit IP trail (`src/utils.rs:292-315,874-885`).
- **G-150.** Encryption-key handling: the well-known example key `12345678…` is accepted silently (boot checks presence only, `src/main.rs:104-109`); `decrypt_secret_or_legacy` returns the stored value on **any** decryption failure — after a key change, ciphertext is fed to providers as if it were the secret (opaque send failures) and legacy plaintext rows never force-migrate (`src/crypto.rs:74-76`); single `OnceLock` key, no key-id/version in ciphertext, rotation = manual decrypt/re-encrypt everything, no tooling.
- **G-151.** Internal session refresh chains have no absolute lifetime: `auth_time` is carried forward unbounded (`src/db.rs:310-422`, pass-through at `:394`); an internal session can rotate every 15 min forever. The OIDC path caps families at 30 days; the internal path — which gates the admin API — has no equivalent. Compounds G-106/G-128.
- **G-152.** `SEND_THROTTLE` keys (`email:<addr>` / `mobile:<digits>`) have no tenant/domain component (`src/utils.rs:906-939`): two tenants share one 3/min per-recipient budget, so an attacker with any account on tenant A can exhaust magic-link/SMS delivery for a victim on tenant B. The verify-failure gate is correctly domain-scoped (`:980-982`) — the throttle isn't.
- **G-153.** Network sends while holding the tenant write guard: login flows were fixed (H6) to drop the guard before the provider hop, but `email/add` sends under it (`src/email.rs:822`, guard from `:886`), `otp/add` likewise (`src/otp.rs:800`/`:768`), and social does IdP discovery + token exchange under it (`src/social.rs:642-652,847-879`). A slow/hung peer stalls every request for that tenant up to the 15 s timeout.
- **G-154.** `role_delete` removes only the `Role` row: its `Policy` rows stay in the DB **and** the in-memory `PolicyCache` (no eviction, unlike `policy_delete`), `UserRole` rows orphan; outstanding tokens naming the role keep passing evaluation; re-creating a role with the same name silently resurrects every stale policy without passing `policy_create`'s gate (`src/role.rs:257-267`, `src/utils.rs:580-611`).

### SCIM

- **G-144.** Unfiltered `GET /scim/v2/Users` calls `User::all()` (no LIMIT) and paginates in memory — every list materializes the whole tenant user table regardless of `count`; the admin equivalent is properly DB-paginated (`src/scim.rs:388-408`, `src/user.rs:279-298`). The 60/min limiter slows but does not bound this.
- **G-145.** `userName` handling violates RFC 7644 §5/§7.8 case-insensitivity: the filter parser lowercases the *entire filter including the quoted value*, then lookup is exact-match case-sensitive `eq` — `filter=userName eq "Admin"` searches for `admin` and misses a stored `Admin`; `#[unique] name` is case-sensitive too, so `Admin` and `admin` coexist (`src/scim.rs:342-361`, `src/user.rs:88-89,146-153`).
- **G-146.** PATCH: `remove` op rejected with 400 despite `ServiceProviderConfig` advertising `patch.supported: true`; worse, `add` on multi-valued `emails` deletes every address not in the payload (replace semantics) — a compliant IdP sending an incremental `add` silently wipes the user's other emails (`src/scim.rs:275,644-653,716-738`).

### Frontend

- **G-155.** MFA step-up signal unhandled: 403 + `X-MFA-Required` carries no body (`src/verify.rs:164-171`); admin `isUnauthorized` checks only 401 and `problemText` falls back to "Request failed (403)" — no step-up path anywhere (`frontend/src/admin/api.ts:16-23,61-80`).
- **G-156.** No confirmation dialogs for any destructive admin action — user/role/policy/domain/client/key/**tenant** delete all fire directly from `onClick`; grep `confirm` across `frontend/src/**/*.tsx`: zero matches (`frontend/src/admin/App.tsx:144-152,271-279,396-406,519-533,627-635,864-872,959-967`).
- **G-157.** No token refresh in the frontend: session TTL is 15 min, `auth/refresh` exists and is exported by the SDK but never called; on 401 the admin app clears the session and hard-redirects — operators lose work mid-edit every 15 minutes (`frontend/src/admin/api.ts:11-14`).
- **G-161.** TypeScript `strict` is **off** (`frontend/tsconfig.app.json` — the stock Vite template enables it); implicit `any` across all app code; one unit-test file total (`src/login/api.test.ts`, 7 cases); no jsdom/@testing-library deps.
- **G-162.** No self-service credential-management UI despite full backend support (`email/add`, `otp/add`, `passkey/remove`, session-gated passkey *registration*, `social/link`, `user/activate/self`, `user/delete/self`): no account/settings page in any of the four apps, and the login app actively refuses the passkey-registration branch ("sign in another way first", `frontend/src/login/webauthn.ts:44-46`).
- **G-163.** Admin console surface gaps: policy UI hardcodes `allowed: true` and has no Allowed column — **deny policies can neither be created nor distinguished** (`frontend/src/admin/App.tsx:386,455-482` vs `src/policy.rs:120-122`); Method select offers 5 of 9 variants; no UI for TOTP admin, `oauth2client/meta`, OIDC/DCR config, `admin/metrics`, per-user credential removal, or a user's roles — all exist server-side and in the SDK.

### Testing / CI / docs

- **G-158.** The "Playwright-driven e2e" tier has no browser anywhere: no browser-automation crate in Cargo.toml; `fixtures.rs:18` is a self-declared stub; `get_bearer_token` posts `{user, password}` to a **passwordless** server (always `None`, so dependent tests like `test_user_roles_lookup_works` assert nothing); selectors point at nonexistent `/signin.html`/`signup.html` and `input[name=password]`; 9× `is_ok()`-only assertions in `oidc_flow.rs`; structure tests `#[ignore]`d — while CI installs Chromium no test drives (`ci.yml:163-164`, `build.rs:14-39`, README:81,90).
- **G-159.** `just unit` = `cargo test --test unit_tests` and `just test` never run the **lib suite** (~250 tests, the bulk of coverage: 57 in oidc.rs, 44 in utils.rs, 34 in db.rs, …) that CI runs via `cargo test --lib --test unit_tests` — including the seed-shape pin the README advertises (`justfile:25-27,49` vs `ci.yml:77`, `src/seed.rs:184`).
- **G-160.** Dangling tracker references after the KNOWN_ISSUES.md/gaps.md deletion: `README.md:7,97`, `docs/README.md:6`, `docs/DESIGN.md:3` link the deleted file; ~26 orphaned `G-*` citations across README/DESIGN/INTEGRATION/seed.example.toml/src/tests/frontend now resolve to nothing (G-40, G-9/10/11, G-43, G-56, G-66, G-71, G-87, G-97, G-100, G-113, G-119, G-123…G-126, G-5/6, G-25, G-60, G-61). This file is the new registry.
- **G-164.** CI has no `cargo audit`/`cargo deny` (no deny.toml/audit.toml in repo), no coverage tooling, no miri/sanitizers, no frontend `lint`/`test` gate (only `npm ci && npm run build`), no Docker build check, no non-ubuntu matrix (`ci.yml`: 4 jobs).

---

## 🟡 New — Low (condensed)

### OIDC surface
- Post-validation `/authorize` errors (`invalid_scope`, all PKCE errors) redirect to a nonexistent `/error` page → bare 404 instead of an RP callback with `error`/`state` (RFC 6749 §4.1.2.1) (`src/oidc.rs:1095-1097,1031-1073`).
- `/token` **success** responses omit `Cache-Control: no-store`/`Pragma: no-cache` (RFC 6749 §5.1 MUST; error paths set them); 401 `invalid_client` omits `WWW-Authenticate` (`src/oidc.rs:532-543,2075-2078,2653-2661,2980-2988`).
- `/userinfo` is GET-only; OIDC Core §5.3.1 requires GET **and** POST — one-line routing gap (`src/router.rs:434-437`).
- Query-bearing registered redirect URIs corrupted: unconditional `"?code=…"` append produces `…?x=1?code=…`; `end_session` already handles this correctly (`src/oidc.rs:297-313,54-68` vs `src/oidc_ext.rs:722-727`).
- RFC 8252 §7.1 loopback port flexibility not honored — exact-string matching fails native apps on ephemeral ports, though DCR explicitly supports the loopback pattern (`src/oidc.rs:995,2376`, `src/oidc_ext.rs:56-70`).
- PKCE not required for confidential clients (OAuth 2.1 / RFC 9700 §2.1.1 mandates it for all code-flow clients) (`src/oidc.rs:1064-1073,2471`).
- Machine tokens accepted as user "sessions" on ceremony endpoints (no `typ` marker): device-login approve, `/authorize`, `/consent` — minting fails closed but side effects (AuthGrant rows, approved devices, consumed states) land first (`src/oidc.rs:4019-4033,4156-4198`).
- Back-channel logout delivery follows up to 10 redirects with no private-range filtering — bounded blind SSRF from a registered https URI; anonymous-reachable when DCR is on (`src/oidc_ext.rs:541-560`).
- Admin client creation applies none of the DCR validations (no scheme/fragment/loopback rules, no vocabulary checks on grant/response types or auth method, no secret strength) — a typo'd `token_endpoint_auth_method` bricks the client at `/token` (`src/idp.rs:542-585`).
- Discovery inconsistencies: no `scopes_supported` (fixed `KNOWN_SCOPES` vocabulary learnable only by trial); `grant_types_supported` omits `client_credentials` (implemented, and pinned strict-xfail in the conformance suite); `claims_supported` advertises `name/given_name/family_name/picture` that `/userinfo` hardcodes to `None`; no `userinfo_signing_alg_values_supported` (`src/oidc.rs:789-834,3226-3235`).
- JWKS publishes every key of the tenant across all domains (widens the accepted `kid` set, leaks sibling-domain key inventory); no cache headers; `alg` absent (`src/key.rs:357-401`).
- HTTP `Basic` scheme matched case-sensitively (RFC 7235 says case-insensitive; the Bearer equivalent was fixed as G-117) — lowercase `basic` silently falls through to the body-secret path (`src/oidc.rs:2150-2171`, `src/oidc_ext.rs:358`).
- An expired `id_token_hint` **alone** triggers full back-channel logout fan-out for that user across all RPs, repeatedly — anyone holding a historical ID token (logs/backups) can force-logout a user; only the 12/min/IP limiter bounds it (`src/oidc_ext.rs:599-653,713-717`).
- Logout never disturbs outstanding refresh-token families: an RP that missed the best-effort back-channel notification (G-126) can keep rotating and minting fresh tokens for the "logged-out" user up to the 30-day family lifetime (`src/oidc_ext.rs:695-711`, `src/verify.rs:69`).
- Public clients (`token_endpoint_auth_method: none`) are refused by `/revoke` and `/introspect` entirely — SPAs have no RFC 7009 path; deliberate anti-abuse posture, but the middle ground (client_id-scoped revocation) is unimplemented (`src/oidc.rs:3332-3344,3543-3555`).
- Duplicate `/token` (and `/revoke`, `/introspect`, `/device_authorization`) form parameters resolve last-wins instead of being rejected (RFC 6749 §2.3.1/§3.2.1) (`src/oidc.rs:1751-1765,3264-3273,3477-3486,3742-3750`).
- Argon2id client-secret verification runs synchronously on the async worker **while holding the tenant write lock** — attacker-triggerable (valid client_id + wrong secret) head-of-line blocking, bounded only by the 12/min/IP limiter (`src/oidc.rs:1797`, `src/idp.rs:251-257`).
- Ceremony caches capped at 10k entries (moka evicts under pressure): distributed flooding of the cheap `/authorize` park step can evict victims' pending login/consent states and parked codes within their 600-1800 s windows — fail-closed, availability-only (`src/oidc.rs:25-40`, `src/cache.rs:20-32`).
- `authorize_flow` drops and re-acquires the tenant guard mid-flow against DESIGN §6's explicit rule, and re-checks nothing after re-acquisition (unlike `authorize_resume`/`consent_submit`); downstream checks make it fail closed — impact limited to a wasted ceremony (`src/oidc.rs:1100-1119`).
- Introspection `username` returns the user UUID instead of a human-readable identifier (RFC 7662); the login name is resolvable — `/userinfo` does it (`src/oidc.rs:3609-3614,3684-3689` vs `:3198-3204`).

### Factors & user lifecycle
- Unauthenticated `passkey/request` is an account/passkey-existence oracle: 200 + challenge (incl. `allowCredentials` ids) for usernames with active passkeys, 401 otherwise — contradicts DESIGN.md:17's enumeration-resistance invariant; email/OTP `request` responses are correctly identical across signin/signup (`src/passkey.rs:469-483`).
- Social callback renders post-exchange failures (token exchange, missing subject, user creation, JWT mint) as HTTP **200** with internal error text — invisible to status-based monitoring (`src/social.rs:889-978`).
- TOTP step-up forces a re-enrollment round-trip: `totp/verify` requires a one-shot enrollment token; obtaining one for an ACTIVE record consumes a current code and re-returns the plaintext secret as `qr`+`uri` — a code-phishing proxy upgrades a one-time code into the permanent secret (`src/totp.rs:376-445,494-525`).
- MFA policy/ACR hardcode TOTP: `jwt.mfa.contains("totp") && len > 1` — a UV-required passkey or email+otp session can never satisfy `mfa=true` or reach ACR 2 (`src/policy.rs:188`, `src/db.rs:84`).
- Re-request does not invalidate previously issued ceremony secrets: up to 3 live magic links/min coexist; each OTP `request` mints a new code without revoking the prior (`src/email.rs:402-407`, `src/otp.rs:240-250`).
- No delivery-failure retry/fallback for email or SMS: single attempt then hard 401; user must re-request against the 3/min throttle (`src/email.rs:402-410`, `src/otp.rs:235-253`, `src/aliclient.rs:389-402`).
- OTP add-flow code generation is modulo-biased (`buf[0] % 10`, no rejection sampling — the login path does it correctly) and `otp/add_verify` has no attempt gate (`src/otp.rs:706-716,850-908`).
- Authenticated enumeration via add endpoints: "Email already in use" / "Mobile already in use" to any valid session (`src/email.rs:889-890`, `src/otp.rs:769-770`).

### Infra & ops
- Salvo `MokaStore` rate limiters are capacity-`u64::MAX` with no TTL: every distinct source IP ever observed retains an entry for the process lifetime — sustained IP rotation grows memory unboundedly (`src/router.rs:84-89,219-224,399-404`, `src/scim.rs:795-802`).
- `/api/v1/doc/openapi.json` + `/api/v1/doc/scalar` are unauthenticated on every tenant host — full API schema including admin endpoints exposed anonymously (`src/router.rs:483-492`).
- CORS `["tenant"]` share mode never matches: bare domain IDs compared against full `Origin` strings — dead as shipped, fail-closed (`src/db.rs:526-543`, `src/cors.rs:38-39`).
- Latent `rest[2..]` slice panic in the metrics route labeler for a path `/api/v1/auth/social` — unreachable today (no leaf route matches), but any future route there makes it a remotely triggerable per-connection panic (`src/ops.rs:275-278,354-357`).
- Boot-time `load_tenant` inserts the tenant into the map *before* registering domains; on a cross-tenant domain conflict it returns Err but the tenant stays loaded — half-loaded topology instead of a clean refusal (`src/db.rs:742-771,822-833`).
- `/admin/metrics` is process-global telemetry behind a per-tenant admin gate: any one tenant's admin observes cross-tenant aggregates (tenant counts, per-route counters, auth outcomes) (`src/ops.rs:402-419`).
- `seed.example.toml` registers `0.0.0.0` as a tenant domain (direct-IP requests resolve to the bootstrap tenant with its root/admin users — a pattern operators will copy) and carries a stale SECURITY note claiming an attach-on-first-verify takeover that the code now refuses (`seed.example.toml:32-35,50`).
- `.dockerignore` excludes `.env`/`janux.toml` but not `base.toml`/`seed.toml` — the local encryption key and seed credentials are sent to the Docker build context (never COPYed into the image).

### Frontend
- Discovery `identifier` factor metadata (`email`/`mobile`/`null`) declared, typed, never read — inputs hardcoded per factor; the UI cannot adapt to the documented contract (`src/oidc.rs:741,753,783`, `frontend/src/login/App.tsx:268-306`, docs/FRONTEND.md:113-115).
- No logout control in any app; `openapiVerifyLogout` exported, never imported; session lives in `sessionStorage` until tab close.
- Login "done" phase is a dead end: no `client_id`/`redirect_uri` in the URL → static "Signed in." with no navigation (`frontend/src/login/App.tsx:69-73,374`).
- Consent page can show only the raw `client_id` even though a friendlier `client_name` is storable via `oauth2client/meta` — users consent to an opaque identifier (`src/oidc.rs:327-330`, `src/oidc_ext.rs:803-811`).
- Device `user_code` input is trimmed but never case-folded — typing `abcd-1234` fails the exact-match lookup against uppercase RFC 8628 codes (`frontend/src/device/App.tsx:67,87`, `src/oidc.rs:3928-3930`).
- `?error=` query text rendered verbatim via a prototype-unsafe plain-object lookup: arbitrary attacker-chosen copy in the sign-in banner (React escapes it — no XSS), and `?error=constructor` renders an invalid React child (`frontend/src/login/App.tsx:25-31,54,243`).
- The SPA-consumed OIDC endpoints (`/authorize/resume`, `/consent*`, `/device-login/*`) live in `public_routes()`, excluded from the OpenAPI merge — hand-rolled untyped fetch with locally re-declared shapes; contract drift invisible to `just openapi` (`src/bin/openapi.rs:97-98`, `src/router.rs:405-470`).
- GET-with-required-body routes (`admin/user/roles`, `totp/enroll`, `totp/verify` GET variants) generate SDK functions that throw in browsers (`fetch` forbids GET bodies); POST variants work; no UI currently calls the broken ones (`frontend/openapi.json:3131-3142`, `src/api/client/client.gen.ts:83-89`).
- Embedded `frontend/dist/` is older than `frontend/src/` — a `cargo build` without a preceding `npm run build` ships a stale admin bundle (the exact drift FRONTEND.md:143-145 warns about).
- No form semantics anywhere: zero `<form>`/`onSubmit` — Enter never submits (login, device code entry, every admin create form); accessibility + password-manager workflows broken; `autoComplete="one-time-code"` hints at intent the missing `<form>` undercuts.
- All strings hardcoded English, no i18n hook (acceptable for an overridable default frontend, but zero translation surface); server scope labels English-only too.
- Admin console has no overflow handling on mobile: full-width 6-8-column tables, no scroll wrapper, only CSS is `body { margin: 0 }`.
- Dead code/deps: `public/icons.svg` referenced nowhere; `@hey-api/vite-plugin` unused in vite.config; `clearSession`/`loadSession` re-exports imported by nobody.
- Admin tables fetch fields they never render (key material, redirect URIs, provider client_id/scopes) — operators can't verify what's already on the wire.

### Docs / CI hygiene
- DESIGN.md:33 and INTEGRATION.md:128 builtin-role catalogs omit `scim` (level 60), contradicting `src/role.rs:22-28` and DESIGN §7 itself.
- Every code-line citation in INTEGRATION.md has drifted ~100-200 lines (9 verified examples: main.rs:48→86-95, utils.rs:312→400, email.rs:126→205, idp.rs:373→519, oidc.rs:1547→1709, jwt.rs:114→154, router.rs:71→84-89, …); behavioral claims still check out.
- `tests/README.md` references nonexistent just targets (`test-integration`, `test-e2e`, `test-e2e-headed`), a nonexistent `e2e_config::base_url()` helper, conflates the lib suite with the `tests/unit/` target, and omits `tests/compliant` entirely.
- `tests/compliant/README.md:35` quickstart uses a stale pre-extraction path (`auth/test/compliant`).
- `RUN_ENV`-keyed `config/{RUN_ENV}.toml` layer and `JANUX_CONFIG_FILE` are undocumented — silent override paths the README's precedence description doesn't mention (`src/server.rs:327,333`, `src/main.rs:86-92`).
- `build.rs` browser detection calls `fs::metadata()` on a literal `chromium-*` glob path — can never succeed, warning fires on every build; docstring describes commented-out behavior.
- FRONTEND.md:139 says `just dev` needs a separately running backend; `just dev` starts both (root README is correct).
- DESIGN.md:11 says provisioning happens at `request`; code provisions at `verify` — internally inconsistent with DESIGN.md:16.
- No SECURITY.md (disclosure policy for an IdP), no CONTRIBUTING/CHANGELOG/CODEOWNERS/rust-toolchain.toml/dependabot.

---

## ✅ Verified solid (no gap found)

- Magic-link single-use & binding: one-shot consume before validation, `iss`/`sub`/`data.email` checks, signin/signup mode fixed in the signed token and fail-closed for legacy tokens, namespace separation from add tokens.
- OTP attempt budgets: per-IP 6/min, per-recipient 3/min, per-account 5-failure exponential-backoff lockout checked *before* one-shot consumption; CSPRNG codes with rejection sampling on the login path; opaque flow handle (H1 fixed).
- TOTP replay: current-step-only match + consumed-step guard, one-shot enrollment token, secrets encrypted at rest with in-place legacy upgrade; TOTP cannot bootstrap a session.
- WebAuthn: random per-flow challenges (600 s TTL, one-shot), username binding on login flows (C1 fixed), origin/rp_id derived from trusted hosts, post-finish credential-ownership recheck, counter-regression enforcement.
- Social federation: state + PKCE S256 + nonce + `at_hash` all validated; email trusted only when `email_verified`; **no auto-merge** — provisioning creates a fresh user and skips emails owned by others; link is session-gated; login code one-shot + HttpOnly bind cookie.
- Factor-laundering prevention: prior factors inherited only from a same-user session across all five factors, each pinned by a regression test.
- Verify races: per-tenant write guard across the handler, atomic one-shot cache removal, all-or-nothing signup with rollback.
- Token validation: RS256-pinned (no alg confusion), kid-routed, revocation checked before decode, issuer/domain binding, refresh rotation single-winner with family poisoning (H4 fixed); persistent revocation store surviving restarts.
- Secrets at rest: AES-256-GCM with random nonces for signing keys (H2 fixed), TOTP, social, provider credentials; encryption key mandatory at boot. Residual: legacy plaintext fallback (G-150).
- Tenant isolation: per-tenant DB files, Host-derived resolution, issuer binding, domain-bound session tokens — except as noted in G-148/G-149/G-152.
- Default-deny route coverage: every route justified except the unauthenticated doc endpoints (Low, above).
- Login SPA open-redirect handling: same-origin resolution with protocol-relative/backslash evasion tests; server-provided redirects constructed from the parked, validated callback URI.
- Generated client ↔ spec ↔ backend in sync at review time (61 paths spot-checked); caveat: nothing enforces freshness in CI beyond the OpenAPI drift check on `router::api()`.
- Consent/device contract fidelity: pages match the backend wire contract exactly (limitations are server-side design, tracked above).

---

## Recommended fix order

1. **G-130 + G-123 + G-97** — the machine-token kill chain: today there is *no* way to revoke a leaked 90-day SCIM principal short of tenant-wide key deletion. (RBAC integrity item closed: G-128 stale-roles-on-refresh and G-129 policy_create escalation both fixed 2026-09-07.)
2. **G-133 + G-131 + G-134** — out-of-box breakage: the documented quickstart's magic link 404s, seeded admins can't obtain credentials, and the README directs live secrets into a dead file (rotate the ones in the local `.env`).
3. **G-132 + G-139** — session-takeover persistence: step-up for credential changes; move the frontend to the HttpOnly cookie the backend already issues.
4. **G-135 + G-136 + G-137 + G-158 + G-159 + G-164** — release/test integrity: published artifacts and advertised coverage are both unverified.
5. Medium cluster (G-140…G-163), then the Low tail; re-point the ~26 orphaned `G-*` citations (G-160) at this file.
