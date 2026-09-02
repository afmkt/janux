# Janux — Gaps to a Production Passwordless Auth Server

Open issues, tracked by `G-*` ID. Conventions (same as `README.md`):

- **Open gaps live here.** When one is closed, strike the entry here and keep the resolution note (what changed, plus the regression test names) — the code itself carries only unmarked rationale.
- **Design decisions live in `README.md`**, not here. If a README section looks wrong, that is a design discussion — except where this file explicitly flags a README/code divergence.
- **Code comments carry only stable, line-anchored rationale** — why *this* code is shaped this way — with no gap IDs, status, phase/planning notes, or document citations. All tracking is centralized here; planning documents are deleted once their decisions are migrated.
- IDs continue the numbering in this file (nothing in code references them). (G-38 was verified resolved: toasty lowers a delete as `DisassociateAll { delete: true }` over every `has_many` whose child `belongs_to` is non-nullable, so user deletion cascades all credentials; the remaining piece — refresh passing through a deleted user — was closed with it. Regression tests: `user_delete_cascades_credentials`, `refresh_rejects_a_deleted_user`, `refresh_grant_rejects_deleted_user`.)

Scope: what stands between this codebase and a production multi-tenant passwordless auth server / OIDC provider — operations, OIDC completeness, factor lifecycle, hardening, and test/CI integrity.

---

## Carried over (referenced open in code)

### G-28 — HTTP-level admin tests bypass the real `protect` hoop
Handler-level RBAC tests inject a fake `JwtVerify` session directly instead of sending a real token through `protect` (`src/user.rs`, `role_admin_service`). Full end-to-end assertions for the admin surface — policy evaluation, token validation, and the level gate in one HTTP round-trip — remain untested. The `protect` path is only covered indirectly by e2e/integration tests.

---

## Review 2026-08-23 — findings filed together (G-115..G-118)

Four issues found in one review pass; grouped here rather than scattered across the thematic sections. When closed, follow the usual convention: record the resolution inline in code and strike the entry.

### G-115 — Device-flow tokens lose amr/acr and the original auth_time
`device_login_approve` authenticates the approver with a real session (`validate_session`, `src/oidc.rs:3790`) whose `mfa` set and `auth_time` are available, but the device entry records neither — only `user_id` is written at approval. `mint_token_response` (`src/oidc.rs:417-419`) therefore builds an empty factor set: device-grant access/ID tokens carry no `amr`/`acr`, and `auth_time` defaults to poll time (`src/oidc.rs:410`) instead of the approver's original authentication time. RPs enforcing `max_age` or step-up via `acr`/`auth_time` get wrong answers for exactly this grant. Store `mfa` + `auth_time` in the device entry at approve time and thread them into `mint_token_response`.

### G-116 — Introspection cache fast path is not tenant-bound
`OIDC_TOKEN_CACHE` is process-wide and the mint-time entries (`src/oidc.rs:491-503`, `2401-2413`, `2719-2731`) record client/user/scope but not the issuing tenant. The `/introspect` fast path (`src/oidc.rs:3345-3386`) checks expiry, client_id match, and revocation — never the issuer — so with the same client_id registered in two tenants (nothing prevents it), tenant A introspecting tenant B's cached access token gets `active=true` with tenant B's sub/username. The JWT fallback path checks `iss` via `validate_token`; only the cache fast path bypasses it. Store the issuer in the entry and compare it with the requesting tenant's issuer (or key the cache per tenant).

### G-117 — Bearer scheme accepted case-insensitively only on internal endpoints
`get_jwt` (`src/utils.rs:326`) lowercases the header before matching, but `get_bearer_token` (`src/oidc.rs:335-346`) accepts only the literal prefixes `Bearer ` / `bearer `. RFC 6749 §2.1 / RFC 6750: auth-schemes are case-insensitive, so `BEARER <token>` works on `/api/v1/*` but 401s on `/userinfo`. Unify both helpers.

### G-118 — CORS origin echo panics on malformed configured origins
`cors_middleware` inserts the matched Origin into `Access-Control-Allow-Origin` with `origin.parse().unwrap()` (`src/cors.rs:36`). A malformed (non-ASCII) value in the tenant's CORS allow-list panics the request task instead of returning an error — same fail-open-to-crash class as G-107, but reachable from tenant admin config rather than delivery config. Fail closed: skip the CORS headers when the value does not parse as a header value.

---

## Review 2026-08-26 — concurrency audit (G-119..G-122)

Audit of concurrent-API safety. Closed during the audit: the domain/tenant topology race — `add_domain`/`remove_domain`/`new_tenant`/`delete_tenant` are serialized by the `Storage::topology` mutex (regression tests `concurrent_add_domain_has_exactly_one_winner`, `concurrent_add_and_remove_stay_consistent`). The audit also found that the per-tenant request serialization the codebase relies on was undocumented; it is now deliberate design (README §6, `Storage`/`tenant_by_domain` doc comments). Residuals below: G-119/G-120 fire in a single instance today; G-121/G-122 are latent under §6 and become live if the guard discipline loosens or across instances (G-87).

### G-119 — SEND_THROTTLE cold-key burst bypass
The per-recipient dispatch throttle (`send_throttle_allows`, `src/utils.rs:763`) is atomic only while the key exists: on an absent key `get_mut` returns `None` and the fallback inserts `(window, 1)` and allows unconditionally. N concurrent first hits (first ever, or after the 120 s TTL) all pass and the counter lands at 1 — a coordinated burst SMS/email-bombs one recipient despite the 3/min budget, repeating every idle window. Not covered by the tenant guard (the cache is process-wide). Run the absent-key path inside moka's per-key compute (entry API) so create-and-increment is one atomic step.

### G-120 — Revocation records die at `exp` but tokens verify until `exp + leeway`
Verification accepts tokens 120 s past expiry (`leeway = grace*60`, `src/jwt.rs:145`), but revocation records are gc'd at `expire_at < now`, skipped on restart hydration, and skipped on read-through at `exp` (`src/jwt.rs:334/233/320`). In `(exp, exp+120s]` after a gc tick or restart, a revoked or already-rotated token verifies again — and `refresh_jwt` rotates expired-within-leeway tokens, so it can mint a second successor. Timing-dependent logic bug, not a thread race. Retain revocation records for `exp + leeway`.

### G-121 — The revocation "insert-wins" commit point is not atomic
`EphemCache::insert` (`src/cache.rs:34`) uses moka `entry().or_insert()`, which in moka 0.12 is look-then-insert: two concurrent racers can both observe absence and both receive `Ok`, yet `invalid_raw` (`src/jwt.rs:282`) documents the cache insert as the winner point for concurrent rotation/logout. Masked within a process by the tenant guard (README §6) and across instances by the `jwt.db` primary key. Make the DB insert the arbiter (constraint violation = already revoked) or use moka's atomic init path, so the guarantee does not depend on the guard.

### G-122 — `user.active` transitions are unconditional writes
Every activate/deactivate is `update_by_id(...).active(...)` with no condition on the prior state (`src/user.rs:148-215`), and `activate/self` checks-then-writes (`src/user.rs:598`). Under §6 this is serialized within a process, but the guard is the only thing preventing a self-activation from overwriting a concurrent admin deactivation; same class is the active-check-then-mint window in `authenticate_jwt` (`src/db.rs:312`). Make the transitions conditional updates so a stale write fails instead of landing.

---

## Operations & scaling

### G-87 — Single-instance ceremony state (no horizontal scaling)
Every in-flight ceremony lives in process-local moka caches: magic links (`MLINK_CACHE`), SMS codes (`OTP_CODE_CACHE`), passkey challenges (`PASSKEY_CACHE`/`LOGIN_CACHE`), TOTP enrollment (`TOTP_ENROLL_CACHE`), social dances and one-shot login codes (`SOCIAL_SESSION_CACHE`, `SOCIAL_LOGIN_CODE_CACHE`), OIDC auth codes / PKCE / pending / device / token caches, plus the rate limiters (`MokaStore`) and `SEND_THROTTLE`. Only the revocation store is shared (`jwt.db`, G-71). With more than one instance behind a load balancer: a magic link requested on instance A fails verify on B, device-flow polling hits random instances, and every instance grants its own rate-limit budget. Either declare single-instance deployment as a hard requirement (docs + startup guard) or move ceremony state into the shared store.

### G-88 — No backup / restore / DR story
Tenant data is per-directory libsql files (`tenants/<name>/janux.db`) with no backup procedure — the only backup code path runs during tenant *deletion* (`src/db.rs:612`). No documented or automated backup, point-in-time restore, or replication plan for the signing keys, users, credentials, policies, and consent grants that constitute the entire identity state.

### G-89 — Audit trail is an access log, not a security audit
`src/audit.rs` logs method/URI/status/duration only. There is no structured, queryable record of security events: who (actor + client IP + tenant), what (target user/role/client), which factor, and with what outcome — for logins, failed verifications, credential adds/removals, role/policy mutations, tenant lifecycle, and revocations. Required for incident response and any compliance regime; currently reconstruction from unstructured tracing lines.

### G-90 — Token lifetimes are hardcoded
Internal session 15 min, OIDC access token 60 min, ID token 15 min, refresh family 30 days (`OIDC_REFRESH_FAMILY_LIFETIME`), ceremony tokens 15 min — all literals. README §2 names "shorten token lifetimes" as the lever when the deactivation propagation window is too wide, but there is no knob. Make lifetimes tenant/server configuration.

### G-91 — Health, readiness, and metrics are stubs
`GET /api/v1/healthy` answers `ok: true` unconditionally — it never touches a tenant DB, the revocation store, or provider config. No readiness/liveness distinction for orchestrators and no metrics endpoint (request rates, verify failures, throttle hits, dispatch failures, cache occupancy).

---

## OIDC provider completeness

### G-92 — No RP-Initiated Logout, session management, or back-channel logout
Discovery advertises no `end_session_endpoint` and none exists (`src/oidc.rs:611`). An RP can end its own session but cannot log the user out of the IdP, and the IdP cannot notify RPs when a session dies (logout, deactivation, revocation). OIDC Session Management / Back-Channel Logout (or at minimum `end_session_endpoint` revoking the internal session) is missing.

### G-93 — `/authorize` ignores `prompt` and `max_age`
`AuthorizeRequest` parses neither (`src/oidc.rs:648`). `auth_time` is faithfully carried through tokens so RPs can *evaluate* `max_age`, but the server never *enforces* it — an arbitrarily old parked session sails through `/authorize` without re-authentication. `prompt=login|consent|none` and `login_hint` are likewise unsupported, which RPs need for forced re-auth and step-up.

### G-94 — `acr` vocabulary mismatch between discovery and tokens
Discovery advertises `acr_values_supported` as factor names (`email`, `otp`, `social`, `passkey` — `src/oidc.rs:553`), but issued tokens carry `acr` = `"1"`/`"2"` from `acr_value` (`src/db.rs:106`). An RP requesting or interpreting ACR gets two different vocabularies. Pick one: advertise `["1","2"]` (and document the classes) or issue the factor-based values.

### G-95 — No user-facing consent management
`AuthGrant` rows record every consent decision, but users can neither list nor revoke them; consent is only replaced by re-running the flow (REPLACE semantics) — there is no endpoint or UI to withdraw a grant. Consent records also grow unboundedly (no GC). Privacy baseline for an IdP: visible, revocable consent.

### G-96 — OAuth2 client lifecycle is create + soft-delete only
No endpoint rotates a client secret — the `secret_grace_until` column exists (`src/idp.rs:44`) but nothing ever sets it, so rotation means delete + recreate with downtime. No update path for `redirect_uris`, `grant_types`, `response_types`, or `scope` after creation. Production client administration needs rotate-with-grace and in-place update.

### G-97 — Signing-key deletion invalidates outstanding tokens
`key_delete` removes the key immediately (`src/key.rs:109`); every unexpired token carrying that `kid` then fails `jwt_decode`. There is no retire phase (stop signing, keep verifying until the last token expires) and no guard against deleting the domain's last key. Rotation today is a forced logout of the whole tenant. Add `retired_at`/publish state and refuse last-key deletion.

### G-98 — PKCE `plain` is still accepted
`plain` is permitted when the connection is TLS (`src/oidc.rs:871`). RFC 9700 (OAuth 2.0 BCP) recommends S256-only; the `plain` path exists solely for legacy clients and widens the downgrade surface. Drop it once no registered client needs it.

---

## Passwordless factors & account lifecycle

### G-99 — Signup gating is declared but not implemented
README §1 fixes the design: whether self-provisioning is allowed at all is a tenant-level config/policy concern. No such config or policy exists — every tenant is open sign-up forever, and an invite-only deployment (explicitly cited as the use case) is impossible. This is the designated extension point of the unified flow and is unbuilt.

### G-100 — README/code divergence: passkey cannot bootstrap a user
README §1 lists passkey among bootstrap-capable factors, but registration requires a valid session for exactly that user (G-3, `src/passkey.rs:440`) — a first-time user with no session can never sign up with a passkey alone; the ceremony only asserts for existing credentials or registers inside an existing session. Resolve the divergence: either restore a bootstrap path (with its enumeration/DoS considerations) or amend README §1 to say passkey is enrollment-only like TOTP.

### G-101 — No account recovery path
TOTP has no recovery codes; a user who loses every factor (phone gone, email inaccessible, authenticator lost) has no self-service way back in — only admin intervention (`totp/remove`, credential deletion) via out-of-band identity proofing, for which there is also no workflow. Production passwordless needs recovery codes at TOTP enrollment (single-use, rate-limited, audited) or an equivalent gated recovery ceremony.

### G-102 — TOTP secrets stored in plaintext at rest
`Totp.secret` is a raw string in the tenant DB (`src/totp.rs:51`). A TOTP secret is bearer-equivalent (it generates valid codes), so a DB disclosure silently bypasses MFA for every enrolled user. Social provider secrets are AES-GCM encrypted with `JANUX_ENCRYPTION_KEY` (`src/crypto.rs`) and OAuth2 client secrets are Argon2-hashed — TOTP secrets get neither. Encrypt at rest with the existing key.

### G-103 — Delivery-provider secrets stored in plaintext at rest
`ResendDTO.resend_key` and `OTPDTO.api_secret`/`api_key` are written verbatim into the tenant config table (`src/config.rs:113`). Same treatment as G-102: these are send-capable credentials (mail and SMS quota, phishing reach) persisted raw.

### G-104 — No per-user attempt budget on verify endpoints
`/api/v1/auth/*` is limited per client IP only (6/min, `src/router.rs:71`). A distributed botnet gets an unbounded aggregate budget against one account's OTP/TOTP verify — the 6-digit code space plus a 30 s step is the only remaining defense, and nothing counts or delays failed attempts per user. Add a per-(tenant, user) failure counter with backoff/lockout, independent of IP. (Also minor: OTP digits are generated `byte % 10`, a small modulo bias — `src/otp.rs:199`.)

### G-105 — No identifier normalization or validation
`user_create` accepts any string; emails and mobiles are stored exactly as typed and compared by exact match (`Email`/`OTP` primary keys). `Alice@Example.com` and `alice@example.com` are two different credentials; throttling lowercases for rate limits but storage does not, so case rotation also evades uniqueness. Validate formats at ceremony `request` time and normalize (lowercase email; E.164 for mobile) before storage and lookup.

---

## Sessions & users

### G-106 — No session visibility or global revocation
Users cannot list their active sessions or revoke them ("sign out everywhere"); there is no admin equivalent per user either. Deactivation kills sessions only at the refresh boundary by design (README §2), which is fine for admin action, but a user who suspects token theft has no self-service remedy beyond waiting one token lifetime per device. Needs a session index (jti-keyed, per user) and a revoke-all primitive on top of the existing `InvalidJwt` store.

### G-107 — Panic paths in request handlers
Misconfiguration crashes the request task instead of returning an error: `otp/request` unwraps a missing SMS config (`src/otp.rs:256`), magic-link rendering unwraps Tera results (`src/email.rs:292`), TOTP enroll unwraps the otpauth URL (`src/totp.rs:373`), and redirect builders `expect("valid header")` on URL-derived header values (`src/oidc.rs:114`). A tenant with broken config (or an attacker who can induce one) turns into 500s/connection resets rather than clean 4xx/5xx problems. Replace with fail-closed error responses.

---

## Testing & CI integrity

### G-108 — CI does not actually run integration or e2e tests
The integration job runs `cargo test --test playwright` — no such target exists (the target is `all_tests`, `Cargo.toml`), so the job fails or never ran green. The "E2E Passkey + WebAuthn" job is an echo stub that executes nothing. Clippy is `continue-on-error: true`. Net effect: CI enforces fmt + build + unit tests only, while the suite in `tests/` (integration + 5 e2e flow files) is unverified in CI.

### G-109 — Seed test depends on gitignored local files
`seed_toml_bootstraps_builtin_roles` loads `base.toml` + `seed.toml` (`src/seed.rs:167`), both gitignored and untracked — on a fresh checkout (i.e. CI) the test cannot pass. Either track a committed test copy (like `tests/test_config.toml`) or point the test at one.

---

## Hardening (lower severity)

### G-110 — Post-login `redirect_uri` enforced client-side only
The non-OIDC return hop carries `redirect_uri` through the email/social round-trip and the login SPA validates it same-origin in JavaScript (`sameOriginRedirect`, G-61). The server parks and returns the value unvalidated; any XSS in the SPA converts it into an open redirect with a fresh session in hand. Enforce same-origin (or a registered allow-list) server-side at park time.

### G-111 — Session cookie attributes are client-chosen and minimal
The verify endpoints accept a client-supplied cookie *name* and set HttpOnly + Secure + SameSite=Strict, but no `Max-Age` (tab-lifetime session) and no `__Host-` prefix (which would pin Secure/path and block subdomain overwriting). Fix the name server-side (`__Host-janux_session`) and drop the client parameter.

### G-112 — No security response headers on hosted pages
The login/consent/device/admin pages are served without CSP, HSTS, `X-Content-Type-Options`, or `Referrer-Policy`. CSP matters specifically here because magic-link tokens and social one-shot codes transit the URL query — a strict `Referrer-Policy` plus CSP is the standard mitigation against leakage to third parties.

### G-113 — List endpoints are unbounded
`user/list`, `role/list`, `policy/list`, `key/list`, `totp/list`, `oauth2client/list`, `domain/list`, `tenant/list` return every row with no pagination or cap — an availability problem at tenant size and an information-volume problem for any admin-token compromise.

---

## Documentation

### ~~G-114 — Referenced companion documents are missing or stale~~ (closed 2026-09-01)
The planning documents (`api-consolidation.md`, `g10-privilege-escalation.md`, `x.md`) were deliberately removed once their issues were resolved, and every code/README reference to them was cleaned out or rewritten as self-contained rationale (the G-\* IDs they backed remain the canonical pointers). The repository-layout frontend line was updated to the implemented page set (`login`, `admin`, `consent`, `device`).

---

## SCIM residuals (post-implementation, 2026-08-31)

The SCIM 2.0 surface (`src/scim.rs`, `/scim/v2/*`) shipped with the `scim` builtin role, the `client_credentials` machine principal, and integration tests. Two items from its planning doc remain:

### G-123 — Deleting an OAuth2 client does not revoke its machine tokens
`client_credentials` mints a 90-day session-shaped JWT bound to the client's service identity, and JWT verification is stateless (design §2), so `oauth2client_delete` leaves outstanding provisioning tokens valid until expiry. Sweep them through `/revoke` (or the revocation store directly) on client deletion/deactivation.

### G-124 — SCIM surface not yet verified against a live IdP
Implementation is test-covered end-to-end against the real `client_credentials` grant, but Phase 8 of the plan is outstanding: point an Entra ID / Okta test app at `/scim/v2` and verify initial import (list+pagination), create-on-assign, deactivate-on-unassign (PATCH `active:false`), rename-on-UPN-change, and attribute round-trip.

---

## OIDC extension residuals (post-implementation, 2026-09-01)

Dynamic Client Registration (RFC 7591), RP-Initiated Logout 1.0 and Back-Channel Logout 1.0 shipped in `src/oidc_ext.rs` (design in README §8). Three items remain:

### G-125 — RFC 7592 client configuration is read-only
Dynamic registration answers RFC 7591 §3.2.1 and the read operation (§4) works with client-secret authentication, but there is no `registration_access_token`: update (PUT) and delete (DELETE) of `/register/{client_id}` are not implemented. Management of registered clients goes through the admin API (`oauth2client/delete`, `oauth2client/meta`) instead. The OIDF Dynamic OP conformance suite expects the token-based configuration endpoints — implement them (mint + persist a per-client registration access token) before pursuing that certification.

### G-126 — Back-channel logout delivery has no durable retry queue
Delivery is a detached task with three in-memory attempts (1s/2s backoff). A logout that happens while an RP is down — or a process restart mid-delivery — drops the notification; the RP keeps its session until its own token expiry. If SLO guarantees matter, persist pending deliveries (the tenant `Config` store or a dedicated table) and drain them with retries.

### G-127 — Lib-test binary is flaky under parallel execution
`cargo test --lib` intermittently fails on process-wide singleton tests (observed: `otp::tests::request_throttles_per_mobile`, `db::tests::refresh_rotation_revokes_the_presented_token`, `db::tests::refresh_rejects_a_deactivated_user`) — symptoms are vanished `SEND_THROTTLE` entries and dead toasty connection tasks (`RecvError`). Pre-existing on `main` (measured ~3/8 failing runs before the OIDC-extension tests landed); serial execution (`-- --test-threads=1`) is deterministic. The shared-state tests need per-test isolation (unique throttle keys, store init owned by one persistent runtime) or the suite needs a serial convention like the integration target.
