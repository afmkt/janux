# Janux — Gaps to a Production Passwordless Auth Server

Open issues, tracked by `G-*` ID. Conventions (same as `docs/DESIGN.md`):

- **Open gaps live here.** When one is closed, strike the entry here and keep the resolution note (what changed, plus the regression test names) — the code itself carries only unmarked rationale.
- **Design decisions live in `docs/DESIGN.md`**, not here. If a DESIGN section looks wrong, that is a design discussion — except where this file explicitly flags a DESIGN/code divergence.
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

### ~~G-115 — Device-flow tokens lose amr/acr and the original auth_time~~ (closed 2026-09-06)
`device_login_approve` authenticated the approver with a real session whose `mfa` set and `auth_time` were available, but the device entry recorded only `user_id`, so `mint_token_response` built an empty factor set: device-grant access/ID tokens carried no `amr`/`acr` and `auth_time` defaulted to poll time — RPs enforcing `max_age` or step-up got wrong answers for exactly this grant. Resolved: the approval commit now records the session's `mfa` and original `auth_time` in the device entry, the atomic poll reads them out (`Poll::Approved` carries both; a missing `auth_time` on a pre-fix entry falls back to poll time as before — TTL-bounded), and `mint_token_response` takes the factor set as a parameter instead of constructing an empty one, so the access token, ID token, refresh token (offline_access), and the introspection cache entry all carry truthful `amr`/`acr`/`auth_time`. Regression test: `device_grant_tokens_carry_session_amr_acr_and_auth_time` (asserts the entry records the session factors and auth instant at approval, and that a backdated entry `auth_time` — not poll time — lands in both minted tokens).

### ~~G-116 — Introspection cache fast path is not tenant-bound~~ (closed 2026-09-05)
`OIDC_TOKEN_CACHE` is process-wide and the mint-time entries recorded client/user/scope but not the issuing tenant, so with the same client_id registered in two tenants, tenant A introspecting tenant B's cached access token got `active=true` with tenant B's sub/username. Resolved: every mint-time entry (`mint_token_response`, `handle_auth_code`, `handle_refresh`) now records `iss`, and the `/introspect` fast path compares it with the requesting tenant's issuer — a missing or mismatched `iss` fails closed as inactive. Regression tests: `introspect_cached_token_from_another_tenant_is_inactive`, `introspect_cached_token_without_issuer_is_inactive`.

### ~~G-117 — Bearer scheme accepted case-insensitively only on internal endpoints~~ (closed 2026-09-06)
`get_jwt` lowercased the header before matching, but `get_bearer_token` accepted only the literal prefixes `Bearer ` / `bearer `, so `BEARER <token>` worked on `/api/v1/*` but 401'd on `/userinfo` despite RFC 6749 §2.1 / RFC 6750 §2.1 making the auth-scheme case-insensitive. Resolved by unification: `get_bearer_token` is deleted and `/userinfo` extracts through the single `crate::utils::get_jwt` helper, whose prefix check is now an allocation-free `eq_ignore_ascii_case` (the `to_str()` filter guarantees visible ASCII, so the 7-byte slice is char-boundary safe). Regression tests: `get_jwt_matches_bearer_scheme_case_insensitively`, `userinfo_accepts_uppercase_bearer_scheme`.

### ~~G-118 — CORS origin echo panics on malformed configured origins~~ (closed 2026-09-05 — false positive as filed; hardened anyway)
The filed panic was verified unreachable: the echoed value is the *request's* Origin after `HeaderValue::to_str()` (visible ASCII only), and `parse::<HeaderValue>` accepts a strict superset of that charset (http 1.4.2: `is_visible_ascii` ⊆ `is_valid`), so the `unwrap` could not fail; allow-list values from `load_domain_cors` are only compared (`contains`), never inserted into a header, so a malformed configured origin can never reach a parse, and a non-ASCII Origin on the wire fails `to_str()` and skips the whole block. Hardened anyway to keep the invariant local: the echo now runs through a fail-closed `let Ok(origin_value) = origin.parse()` guard in the condition chain — an unparsable value skips the CORS headers and the request continues, so a future edit that echoes a configured allow-list value instead of the request origin cannot reintroduce the panic. Regression test: `cors_origin_echo_fails_closed` (allow-listed echo, non-ASCII obs-text Origin skips fail-closed, non-allow-listed origin gets nothing).

---

## Review 2026-08-26 — concurrency audit (G-119..G-122)

Audit of concurrent-API safety. Closed during the audit: the domain/tenant topology race — `add_domain`/`remove_domain`/`new_tenant`/`delete_tenant` are serialized by the `Storage::topology` mutex (regression tests `concurrent_add_domain_has_exactly_one_winner`, `concurrent_add_and_remove_stay_consistent`). The audit also found that the per-tenant request serialization the codebase relies on was undocumented; it is now deliberate design (docs/DESIGN.md §6, `Storage`/`tenant_by_domain` doc comments). Residuals below: G-119/G-120 fire in a single instance today; G-121/G-122 are latent under §6 and become live if the guard discipline loosens or across instances (G-87).

### ~~G-119 — SEND_THROTTLE cold-key burst bypass~~ (closed 2026-09-05)
The per-recipient dispatch throttle was atomic only while the key existed: on an absent key the fallback inserted `(window, 1)` and allowed unconditionally, so N concurrent first hits all passed — a coordinated burst SMS/email-bombed one recipient despite the 3/min budget, repeating every idle window. Resolved: `EphemCache::compute_or_insert` (`src/cache.rs`) runs create-and-update inside moka's per-key compute (`entry_by_ref().and_compute_with`), and `send_throttle_allows` now uses it, so the cold-key path is one atomic step. Regression test: `send_throttle_cold_key_burst_respects_the_limit` (10 concurrent cold-key hits, limit 3 → exactly 3 allowed).

### ~~G-120 — Revocation records die at `exp` but tokens verify until `exp + leeway`~~ (closed 2026-09-05)
Verification accepts tokens 120 s past expiry, but revocation records were gc'd at `expire_at < now`, skipped on restart hydration, and skipped on read-through at `exp` — in `(exp, exp+120s]` after a gc tick or restart, a revoked or already-rotated token verified again, and `refresh_jwt` could mint a second successor. Resolved: the leeway is now the shared constant `VERIFICATION_GRACE_MINUTES` (`src/jwt.rs`, used by every `jwt_decode` verification call site), and `invalid_raw` — the single write choke point for all revocations — stores `expire_at + leeway + 1s` (the extra second covers jsonwebtoken's whole-second clock truncation, which accepts tokens through the entire boundary second), so every prune path (gc, hydration, read-through) retains records for the token's full verification window by construction. Regression tests: `revocation_survives_gc_and_restart_through_the_leeway_window`, `refresh_rejects_reuse_of_an_expired_rotated_token_after_gc`.

### G-121 — The revocation "insert-wins" commit point is not atomic
`EphemCache::insert` (`src/cache.rs:34`) uses moka `entry().or_insert()`, which in moka 0.12 is look-then-insert: two concurrent racers can both observe absence and both receive `Ok`, yet `invalid_raw` (`src/jwt.rs:282`) documents the cache insert as the winner point for concurrent rotation/logout. Masked within a process by the tenant guard (docs/DESIGN.md §6) and across instances by the `jwt.db` primary key. Make the DB insert the arbiter (constraint violation = already revoked) or use moka's atomic init path, so the guarantee does not depend on the guard.

### G-122 — `user.active` transitions are unconditional writes
Every activate/deactivate is `update_by_id(...).active(...)` with no condition on the prior state (`src/user.rs:148-215`), and `activate/self` checks-then-writes (`src/user.rs:598`). Under §6 this is serialized within a process, but the guard is the only thing preventing a self-activation from overwriting a concurrent admin deactivation; same class is the active-check-then-mint window in `authenticate_jwt` (`src/db.rs:312`). Make the transitions conditional updates so a stale write fails instead of landing.

---

## Operations & scaling

### G-87 — Single-instance ceremony state (no horizontal scaling)
Every in-flight ceremony lives in process-local moka caches: magic links (`MLINK_CACHE`), SMS codes (`OTP_CODE_CACHE`), passkey challenges (`PASSKEY_CACHE`/`LOGIN_CACHE`), TOTP enrollment (`TOTP_ENROLL_CACHE`), social dances and one-shot login codes (`SOCIAL_SESSION_CACHE`, `SOCIAL_LOGIN_CODE_CACHE`), OIDC auth codes / PKCE / pending / device / token caches, plus the rate limiters (`MokaStore`), `SEND_THROTTLE`, and the per-account verify-failure gate (`VERIFY_FAILURES`). Only the revocation store is shared (`jwt.db`, G-71). With more than one instance behind a load balancer: a magic link requested on instance A fails verify on B, device-flow polling hits random instances, and every instance grants its own rate-limit budget. Either declare single-instance deployment as a hard requirement (docs + startup guard) or move ceremony state into the shared store.

### G-88 — No backup / restore / DR story
Tenant data is per-directory libsql files (`tenants/<name>/janux.db`) with no backup procedure — the only backup code path runs during tenant *deletion* (`src/db.rs:612`). No documented or automated backup, point-in-time restore, or replication plan for the signing keys, users, credentials, policies, and consent grants that constitute the entire identity state.

### G-89 — Audit trail is an access log, not a security audit
`src/audit.rs` logs method/URI/status/duration only. There is no structured, queryable record of security events: who (actor + client IP + tenant), what (target user/role/client), which factor, and with what outcome — for logins, failed verifications, credential adds/removals, role/policy mutations, tenant lifecycle, and revocations. Required for incident response and any compliance regime; currently reconstruction from unstructured tracing lines.

### G-90 — Token lifetimes are hardcoded
Internal session 15 min, OIDC access token 60 min, ID token 15 min, refresh family 30 days (`OIDC_REFRESH_FAMILY_LIFETIME`), ceremony tokens 15 min — all literals. docs/DESIGN.md §2 names "shorten token lifetimes" as the lever when the deactivation propagation window is too wide, but there is no knob. Make lifetimes tenant/server configuration.

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
docs/DESIGN.md §1 fixes the design: whether self-provisioning is allowed at all is a tenant-level config/policy concern. No such config or policy exists — every tenant is open sign-up forever, and an invite-only deployment (explicitly cited as the use case) is impossible. This is the designated extension point of the unified flow and is unbuilt.

### G-100 — DESIGN/code divergence: passkey cannot bootstrap a user
docs/DESIGN.md §1 lists passkey among bootstrap-capable factors, but registration requires a valid session for exactly that user (G-3, `src/passkey.rs:440`) — a first-time user with no session can never sign up with a passkey alone; the ceremony only asserts for existing credentials or registers inside an existing session. Resolve the divergence: either restore a bootstrap path (with its enumeration/DoS considerations) or amend docs/DESIGN.md §1 to say passkey is enrollment-only like TOTP.

### G-101 — No account recovery path
TOTP has no recovery codes; a user who loses every factor (phone gone, email inaccessible, authenticator lost) has no self-service way back in — only admin intervention (`totp/remove`, credential deletion) via out-of-band identity proofing, for which there is also no workflow. Production passwordless needs recovery codes at TOTP enrollment (single-use, rate-limited, audited) or an equivalent gated recovery ceremony.

### ~~G-102 — TOTP secrets stored in plaintext at rest~~ (closed 2026-09-05)
`Totp.secret` was a raw string in the tenant DB; being bearer-equivalent (it generates valid codes), a DB disclosure silently bypassed MFA for every enrolled user. Resolved: `add_totp` encrypts the secret with the server AES-GCM key (`crypto::encrypt_secret`, the generalized former `encrypt_client_secret`) before the row is written, and the single read seam `Totp::totp()` decrypts with a legacy fallback (`decrypt_secret_or_legacy`) — safe because the GCM auth tag makes it cryptographically impossible for a plaintext to decrypt successfully. Pre-existing plaintext rows are re-encrypted in place on the first read through `totp_of` (`ensure_secret_encrypted`), so the DB converges to ciphertext with no migration script; the enrollment URI/QR still carries the plaintext once, as the protocol requires. `crypto::get_encryption_key` now fails closed with an error instead of panicking, and `JANUX_ENCRYPTION_KEY` is documented as recovery-critical in base.example.toml. Regression tests: `totp_secret_is_encrypted_at_rest`, `legacy_plaintext_totp_secret_still_verifies_and_upgrades`.

### ~~G-103 — Delivery-provider secrets stored in plaintext at rest~~ (closed 2026-09-05)
`ResendDTO.resend_key` and `OTPDTO.api_secret`/`api_key` were written verbatim into the tenant config table — send-capable credentials (mail and SMS quota, phishing reach) persisted raw. Resolved with the same treatment as G-102, at the DTO boundary: `save` encrypts via `crypto::encrypt_secret`, `load` decrypts with the legacy fallback, so consumers (mail/SMS dispatch) keep reading plaintext fields and pre-existing plaintext config values keep loading; seeded tenants converge to ciphertext on the next boot since seeding runs `save`. Regression tests: `otp_provider_keys_are_encrypted_at_rest`, `resend_key_is_encrypted_at_rest`.

### ~~G-104 — No per-user attempt budget on verify endpoints~~ (closed 2026-09-05)
`/api/v1/auth/*` was limited per client IP only (6/min), so a distributed attacker got an unbounded aggregate budget of request→verify cycles against one account's OTP/TOTP codes (each ceremony is one-shot, but nothing bounded the ceremony loop). Resolved with the second rate-limit layer: a per-(tenant, user) failure gate (`VERIFY_FAILURES`, `src/utils.rs`) — 5 failed verifies per 15-min window lock the account's code ceremonies for 15 min, doubling per repeated cycle up to 24 h; success clears the state. Gated surfaces: `otp/verify`, `otp/request` (both the claimed name and, in the signin branch, the `user_by_mobile`-RESOLVED account, so a throwaway claimed name cannot keep codes flowing to a locked-out phone), `totp/verify`, and the `totp/enroll` re-enrollment possession check on active records (a code-guessing surface that re-exposes the live secret on a hit). The gate is checked at handler entry before any one-shot ceremony secret is consumed, so a locked-out attacker cannot burn a code just issued to the legitimate user. Failures are recorded only when the ceremony token validated for the claimed identity — junk bodies cannot flood the lockout cache (capacity is also raised to 200k entries so eviction cannot lift a live lockout), and server-side failures are not charged to the account. The deliberate-lockout DoS trade-off is bounded by covering only guessable-code ceremonies (magic links, passkeys, social dances are not gated). Counters are create-and-increment atomic via `EphemCache::compute_or_insert` (the G-119 lesson). The OTP modulo bias is fixed with rejection sampling (`buf[0] < 250`, `src/otp.rs`). The new 429 responses are annotated in the OpenAPI spec and the frontend client is regenerated. Caveat: the counter is process-local, so the budget is per-instance (G-87). Regression tests: `verify_gate_locks_after_repeated_failures`, `verify_gate_backoff_escalates_per_cycle`, `verify_gate_window_reset_drops_stale_failures`, `verify_locks_the_account_after_repeated_failures` (otp), `verify_locks_after_repeated_wrong_codes`, `enroll_reenrollment_code_checks_are_gated` (totp).

### G-105 — No identifier normalization or validation
`user_create` accepts any string; emails and mobiles are stored exactly as typed and compared by exact match (`Email`/`OTP` primary keys). `Alice@Example.com` and `alice@example.com` are two different credentials; throttling lowercases for rate limits but storage does not, so case rotation also evades uniqueness. Validate formats at ceremony `request` time and normalize (lowercase email; E.164 for mobile) before storage and lookup.

---

## Sessions & users

### G-106 — No session visibility or global revocation
Users cannot list their active sessions or revoke them ("sign out everywhere"); there is no admin equivalent per user either. Deactivation kills sessions only at the refresh boundary by design (docs/DESIGN.md §2), which is fine for admin action, but a user who suspects token theft has no self-service remedy beyond waiting one token lifetime per device. Needs a session index (jti-keyed, per user) and a revoke-all primitive on top of the existing `InvalidJwt` store.

### ~~G-107 — Panic paths in request handlers~~ (closed 2026-09-05)
Misconfiguration crashed the request task instead of returning an error: `otp/request` unwrapped a missing SMS config, magic-link rendering unwrapped Tera results (at the call site AND inside `render_email`), TOTP enroll unwrapped the otpauth URL, and `redirect_to` expected URL-derived `Location` header values to parse. All four now fail closed: missing SMS config renders the same 401 `MobileResponse` the add flow already used; Tera failures propagate as `Err` through the magic-link `Result`; enroll falls through to its 401 unless both QR and URI build (`if let (Ok(qr), Ok(uri))`); and `redirect_to` — the single builder behind all six OIDC redirect sites — renders a 400 `ApiProblem` when the URL carries bytes a header value cannot represent (non-ASCII or control chars, e.g. a CRLF injection attempt). Regression tests: `request_without_sms_config_fails_closed`, `render_email_surfaces_template_errors`, `redirect_to_fails_closed_on_unparsable_url`. The same-class CORS entry (G-118) was verified a false positive as filed and hardened separately.

---

## Testing & CI integrity

### ~~G-108 — CI does not actually run integration or e2e tests~~ (closed 2026-09-05)
The filed defects (nonexistent `--test playwright` target, echo-stub e2e job, `continue-on-error` clippy) were verified already fixed in the current `ci.yml`: the integration job runs `cargo test --test z_integration_tests -- --test-threads=1`, the e2e job installs Playwright Chromium and runs `cargo test --test all_tests -- --test-threads=1`, and clippy runs `-D warnings` as a hard gate. The remaining gap is closed here: the unit job ran the lib suite with default parallelism even though it shares process-wide singletons (revocation store, throttle/gate caches) and is order-sensitive (G-127 class), so it now runs `-- --test-threads=1` like the integration and e2e jobs.

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

### ~~G-113 — List endpoints are unbounded~~ (closed 2026-09-06)
`user/list`, `role/list`, `policy/list`, `key/list`, `totp/list`, `oauth2client/list`, `domain/list`, `tenant/list` returned every row with no pagination or cap. Resolved with DB-level offset pagination on all eight endpoints: shared `limit`/`offset` query parameters (`src/utils.rs` — `page_params`, default 50, hard cap `MAX_PAGE_LIMIT` = 200, which SCIM's `filter.maxResults` is now defined from so the two surfaces share one ceiling) and a `Page<T>` envelope (`items`, `limit`, `offset`, `next_offset`). Eight `*_page` Tenant methods (`users_page`, `roles_page`, `policies_page`, `keys_page`, `providers_page`, `domains_page`, `totps_page`, `oauth2client_page`) encapsulate the whole protocol: they order by primary key (composite pk for `Totp`) so pages are stable and disjoint, fetch `limit + 1` through toasty `.limit()/.offset()` so the probe row signals a next page without a `COUNT(*)`, clamp both bounds into toasty's `i64` range (`page_bounds` — an unclamped `offset` above `i64::MAX` panics inside the toasty builder), and return `Page<Model>` directly. `tenant/list` pages the in-memory directory (`Page::from_all`, name-sorted, saturating arithmetic). `next_offset` is `Some` only when more rows follow, so clients loop without totals. The unpaginated `all_users`/`all_keys`/`all_providers`/`all_domains` remain for internal callers (SCIM, JWKS + active-key cache, OIDC discovery + social registry, CORS/tenant loading); `all_roles`, `all_policies`, `all_totps`, and `oauth2client_all` became test-only after the handler switch and were deleted (tests call the `*_page` methods). `oauth2client/list` batch-fetches the page's redirect URIs in one indexed `in_list` query, replacing the per-client N+1. IDs are UUIDv7, so a keyset (`id > cursor`) upgrade is available if datasets grow. SCIM keeps its spec-mandated `startIndex`/`count`. The OpenAPI spec documents the parameters and envelope (descriptions reference the server-enforced bounds instead of literals), and the regenerated frontend SDK walks `next_offset` via `fetchAllPages` so admin tabs show the full dataset. Regression tests: `page_params_defaults_and_clamping`, `page_bounds_probes_one_extra_row_within_toasty_limits`, `page_from_rows_uses_the_probe_row_to_detect_a_next_page`, `page_from_all_slices_in_memory_rows`, `page_map_preserves_pagination_metadata`, `page_serializes_without_next_offset_on_the_last_page`, `users_page_walks_the_table_in_disjoint_pages`.

---

## Documentation

### ~~G-114 — Referenced companion documents are missing or stale~~ (closed 2026-09-01)
The planning documents (`api-consolidation.md`, `g10-privilege-escalation.md`, `x.md`) were deliberately removed once their issues were resolved, and every code/docs reference to them was cleaned out or rewritten as self-contained rationale (the G-\* IDs they backed remain the canonical pointers). The repository-layout frontend line was updated to the implemented page set (`login`, `admin`, `consent`, `device`).

---

## SCIM residuals (post-implementation, 2026-08-31)

The SCIM 2.0 surface (`src/scim.rs`, `/scim/v2/*`) shipped with the `scim` builtin role, the `client_credentials` machine principal, and integration tests. Two items from its planning doc remain:

### G-123 — Deleting an OAuth2 client does not revoke its machine tokens
`client_credentials` mints a 90-day session-shaped JWT bound to the client's service identity, and JWT verification is stateless (design §2), so `oauth2client_delete` leaves outstanding provisioning tokens valid until expiry. Sweep them through `/revoke` (or the revocation store directly) on client deletion/deactivation.

### G-124 — SCIM surface not yet verified against a live IdP
Implementation is test-covered end-to-end against the real `client_credentials` grant, but Phase 8 of the plan is outstanding: point an Entra ID / Okta test app at `/scim/v2` and verify initial import (list+pagination), create-on-assign, deactivate-on-unassign (PATCH `active:false`), rename-on-UPN-change, and attribute round-trip.

---

## OIDC extension residuals (post-implementation, 2026-09-01)

Dynamic Client Registration (RFC 7591), RP-Initiated Logout 1.0 and Back-Channel Logout 1.0 shipped in `src/oidc_ext.rs` (design in docs/DESIGN.md §8). Three items remain:

### G-125 — RFC 7592 client configuration is read-only
Dynamic registration answers RFC 7591 §3.2.1 and the read operation (§4) works with client-secret authentication, but there is no `registration_access_token`: update (PUT) and delete (DELETE) of `/register/{client_id}` are not implemented. Management of registered clients goes through the admin API (`oauth2client/delete`, `oauth2client/meta`) instead. The OIDF Dynamic OP conformance suite expects the token-based configuration endpoints — implement them (mint + persist a per-client registration access token) before pursuing that certification.

### G-126 — Back-channel logout delivery has no durable retry queue
Delivery is a detached task with three in-memory attempts (1s/2s backoff). A logout that happens while an RP is down — or a process restart mid-delivery — drops the notification; the RP keeps its session until its own token expiry. If SLO guarantees matter, persist pending deliveries (the tenant `Config` store or a dedicated table) and drain them with retries.

### G-127 — Lib-test binary is flaky under parallel execution
`cargo test --lib` intermittently fails on process-wide singleton tests (observed: `otp::tests::request_throttles_per_mobile`, `db::tests::refresh_rotation_revokes_the_presented_token`, `db::tests::refresh_rejects_a_deactivated_user`) — symptoms are vanished `SEND_THROTTLE` entries and dead toasty connection tasks (`RecvError`). Pre-existing on `main` (measured ~3/8 failing runs before the OIDC-extension tests landed); serial execution (`-- --test-threads=1`) is deterministic. The shared-state tests need per-test isolation (unique throttle keys, store init owned by one persistent runtime) or the suite needs a serial convention like the integration target.
