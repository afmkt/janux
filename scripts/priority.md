Reviewed the repo, `KNOWN_ISSUES.md` (G-* tracker), CI, and spot-checked the code. Two tracker entries are stale: **G-92** (RP-initiated + back-channel logout shipped in `src/oidc_ext.rs`) and **G-108** (CI now runs integration + e2e single-threaded, clippy with `-D warnings`) — worth striking per the file's own convention.

Most valuable open tasks, ranked by risk-to-effort for a multi-tenant auth server:

**Tier 1 — security-critical, small/medium fixes**

1. **G-116 — Introspection cache not tenant-bound** (`src/oidc.rs:3345`): cross-tenant token validation leak; same client_id in two tenants → tenant A validates tenant B's tokens. Small fix (store issuer in cache entry), highest severity.
2. **G-120 — Revocation records die at `exp` but tokens verify until `exp+leeway`** (`src/jwt.rs`): revoked/rotated tokens re-verify for 120s after gc/restart, and refresh can mint a second successor. Undermines the core revocation guarantee; retain records for `exp + leeway`.
3. **G-104 — No per-user attempt budget on verify**: IP-only rate limiting leaves 6-digit OTP/TOTP open to distributed brute force. This is the primary attack surface of a passwordless server.
4. **G-102 + G-103 — TOTP and delivery-provider secrets plaintext at rest**: AES-GCM infra already exists in `src/crypto.rs`; DB disclosure silently bypasses MFA and hands over mail/SMS send capability.
5. **G-119 — SEND_THROTTLE cold-key burst bypass** (`src/utils.rs:763`): coordinated first-hits bypass the 3/min budget → SMS/email bombing. Fix via moka entry API, tiny change.

**Tier 2 — robustness / fail-closed**

6. **G-107 + G-118 — Panic paths in handlers and CORS** (confirmed still present, e.g. `src/cors.rs:37` `origin.parse().unwrap()`): tenant misconfiguration crashes request tasks; convert to fail-closed errors.
7. **G-105 — Identifier normalization**: `Alice@Example.com` ≠ `alice@example.com` defeats both uniqueness and throttling; normalize at ceremony `request` time.
8. **G-110 — Server-side `redirect_uri` validation**: currently client-side-only; open redirect with a fresh session on any SPA XSS.
9. **G-97 — Signing-key retire phase**: key deletion = forced tenant-wide logout; add `retired_at` + last-key guard.
10. **G-115 — Device-flow tokens lose amr/acr/auth_time**: RPs enforcing `max_age`/step-up get wrong answers for device grants; data is already available at approve time.

**Tier 3 — production-readiness (larger efforts)**

11. **G-89 — Structured security audit trail**: prerequisite for incident response and any compliance regime; currently access-log only.
12. **G-87 — Enforce single-instance**: README declares it, but add the startup guard/doc contract so a scaled deployment fails loudly instead of silently breaking ceremonies.
13. **G-91 — Real health/readiness/metrics**: `healthy` returns `ok: true` unconditionally.
14. **G-99 — Signup gating**: the design's designated extension point (invite-only tenants) is unbuilt.
15. **G-112 — Security headers/CSP on hosted pages**: magic-link tokens transit URL query; `Referrer-Policy` + CSP is the standard mitigation.

If you want a single starting point: **G-116 + G-120 + G-119** together are ~a day of work and close the three cheapest correctness holes in the token/throttle machinery. Say the word and I'll start on them (or fan them out into Agent Manager worktrees).