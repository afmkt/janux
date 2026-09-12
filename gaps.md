# Janux — Gaps & Residuals

A current review of open gaps, accepted (by-design) limitations, and the
recommended fix order. The design decisions behind "accepted" items live in
[docs/DESIGN.md](docs/DESIGN.md); treat a flagging there as a *design
discussion*, not a bug. The historical `G-*` items referenced throughout the
source are closed fixes (see [Closed / verified below](#closed--verified));
this file starts new tracking at **G-167**.

> **Scope of this review.** Static + structural review of `src/`, `docs/`,
> `tests/`, `.github/`, and the build. The tree builds clean
> (`cargo build`), the full Rust suite runs single-threaded, and the OIDF/
> SCIM conformance suite exists under `tests/compliant`. Findings below are
> gaps in *coverage, completeness, or operational posture* — not compile
> breakage or known-panic bugs. Items marked **verify** need a confirming
> test before they can be closed.

---

## 1. Open gaps

### G-167 — No SAML 2.0 federation
**Severity: Medium · Area: IdP/SP federation**

`docs/` carries the SAML 2.0 stack as research material
(`docs/saml-core-2-0-os.pdf`, `docs/saml-chapters/`, `docs/convert_saml.py`),
but `src/` contains **zero SAML code** — a case-insensitive `grep -i saml`
over `src/` returns nothing. Federation is OIDC/social (`social.rs`) plus
passkeys only.

- **Impact.** Deployments whose relying parties or upstream corp IdPs
  speak SAML (a large share of the enterprise SP/IdP world) cannot adopt
  Janux without a bridge. The SAML research artifacts suggest this was on the
  roadmap, never closed.
- **Recommendation.** Either (a) start the SAML SP-Initiated + IdP-Initiated
  assertion flow behind a new factor (`src/saml.rs`, mirroring
  `social.rs`/passkey), or (b) delete the unimplemented reference specs so a
  reader is not misled about support. At minimum, state SAML scope in the
  README feature list.

### G-168 — SCIM is Users-only; Groups and most protocol features absent
**Severity: Medium · Area: SCIM 2.0 provisioning**

`/scim/v2` implements `Users` CRUD plus discovery
(`ServiceProviderConfig`, `Schemas`, `ResourceTypes`, `scim.rs:925`).
`ServiceProviderConfig` itself advertises the gaps:
`bulk: false`, `sort: false`, `etag: false`, `changePassword: false`
(`src/scim.rs`). There are **no `Group` resources** (RFC 7643 `urn:ietf:params
:scim:schemas:core:2.0:Group`) — `grep -i group src/scim.rs` matches nothing.

- **Impact.** Enterprise IdPs (Entra, Okta, Ping) commonly provision
  *groups* alongside users; a Janux-fed tenant receives users but no group
  sync, and bulk provisioning (IdP initial sync of a large user base) is
  absent, forcing per-user round-trips under the per-tenant write-lock
  (DESIGN §6 head-of-line blocking amplifies this).
- **Recommendation.** Add `GET/POST /scim/v2/Groups` and `Groups/{id}` with
  a `members` relation to `User`, and flip `sort`/`etag` to `true` once the
  list handlers support `sortBy`/`If-Match`. Keep `bulk` gated until the
  write-lock serialization cost of a bulk write is characterized.

### G-169 — Audit tamper-evidence is in-memory and non-durable
**Severity: Medium · Area: Audit / tamper-evidence**

The G-166 tamper-evident chain lives in a process-global
`OnceLock<Mutex<Chain>>` (`src/audit.rs`). Concrete residuals:

1. **`seq` restarts at 0 every boot.** A verifier replaying a log that spans
   a restart sees two independent sequences both starting at `seq=1`, so the
   global ordering the chain is meant to provide does not survive a restart.
2. **The verification primitive is dead code.** `verify_chain` is
   `#[allow(dead_code)]` — "not yet wired into the running binary"
   (`src/audit.rs`). No path in the binary or the conformance suite replays a
   trail.
3. **No external append-only sink.** The module docstring states the
   residual openly: "Janux writes lines in-process; the operator's sink…" —
   the integrity property holds only against tampering *within one process
   lifetime* that keeps its own log intact.

- **Impact.** After a single restart the chain offers no cross-restart
  tamper-evidence; a host or log compromise that also restarts the process is
  invisible. For a security control whose whole value is tamper-evidence,
  "within one boot" is a narrow guarantee.
- **Recommendation.** Persist the head (`seq`/`prev`) — e.g. into the
  `jwt.db` revocation store, which already survives restarts and is
  process-wide — so the genesis re-anchors on boot; wire `verify_chain` into
  a `janux audit --verify <trail>` subcommand; document the external-sink
  expectation (SIEM/ship-the-file) in the README backup section.

### G-170 — No tenant-wide "require MFA" knob
**Severity: Low–Medium · Area: MFA policy**

MFA enforcement is **per-policy only** (`Policy.mfa` → `expect_mfa`,
`src/policy.rs:239`). There is no tenant-level switch (a grep for a
`require_mfa`/`mfa_enabled` tenant setting returns nothing). To force a
second factor on a surface the operator must set `mfa: true` on each
governing policy in the seed.

- **Impact.** Easy to under-gate: a new policy added with the seed default
  (`mfa = false`, see `seed.example.toml`) silently drops into a no-MFA
  surface. "Require MFA for everything except explicitly-exempted" is the
  safer default for an auth server.
- **Recommendation.** Add a tenant config flag (default-deny style):
  enforce a second factor by default, with an allow-list of `mfa: false`
  exemptions, rather than the current opt-in-per-policy default.

### G-171 — `config::all_configs` dumps all tenant config but is unwired
**Severity: Low (latent) · Area: API surface / secrets**

`all_configs` (`src/config.rs:231`) lists the *entire* per-tenant `Config`
table via `config_list("")` — which includes the send-capable encrypted
secrets `resend.key` and `otp.api_secret` (`RESEND_KEY`/`OTP_API_SECRET`).
It is `pub` but **never routed** (no reference outside its definition), so it
is currently dead.

- **Impact.** No runtime exposure today. The risk is a future wiring: if a
  handler mounts `all_configs` without the `admin` `protect` hoop (and the
  `encrypt`/`decrypt` path is only a at-rest concern, not a response-time
  concern), an authenticated caller of the wrong role would receive encrypted
  provider credentials.
- **Recommendation.** Either delete the dead handler, or wire it behind
  `admin`/`protect` with `audit` and a response that redacts `*key`/`*secret`
  fields (mirroring the audit hoop's `redacted_uri` for G-140).

### G-172 — Unauthenticated `auth/verify` carries no per-IP limit
**Severity: Low · Area: Rate limiting**

`/api/v1/auth/verify` (the forward-auth entry, `src/router.rs`) is **not**
behind the per-IP `limiter` — the limiter guards only the
`Router::with_path("auth")` subtree (`email/request`, `totp/verify`, …).
Discovery endpoints are exempt by intent (cheap, cacheable) but `verify`
performs a JWT decode + revocation-store check per call.

- **Impact.** Low today: revocation lookups are cached and JWT decode is
  cheap, and forward-auth proxies drive this at high legitimate QPS, so a
  limiter would hurt. Noted so the exemption is a *conscious* choice, not an
  accident.
- **Recommendation.** Confirm intent; if the revocation-store miss path
  ever grows (uncached decode, a per-call DB hit), add a coarse limiter or a
  token-bucket that permits anonymous bursts but caps sustained unauthenticated
  load.

### G-173 — Test suites are pinned single-threaded (G-127 DI deferral)
**Severity: Low · Area: Test infra / CI cost**

`unit`, `integration`, `e2e` all run `-- --test-threads=1`
(`justfile`) because of process-global singletons (revocation store, throttle
caches — see the CI comment at G-127). This is correct (parallel runs are
flaky) but it is the dominant CI-time cost and it *masks* data races: a
future multi-instance change would be untested.

- **Impact.** Slow CI; and no automated signal that the in-memory state is
  actually concurrency-safe (DESIGN §6 says the tenant guard makes tenant
  state safe, but the *guard-free* singletons are asserted safe "on their
  own" — G-119 — with no concurrent test to prove it).
- **Recommendation.** The G-127 DI effort (per-process cache/DB injection)
  is the real fix; until then add at least one explicit concurrency test
  hammering `SEND_THROTTLE`/`InvalidJwt::gc` under N tasks so the
  "concurrency-safe on its own" claim (G-119) has a regression net.

---

## 2. Accepted by design (not bugs — re-verify intent, do not "fix")

These are deliberate decisions, documented in
[docs/DESIGN.md](docs/DESIGN.md). They are residual *limitations*, tracked
here so a future reader does not file them as defects.

| ID | Decision | Where | Note |
|----|----------|-------|------|
| G-87 | One instance per data dir; ceremony state (magic links, OTP, challenges, throttles, OIDC parked flows, backchannel queue) is **process-local by design** and fails closed on loss; only the revocation store is shared via `jwt.db`. | DESIGN §6 | Accepted. Multi-instance HA (sticky routing or a shared ceremony store) is a future feature, not a correctness fix. |
| G-5 / DESIGN §5 | Domain registration is an **operator trust decision, not an attested claim** — `admin/domain/add` does no DNS-01/HTTP-01/TLS-ALPN. | DESIGN §5 | Re-open only if targeting public multi-tenant hosting. Re-point `domain/add|delete` to a higher-trust role to close it for a given deployment. |
| G-99 | **Open signup**: a completed ceremony provisions a `guest` floor; closed enrollment is an RP concern. | DESIGN §1 | Owner decision 2026-09-08. |
| G-100 | **Passkey/TOTP can never provision a user**; anchor-first (verifiable external identity), passkey second. | DESIGN §1 | Owner decision 2026-09-08. |
| head-of-line blocking | A slow SMS/email send holds the per-tenant write lock, so other requests for that tenant queue (DESIGN §6). | DESIGN §6 | Throughput, not correctness. Aggravated by G-168 bulk absence. |
| G-175 | **Root role is seed-only and single-tenant.** `bootstrap_tenant` (runtime path via `admin/tenant/create`) provisions `admin`/`scim`/`user`/`guest` but NOT `root`. The `root` role is established exclusively through `seed.toml` via `Caller::Bootstrap` (the platform-level trust anchor). `Storage::seed` enforces the single-root invariant: at most one tenant may define a user with the `root` role; a config defining root in two tenants is rejected at boot. No runtime API grants or creates `root`. | DESIGN §3, §5 | Root is the platform authority; two roots are incoherent. SCIM (level 60) cannot provision admin (80) or root (100) by the level gate (§3). No promotion path exists. The first admin's credential (email or mobile) lands UNVERIFIED — the admin proves ownership at first login via the normal ceremony. |

---

## 3. Recommended fix order

1. **G-169** (audit durability) — highest-value security-control gap;
   smallest blast radius; the `verify_chain` primitive already exists.
2. **G-168 → G-167** federation completeness — the biggest
   adoption-blockers for an IdP, and both are "presence" gaps (SCIM
   Groups, SAML) rather than correctness fixes.
3. **G-170** (global MFA default) — default-deny hygiene on a new-policy
   path; cheap and reduces a whole class of under-gating mistakes.
4. **G-171 / G-172** — latency/latent-secret cleanups; either delete the
   dead handler or wire it safely, and document the `verify` exemption.
5. **G-173** — test-infrastructure debt; pairs with the long-standing G-127
   DI track.

Open items from the DESIGN residuals that were already closed this cycle
(verified via `git log`): **G-123** (client-deletion poison marker),
**G-125** (RFC 7592 DCR management surface), **G-126** (durable
back-channel worker). Their DESIGN §7/§8 "open residuals" wording is now
stale — update those two sentences when those items are re-touched.

---

## 4. Closed / verified

The `G-*` IDs embedded in source comments are historical *fix markers*
(what the change closed and why), not open work. They are resolved —
traceable in `git log` (e.g. `G-119`, `G-121`, `G-125`, `G-126`, `G-149`,
`G-150`, `G-166`). A non-exhaustive set, with the area they fixed:

- **G-149** — `X-Forwarded-*` header authority restricted to a
  `trusted_proxies` allow-list (`src/main.rs`, G-149 warning).
- **G-150** — at-rest encryption of secrets + `janux rekey` rotation,
  with the example-key boot warning.
- **G-166** — tamper-evident audit hash chain (see G-169 above:
  *durable* wiring is the open residual).
- **G-139** — canonical `janux.session` HttpOnly cookie; refresh/logout
  rotate and clear it server-side.
- **G-132** — sudo-mode freshness window for credential mutations
  (`auth_time`-gated, `src/verify.rs`).
- **G-123 / G-125 / G-126** — client-deletion revocation marker, RFC 7592
  DCR PUT/DELETE, durable back-channel worker.
- **G-121** — refresh rotation single-winner via the persistent
  revocation store (atomic winner point).

New tracking resumes at **G-167**. When an item is closed, keep its ID
referenced in the fixing commit (the codebase's convention) and delete it
from §1 here.

---

_Generated: 2026-09-11 · tree builds clean · next ID: G-174._
