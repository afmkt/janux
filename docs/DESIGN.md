# Janux — Design Decisions

This document records the design decisions behind Janux. When reviewing the codebase, treat the sections below as **intentional design** — if one of them looks wrong, that is a design discussion, not a gap to file. The public overview, quickstart and deployment notes live in [README.md](../README.md); open issues are tracked in [KNOWN_ISSUES.md](../KNOWN_ISSUES.md).

---

## 1. Passwordless: signin and signup are one flow

Janux has no passwords and no signin/signup distinction. Every factor follows the same two-phase pattern:

1. `POST /api/v1/auth/{factor}/request` — username + chosen factor. If the user does not exist, they are provisioned here (`ensure_user_*`); if they exist, the challenge is issued. **The response is identical in both cases.**
2. `POST /api/v1/auth/{factor}/verify` — prove the challenge; factors accumulate, a JWT is minted, the session cookie is set.

Why this is deliberate and safe:

- **Possession is the identity proof.** A magic link proves control of the email inbox, SMS OTP proves control of the phone, social delegates to an external IdP, passkeys attest the authenticator. Whoever passes `verify` owns the identifier, so auto-provisioning on first successful verification is the point of passwordless.
- **Enumeration resistance falls out for free.** `request` never reveals whether the account existed. Do not add existence signals "for UX".
- **Do not re-introduce a per-request `mode: signin|signup` field.** An explicit signup mode was proposed during API consolidation and superseded by this design: it would duplicate a provisioning decision the unified flow already makes, and a default-`signin` mode would break first-time users.

Invariants that keep the unified flow safe:

- **Bootstrap-capable factors**: magic link, SMS OTP, social, passkey. **TOTP can never provision a user** — it proves nothing out-of-band; it is enrollment/step-up for existing accounts only.
- **Signup gating is a tenant-level concern** (config/policy deciding whether self-provisioning is allowed at all, e.g. invite-only deployments) — never a per-request body field.
- **The passkey ceremony branches server-side** (registration vs assertion based on existing credentials, `src/passkey.rs`); the client API stays `request`/`verify`.
- Provisioning must attach the credential to the real user record (G-40 was a bug against this invariant — the social flow attached the email to a provider-named user — not an argument against the unified flow).

## 2. Stateless JWTs; activeness enforced at stateful boundaries

`verify_jwt` / `decode_session` deliberately never consult live user state: JWTs are stateless and a distributed verifier has no central authority to check activeness. `user.active` is enforced at the stateful boundaries — login (`authenticate_jwt`) and refresh (`Tenant::refresh_jwt`, OIDC `handle_refresh`) — so a deactivated account's tokens die within one token lifetime (refresh is the only extension point and re-checks). Do not add live-state lookups to the verification path; if the propagation window is too wide, shorten token lifetimes instead (G-9).

## 3. Bounded role hierarchy (privilege escalation closed by construction)

Every `Role` carries a `level` and a `builtin` flag; the builtin catalog is fixed in code (`root`=100, `admin`=80, `user`=40, `guest`=20 — `BUILTIN_ROLES`, `src/role.rs`). One gate — `Tenant::require_below` — enforces that a caller may create/grant/revoke/empower/delete a role only when that role's level is strictly below the caller's effective level; all six role/policy mutation functions funnel through it. A policy can widen *which* endpoints are callable, never *what power* they confer. `root` is seed-only; builtin roles are undeletable and their names reserved (G-10).

## 4. Default-deny authorization

The `protect` hoop (`src/router.rs`) rejects anything without an explicit allow policy. The `tenant/*` lifecycle endpoints are bound to `root` only (G-11); root operating across all tenants is intended — root is the cross-tenant lifecycle role. Policy writes derive their domain from the request `Host` (the resolved tenant domain), never from a client-supplied body field (G-56).

## 5. Multi-tenancy

A tenant is resolved from the request `Host`/domain and gets its own database schema (`push_schema`). `seed.toml` seeds the bootstrap tenant (builtin role catalog + users + admin policies); runtime tenants created via `admin/tenant/create` are bootstrapped with the same catalog + standard admin policies + optional first admin/domain (`bootstrap_tenant`, `src/seed.rs`) so they are operable immediately. Seeding runs as `Caller::Bootstrap`, which is exempt from the level gate. The `seed.toml` shape is pinned by the `seed_toml_bootstraps_builtin_roles` test so a typo fails at `cargo test` time instead of as a lockout on first boot.

## 6. Per-tenant serialization: one request at a time per tenant

Same-tenant requests never run concurrently within a process. The mechanism is `Storage::tenant_by_domain` / `tenant_by_id` (`src/db.rs`): they return a DashMap `RefMut` — a shard **write lock** on the tenant map — and every handler holds that guard from tenant resolution to the end of the request, across every `.await`. This serialization is what the check-then-act sequences rely on: identity claims (email/mobile/social/passkey), `user.active` transitions and the level gates (§3, G-66), the refresh-rotation single-winner, and the key/policy caches against their per-tenant databases. Tenant/domain lifecycle mutations run outside any tenant guard and are serialized separately by the `Storage::topology` mutex.

Rules for code that touches a tenant:

- **Hold the guard across the entire multi-step flow.** Dropping it mid-flow and re-borrowing reopens every race the design closes.
- **Never use `tenants.get()` (a read ref) in a flow that mutates.** Mutation flows go through `get_mut`.
- **Do not clone a `toasty::Db` handle out of the guard and mutate the tenant elsewhere.** The one exception is the revocation store (`InvalidJwt`): it is process-wide, keyed by token, and takes `&self` by design — its within-instance safety rests on the *caller's* tenant guard, its cross-instance safety on the `jwt.db` primary key (G-71).

Accepted costs: a slow SMS/email send holds the lock, so other requests for the tenant queue behind it (head-of-line blocking); tenants hashing to the same DashMap shard serialize together — a throughput concern, never a correctness one.

Scope: the guarantee is per-process. Process-wide caches that are not keyed by tenant (`SEND_THROTTLE`, the per-IP limiters) are NOT covered by the guard and must be concurrency-safe on their own (G-119). Nothing here extends across instances sharing a data dir — horizontal scaling means moving the commit points into the shared store (G-87), after which this guard degrades to a fast path.

## 7. SCIM-first user management

External user lifecycle (provisioning, deactivation, rename) belongs to the SCIM 2.0 surface (`/scim/v2/*`, `src/scim.rs`), not the RPC-style admin API: IdPs drive it under a machine principal minted by the `client_credentials` grant and carrying the builtin `scim` role (level 60 — above `user` so the G-66 gate lets it manage regular accounts, below `admin` so it can never administer administrators). Identity model: `User.id` is an opaque UUIDv7 surrogate key (SCIM resource id, JWT `sub`, every FK); `User.name` is the unique, mutable login name (SCIM `userName`); `User.external_id` persists the IdP join key. Custom admin endpoints remain only for what SCIM does not cover (role grants, factor administration). Open residuals: G-123, G-124.

## 8. OIDC beyond Basic/Config: dynamic registration and logout (`src/oidc_ext.rs`)

The OP implements three profiles on top of Basic + Config, and deliberately stops there:

- **Dynamic Client Registration** — RFC 7591 `POST /register` plus the RFC 7592 §4 read (`GET /register/{client_id}`, client-authenticated). Gated by a per-tenant switch (`oidc.dcr` in the tenant config store, `admin/oidc/config`), default **off**: open registration lets anyone mint client rows, so each tenant opts in. Self-service registration stays bounded: `client_credentials` is excluded (no self-minted service identities), the scope vocabulary cannot widen beyond `KNOWN_SCOPES`, and implicit/hybrid response types are never registered (deprecated by the OAuth 2.1 BCP, same reason the server is code-flow-only).
- **RP-Initiated Logout 1.0** — `GET|POST /end_session`. Validates `id_token_hint`/`client_id`, refuses any `post_logout_redirect_uri` that is not registered for that client (direct 400, never a redirect to an unvalidated URI), revokes the session presented to it, and answers 302 (with the RP's `state`) or 200.
- **Back-Channel Logout 1.0** — on logout (`/end_session` and first-party `auth/logout`) every RP of the user that registered a `backchannel_logout_uri` receives a form-encoded `logout_token`. Delivery is fire-and-forget with bounded retries — logout never fails because one RP is unreachable.

Two spec mechanisms adapt to the stateless-session design (§2), and this is deliberate:

- **No `sid` anywhere.** There is no server-side session registry, so logout tokens identify the user by `sub` only and discovery advertises `backchannel_logout_session_supported: false`. The RP set to notify comes from the user's non-revoked consent grants (`AuthGrant`) — the only durable record of where a user holds an active OIDC authorization.
- **`/end_session` terminates the session presented to it (Bearer JWT), not a cookie.** Login factors set cookies under client-chosen names (§1-era API), so no fixed session cookie exists for the OP to clear.

Extended client metadata (`backchannel_logout_uri`, `post_logout_redirect_uris`, `client_name`, dynamic provenance) lives in the tenant `Config` store under `oidc.client.<client_id>`, not in `OAuth2Client` columns: tenant databases created before a feature tolerate `push_schema` failures on existing tables, so a new column would silently never appear there while queries reference it. Admin surface: `admin/oauth2client/meta` sets the metadata for statically created clients. Open residuals: G-125, G-126.

