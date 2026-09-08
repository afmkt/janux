# janux conformance suite

Black-box standards conformance testing for the janux auth server:
OpenID Connect (OP + RP roles), OAuth 2.0, SCIM 2.0.

## Division of labor

| Track | Tool | Where |
|---|---|---|
| OIDC OP profiles (Basic, Config) | official OIDF conformance suite | `oidf/` |
| OIDC RP profile for social login | official OIDF conformance suite (suite = fake OP) | `oidf/` |
| Everything OIDF does not cover | this Python suite (pytest + httpx + jwcrypto) | `tests_op/`, `tests_scim/` |

The custom suite covers what no external suite can: SCIM 2.0 (no official
certification exists), the RFC 8628 device flow, revocation/introspection
depth, and janux-specific invariants (per-client grant allowlists, consent
grants, refresh-rotation single-winner, tenant isolation). Tests are written
against the RFC/OIDC text, not against observed janux behavior; known
deviations are marked `xfail(strict=True)` with the precise gap so a fix
flips them loudly.

## Layout

```
harness/        janux test-server lifecycle, mock Resend (email interception),
                magic-link login, admin API, OIDC protocol primitives
tests_op/       discovery, JWKS, authorize errors, full code flow + token lifecycle
tests_scim/     RFC 7643/7644 surface: discovery documents, the
                unauthenticated 401, and the full user CRUD track driven
                by a real machine principal (client_credentials → scim
                scope): create/get/list/filter/pagination, PATCH
                add/replace/remove, case-insensitive userName,
                uniqueness, delete (G-124)
oidf/           driver + plan configs for the official OIDF suite
```

## Quickstart

```sh
cd auth/test/compliant
uv sync
uv run pytest                          # spawns janux (target/debug/janux) + mock Resend
uv run pytest tests_op/test_discovery.py -k "not authorize"   # subset
uv run pytest --janux-url http://127.0.0.1:18092 --janux-domain conf.local  # attach mode
```

The session fixture generates a janux config (temp data dir, free ports,
seeded tenant `conf-tenant` on domain `conf.local`, admin policies for the
test tenant) and points `resend.base_url` at an in-process mock Resend so
magic-link emails are intercepted — this is how the suite logs in black-box.

## How the login interception works

1. `POST /api/v1/auth/email/request` — janux sends the magic link to the
   mock Resend (`[seed.resend] base_url`).
2. The mock records the email; the harness extracts the link
   (`token`/`username`/`email` query params).
3. `POST /api/v1/auth/email/verify` with those params → session JWT.

The same trick services the OIDF suite's browser steps.

## Janux enablers — ALL LANDED (2026-09-08, gaps.md G-136)

The suite runs green end to end (60 tests, no skips/xfails) and is wired
into CI (`compliance-tests` job in `.github/workflows/ci.yml`):

1. **Rate-limit override** — landed: top-level `disable_rate_limits = true`
   (`JanuxConfig`) widens every per-IP quota (auth 6/min, OIDC public
   12/min, admin 12/min, SCIM 60/min) to absurdity while keeping hoop
   order and the 429 machinery intact. The generated test config sets it.
   TEST CONFIGS ONLY — never on a reachable host.
2. **Seed user emails** — landed (G-131): `UserDTO.email` vouches a
   VERIFIED credential at seed time, and `bootstrap_tenant` /
   `admin/tenant/create` accept `admin_email`. The generated config
   vouches the admin's address, so the black-box magic-link login works.
3. **Seed a signing key** — landed: `TenantDTO::save` creates one key per
   seeded domain (`seed-<domain>`), idempotent across restarts; the JWKS
   is populated from first boot.
4. **Discovery gap** — landed: `client_credentials` is advertised in
   `grant_types_supported`.

Harness fixes that landed with the unblock: `load_jwks` built the
`JWKSet` incorrectly (list passed where JWK objects are required — never
exercised while the suite was blocked); the magic-link claim assertions
expected `sub` to be the username (janux flattens `JwtData`, so the name
is the top-level `username` and `sub` is the UUID); the public-client
registration collided with the session fixture's redirect URI (the
`RedirectURI` keyspace is global across clients — gaps.md G-143, worked
around with a unique callback).

The OIDF driver under `oidf/` remains manual (external certification
against a live deployment — tracked as gaps.md G-124).

## Spec mapping

| Area | References |
|---|---|
| Discovery | OpenID Discovery 1.0 §3, RFC 8414 |
| Code flow / errors | RFC 6749 §4.1, OIDC Core §3.1 |
| PKCE | RFC 7636 |
| ID token validation | OIDC Core §3.1.3.7 |
| Refresh rotation | RFC 6749 §6 (+ janux single-winner design) |
| Revocation / introspection | RFC 7009, RFC 7662 |
| Device flow | RFC 8628 |
| Dynamic registration / logout | RFC 7591 (+7592 §4), RP-Initiated Logout 1.0, Back-Channel Logout 1.0 |
| SCIM | RFC 7643, RFC 7644 |
