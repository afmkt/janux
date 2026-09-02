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
tests_scim/     RFC 7643/7644 surface
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

## Janux enablers (changes needed server-side)

The suite is built to light up as these land:

1. **Rate-limit override** — `/api/v1/auth/*` (6/min), OIDC public endpoints
   (12/min) and admin (12/min) are hardcoded per-IP (`router.rs`); any
   conformance run exhausts them in seconds. Needs a config knob used by the
   generated test config. Until then, flow tests 429 intermittently.
2. **Seed user emails** — seeded users get no email credential
   (`UserDTO {id, active, roles}`), so the seeded admin cannot log in
   black-box and OAuth2 clients cannot be registered via the admin API.
   Tests depending on it skip with this reason. Add `emails: Vec<String>`
   to `UserDTO` (attach at seed time).
3. **Seed a signing key** — seeded tenants have an empty JWKS (keys are
   created only via the admin-gated `key/create`), so no ID token can be
   signed until an admin acts. The seed should create one key per seeded
   domain. Tracked as a strict xfail in `tests_op/test_jwks.py`.
4. **Discovery gap** — `client_credentials` is implemented at `/token` but
   absent from `grant_types_supported` (`oidc.rs` `well_known`); tracked as
   a strict xfail in `tests_op/test_discovery.py`.

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
