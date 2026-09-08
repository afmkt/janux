# Janux — Hands-on Integration Guide

A manual, step-by-step integration guide. It is designed so you do each step yourself and understand *why* — it gives the exact API shapes (reference facts from the code), not the implementation.

---

## Mental model first

Janux plays two roles at once:

1. **Auth server** — passwordless login flows (`/api/v1/auth/*`) that mint JWT sessions, plus a hosted login/consent UI (`/login`, `/consent`).
2. **OIDC provider (IdP)** — `/.well-known/openid-configuration`, `/authorize`, `/token`, `/userinfo`, JWKS. External services ("relying parties", RPs) redirect users here and receive tokens back.

Tenants are resolved from the request `Host` header. `seed.toml` bootstraps tenant `localhost` with domain `localhost`, users `admin`/`demo`, and RBAC policies. The admin's seed entry vouches an `email` — seeding attaches it as a VERIFIED credential on every boot (G-131), so set it to an inbox you control before first launch; a seeded user *without* an email has no credential and cannot sign in (strict signup refuses the pre-existing username — there is no attach-on-first-verify). The admin API is protected by those policies, so you need a real `admin` session JWT before you can register an OAuth2 client.

---

## Phase 1 — Run Janux standalone

1. `just run` (builds the frontend into `frontend/dist`, then `cargo run`). Server binds `0.0.0.0:8080` (`base.toml`).
2. One config gotcha to fix, one default to know:
   - `seed.toml` `[seed.resend] verify_url` is `http://localhost/login` (port 80) — the hosted login SPA that consumes the link's `token`/`username`/`email` query params (G-133). Your server runs on 8080 — change it to `http://localhost:8080/login` so magic links point at your running instance. Also set the admin's seed `email` to your real inbox if you haven't already (G-131).
   - `base.example.toml` ships `trust_forwarded_headers = false` — the safe standalone default (G-149): `X-Forwarded-*` headers are ignored and tenant resolution uses the raw `Host`, which is exactly right while you hit the server directly. Flip it to `true` only when every request traverses a reverse proxy that overwrites those headers (boot logs a loud warning while it is on).
3. Verify discovery: `curl -s http://localhost:8080/.well-known/openid-configuration | jq`. The `issuer` must be `http://localhost:8080` (derived from Host, `src/utils.rs:312`). Note the `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`.
4. Verify JWKS: `curl -s http://localhost:8080/.well-known/jwks.json` — you should see an RSA key. That's what RPs use to verify tokens.

**Checkpoint:** discovery + JWKS respond, issuer matches the URL you'll use in the browser.

---

## Phase 2 — Get an admin session via magic link

1. Request a magic link for the seeded admin, using the inbox vouched in `seed.toml`:
   ```sh
   curl -X POST http://localhost:8080/api/v1/auth/email/request \
     -H 'Content-Type: application/json' \
     -d '{"name":"admin","email":"<the vouched inbox>"}'
   ```
   (`ReqRequest` shape: `src/email.rs`. If your `seed.toml` configures a live mail provider, a real email arrives. Signin is strict: the credential must already be attached — the seed's `email` field did that, and "add the email, restart" is the repair path for a credential-less account. Later, admins can attach credentials to other users via `admin/user/attach_email`.)
2. Open the email and click the link → it lands on the hosted `/login` SPA with `token`/`username`/`email` in the query (G-133), which auto-verifies and establishes the session: the JWT lands in the canonical `janux.session` HttpOnly cookie (G-139) and in the response body for non-browser callers.
3. Save the JWT — it's your Bearer token for the admin API. Decode it (`jwt.io` or `jq` on the base64 parts) and look at the claims: `sub`, `iss`, `exp`, roles. This is the same token format RPs will later validate.

**Checkpoint:** `curl -H "Authorization: Bearer <jwt>" http://localhost:8080/api/v1/admin/oauth2client/list` returns 200 (proves RBAC `protect` + policy gate work).

---

## Phase 3 — Register the sample RP as an OAuth2 client

POST to `/api/v1/admin/oauth2client/create` with the admin Bearer token. Body shape (`NewOauth2Client`, `src/idp.rs:373` — all strings, `redirect_uris` space-separated):

```json
{
  "client_id": "sample-rp",
  "secret": "<generate something random>",
  "redirect_uris": "http://localhost:3000/callback",
  "grant_types": "authorization_code refresh_token",
  "response_types": "code",
  "token_endpoint_auth_method": "client_secret_post",
  "default_scopes": "openid profile email offline_access"
}
```

Understand each field against RFC 6749: `grant_types` is what `/token` will accept for this client; `token_endpoint_auth_method` decides how the client proves itself at `/token` (`client_secret_post` = secret in the form body, `client_secret_basic` = HTTP Basic); `redirect_uris` is the exact-match allow-list `/authorize` enforces (`src/oidc.rs:793`).

**Checkpoint:** the client shows up in `/api/v1/admin/oauth2client/list`.

---

## Phase 4 — Build the sample RP (this is the learning part)

Create a new small service, e.g. `sample_rp/` — a single-file FastAPI app on port 3000 is ideal. Dependencies you'll need: `fastapi`, `uvicorn`, `httpx`, and a JWT library with JWKS support (e.g. `pyjwt[crypto]` + fetching JWKS yourself, or `authlib`). Write it yourself; here is the spec:

**Endpoint 1: `GET /login`** — start the flow.
- Generate a random `state` and a PKCE `code_verifier` (43–128 chars of `[A-Za-z0-9-._~]`); compute `code_challenge = BASE64URL(SHA256(code_verifier))` — no padding. Store both in a short-lived signed/encrypted cookie or server-side dict keyed by `state`.
- Respond `302` to `http://localhost:8080/authorize?response_type=code&client_id=sample-rp&redirect_uri=http://localhost:3000/callback&scope=openid profile email offline_access&state=<state>&code_challenge=<challenge>&code_challenge_method=S256`.

**What happens inside Janux while the user is away** (watch this in your browser's network tab — it's the whole point of the exercise): `/authorize` validates client_id + redirect_uri + PKCE, *parks* the request, and redirects to the hosted `/login?client_id=...` SPA → you sign in (magic link again) → the SPA calls `/authorize/resume` with your session → first time, the consent page (`/consent`) appears → approve → Janux `302`s back to your `redirect_uri` with `?code=...&state=...`.

**Endpoint 2: `GET /callback`** — exchange the code.
- Verify `state` matches what you stored (reject otherwise — this is CSRF protection).
- `POST http://localhost:8080/token` **form-encoded** (`TokenRequest`, `src/oidc.rs`): `grant_type=authorization_code`, `code`, `redirect_uri` (must be byte-identical to the one in `/authorize`), `client_id`, `client_secret`, `code_verifier`. Optional `lifetime` (seconds, G-90): requested ACCESS-token lifetime, clamped into `[60, ceiling]` — ceiling 60 min for user access tokens, 90 days for `client_credentials`. A client may **shorten** its tokens, never lengthen them past policy; omitted → ceiling. ID tokens (15-min authentication assertions) and refresh-family windows (30 days) are unaffected. The ceremony `verify` endpoints accept the same parameter for the session JWT (ceiling 15 min), and social login takes it as a `lifetime` query param at initiation; shortened internal sessions keep their lifetime across `auth/refresh` rotation.
- The response is `TokenResponse`: `access_token`, `id_token` (because you asked for `openid`), `refresh_token` (because of `offline_access`), `expires_in`.
- Validate the `id_token` properly: fetch JWKS from `jwks_uri`, verify signature (**RS256**, `src/jwt.rs:114`), and check `iss` equals the issuer from discovery, `aud` equals your `client_id`, `exp` not passed. Then (or additionally) call `GET /userinfo` with `Authorization: Bearer <access_token>` to get claims.
- Set your own local session cookie and redirect to `/`.

**Endpoint 3: `GET /`** — show the signed-in user's claims, or a "Sign in" link.

**Checkpoint — run these negative tests too, they teach more than the happy path:**
1. Full loop works end-to-end; consent page appears only the first time (grants are stored, `AuthGrant`).
2. Tamper with `state` in the callback URL → your RP rejects.
3. Wrong `code_verifier` → `/token` returns an OAuth2 error.
4. Replay the same `code` twice → second exchange fails (codes are one-shot).
5. Use the access token on `/userinfo` → claims; use a garbage token → 401.
6. Use the `refresh_token` at `/token` with `grant_type=refresh_token` → new access token.

---

## Phase 5 — Optional: wire into the existing system

Once the loop works standalone, containerize: the `Dockerfile` (multi-stage: node build frontend → cargo build → slim runtime with `data/` volume), `compose.yml`, and route it through your reverse proxy (e.g. `auth.example.com`). Then flip `trust_forwarded_headers` back to `true` (now it genuinely sits behind the proxy), update `verify_url`/redirect URIs to the public hostnames, and re-register the client's `redirect_uri` for the RP's public URL. Note: ceremony state is process-local by design — it fails closed on loss, and only the revocation store is shared via `jwt.db` — so keep janux to one instance per data dir (DESIGN.md §6).

---

Two warnings for the road: rate limits are tight for manual testing (6/min on `/api/v1/auth/*`, 12/min on protocol endpoints — `src/router.rs:71`, `src/router.rs:360`), and everything you need is also in `frontend/openapi.json` if you want to browse the exact API schemas.


Hosted pages: `/login` (also `/signup`), `/admin`, `/consent`, `/device-login` (`src/router.rs:50-54`). Assuming the server is on `http://localhost:8080`:

## 1. Sign in via `/login` (magic link)

1. Open `http://localhost:8080/login`.
2. Enter username `admin`, select the **Email** factor, type a real inbox you control, submit.
3. Open the inbox, click the magic link. It returns to the login page, auto-verifies, and shows "Signed in." — the session JWT lands in the canonical `janux.session` **HttpOnly cookie** (G-139: no JS-readable token storage); `frontend/src/shared/session.ts` keeps only a non-sensitive per-tab presence marker.
   - Prerequisite from the earlier guide: `verify_url` in `seed.toml` must point at the same host:port you're browsing, or the emailed link hits a dead port.
4. Repeat with username `demo` in a **different browser/profile** later — it exercises the same flow for a non-admin user.

## 2. Sign in via SMS OTP (optional)

Same page, **SMS** factor: username + mobile number → enter the code that arrives (if your `seed.toml` configures an SMS provider). Confirms the second factor end-to-end.

## 3. Admin UI at `/admin`

Open `/admin` **in the same tab** you signed in on — the session cookie is browser-wide, but the admin UI gates its initial render on a per-tab presence marker, so a fresh tab bounces to the login page. Signed in as `admin` (seeded with root+admin+user roles), walk the tabs:

| Tab | Operations to perform |
|---|---|
| Users | See `admin`/`demo`; create a new user; add a role to it; remove it; delete it |
| Roles | See builtin catalog (`root`=100, `admin`=80, `user`=40, `guest`=20); create a custom role with a level; note builtins can't be deleted |
| Policies | See the seeded allow-list; create a policy granting your custom role an endpoint; delete it |
| Domains | See `localhost`; add a domain, then delete it |
| OAuth2 clients | **Create your `sample-rp` client here** (client id, secret, redirect URIs, grant/response types, auth method, scopes) instead of the curl from Phase 3 |
| Signing keys | List/create/retire/delete. Rotation lifecycle (G-97, fixed): create the replacement → **retire** the old key (stops signing; keeps verifying outstanding tokens and stays in the JWKS while they drain) → delete it after the drain. Guardrails: an active key refuses deletion, and a domain's last signable key refuses retirement |
| Tenants | Root-only: list/create/delete tenants |

## 4. RBAC negative checks (worth doing)

1. Open `/admin` in a fresh tab (no session) → every call should fail unauthorized.
2. Sign in as `demo` (role `user` only) and open `/admin` → lists load nothing/403; this demonstrates the default-deny `protect` gate in the UI.

## 5. Consent & device pages

`/consent` and `/device-login` can't be exercised standalone — they're only reached through a live `/authorize` (consent) or device-code grant (device-login). They light up automatically in Phase 4 of the integration guide: first OIDC login redirects you to `/consent`, and the device flow lands on `/device-login` to approve a user code.

Passkey note: the passkey button on `/login` only asserts existing credentials; enrollment requires an existing session (G-100), so expect it to fail for a brand-new user — that's known behavior, not a bug.