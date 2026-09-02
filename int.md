Here's a manual, step-by-step integration guide. It's designed so you do each step yourself and understand *why* — I give you the exact API shapes (reference facts from the code), not the implementation.

---

## Mental model first

Janux plays two roles at once:

1. **Auth server** — passwordless login flows (`/api/v1/auth/*`) that mint JWT sessions, plus a hosted login/consent UI (`/login`, `/consent`).
2. **OIDC provider (IdP)** — `/.well-known/openid-configuration`, `/authorize`, `/token`, `/userinfo`, JWKS. External services ("relying parties", RPs) redirect users here and receive tokens back.

Tenants are resolved from the request `Host` header. `seed.toml` bootstraps tenant `localhost` with domain `localhost`, users `admin`/`demo` (no credentials — first magic-link verify attaches the credential), and RBAC policies. The admin API is protected by those policies, so you need a real `admin` session JWT before you can register an OAuth2 client.

---

## Phase 1 — Run Janux standalone

1. `cd auth && just run` (builds the frontend into `frontend/dist`, then `cargo run`). Server binds `0.0.0.0:8080` (`base.toml`).
2. Before this works cleanly, fix two config gotchas:
   - `base.toml` has `trust_forwarded_headers = true` — that mode assumes a reverse proxy in front. Since you're hitting the server directly, create `auth/janux.toml` (gitignored, highest precedence — see `src/server.rs` config layering) with `trust_forwarded_headers = false`, and run `cargo run -- -c base -c seed -c janux` (or check `src/main.rs:48` for the exact flag handling).
   - `seed.toml` `[seed.resend] verify_url` is `http://localhost/api/v1/auth/email/landing` (port 80). Your server runs on 8080 — change it to `http://localhost:8080/api/v1/auth/email/landing` so magic links point at your running instance.
3. Verify discovery: `curl -s http://localhost:8080/.well-known/openid-configuration | jq`. The `issuer` must be `http://localhost:8080` (derived from Host, `src/utils.rs:312`). Note the `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`.
4. Verify JWKS: `curl -s http://localhost:8080/.well-known/jwks.json` — you should see an RSA key. That's what RPs use to verify tokens.

**Checkpoint:** discovery + JWKS respond, issuer matches the URL you'll use in the browser.

---

## Phase 2 — Get an admin session via magic link

1. Request a magic link for the seeded admin:
   ```sh
   curl -X POST http://localhost:8080/api/v1/auth/email/request \
     -H 'Content-Type: application/json' \
     -d '{"name":"admin","email":"<your real inbox>"}'
   ```
   (`ReqRequest` shape: `src/email.rs:126`. The seed has a live Resend key, so a real email arrives.)
2. Open the email and click the link → hits `/api/v1/auth/email/landing` → verifies → this **attaches the email credential to user `admin`** and mints a session. Observe the response: a JWT and a `Set-Cookie`.
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

Create a new small service, e.g. `sample_rp/` — a single-file FastAPI app on port 3000 is ideal (the repo already standardizes on FastAPI/uv). Dependencies you'll need: `fastapi`, `uvicorn`, `httpx`, and a JWT library with JWKS support (e.g. `pyjwt[crypto]` + fetching JWKS yourself, or `authlib`). Write it yourself; here is the spec:

**Endpoint 1: `GET /login`** — start the flow.
- Generate a random `state` and a PKCE `code_verifier` (43–128 chars of `[A-Za-z0-9-._~]`); compute `code_challenge = BASE64URL(SHA256(code_verifier))` — no padding. Store both in a short-lived signed/encrypted cookie or server-side dict keyed by `state`.
- Respond `302` to `http://localhost:8080/authorize?response_type=code&client_id=sample-rp&redirect_uri=http://localhost:3000/callback&scope=openid profile email offline_access&state=<state>&code_challenge=<challenge>&code_challenge_method=S256`.

**What happens inside Janux while the user is away** (watch this in your browser's network tab — it's the whole point of the exercise): `/authorize` validates client_id + redirect_uri + PKCE, *parks* the request, and redirects to the hosted `/login?client_id=...` SPA → you sign in (magic link again, or the now-attached email factor) → the SPA calls `/authorize/resume` with your session JWT → first time, the consent page (`/consent`) appears → approve → Janux `302`s back to your `redirect_uri` with `?code=...&state=...`.

**Endpoint 2: `GET /callback`** — exchange the code.
- Verify `state` matches what you stored (reject otherwise — this is CSRF protection).
- `POST http://localhost:8080/token` **form-encoded** (`TokenRequest`, `src/oidc.rs:1547`): `grant_type=authorization_code`, `code`, `redirect_uri` (must be byte-identical to the one in `/authorize`), `client_id`, `client_secret`, `code_verifier`.
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

Once the loop works standalone, containerize: Dockerfile for `auth/` (multi-stage: node build frontend → cargo build → slim runtime with `data/` volume), `auth/compose.yml`, add to root `compose.yml`, and route it through caddy using the reserved block at `caddy/Caddyfile:5` (e.g. `auth.sparkpos.cn`). Then flip `trust_forwarded_headers` back to `true` (now it genuinely sits behind caddy), update `verify_url`/redirect URIs to the public hostnames, and re-register the client's `redirect_uri` for the RP's public URL. Note G-87: ceremony state is process-local, so keep janux to one instance.

---

Two warnings for the road: rate limits are tight for manual testing (6/min on `/api/v1/auth/*`, 12/min on protocol endpoints — `src/router.rs:71`, `src/router.rs:360`), and everything you need is also in `auth/frontend/openapi.json` if you want to browse the exact API schemas.


Hosted pages: `/login` (also `/signup`), `/admin`, `/consent`, `/device-login` (`auth/src/router.rs:50-54`). Assuming the server is on `http://localhost:8080`:

## 1. Sign in via `/login` (magic link)

1. Open `http://localhost:8080/login`.
2. Enter username `admin`, select the **Email** factor, type a real inbox you control, submit.
3. Open the inbox, click the magic link. It returns to the login page, auto-verifies, and shows "Signed in." — the session JWT is stored in `sessionStorage` (`auth/frontend/src/shared/session.ts`).
   - Prerequisite from the earlier guide: `verify_url` in `seed.toml` must point at the same host:port you're browsing, or the emailed link hits a dead port.
4. Repeat with username `demo` in a **different browser/profile** later — it exercises the same flow for a non-admin user.

## 2. Sign in via SMS OTP (optional)

Same page, **SMS** factor: username + mobile number → enter the code that arrives (seed.toml has a live Aliyun SMS config). Confirms the second factor end-to-end.

## 3. Admin UI at `/admin`

Open `/admin` **in the same tab** you signed in on — the session lives in per-tab `sessionStorage`; a fresh tab shows unauthorized. Signed in as `admin` (seeded with root+admin+user roles), walk the tabs:

| Tab | Operations to perform |
|---|---|
| Users | See `admin`/`demo`; create a new user; add a role to it; remove it; delete it |
| Roles | See builtin catalog (`root`=100, `admin`=80, `user`=40, `guest`=20); create a custom role with a level; note builtins can't be deleted |
| Policies | See the seeded allow-list; create a policy granting your custom role an endpoint; delete it |
| Domains | See `localhost`; add a domain, then delete it |
| OAuth2 clients | **Create your `sample-rp` client here** (client id, secret, redirect URIs, grant/response types, auth method, scopes) instead of the curl from Phase 3 |
| Signing keys | List/create. Do **not** delete the only key — it invalidates all outstanding tokens (G-97) |
| Tenants | Root-only: list/create/delete tenants |

## 4. RBAC negative checks (worth doing)

1. Open `/admin` in a fresh tab (no session) → every call should fail unauthorized.
2. Sign in as `demo` (role `user` only) and open `/admin` → lists load nothing/403; this demonstrates the default-deny `protect` gate in the UI.

## 5. Consent & device pages

`/consent` and `/device-login` can't be exercised standalone — they're only reached through a live `/authorize` (consent) or device-code grant (device-login). They light up automatically in Phase 4 of the integration guide: first OIDC login redirects you to `/consent`, and the device flow lands on `/device-login` to approve a user code.

Passkey note: the passkey button on `/login` only asserts existing credentials; enrollment requires an existing session (G-100), so expect it to fail for a brand-new user — that's known behavior, not a bug.