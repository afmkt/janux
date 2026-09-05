# Frontend architecture & per-domain page overrides

## How the built-in frontend is served

The SPA in `frontend/` is built with Vite (`npm run build` → `frontend/dist`)
and embedded into the binary at compile time (`src/pages.rs`, rust-embed).
The server routes:

| Route | Asset |
|---|---|
| `/login`, `/signup` | `login.html` |
| `/consent` | `consent.html` |
| `/device-login` | `device.html` |
| `/admin` | `admin.html` |
| everything else (GET) | `frontend/dist` catch-all (JS/CSS bundles) |

Pages are behavior-driven by **OIDC discovery**: on load, the SPA fetches
`/.well-known/openid-configuration` and renders exactly the factors the
document advertises.

### Tier-A discovery (`janux_provisioned`)

Discovery always answers when the request carries a usable host:

- **Registered domain** → full document: `janux_provisioned: true`,
  `janux_factors` (email / otp / social / passkey), `acr_values_supported`,
  optional `registration_endpoint`.
- **Unprovisioned host** → skeleton: issuer and endpoint URLs derived from
  the request, `janux_provisioned: false`, **no factors**. The login page
  renders a "not provisioned" notice instead of a dead form. No tenant
  state is exposed and no token can ever be minted for such a host — the
  ceremony endpoints still require a registered tenant.

This makes a fresh deployment self-explanatory: pointing a new domain at
the server no longer produces an opaque `Discovery failed (404)`.

## Per-domain page overrides

Operators can replace any subset of the built-in pages per domain —
branding, copy, or entire flows.

### Workflow

```sh
# 1. Dump the embedded frontend as a scaffold (server does NOT start).
#    Writes every embedded asset plus a .janux-version marker.
janux dump-frontend ./data/pages/auth.example.com
#    (in docker: docker compose exec auth janux dump-frontend /app/data/pages/auth.example.com)

# 2. Prune: delete everything you do NOT want to override.
#    Serving is per-file — missing files fall back to the embedded asset.
#    For a branding-only change, keep just login.html (+ your CSS).
rm -rf ./data/pages/auth.example.com/assets  # example

# 3. Edit what you kept.

# 4. Point the domain at the dir in the seed config and restart:
#    domains = [{ id = "auth.example.com", cors = [], pages_dir = "./data/pages/auth.example.com" }]
```

`pages_dir` is persisted in the tenant Config store (`pages.<domain>`) at
seed time and cached at boot; there is deliberately **no API** for it.
Whoever can edit the config file already holds the encryption keys, so
overrides are an operator act — no new privilege boundary, no upload
endpoint.

**Disabling an override is declarative**: remove `pages_dir` from the
domain's seed entry and restart — seeding deletes the stale Config-store
binding. Deleting a domain (`admin/domain/delete`) drops the binding too,
so re-registering the domain later never resurrects an old override dir.

### Resolution order (per file, per request)

1. Request host → registered tenant domain (same trusted host chain as
   every other endpoint; unregistered hosts never reach a disk dir).
2. Domain has `pages_dir` and the confined path exists on disk → serve it.
3. Otherwise → serve the embedded asset.
4. Neither → 404.

Both tiers carry an `ETag` (sha256 for embedded assets, mtime+size for
disk overrides) and answer `If-None-Match` with `304 Not Modified`, so
revisits revalidate instead of re-transferring bundles. Edits to a disk
override are picked up on the next request (no restart needed); the boot
cache only holds the dir *binding*, not file contents.

### Path confinement

The URL path is untrusted network input joined onto an operator-configured
root, so it is percent-decoded first, any `..` segment rejects the lookup,
and the result is verified to stay under the canonicalized root
(`pages::confine`). A traversal attempt simply falls through to the
embedded tier.

### Version drift

The dump stamps `.janux-version` into the scaffold. At boot janux warns
when a configured dir was dumped by a different version (or carries no
marker), because the embedded fallback assets your pruned dir mixes with
may have moved on — most visibly through hashed bundle filenames
(`assets/login-abc123.js`) that a hand-edited HTML file may still
reference. To refresh: dump into a **new** dir with the new binary and
re-apply your edits; janux never silently overwrites a scaffold in place
at boot.

## Developing a frontend from scratch

Anything that honors the server contract is a valid override — including a
completely rewritten login flow. The contract:

1. **Bootstrap**: `GET /.well-known/openid-configuration`.
   - `janux_provisioned: false` → show a "not set up" state, stop.
   - `janux_factors` → which factors are enabled and where their endpoints
     live. Presence of a key means enabled; `identifier` says which extra
     input the factor needs (`"email"`, `"mobile"`, or `null` for
     username-only).
2. **Ceremonies** (all `POST`, JSON; success carries a session `jwt`):
   - Email magic link: `request` `{name, email, client_id?, state?, redirect_uri?}`
     → user clicks the link → `verify` `{token, name, email}`.
   - SMS OTP: `request` `{name, mobile}` → returns a ceremony `jwt` →
     `verify` `{token, name, mobile, code}`.
   - Passkey: `request`/`verify` per WebAuthn (see
     `frontend/src/login/webauthn.ts` for the exact ceremony).
   - Social: redirect the browser to the provider's `request` URL,
     carrying `client_id`/`state`/`redirect_uri` through; the callback
     lands with `?code=` → `POST /api/v1/auth/social/redeem` `{code}`.
3. **Session**: store the session JWT (see `frontend/src/shared/session.ts`)
   and use it as `Authorization: Bearer` for the OIDC resume/consent APIs.
4. **OIDC resume**: after login, `GET/POST /authorize/resume` continues a
   parked authorization-code flow; `/consent/info` + `POST /consent` drive
   the consent screen; `/device-login/info` + `/device-login/approve`
   drive the device flow.

The full API surface is documented at `/api/v1/doc/scalar` (OpenAPI JSON
at `/api/v1/doc/openapi.json`, regenerated with `just openapi`).

### Local development

```sh
just dev        # vite dev server with HMR (backend must be running)
just build      # npm run build + cargo build (dist is embedded at compile time)
```

Note: the binary embeds `frontend/dist` **at compile time** — after
changing frontend sources, rebuild the Rust binary (or re-dump overrides)
for the server to pick them up.
