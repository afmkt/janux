# janux + Caddy forward-auth, two deployment scenarios

Two self-contained `docker compose` projects that put janux in front of a
simple service and **gate that service with `forward_auth`** — one where the
auth server and the service sit behind a **single host**, and one where
auth, the service, and the front sit on **separate hostnames**. Each project
is a 3-container stack:

| service    | image           | role |
| ---------- | ------------ -- | ---- |
| `caddy`    | `caddy:latest` | public front; runs `forward_auth` for the gated path |
| `auth`     | janux (built here or pulled) | the auth server / forward-auth probe |
| `app`      | `nginx:alpine` | the "simple service" — serves one static file at `/app` |

```
examples/
  up.py                  # checks config exists (needs base.toml/seed.toml), maps hosts, runs either stack
  single-host/           # ONE hostname (localhost): auth + gated /app, same host
    compose.yml
    Caddyfile
    app-nginx.conf       # nginx `location /app/` -> aliased static file
    base.example.toml    # template -> base.toml (gitignored), `cp` once by hand
    seed.example.toml    # -> seed.toml (gitignored; put real creds in the copy)
    site/index.html      # the protected static file
  split-hosts/           # TWO hostnames: auth.example.com + app.example.com
                         (same files, app-nginx.conf + seed keyed to app.example.com)
```

## The one hard constraint: TLS is mandatory

janux's session cookie is **`Secure`** and, by default, **host-only** (no
`Domain` attribute). It *can* carry a `Domain=` via a new tenant-scoped
`session.cookie_scope` (sub-domain SSO, feature #1 below), but that scope
defaults **unset**, and even then the two facts below make plain HTTP
non-viable for a **gated browser page**:

- **`Secure`** means the cookie is *transmitted only over an https origin*.
  Over http the browser never sends it, so the forward-auth probe is always
  unauthenticated.
- **Caddy auto-redirects http -> https on `localhost`** (localhost is a
  browser secure-context), so even `CADDY_TLS=off` bounces `:80` -> `:443`.

So TLS is on by default (`CADDY_TLS` env, value `tls internal` = Caddy's
local CA). On **Linux** open `https://127.0.0.1/app` (the self-signed cert
warns once but works); on **macOS** trust Caddy's CA once:
`./up.py <setup> trust-ca`.

## Scenario 1 — single-host (recommended)

**`localhost` fronts both janux's whole surface and a gated `/app`.** This is
the layout janux's host-only cookie supports cleanly: the cookie is set on
`localhost` and sent back to `localhost`, so a browser authenticates and the
gate opens. No `cookie_scope` is needed.

```
browser ─► caddy:80
           /app   ─┐
                   ├─► janux /api/v1/auth/verify   (forward_auth probe)
           /login ─┘       ├─ 2xx   ─► nginx serves site/index.html
                   └────────┴─ 303/401 -> /login (see below)
           /              ─► janux   (discovery, OIDC, admin UI, SCIM, health)
```

Run it:

```sh
cd examples
./up.py single-host up             # needs base.toml/seed.toml; up (detached)
open  https://localhost/app        # macOS;  https://127.0.0.1/app on Linux
```

The first visit to `/app` bounces to `/login`, you authenticate (magic link),
and `/app` opens. `docker compose -f single-host/compose.yml logs` tails; `./up.py single-host down` tears it down.

## Scenario 2 — split-hosts (sub-domain SSO via a Domain-scoped cookie)

`auth.example.com` fronts janux's IdP/admin/discovery host; `app.example.com`
fronts the gated `/app` (+ full UI). Both are reachable from the client, both
point at the **same** janux. `up.py` maps both names to `127.0.0.1` and
trusts the CA.

```sh
./up.py split-hosts up
./up.py split-hosts trust-ca       # macOS only
open  https://app.example.com/app
```

The `/app` gate on `app.example.com` now authenticates a browser end-to-end
because the seed sets `cookie_scope = "example.com"` on **both** domains
(see #1). janux writes `Set-Cookie: januxSession; Domain=example.com`, so the
browser treats the two hostnames as one site and shares **one login**:

```
browser ─► https://app.example.com/app
             │  unauthenticated → 303  https://auth.example.com/login
             │   (tenant-scoped redirect; #5)
             ▼
browser ─► https://auth.example.com/login   → authenticate (magic link)
             │  Set-Cookie januxSession Domain=example.com   (the #1 widening)
             ▼
browser ─► https://app.example.com/app      → cookie shared → 2xx → nginx
```

> **Why `cookie_scope` must be set.** janux's cookie is host-only *by default*
> (a session minted on `auth.example.com` is **not** sent to `app.example.com`).
> Both domains declaring the registrable `example.com` widens the cookie to
> `Domain=example.com`, the **only** change that makes cross-host browser SSO
> work. The scope is validated label-aligned (RFC 6265 §5.1.3 — **not** a
> substring) at seed time, so it can never accidentally reach a sibling
> registrable domain like `example.com.evil.com`.
>
> For a non-browser service that authenticates via a **JWT bearer token**
> (not a cookie), a Domain constraint does not exist: omit `cookie_scope` and
> split-hosts works as written.

## The two janux enhancements this example needs

### #1 — sub-domain SSO: a Domain-scoped session cookie (`session.cookie_scope`)

A per-domain, config-file-only `session.cookie_scope` (the same migration-free
pattern as `pages.<domain>`, `src/config.rs::SessionDTO`) widens the session
cookie to a registrable `Domain=`. janux **never infers** the scope from the
request — the operator declares it in the seed config, and janux only
*confirms*, at write time, that the host being served actually label-matches
the declared scope (`src/utils.rs::validate_cookie_scope`, an RFC 6265 §5.1.3
label-aligned match that rejects `example.com.evil.com` even though it
*contains* `example.com`). Logout and refresh re-use the scope, so the cleared
and rotated cookies carry the same `Domain=` — a `Domain=` clear that omits
`Domain=` would silently fail to delete from the jar.

### #5 — tenant-scoped forward-auth redirect (`forward_auth_redirect` + `session.redirect_url`)

When a forward-auth probe is **unauthenticated**, janux historically answered a
bare **`401` problem+json** — correct, but a user in a browser cannot act on a
`401`. A proxy *cannot* inject a `Location` into a response it merely copied,
so the redirect to the login page has to come from **janux itself**.

Two pieces were added (`src/server.rs`, `src/verify.rs`):

- `JanuxConfig.forward_auth_redirect` (opt-in, default `false`): when enabled,
  `verify` answers an unauthenticated **forwarded** request with **`303`**
  instead of `401`.
- `session.redirect_url` (#5): the `Location` janux emits is the request
  domain's configured **login origin**, with `/login` appended — an absolute
  target that works across hosts (`https://auth.example.com/login`). When
  unset it falls back to the bare relative `/login` (correct for single-host,
   where the proxy fronts janux's own `/login`).

Both fronts get the redirect:

- **Caddy** `forward_auth` simply *propagates* the 303 to the browser, which
  then authenticates and retries — the Caddyfile needs no `redir`.
- **nginx** `auth_request` sees the 303 too, so the same flag serves both
  fronts. Direct (non-forwarded) callers always see the historical `401`.

It is enabled in every `base.example.toml`:

```toml
trust_forwarded_headers = true           # janux trusts Caddy's X-Forwarded-*
trusted_proxies = ["172.28.0.0/16"]     # only the caddy bridge source may supply them
forward_auth_redirect = true             # 303 -> <login origin>/login on an unauth probe
```

With the flag **off**, janux answers a bare 401 — still a valid "denied"
result (the gate blocks the request, just without the browser bounce). Unit
tests pin both branches and the widening:
`verify::tests::forward_auth_unauth_redirects_or_401` and
`verify::tests::session_cookie_domain_scope`.

`split-hosts/seed.example.toml` demonstrates the coupled use — the auth host
sets `cookie_scope` so the post-login cookie is shared, and the app host
points `redirect_url` at the auth host so a bounced `/app` lands on the login
UI:

```toml
domains = [
            { id = "app.example.com",  cors = [], cookie_scope = "example.com",
                redirect_url = "https://auth.example.com" },
            { id = "auth.example.com", cors = [], cookie_scope = "example.com" },
            { id = "0.0.0.0", cors = [] }
          ]
```

## Conflicts found during design, and how they are resolved

| # | Conflict | Resolution |
| - | -------- | ---------- |
| 1 | `Secure` + host-only cookie cannot cross to a second origin | now solved: `session.cookie_scope` widens the cookie to `Domain=example.com`, sharing one login across subdomains (RFC 6265 §5.1.3 label match); single-host stays the host-only path |
| 2 | Caddy auto-https on `localhost` blocks plain HTTP | TLS is mandatory; `CADDY_TLS` env (value `tls internal`); Linux uses `https://127.0.0.1` |
| 3 | Caddy `global { tls internal }` breaks `handle` parsing in v2.11.4 | TLS is driven by the **`CADDY_TLS` env var only**; no TLS directive in the Caddyfile |
| 4 | In Caddy v2.11.4, a bare `forward_auth { … }; handle { reverse_proxy }` at the top of a site fails to parse (`unrecognized directive: handle`); a `global { tls … }` block *also* breaks `handle` | structure everything under `handle @appName { forward_auth { uri }; reverse_proxy app:80 }`; drive TLS only through the `CADDY_TLS` env, never a Caddyfile `tls` directive |
| 5 | A 401 answer gives a browser nothing to act on | janux `forward_auth_redirect` (303 -> `<redirect_url>`/login), above; `session.redirect_url` makes it host-independent |
| 6 | nginx would double-process the path if Caddy stripped `/app` | Caddy does **not** strip; nginx `alias /app/` -> static root; `location = /app` -> 301 `/app/` |
| 7 | janux runs **default-deny**: an unlisted resource 401s for everyone | `seed.toml` seeds an exact-match RBAC row for `resource = "/app"` for `user`/`admin`/`root` (G-43, no wildcards) |
| 8 | G-149: `trust_forwarded_headers = true` warns unless `trusted_proxies` is set | the fixed bridge subnet pins caddy's source (`172.28.0.0/16` / `172.29.0.0/16`), closing the tenant-spoof / limiter-bypass hole |
| 9 | Both setups publish `:80/:443` | run **one at a time**; per-setup named volumes (`single_*` / `split_*`) keep their data separate |
| 10 | janux config is **TOML-only** (`Environment` has no `JANUX__SERVER__…`) | `trust_forwarded_headers`, `trusted_proxies`, `forward_auth_redirect` live in `base.toml [server]`, not env vars |
| 11 | a `Domain=` cookie clear must re-carry `Domain=` or it silently no-ops | logout/refresh read the same `session.cookie_scope` and re-emit it; `utils::tests::cookie_scope_label_matching` pins the validator |

## Files

- **`up.py`** — ensures the git-ignored `base.toml` / `seed.toml` exist
  (create them from the committed `*.example.toml` templates by hand with `cp` on
   first run — it NEVER renders or clobbers them, so the creds you put in
   `seed.toml` survive every `up`), sets `CADDY_TLS`, maps split-hosts into
   `/etc/hosts`, and runs compose.
- **`single-host/`**, **`split-hosts/`** — see the tree above; each is a
  standalone `docker compose` project.
- **`site/index.html`** — the protected static file (self-contained: no
  sub-resources, so only the single `/app` resource needs an RBAC row).

## Manual run (without `up.py`)

```sh
cd examples/single-host
cp base.example.toml base.toml; cp seed.example.toml seed.toml
#   then edit base.toml's encryption_key (openssl rand -hex 32) and
#   seed.toml's [seed.resend] creds + the admin email.
CADDY_TLS="tls internal" docker compose up -d --build
# open https://localhost/app
```
