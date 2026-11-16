# janux + Caddy forward-auth — a single-host example

One self-contained `docker compose` project that puts janux in front of a
simple service and **gates that service with `forward_auth`**. The auth server
and the service sit behind a **single host** (`localhost`) — the only layout
janux's host-only `Secure` session cookie supports cleanly, because the browser
only re-sends the cookie to the host that set it.

The stack is fully **self-contained**: the magic-link email is delivered to a
local [Mailpit](https://github.com/axllent/mailpit) inbox instead of a real
mailbox or SaaS, so you can try the whole sign-in flow with no credentials.

| service    | image             | role |
| ---------- | ----------------- | ---- |
| `caddy`    | `caddy:latest`    | public front; runs `forward_auth` for the gated path |
| `auth`     | janux            | the auth server / forward-auth probe |
| `app`      | `nginx:alpine`    | the "simple service" — serves one static file at `/app` |
| `mailpit`  | `axllent/mailpit` | local SMTP sink + web inbox for the magic link (no SaaS) |

```
examples/
  compose.yml          # the stack (name: janux)
  Caddyfile            # localhost front: /app gated, everything else -> janux
  app-nginx.conf       # nginx `location /app/` -> aliased static file
  janux.example.toml   # template -> janux.toml (gitignored); `cp` once by hand
  site/index.html      # the protected static file
```

## Request flow

```
/api/v1/auth/verify -> janux     (public — Caddy POSTs the auth probe here)
/app                 -> forward_auth janux verify -> nginx (gated)
/   (everything else) -> janux   (discovery, OIDC, admin UI, SCIM, health, /login)
```

On an unauthenticated probe janux answers `303 -> /login` (`forward_auth_redirect
= true` in `janux.toml`); Caddy propagates that to the browser, which authenticates
at `/login`, gets its host-only cookie, and retries `/app`.

## Quickstart

```sh
cd examples
cp janux.example.toml janux.toml
#   edit janux.toml's encryption_key:  openssl rand -hex 32
docker compose up -d
# open https://localhost/app
```

`janux.toml` is gitignored (it holds per-run secrets), so copy the committed
`janux.example.toml` template by hand on first run. The stack uses the
local Mailpit relay by default, so no mail credentials are needed.

## First time on macOS

Caddy signs `localhost` with its local CA (`tls internal`). The browser shows a
certificate warning on the first load. Two options:

- **Quick:** click through the warning once; the `Secure` session cookie still
  works over untrusted HTTPS, and the warning won't reappear for the session.
- **One-time clean:** extract Caddy's root CA and trust it, then reload:
  ```sh
  docker compose exec caddy caddy trust extract --output caddy-root.crt 2>/dev/null \
    || docker cp caddy:/data/caddy/pki/authorities/local/root.crt caddy-root.crt
  security add-trusted-cert -r trustRoot \
    -k ~/Library/Keychains/login.keychain-db caddy-root.crt
  ```

On Linux, `localhost` is a secure context already — just open `https://127.0.0.1/app`.

## Sign in (magic link)

1. Open the Mailpit inbox at <http://localhost:8025> in one tab and
   <https://localhost/app> in another.
2. `/app` won't load — it bounces you to `https://localhost/login`.
3. On the login page, enter `tester@example.com` (a seeded `user`) and request
   the link. `admin@example.com` and `root@example.com` work too.
4. In the Mailpit tab, a **"Janux login"** email appears; click the link.
5. The link auto-completes sign-in and sets your session. Back to the `/app`
   tab, reload — you'll see **"Protected content ✓"**.

## Serve the latest frontend without rebuilding the image

The `localhost` domain's UI is served from a **bind-mounted** copy of the built
frontend instead of the image-baked one (`../frontend/dist` → `/app/pages-override`,
mounted in `compose.yml` and pointed at by `pages_dir` in `janux.toml`). janux
reads that directory **per request**, so after editing `../frontend/src/*`:

```sh
cd ../frontend && npm run build   # regenerates ../frontend/dist
```

…the running stack serves the new build with **no image rebuild and no restart**.
(HTML entry pages carry `Cache-Control: no-cache` so a plain reload picks up the
new content-hashed bundles.) Remove the `../frontend/dist` volume in
`compose.yml` and the `pages_dir` in `janux.toml` to revert to the embedded UI.

## Tearing down

```sh
docker compose down            # stop, keep named volumes (CA + data persist)
docker compose down -v         # also wipe the named volumes (fresh start)
```

## Writing policies (RBAC authoring)

RBAC is **default-deny**: anything not granted is rejected. Built-in
admin/scim/tenant/user endpoints are guarded in code (role membership) and need
no policy rows; only tenant-defined resources — like the `/app` forward-auth path
here — use the policy engine. Paths match **exactly** (G-43, no wildcards).

#### Scenario 1 (simplest) — domain + role

Omit `resource`: it defaults to `""`, which matches **any** path in the domain,
so a single row full-grants one role the whole tenant.

```toml
{ domain = "localhost", role = "user" },
{ domain = "localhost", role = "admin" },
{ domain = "localhost", role = "root" },
```

#### Scenario 2 (the workhorse — what gates `/app`) — domain + resource + role

Gate **one exact path per role**. Grant the real path the forward-auth proxy
hits — `/app`, no trailing slash. Every other field defaults: all methods;
`source`/`target` = `Nothing`; `mfa` = `false`; `allowed` = `true`.

```toml
{ domain = "localhost", resource = "/app", role = "user" },
{ domain = "localhost", resource = "/app", role = "admin" },
{ domain = "localhost", resource = "/app", role = "root" },
```

#### Scenario 3 (advanced) — domain + resource + role + source + target

`source`/`target` make a grant **conditional** on *who* the caller is and *what*
they ask for:

- `source` is an identity read from **the caller** (JWT/session): `Nothing`,
  `User` (`jwt.user`), `Domain` (`jwt.domain`), or `Role`.
- `target` is an identity read from **the request**: `Nothing`,
  `FromPath{n}`, `FromQuery{n}`, or `FromHeader{n}`.

The engine grants **iff the two agree** (both absent, or both present and equal)
— *not* "missing is fine". `source = User` + `target = FromPath /app/{owner}`
collapses access to "you may only reach **your own** thing": `alice` reaches
`/app/alice`, but `/app/bob` is denied. `mfa = true` adds a TOTP step-up gate.

```toml
{ domain = "localhost", resource = "/app/{owner}", role = "user",
  source = "User", target = { FromPath = { pname = "owner" } }, mfa = true, allowed = true },
```
