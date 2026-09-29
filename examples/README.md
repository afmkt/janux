# janux + Caddy forward-auth, two deployment scenarios

Two self-contained `docker compose` projects that put janux in front of a
simple service and **gate that service with `forward_auth`** — one where the
auth server and the service sit behind a **single host**, and one where
auth, the service, and the front sit on **separate hostnames**. Each project
is a 3-container stack:

| service    | image          | role |
| ---------- | -------------- | ---- |
| `caddy`    | `caddy:latest` | public front; runs `forward_auth` for the gated path |
| `auth`     | janux | the auth server / forward-auth probe |
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

## How to write policies


#### Scenario 1 (simplest) — domain + role

Omit `resource`: it defaults to `""`, which matches **any** path in the domain,
so a single row full-grants one role the whole tenant. Handy as a broad allow,
or to gate an entire domain per role in a few lines.

```toml
{ domain = "localhost", role = "user" },
{ domain = "localhost", role = "admin" },
{ domain = "localhost", role = "root" },
```

#### Scenario 2 (the workhorse — what forwards `/app`) — domain + resource + role

Gate **one exact path per role** on the default-deny engine. Paths match
**exactly** (G-43, no wildcards), so grant the real path the forward-auth proxy
hits — `/app`, no trailing slash. Every other field defaults: all methods;
`source`/`target` = `Nothing` (the grant is purely "this role may reach this
resource"); `mfa` = `false`; `allowed` = `true`.

```toml
{ domain = "localhost", resource = "/app1", role = "user" },
{ domain = "localhost", resource = "/app2", role = "admin" },
{ domain = "localhost", resource = "/app3", role = "root" },
```

#### Scenario 3 (advanced) — domain + resource + role + source + target

`source`/`target` only make a grant **conditional** on *who* the caller is and
*what* they ask for. With both `Nothing` (Scenario 2) the row is a plain "this
role may reach this resource" and the engine never looks at the caller. Turn them
on and the engine resolves two identities and permits **only when they agree**.

**What each side means** —

- `source` is an identity read from **the caller** (its JWT / session):
  - `Nothing` — no caller-side identity to compare
  - `User` — the caller's username (`jwt.user`)
  - `Domain` — the caller's home tenant (`jwt.domain`)
  - `Role` — this row's own role id (the grant's role)
- `target` is an identity read from **the request** the caller is making, i.e.
  "which object are they asking for":
  - `Nothing` — no request-side identity to compare
  - `FromPath{n}` — the `{n}` path segment of the resource, e.g. `/app/{owner}`
  - `FromQuery{n}` — the `?n=...` query parameter
  - `FromHeader{n}` — a request header named `n` (looked up lower-cased)

In TOML the target variants look like:

```toml
{ domain = "app.example.com", resource = "/app1/{owner}", role = "user", source = "User", target = { FromPath = { pname = "owner" } }, mfa = true, allowed = true },
{ domain = "app.example.com", resource = "/app2", role = "user", source = "User", target = { FromQuery = { qname = "owner" } }, mfa = true, allowed = true },
{ domain = "app.example.com", resource = "/app3", role = "user", source = "User", target = { FromHeader = { hname = "x-tenant-id" } }, mfa = true, allowed = true },

```

**How the engine uses them** (`Policy::can_access`, default-deny):

1. `domain` + `role` + **exact** resource must match first (G-43: exact, no
   wildcards).
2. It resolves `source` and `target`, each to an `Option<identity>`, then
   **grants iff the two agree** — both absent, or both present and equal. It is
   *not* "missing is fine": a `source` that does not equal the request's `target`
   yields no match, so default-deny wins and the request is rejected.
3. That "must be equal" **is** the self-scoping: bind `source` to the caller and
   `target` to the object they name, and access collapses to "you may only reach
   **your own** thing". `source = User` + `target = FromPath /app/{owner}` ⇒
   `alice` reaches `/app/alice`, but `/app/bob` is **denied** (source `"alice"`
   ≠ target `"bob"`).
4. `source = Domain` + `target = FromHeader{x-tenant-id}` is the cross-tenant
   case: reach the resource only when the caller's home tenant equals that header.
5. `mfa = true` adds a gate: even when `source == target`, the caller must have
   done a TOTP step-up first, else the engine asks for MFA re-auth, not allow.

Full example — a user may reach **only their own** `/app/{owner}`, behind TOTP:

```toml
{ domain = "localhost", resource = "/app/{owner}", role = "user", source = "User", target = { FromPath = { pname = "owner" } }, mfa = true, allowed = true },
```

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
