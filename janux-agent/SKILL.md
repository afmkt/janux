---
name: janux-deploy
description: >
  Operate Janux — a self-hosted passwordless OIDC provider. Covers initial
  deployment, adding domains and services, proposing RBAC policies, and
  verifying DNS setup.
compatibility: >
  Requires the janux binary and a reverse proxy (Caddy or nginx).
  For remote operations, requires SSH access.
---

# Janux Operations

## Mental model

Janux is a single process that handles authentication for one or more
tenants. Each tenant is identified by a hostname.

    Browser → Caddy (forward_auth) → janux /api/v1/auth/verify
                                        ↓
                              default-deny RBAC engine
                              (domain + resource + role → allow / deny)
                                        ↓
                              allow → Caddy → your service
                              deny  → 401 or 303 → /login

The two config files (`base.toml`, `seed.toml`) are the only filesystem
interface at bootstrap. After that, all operations go through the admin API.

For the configuration schema, RBAC model, and API endpoint reference
see **REF.md**.

---

## Inputs to establish

Before any op, the agent must have these. Ask the user or inspect the
environment.

| Input        | Where to get it                           |
|--------------|-------------------------------------------|
| `domain`     | tenant's hostname, e.g. `example.com`     |
| `janux_url`  | `https://<domain>` — the base URL of janux |
| `admin_jwt`  | a valid admin JWT for that tenant          |
| `proxy`      | `caddy` or `nginx`                        |
| `backend`    | address of the service being protected     |
| `config_dir` | path to `base.toml` / `seed.toml` (bootstrap ops only) |

To obtain `admin_jwt`: open the janux login page, sign in as the
bootstrap admin, capture the session JWT from the browser. For scripted
ops, use the magic-link flow: send an email to the admin's seeded
`email` and extract the token from `verify_url`.

---

## Op 1 — Initial deployment

### Gather inputs

- `domain`
- `backend` (the service to protect)
- auth factor and provider credentials
  (`resend_key` for email, or `api_key`/`api_secret` for SMS)
- `admin_email` (the bootstrap operator's inbox)
- `tls`: `internal` (dev, Caddy local CA) or `acme` (prod, Let's Encrypt)

### Generate the encryption key

    ENCRYPTION_KEY=$(openssl rand -hex 32)

This secret encrypts all at-rest secrets in the data dir. Store it with
the same care as a DB password — it is unrecoverable if lost, and
leaked means every signing key is exposed.

### Author base.toml

See REF.md for the full schema. Minimum:

    data_dir = "./data"
    encryption_key = "<ENCRYPTION_KEY>"
     # if behind a proxy:
    trust_forwarded_headers = true
    trusted_proxies = ["<proxy-subnet-CIDR>"]
    forward_auth_redirect = true


      [bind]
    address = "0.0.0.0"
    port = 8080

### Author seed.toml

One `[[seed]]` block. See REF.md for full schema. Minimum:

    [[seed]]
    name = "<domain>"
    domains = [{ id = "<domain>", cors = [] }]
    roles = ["root", "admin", "scim", "user", "guest"]
    users = [
      { name = "admin", roles = ["admin"],
        active = true, email = "<admin_email>" },
    ]
    policies = []   # add per Op 3

    [seed.resend]   # or [seed.alisms] for SMS
    from = "no-reply@<domain>"
    resend_key = "<RESEND_KEY>"
    verify_url = "https://<domain>/login"

### Deploy

**Docker** (local or remote):

    cd <config_dir>/..
    docker compose up -d --build

    Use the compose.yml / Caddyfile from janux/examples/single-host/
    as a starting point. Change:
    - the janux image source: `build:` context to `janux/Dockerfile`
      or `ghcr.io/afmkt/janux:latest`
    - the `backend` service to the user's actual service
    - `trusted_proxies` to match the compose bridge subnet (check
      `docker network ls` or the subnet in compose.yml)

**Systemd (remote, via SSH)**:

    ssh user@host "
      mkdir -p /etc/janux /var/lib/janux
      cat > /etc/janux/base.toml << 'EOF'
      <base.toml contents>
      EOF
      cat > /etc/janux/seed.toml << 'EOF'
      <seed.toml contents>
      EOF
      janux -c /etc/janux/base -c /etc/janux/seed &
     "

    Then install a systemd unit with `ExecStart=janux -c ... base \
    -c .../seed` and `systemctl enable --now janux`.

### Verify

    curl -fsS https://<domain>/api/v1/health/ready

    Expect a 200. A 503 means the data dir is empty or the server didn't
    start — check the container or systemd logs.

    Then open `https://<domain>/login`, sign in with the admin magic
    link, and confirm the admin console loads.

---

## Op 2 — Add a new domain to an existing tenant

Adds a second hostname to the same tenant (same users, same policies).

### 1. Create the domain in janux

    POST {janux_url}/api/v1/admin/domain/create
    Authorization: Bearer {admin_jwt}
    Content-Type: application/json

    { "tenant": "<tenant-name>", "domain": "<new-domain>" }

### 2. Add the domain to the proxy

**Caddy**: add a second site address to the site block:

    <existing-domain> <new-domain> {
      # existing block contents
      tls internal   # or acme for prod
       ...
     }

Reload Caddy: `docker compose exec caddy caddy reload` or
`systemctl reload caddy`.

**nginx**: add a new `server` block listening on 443, with a new
`location /` that does `auth_request` to janux's verify endpoint.

### 3. Configure DNS (see Op 5)

### 4. Restart janux if seed.toml drives this tenant

Janux reloads `seed.toml` on restart (idempotent upsert). Restart the
janux process if the domain was added to `seed.toml` rather than via
the admin API.

---

## Op 3 — Protect a new service

Adds a new backend path to an already-running janux deployment.

### Inputs

- `domain`: the tenant domain (from Op 1 context)
- `resource`: the path to gate, e.g. `/api` or `/dashboard`
- `role`: who can access it (`user`, `admin`, `scim`, or a custom role)
- `backend`: the service's network address reachable from janux's proxy

### 1. Add the RBAC policy

    POST {janux_url}/api/v1/admin/policy/create
    Authorization: Bearer {admin_jwt}
    Content-Type: application/json

    {
      "domain": "<domain>",
      "resource": "<resource>",
      "role": "<role>",
      "allowed": true
    }

See Op 4 for advanced policy authoring (self-scoping, MFA,
method-specific grants).

### 2. Wire the route in the proxy

**Caddy**: add a `handle` block that forwards to the backend and
gates it with forward_auth to janux:

    @<path> path <resource>
    handle @<path> {
      forward_auth <janux-host>:8080 {
        uri /api/v1/auth/verify
      }
      reverse_proxy <backend>
    }

**nginx**: add a `location` with `auth_request` pointing at janux's
verify endpoint, then proxy the original request to `<backend>`.

### 3. Verify

    curl -s -o /dev/null -w "%{http_code}" https://<domain><resource>
    # Expect 401 (redirect) when unauthenticated
    # with a valid session cookie, expect 200

---

## Op 4 — Propose an RBAC policy

The agent examines a service URL pattern and proposes the correct
janux policy row(s). This is the highest-value op — it's where the
agent's domain knowledge matters.

### Step 1 — Parse the URL pattern

Break the URL into `domain` + `path`. Identify any `{var}` placeholder.

    example.com/api/users/{id}   → resource="/api/users/{id}",
                                    path_var="id" at segment 3
    example.com/orders?owner=alice → resource="/orders", query_var="owner"
    example.com/dashboard          → resource="/dashboard" (no var)

Paths match **exactly** (segment-by-segment; `{x}` is a wildcard segment).
No glob wildcards. A partial match is a deny.

### Step 2 — Classify the intent

Ask the user or infer from the URL pattern. The table maps URL shapes
to the RBAC scenario from REF.md.

| Intent                              | Scenario | source   | target           |
|-------------------------------------|----------|----------|------------------|
| "any user can reach this page"      | S1/S2    | Nothing  | Nothing          |
| "user X only accesses their own Y"  | S3       | User     | FromPath{pname}  |
| "user X only for their ?owner=Y"    | S3       | User     | FromQuery{qname} |
| "user X only for their X-Tenant=Y"  | S3       | User     | FromHeader{hname}|
| "admins write, all users read"      | S2×2     | Nothing  | Nothing          |
| "admins only"                       | S1       | Nothing  | Nothing          |
| "require MFA step-up"               | any +`mfa=true` | —     | —                |

"S1" = domain + role only (`resource=""` matches all paths).
"S2" = domain + resource + role. "S3" = full source/target self-scoping.

### Step 3 — Propose the TOML row

Present the row to the user before applying. Format per REF.md `PolicyDTO`.

Example (self-scoping, user reads only their own record):

    { domain = "example.com",
      resource = "/api/users/{id}",
      role = "user",
      source = "User",
      target = { FromPath = { pname = "id" } },
      mfa = false,
      allowed = true }

Example (two-row, method-specific):

    { domain = "example.com", resource = "/api/users",
      role = "user",  action = "GET",       allowed = true },
    { domain = "example.com", resource = "/api/users",
      role = "admin", action = "POST",      allowed = true },
    { domain = "example.com", resource = "/api/users",
      role = "admin", action = "DELETE",    allowed = true }

### Step 4 — Apply

    POST {janux_url}/api/v1/admin/policy/create
    Authorization: Bearer {admin_jwt}

Body is the `PolicyDTO` JSON. Send one call per row.

### Step 5 — Verify

With a JWT for the role being granted, request the resource:
- Allowed case: `curl -H "Authorization: Bearer <user_jwt>" \
  <janux_url>/api/v1/auth/verify -X POST ...` → 200
- Denied case:  request a resource the user shouldn't reach → 403
- MFA case:    request with `mfa=true` but no TOTP → 401 with
  `expect_mfa: true` (caller must retry after TOTP verify)

---

## Op 5 — Verify DNS is set up

The domain must resolve to the proxy's IP. This is a prerequisite for
all other ops on a non-localhost domain.

### Check A record

    dig +short <domain> A

    Or via the proxy host:

    getent hosts <domain>    # on the proxy host itself
    nslookup <domain>        # any host with DNS

    Expected: the proxy host's IP appears. For Caddy, this is the IP of
    the machine running Caddy. For docker-compose, it may be the host IP.

### Check TLS (for external domains)

    curl -sI https://<domain> | head -1

    Expected: `HTTP/2 200` (or 301/302). A TLS handshake failure
    means the cert isn't set up (Caddy acme, or the cert file).

### Caddy TLS mode

- `tls internal`: self-signed via Caddy's local CA. The browser must
  trust that CA once. On macOS: `up.py <setup> trust-ca`. On Linux:
  accept the cert warning.
- `tls acme` / no directive: Caddy auto-provisions from Let's Encrypt
  via ACME. Needs the domain's A record to point to the Caddy host.

---

## Operational notes

### Rate limits

janux has per-IP rate limiting on all endpoints. In docker-compose
dev environments, all traffic comes from one IP; add
`disable_rate_limits = true` to `base.toml` for local testing only.
NEVER enable on a publicly reachable host.

### Encrypted at rest

All provider secrets, signing keys, and TOTP secrets in the data dir
are AES-256-GCM encrypted with `encryption_key`. Without it, the data
dir is unrecoverable. Store it with the same care as a DB password.

Rotate with `janux rekey <new-key>` (cold operation, stops the server).
After rekey, update `encryption_key` in `base.toml` immediately.

### Idempotent seed

Seeding is upsert-on-startup. Restarting janux with the same
`seed.toml` is safe. New roles/policies/users are added; existing
ones are unchanged. To remove a seeded user or policy, delete it via
the admin API before relying on a subsequent seed.
