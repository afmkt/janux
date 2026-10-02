---
name: janux-deploy
description: >
  Operate Janux — a self-hosted passwordless OIDC provider. Covers initial
  deployment, adding domains and services, proposing RBAC policies,
  verifying DNS setup, and migrating users to another auth system
  (via SCIM or a cold `janux dump` / load).
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

This secret encrypts all at-rest secrets in the data dir. See **Op 6**
for how to place it (env var vs. config file) and how to rotate it. For
Op 1 just generate it and put it in `base.toml`.

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

## Op 6 — Set up and rotate the encryption key

### How many secret keys does janux use

There are **two** kinds of key, but **only one is yours to provide**:

     1. the ENCRYPTION key — ONE process-wide 32-byte (64-hex-char)
        AES-256-GCM key. This is the only key you generate and supply.
        It encrypts EVERYTHING at rest:
              - the private halves of the signing keys below,
              - social / OIDC provider secrets,
              - TOTP secrets,
              - the stored Resend / Aliyun-SMS delivery credentials.
        It spans the whole janux process (all tenants) and must be
        stable across every restart — it is held in a process-wide
        OnceLock. Lose it and the entire data dir is unrecoverable;
        leak it and every signing key is exposed.

     2. the SIGNING keys — RSA (RS256) keypairs, one per domain, that
        janux AUTO-GENERATES at seed time (id `seed-<domain>`). You do
        NOT provide these. Each JWT (session / id / refresh / device)
        they sign is verified through the published JWKS
        (`/.well-known/jwks.json`). Their private halves live at rest
        encrypted by the encryption key above; manage their lifecycle
        (create / retire / delete) via `admin/key/{create,retire,delete}`
        — see REF.md. The public half is published, the private half is
        never emitted (not even by `janux jwks`).

So: **1 encryption key to manage, N auto-generated signing keys**.

### Place the encryption key

Generate it once:

    export ENCRYPTION_KEY=$(openssl rand -hex 32)

Two ways to hand it to janux (same value, pick by where it lives):

     - ENV VAR (preferred for production):
          JANUX__encryption_key="$ENCRYPTION_KEY" janux -c base -c seed
        Supply it via the orchestrator — a systemd `EnvironmentFile=`
        with `0600` perms, a Docker `environment`/secret, or a
        Kubernetes Secret. Keep it OUT of `base.toml` and OUT of version
        control, so it never sits in a plaintext config file that gets
        committed or copied into a backup tarball beside the data dir
        it guards.

     - CONFIG FILE (fine for dev / single-box):
          encryption_key = "$ENCRYPTION_KEY"       # in base.toml

Precedence: `JANUX__*` env vars override the files, so the env var
always wins. The key is REQUIRED at boot — janux exits with a FATAL if
it is missing, and logs a loud warning if it is the well-known example
key from `base.example.toml`.

> Prefer the env var in deployment, but remember an env var lives in the
> process environment (visible to the same UID via `/proc/PID/environ`).
> The point is keeping it off disk and out of git — not hiding it from
> the process. Use an orchestrator secret either way; never hardcode it.

### Rotate the key

Cold operation. Stop the server first, run rekey, then point config at
the new key:

     # 1. stop janux (the data DB is exclusively locked while it runs)
     # 2. re-encrypt every at-rest secret under the NEW key:
    JANUX__encryption_key="$OLD_KEY" janux rekey "$NEW_KEY"
           # OLD key is read from config/env; NEW is the arg.
           # Upgrades any legacy plaintext rows to ciphertext on the way.
     # 3. SET encryption_key = "<NEW_KEY>" in your env/config now —
     #    the data dir no longer decrypts under the old key.
     # 4. start janux with the new key.

A successful rekey prints a tally (`Rekeyed N tenant(s): … signing
key(s), … provider secret(s), … TOTP secret(s), … config secret(s)`).

---

## Op 7 — Customize the built-in UI

The UI (login, admin, consent, device-login, admin console) is a Vite +
React (Mantine) app **embedded in the binary**. There is no branding
config knob and no upload API — the only customization path is **file
override** with `janux dump-frontend` + the per-domain `pages_dir` seed
field. (By design: whoever edits config already holds the encryption
key, so a new upload surface would add a privilege boundary for no
security gain.)

### Scaffolding (per domain)

     1. Dump the scaffold:
            janux dump-frontend <dir>          # writes the embedded UI
                                              # + a .janux-version marker;
                                              # the server does NOT start
     2. Edit the files in `<dir>` — branding, copy, or a new login form.
       Prune the files you do NOT override: serving is per-file, so any
       file missing from `<dir>` falls back to the embedded version.
     3. Point the domain at the dir in `seed.toml`:

            domains = [
                 { id = "auth.example.com",
                  cors = ["tenant"],
                  pages_dir = "./data/pages/auth.example.com" },
              ]

     4. Restart janux. `pages_dir` is config-file-only and declarative —
       removing it on the next restart disables the override.

### What you can brand

The served pages are `login.html`, `admin.html`, `consent.html`,
`device.html`, plus `favicon.svg` / `icons.svg`. To rebrand:

     - swap `favicon.svg` / `icons.svg` (your logo),
     - edit the `<title>` and shell markup in the `*.html` files,
     - restyle via CSS — the app is Mantine-based (`src/*/index.css`).

### Building a new / custom login form

The login page drives the passwordless ceremony — request then verify:
`/api/v1/auth/<factor>/request` → `/api/v1/auth/<factor>/verify`
(`email`, `otp`, `passkey`, and `social/{id}`); a magic link lands at
`/login` and reads `token` / `username` / `email` from the query. You
can do this two ways:

    a. Edit the SPA (`frontend/src/login/*`): `cd frontend && npm i &&
        npm run build` produces hashed bundles in `dist/`; serve those
        assets from your `pages_dir`.
    b. Hand-roll a same-origin static login page that calls the same
        request/verify endpoints above.

**CSP is strict and blocks inline code.** Every hosted page carries
`script-src 'self'`, `style-src 'self'` (no `unsafe-inline`),
`img-src 'self' data:`, `object-src 'none'`, `frame-ancestors 'none'`. So
a custom form must ship as same-origin static assets — an external
hashed `<script>` bundle + an external `.css` file, with images either
same-origin or `data:`. Inline `<script>` / `<style>` / event handlers
are dropped by the CSP on purpose (the login page is the most
phishing-sensitive surface the server has).

### Keep the override current

janux compares the scaffold's `.janux-version` against the running binary
at boot. A mismatch (or a missing marker) is logged loudly: re-run
`janux dump-frontend` into a fresh dir and re-apply your edits whenever
you upgrade janux.

---

## Op 8 — Migrate users to another auth system

When a tenant's users must move to a *different* authentication system
(another janux instance, a commercial IdP, or an in-house one), use one
of two methods. **Method 1 (SCIM) is the preferred, live path** if the
target supports it; **Method 2 (dump/load) is the offline fallback** and
the one that is usable today without changes.

### Method 1 — SCIM (live federation / provisioning)

SCIM 2.0 is the standard way to push and sync users, groups, and roles
between identity systems without exporting password material. janux ships
a **SCIM 2.0 *receiver***: it can accept user/group/role
provisioning from an external IdP over `/api/v1/scim/*` (see REF.md). It
exposes:

- `GET /Users`, `POST /Users`, `PATCH /Users`, `DELETE /Users`
- `GET /Groups`, `POST /Groups`
- `GET /Roles` (and the `Roles` bulk endpoint, gated by RBAC)

For a migration **out of janux *to* another system**, SCIM is the
"carry the verifier, not the bytes" model: the target system of record
creates the user objects and janux (or the source IdP) is the producer.
Two practical shapes exist:

1. **External IdP as the source of truth.** If your organization already
   runs an IdP that janux consumes via SCIM, you re-point the downstream
   consumer at the new target and let SCIM re-provision. janux itself
   never holds the secrets — they live upstream. Cleanest move, no secret
   ever touches janux's data dir.

2. **janux as the SCIM producer (planned).** Janux's `dump` command
   (Method 2) is the interim producer: it emits the user + role + policy
   graph as a portable TOML bundle that a target SCIM *consumer* can
   import. This replaces a future native SCIM-out endpoint.

SCIM is the **recommended** method because it never moves credential
secrets between systems; it moves *identities* and lets each side keep
its own verifiers. Federation (RFC 9470 OpenID Federation, or OIDC
federation) is the alternative when the target is an OpenID provider that
trusts janux's identity assertion directly.

### Method 2 — dump / load (offline export)

Use when the target cannot consume SCIM, when the move must be
point-in-time and atomic, or for a one-shot teardown. This is a **cold,
read-only** operation, exactly like `janux rekey` and `janux jwks`:
stop the server first. The output is a `janux-dump/1` TOML bundle carrying
users, their factors, machine config, **and RBAC policies**.

```
janux dump --output migrate.toml            # secrets redacted (default)
janux dump --domain example.com --secrets --yes --output migrate-with-secrets.toml
```

Flags:

| Flag         | Effect                                                        |
|--------------|--------------------------------------------------------------|
| `--domain D` | Restrict to the owning tenant of domain `D`. Omit = every tenant.|
| `--secrets`  | Decrypt AES-at-rest fields (TOTP secrets, social client secrets, mail/SMS keys, signing-key private halves) and emit in the clear. Requires `--yes`. |
| `--yes`  | Confirmation that `--secrets` may print plaintext (prevents an accidental leak to a logged stdout / redirected file). |
| `--output F` | Write to `F` instead of stdout. Default: stdout. |

**The dump classifies every credential into one of four buckets.** The
cardinal decision of this op:

> A credential that cannot survive a dump/load round-trip is **skipped
> with a warning**, never silently corrupted. If one login factor is
> not portable, let the user **rotate or re-register** that factor at
> the target rather than lose the account.

| Bucket        | What travels                                    | Target action                       |
|---------------|-------------------------------------------------|-------------------------------------|
| `portable`    | Verifier material that survives verbatim: Argon2id client-secret hash, TOTP base32 shared secret (gated by `--secrets`), social provider config + binding, mail/SMS keys, signing-key PEM (private half gated). | Use immediately. |
| `repro`       | Only metadata travels; the verifier is re-provisioned at the target on first use. | Target re-provisions. |
| `advisory`    | Factor cannot round-trip. Only metadata (passkey `rp_id`, `name`, `created_at`) travels so the target can offer a **re-enrollment prompt at `rp_id`**. | Admin re-enrolls / vouches. |
| `drop`        | Purely janux-internal, no equivalent on the target. Omitted. | N/A. |

#### Liveness check

Because janux is multi-factor, losing one factor during migration is not
necessarily fatal. Before you load the bundle, check the `account_warnings`
bucket in the manifest. Each user is classified:

- `login_immediately` — has a portable factor (active TOTP, or an Argon2id
  client). Loads and works first try.
- `login_after_social` — no portable factor, but has a social binding.
  Works after the target loads the same provider config and the user
  re-authenticates via the provider.
- `locked_out` — has *only* non-portable factors (passkeys). The user
  **cannot self-serve**; provision by admin or vouch via federation.
- `no_factor` — no factors at all (pre-feature account or seed stub).

**`locked_out` users are the gate you must resolve before cutover.**
Offer them a passkey re-enrollment at the original `rp_id` domain, or
an admin-provisioned TOTP, and only then cut over.

#### The TOML shape

The top-level `janux-dump/1` bundle is:

```toml
# manifest — the contract a target checks before anything destructive.
[manifest]
schema = "janux-dump/1"
source = "janux"
source_user_prefix = "janux:user:"
generated_at = "2026-03-17T...Z"
secrets_emit = false
# domain = "example.com"   # present only when --domain was set

[[users]]
  user_id = "..."
  name = "alice"
  external_id = null            # only when present
  active = true
  roles = ["user"]
  liveness = "login_immediately"

  [[users.emails]]
    email = "alice@example.com"
    verified = true

  [[users.mobiles]]
    mobile = "+1555..."

  [[users.totp_factors]]
    name = "authenticator"
    active = true
    status = "portable"            # portable | repro | advisory
    algorithm = "SHA1"            # janux pins SHA1 / 6 digits / 30s
    digits = 6
    period = 30
    secret = "****redacted****"  # base32 secret when --secrets; sentinel otherwise
    domain_id = "example.com"
    created_at = "2026-03-17T...Z"

  [[users.social_bindings]]
    provider_id = "google"
    provider_user_id = "1234567"
    status = "repro"
    created_at = "..."

  [[users.passkey_advisories]]         # bytes do NOT travel
    passkey_id = "..."
    active = true
    status = "advisory"
    reason = "rp-scoped credential; the target must own this rp_id domain or re-enroll"
    rp_id = "example.com"             # used to build a re-enrollment prompt
    name = "laptop"
    created_at = "..."

[[tenants]]
  name = "example.com"

  [tenants.mail]
    provider = "resend"               # or config-driven; null when unset
    from = "..."
    key = "****redacted****"          # base64/AES decrypted when --secrets

  [tenants.sms]
    provider = "twilio"
    api_from = "..."
    api_key = "****redacted****"

  [[tenants.social_providers]]
    id = "google"
    name = "Google"
    client_id = "..."
    client_secret = "****redacted***"   # when --secrets
    scopes = ["openid"]

  [[tenants.signing_keys]]
    key_name = "key1"
    retired = false
    public = "-----BEGIN PUBLIC KEY...-----"   # always emitted
    private = "****redacted****"               # PEM, only when --secrets

  [[tenants.oauth2_clients]]
    client_id = "svc"
    client_secret_hash = "$argon2id$v=19$m=...$...$..."   # portable, always
    redirect_uris = ["https://app.example.com/callback"]
    grant_types = ["client_credentials"]
    response_types = ["token"]
    token_endpoint_auth_method = "client_secret_basic"
    default_scopes = ["openid"]
    active = true

  [[tenants.domains]]
    name = "example.com"
    cors = ["https://app.example.com"]
    acme_email = "..."          # when present
    has_cert = true            # metadata only; no PEM bytes
    has_key = true

  [[tenants.policies]]          # the RBAC graph travels with the tenant
    id = "..."
    domain_id = "example.com"
    action = "GET"             # HttpMethod; null when any method
    resource = ["", "api", "v1", "app"]
    role_id = "user"
    source = "nothing"         # nothing | user | domain | role
    target = "nothing"         # nothing | from_path | from_query | from_header
    mfa = false
    allowed = true            # the engine is default-deny; only allow rows matter
    created_at = "..."

[account_warnings]
  login_immediately = ["alice"]
  login_after_social = ["bob"]
  locked_out = ["carol"]
  no_factor = []
```

#### How a target loads it

A target that speaks `janux-dump/1` consumes the bundle in this order:

1. **Read the manifest first.** Confirm `schema == "janux-dump/1"` and
   note `secrets_emit`. If `secrets_emit = false`, the target must
   re-provision every factor it needs rather than expecting the bytes.
2. **Create tenants** from `[[tenants]]`, loading `social_providers`,
   `mail`, `sms`, `signing_keys`, `oauth2_clients`, and `domains`. The
   argon2id client-secret hashes travel verbatim, so OAuth2 clients work
   immediately. Signing-key private halves, if present, let the target
   verify existing janux-issued JWTs during the cutover window.
3. **Create users** from `[[users]]`, attaching `emails`, `mobiles`,
   `totp_factors` (when unredacted), and `social_bindings`.
4. **Re-apply the policy graph** from `[[tenants.policies]]`. The target
   may *ignore* it, *transform* it (remap roles/resources to its
   vocabulary), or *import* it verbatim — it is the user's decision. If
   the target does not understand janux RBAC, read each row as
   `role_id → resource (+action) → allow/deny (+mfa)` and reconcile
   against the target's own access model.
5. **Work the `account_warnings`.** Every `locked_out` user must be
   resolved (re-enroll passkey or provision TOTP) **before** cutover.
   `login_after_social` users self-serve on their next login once the
   provider config is loaded.

> **Policies are the user's call.** The dump emits the full RBAC graph
> because a target can do anything with it, but janux takes no position
> on what you do. If you keep the default-deny engine on the target,
> importing the policies verbatim is sufficient. If the target has its
> own access model, treat the row set as data and map it.

### Choosing between the two methods

| Situation                                   | Use              |
|---------------------------------------------|------------------|
| Target is an SCIM consumer / you want live sync | Method 1 (SCIM) |
| One-shot, point-in-time cutover             | Method 2 (dump)  |
| Target trusts janux's identity assertion      | Federation (RFC 9470) |
| You want to inspect / hand-tune before load   | Method 2 (dump)  |
| Passkey-heavy user base                     | Either, but expect `locked_out` work |

---

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
