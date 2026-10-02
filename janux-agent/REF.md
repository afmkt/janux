# Janux Reference

Configuration schema, RBAC model, and admin API. Read on demand when
authoring config or calling the admin API.

---

## base.toml

Layered TOML. `janux -c base -c seed` loads both; later file wins.
Env vars with prefix `JANUX__` override everything (field overrides
only, e.g. `JANUX__bind__port=9090`).

    data_dir = "./data"            # required, filesystem path. Holds
                                   # tenant DBs, signing keys, revocation store.
    encryption_key = "..."         # required at runtime. 64 hex chars (32 bytes).
                                   # AES-256-GCM key for all at-rest secrets.
                                   # Generate: openssl rand -hex 32
    trust_forwarded_headers = false # true only when behind a reverse proxy
                                   # that owns X-Forwarded-* headers.
    trusted_proxies = []            # CIDR / IP list of peers allowed to supply
                                   # X-Forwarded-* when trust_forwarded_headers=true.
                                   # Required for security when true.
    forward_auth_redirect = false   # true: unauthenticated forward-auth probes
                                   # get 303 → /login instead of 401.
    disable_rate_limits = false     # DEV/TEST ONLY. Never enable in production.

    [bind]
    address = "0.0.0.0"
    port = 8080

---

## seed.toml

Bootstraps tenant state at startup. Idempotent — safe to re-run.

    [[seed]]
    name = "<tenant-name>"         # required, internal identifier
    domains = [
      { id = "example.com", cors = [] },
       { id = "0.0.0.0", cors = [] }   # optional catch-all
      ]
    roles = ["root", "admin", "scim", "user", "guest"]
     # built-in catalog. "root" is SEED-ONLY (not available via
     # admin/tenant/create). At most one tenant may hold a root user.

    users = [
        { name = "admin", roles = ["admin"], active = true,
         email = "admin@..." },
        # email marks the address VERIFIED at seed time. Without it the
        # user has no credential and cannot sign in until one is attached.
        { name = "ops", roles = ["user"], active = true,
         mobile = "+15551234567" },
        # mobile: alternative to email for OTP sign-in.
      ]

    policies = [
     # see RBAC section below
      ]

    [seed.resend]            # email delivery via Resend (required if
    from = "no-reply@..."    # enabling email magic-link sign-in)
    resend_key = "re_..."    # RECOVERY-CRITICAL if real
    template = "./email/verify.html"   # optional, Tera template
    verify_url = "http://localhost/login"    # where magic links land

    [seed.alisms]            # optional, Aliyun SMS delivery
    api_key = "..."
    api_secret = "..."
    region_id = "cn-shanghai"
    endpoint = "dysmsapi.aliyuncs.com"
    sign_name = "..."
    template_code = "..."

---

## RBAC model

### Built-in roles

| Role   | Level | Scope                       |
|--------|-------|-----------------------------|
| root   | —     | Tenant lifecycle (create/delete tenant). Seed-only. |
| admin  | 50    | Full access within its tenant |
| scim   | 60    | User provisioning via /scim/v2/* (above user, below admin) |
| user   | 10    | Self-service endpoints (/self/*) |
| guest  | 0     | Authenticated, no admin grants |

Level gate: a lower-level role cannot grant to a higher level.
A level-50 admin can add role "user" (10) but not "root" (seed-only).

### Code tier vs. policy tier

**Code tier**: `admin/*` endpoints are guarded in code by `protect_admin`.
No policy row needed. Any admin-role user can reach them.

**Policy tier**: tenant-defined resources (your app paths) use the
policy engine. Default-deny: if no policy row matches, access is denied.

### Policy scenarios

**Scenario 1 — Domain + role (full grant)**

    { domain = "example.com", role = "user" }
    # resource="" → matches ANY path in example.com
     # Use when "all users may reach everything on this domain"

**Scenario 2 — Domain + resource + role (path grant)**

    { domain = "example.com", resource = "/app", role = "user" }
     # exact path match, all HTTP methods
     # Use when "users may only reach /app"

**Scenario 3 — Self-scoping (source + target)**

    { domain = "example.com",
      resource = "/app/{owner}",
      role = "user",
      source = "User",                    # caller's username (from JWT)
      target = { FromPath = { pname = "owner" } },
      mfa = false,
      allowed = true }
    # alice may reach /app/alice, not /app/bob.
     # source and target must agree, else deny.

### Target resolvers

    Nothing          — no identity check (scenarios 1, 2)
    FromPath{name}  — reads path segment {name} from the request
    FromQuery{name} — reads ?name=... from the request
    FromHeader{name}— reads header "name" (lower-cased lookup)

### MFA

`mfa = true` forces a TOTP step-up even when source == target. The
caller's JWT must carry `amr=otp` (TOTP verified) or the engine
returns `expect_mfa: true` and the caller must re-authenticate.

---

## PolicyDTO (policy row)

Fields with defaults — omit to use the default:

    pub struct PolicyDTO {
        pub domain: String,              # required, no default
        pub role: String,                # required, no default
        pub resource: String,            # default "" (= any path in domain)
        pub action: Option<HttpMethod>,  # default None (= all methods)
        pub source: SourceResolver,      # default Nothing
        pub target: TargetResolver,      # default Nothing
        pub mfa: bool,                   # default false
        pub allowed: bool,               # default true
      }

HTTP methods: `GET`, `POST`, `PUT`, `DELETE`, `PATCH`.

---

## Admin API

All admin endpoints require `Authorization: Bearer <jwt>` where jwt is
a token for an admin-role user in the tenant's home domain.

### Tenants (root-only)

    GET  /api/v1/admin/tenant/list
    POST /api/v1/admin/tenant/create       # body: {name, domain?, admin?, admin_email?, admin_mobile?}
    POST /api/v1/admin/tenant/delete      # body: {name}

### Domains

    GET  /api/v1/admin/domain/list
    POST /api/v1/admin/domain/create        # body: {tenant, domain}
    POST /api/v1/admin/domain/delete      # body: {tenant, domain}

### Policies

    GET  /api/v1/admin/policy/list
    POST /api/v1/admin/policy/create       # body: PolicyEntry: {resource, domain, role, action?, source?, target?, mfa?, allowed?}
    POST /api/v1/admin/policy/delete      # body: {resource, role, action?}

### Users

    GET  /api/v1/admin/user/list
    POST /api/v1/admin/user/create       # body: {name, roles, active, email|mobile}
    POST /api/v1/admin/user/activate
    POST /api/v1/admin/user/delete
    POST /api/v1/admin/user/add_role
    POST /api/v1/admin/user/remove_role
    POST /api/v1/admin/user/attach_email
    POST /api/v1/admin/user/remove_email

### OIDC Clients

    GET  /api/v1/admin/oauth2client/list
    POST /api/v1/admin/oauth2client/create     # body: {client_name, redirect_uris}
    POST /api/v1/admin/oauth2client/delete
    POST /api/v1/admin/oauth2client/reactivate
    POST /api/v1/admin/oauth2client/rotate     # rotate client secret

### Social / OIDC Federal Providers

    GET  /api/v1/admin/provider/list
    POST /api/v1/admin/provider/create         # body: provider config
    POST /api/v1/admin/provider/delete

### Keys

    GET  /api/v1/admin/key/list
    POST /api/v1/admin/key/create
    POST /api/v1/admin/key/delete
    POST /api/v1/admin/key/retire

### OIDC Config

    GET  /api/v1/admin/oidc/config
    POST /api/v1/admin/oidc/config            # toggle DCR, logout, etc.

### Health

    GET /api/v1/health/ready    # 200 when server state is ready
    GET /api/v1/health/live     # 200 whenever the process is up

---

## Forward-auth flow (how proxy + janux work together)

    1. Browser requests https://domain/app
    2. Caddy's handle block runs forward_auth to janux:
           POST /api/v1/auth/verify
           X-Forwarded-Host: domain
           X-Forwarded-Uri: /app
           X-Forwarded-Method: GET
    3. janux evaluates its policy engine:
           domain=domain, resource=/app, role=caller's role
         → 200 (allow) or 401/403 (deny)
    4. Caddy sees 200 → reverse_proxies to /app backend
       Caddy sees 401 → if forward_auth_redirect=true, 303 → /login
                        else 401 to the browser

The `X-Forwarded-*` headers are critical. Set `trust_forwarded_headers=true`
and `trusted_proxies=[<proxy-subnet>]` in base.toml. Without
`trusted_proxies`, any peer can spoof the tenant (G-149).

---

## Secret keys

Two key kinds; **only the encryption key is operator-provided**:

| Key                | Count       | Who supplies it        | Purpose                                |
|-------------------|-------------|----------------------|------------------------------------|
| Encryption        | 1 (process)| Operator (`openssl rand -hex 32`) | AES-256-GCM; encrypts all at-rest secrets |
| Signing (RSA RS256) | N (one/domain) | janux auto, at seed | Signs session/id/refresh/device JWTs |

    ENCRYPTION key
      - base.toml `encryption_key` (64 hex / 32 bytes) or, overriding it,
        env var `JANUX__encryption_key=<hex>` (prefix `JANUX`, `__` sep).
      - REQUIRED at boot (FATAL exit if missing); warning if it equals the
        example key. Process-wide, once-only (`OnceLock`): stable across
        every restart or the data dir won't decrypt.
      - Encrypts at rest: signing-key privates, social/OIDC provider
        secrets, TOTP secrets, stored Resend/Aliyun credentials.
      - Rotation is a COLD op: stop the server, then
        `janux rekey <new-key>` (old key from config/env, new is the arg;
        upgrades legacy plaintext rows). Then set `encryption_key` to the
        NEW value or nothing decrypts. See SKILL.md Op 6.

    SIGNING key
      - Auto-created one per domain at seed time, id `seed-<domain>`
        (`rcgen` PKCS#1 RSA / RS256). Per-domain active key signs new JWTs.
      - Private PEM stored at rest encrypted with the encryption key;
        public PEM published at `GET /.well-known/jwks.json` and via
        `janux jwks [DOMAIN]` (public only — the private half is never
        emitted).
      - Rotation lifecycle (G-97): create a replacement → `key/retire`
        (stops signing, keeps verifying outstanding tokens, stays in the
        JWKS until drained) → `key/delete` (refuses an active key). One
        domain may not lose its last signable key. Endpoints:
        `POST /api/v1/admin/key/{create,retire,delete}` and `GET /api/v1/admin/key/list`.

---

## Frontend / UI overrides

The UI (login, admin, consent, device-login, admin console) is a Vite +
React (Mantine) app **embedded in the binary**. No branding config knob
and no upload API — customization is **file override** only.

     `janux dump-frontend <dir>`
      Write the embedded frontend + a `.janux-version` marker into <dir>.
      The server exits; it does NOT start. Existing files are overwritten
      (a refresh, not a merge with operator edits).

     Point a domain at <dir> in `seed.toml` (config-file-only, declarative
      — the key is `pages.<domain>` in the tenant Config store; boot reads
      it at startup, so restart to apply; removing it on the next restart
      disables the override):

          domains = [{ id = "auth.example.com",
                      cors = ["tenant"],
                      pages_dir = "./data/pages/auth.example.com" }]

     Serving is PER-FILE: disk override under <dir> first, embedded asset
      second, 404 last. Prune the files you don't override; anything
      missing falls back to the embedded frontend. Paths are confined
      under <dir> (percent-decoded; `..` rejected).

     Pages served: `login.html`, `admin.html`, `consent.html`,
      `device.html`, `favicon.svg`, `icons.svg`.

     Rebrand: swap `favicon.svg`/`icons.svg` (logo), edit the
      `<title>`/shell in the `*.html`, restyle via `src/*/index.css`
      (Mantine). Build a custom login by editing `frontend/src/login/*`
      (`cd frontend && npm i && npm run build` → hashed bundles in
      `dist/`) or hand-rolling a same-origin page that drives the
      passwordless ceremony: `POST /api/v1/auth/<factor>/request` then
        `.../verify` (factor = email | otp | passkey | social/<id>); a
       magic link lands at `/login` reading `token` / `username` / `email`
        from the query.

     STRICT CSP on every hosted-page response (G-112):

        default-src 'self'; script-src 'self'; style-src 'self';
        img-src 'self' data:; font-src 'self'; connect-src 'self';
        object-src 'none'; base-uri 'none'; form-action 'self';
        frame-ancestors 'none'

      No `unsafe-inline`. So a custom form must be same-origin static
      assets: an external hashed `<script>` bundle + external `.css`, with
      images same-origin or `data:`. Inline `<script>`/`<style>`/event
      handlers are dropped by the CSP — by design (the login page is the
      most phishing-sensitive surface).

     Version drift: boot compares `.janux-version` against the running
      binary and warns on mismatch. Re-run `janux dump-frontend` and
      re-apply edits after upgrading janux.

---

## Migration (dump / load)

Migrate a tenant's users to another auth system via a cold, read-only
export — stop the server first, like `janux rekey` and `janux jwks`.
Full procedure, four-bucket classification, and TOML shape: **SKILL.md
Op 8**.

### `janux dump`

    janux dump [--domain D] [--secrets] [--yes] [--output FILE]

Cold operation. Writes a `janux-dump/1` TOML bundle to stdout (or
`--output FILE`), then exits. The server does NOT start.

| Flag         | Effect                                                            |
|-------------|------------------------------------------------------------------|
| `--domain D` | Restrict to the owning tenant of domain `D`; omit = every tenant. |
| `--secrets` | Decrypt AES-at-rest fields and emit in the clear. Requires `--yes`. |
| `--yes`   | Required when `--secrets` is set (anti-leak guard).               |
| `--output` | Write to a file instead of stdout.                                |

### What travels and how it is classified

Every credential is bucketed so a non-portable factor is **skipped with a
warning, never silently corrupted** — rotate or re-register at the target
instead of losing the account.

- **portable** — survives verbatim. Argon2id OAuth2-client-secret hash
  (always emitted, self-describing `$argon2id$v=19$m=...$...$...`); TOTP base32
  shared secret (emitted only with `--secrets`); social provider config +
  bindings; mail/SMS keys; signing-key PEM (private half gated by
  `--secrets`).
- **repro** — metadata only; the target re-provisions the verifier on
  first use.
- **advisory** — cannot round-trip; passkey metadata (`rp_id`, `name`,
  `created_at`) travels so the target can offer a re-enrollment prompt at
  the original `rp_id`. Bytes do not travel.
- **drop** — janux-internal, omitted.

`account_warnings` classifies each user: `login_immediately` (portable
factor present), `login_after_social` (only social bindings), `locked_out`
(passkeys only — must be resolved before cutover), `no_factor` (no
factors).

### RBAC policies

The tenant's full policy graph travels under `[[tenants.policies]]` so a
target can re-apply or transform it. The engine is **default-deny**, so
only `allowed = true` rows are security-relevant. It is the user's
decision how to treat the rows: ignore, transform, or import verbatim.
