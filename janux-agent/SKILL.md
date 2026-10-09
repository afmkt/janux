---
name: janux-deploy
description: >
  Deploy and operate Janux (passwordless OIDC). Use when the user says
  "deploy janux", "set up auth", "protect my service with janux",
  gives the janux GitHub URL and asks for deployment help, or needs
  RBAC policies, DNS checks, key rotation, or user migration (SCIM / dump).
compatibility: >
  Requires the janux binary (or ghcr.io/afmkt/janux image) and a reverse
  proxy (Caddy or nginx). For remote operations, requires SSH access.
  Python 3 for scripts/render-deploy.py (stdlib only).
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

Config at bootstrap: `base.toml` + `seed.toml`. After that, admin API.
Schema/API: **REF.md**.

## Modes (read this first)

| Mode | When | Agent behaviour |
|------|------|-----------------|
| **Generate-only** (default) | User asks to deploy / set up / protect a service | Run the survey → emit a deploy pack → show commands → **stop** |
| **Live deploy** | User explicitly says "deploy it on host" / "bring it up" | Generate pack, then run compose/SSH **only after confirmation** |
| **Operate** | Janux already running | Need `janux_url` + `admin_jwt`; use Ops in REF.md / this skill |

Never commit real secrets into git. Prefer `JANUX__encryption_key` (env)
over putting the key in `base.toml` for production.

## Deployment survey (run this first for any new deploy)

Ask **in order**. Do not invent secrets. Record as JSON for `scripts/render-deploy.py`.

1. **Topology**: Local Docker | Remote Docker (SSH) | Systemd VM | **Generate assets only** (default)
2. **Layout**: Single host (recommended) | Split hosts
3. **Domain(s)**: primary/auth domain; app domain if split
4. **Service**: backend address, path to gate (exact), role (user/admin/custom)
5. **Auth factors**: email (Resend key), SMS, social, or none yet
6. **Bootstrap admin**: email or mobile
7. **TLS**: `internal` (dev) | ACME (prod)
8. **Proxy**: Caddy (default) / nginx; trusted proxy CIDR (e.g. `172.28.0.0/16`)

Example answers JSON:

```json
{
  "mode": "generate",
  "layout": "single-host",
  "domain": "localhost",
  "resource": "/app",
  "role": "user",
  "admin_email": "admin@example.com",
  "tls": "internal",
  "backend": "app:80",
  "trusted_proxies": "172.28.0.0/16",
  "image": "ghcr.io/afmkt/janux:latest"
}
```

## Op 0 — Artifact generation (default)

```sh
python3 scripts/render-deploy.py \
  --layout single-host \
  --domain localhost \
  --resource /app \
  --admin-email admin@example.com \
  --out ./deploy-pack
```

Or: `python3 scripts/render-deploy.py --answers answers.json --out ./deploy-pack`

Hand the pack to the user. **Stop** unless they requested live deploy.

Verify after they start it:

```sh
curl -fsS https://<domain>/api/v1/health/ready
```

## Op 1 — Live deploy (only with explicit confirmation)

1. Generate pack (Op 0) or author `base.toml` / `seed.toml` (see REF.md).
2. Encryption key: `openssl rand -hex 32` → prefer `JANUX__encryption_key` env.
3. `cd <pack> && docker compose up -d` (or systemd/SSH only if user approved).
4. Health-check `/api/v1/health/ready`, then open `/login` for admin magic link.

## Ongoing ops (Op 2+)

| Op | Goal | Entry |
|----|------|--------|
| 2 | Add domain | `POST /api/v1/admin/domain/create` + proxy + DNS |
| 3 | Protect service | `POST /api/v1/admin/policy/create` + proxy forward_auth |
| 4 | Propose RBAC | Parse URL → PolicyDTO rows (REF.md scenarios S1–S3) |
| 5 | Verify DNS | `dig` / TLS check |
| 6 | Encryption key | place/rotate via `janux rekey` (cold) |
| 7 | Customize UI | `janux dump-frontend` + `pages_dir` |
| 8 | Migrate users | SCIM or `janux dump` |

Details and examples: **REF.md** and the prior skill revision on `main`
(https://github.com/afmkt/janux/blob/main/janux-agent/SKILL.md).

## Inputs for ongoing ops

| Input | Source |
|-------|--------|
| `domain` | tenant hostname |
| `janux_url` | `https://<domain>` |
| `admin_jwt` | login as bootstrap admin; or magic-link flow |
| `proxy` | caddy or nginx |
| `backend` | service address from proxy network |
