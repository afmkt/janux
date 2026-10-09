# AGENTS.md — Janux

Instructions for AI coding and operations agents (Pi, Hermes, Codex, Copilot, Claude Code, etc.).

## Project overview

Janux is a self-hosted, passwordless auth server and OIDC provider (Rust · Salvo · Toasty · WebAuthn · Vite/React). One binary, layered TOML config (`base.toml` + `seed.toml`), multi-tenant by hostname, default-deny RBAC, forward-auth friendly.

## When the user wants to deploy or operate Janux

1. **Load the skill**: read `janux-agent/SKILL.md` (and `janux-agent/REF.md` on demand for schemas/API).
2. **Run the Deployment Survey** defined in the skill (topology, domain, backend, auth factors, admin email, TLS, proxy). Do not invent secrets.
3. **Default mode is generate-only**: produce a deployable asset pack (compose + configs). Stop and show the user the files and commands.
4. **Live deploy** (Docker/`docker compose up`, SSH, systemd) only after the user explicitly confirms.
5. Never commit real secrets (`encryption_key`, Resend keys, SMS keys, admin emails with production inboxes) into the repository.

### Skill install (optional, for agents that load skills from a path)

```text
# Claude Code
cp -r janux-agent .claude/skills/janux-deploy

# Codex / OpenCode-style
cp -r janux-agent .codex/skills/janux-deploy

# Pi
cp -r janux-agent .pi/skills/janux-deploy
```

Or simply: *read `janux-agent/SKILL.md` and follow it*.

### Artifact generation helper

```sh
# After the survey, agents (or humans) can render a pack:
python3 scripts/render-deploy.py --answers answers.json --out ./deploy-pack
# or pass flags; see scripts/render-deploy.py --help
```

## Coding on this repository

### Rust formatting (mandatory)

- This project uses standard **rustfmt**.
- Whenever you modify or create any `.rs` file, **immediately run `cargo fmt`**.
- If an edit fails due to exact-match whitespace mismatch, re-read the file and retry; do not guess.

### Build & test

| Command | Purpose |
|---------|--------|
| `just unit` | lib suite + unit tests (`--test-threads=1`) |
| `just integration` | integration tests |
| `just e2e` | HTTP-level e2e |
| `just compliant` | OIDC/SCIM conformance (needs `uv`) |
| `just test` | unit + integration + e2e |
| `just openapi` | regenerate OpenAPI → frontend client |
| `just build` / `just release` | frontend build + cargo |

All Rust test tiers that share process-wide state **must** run with `--test-threads=1` (the `just` targets already do).

### Safety rules for agents

- Do **not** enable `disable_rate_limits` outside demos/`examples/`.
- Do **not** put real provider credentials or encryption keys in tracked files; use `*.example.toml` as templates and gitignored local copies.
- Prefer generating assets over remote mutation. Confirm before SSH, `systemctl`, or destructive admin API calls (`tenant/delete`, `key/delete`, etc.).
- Production-like security testing lives under `pentest/` — use that harness, not ad-hoc attacks against a live operator instance.

## Repository map

| Path | Contents |
|------|----------|
| `src/` | Server (router, factors, OIDC, RBAC, tenancy) |
| `frontend/` | Vite + React hosted UI |
| `examples/` | Caddy forward-auth demos (single-host, split-hosts) |
| `janux-agent/` | **Agent skill** for deploy/ops (`SKILL.md` + `REF.md`) |
| `scripts/` | Operator helpers (`render-deploy.py`, …) |
| `tests/` | unit / integration / e2e / conformance |
| `pentest/` | Production-like security harness |
| `Dockerfile` | Multi-stage image → `ghcr.io/afmkt/janux` |

## Quick human/dev path (non-agent)

```sh
cd examples
cp single-host/base.example.toml single-host/base.toml
cp single-host/seed.example.toml single-host/seed.toml
# edit encryption_key + admin email + resend_key
./up.py single-host up
```
