# Changelog

All notable changes to Janux. The format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- **Mailer abstraction** (`src/mailer.rs`): email delivery is now behind a
  `Mailer` trait with three backends, so a self-hosted Janux no longer depends
  on the Resend SaaS.
  - `Resend` — the existing `resend-rs` path (unchanged behaviour).
  - `Zonemail` — a self-hosted DNS+SMTP stack
    ([`github.com/afmkt/zonemail`](https://github.com/afmkt/zonemail)); Janux
    calls its `POST /mail` (a janux-style `{ ok, data }` envelope).
  - `SmtpRelay` — a built-in `lettre` relay client (STARTTLS by default; the
    lightest self-hosted option, no second process).
- **Config** (`src/config.rs`): per-backend DTOs — `[seed.zonemail]`
  (`base_url`, `from`, `api_token`) and `[seed.smtp]` (`host`, `port`, `from`,
  `user`, `password`, `tls`, `insecure`) — plus an optional `mail.backend`
  selector. Send-capable secrets (`zonemail.api_token`, `smtp.password`) are
  encrypted at rest like `resend_key`.
- **Selection**: the email factor turns on with *any* configured backend.
  Without an explicit `mail.backend`, the first configured backend wins by
  fixed priority `resend → zonemail → smtp`. An existing tenant with only
  `[seed.resend]` keeps using Resend — migration-free.
- **Dump** (`src/dump.rs`): `[[tenants.mail]]` now reports the active backend
  and redacts the new secrets unless `--secrets`.
- **Docs**: `docs/mailer.md` (design, now implemented); `janux-agent/REF.md`
  seed reference; `examples/janux.example.toml` shows the Zonemail / SMTP
  alternatives.
- **Debug diagnostics** (`debug` config / `JANUX__debug`): when on, 401/403
  failure responses carry the full reason in their `detail` field (which token
  check failed, which role is missing) so a developer sees *why* a request was
  refused. Off by default in production — the reason stays server-side so a
  client learns only *that* it was refused, never *why* (the secure,
  fail-closed behavior). Resolves to `true` under `RUN_ENV=development` (the
  default) and `false` under `RUN_ENV=production`; set `debug`/`JANUX__debug`
  to override. A loud boot warning flags a reachable host running with it on.

### Changed
- **Config** (`src/main.rs`): the default config is now a single `janux.toml`
  (platform config + the `[[seed]]` bootstrap section, formerly `base.toml` +
  `seed.toml`). `--config <file>` (repeatable) layers additional files on top;
  `JANUX_CONFIG_FILE` overrides the default name. `examples/` ships one
  `janux.example.toml`; `render-deploy.py` writes `janux.toml`.
- **Examples** (`examples/`): the tree is now a single flat, dogfood-style
  deployment — Caddy + nginx + Mailpit + the per-domain frontend override —
  replacing the `single-host`/`split-hosts` subfolders and the `up.py`
  lifecycle harness. `render-deploy.py` is single-host-only and copies this
  flat example; its mailpit + frontend-override defaults match the dogfood
  harness. `seed_toml_bootstraps_builtin_roles`' G-133 magic-link guard is now
  backend-agnostic (any configured `resend` / `zonemail` / `smtp`, ≥1 required,
  not Resend-only) so the SMTP-relay example satisfies it.
- **User detail page** (`frontend/src/admin/tabs/UserDetailTab.tsx`, hash
  `#users/<name>`): Users is now a directory. Opening a row lands on a dedicated
  surface with grouped sections — Roles (chips + grant/revoke), Credentials
  (drop passkeys / remove email / remove mobile), API keys (self only), and a
  Danger zone (delete). The old six-button action row is gone.
- **Users list** (`UsersTab.tsx`): thin rows (name · optional role badges ·
  Open). Create jumps into the new user's detail page.
- **API key mint UI** on Account and on the self user-detail page: lifetime
  preset, optional role subset (session roles only), one-time reveal modal with
  copy. Wires the existing `POST /api/v1/auth/api-key` endpoint; there is still
  no server-side key registry, so list/revoke-by-id is out of scope.

- `Resend` is now **one optional backend**, not a hard dependency. The email
  magic-link factor is available via Resend **or** Zonemail **or** a built-in
  SMTP relay.
- **Login terminal** (`frontend/src/login/App.tsx`): a magic-link login with
  no parked return target (no `client_id`/`state`/`redirect_uri`) routes
  straight to `/admin` — the admin console — instead of parking on an
  intermediate "Signed in — click continue" screen, so a user who reaches
  `/login` without a redirect lands on the console.
- **Admin console shell** (`frontend/src/admin/App.tsx`,
  `frontend/src/admin/index.css`): the flat 12-item tab strip is now a
  **collapsible accordion sidebar** — one control per intent group
  (Identity · Directory · Authentication · Security · Insights) that expands its
  panel of sections, so an operator collapses the groups they are not in and the
  group holding the active section stays open as navigation (and back/forward)
  happens. A header carries the Janux brand, a light/dark theme toggle, and a
  user menu (roles, MFA status, self-service *Account*, sign out). Navigation is
  hash-routed (`#users`, `#roles`, …) so deep-links and back/forward work with no
  new server route; user detail deep-links use `#users/<name>`. The frame is a
  hand-rolled flex layout shipped in the hashed CSS bundle rather than Mantine's
  `<AppShell>`: AppShell injects its fixed-panel offsets as a runtime `<style>`
  tag, which the server's `style-src 'self'` CSP blocks — leaving the main
  content un-offset and the sidebar overlapping it. The static layout reproduces
  the same frame (and the mobile slide-in overlay) with no runtime-injected
  style, so the console renders correctly under the CSP.
- **Unified theme** (`frontend/src/shared/theme.ts`,
  `frontend/src/shared/providers.tsx`): all four SPAs (admin, login, consent,
  device) now mount one shared `ThemeProvider` with a brand accent (`grape`) and
  a persisted light/dark color scheme, so the console and the auth ceremony read
  as a single product.
- **Hosted page caching** (`src/pages.rs`): HTML entry pages (`login`, `consent`,
  `device`, `admin`) now carry `Cache-Control: no-cache` on both the 200 body and
  the 304 revalidation, so a plain browser reload revalidates via the response
  ETag instead of serving a stale entry that points at an already-replaced,
  content-hashed bundle — the trap that made a freshly built frontend appear
  unchanged. Hashed static assets get no `Cache-Control`, so the browser keeps
  caching them by their content-hash name.
