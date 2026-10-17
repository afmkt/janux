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
  seed reference; `examples/*/seed.example.toml` show the Zonemail / SMTP
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
- `Resend` is now **one optional backend**, not a hard dependency. The email
  magic-link factor is available via Resend **or** Zonemail **or** a built-in
  SMTP relay.
- **Login terminal** (`frontend/src/login/App.tsx`): a magic-link login with
  no parked return target (no `client_id`/`state`/`redirect_uri`) no longer
  stops on a bare "Signed in." alert. It now renders "Signed in. You can close
  this tab." plus a **Continue to admin console** button (→ `/admin`), so a
  user who reaches `/login` without a redirect is no longer stranded.
- **Admin console shell** (`frontend/src/admin/App.tsx`): the flat 12-item tab
  strip is replaced by a Mantine `AppShell` — a grouped sidebar
  (Identity · Directory · Authentication · Security · Insights), a header with the
  Janux brand, a light/dark theme toggle, and a user menu (roles, MFA status,
  self-service *Account*, sign out). Navigation is hash-routed (`#users`,
  `#roles`, …) so deep-links and back/forward work with no new server route.
- **Unified theme** (`frontend/src/shared/theme.ts`,
  `frontend/src/shared/providers.tsx`): all four SPAs (admin, login, consent,
  device) now mount one shared `ThemeProvider` with a brand accent (`grape`) and
  a persisted light/dark color scheme, so the console and the auth ceremony read
  as a single product.
