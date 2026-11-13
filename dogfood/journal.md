# Janux usability-test journal

- **Date:** 2026-10-16
- **Setup:** single-host — Caddy (forward_auth) → Janux `ghcr.io/afmkt/janux:latest` → nginx static `/app`; magic-link email via local Mailpit relay.
- **Roles in play:** user = `tester@example.com` (role `user`); ops = `admin@example.com`; platform = `root@example.com`.
- **User entry point:** `https://localhost/app` (gated) → `https://localhost/login`; email inbox `http://localhost:8025`.

_(agent appends health, log excerpts, and what it sees while the user interacts)_

### 2026-10-16 16:47 — environment up + smoke-verified (agent)
- 4 containers healthy: `auth` (janux, healthy), `caddy` (front), `app` (nginx), `mailpit` (healthy).
- `GET /api/v1/health/ready` → `{"ok":true}`.
- `GET /app` unauthenticated → `303 → /login` (forward-auth gate bounces; `forward_auth_redirect=true`).
- `GET /login` → `200`; `GET /.well-known/openid-configuration` → OIDC metadata (acr: email/otp/passkey/totp).
- Magic-link pipeline proven: `POST /api/v1/auth/email/request {name:tester,email:tester@example.com}` → `{"ok":true}`; Mailpit REST `/api/v1/messages` shows 1 message, subject "Janux login", to tester@example.com. **Delivery works.**
- Caddy local CA extracted to `dogfood/caddy-root.crt`; auto-trust into the login keychain **did not complete** — the `security add-trusted-cert` call blocked on a GUI prompt and was killed at 300s. Fallback: click through the one-time browser warning, or run the manual command in `USER-GUIDE.md`.
- Mailpit REST inbox is at `GET http://localhost:8025/api/v1/messages` (not `/api/v1/emails`).

## User feedback
_(agent transcribes the user's in-chat reactions, timestamped)_

## Findings / report
_(filled at the end of the test)_
