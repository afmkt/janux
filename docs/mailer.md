# Mailer abstraction — design (implemented)

> **Status:** implemented in `src/mailer.rs`, `src/config.rs`, `src/email.rs`,
> `src/oidc.rs`, `src/dump.rs`. Resend is now one optional backend among three;
> the email factor turns on with **any** configured backend.
Adapt email delivery behind a `Mailer` trait with three backends, so a self-hosted
Janux no longer depends on the Resend SaaS:

1. **Resend** — the existing `resend-rs` path (unchanged behaviour).
2. **Zonemail** — the self-hosted DNS+SMTP stack
   ([`github.com/afmkt/zonemail`](https://github.com/afmkt/zonemail)); Janux calls
   its `POST /mail`.
3. **SMTP relay (built-in fallback)** — a relay-only `lettre` client; the lightest
   self-hosted option, no second process.

Non-goal: **direct MX-to-MX delivery from Janux itself.** MX resolution + durable
outbound queue + retry/backoff are Zonemail's job; re-deriving them in Janux would
duplicate that binary and land on the worst delivery path (no IP reputation, SPF/
DKIM/DMARC liability). The built-in fallback talks only to an operator-configured
relay, never to an arbitrary recipient's MX.

---

## 1. The `Mailer` trait

A backend owns both its **content** (the HTML template, `from`, `verify_url`) and
its **transport** — a self-contained DTO per backend, matching the existing
`ResendDTO` / `OTPDTO` pattern (each service is self-contained). Content stays
backend-agnostic (one HTML template), so all three backends render identically and
only differ on the wire.

```rust
// src/mailer.rs — as implemented
/// The content side is shared (one Tera template), so it lives on a
/// `MailCommon` each backend embeds; only transport differs per backend.
pub struct MailCommon { pub from: String, pub template: String, pub verify_url: String }

pub trait Mailer: Send + Sync {
    /// Content side, borrowed from the embedded `MailCommon`.
    fn common(&self) -> &MailCommon;

    /// Transport side: deliver `html` (already rendered by `email.rs`) to
    /// `to`. A boxed `Send` future keeps the trait object-safe on the
    /// pinned toolchain (no `async fn in trait`).
    fn send<'a>(&'a self, to: &'a str, subject: &'a str, html: &'a str)
        -> BoxFuture<'a, anyhow::Result<()>>;
}
```

Each backend embeds `MailCommon` and implements `send`. `render_email` stays in
`email.rs`: it reads `mailer.common()` + `build_magic_link` + the shared Tera
template, so the ceremony builds content identically regardless of backend.
Each impl is `Send + Sync` so a `Box<dyn Mailer>` can be built **under** the
tenant guard and carried across the guard-drop boundary into phase 2 (H6/G-153).

### Backends

**`ResendMailer { from, key, base_url, http }`** — moves today's `send()`
(`email.rs:268`) + `describe_resend_error()` (`email.rs:314`) verbatim into the impl.
`http` is `crate::utils::outbound_http_client()` (the H6 bounded-timeout client).
`base_url` keeps the existing test/proxy override. No behaviour change.

**`ZonemailMailer { base_url, from, api_token: Option<String>, http }`** —
`POST {base_url}/mail` on the shared HTTP client. Zonemail's wire contract is
*Janux's own* envelope (`ApiResponse`/`ApiProblem`), so parsing is trivial.

- Request `SendEmail` (from Zonemail `src/api.rs`):
  ```json
  {
    "from": "<from>",
    "to": ["<to>"],
    "subject": "<subject>",
    "body": "<html>",
    "content_type": "text/html"
  }
  ```
  (`cc`/`bcc` optional; unused here — one recipient per ceremony.)
- Success: `200 { "ok": true, "data": { "message_id", "outbound_ids" } }` — the
  message is **enqueued**, not delivered synchronously, so `send` returns fast and
  never pins the tenant guard (better than Resend's synchronous hop).
- Failure: non-2xx `ApiProblem { status, type, detail }` → `anyhow!(detail)`.
- `api_token`: optional bearer. Zonemail's API is open by default (config-gated JWT,
  `enabled=false`); when an operator enables auth, present `api_token` as
  `Authorization: Bearer …`.
- **Operator pre-requisite**: the `from` address must be a provisioned mailbox on the
  Zonemail instance (`POST /mail` 409s otherwise — `Outbound.sender_id` is a
  non-nullable FK). Document this in the seed/example.

**`SmtpRelayMailer { from, host, port, user: Option, password: Option, tls, insecure }`**
— a relay-only `lettre` client. TLS modes mirror Zonemail's `[outbound]` table:

| `tls` | meaning |
|---|---|
| `plain` | clear text on `port` (default `587`) |
| `opportunistic` | STARTTLS if advertised, else clear text (dev/test only) |
| `required` | STARTTLS mandatory (MITM-safe) |
| `implicit` | SMTPS / implicit-TLS from connect (conventional `465`) |

`insecure` (default `false`, dev-only) accepts certs that fail verification — mirrors
Zonemail; **never in production**. The peer cert is verified against the system trust
store for `host` unless `insecure`. No DNS/MX resolution (relay-only).

---

## 2. Config & selection

Per-backend DTOs in `config.rs`, mirroring `ResendDTO` (each carries
`from`/`template`/`verify_url` + its transport fields). Send-capable secrets
(`resend.key`, `zonemail.api_token`, `smtp.password`) are stored encrypted via
`crypto::encrypt_secret`, loaded via `decrypt_secret_or_legacy` — the exact
`ResendDTO` pattern.

| backend | config keys |
|---|---|
| resend | `resend.from` `resend.key` `resend.template` `resend.verify_url` `resend.base_url` (unchanged) |
| zonemail | `zonemail.base_url` `zonemail.from` `zonemail.template` `zonemail.verify_url` `zonemail.api_token` |
| smtp-relay | `smtp.host` `smtp.port` `smtp.from` `smtp.template` `smtp.verify_url` `smtp.user` `smtp.password` `smtp.tls` `smtp.insecure` |

```rust
// src/mailer.rs
/// Build the tenant's active mailer, or `None` when no backend is configured
/// (the email factor then stays off — the pre-feature default).
pub async fn build_mailer(tenant: &mut Tenant) -> Option<Box<dyn Mailer>> {
    // explicit selector wins; else first-present by fixed priority.
}
```

**Selection**: an optional `mail.backend` key (`"resend"` | `"zonemail"` | `"smtp"`)
forces a backend when set; otherwise **first-configured-wins by fixed priority
`resend → zonemail → smtp`**. Migration-free: an existing tenant with only `resend.*`
keeps using Resend via the fallback priority. (Alternative — drop the priority fallback
and require `mail.backend` — noted as a refinement; the fallback is the
migration-friendly default.)

---

## 3. Gate & two-phase rewire

The email factor turns on when *any* backend is configured.

- **Gate** — `oidc.rs:767`:
  `if crate::config::ResendDTO::load(&mut tenant).await.is_some()`
  → `if crate::mailer::build_mailer(&mut tenant).await.is_some()`.

- **Magic link** — `prepare_magic_link` (`email.rs:438`) / `dispatch_magic_link`
  (`email.rs:482`): phase 1 (under guard) builds the mailer via `build_mailer` and
  renders content (`mailer.render(…)` over the `build_magic_link` output); returns
  `Box<dyn Mailer>` + `subject` + `content` to phase 2, which calls
  `mailer.send(to, subject, content)`. The free `send()` / `describe_resend_error()`
  become `ResendMailer` methods; `render_email` moves into each backend's `render`
  (shared `tera` template — `get_template` + `Template` embed stay in `email.rs`).

- **Email add** — `prepare_add_email_ceremony` (`email.rs:1007`) /
  `deliver_add_email_ceremony` (`email.rs:1053`): `PreparedAddMail.cfg: ResendDTO`
  → `mailer: Box<dyn Mailer>`; same two-phase shape.

---

## 4. Dependencies

- Add `lettre` for the SMTP relay client (added):
  `lettre = { version = "0.11", default-features = false, features =
  ["builder", "smtp-transport", "tokio1", "tokio1-native-tls"] }`
  (`builder` for the fluent `EmailBuilder`, `smtp-transport` for
  `SmtpTransport`/`SmtpTransportOptions`; `native-tls` is already in the tree
  via mysql and matches Zonemail's `native_tls::Identity`; the rustls backend
  is the alternative).
- `reqwest` is already a dependency — Zonemail + Resend HTTP reuse it.
- **No DNS crate** — relay-only means no MX resolution in Janux.

---

## 5. Secrets & dump

- `zonemail.api_token` and `smtp.password` are send-capable → encrypted at rest,
  same as `resend_key`.
- `dump.rs`: extend `MailEntry` / `load_mail` to report the active backend and redact
  the new secrets like `resend_key` / `client_secret` (redacted unless `--secrets`).

---

## 6. Tests

- Keep the existing Resend `base_url` mock path.
- `ZonemailMailer`: assert the `/mail` request shape
  (`{from, to, subject, body, content_type:"text/html"}`) + `ApiResponse.ok`
  against a loopback mock (mirror the mock-Resend server).
- `SmtpRelayMailer`: loopback SMTP sink (mirror Zonemail's `scripts/e2e.sh` TCP-sink
  pattern); cover `plain` / `required` / `implicit` + an `insecure` rejection.
- `build_mailer`: selection by `mail.backend` and by fixed priority; `None` when
  nothing is configured.
- Frontend magic-link e2e unchanged.

---

## 7. Migration / cutover

1. Add `src/mailer.rs` (trait + `build_mailer`) and the `ZonemailDTO` / `SmtpRelayDTO`
   in `config.rs`; move `ResendMailer` from `email.rs`.
2. Rewire the two ceremonies + the `oidc.rs` gate to `build_mailer`/`mailer.send`.
3. `smtp`/`zonemail` config keys + seed/example TOML (Zonemail `from`-must-be-provisioned
   note); `dump.rs` entries + redaction.
4. `lettre` dep; tests; `cargo fmt`; `just test`.
5. Update `janux-agent/REF.md` + changelog: email factor now available via Resend
   **or** Zonemail **or** SMTP relay; no Resend dependency required.

**Open decisions** (defaults chosen above; confirm or override):
- Selection: explicit `mail.backend` + fixed-priority fallback (chosen) vs. required
  `mail.backend` (stricter, no migration story).
- `lettre` TLS backend: `native-tls` (chosen, matches tree + Zonemail) vs. `rustls`.
