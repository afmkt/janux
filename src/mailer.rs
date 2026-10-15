//! Mail delivery backends (G-mailer).
//!
//! The email factor ships its ceremony email through one of three pluggable
//! backends, selected by [`build_mailer`]:
//!
//! * **Resend** — the existing SaaS API (`api.resend.com`), the zero-config
//!   hosted path.
//! * **Zonemail** — a self-hosted DNS+SMTP stack
//!   (github.com/afmkt/zonemail); Janux POSTs `/{base_url}/mail`, which
//!   enqueues a durable delivery job — the fast, non-blocking path.
//! * **SMTP relay** — a built-in fallback that hands the message to an
//!   operator-configured `host:port` (optionally authenticated), never to a
//!   recipient's MX.
//!
//! Every backend delivers the *same* rendered email, so the ceremony, the
//! link, and the UI are backend-agnostic — adding a backend is a `Mailer`
//! impl plus config, not a new ceremony.
//!
//! The `Mailer` trait boxes its future so it can be held as `Box<dyn Mailer>`
//! across the tenant-guard drop in the two-phase ceremony (H6) — `async fn`
//! in a trait is not yet `dyn`-compatible.

use crate::config::{ResendDTO, SmtpRelayDTO, SmtpTls, ZonemailDTO};
use crate::db::Tenant;
use resend_rs::types::CreateEmailBaseOptions;
use resend_rs::*;

/// A boxed, `Send` ceremony-send future — the object-safe form of
/// `async fn send` (which is not yet `dyn`-compatible).
type SendFuture<'a> = std::pin::Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>>;

/// The backend-agnostic fields shared by every mailer: the sending address,
/// the Tera template for the body, and the verify URL the magic link points
/// at. The ceremony renders the body from `from`+`template` and the link from
/// `verify_url`, then hands the result to whichever backend is selected.
#[derive(Debug, Clone)]
pub struct MailCommon {
    pub from: String,
    pub template: String,
    pub verify_url: String,
}

/// A mail delivery backend. One impl per transport; the ceremony never names a
/// backend — [`build_mailer`] does.
pub trait Mailer: Send + Sync {
    /// The shared render fields (`from`/`template`/`verify_url`).
    fn common(&self) -> &MailCommon;
    /// Deliver a rendered email to `to`.
    fn send<'a>(&'a self, to: &'a str, subject: &'a str, html: &'a str) -> SendFuture<'a>;
}

/// The Resend SaaS backend — the historical default.
pub struct ResendMailer {
    common: MailCommon,
    api_key: String,
    base_url: Option<String>,
}

impl Mailer for ResendMailer {
    fn common(&self) -> &MailCommon {
        &self.common
    }
    fn send<'a>(&'a self, to: &'a str, subject: &'a str, html: &'a str) -> SendFuture<'a> {
        Box::pin(async move {
            // An optional base_url override of the official Resend endpoint — a
            // proxy in production, a mock server in tests. H6: both branches run
            // on the bounded-timeout shared client, so a hung Resend (or proxy)
            // peer cannot pin the caller for the network's entire lifetime.
            let http = crate::utils::outbound_http_client();
            let resend = match self.base_url.as_deref() {
                Some(url) => {
                    let cfg = resend_rs::ConfigBuilder::new(self.api_key.as_str())
                        .base_url(url.parse()?)
                        .client(http)
                        .build();
                    Resend::with_config(cfg)
                }
                None => {
                    let cfg = resend_rs::ConfigBuilder::new(self.api_key.as_str())
                        .client(http)
                        .build();
                    Resend::with_config(cfg)
                }
            };
            let email = CreateEmailBaseOptions::new(self.common.from.clone(), vec![to], subject)
                .with_html(html);
            let response = resend.emails.send(email).await;
            // Surface the Resend-side reason (status + body) in the console — the
            // failure is otherwise swallowed downstream into a bare "Fail to send
            // email", leaving nothing to act on.
            if let Err(e) = &response {
                tracing::error!(
                    from = %self.common.from,
                    to,
                    error = %format!("{e:#}"),
                    "Magic-link email failed to send via Resend"
                );
            }
            if let Err(e) = response {
                return Err(anyhow::anyhow!(describe_resend_error(&e)));
            }
            Ok(())
        })
    }
}

/// The Zonemail self-hosted backend. Janux POSTs `/{base_url}/mail` (Zonemail
/// enqueues a durable delivery job — the fast, non-blocking path). Its wire
/// contract is janux's own `{ ok, data }` envelope, so a `false`/error status
/// carries the `detail`.
pub struct ZonemailMailer {
    common: MailCommon,
    base_url: String,
    api_token: Option<String>,
}

impl Mailer for ZonemailMailer {
    fn common(&self) -> &MailCommon {
        &self.common
    }
    fn send<'a>(&'a self, to: &'a str, subject: &'a str, html: &'a str) -> SendFuture<'a> {
        Box::pin(async move {
            let url = format!("{}/mail", self.base_url.trim_end_matches('/'));
            let mut builder = crate::utils::outbound_http_client()
                .post(url.as_str())
                .json(&serde_json::json!({
                    "from": &self.common.from,
                    "to": [to],
                    "subject": subject,
                    "body": html,
                    "content_type": "text/html",
                }));
            if let Some(token) = &self.api_token {
                builder = builder.header("Authorization", format!("Bearer {token}"));
            }
            let res = builder.send().await?;
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            // Zonemail speaks janux's `{ ok, data }` envelope; a `false` (even
            // on a 2xx) is a rejection we must surface, and a non-2xx carries
            // the raw body.
            let parsed = serde_json::from_str::<serde_json::Value>(&text).ok();
            if let Some(false) = parsed
                .as_ref()
                .and_then(|v| v.get("ok"))
                .and_then(|v| v.as_bool())
            {
                let detail = parsed
                    .as_ref()
                    .and_then(|v| v.get("detail"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                return Err(anyhow::anyhow!(
                    "[Zonemail] rejected the send: HTTP {status}, detail={detail}"
                ));
            }
            if !status.is_success() {
                return Err(anyhow::anyhow!(
                    "[Zonemail] send failed: HTTP {status}, {text}"
                ));
            }
            Ok(())
        })
    }
}

/// The built-in SMTP relay fallback (via `lettre`). Hands the message to an
/// operator-configured `host:port` (optionally authenticated, STARTTLS by
/// default) — never to a recipient's MX. Delivery reputation / MX resolution
/// belong to a Zonemail instance, not to an auth server, so this is the
/// lowest-friction option for a relay you control.
pub struct SmtpRelayMailer {
    common: MailCommon,
    host: String,
    port: u16,
    tls: SmtpTls,
    insecure: bool,
    user: Option<String>,
    password: Option<String>,
}

impl Mailer for SmtpRelayMailer {
    fn common(&self) -> &MailCommon {
        &self.common
    }
    fn send<'a>(&'a self, to: &'a str, subject: &'a str, html: &'a str) -> SendFuture<'a> {
        Box::pin(async move {
            use lettre::message::header::ContentType;
            use lettre::transport::AsyncTransport;
            use lettre::transport::smtp::AsyncSmtpTransport;
            use lettre::transport::smtp::authentication::Credentials;
            use lettre::transport::smtp::client::{Tls, TlsParameters};
            use lettre::{Message, Tokio1Executor};

            // `builder_dangerous` skips DNS resolution so the operator's
            // `host:port` is used verbatim — a relay address, not an MX lookup.
            let tls_params = TlsParameters::builder(self.host.clone())
                .dangerous_accept_invalid_certs(self.insecure)
                .build()
                .map_err(|e| anyhow::anyhow!("[SMTP] tls: {e}"))?;
            let base = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(self.host.as_str())
                .port(self.port);
            let builder = match self.tls {
                SmtpTls::Plain => base.tls(Tls::None),
                SmtpTls::Opportunistic => base.tls(Tls::Opportunistic(tls_params)),
                SmtpTls::Required => base.tls(Tls::Required(tls_params)),
                SmtpTls::Implicit => base.tls(Tls::Wrapper(tls_params)),
            };
            let builder = if let (Some(user), Some(password)) =
                (self.user.as_deref(), self.password.as_deref())
            {
                builder.credentials(Credentials::new(user.to_string(), password.to_string()))
            } else {
                builder
            };
            let transport = builder.build();
            let message = Message::builder()
                .from(
                    self.common
                        .from
                        .parse()
                        .map_err(|e| anyhow::anyhow!("[SMTP] from: {e}"))?,
                )
                .to(to.parse().map_err(|e| anyhow::anyhow!("[SMTP] to: {e}"))?)
                .subject(subject)
                .header(ContentType::TEXT_HTML)
                .body(html.to_string())
                .map_err(|e| anyhow::anyhow!("[SMTP] build: {e}"))?;
            transport
                .send(message)
                .await
                .map_err(|e| anyhow::anyhow!("[SMTP] send: {e}"))?;
            Ok(())
        })
    }
}

/// Select a mail backend for the tenant. `mail.backend` forces one
/// (`"resend"`/`"zonemail"`/`"smtp"`); otherwise the first *configured*
/// backend wins in the order `resend → zonemail → smtp`. Returns `None` when
/// no backend is configured — the email factor is then unavailable.
pub async fn build_mailer(tenant: &mut Tenant) -> Option<Box<dyn Mailer>> {
    let backend = tenant
        .config_get(crate::config::MAIL_BACKEND)
        .await
        .and_then(|v| v.as_str().map(str::to_ascii_lowercase));
    let order: Vec<&str> = match backend.as_deref() {
        Some(b) => vec![b],
        None => vec!["resend", "zonemail", "smtp"],
    };
    for name in order {
        match name {
            "resend" => {
                let Some(dto) = ResendDTO::load(tenant).await else {
                    continue;
                };
                return Some(Box::new(ResendMailer {
                    common: MailCommon {
                        from: dto.from,
                        template: dto.template,
                        verify_url: dto.verify_url,
                    },
                    api_key: dto.resend_key,
                    base_url: dto.base_url,
                }));
            }
            "zonemail" => {
                let Some(dto) = ZonemailDTO::load(tenant).await else {
                    continue;
                };
                return Some(Box::new(ZonemailMailer {
                    common: MailCommon {
                        from: dto.from,
                        template: dto.template,
                        verify_url: dto.verify_url,
                    },
                    base_url: dto.base_url,
                    api_token: dto.api_token,
                }));
            }
            "smtp" => {
                let Some(dto) = SmtpRelayDTO::load(tenant).await else {
                    continue;
                };
                return Some(Box::new(SmtpRelayMailer {
                    common: MailCommon {
                        from: dto.from,
                        template: dto.template,
                        verify_url: dto.verify_url,
                    },
                    host: dto.host,
                    port: dto.port,
                    tls: dto.tls,
                    insecure: dto.insecure,
                    user: dto.user,
                    password: dto.password,
                }));
            }
            other => {
                tracing::warn!(mail_backend = %other, "unknown mail.backend - skipping");
            }
        }
    }
    None
}

/// Map a `resend-rs` error to a single message that leads with an actionable
/// hint but keeps the raw Resend response (status + name + body) intact, so
/// email failures are both *diagnosable* and never silently collapsed to a
/// bare "Fail to send email".
fn describe_resend_error(err: &resend_rs::Error) -> String {
    match err {
        resend_rs::Error::Resend(resp) => {
            let hint = match resp.status_code {
                401 => "Invalid or revoked Resend API key - check `resend_key` in your seed/config",
                403 => {
                    "Resend refused the send - the `from` domain is usually not verified or not \
                     authorized on your Resend account"
                }
                400 | 422 => {
                    "Resend rejected the request - check `from`/`to` and your account mode (test \
                   mode only delivers to test@resend.dev)"
                }
                429 => "Resend rate limit exceeded - send less often or check your plan",
                500..=599 => "Resend-side error - resend.com may be degraded; try again shortly",
                other => return format!("Resend HTTP {other}: {}", resp.message),
            };
            if resp.message.trim().is_empty() {
                format!("{hint} (HTTP {} {})", resp.status_code, resp.name)
            } else {
                format!(
                    "{hint} (HTTP {} {}): {}",
                    resp.status_code, resp.name, resp.message,
                )
            }
        }
        resend_rs::Error::Http(req_err) => format!(
            "Could not reach Resend - check outbound network / `resend.base_url`: {req_err}"
        ),
        resend_rs::Error::RateLimit {
            ratelimit_limit,
            ratelimit_reset,
            ..
        } => {
            let limit = ratelimit_limit
                .map(|n| n.to_string())
                .unwrap_or_else(|| "?".to_string());
            let seconds = ratelimit_reset
                .map(|n| n.to_string())
                .unwrap_or_else(|| "?".to_string());
            format!("Resend rate limit exceeded - {limit} requests / {seconds}s")
        }
        resend_rs::Error::Parse { message, .. } => {
            format!("Resend returned an unparseable response: {message}")
        }
        resend_rs::Error::Other(msg) => msg.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// regression: a failed Resend send must surface an *actionable* hint and
    /// the *raw* Resend response (status + name + body), not just the bare
    /// "Fail to send email". This is the unverified-`from`-domain case.
    #[test]
    fn describe_resend_error_keeps_hint_and_raw_body() {
        use resend_rs::types::ErrorResponse;
        let err = resend_rs::Error::Resend(ErrorResponse {
            status_code: 403,
            message: "The gmail.com domain is not verified. Please, add and verify your domain."
                .to_string(),
            name: "validation_error".to_string(),
        });

        let msg = describe_resend_error(&err);
        // actionable: points at the likely cause
        assert!(
            msg.contains("not verified"),
            "actionable hint missing from: {msg}"
        );
        // raw: the actual Resend status + name + body are preserved
        assert!(msg.contains("HTTP 403"), "status missing from: {msg}");
        assert!(
            msg.contains("validation_error"),
            "resend 'name' missing from: {msg}"
        );
        assert!(
            msg.contains("gmail.com domain is not verified"),
            "resend body missing from: {msg}"
        );
    }

    #[test]
    fn describe_resend_error_maps_401_to_key_hint() {
        use resend_rs::types::ErrorResponse;
        let err = resend_rs::Error::Resend(ErrorResponse {
            status_code: 401,
            message: "API key is invalid".to_string(),
            name: "invalid_api_key".to_string(),
        });
        let msg = describe_resend_error(&err);
        assert!(msg.contains("API key"), "401 hint missing from: {msg}");
        assert!(
            msg.contains("API key is invalid"),
            "raw body missing from: {msg}"
        );
    }

    #[test]
    fn smtp_tls_round_trips_through_parse_and_display() {
        for s in ["plain", "opportunistic", "required", "implicit"] {
            let t = SmtpTls::parse(s).expect("parses");
            assert_eq!(t.to_string(), s);
        }
        assert_eq!(
            SmtpTls::parse("bogus"),
            None,
            "unknown tls mode is rejected"
        );
        // The secure default: a self-hoster that omits `tls` gets STARTTLS,
        // never clear text.
        assert_eq!(SmtpTls::default(), SmtpTls::Required);
    }

    /// A minimal HTTP server that replies with a fixed JSON body — stands in
    /// for a Zonemail `/mail` endpoint in tests. Returns the base URL and a
    /// buffer the test inspects to assert the request shape.
    async fn spawn_mock(body: &str) -> (String, std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock");
        let addr = listener.local_addr().expect("mock addr");
        let body = std::sync::Arc::new(body.to_string());
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured_tx = captured.clone();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let body = body.clone();
                let captured = captured_tx.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        let n = sock.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let headers = String::from_utf8_lossy(&buf[..pos]).to_lowercase();
                            let content_length = headers
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length:"))
                                .and_then(|v| v.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            if buf.len() >= pos + 4 + content_length {
                                break;
                            }
                        }
                    }
                    {
                        let mut guard = captured.lock().expect("mock capture lock");
                        guard.push(buf.clone());
                    }
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        (format!("http://{addr}"), captured)
    }

    fn zonemail(base_url: &str) -> ZonemailMailer {
        ZonemailMailer {
            common: MailCommon {
                from: "noreply@example.com".to_string(),
                template: "verify.html".to_string(),
                verify_url: "http://localhost/login".to_string(),
            },
            base_url: base_url.to_string(),
            api_token: None,
        }
    }

    /// Zonemail accepts its `{ ok: true }` envelope — the send succeeds.
    #[tokio::test]
    async fn zonemail_send_accepts_ok_envelope() {
        let (base, _captured) = spawn_mock(r#"{"ok":true}"#).await;
        let mailer = zonemail(&base);
        mailer
            .send("to@example.com", "hi", "<p>body</p>")
            .await
            .expect("ok envelope should succeed");
    }

    /// A Zonemail `{ ok: false, detail }` rejection must surface the detail —
    /// the ceremony turns it into an actionable failure, not a silent drop.
    #[tokio::test]
    async fn zonemail_send_surfaces_rejection_detail() {
        let (base, _captured) = spawn_mock(r#"{"ok":false,"detail":"quota exceeded"}"#).await;
        let mailer = zonemail(&base);
        let err = mailer
            .send("to@example.com", "hi", "<p>body</p>")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("quota exceeded"),
            "the rejection detail must surface: {err}"
        );
    }

    /// Zonemail's `/mail` request is the `{from, to[], subject, body,
    /// content_type}` envelope — a one-recipient array, `text/html` body.
    #[tokio::test]
    async fn zonemail_posts_the_envelope_shape() {
        let (base, captured) = spawn_mock(r#"{"ok":true}"#).await;
        let mailer = zonemail(&base);
        mailer
            .send("to@example.com", "hi", "<p>body</p>")
            .await
            .expect("ok envelope should succeed");
        // The mock is fire-and-forget; give it a beat to record the request.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let raw = captured.lock().expect("mock capture lock")[0].clone();
        // Split the raw HTTP request at the header/body boundary.
        let body = String::from_utf8_lossy(
            &raw[raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4..],
        );
        let v: serde_json::Value = serde_json::from_str(&body).expect("request body is JSON");
        assert_eq!(v["from"], "noreply@example.com");
        assert_eq!(v["to"], serde_json::json!(["to@example.com"]));
        assert_eq!(v["subject"], "hi");
        assert_eq!(v["body"], "<p>body</p>");
        assert_eq!(v["content_type"], "text/html");
    }
}
