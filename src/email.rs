use crate::cache::EphemCache;
use crate::config::ResendDTO;
use crate::db::AuthType;
use crate::db::JwtVerify;
use crate::db::Tenant;
use crate::server::ServerState;
use crate::user::User;
use crate::utils::{ApiProblem, ApiResponse};

use crate::utils::extract;
use anyhow::Result;
use dashmap::mapref::one::RefMut;
use resend_rs::types::CreateEmailBaseOptions;
use resend_rs::*;
use rust_embed::RustEmbed;
use salvo::http::cookie::{Cookie, SameSite};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::LazyLock;
use tera::Tera;
use toasty::*;
use url::Url;

#[derive(Debug, toasty::Model, Clone)]
pub struct Email {
    #[key]
    pub id: String,

    #[index]
    pub user_id: uuid::Uuid,

    /// Whether ownership of the address was ever proven to this IdP: a
    /// magic-link ceremony completed here, or an upstream IdP asserted
    /// `email_verified` during social provisioning. SCIM/admin-provisioned
    /// addresses start `false`. `/userinfo` reports this value verbatim as
    /// the `email_verified` claim (M3) — RPs doing email-based account
    /// linking must not see `true` for an address nobody proved control of.
    pub verified: bool,

    #[auto]
    pub created_at: jiff::Timestamp,
    #[auto]
    pub updated_at: jiff::Timestamp,

    #[belongs_to(key = user_id, references = id)]
    pub user: Deferred<User>,
}

/// Module-level cache for magic link login (token -> username).
pub static MLINK_CACHE: LazyLock<EphemCache<String, String>> =
    LazyLock::new(|| EphemCache::new("magic_link_tokens", Some(900)));

impl Tenant {
    /// Strict signup: create the user within this ceremony and
    /// attach the email to it. Fails when the username pre-exists, so the
    /// credential is never attached to a user this ceremony did not create.
    /// All-or-nothing: if the attach fails (e.g. the email was claimed by
    /// another user between `request` and `verify`), the just-created user
    /// is rolled back so the username is not burned by an orphan row.
    pub async fn signup_user_email(&mut self, user_name: &str, email: &str) -> Result<()> {
        // G-99: signup provisioning grants the builtin `guest` floor.
        self.signup_provision(user_name).await?;
        // The completed magic-link ceremony proved ownership of the address.
        if let Err(e) = self.email_create_verified(user_name, email).await {
            // System-initiated rollback — 's gate does not apply.
            self.user_delete(&crate::role::Caller::Bootstrap, user_name)
                .await
                .ok();
            return Err(e);
        }
        Ok(())
    }

    /// Strict signin: the email must already belong to `user_name`.
    /// Nothing is attached. The completed magic-link ceremony is a fresh
    /// proof of ownership, so an unverified row (SCIM-provisioned or a
    /// pre-M3 legacy row) converges to verified here.
    pub async fn signin_user_email(&mut self, user_name: &str, email: &str) -> Result<()> {
        let user = self.user_by_email(email).await?;
        if user.name != user_name {
            return Err(anyhow::anyhow!("Email does not belong to this user"));
        }
        self.email_mark_verified(email).await?;
        Ok(())
    }
    pub async fn all_emails(&mut self, username: Option<&str>) -> Result<Vec<Email>> {
        if let Some(user_name) = username {
            let user = self.user(user_name).await?;
            Email::filter(Email::fields().user_id().eq(user.id))
                .exec(&mut self.database)
                .await
                .map_err(Into::into)
        } else {
            Email::all()
                .exec(&mut self.database)
                .await
                .map_err(Into::into)
        }
    }

    /// Attach an email WITHOUT an ownership proof (SCIM/admin provisioning).
    /// The row starts unverified, so `/userinfo` reports
    /// `email_verified: false` for it (M3). Re-attaching an address the same
    /// user already owns is an idempotent no-op — it never downgrades a
    /// verified row.
    pub async fn email_create(&mut self, user_name: &str, email: &str) -> Result<()> {
        self.email_create_inner(user_name, email, false).await
    }

    /// Attach an email AFTER ownership was proven — a completed magic-link
    /// ceremony here, or an upstream IdP that asserted `email_verified`
    /// during social provisioning. Re-attaching an address the same user
    /// already owns UPGRADES it to verified: the self-service convergence
    /// path for SCIM-provisioned and pre-M3 legacy rows.
    pub async fn email_create_verified(&mut self, user_name: &str, email: &str) -> Result<()> {
        self.email_create_inner(user_name, email, true).await
    }

    async fn email_create_inner(
        &mut self,
        user_name: &str,
        email: &str,
        verified: bool,
    ) -> Result<()> {
        // G-105: canonicalize at the data layer — the single choke point
        // where every attach path (signup, add flow, admin vouch, social
        // provisioning, SCIM) agrees on ONE spelling per mailbox. ASCII
        // case-fold + trim; the ceremony already proved deliverability,
        // so there is no syntax policing here.
        let email = email.trim().to_lowercase();
        let user = self.user(user_name).await?;
        match Email::get_by_id(&mut self.database, &email).await {
            Ok(e) => {
                if e.user_id != user.id {
                    Err(anyhow::anyhow!("Email already exist"))
                } else {
                    if verified && !e.verified {
                        self.email_mark_verified(&email).await?;
                    }
                    Ok(())
                }
            }
            Err(_) => toasty::create!(Email {
                id: email,
                user_id: user.id,
                verified,
            })
            .exec(&mut self.database)
            .await
            .map(|_| ())
            .map_err(Into::into),
        }
    }

    /// Flip an existing row to verified. Update-only: a missing row is a
    /// no-op, so this can never attach an address nobody owns. Called when a
    /// magic-link signin proves ownership of an already-attached address —
    /// legacy and SCIM-provisioned rows converge to verified on the next
    /// successful ceremony (M3).
    pub async fn email_mark_verified(&mut self, email: &str) -> Result<()> {
        // G-105: fold so a mixed-case ceremony email converges the
        // canonically-stored row.
        let email = email.trim().to_lowercase();
        match Email::get_by_id(&mut self.database, &email).await {
            Ok(e) if !e.verified => Email::update_by_id(&email)
                .verified(true)
                .exec(&mut self.database)
                .await
                .map(|_| ())
                .map_err(Into::into),
            Ok(_) => Ok(()),
            Err(_) => Ok(()),
        }
    }

    /// Owner-scoped variant of [`email_mark_verified`]: flips the row only
    /// when `user_id` owns it. Used where a third-party assertion (an
    /// upstream IdP's `email_verified` on a repeat social login) re-attests
    /// an address — the attestation applies to the account that logged in,
    /// never to another user's row holding the same address (M3).
    pub async fn email_mark_verified_for(
        &mut self,
        user_id: uuid::Uuid,
        email: &str,
    ) -> Result<()> {
        let email = email.trim().to_lowercase(); // G-105
        match Email::get_by_id(&mut self.database, &email).await {
            Ok(e) if e.user_id == user_id && !e.verified => Email::update_by_id(&email)
                .verified(true)
                .exec(&mut self.database)
                .await
                .map(|_| ())
                .map_err(Into::into),
            Ok(_) => Ok(()),
            Err(_) => Ok(()),
        }
    }
    pub async fn email_delete(&mut self, user_name: &str, email: &str) -> Result<()> {
        let email = email.trim().to_lowercase(); // G-105
        let user = self.user(user_name).await?;
        Email::filter(
            Email::fields()
                .id()
                .eq(email)
                .and(Email::fields().user_id().eq(user.id)),
        )
        .delete()
        .exec(&mut self.database)
        .await
        .map(|_| ())
        .map_err(Into::into)
    }
}

#[derive(Deserialize, Serialize, Debug, ToSchema)]
struct ReqRequest {
    name: String,
    email: String,
    /// Return context parked on the login page: an in-flight OIDC
    /// `/authorize` (client_id + state) or a plain same-origin redirect.
    /// Embedded in the emailed link so the magic-link round-trip can resume
    /// it after verify — safe because resume/redirect targets are validated
    /// server-side (parked authorize) or same-origin-checked client-side.
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
}

#[derive(Deserialize, Debug, ToSchema)]
struct VerifyRequest {
    token: String,
    name: String,
    email: String,
    cookie: Option<String>,
    /// Requested session lifetime in seconds (G-90), clamped to the
    /// 15-minute ceiling — a caller may shorten its session, never
    /// lengthen it. Omitted → 15 minutes.
    #[serde(default)]
    lifetime: Option<i64>,
}

/// Payload of the 15-minute magic-link JWT. A struct (not a bare `String`)
/// because the claim's `data` field is `#[serde(flatten)]`, which can only
/// serialize maps.
///
/// `signup` fixes the ceremony mode at `request` time: `verify`
/// enforces the recorded mode instead of re-deriving it from DB state that
/// may have changed during the token's lifetime. Tokens minted before this
/// field existed deserialize with `signup = false` — signin-only — which
/// fails closed for the old signup-attach attack.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct MagicLinkData {
    email: String,
    #[serde(default)]
    signup: bool,
}

#[derive(Deserialize, Serialize, Debug, ToSchema)]
struct EmailResponse {
    ok: bool,
    code: u16,
    msg: String,
    jwt: Option<String>,
}

async fn send(config: &ResendDTO, to: &str, subject: &str, content: &str) -> anyhow::Result<()> {
    // An optional base_url override the official Resend endpoint — a proxy
    // in production, a mock server in tests.
    // H6: both branches run on the bounded-timeout shared client, so a
    // hung Resend (or proxy) peer cannot pin the email request handler —
    // and the tenant write guard it holds — indefinitely.
    let http = crate::utils::outbound_http_client();
    let resend = match config.base_url.as_deref() {
        Some(url) => {
            let cfg = resend_rs::ConfigBuilder::new(config.resend_key.as_str())
                .base_url(url.parse()?)
                .client(http)
                .build();
            Resend::with_config(cfg)
        }
        None => {
            let cfg = resend_rs::ConfigBuilder::new(config.resend_key.as_str())
                .client(http)
                .build();
            Resend::with_config(cfg)
        }
    };
    let email =
        CreateEmailBaseOptions::new(config.from.clone(), vec![to], subject).with_html(content);
    let _response = resend.emails.send(email).await?;

    Ok(())
}

#[derive(RustEmbed)]
#[folder = "./template/email/"]
struct Template;

fn get_template(path: &str) -> String {
    if let Ok(content) = fs::read_to_string(path) {
        return content;
    }
    let file =
        Template::get("verify.html").expect("Template not found in disk OR embedded storage");
    String::from_utf8(file.data.into_owned()).expect("Embedded template is not valid UTF-8")
}

fn render_email(config: &ResendDTO, to: &str, subject: &str, link: &str) -> anyhow::Result<String> {
    let mut tera = Tera::new();
    let template = get_template(&config.template);
    tera.add_raw_template("email", &template)?;

    let mut context = tera::Context::new();
    context.insert("link", link);
    context.insert("subject", subject);
    context.insert("from", &config.from);
    context.insert("to", to);
    tera.render("email", &context).map_err(Into::into)
}

/// Return context the magic link carries through the email hop.
#[derive(Default)]
struct MagicLinkContext<'a> {
    client_id: Option<&'a str>,
    state: Option<&'a str>,
    redirect_uri: Option<&'a str>,
    /// Marks the link's ceremony for the landing page: `Some("add")` tells
    /// the hosted SPA to complete an email-ADD verification (session-gated
    /// `email/add/verify`) instead of a login (G-162: without it the SPA
    /// had no way to tell the two link kinds apart).
    flow: Option<&'a str>,
}

/// Build the magic link: the ceremony halves (token/username/email)
/// plus the login page's parked return context, so the round-trip can
/// resume a parked `/authorize` or same-origin redirect after verify.
fn build_magic_link(
    verify_url: &str,
    token: &str,
    user_name: &str,
    email: &str,
    ctx: MagicLinkContext<'_>,
) -> Result<Url, url::ParseError> {
    let mut link = Url::parse(verify_url)?;
    let mut q = link.query_pairs_mut();
    q.append_pair("token", token)
        .append_pair("username", user_name)
        .append_pair("email", email);
    if let Some(v) = ctx.client_id {
        q.append_pair("client_id", v);
    }
    if let Some(v) = ctx.state {
        q.append_pair("state", v);
    }
    if let Some(v) = ctx.redirect_uri {
        q.append_pair("redirect_uri", v);
    }
    if let Some(v) = ctx.flow {
        q.append_pair("flow", v);
    }
    drop(q);
    Ok(link)
}

/// Phase 1 of the magic-link ceremony — runs WHILE the tenant guard is
/// held: mint the ceremony JWT, load the Resend config, render the link
/// and the email body. Local-only, no network. Returns everything phase 2
/// needs, including the resolved `user_name` the verify cache maps to.
#[allow(clippy::too_many_arguments)]
async fn prepare_magic_link<'a>(
    tenant: &mut RefMut<'a, String, Tenant>,
    issuer: &str,
    domain: &str,
    user_name: String,
    email: String,
    signup: bool,
    ctx: MagicLinkContext<'_>,
) -> Result<(String, String, ResendDTO, String, String), String> {
    let token = tenant
        .jwt_authenticate(
            issuer,
            domain,
            &user_name,
            &MagicLinkData {
                email: email.clone(),
                signup,
            },
            15,
        )
        .await
        .map_err(|_| "Fail to issue JWT".to_string())?;
    let subject = "Janux login".to_string();
    let cfg = ResendDTO::load(tenant)
        .await
        .ok_or("Failed to load email config")?;
    let link = build_magic_link(
        cfg.verify_url.as_str(),
        token.as_str(),
        user_name.as_str(),
        email.as_str(),
        ctx,
    )
    .map_err(|e| format!("Invalid verify_url in email config: {e}"))?;
    let content = render_email(&cfg, &email, &subject, link.as_str())
        .map_err(|e| format!("Failed to render email: {e}"))?;
    Ok((token, user_name, cfg, subject, content))
}

/// Phase 2 — runs AFTER the tenant guard is dropped (H6): the Resend
/// network hop must not pin the tenant's `DashMap` write guard and stall
/// every other caller for the domain. On success, parks the token →
/// username mapping `verify` consumes.
#[allow(clippy::too_many_arguments)]
async fn dispatch_magic_link(
    domain: &str,
    email: &str,
    token: &str,
    user_name: &str,
    cfg: &ResendDTO,
    subject: &str,
    content: &str,
) -> Result<(), String> {
    if send(cfg, email, subject, content).await.is_ok() {
        MLINK_CACHE
            .insert(format!("{}:{}", domain, token), user_name.to_string())
            .await
            .ok();
        Ok(())
    } else {
        Err("Fail to send email".to_string())
    }
}

#[endpoint(
    summary = "Request Magic Link",
    request_body = ReqRequest,
    responses(
        (status_code = 200, description = "Success", body = EmailResponse),
        (status_code = 401, description = "Failed", body = EmailResponse),
        (status_code = 429, description = "Per-recipient dispatch budget exhausted", body = EmailResponse)
    )
)]

pub async fn request(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let mut err_msg: String = String::new();
    // ServerState may not be available if affix_state hasn't injected it yet (e.g.,
    // during server startup). Skip email processing gracefully.
    let state = match depot.obtain::<ServerState>() {
        Ok(s) => s,
        Err(_) => return, // Can't process without ServerState; no valid response to send.
    };
    let domain = crate::utils::get_domain(req, state)
        .unwrap_or("")
        .to_string();
    let issuer = crate::utils::get_issuer(req, state).unwrap_or_default();
    if let Some(req_request) = extract::<ReqRequest>(req, None).await {
        if !crate::utils::send_throttle_allows(
            &format!("{domain}|email:{}", req_request.email.to_lowercase()),
            3,
        )
        .await
        {
            res.status_code(StatusCode::TOO_MANY_REQUESTS);
            res.render(Json(EmailResponse {
                ok: false,
                code: StatusCode::TOO_MANY_REQUESTS.as_u16(),
                msg: "Too many requests".to_string(),
                jwt: None,
            }));
            return;
        }
        if !req_request.name.is_empty() {
            if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
                // carry the login page's parked return context through
                // the email hop (both existing-user and signup branches).
                let ctx = MagicLinkContext {
                    client_id: req_request.client_id.as_deref(),
                    state: req_request.state.as_deref(),
                    redirect_uri: req_request.redirect_uri.as_deref(),
                    flow: None,
                };
                // Phase 1 under the tenant guard: resolve the ceremony
                // identity, mint its JWT and render the email (local only).
                let prepared = if let Ok(user) = tenant.user_by_email(&req_request.email).await {
                    // Existing credential: signin ceremony (— verify
                    // will resolve, never attach).
                    prepare_magic_link(
                        &mut tenant,
                        issuer.as_str(),
                        domain.as_str(),
                        user.name,
                        req_request.email.clone(),
                        false,
                        ctx,
                    )
                    .await
                } else {
                    // Unknown credential: signup ceremony (— verify
                    // will create the user or fail; it never attaches to a
                    // pre-existing user).
                    prepare_magic_link(
                        &mut tenant,
                        issuer.as_str(),
                        domain.as_str(),
                        req_request.name.clone(),
                        req_request.email.clone(),
                        true,
                        ctx,
                    )
                    .await
                };
                // H6: drop the tenant's write guard BEFORE the Resend
                // network hop — a hung peer must not stall every other
                // caller for this domain.
                drop(tenant);
                match prepared {
                    Ok((token, user_name, cfg, subject, content)) => {
                        match dispatch_magic_link(
                            domain.as_str(),
                            &req_request.email,
                            &token,
                            &user_name,
                            &cfg,
                            &subject,
                            &content,
                        )
                        .await
                        {
                            Ok(()) => {
                                res.status_code(StatusCode::OK);
                                res.render(Json(EmailResponse {
                                    ok: true,
                                    code: StatusCode::OK.as_u16(),
                                    msg: format!("Success{}", err_msg),
                                    jwt: None,
                                }));
                                // without this return the handler fell
                                // through to the 401 render below, so every
                                // successful request still answered 401.
                                return;
                            }
                            Err(e) => {
                                err_msg = e;
                            }
                        }
                    }
                    Err(e) => {
                        err_msg = e;
                    }
                }
            } else {
                err_msg = "Failed to find tenant".to_string();
            }
        } else {
            err_msg = "Empty user name".to_string();
        }
    } else {
        err_msg = "Invalid request".to_string();
    }
    res.status_code(StatusCode::UNAUTHORIZED);
    res.render(Json(EmailResponse {
        ok: false,
        code: StatusCode::UNAUTHORIZED.as_u16(),
        msg: format!("Unauthorized: {}", err_msg),
        jwt: None,
    }))
}

#[endpoint(
    summary = "Verify Magic Link",
    parameters(
        ("token" = String, Query, description="Unique token"),
        ("name" = String, Query, description="User name"),
        ("email" = String, Query, description="User email"),
    ),
    responses(
        (status_code = 200, description = "Success", body = EmailResponse),
        (status_code = 401, description = "Failed", body = EmailResponse)
    )
)]

pub async fn verify(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let err_msg = String::from("");
    // prior factors are inherited only from a session belonging to
    // the user being authenticated; an unrelated session contributes none
    // (passkey pattern). The session is captured here and filtered once the
    // ceremony identity is known below.
    let session = depot
        .obtain_mut::<JwtVerify>()
        .ok()
        .map(|a| (a.jwt_data.username.clone(), a.jwt_data.mfa.clone()));

    let state = depot.obtain_mut::<ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state)
        .unwrap_or("")
        .to_string();
    let issuer = crate::utils::get_issuer(req, state).unwrap_or_default();
    if let Some(verify_reqest) = extract::<VerifyRequest>(req, None).await
        && let Some(_value) = MLINK_CACHE
            .get_one_shot(&format!("{}:{}", domain, verify_reqest.token))
            .await
        && let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref())
    {
        // G-89: attribute the authentication attempt — successes AND
        // failures — to the claimed identity.
        crate::audit::record_target_detail(res, "auth", &verify_reqest.name, "factor=email");
        let data_wrap = tenant
            .jwt_verify::<MagicLinkData>(issuer.as_str(), &verify_reqest.name, &verify_reqest.token)
            .await;
        if data_wrap.is_ok() {
            let data = data_wrap.unwrap();
            if data.email == verify_reqest.email {
                // the ceremony mode is fixed in the signed
                // token. Signup creates the user within the ceremony
                // (failing when the name pre-exists); signin only
                // resolves the email's owner and never attaches.
                let bound = if data.signup {
                    tenant
                        .signup_user_email(&verify_reqest.name, &verify_reqest.email)
                        .await
                } else {
                    tenant
                        .signin_user_email(&verify_reqest.name, &verify_reqest.email)
                        .await
                };
                if bound.is_ok() {
                    // inherit only if the injected session
                    // belongs to the user being authenticated.
                    let mut previous_fa = session
                        .as_ref()
                        .filter(|(user, _)| user == &verify_reqest.name)
                        .map(|(_, mfa)| mfa.clone())
                        .unwrap_or_default();
                    previous_fa.insert(AuthType::Email.as_str().to_string());
                    if let Ok(jwt) = tenant
                        .authenticate_jwt(
                            &previous_fa,
                            issuer.as_str(),
                            domain.as_ref(),
                            &verify_reqest.name,
                            crate::utils::clamped_token_lifetime_minutes(
                                verify_reqest.lifetime,
                                15,
                            ),
                        )
                        .await
                    {
                        if let Some(name) = verify_reqest.cookie {
                            let cookie = Cookie::build((name, jwt.clone()))
                                .path("/")
                                .http_only(true)
                                .secure(true)
                                .same_site(SameSite::Strict)
                                .build();
                            res.add_cookie(cookie);
                        }
                        res.status_code(StatusCode::OK);
                        res.render(Json(EmailResponse {
                            ok: true,
                            code: StatusCode::OK.as_u16(),
                            msg: format!("Success{}", err_msg),
                            jwt: Some(jwt),
                        }));
                        return;
                    }
                }
            }
        }
    }

    res.status_code(StatusCode::UNAUTHORIZED);
    res.render(Json(EmailResponse {
        ok: false,
        code: StatusCode::UNAUTHORIZED.as_u16(),
        msg: format!("Unauthorized: {}", err_msg),
        jwt: None,
    }))
}

#[endpoint(
    summary = "Remove Magic Link",
    parameters(
        ("name" = String, Query, description="User name"),
        ("email" = String, Query, description="Email address to remove"),
    ),
    responses(
        (status_code = 200, description = "Success", body = EmailResponse),
        (status_code = 400, description = "Failed", body = EmailResponse),
        (status_code = 401, description = "No verified session", body = ApiProblem),
        (status_code = 403, description = "Level gate refused the target user", body = ApiProblem)
    )
)]

pub async fn remove(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    // H3: credential removal is a user-lifecycle mutation — the caller
    // must outrank the target on the role ladder (the same gate
    // `user_delete` enforces), or a lower admin could strip root's login
    // factors. Fail closed without a verified session.
    let caller = match crate::utils::caller_from_depot(depot) {
        Some(c) => c,
        None => {
            res.status_code(StatusCode::UNAUTHORIZED);
            res.render(Json(ApiProblem::unauthorized()));
            return;
        }
    };
    let state = depot.obtain_mut::<ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state)
        .unwrap_or("")
        .to_string();
    if let Some(req_request) = extract::<ReqRequest>(req, None).await
        && !req_request.name.is_empty()
        && let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref())
    {
        crate::audit::record_target_detail(
            res,
            "credential",
            &format!("email:{}", req_request.email),
            &format!("user={},flow=remove", req_request.name),
        );
        if let Ok(target) = tenant.user(&req_request.name).await
            && let Err(e) = tenant.require_above_user(&caller, target.id).await
        {
            crate::utils::render_admin_error(res, e);
            return;
        }
        if tenant
            .email_delete(&req_request.name, &req_request.email)
            .await
            .is_ok()
        {
            res.status_code(StatusCode::OK);
            res.render(Json(EmailResponse {
                ok: true,
                code: StatusCode::OK.as_u16(),
                msg: "Success".to_string(),
                jwt: None,
            }));
            return;
        }
    }

    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(EmailResponse {
        ok: false,
        code: StatusCode::BAD_REQUEST.as_u16(),
        msg: "Failure".to_string(),
        jwt: None,
    }))
}

#[derive(Deserialize, Serialize, Debug, ToSchema)]
pub struct AttachEmailRequest {
    pub name: String,
    pub email: String,
}

#[endpoint(
    summary = "Attach a verified email credential to a user (admin vouches)",
    description = "G-131 bootstrap/repair path: seeded and admin-created users are credential-less, and strict signup refuses a pre-existing username — without an admin-driven attach such a user could never sign in (only DB surgery recovered them). The admin VOUCHES for the address (no ownership ceremony — the same trust model SCIM email provisioning uses), so the row lands verified and the user can immediately sign in with a magic link. Level-gated like every credential mutation (H3): the caller must outrank the target, so peers cannot grant each other login factors. Re-attaching an address the same user already owns is an idempotent upgrade; an address owned by ANOTHER user is refused.",
    request_body = AttachEmailRequest,
    responses(
        (status_code = 200, description = "Success", body = EmailResponse),
        (status_code = 400, description = "Unknown user, or the address belongs to another user", body = EmailResponse),
        (status_code = 401, description = "No verified session", body = ApiProblem),
        (status_code = 403, description = "Level gate refused the target user", body = ApiProblem)
    )
)]
pub async fn attach(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let caller = match crate::utils::caller_from_depot(depot) {
        Some(c) => c,
        None => {
            res.status_code(StatusCode::UNAUTHORIZED);
            res.render(Json(ApiProblem::unauthorized()));
            return;
        }
    };
    let state = depot.obtain_mut::<ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state)
        .unwrap_or("")
        .to_string();
    if let Some(req_request) = extract::<AttachEmailRequest>(req, None).await
        && !req_request.name.is_empty()
        && !req_request.email.is_empty()
        && let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref())
    {
        // G-105: normalization lives in the data layer now
        // (`email_create_inner` / `user_by_email` fold case and
        // whitespace) — one choke point shared by every flow.
        let email = req_request.email.trim().to_string();
        crate::audit::record_target_detail(
            res,
            "credential",
            &format!("email:{email}"),
            &format!("user={},flow=attach,verified", req_request.name),
        );
        let target = match tenant.user(&req_request.name).await {
            Ok(t) => t,
            Err(_) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(EmailResponse {
                    ok: false,
                    code: StatusCode::BAD_REQUEST.as_u16(),
                    msg: "Unknown user".to_string(),
                    jwt: None,
                }));
                return;
            }
        };
        // H3, symmetric with `remove`: granting a login factor is a
        // user-lifecycle mutation — the caller must outrank the target.
        if let Err(e) = tenant.require_above_user(&caller, target.id).await {
            crate::utils::render_admin_error(res, e);
            return;
        }
        match tenant
            .email_create_verified(&req_request.name, &email)
            .await
        {
            Ok(()) => {
                res.status_code(StatusCode::OK);
                res.render(Json(EmailResponse {
                    ok: true,
                    code: StatusCode::OK.as_u16(),
                    msg: "Success".to_string(),
                    jwt: None,
                }));
            }
            // The only failure left is foreign ownership — ownership
            // disputes are never settled by whoever asks (class rule).
            Err(_) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(EmailResponse {
                    ok: false,
                    code: StatusCode::BAD_REQUEST.as_u16(),
                    msg: "Email already in use".to_string(),
                    jwt: None,
                }));
            }
        }
        return;
    }

    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(EmailResponse {
        ok: false,
        code: StatusCode::BAD_REQUEST.as_u16(),
        msg: "Failure".to_string(),
        jwt: None,
    }))
}

#[derive(Deserialize, Serialize, Debug, ToSchema)]
struct AllEmailRequest {
    pub name: Option<String>,
}
#[derive(Deserialize, Serialize, Debug, ToSchema)]
struct EmailEntry {
    pub name: String,
    pub email: String,
}

#[endpoint(
    summary = "Return all email addresses of a user",    
    request_body = AllEmailRequest,
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<Vec<EmailEntry>>),
        (status_code = 401, description = "Failed")
    )
)]
pub async fn all_emails(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain_mut::<ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state)
        .unwrap_or("")
        .to_string();
    if let Some(req_request) = extract::<AllEmailRequest>(req, None).await
        && let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref())
        && let Ok(data) = tenant.all_emails(req_request.name.as_deref()).await
    {
        let tmp: Vec<EmailEntry> = data
            .iter()
            .map(|a| EmailEntry {
                email: a.id.clone(),
                name: a.user.get().name.clone(),
            })
            .collect();
        res.status_code(StatusCode::OK);
        res.render(Json(ApiResponse::ok(tmp)));
        return;
    }

    let err = ApiProblem::validation_error("Failed to parse request body");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err));
}

// ── session-gated email add ──────────────────────────────────────────
//
// Closing removed the implicit resolve-or-create path, so an existing
// user had no way to attach a new email. These endpoints restore it the
// safe way: the ceremony is session-gated and the credential is attached
// to the session's own user — never to a client-supplied name. The magic
// link to the NEW address proves possession before anything is attached.

#[derive(Deserialize, Serialize, Debug, ToSchema)]
struct EmailAddRequest {
    pub email: String,
}

#[derive(Deserialize, Serialize, Debug, ToSchema)]
struct EmailAddVerifyRequest {
    pub token: String,
    pub email: String,
}

/// Payload of the 15-minute add-ceremony JWT. The subject is the
/// session user at `add` time; `add_verify` attaches only to that user.
/// Tokens live under the `email_add:` cache namespace, so a login
/// ceremony can never consume one and vice versa.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct EmailAddData {
    email: String,
}

/// Phase 1 of the add ceremony — runs UNDER the tenant guard: mint the
/// ceremony JWT and prepare the mail (config, link, rendered content).
/// G-153: the network send must NOT run while the guard is held — a slow
/// provider hop used to stall every request for the tenant up to the 15 s
/// timeout (the login `request` flow learned this as H6).
struct PreparedAddMail {
    token: String,
    cfg: ResendDTO,
    to: String,
    subject: String,
    content: String,
}

async fn prepare_add_email_ceremony(
    tenant: &mut RefMut<'_, String, Tenant>,
    issuer: &str,
    domain: &str,
    user_name: &str,
    email: &str,
) -> Result<PreparedAddMail, String> {
    let token = tenant
        .jwt_authenticate(
            issuer,
            domain,
            user_name,
            &EmailAddData {
                email: email.to_string(),
            },
            15,
        )
        .await
        .map_err(|_| "Fail to issue JWT".to_string())?;
    let subject = "Confirm your email";
    let cfg = ResendDTO::load(tenant)
        .await
        .ok_or("Failed to load email config")?;
    let link = build_magic_link(
        cfg.verify_url.as_str(),
        token.as_str(),
        user_name,
        email,
        MagicLinkContext {
            flow: Some("add"),
            ..Default::default()
        },
    )
    .map_err(|e| format!("Invalid verify_url in email config: {e}"))?;
    let content = render_email(&cfg, email, subject, link.as_str()).map_err(|e| e.to_string())?;
    Ok(PreparedAddMail {
        token,
        cfg,
        to: email.to_string(),
        subject: subject.to_string(),
        content,
    })
}

/// Phase 2 of the add ceremony — runs AFTER the tenant guard is dropped
/// (G-153): the provider hop, then the one-shot park.
async fn deliver_add_email_ceremony(
    domain: &str,
    user_name: &str,
    prepared: PreparedAddMail,
) -> Result<String, String> {
    if send(
        &prepared.cfg,
        &prepared.to,
        &prepared.subject,
        prepared.content.as_ref(),
    )
    .await
    .is_ok()
    {
        MLINK_CACHE
            .insert(
                format!("email_add:{}:{}", domain, prepared.token),
                user_name.to_string(),
            )
            .await
            .ok();
        return Ok(prepared.token);
    }
    Err("Fail to send email".to_string())
}

#[endpoint(
    summary = "Add an email address to the session's own account",
    request_body = EmailAddRequest,
    responses(
        (status_code = 200, description = "Success — confirmation link sent", body = EmailResponse),
        (status_code = 401, description = "No valid session or failed", body = EmailResponse),
        (status_code = 429, description = "Per-recipient dispatch budget exhausted", body = EmailResponse)
    )
)]
pub async fn add(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let err_msg: String;
    // session-gated — the identity comes from the validated session
    // (hoop), never from the request body.
    let user = match depot.obtain_mut::<JwtVerify>() {
        // G-132 sudo mode: attaching a login credential requires a freshly
        // AUTHENTICATED session, not a merely rotated one — a stolen
        // session must not be able to make the takeover persistent.
        Ok(v) if !crate::verify::session_is_fresh(v) => {
            crate::verify::mark_reauth_required(res);
            res.render(Json(EmailResponse {
                ok: false,
                code: StatusCode::FORBIDDEN.as_u16(),
                msg: "Re-authentication required before changing credentials".to_string(),
                jwt: None,
            }));
            return;
        }
        Ok(v) => v.jwt_data.username.clone(),
        Err(_) => {
            res.status_code(StatusCode::UNAUTHORIZED);
            res.render(Json(EmailResponse {
                ok: false,
                code: StatusCode::UNAUTHORIZED.as_u16(),
                msg: "Unauthorized: no valid session".to_string(),
                jwt: None,
            }));
            return;
        }
    };
    let state = match depot.obtain::<ServerState>() {
        Ok(s) => s,
        Err(_) => return,
    };
    let domain = crate::utils::get_domain(req, state)
        .unwrap_or("")
        .to_string();
    let issuer = crate::utils::get_issuer(req, state).unwrap_or_default();
    if let Some(req_request) = extract::<EmailAddRequest>(req, None).await {
        // G-105: the data layer canonicalizes (see `email_create_inner`).
        let email = req_request.email.trim().to_string();
        crate::audit::record_target_detail(
            res,
            "credential",
            &format!("email:{email}"),
            &format!("user={user},flow=add"),
        );
        // per-recipient throttle — adding must not become a mail
        // bomb either.
        if !crate::utils::send_throttle_allows(&format!("{domain}|email:{email}"), 3).await {
            res.status_code(StatusCode::TOO_MANY_REQUESTS);
            res.render(Json(EmailResponse {
                ok: false,
                code: StatusCode::TOO_MANY_REQUESTS.as_u16(),
                msg: "Too many requests".to_string(),
                jwt: None,
            }));
            return;
        }
        if !email.is_empty() {
            if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
                // An owned address is refused outright — ownership disputes
                // are never settled by whoever asks (class).
                if tenant.user_by_email(&email).await.is_ok() {
                    err_msg = "Email already in use".to_string();
                } else {
                    match prepare_add_email_ceremony(
                        &mut tenant,
                        issuer.as_str(),
                        domain.as_str(),
                        &user,
                        &email,
                    )
                    .await
                    {
                        Ok(prepared) => {
                            // G-153: drop the tenant write guard BEFORE the
                            // mail network hop (the H6 pattern from the
                            // login request flow).
                            drop(tenant);
                            match deliver_add_email_ceremony(domain.as_str(), &user, prepared).await
                            {
                                Ok(_token) => {
                                    res.status_code(StatusCode::OK);
                                    res.render(Json(EmailResponse {
                                        ok: true,
                                        code: StatusCode::OK.as_u16(),
                                        msg: "Success".to_string(),
                                        jwt: None,
                                    }));
                                    return;
                                }
                                Err(e) => {
                                    err_msg = e;
                                }
                            }
                        }
                        Err(e) => {
                            err_msg = e;
                        }
                    }
                }
            } else {
                err_msg = "Failed to find tenant".to_string();
            }
        } else {
            err_msg = "Empty email".to_string();
        }
    } else {
        err_msg = "Invalid request".to_string();
    }
    res.status_code(StatusCode::UNAUTHORIZED);
    res.render(Json(EmailResponse {
        ok: false,
        code: StatusCode::UNAUTHORIZED.as_u16(),
        msg: format!("Unauthorized: {}", err_msg),
        jwt: None,
    }));
}

#[endpoint(
    summary = "Complete a session-gated email add",
    request_body = EmailAddVerifyRequest,
    responses(
        (status_code = 200, description = "Success — email attached to the session's account", body = EmailResponse),
        (status_code = 401, description = "No valid session, unknown/consumed token, or the email was claimed in the meantime", body = EmailResponse)
    )
)]
pub async fn add_verify(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let err_msg: String;
    let user = match depot.obtain_mut::<JwtVerify>() {
        Ok(v) => v.jwt_data.username.clone(),
        Err(_) => {
            res.status_code(StatusCode::UNAUTHORIZED);
            res.render(Json(EmailResponse {
                ok: false,
                code: StatusCode::UNAUTHORIZED.as_u16(),
                msg: "Unauthorized: no valid session".to_string(),
                jwt: None,
            }));
            return;
        }
    };
    let state = depot.obtain_mut::<ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state)
        .unwrap_or("")
        .to_string();
    let issuer = crate::utils::get_issuer(req, state).unwrap_or_default();
    if let Some(verify_request) = extract::<EmailAddVerifyRequest>(req, None).await {
        crate::audit::record_target_detail(res, "auth", &user, "factor=email,flow=add");
        if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
            // One-shot consume under the add namespace — login tokens can
            // never be consumed here and vice versa.
            if MLINK_CACHE
                .get_one_shot(&format!("email_add:{}:{}", domain, verify_request.token))
                .await
                .is_some()
                && let Ok(data) = tenant
                    .jwt_verify::<EmailAddData>(&issuer, &user, &verify_request.token)
                    .await
                && data.email == verify_request.email
            {
                // Attach to the session's own user; `email_create_verified`
                // refuses an address owned by anyone else, so a raced
                // claim fails closed. The magic link to this address proved
                // possession, so the row is recorded verified (M3).
                if tenant
                    .email_create_verified(&user, &verify_request.email)
                    .await
                    .is_ok()
                {
                    res.status_code(StatusCode::OK);
                    res.render(Json(EmailResponse {
                        ok: true,
                        code: StatusCode::OK.as_u16(),
                        msg: "Success".to_string(),
                        jwt: None,
                    }));
                    return;
                }
                err_msg = "Email already in use".to_string();
            } else {
                err_msg = "Invalid or expired token".to_string();
            }
        } else {
            err_msg = "Failed to find tenant".to_string();
        }
    } else {
        err_msg = "Invalid request".to_string();
    }
    res.status_code(StatusCode::UNAUTHORIZED);
    res.render(Json(EmailResponse {
        ok: false,
        code: StatusCode::UNAUTHORIZED.as_u16(),
        msg: format!("Unauthorized: {}", err_msg),
        jwt: None,
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn query_map(link: &Url) -> std::collections::HashMap<String, String> {
        link.query_pairs().into_owned().collect()
    }

    /// regression: the magic link must carry the parked return
    /// context (OIDC client_id/state or redirect_uri) through the email
    /// hop, alongside the ceremony halves.
    #[test]
    fn magic_link_embeds_ceremony_and_return_context() {
        let ctx = MagicLinkContext {
            client_id: Some("client-a"),
            state: Some("st&ate 1"),
            redirect_uri: Some("/admin"),
            flow: None,
        };
        let link = build_magic_link(
            "https://idp.example/login",
            "tok123",
            "alice",
            "a@example.com",
            ctx,
        )
        .expect("link builds");
        let q = query_map(&link);
        assert_eq!(q.get("token").map(String::as_str), Some("tok123"));
        assert_eq!(q.get("username").map(String::as_str), Some("alice"));
        assert_eq!(q.get("email").map(String::as_str), Some("a@example.com"));
        assert_eq!(q.get("client_id").map(String::as_str), Some("client-a"));
        assert_eq!(q.get("state").map(String::as_str), Some("st&ate 1"));
        assert_eq!(q.get("redirect_uri").map(String::as_str), Some("/admin"));
        assert!(link.as_str().starts_with("https://idp.example/login?"));
        assert!(!q.contains_key("flow"), "login links carry no flow marker");

        // G-162: add-ceremony links mark `flow=add` so the hosted SPA
        // completes them against `email/add/verify` instead of the login
        // endpoint (the token namespaces are disjoint — a login verify
        // could never consume an add token).
        let add_link = build_magic_link(
            "https://idp.example/login",
            "tok-add",
            "alice",
            "new@example.com",
            MagicLinkContext {
                flow: Some("add"),
                ..Default::default()
            },
        )
        .expect("add link builds");
        assert_eq!(
            query_map(&add_link).get("flow").map(String::as_str),
            Some("add")
        );
    }

    #[test]
    fn magic_link_omits_absent_context_fields() {
        let link = build_magic_link(
            "https://idp.example/login",
            "t",
            "u",
            "e@example.com",
            MagicLinkContext::default(),
        )
        .expect("link builds");
        let q = query_map(&link);
        assert!(!q.contains_key("client_id"));
        assert!(!q.contains_key("state"));
        assert!(!q.contains_key("redirect_uri"));
    }

    #[test]
    fn magic_link_rejects_invalid_verify_url() {
        assert!(
            build_magic_link("not a url", "t", "u", "e@x", MagicLinkContext::default()).is_err()
        );
    }

    /// Tokens minted before added the ceremony-mode flag deserialize
    /// as signin-only, failing closed for the old signup-attach attack.
    #[test]
    fn legacy_ceremony_payload_defaults_to_signin() {
        let data: MagicLinkData =
            serde_json::from_str(r#"{"email":"a@example.com"}"#).expect("deserialize");
        assert!(!data.signup);
    }

    // ── regression tests (endpoint-level) ───────────────────────────

    const DOMAIN: &str = "localhost";
    const TEST_ISSUER: &str = "http://localhost";
    const ALICE_EMAIL: &str = "alice@example.com";

    /// The revocation store is a process-wide singleton, so all tests share
    /// one backing directory that must outlive every individual test's
    /// TempDir (same pattern as the otp.rs/totp.rs endpoint tests).
    static TEST_STORE_DIR: LazyLock<tempfile::TempDir> =
        LazyLock::new(|| tempfile::tempdir().expect("tempdir"));

    /// toasty spawns the store's connection task on whichever runtime is
    /// current during `init_global`; a `#[tokio::test]` runtime dies with
    /// its test. Initialize once on a dedicated multi-thread runtime whose
    /// workers outlive every individual test.
    static TEST_STORE_RT: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("store runtime")
    });
    static TEST_STORE_INIT: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

    async fn init_revocation_store() {
        TEST_STORE_RT
            .spawn(TEST_STORE_INIT.get_or_init(|| async {
                crate::jwt::InvalidJwt::init_global(TEST_STORE_DIR.path())
                    .await
                    .expect("init revocation store");
            }))
            .await
            .expect("store init task");
    }

    /// In-process tenant with a signing key and one user who owns an email.
    async fn email_test_env() -> (crate::server::ServerState, tempfile::TempDir) {
        init_revocation_store().await;
        // Signing keys are encrypted at rest (H2); the process-wide
        // encryption key is first-call-wins across test envs.
        let _ = crate::crypto::setup_encryption_key(&"0".repeat(64));
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage = crate::db::Storage::init(tmp.path())
            .await
            .expect("storage init");
        storage.new_tenant("test-tenant").await.expect("tenant");
        storage
            .add_domain(DOMAIN, "test-tenant")
            .await
            .expect("domain");
        {
            let mut tenant = storage.tenant_by_id("test-tenant").expect("tenant");
            tenant
                .key_create(DOMAIN, "key1")
                .await
                .expect("signing key");
            tenant.user_create("alice").await.expect("user");
            // Ceremony tokens are signin-only after , so the signin
            // fixture user must already own her credential.
            tenant
                .email_create("alice", ALICE_EMAIL)
                .await
                .expect("email");
        }
        let state = crate::server::ServerState::create_with(storage, false, &[])
            .await
            .expect("server state");
        (state, tmp)
    }

    fn email_service(state: crate::server::ServerState) -> Service {
        Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state))
                .push(Router::with_path("verify").post(verify)),
        )
    }

    /// Mints the ceremony token exactly like `request` does (minus the email
    /// hop, which needs a live Resend endpoint) and seeds the one-shot
    /// cache under the same key `request` uses.
    async fn issue_ceremony_for(
        state: &crate::server::ServerState,
        name: &str,
        email: &str,
        signup: bool,
    ) -> String {
        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        let token = tenant
            .jwt_authenticate(
                TEST_ISSUER,
                DOMAIN,
                name,
                &MagicLinkData {
                    email: email.to_string(),
                    signup,
                },
                15,
            )
            .await
            .expect("ceremony token");
        MLINK_CACHE
            .insert(format!("{}:{}", DOMAIN, token), name.to_string())
            .await
            .expect("cache insert");
        token
    }

    async fn post_verify(
        service: &Service,
        body: &serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        use salvo::test::ResponseExt;
        let mut res = salvo::test::TestClient::post("http://localhost/verify")
            .add_header("Host", DOMAIN, true)
            .json(body)
            .send(service)
            .await;
        let status = res.status_code.expect("status code");
        let body = res.take_string().await.unwrap_or_default();
        (
            status,
            serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
        )
    }

    /// G-90: a verify request may shorten the minted session (clamped to
    /// the 15-minute ceiling) — callers embedding the ceremony can pick
    /// a smaller exposure window than the default.
    #[tokio::test]
    async fn verify_honors_clamped_session_lifetime() {
        let (state, _tmp) = email_test_env().await;
        let service = email_service(state.clone());
        let token = issue_ceremony_for(&state, "alice", ALICE_EMAIL, false).await;

        let (status, body) = post_verify(
            &service,
            &serde_json::json!({
                "token": token,
                "name": "alice",
                "email": ALICE_EMAIL,
                "lifetime": 300,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let jwt = body["jwt"].as_str().expect("session jwt");

        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        let decoded = crate::jwt::jwt_decode::<crate::db::JwtData>(
            jwt,
            crate::jwt::VERIFICATION_GRACE_MINUTES,
            &mut tenant,
        )
        .await
        .expect("decode");
        assert_eq!(
            decoded.claims.exp - decoded.claims.iat,
            300,
            "the session must carry the requested 5-minute lifetime"
        );
    }

    /// G-99 (owner decision): signup is open, and the provisioned user
    /// lands on the builtin `guest` floor — no governed surface (the
    /// standard policy set binds nothing to guest), but a positive
    /// `roles: ["guest"]` claim for RPs and an explicit hierarchy rung.
    #[tokio::test]
    async fn signup_provisions_the_guest_floor_role() {
        let (state, _tmp) = email_test_env().await;
        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        let bootstrap = crate::role::Caller::Bootstrap;
        for (name, _) in crate::role::BUILTIN_ROLES {
            tenant
                .role_create(&bootstrap, name, 0)
                .await
                .expect("builtin role");
        }
        tenant
            .signup_user_email("newcomer", "newcomer@example.com")
            .await
            .expect("signup");
        let user = tenant.user("newcomer").await.expect("provisioned");
        let roles = tenant.user_roles(user.id).await.expect("roles");
        let names: Vec<&str> = roles.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(names, vec!["guest"], "signup lands on the guest floor");
    }

    /// Takeover attempt: a signup ceremony targeting a pre-existing username
    /// must fail and must not attach the attacker's email to the victim.
    #[tokio::test]
    async fn signup_with_existing_name_is_rejected_and_attaches_nothing() {
        let (state, _tmp) = email_test_env().await;
        let service = email_service(state.clone());
        let attacker_email = "attacker@evil.example";
        let token = issue_ceremony_for(&state, "alice", attacker_email, true).await;

        let (status, body) = post_verify(
            &service,
            &serde_json::json!({
                "token": token,
                "name": "alice",
                "email": attacker_email,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_ne!(body["ok"], true);

        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        assert!(tenant.user_by_email(attacker_email).await.is_err());
        let emails = tenant.all_emails(Some("alice")).await.expect("emails");
        assert_eq!(
            emails.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
            vec![ALICE_EMAIL]
        );
    }

    /// Legit signup: a fresh username is created and the email attached
    /// within the same ceremony.
    #[tokio::test]
    async fn signup_with_new_name_creates_user_and_attaches_email() {
        let (state, _tmp) = email_test_env().await;
        let service = email_service(state.clone());
        let token = issue_ceremony_for(&state, "carol", "carol@example.com", true).await;

        let (status, body) = post_verify(
            &service,
            &serde_json::json!({
                "token": token,
                "name": "carol",
                "email": "carol@example.com",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], true);

        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        assert_eq!(
            tenant
                .user_by_email("carol@example.com")
                .await
                .expect("email owner")
                .name,
            "carol"
        );
    }

    /// Signup is all-or-nothing: when the email already belongs to
    /// someone else, the just-created user is rolled back so the username
    /// stays available instead of being burned by an orphan row.
    #[tokio::test]
    async fn signup_rolls_back_user_when_email_is_already_claimed() {
        let (state, _tmp) = email_test_env().await;
        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");

        assert!(tenant.signup_user_email("dave", ALICE_EMAIL).await.is_err());
        assert!(tenant.user("dave").await.is_err());
    }

    /// Legit signin: the email's owner gets a session; nothing is attached.
    #[tokio::test]
    async fn signin_with_known_email_succeeds() {
        let (state, _tmp) = email_test_env().await;
        let service = email_service(state.clone());
        let token = issue_ceremony_for(&state, "alice", ALICE_EMAIL, false).await;

        let (status, body) = post_verify(
            &service,
            &serde_json::json!({
                "token": token,
                "name": "alice",
                "email": ALICE_EMAIL,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], true);
        assert!(!body["jwt"].as_str().unwrap_or("").is_empty());
    }

    /// A signin ceremony must never attach: an unknown email is rejected
    /// instead of provisioning.
    #[tokio::test]
    async fn signin_with_unknown_email_is_rejected_and_attaches_nothing() {
        let (state, _tmp) = email_test_env().await;
        let service = email_service(state.clone());
        let token = issue_ceremony_for(&state, "alice", "unknown@example.com", false).await;

        let (status, body) = post_verify(
            &service,
            &serde_json::json!({
                "token": token,
                "name": "alice",
                "email": "unknown@example.com",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_ne!(body["ok"], true);

        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        assert!(tenant.user_by_email("unknown@example.com").await.is_err());
    }

    // ── regression tests ──────────────────────────────────────────────

    /// Stands in for the `protect` hoop: an authenticated session for alice
    /// carrying a TOTP factor, injected into the depot.
    #[handler]
    async fn inject_alice_totp_session(
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        depot.inject(JwtVerify {
            can_access: true,
            jwt_data: crate::db::JwtData {
                user: "alice".to_string(),
                username: "alice".to_string(),
                domain: DOMAIN.to_string(),
                mfa: HashSet::from([AuthType::TOTP.as_str().to_string()]),
                roles: HashSet::new(),
            },
            expect_mfa: false,
            domain: DOMAIN.to_string(),
            auth_time: Some(jiff::Timestamp::now().as_second().max(0) as usize),
        });
        ctrl.call_next(req, depot, res).await;
    }

    /// Same, but for bob — the user who completes the ceremony below.
    #[handler]
    async fn inject_bob_totp_session(
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        depot.inject(JwtVerify {
            can_access: true,
            jwt_data: crate::db::JwtData {
                user: "bob".to_string(),
                username: "bob".to_string(),
                domain: DOMAIN.to_string(),
                mfa: HashSet::from([AuthType::TOTP.as_str().to_string()]),
                roles: HashSet::new(),
            },
            expect_mfa: false,
            domain: DOMAIN.to_string(),
            auth_time: Some(jiff::Timestamp::now().as_second().max(0) as usize),
        });
        ctrl.call_next(req, depot, res).await;
    }

    fn email_service_with_session(
        state: crate::server::ServerState,
        session: impl salvo::Handler,
    ) -> Service {
        Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state))
                .push(Router::with_path("verify").hoop(session).post(verify)),
        )
    }

    /// G-152: the send throttle is tenant-scoped — the same address on a
    /// sibling domain has its own budget. The key used to be the bare
    /// recipient, so any account on one tenant could exhaust a victim's
    /// 3/min magic-link budget on ANOTHER tenant of the same deployment.
    #[tokio::test]
    async fn send_throttle_is_scoped_per_domain() {
        const SIBLING: &str = "throttle-sibling.test";
        let (state, _tmp) = email_test_env().await;
        state
            .storage
            .add_domain(SIBLING, "test-tenant")
            .await
            .expect("sibling domain");
        let service = Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state.clone()))
                .push(Router::with_path("email/request").post(request)),
        );
        // Unique address: SEND_THROTTLE is process-global across tests.
        // (The env has no mail provider, so sends may fail downstream —
        // the throttle increments before the send and that is what is
        // pinned here.)
        let body = serde_json::json!({
            "name": "throttled",
            "email": "throttle-scoped@example.com",
        });

        for i in 0..3 {
            let res = salvo::test::TestClient::post("http://localhost/email/request")
                .add_header("Host", DOMAIN, true)
                .json(&body)
                .send(&service)
                .await;
            assert_ne!(
                res.status_code,
                Some(StatusCode::TOO_MANY_REQUESTS),
                "send {i} is within the domain's budget"
            );
        }
        let res = salvo::test::TestClient::post("http://localhost/email/request")
            .add_header("Host", DOMAIN, true)
            .json(&body)
            .send(&service)
            .await;
        assert_eq!(
            res.status_code,
            Some(StatusCode::TOO_MANY_REQUESTS),
            "the 4th send on the same domain is throttled"
        );

        let res = salvo::test::TestClient::post("http://sibling.test/email/request")
            .add_header("Host", SIBLING, true)
            .json(&body)
            .send(&service)
            .await;
        assert_ne!(
            res.status_code,
            Some(StatusCode::TOO_MANY_REQUESTS),
            "the sibling domain has its own budget for the same recipient"
        );
    }

    /// G-105: one spelling per mailbox — the data layer folds case and
    /// whitespace on store AND lookup, killing both the add-flow lockout
    /// (register "Alice@X", sign in with "Alice@X" → miss → strict-signup
    /// refusal) and the duplicate-identity bypass (uniqueness missing a
    /// case variant of an owned address).
    #[tokio::test]
    async fn email_identity_folds_at_the_data_layer() {
        let (state, _tmp) = email_test_env().await;
        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        tenant.user_create("folder").await.expect("user");
        tenant.user_create("rival").await.expect("rival");

        tenant
            .email_create_verified("folder", "  Mixed@Case.Example  ")
            .await
            .expect("attach folds and trims");

        // Lookup resolves under any spelling.
        for queried in [
            "mixed@case.example",
            "Mixed@Case.Example",
            "MIXED@CASE.EXAMPLE",
            "  mixed@CASE.example  ",
        ] {
            let owner = tenant
                .user_by_email(queried)
                .await
                .expect("folded lookup resolves");
            assert_eq!(owner.name, "folder", "query {queried:?}");
        }

        // The stored form is canonical.
        let emails = tenant.all_emails(Some("folder")).await.expect("emails");
        assert!(
            emails
                .iter()
                .any(|e| e.id == "mixed@case.example" && e.verified),
            "stored canonical + verified"
        );

        // Uniqueness sees through case: a rival cannot take the mailbox.
        let err = tenant
            .email_create("rival", "MIXED@case.EXAMPLE")
            .await
            .expect_err("foreign ownership must be detected across case");
        assert!(err.to_string().contains("already"), "{err}");

        // Delete folds too.
        tenant
            .email_delete("folder", "MiXeD@CaSe.ExAmPlE")
            .await
            .expect("delete folds");
        assert!(tenant.user_by_email("mixed@case.example").await.is_err());
    }

    /// Stands in for a session whose authentication is OLDER than the sudo
    /// window (G-132) — the shape a stolen-and-rotated chain presents
    /// (`refresh_jwt` preserves the original `auth_time`).
    #[handler]
    async fn inject_stale_alice_session(
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        depot.inject(JwtVerify {
            can_access: true,
            jwt_data: crate::db::JwtData {
                user: "alice".to_string(),
                username: "alice".to_string(),
                domain: DOMAIN.to_string(),
                mfa: HashSet::new(),
                roles: HashSet::new(),
            },
            expect_mfa: false,
            domain: DOMAIN.to_string(),
            auth_time: Some(
                (jiff::Timestamp::now().as_second() - crate::verify::SUDO_WINDOW_SEC as i64 - 60)
                    .max(0) as usize,
            ),
        });
        ctrl.call_next(req, depot, res).await;
    }

    /// G-132: attaching an email credential requires a freshly
    /// AUTHENTICATED session — a stale one gets 403 plus the
    /// machine-readable `X-Reauth-Required` signal, and no ceremony is
    /// started (no mail leaves the building).
    #[tokio::test]
    async fn add_email_refuses_stale_session() {
        let (state, _tmp) = email_test_env().await;
        let service = Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state.clone()))
                .push(
                    Router::with_path("add")
                        .hoop(inject_stale_alice_session)
                        .post(add),
                ),
        );
        let mut res = salvo::test::TestClient::post("http://localhost/add")
            .add_header("Host", DOMAIN, true)
            .json(&serde_json::json!({ "email": "fresh@example.com" }))
            .send(&service)
            .await;
        assert_eq!(res.status_code.expect("status"), StatusCode::FORBIDDEN);
        assert_eq!(
            res.headers()
                .get(crate::verify::REAUTH_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("true"),
            "the 403 must carry the re-auth signal"
        );
        use salvo::test::ResponseExt;
        let body = res.take_string().await.unwrap_or_default();
        let json: serde_json::Value = serde_json::from_str(&body).expect("json body");
        assert_eq!(json["ok"], false);
    }

    /// Stands in for the `protect` hoop on the admin surface: an `admin`
    /// (level 80) session for alice, injected as the RBAC caller.
    #[handler]
    async fn inject_admin_caller(
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        depot.inject(JwtVerify {
            can_access: true,
            jwt_data: crate::db::JwtData {
                user: uuid::Uuid::nil().to_string(),
                username: "alice".to_string(),
                domain: DOMAIN.to_string(),
                mfa: HashSet::new(),
                roles: HashSet::from(["admin".to_string()]),
            },
            expect_mfa: false,
            domain: DOMAIN.to_string(),
            auth_time: Some(jiff::Timestamp::now().as_second().max(0) as usize),
        });
        ctrl.call_next(req, depot, res).await;
    }

    async fn post_attach(
        service: &Service,
        name: &str,
        email: &str,
    ) -> (StatusCode, serde_json::Value) {
        use salvo::test::ResponseExt;
        let mut res = salvo::test::TestClient::post("http://localhost/user/attach_email")
            .add_header("Host", DOMAIN, true)
            .json(&serde_json::json!({ "name": name, "email": email }))
            .send(service)
            .await;
        let status = res.status_code.expect("status code");
        let body = res.take_string().await.unwrap_or_default();
        (
            status,
            serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
        )
    }

    /// G-131: the admin-vouched attach gives a credential-less user its
    /// FIRST login credential (seeded/admin-created users cannot self-
    /// signup over a pre-existing username). The row lands verified and
    /// lowercased; re-attach is idempotent; an address owned by another
    /// user is refused; and the H3 level gate applies — an admin cannot
    /// vouch credentials onto a root-level account.
    #[tokio::test]
    async fn attach_email_vouches_a_first_credential() {
        let (state, _tmp) = email_test_env().await;
        {
            let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
            let bootstrap = crate::role::Caller::Bootstrap;
            for (name, _) in crate::role::BUILTIN_ROLES {
                tenant
                    .role_create(&bootstrap, name, 0)
                    .await
                    .expect("builtin role");
            }
            tenant.user_create("newbie").await.expect("newbie");
            tenant.user_create("boss").await.expect("boss");
            tenant
                .user_add_role(&bootstrap, "boss", "root")
                .await
                .expect("boss holds root");
        }
        let service = Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state.clone()))
                .hoop(inject_admin_caller)
                .push(Router::with_path("user/attach_email").post(attach)),
        );

        // The credential-less user gets a first, VERIFIED credential —
        // stored lowercase (the wire boundary folds case).
        let (status, body) = post_attach(&service, "newbie", "Newbie@Example.com").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        {
            let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
            let owner = tenant
                .user_by_email("newbie@example.com")
                .await
                .expect("attached lowercase");
            assert_eq!(owner.name, "newbie");
            let emails = tenant.all_emails(Some("newbie")).await.expect("emails");
            assert!(
                emails.iter().any(|e| e.verified),
                "a vouched credential lands verified — signin, not signup"
            );
        }

        // Idempotent re-attach for the same user.
        let (status, _) = post_attach(&service, "newbie", "newbie@example.com").await;
        assert_eq!(status, StatusCode::OK, "re-attach is an idempotent upgrade");

        // An address owned by ANOTHER user is refused — ownership disputes
        // are never settled by whoever asks.
        let (status, body) = post_attach(&service, "newbie", ALICE_EMAIL).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_ne!(body["ok"], true);

        // Unknown user → 400, not a silent no-op.
        let (status, _) = post_attach(&service, "ghost", "ghost@example.com").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // H3: admin (80) may not vouch credentials onto root (100).
        let (status, _) = post_attach(&service, "boss", "boss@example.com").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    /// Provision bob with an email so he can run a signin ceremony.
    async fn create_bob(state: &crate::server::ServerState) {
        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        tenant.user_create("bob").await.expect("bob");
        tenant
            .email_create("bob", "bob@example.com")
            .await
            .expect("bob email");
    }

    /// Factor laundering: a session belonging to alice must not contribute
    /// its factors to bob's new JWT.
    #[tokio::test]
    async fn verify_does_not_inherit_factors_from_another_users_session() {
        let (state, _tmp) = email_test_env().await;
        create_bob(&state).await;
        let service = email_service_with_session(state.clone(), inject_alice_totp_session);
        let token = issue_ceremony_for(&state, "bob", "bob@example.com", false).await;

        let (status, body) = post_verify(
            &service,
            &serde_json::json!({
                "token": token,
                "name": "bob",
                "email": "bob@example.com",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let jwt = body["jwt"].as_str().expect("jwt").to_string();
        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        let bob = tenant.user("bob").await.expect("bob");
        let data: crate::db::JwtData = tenant
            .jwt_verify(TEST_ISSUER, &bob.id.to_string(), &jwt)
            .await
            .expect("decode session jwt");
        assert!(
            data.mfa.contains(AuthType::Email.as_str()),
            "this ceremony's own factor must be present"
        );
        assert!(
            !data.mfa.contains(AuthType::TOTP.as_str()),
            "alice's factor must not be inherited by bob"
        );
    }

    /// Step-up control: a session belonging to the same user still carries
    /// its factors forward.
    #[tokio::test]
    async fn verify_inherits_factors_from_the_same_users_session() {
        let (state, _tmp) = email_test_env().await;
        create_bob(&state).await;
        let service = email_service_with_session(state.clone(), inject_bob_totp_session);
        let token = issue_ceremony_for(&state, "bob", "bob@example.com", false).await;

        let (status, body) = post_verify(
            &service,
            &serde_json::json!({
                "token": token,
                "name": "bob",
                "email": "bob@example.com",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let jwt = body["jwt"].as_str().expect("jwt").to_string();
        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        let bob = tenant.user("bob").await.expect("bob");
        let data: crate::db::JwtData = tenant
            .jwt_verify(TEST_ISSUER, &bob.id.to_string(), &jwt)
            .await
            .expect("decode session jwt");
        assert!(data.mfa.contains(AuthType::Email.as_str()));
        assert!(
            data.mfa.contains(AuthType::TOTP.as_str()),
            "the same user's prior factor must be carried forward"
        );
    }

    // ── regression tests ──────────────────────────────────────────────

    fn header_end(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|w| w == b"\r\n\r\n")
    }

    /// A minimal stand-in for the Resend API: accepts any request and
    /// answers 200 with an email id, which is all `send` needs to succeed.
    async fn spawn_mock_resend() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock resend");
        let addr = listener.local_addr().expect("mock addr");
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        let n = sock.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(pos) = header_end(&buf) {
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
                    let body = r#"{"id":"mock-email-id"}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        format!("http://{addr}")
    }

    /// Tenant whose Resend config points at the given base URL.
    async fn email_request_env(base_url: &str) -> (crate::server::ServerState, tempfile::TempDir) {
        init_revocation_store().await;
        // Provider keys are encrypted at rest on save; the key is
        // process-wide and first-call-wins, matching the social test envs.
        let _ = crate::crypto::setup_encryption_key(&"0".repeat(64));
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage = crate::db::Storage::init(tmp.path())
            .await
            .expect("storage init");
        storage.new_tenant("test-tenant").await.expect("tenant");
        storage
            .add_domain(DOMAIN, "test-tenant")
            .await
            .expect("domain");
        {
            let mut tenant = storage.tenant_by_id("test-tenant").expect("tenant");
            tenant
                .key_create(DOMAIN, "key1")
                .await
                .expect("signing key");
            let config: [(&str, String); 5] = [
                ("resend.from", "noreply@example.com".to_string()),
                ("resend.key", "re_test_key".to_string()),
                ("resend.template", String::new()),
                (
                    "resend.verify_url",
                    "http://localhost:8080/email/verify".to_string(),
                ),
                ("resend.base_url", base_url.to_string()),
            ];
            for (key, value) in config {
                tenant
                    .config_set(key, serde_json::json!(value))
                    .await
                    .expect("config");
            }
        }
        let state = crate::server::ServerState::create_with(storage, false, &[])
            .await
            .expect("server state");
        (state, tmp)
    }

    fn request_service(state: crate::server::ServerState) -> Service {
        Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state))
                .push(Router::with_path("email/request").post(request)),
        )
    }

    /// regression: a successful magic-link request must answer 200.
    /// Before the fix both success branches rendered 200 but never
    /// returned, so the handler fell through to the 401 render.
    #[tokio::test]
    async fn request_returns_200_on_success() {
        use salvo::test::ResponseExt;
        let base_url = spawn_mock_resend().await;
        let (state, _tmp) = email_request_env(&base_url).await;
        let service = request_service(state);

        let mut res = salvo::test::TestClient::post("http://localhost/email/request")
            .add_header("Host", DOMAIN, true)
            .json(&serde_json::json!({ "name": "carol", "email": "carol@example.com" }))
            .send(&service)
            .await;
        assert_eq!(
            res.status_code.expect("status code"),
            StatusCode::OK,
            "a successful request must answer 200"
        );
        let body = res.take_string().await.unwrap_or_default();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
        assert_eq!(body["ok"], true);
    }

    /// The failure contract is unchanged: a malformed request still ends
    /// at the trailing 401 render.
    #[tokio::test]
    async fn request_still_returns_401_on_failure() {
        use salvo::test::ResponseExt;
        let base_url = spawn_mock_resend().await;
        let (state, _tmp) = email_request_env(&base_url).await;
        let service = request_service(state);

        let mut res = salvo::test::TestClient::post("http://localhost/email/request")
            .add_header("Host", DOMAIN, true)
            .json(&serde_json::json!({ "name": "", "email": "carol@example.com" }))
            .send(&service)
            .await;
        assert_eq!(
            res.status_code.expect("status code"),
            StatusCode::UNAUTHORIZED
        );
        let body = res.take_string().await.unwrap_or_default();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
        assert_eq!(body["ok"], false);
    }

    /// regression: per-recipient throttle — the 4th request for the
    /// same email within the window gets 429 while another recipient keeps
    /// its own budget.
    #[tokio::test]
    async fn request_throttles_per_recipient() {
        let base_url = spawn_mock_resend().await;
        let (state, _tmp) = email_request_env(&base_url).await;
        let service = request_service(state);

        for i in 0..3 {
            let res = salvo::test::TestClient::post("http://localhost/email/request")
                .add_header("Host", DOMAIN, true)
                .json(&serde_json::json!({ "name": "carol", "email": "victim@example.com" }))
                .send(&service)
                .await;
            assert_eq!(
                res.status_code.expect("status code"),
                StatusCode::OK,
                "request {i} is within the per-recipient budget"
            );
        }
        let res = salvo::test::TestClient::post("http://localhost/email/request")
            .add_header("Host", DOMAIN, true)
            .json(&serde_json::json!({ "name": "carol", "email": "victim@example.com" }))
            .send(&service)
            .await;
        assert_eq!(
            res.status_code.expect("status code"),
            StatusCode::TOO_MANY_REQUESTS,
            "the 4th request for the same recipient must be throttled"
        );

        // A different recipient is unaffected.
        let res = salvo::test::TestClient::post("http://localhost/email/request")
            .add_header("Host", DOMAIN, true)
            .json(&serde_json::json!({ "name": "dave", "email": "other@example.com" }))
            .send(&service)
            .await;
        assert_eq!(res.status_code.expect("status code"), StatusCode::OK);
    }

    // ── regression tests (session-gated email add) ────────────────────

    #[handler]
    async fn inject_alice_session(
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        depot.inject(JwtVerify {
            can_access: true,
            jwt_data: crate::db::JwtData {
                user: "alice".to_string(),
                username: "alice".to_string(),
                domain: DOMAIN.to_string(),
                mfa: HashSet::from([AuthType::Email.as_str().to_string()]),
                roles: HashSet::new(),
            },
            expect_mfa: false,
            domain: DOMAIN.to_string(),
            auth_time: Some(jiff::Timestamp::now().as_second().max(0) as usize),
        });
        ctrl.call_next(req, depot, res).await;
    }

    #[handler]
    async fn inject_bob_session(
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        depot.inject(JwtVerify {
            can_access: true,
            jwt_data: crate::db::JwtData {
                user: "bob".to_string(),
                username: "bob".to_string(),
                domain: DOMAIN.to_string(),
                mfa: HashSet::from([AuthType::Email.as_str().to_string()]),
                roles: HashSet::new(),
            },
            expect_mfa: false,
            domain: DOMAIN.to_string(),
            auth_time: Some(jiff::Timestamp::now().as_second().max(0) as usize),
        });
        ctrl.call_next(req, depot, res).await;
    }

    fn email_add_service<H: salvo::Handler>(
        state: crate::server::ServerState,
        session: H,
    ) -> Service {
        Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state))
                .hoop(session)
                .push(Router::with_path("email/add").post(add))
                .push(Router::with_path("email/add/verify").post(add_verify))
                .push(Router::with_path("email/verify").post(verify)),
        )
    }

    /// The add ceremony succeeds for a session user adding an unowned
    /// address (dispatch via the mock Resend server).
    #[tokio::test]
    async fn add_sends_confirmation_for_unowned_email() {
        use salvo::test::ResponseExt;
        let base_url = spawn_mock_resend().await;
        let (state, _tmp) = email_request_env(&base_url).await;
        {
            let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
            tenant.user_create("alice").await.expect("alice");
        }
        let service = email_add_service(state, inject_alice_session);

        let mut res = salvo::test::TestClient::post("http://localhost/email/add")
            .add_header("Host", DOMAIN, true)
            .json(&serde_json::json!({ "email": "alice2@example.com" }))
            .send(&service)
            .await;
        assert_eq!(
            res.status_code.expect("status code"),
            StatusCode::OK,
            "session-gated add of an unowned email must succeed"
        );
        let body = res.take_string().await.unwrap_or_default();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
        assert_eq!(body["ok"], true);
    }

    /// An address owned by ANY user is refused outright — ownership is
    /// never settled by whoever asks (class).
    #[tokio::test]
    async fn add_refuses_an_owned_email() {
        use salvo::test::ResponseExt;
        let base_url = spawn_mock_resend().await;
        let (state, _tmp) = email_request_env(&base_url).await;
        {
            let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
            tenant.user_create("alice").await.expect("alice");
            tenant.user_create("bob").await.expect("bob");
            tenant
                .email_create("bob", "bob@example.com")
                .await
                .expect("bob email");
        }
        let service = email_add_service(state, inject_alice_session);

        let mut res = salvo::test::TestClient::post("http://localhost/email/add")
            .add_header("Host", DOMAIN, true)
            .json(&serde_json::json!({ "email": "bob@example.com" }))
            .send(&service)
            .await;
        assert_eq!(
            res.status_code.expect("status code"),
            StatusCode::UNAUTHORIZED
        );
        let body = res.take_string().await.unwrap_or_default();
        assert!(body.contains("already in use"), "{body}");
    }

    /// Mint an add-ceremony token the way `add` does (minus the email hop)
    /// and register it under the `email_add:` namespace.
    async fn issue_add_ceremony(
        state: &crate::server::ServerState,
        user: &str,
        email: &str,
    ) -> String {
        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        let token = tenant
            .jwt_authenticate(
                TEST_ISSUER,
                DOMAIN,
                user,
                &EmailAddData {
                    email: email.to_string(),
                },
                15,
            )
            .await
            .expect("ceremony token");
        MLINK_CACHE
            .insert(format!("email_add:{DOMAIN}:{token}"), user.to_string())
            .await
            .expect("cache insert");
        token
    }

    /// Completing the ceremony attaches the email to the session's own
    /// user.
    #[tokio::test]
    async fn add_verify_attaches_email_to_the_session_user() {
        use salvo::test::ResponseExt;
        let (state, _tmp) = email_test_env().await;
        let service = email_add_service(state.clone(), inject_alice_session);
        let token = issue_add_ceremony(&state, "alice", "alice2@example.com").await;

        let mut res = salvo::test::TestClient::post("http://localhost/email/add/verify")
            .add_header("Host", DOMAIN, true)
            .json(&serde_json::json!({ "token": token, "email": "alice2@example.com" }))
            .send(&service)
            .await;
        assert_eq!(
            res.status_code.expect("status code"),
            StatusCode::OK,
            "the session owner must complete their own add ceremony"
        );
        let body = res.take_string().await.unwrap_or_default();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
        assert_eq!(body["ok"], true);

        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        assert_eq!(
            tenant
                .user_by_email("alice2@example.com")
                .await
                .expect("attached email")
                .name,
            "alice"
        );
    }

    /// A DIFFERENT session cannot complete someone else's add ceremony —
    /// the token subject and the session user must match.
    #[tokio::test]
    async fn add_verify_refuses_a_foreign_session() {
        let (state, _tmp) = email_test_env().await;
        create_bob(&state).await;
        let service = email_add_service(state.clone(), inject_bob_session);
        let token = issue_add_ceremony(&state, "alice", "alice2@example.com").await;

        let res = salvo::test::TestClient::post("http://localhost/email/add/verify")
            .add_header("Host", DOMAIN, true)
            .json(&serde_json::json!({ "token": token, "email": "alice2@example.com" }))
            .send(&service)
            .await;
        assert_eq!(
            res.status_code.expect("status code"),
            StatusCode::UNAUTHORIZED,
            "a foreign session must not complete the ceremony"
        );

        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        assert!(tenant.user_by_email("alice2@example.com").await.is_err());
    }

    /// Namespace separation: an add-ceremony token must not be consumable
    /// at the LOGIN verify endpoint (and vice versa), even though both
    /// share MLINK_CACHE.
    #[tokio::test]
    async fn add_token_is_not_a_login_token() {
        let (state, _tmp) = email_test_env().await;
        let service = email_add_service(state.clone(), inject_alice_session);
        let token = issue_add_ceremony(&state, "alice", "alice2@example.com").await;

        let res = salvo::test::TestClient::post("http://localhost/email/verify")
            .add_header("Host", DOMAIN, true)
            .json(&serde_json::json!({
                "token": token,
                "name": "alice",
                "email": "alice2@example.com",
            }))
            .send(&service)
            .await;
        assert_eq!(
            res.status_code.expect("status code"),
            StatusCode::UNAUTHORIZED,
            "the login ceremony must not consume an add token"
        );
    }

    /// regression: the Resend API key is a send-capable credential — the
    /// config table must hold ciphertext, `ResendDTO::load` must still
    /// hand consumers plaintext, and legacy plaintext values must keep
    /// loading through the fallback.
    #[tokio::test]
    async fn resend_key_is_encrypted_at_rest() {
        let (state, _tmp) = email_request_env("http://127.0.0.1:1").await;
        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");

        // The env seeds a legacy plaintext key; load falls back.
        let legacy = ResendDTO::load(&mut tenant).await.expect("legacy load");
        assert_eq!(legacy.resend_key, "re_test_key");

        // Re-saving encrypts at rest.
        legacy.save(&mut tenant).await.expect("save");
        let raw = tenant.config_get("resend.key").await.expect("raw value");
        let raw = raw.as_str().expect("string");
        assert_ne!(raw, "re_test_key", "the config table must hold ciphertext");
        assert_eq!(
            crate::crypto::decrypt_secret(raw).expect("ciphertext"),
            "re_test_key"
        );

        // And load round-trips back to plaintext for consumers.
        let reloaded = ResendDTO::load(&mut tenant).await.expect("reload");
        assert_eq!(reloaded.resend_key, "re_test_key");
    }

    /// regression: a broken email template must surface as an error the
    /// caller turns into a clean failure, not a panic inside render.
    #[test]
    fn render_email_surfaces_template_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("broken.html");
        std::fs::write(&path, "{{ nope }}").expect("write");
        let cfg = ResendDTO {
            from: "noreply@example.com".into(),
            resend_key: "re_test_key".into(),
            template: path.to_string_lossy().to_string(),
            verify_url: "http://localhost/email/verify".into(),
            base_url: None,
        };
        assert!(
            render_email(
                &cfg,
                "alice@example.com",
                "Janux login",
                "http://localhost/l"
            )
            .is_err(),
            "a template referencing a missing variable must error, not panic"
        );
    }
    // ── M3: email verification provenance ──────────────────────────────────

    /// M3: provenance is recorded per row — the bare `email_create`
    /// (SCIM/admin path) stays unverified; `email_create_verified`
    /// (post-ceremony path) records the proof; a proven re-attach upgrades
    /// an unverified row, and an unproven re-attach never downgrades one.
    #[tokio::test]
    async fn email_verified_tracks_provenance() {
        let (state, _tmp) = email_test_env().await;
        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        tenant.user_create("carol").await.expect("carol");

        tenant
            .email_create("carol", "carol@example.com")
            .await
            .expect("attach");
        let emails = tenant.all_emails(Some("carol")).await.expect("emails");
        assert!(
            !emails[0].verified,
            "an admin/SCIM-path attach must start unverified"
        );

        tenant
            .email_create_verified("carol", "carol@example.com")
            .await
            .expect("proven re-attach");
        let emails = tenant.all_emails(Some("carol")).await.expect("emails");
        assert!(emails[0].verified, "an ownership proof upgrades the row");

        tenant
            .email_create("carol", "carol@example.com")
            .await
            .expect("idempotent re-attach");
        let emails = tenant.all_emails(Some("carol")).await.expect("emails");
        assert!(
            emails[0].verified,
            "an unproven re-attach must never downgrade a verified row"
        );
    }

    /// M3: the magic-link signin ceremony is a fresh proof of ownership —
    /// an unverified (SCIM-provisioned or pre-M3 legacy) row converges to
    /// verified when the user completes the ceremony end to end.
    #[tokio::test]
    async fn signin_ceremony_converges_unverified_row() {
        let (state, _tmp) = email_test_env().await;
        {
            let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
            tenant.user_create("carol").await.expect("carol");
            tenant
                .email_create("carol", "carol@example.com")
                .await
                .expect("unverified attach");
        }
        let service = email_service(state.clone());
        let token = issue_ceremony_for(&state, "carol", "carol@example.com", false).await;

        let (status, _body) = post_verify(
            &service,
            &serde_json::json!({
                "token": token,
                "name": "carol",
                "email": "carol@example.com",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "signin ceremony succeeds");

        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        let emails = tenant.all_emails(Some("carol")).await.expect("emails");
        assert!(
            emails[0].verified,
            "the completed ceremony must converge the row to verified"
        );
    }

    /// M3: the owner-scoped mark (repeat social login re-attestation) never
    /// upgrades a row belonging to a different user.
    #[tokio::test]
    async fn verified_mark_is_owner_scoped() {
        let (state, _tmp) = email_test_env().await;
        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        tenant.user_create("carol").await.expect("carol");
        tenant
            .email_create("carol", "carol@example.com")
            .await
            .expect("attach");
        let carol = tenant.user("carol").await.expect("carol").id;
        let alice = tenant.user("alice").await.expect("alice").id;

        tenant
            .email_mark_verified_for(alice, "carol@example.com")
            .await
            .expect("foreign mark is a no-op");
        let emails = tenant.all_emails(Some("carol")).await.expect("emails");
        assert!(
            !emails[0].verified,
            "another user's attestation must not upgrade the row"
        );

        tenant
            .email_mark_verified_for(carol, "carol@example.com")
            .await
            .expect("owner mark");
        let emails = tenant.all_emails(Some("carol")).await.expect("emails");
        assert!(emails[0].verified, "the owner's attestation upgrades");
    }
}
