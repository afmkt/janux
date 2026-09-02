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
use jiff;
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
        self.user_create(user_name).await?;
        if let Err(e) = self.email_create(user_name, email).await {
            // System-initiated rollback — 's gate does not apply.
            self.user_delete(&crate::role::Caller::Bootstrap, user_name)
                .await
                .ok();
            return Err(e);
        }
        Ok(())
    }

    /// Strict signin: the email must already belong to `user_name`.
    /// Nothing is attached.
    pub async fn signin_user_email(&mut self, user_name: &str, email: &str) -> Result<()> {
        let user = self.user_by_email(email).await?;
        if user.name != user_name {
            return Err(anyhow::anyhow!("Email does not belong to this user"));
        }
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

    pub async fn email_create(&mut self, user_name: &str, email: &str) -> Result<()> {
        let user = self.user(user_name).await?;
        match Email::get_by_id(&mut self.database, email).await {
            Ok(e) => {
                if e.user_id != user.id {
                    Err(anyhow::anyhow!("Email already exist"))
                } else {
                    Ok(())
                }
            }
            Err(_) => toasty::create!(Email {
                id: email,
                user_id: user.id,
            })
            .exec(&mut self.database)
            .await
            .map(|_| ())
            .map_err(Into::into),
        }
    }
    pub async fn email_delete(&mut self, user_name: &str, email: &str) -> Result<()> {
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
    let resend = match config.base_url.as_deref() {
        Some(url) => {
            let cfg = resend_rs::ConfigBuilder::new(config.resend_key.as_str())
                .base_url(url.parse()?)
                .build();
            Resend::with_config(cfg)
        }
        None => Resend::new(config.resend_key.as_ref()),
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
    Ok(tera.render("email", &context).unwrap())
}

/// Return context the magic link carries through the email hop.
#[derive(Default)]
struct MagicLinkContext<'a> {
    client_id: Option<&'a str>,
    state: Option<&'a str>,
    redirect_uri: Option<&'a str>,
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
    drop(q);
    Ok(link)
}

#[allow(clippy::too_many_arguments)]
async fn handle_user<'a>(
    tenant: &mut RefMut<'a, String, Tenant>,
    issuer: &str,
    domain: &str,
    user_name: String,
    email: String,
    signup: bool,
    _state: &'a ServerState,
    ctx: MagicLinkContext<'_>,
) -> Result<String, String> {
    if let Ok(token) = tenant
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
    {
        let subject = "Janux login";
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
        let content = render_email(&cfg, &email, subject, link.as_str()).unwrap();
        if let Ok(_) = send(&cfg, &email, subject, content.as_ref()).await {
            MLINK_CACHE
                .insert(format!("{}:{}", domain, token), user_name)
                .await
                .ok();
            return Ok(token);
        } else {
            return Err("Fail to send email".to_string());
        }
    } else {
        return Err("Fail to issue JWT".to_string());
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
        // per-recipient throttle on top of the per-IP quota —
        // distributed clients must not be able to bombard one inbox and
        // burn the mail quota. The address is lowercased so case rotation
        // cannot evade the budget.
        if !crate::utils::send_throttle_allows(
            &format!("email:{}", req_request.email.to_lowercase()),
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
                };
                if let Ok(user) = tenant.user_by_email(&req_request.email).await {
                    // Existing credential: signin ceremony (— verify
                    // will resolve, never attach).
                    match handle_user(
                        &mut tenant,
                        issuer.as_str(),
                        domain.as_str(),
                        user.name,
                        req_request.email,
                        false,
                        state,
                        ctx,
                    )
                    .await
                    {
                        Ok(_token) => {
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
                } else {
                    // Unknown credential: signup ceremony (— verify
                    // will create the user or fail; it never attaches to a
                    // pre-existing user).
                    match handle_user(
                        &mut tenant,
                        issuer.as_str(),
                        domain.as_str(),
                        req_request.name,
                        req_request.email,
                        true,
                        state,
                        ctx,
                    )
                    .await
                    {
                        Ok(_token) => {
                            res.status_code(StatusCode::OK);
                            res.render(Json(EmailResponse {
                                ok: true,
                                code: StatusCode::OK.as_u16(),
                                msg: format!("Success{}", err_msg),
                                jwt: None,
                            }));
                            // same fall-through as the signin branch.
                            return;
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
    if let Some(verify_reqest) = extract::<VerifyRequest>(req, None).await {
        if let Some(_value) = MLINK_CACHE
            .get_one_shot(&format!("{}:{}", domain, verify_reqest.token))
            .await
        {
            if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
                let data_wrap = tenant
                    .jwt_verify::<MagicLinkData>(
                        issuer.as_str(),
                        &verify_reqest.name,
                        &verify_reqest.token,
                    )
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
                                    15,
                                )
                                .await
                            {
                                if verify_reqest.cookie.is_some() {
                                    let name = verify_reqest.cookie.unwrap();
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
        ("mobile" = String, Query, description="User mobile"),
    ),
    responses(
        (status_code = 200, description = "Success", body = EmailResponse),
        (status_code = 401, description = "Failed", body = EmailResponse)
    )
)]

pub async fn remove(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain_mut::<ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state)
        .unwrap_or("")
        .to_string();
    if let Some(req_request) = extract::<ReqRequest>(req, None).await {
        if !req_request.name.is_empty() {
            if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
                if tenant
                    .email_delete(&req_request.name, &req_request.email)
                    .await
                    .is_ok()
                {
                    res.status_code(StatusCode::OK);
                    res.render(Json(EmailResponse {
                        ok: true,
                        code: StatusCode::OK.as_u16(),
                        msg: format!("Success"),
                        jwt: None,
                    }));
                    return;
                }
            }
        }
    }
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(EmailResponse {
        ok: false,
        code: StatusCode::BAD_REQUEST.as_u16(),
        msg: format!("Failure"),
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
    if let Some(req_request) = extract::<AllEmailRequest>(req, None).await {
        if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
            if let Ok(data) = tenant.all_emails(req_request.name.as_deref()).await {
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
        }
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

async fn add_user_email_ceremony(
    tenant: &mut RefMut<'_, String, Tenant>,
    issuer: &str,
    domain: &str,
    user_name: &str,
    email: &str,
) -> Result<String, String> {
    if let Ok(token) = tenant
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
    {
        let subject = "Confirm your email";
        let cfg = ResendDTO::load(tenant)
            .await
            .ok_or("Failed to load email config")?;
        let link = build_magic_link(
            cfg.verify_url.as_str(),
            token.as_str(),
            user_name,
            email,
            MagicLinkContext::default(),
        )
        .map_err(|e| format!("Invalid verify_url in email config: {e}"))?;
        let content = render_email(&cfg, email, subject, link.as_str()).unwrap();
        if send(&cfg, email, subject, content.as_ref()).await.is_ok() {
            MLINK_CACHE
                .insert(
                    format!("email_add:{}:{}", domain, token),
                    user_name.to_string(),
                )
                .await
                .ok();
            return Ok(token);
        }
        return Err("Fail to send email".to_string());
    }
    Err("Fail to issue JWT".to_string())
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
        let email = req_request.email.to_lowercase();
        // per-recipient throttle — adding must not become a mail
        // bomb either.
        if !crate::utils::send_throttle_allows(&format!("email:{email}"), 3).await {
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
                    match add_user_email_ceremony(
                        &mut tenant,
                        issuer.as_str(),
                        domain.as_str(),
                        &user,
                        &email,
                    )
                    .await
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
                // Attach to the session's own user; `email_create`
                // refuses an address owned by anyone else, so a raced
                // claim fails closed.
                if tenant
                    .email_create(&user, &verify_request.email)
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
        let state = crate::server::ServerState::create(storage, false)
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
            auth_time: None,
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
            auth_time: None,
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
        let state = crate::server::ServerState::create(storage, false)
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
            auth_time: None,
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
            auth_time: None,
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
}
