use crate::cache::EphemCache;
use crate::config::OTPDTO;
use crate::db::AuthType;
use crate::db::JwtVerify;
use crate::db::Tenant;
use crate::server::ServerState;
use crate::user::User;
use crate::utils::{ApiProblem, ApiResponse};

use anyhow::Result;
use dashmap::mapref::one::RefMut;
use salvo::http::cookie::{Cookie, SameSite};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use toasty::*;

#[derive(Debug, toasty::Model, Clone)]
pub struct OTP {
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

/// Module-level cache for OTP verification codes (token -> 6-digit code).
pub static OTP_CODE_CACHE: LazyLock<EphemCache<String, String>> =
    LazyLock::new(|| EphemCache::new("otp_codes", Some(300)));

impl Tenant {
    /// Strict signup: create the user within this ceremony and
    /// attach the mobile to it. Fails when the username pre-exists, so the
    /// credential is never attached to a user this ceremony did not create.
    /// All-or-nothing: if the attach fails (e.g. the mobile was claimed by
    /// another user between `request` and `verify`), the just-created user
    /// is rolled back so the username is not burned by an orphan row.
    pub async fn signup_user_mobile(&mut self, user_name: &str, mobile: &str) -> Result<()> {
        self.user_create(user_name).await?;
        if let Err(e) = self.mobile_create(user_name, mobile).await {
            // System-initiated rollback — 's gate does not apply.
            self.user_delete(&crate::role::Caller::Bootstrap, user_name)
                .await
                .ok();
            return Err(e);
        }
        Ok(())
    }

    /// Strict signin: the mobile must already belong to `user_name`.
    /// Nothing is attached.
    pub async fn signin_user_mobile(&mut self, user_name: &str, mobile: &str) -> Result<()> {
        let user = self.user_by_mobile(mobile).await?;
        if user.name != user_name {
            return Err(anyhow::anyhow!("Mobile does not belong to this user"));
        }
        Ok(())
    }
    pub async fn all_mobiles(&mut self, username: Option<&str>) -> Result<Vec<OTP>> {
        if let Some(user_name) = username {
            let user = self.user(user_name).await?;
            OTP::filter(OTP::fields().user_id().eq(user.id))
                .exec(&mut self.database)
                .await
                .map_err(Into::into)
        } else {
            OTP::all()
                .exec(&mut self.database)
                .await
                .map_err(Into::into)
        }
    }

    pub async fn mobile_create(&mut self, user_name: &str, mobile: &str) -> Result<()> {
        let user = self.user(user_name).await?;
        match OTP::get_by_id(&mut self.database, mobile).await {
            Ok(otp) => {
                if otp.user_id != user.id {
                    Err(anyhow::anyhow!("Mobile already exist"))
                } else {
                    Ok(())
                }
            }
            Err(_) => toasty::create!(OTP {
                id: mobile,
                user_id: user.id,
            })
            .exec(&mut self.database)
            .await
            .map(|_| ())
            .map_err(Into::into),
        }
    }
    pub async fn mobile_delete(&mut self, user_name: &str, mobile: &str) -> Result<()> {
        let user = self.user(user_name).await?;
        OTP::filter(
            OTP::fields()
                .id()
                .eq(mobile)
                .and(OTP::fields().user_id().eq(user.id)),
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
    mobile: String,
}

#[derive(Deserialize, Debug, ToSchema)]
struct VerifyRequest {
    token: String,
    name: String,
    mobile: String,
    code: String,
    cookie: Option<String>,
}

/// Payload of the 15-minute OTP JWT. A struct (not a bare `String`) because
/// the claim's `data` field is `#[serde(flatten)]`, which can only serialize
/// maps.
///
/// `signup` fixes the ceremony mode at `request` time: `verify`
/// enforces the recorded mode instead of re-deriving it from DB state that
/// may have changed during the token's lifetime. Tokens minted before this
/// field existed deserialize with `signup = false` — signin-only — which
/// fails closed for the old signup-attach attack.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct OtpData {
    mobile: String,
    #[serde(default)]
    signup: bool,
}

#[derive(Deserialize, Serialize, Debug, ToSchema)]
struct MobileResponse {
    ok: bool,
    code: u16,
    msg: String,
    jwt: Option<String>,
}

async fn sendsms(config: &OTPDTO, mobile: &str, code: &str) -> anyhow::Result<String> {
    crate::aliclient::send_otp(
        config.api_key.as_str(),
        config.api_secret.as_str(),
        config.endpoint.as_str(),
        config.region_id.as_str(),
        mobile,
        code,
        config.sign_name.as_str(),
        config.template_code.as_str(),
    )
    .await
}

async fn handle_user<'a>(
    tenant: &mut RefMut<'a, String, Tenant>,
    issuer: &str,
    domain: &str,
    user_name: String,
    mobile: String,
    signup: bool,
    otp_cfg: &OTPDTO,
) -> Result<String, String> {
    if let Ok(token) = tenant
        .jwt_authenticate(
            issuer,
            domain,
            &user_name,
            &OtpData {
                mobile: mobile.clone(),
                signup,
            },
            15,
        )
        .await
    {
        use rsa::rand_core::{OsRng, RngCore};

        let mut rng = OsRng;
        let mut buf = [0u8; 1];
        let mut digits = String::with_capacity(6);
        while digits.len() < 6 {
            rng.fill_bytes(&mut buf);
            digits.push(char::from((buf[0] % 10) + b'0'));
        }
        let code = digits;

        let ret = sendsms(otp_cfg, &mobile, code.as_str()).await;
        if ret.is_ok() {
            OTP_CODE_CACHE
                .insert(format!("{}:{}", domain, token), code)
                .await
                .ok();
            return Ok(token);
        } else {
            return Err("Fail to send SMS".to_string());
        }
    } else {
        return Err("Fail to issue JWT".to_string());
    }
}

#[endpoint(
    summary = "Request OTP",
    request_body = ReqRequest,
    responses(
        (status_code = 200, description = "Success", body = MobileResponse),
        (status_code = 401, description = "Failed", body = MobileResponse),
        (status_code = 429, description = "Per-recipient dispatch budget exhausted", body = MobileResponse)
    )
)]
pub async fn request(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let mut err_msg: String = String::new();
    let state = depot.obtain_mut::<ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state)
        .unwrap_or("")
        .to_string();
    let issuer = crate::utils::get_issuer(req, state).unwrap_or_default();
    if let Some(req_request) = crate::utils::extract::<ReqRequest>(req, None).await {
        // per-recipient throttle on top of the per-IP quota —
        // distributed clients must not be able to SMS-bomb one phone.
        // The number is reduced to digits so formatting rotation
        // (+86..., dashes, spaces) cannot evade the budget.
        let mobile_digits: String = req_request
            .mobile
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect();
        if !crate::utils::send_throttle_allows(&format!("mobile:{mobile_digits}"), 3).await {
            res.status_code(StatusCode::TOO_MANY_REQUESTS);
            res.render(Json(MobileResponse {
                ok: false,
                code: StatusCode::TOO_MANY_REQUESTS.as_u16(),
                msg: "Too many requests".to_string(),
                jwt: None,
            }));
            return;
        }
        if !req_request.name.is_empty() {
            if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
                let cfg = OTPDTO::load(&mut tenant)
                    .await
                    .ok_or("Failed to load OTP config")
                    .unwrap();
                if let Ok(user) = tenant.user_by_mobile(&req_request.mobile).await {
                    // Existing credential: signin ceremony (— verify
                    // will resolve, never attach).
                    match handle_user(
                        &mut tenant,
                        issuer.as_str(),
                        domain.as_str(),
                        user.name,
                        req_request.mobile,
                        false,
                        &cfg,
                    )
                    .await
                    {
                        Ok(token) => {
                            res.status_code(StatusCode::OK);
                            res.render(Json(MobileResponse {
                                ok: true,
                                code: StatusCode::OK.as_u16(),
                                msg: format!("Success{}", err_msg),
                                jwt: Some(token),
                            }));
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
                        req_request.mobile,
                        true,
                        &cfg,
                    )
                    .await
                    {
                        Ok(token) => {
                            res.status_code(StatusCode::OK);
                            res.render(Json(MobileResponse {
                                ok: true,
                                code: StatusCode::OK.as_u16(),
                                msg: format!("Success{}", err_msg),
                                jwt: Some(token),
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
            err_msg = "Empty user name".to_string();
        }
    } else {
        err_msg = "Invalid request".to_string();
    }
    res.status_code(StatusCode::UNAUTHORIZED);
    res.render(Json(MobileResponse {
        ok: false,
        code: StatusCode::UNAUTHORIZED.as_u16(),
        msg: format!("Unauthorized: {}", err_msg),
        jwt: None,
    }))
}

#[endpoint(
    summary = "Verify OTP",
    parameters(
        ("token" = String, Query, description="Unique token"),
        ("name" = String, Query, description="User name"),
        ("mobile" = String, Query, description="User mobile"),
        ("code" = String, Query, description="OTP code"),
    ),
    responses(
        (status_code = 200, description = "Success", body = MobileResponse),
        (status_code = 401, description = "Failed", body = MobileResponse)
    )
)]
pub async fn verify(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let mut err_msg = String::from("");
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
    if let Some(verify_reqest) = crate::utils::extract::<VerifyRequest>(req, None).await {
        if let Some(stored_code) = OTP_CODE_CACHE
            .get_one_shot(&format!("{}:{}", domain, verify_reqest.token))
            .await
        {
            if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
                let data_wrap = tenant
                    .jwt_verify::<OtpData>(
                        issuer.as_str(),
                        &verify_reqest.name,
                        &verify_reqest.token,
                    )
                    .await;
                if data_wrap.is_ok() {
                    let data = data_wrap.unwrap();
                    // Bind the token to the requested mobile and check the
                    // single-use code sent over SMS (functional bug: the
                    // old check compared the mobile number to the code).
                    if data.mobile == verify_reqest.mobile && stored_code == verify_reqest.code {
                        // the ceremony mode is fixed in the signed
                        // token. Signup creates the user within the ceremony
                        // (failing when the name pre-exists); signin only
                        // resolves the mobile's owner and never attaches.
                        let bound = if data.signup {
                            tenant
                                .signup_user_mobile(&verify_reqest.name, &verify_reqest.mobile)
                                .await
                        } else {
                            tenant
                                .signin_user_mobile(&verify_reqest.name, &verify_reqest.mobile)
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
                            previous_fa.insert(AuthType::OTP.as_str().to_string());
                            if let Ok(jwt) = tenant
                                .authenticate_jwt(
                                    &&previous_fa,
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
                                res.render(Json(MobileResponse {
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
            } else {
                err_msg = "Failed to find tenant".to_string();
            }
        } else {
            err_msg = "Invalid request".to_string();
        }
    } else {
        err_msg = "Invalid request".to_string();
    }
    res.status_code(StatusCode::UNAUTHORIZED);
    res.render(Json(MobileResponse {
        ok: false,
        code: StatusCode::UNAUTHORIZED.as_u16(),
        msg: format!("Unauthorized: {}", err_msg),
        jwt: None,
    }))
}

#[endpoint(
    summary = "Remove OTP",
    parameters(
        ("name" = String, Query, description="User name"),
        ("mobile" = String, Query, description="User mobile"),
    ),
    responses(
        (status_code = 200, description = "Success", body = MobileResponse),
        (status_code = 401, description = "Failed", body = MobileResponse)
    )
)]

pub async fn remove(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain_mut::<ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state)
        .unwrap_or("")
        .to_string();
    if let Some(req_request) = crate::utils::extract::<ReqRequest>(req, None).await {
        if !req_request.name.is_empty() {
            if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
                if tenant
                    .mobile_delete(&req_request.name, &req_request.mobile)
                    .await
                    .is_ok()
                {
                    res.status_code(StatusCode::OK);
                    res.render(Json(MobileResponse {
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
    res.render(Json(MobileResponse {
        ok: false,
        code: StatusCode::BAD_REQUEST.as_u16(),
        msg: format!("Failure"),
        jwt: None,
    }))
}

#[derive(Deserialize, Serialize, Debug, ToSchema)]
struct AllMobileRequest {
    pub name: Option<String>,
}
#[derive(Deserialize, Serialize, Debug, ToSchema)]
struct MobileEntry {
    pub name: String,
    pub mobile: String,
}

#[endpoint(
    summary = "Return all mobile numbers of a user",    
    request_body = AllMobileRequest,
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<Vec<MobileEntry>>),
        (status_code = 401, description = "Failed")
    )
)]
pub async fn all_mobile(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain_mut::<ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state)
        .unwrap_or("")
        .to_string();
    if let Some(req_request) = crate::utils::extract::<AllMobileRequest>(req, None).await {
        if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
            if let Ok(data) = tenant.all_mobiles(req_request.name.as_deref()).await {
                let tmp: Vec<MobileEntry> = data
                    .iter()
                    .map(|a| MobileEntry {
                        mobile: a.id.clone(),
                        name: a.user.get().name.clone(),
                    })
                    .collect();
                res.status_code(StatusCode::OK);
                res.render(Json(ApiResponse::ok(tmp)));
                return;
            }
        }
    }
    let err = ApiProblem::validation_error(&format!("Failed to parse request body"));
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err));
}

// ── session-gated mobile add ─────────────────────────────────────────
//
// Closing removed the implicit resolve-or-create path, so an existing
// user had no way to attach a phone. These endpoints restore it the safe
// way: the ceremony is session-gated and the credential is attached to the
// session's own user — never to a client-supplied name. The SMS code to
// the NEW number proves possession before anything is attached.

#[derive(Deserialize, Serialize, Debug, ToSchema)]
struct MobileAddRequest {
    pub mobile: String,
}

#[derive(Deserialize, Serialize, Debug, ToSchema)]
struct MobileAddVerifyRequest {
    pub token: String,
    pub code: String,
}

/// Payload of the 15-minute add-ceremony JWT. The subject is the
/// session user at `add` time; `add_verify` attaches only to that user.
/// Tokens live under the `otp_add:` cache namespace, so a login ceremony
/// can never consume one and vice versa.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct OtpAddData {
    mobile: String,
}

fn generate_otp_code() -> String {
    use rsa::rand_core::{OsRng, RngCore};
    let mut rng = OsRng;
    let mut buf = [0u8; 1];
    let mut digits = String::with_capacity(6);
    while digits.len() < 6 {
        rng.fill_bytes(&mut buf);
        digits.push(char::from((buf[0] % 10) + b'0'));
    }
    digits
}

#[endpoint(
    summary = "Add a mobile number to the session's own account",
    request_body = MobileAddRequest,
    responses(
        (status_code = 200, description = "Success — SMS code sent", body = MobileResponse),
        (status_code = 401, description = "No valid session or failed", body = MobileResponse),
        (status_code = 429, description = "Per-recipient dispatch budget exhausted", body = MobileResponse)
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
            res.render(Json(MobileResponse {
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
    if let Some(req_request) = crate::utils::extract::<MobileAddRequest>(req, None).await {
        // per-recipient throttle — adding must not become an SMS
        // bomb either. Digits-only key so formatting cannot evade.
        let digits: String = req_request
            .mobile
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect();
        if !crate::utils::send_throttle_allows(&format!("mobile:{digits}"), 3).await {
            res.status_code(StatusCode::TOO_MANY_REQUESTS);
            res.render(Json(MobileResponse {
                ok: false,
                code: StatusCode::TOO_MANY_REQUESTS.as_u16(),
                msg: "Too many requests".to_string(),
                jwt: None,
            }));
            return;
        }
        if !req_request.mobile.is_empty() {
            if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
                // An owned number is refused outright — ownership disputes
                // are never settled by whoever asks (class).
                if tenant.user_by_mobile(&req_request.mobile).await.is_ok() {
                    err_msg = "Mobile already in use".to_string();
                } else {
                    let cfg = match OTPDTO::load(&mut tenant).await {
                        Some(c) => c,
                        None => {
                            err_msg = "Failed to load OTP config".to_string();
                            res.status_code(StatusCode::UNAUTHORIZED);
                            res.render(Json(MobileResponse {
                                ok: false,
                                code: StatusCode::UNAUTHORIZED.as_u16(),
                                msg: format!("Unauthorized: {}", err_msg),
                                jwt: None,
                            }));
                            return;
                        }
                    };
                    match tenant
                        .jwt_authenticate(
                            issuer.as_str(),
                            domain.as_str(),
                            &user,
                            &OtpAddData {
                                mobile: req_request.mobile.clone(),
                            },
                            15,
                        )
                        .await
                    {
                        Ok(token) => {
                            let code = generate_otp_code();
                            if sendsms(&cfg, &req_request.mobile, code.as_str())
                                .await
                                .is_ok()
                            {
                                OTP_CODE_CACHE
                                    .insert(format!("otp_add:{}:{}", domain, token), code)
                                    .await
                                    .ok();
                                res.status_code(StatusCode::OK);
                                res.render(Json(MobileResponse {
                                    ok: true,
                                    code: StatusCode::OK.as_u16(),
                                    msg: "Success".to_string(),
                                    jwt: Some(token),
                                }));
                                return;
                            }
                            err_msg = "Fail to send SMS".to_string();
                        }
                        Err(_) => {
                            err_msg = "Fail to issue JWT".to_string();
                        }
                    }
                }
            } else {
                err_msg = "Failed to find tenant".to_string();
            }
        } else {
            err_msg = "Empty mobile".to_string();
        }
    } else {
        err_msg = "Invalid request".to_string();
    }
    res.status_code(StatusCode::UNAUTHORIZED);
    res.render(Json(MobileResponse {
        ok: false,
        code: StatusCode::UNAUTHORIZED.as_u16(),
        msg: format!("Unauthorized: {}", err_msg),
        jwt: None,
    }));
}

#[endpoint(
    summary = "Complete a session-gated mobile add",
    request_body = MobileAddVerifyRequest,
    responses(
        (status_code = 200, description = "Success — mobile attached to the session's account", body = MobileResponse),
        (status_code = 401, description = "No valid session, unknown/consumed token, wrong code, or the number was claimed in the meantime", body = MobileResponse)
    )
)]
pub async fn add_verify(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let err_msg: String;
    let user = match depot.obtain_mut::<JwtVerify>() {
        Ok(v) => v.jwt_data.username.clone(),
        Err(_) => {
            res.status_code(StatusCode::UNAUTHORIZED);
            res.render(Json(MobileResponse {
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
    if let Some(verify_request) = crate::utils::extract::<MobileAddVerifyRequest>(req, None).await {
        if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
            // One-shot consume under the add namespace — login codes can
            // never be consumed here and vice versa.
            let stored = OTP_CODE_CACHE
                .get_one_shot(&format!("otp_add:{}:{}", domain, verify_request.token))
                .await;
            if let Some(stored_code) = stored
                && let Ok(data) = tenant
                    .jwt_verify::<OtpAddData>(&issuer, &user, &verify_request.token)
                    .await
                && stored_code == verify_request.code
            {
                // Attach to the session's own user; `mobile_create`
                // refuses a number owned by anyone else, so a raced claim
                // fails closed.
                if tenant.mobile_create(&user, &data.mobile).await.is_ok() {
                    res.status_code(StatusCode::OK);
                    res.render(Json(MobileResponse {
                        ok: true,
                        code: StatusCode::OK.as_u16(),
                        msg: "Success".to_string(),
                        jwt: None,
                    }));
                    return;
                }
                err_msg = "Mobile already in use".to_string();
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
    res.render(Json(MobileResponse {
        ok: false,
        code: StatusCode::UNAUTHORIZED.as_u16(),
        msg: format!("Unauthorized: {}", err_msg),
        jwt: None,
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use salvo::test::ResponseExt;
    use std::collections::HashSet;
    use std::sync::LazyLock;

    const DOMAIN: &str = "localhost";
    const TEST_ISSUER: &str = "http://localhost";
    const MOBILE: &str = "13800000000";

    /// The revocation store is a process-wide singleton, so all tests share
    /// one backing directory that must outlive every individual test's
    /// TempDir (same pattern as the totp.rs/oidc.rs endpoint tests).
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

    /// In-process tenant with a signing key and one user.
    async fn otp_test_env() -> (crate::server::ServerState, tempfile::TempDir) {
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
            tenant.mobile_create("alice", MOBILE).await.expect("mobile");
        }
        let state = crate::server::ServerState::create(storage, false)
            .await
            .expect("server state");
        (state, tmp)
    }

    fn otp_service(state: crate::server::ServerState) -> Service {
        Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state))
                .push(Router::with_path("verify").post(verify)),
        )
    }

    /// Mints the ceremony token exactly like `request` does (minus the SMS
    /// hop, which needs a live Aliyun endpoint) and seeds the code cache
    /// with a known code under the same key `request` uses.
    async fn issue_ceremony_for(
        state: &crate::server::ServerState,
        name: &str,
        mobile: &str,
        signup: bool,
        code: &str,
    ) -> String {
        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        let token = tenant
            .jwt_authenticate(
                TEST_ISSUER,
                DOMAIN,
                name,
                &OtpData {
                    mobile: mobile.to_string(),
                    signup,
                },
                15,
            )
            .await
            .expect("ceremony token");
        OTP_CODE_CACHE
            .insert(format!("{}:{}", DOMAIN, token), code.to_string())
            .await
            .expect("cache insert");
        token
    }

    /// Signin ceremony token for the fixture user (signup defaults to false
    /// for tokens minted before , so this matches legacy tokens too).
    async fn issue_ceremony(state: &crate::server::ServerState, code: &str) -> String {
        issue_ceremony_for(state, "alice", MOBILE, false, code).await
    }

    async fn post_verify(
        service: &Service,
        body: &serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
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

    // ── regression tests ─────────────────────────────────────────────

    /// The ceremony completes end-to-end once the client holds the token
    /// minted by `request` (now returned in its `jwt` response field).
    #[tokio::test]
    async fn verify_with_issued_token_and_correct_code_succeeds() {
        let (state, _tmp) = otp_test_env().await;
        let service = otp_service(state.clone());
        let token = issue_ceremony(&state, "123456").await;

        let (status, body) = post_verify(
            &service,
            &serde_json::json!({
                "token": token,
                "name": "alice",
                "mobile": MOBILE,
                "code": "123456",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], true);
        assert!(!body["jwt"].as_str().unwrap_or("").is_empty());
    }

    /// The pre-fix frontend sent `token: ''` because `request` discarded
    /// the token; that must be refused, not silently pass.
    #[tokio::test]
    async fn verify_with_empty_token_is_rejected() {
        let (state, _tmp) = otp_test_env().await;
        let service = otp_service(state.clone());

        let (status, body) = post_verify(
            &service,
            &serde_json::json!({
                "token": "",
                "name": "alice",
                "mobile": MOBILE,
                "code": "123456",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_ne!(body["ok"], true);
    }

    #[tokio::test]
    async fn verify_with_wrong_code_is_rejected() {
        let (state, _tmp) = otp_test_env().await;
        let service = otp_service(state.clone());
        let token = issue_ceremony(&state, "123456").await;

        let (status, body) = post_verify(
            &service,
            &serde_json::json!({
                "token": token,
                "name": "alice",
                "mobile": MOBILE,
                "code": "000000",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_ne!(body["ok"], true);
    }

    /// The one-shot code is consumed on first use; a replay of the same
    /// token+code pair must not mint a second session.
    #[tokio::test]
    async fn verify_token_is_single_use() {
        let (state, _tmp) = otp_test_env().await;
        let service = otp_service(state.clone());
        let token = issue_ceremony(&state, "123456").await;
        let body = serde_json::json!({
            "token": token,
            "name": "alice",
            "mobile": MOBILE,
            "code": "123456",
        });

        let (status, _) = post_verify(&service, &body).await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = post_verify(&service, &body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_ne!(body["ok"], true);
    }

    // ── regression tests ─────────────────────────────────────────────

    /// Takeover attempt: a signup ceremony targeting a pre-existing username
    /// must fail and must not attach the attacker's mobile to the victim.
    #[tokio::test]
    async fn signup_with_existing_name_is_rejected_and_attaches_nothing() {
        let (state, _tmp) = otp_test_env().await;
        let service = otp_service(state.clone());
        let attacker_mobile = "13999999999";
        let token = issue_ceremony_for(&state, "alice", attacker_mobile, true, "123456").await;

        let (status, body) = post_verify(
            &service,
            &serde_json::json!({
                "token": token,
                "name": "alice",
                "mobile": attacker_mobile,
                "code": "123456",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_ne!(body["ok"], true);

        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        assert!(tenant.user_by_mobile(attacker_mobile).await.is_err());
        let mobiles = tenant.all_mobiles(Some("alice")).await.expect("mobiles");
        assert_eq!(
            mobiles.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
            vec![MOBILE]
        );
    }

    /// Legit signup: a fresh username is created and the mobile attached
    /// within the same ceremony.
    #[tokio::test]
    async fn signup_with_new_name_creates_user_and_attaches_mobile() {
        let (state, _tmp) = otp_test_env().await;
        let service = otp_service(state.clone());
        let token = issue_ceremony_for(&state, "carol", "13777777777", true, "123456").await;

        let (status, body) = post_verify(
            &service,
            &serde_json::json!({
                "token": token,
                "name": "carol",
                "mobile": "13777777777",
                "code": "123456",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], true);

        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        assert_eq!(
            tenant
                .user_by_mobile("13777777777")
                .await
                .expect("mobile owner")
                .name,
            "carol"
        );
    }

    /// Signup is all-or-nothing: when the mobile already belongs to
    /// someone else, the just-created user is rolled back so the username
    /// stays available instead of being burned by an orphan row.
    #[tokio::test]
    async fn signup_rolls_back_user_when_mobile_is_already_claimed() {
        let (state, _tmp) = otp_test_env().await;
        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");

        assert!(tenant.signup_user_mobile("dave", MOBILE).await.is_err());
        assert!(tenant.user("dave").await.is_err());
    }

    /// A signin ceremony must never attach: an unknown mobile is rejected
    /// instead of provisioning.
    #[tokio::test]
    async fn signin_with_unknown_mobile_is_rejected_and_attaches_nothing() {
        let (state, _tmp) = otp_test_env().await;
        let service = otp_service(state.clone());
        let token = issue_ceremony_for(&state, "alice", "13666666666", false, "123456").await;

        let (status, body) = post_verify(
            &service,
            &serde_json::json!({
                "token": token,
                "name": "alice",
                "mobile": "13666666666",
                "code": "123456",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_ne!(body["ok"], true);

        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        assert!(tenant.user_by_mobile("13666666666").await.is_err());
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

    fn otp_service_with_session(
        state: crate::server::ServerState,
        session: impl salvo::Handler,
    ) -> Service {
        Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state))
                .push(Router::with_path("verify").hoop(session).post(verify)),
        )
    }

    /// Provision bob with a mobile so he can run a signin ceremony.
    async fn create_bob(state: &crate::server::ServerState) {
        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        tenant.user_create("bob").await.expect("bob");
        tenant
            .mobile_create("bob", "13555555555")
            .await
            .expect("bob mobile");
    }

    /// Factor laundering: a session belonging to alice must not contribute
    /// its factors to bob's new JWT.
    #[tokio::test]
    async fn verify_does_not_inherit_factors_from_another_users_session() {
        let (state, _tmp) = otp_test_env().await;
        create_bob(&state).await;
        let service = otp_service_with_session(state.clone(), inject_alice_totp_session);
        let token = issue_ceremony_for(&state, "bob", "13555555555", false, "123456").await;

        let (status, body) = post_verify(
            &service,
            &serde_json::json!({
                "token": token,
                "name": "bob",
                "mobile": "13555555555",
                "code": "123456",
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
            data.mfa.contains(AuthType::OTP.as_str()),
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
        let (state, _tmp) = otp_test_env().await;
        create_bob(&state).await;
        let service = otp_service_with_session(state.clone(), inject_bob_totp_session);
        let token = issue_ceremony_for(&state, "bob", "13555555555", false, "123456").await;

        let (status, body) = post_verify(
            &service,
            &serde_json::json!({
                "token": token,
                "name": "bob",
                "mobile": "13555555555",
                "code": "123456",
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
        assert!(data.mfa.contains(AuthType::OTP.as_str()));
        assert!(
            data.mfa.contains(AuthType::TOTP.as_str()),
            "the same user's prior factor must be carried forward"
        );
    }

    // ── regression tests ──────────────────────────────────────────────

    /// Tenant with OTP config pointing at a dead endpoint — SMS dispatch
    /// fails fast, which is all the throttle probe needs.
    async fn otp_throttle_env() -> (crate::server::ServerState, tempfile::TempDir) {
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
            let config: [(&str, &str); 6] = [
                ("otp.api_secret", "secret"),
                ("otp.api_key", "key"),
                ("otp.template_code", "tpl"),
                ("otp.sign_name", "sign"),
                ("otp.region_id", "cn-hangzhou"),
                ("otp.endpoint", "http://127.0.0.1:9"),
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

    /// regression: the SMS flow is throttled per mobile number. The
    /// in-budget requests end at the SMS send failure (no Aliyun in tests,
    /// hence 401); the 429 on the 4th proves the throttle fires before
    /// dispatch.
    #[tokio::test]
    async fn request_throttles_per_mobile() {
        let (state, _tmp) = otp_throttle_env().await;
        let service = Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state))
                .push(Router::with_path("otp/request").post(request)),
        );

        for i in 0..3 {
            let res = salvo::test::TestClient::post("http://localhost/otp/request")
                .add_header("Host", DOMAIN, true)
                .json(&serde_json::json!({ "name": "u", "mobile": "13800001111" }))
                .send(&service)
                .await;
            assert_ne!(
                res.status_code.expect("status code"),
                StatusCode::TOO_MANY_REQUESTS,
                "request {i} is within the per-recipient budget"
            );
        }
        let res = salvo::test::TestClient::post("http://localhost/otp/request")
            .add_header("Host", DOMAIN, true)
            .json(&serde_json::json!({ "name": "u", "mobile": "138 0000-1111" }))
            .send(&service)
            .await;
        assert_eq!(
            res.status_code.expect("status code"),
            StatusCode::TOO_MANY_REQUESTS,
            "the 4th request for the same number must be throttled — formatting must not evade"
        );
    }

    // ── regression tests (session-gated mobile add) ───────────────────

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
                mfa: HashSet::from([AuthType::OTP.as_str().to_string()]),
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
                mfa: HashSet::from([AuthType::OTP.as_str().to_string()]),
                roles: HashSet::new(),
            },
            expect_mfa: false,
            domain: DOMAIN.to_string(),
            auth_time: None,
        });
        ctrl.call_next(req, depot, res).await;
    }

    fn otp_add_service<H: salvo::Handler>(
        state: crate::server::ServerState,
        session: H,
    ) -> Service {
        Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state))
                .hoop(session)
                .push(Router::with_path("otp/add").post(add))
                .push(Router::with_path("otp/add/verify").post(add_verify)),
        )
    }

    /// An owned number is refused outright — ownership is never settled by
    /// whoever asks (class).
    #[tokio::test]
    async fn add_refuses_an_owned_mobile() {
        use salvo::test::ResponseExt;
        let (state, _tmp) = otp_test_env().await;
        let service = otp_add_service(state, inject_bob_session);

        // alice owns MOBILE (seeded by otp_test_env).
        let mut res = salvo::test::TestClient::post("http://localhost/otp/add")
            .add_header("Host", DOMAIN, true)
            .json(&serde_json::json!({ "mobile": MOBILE }))
            .send(&service)
            .await;
        assert_eq!(
            res.status_code.expect("status code"),
            StatusCode::UNAUTHORIZED
        );
        let body = res.take_string().await.unwrap_or_default();
        assert!(body.contains("already in use"), "{body}");
    }

    /// Mint an add-ceremony token the way `add` does (minus the SMS hop)
    /// and register its code under the `otp_add:` namespace.
    async fn issue_add_ceremony(
        state: &crate::server::ServerState,
        user: &str,
        mobile: &str,
        code: &str,
    ) -> String {
        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        let token = tenant
            .jwt_authenticate(
                TEST_ISSUER,
                DOMAIN,
                user,
                &OtpAddData {
                    mobile: mobile.to_string(),
                },
                15,
            )
            .await
            .expect("ceremony token");
        OTP_CODE_CACHE
            .insert(format!("otp_add:{DOMAIN}:{token}"), code.to_string())
            .await
            .expect("cache insert");
        token
    }

    /// Completing the ceremony attaches the mobile to the session's own
    /// user.
    #[tokio::test]
    async fn add_verify_attaches_mobile_to_the_session_user() {
        use salvo::test::ResponseExt;
        let (state, _tmp) = otp_test_env().await;
        let service = otp_add_service(state.clone(), inject_alice_session);
        let token = issue_add_ceremony(&state, "alice", "13777777777", "123456").await;

        let mut res = salvo::test::TestClient::post("http://localhost/otp/add/verify")
            .add_header("Host", DOMAIN, true)
            .json(&serde_json::json!({ "token": token, "code": "123456" }))
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
                .user_by_mobile("13777777777")
                .await
                .expect("attached mobile")
                .name,
            "alice"
        );
    }

    /// A DIFFERENT session cannot complete someone else's add ceremony.
    #[tokio::test]
    async fn add_verify_refuses_a_foreign_session() {
        let (state, _tmp) = otp_test_env().await;
        {
            let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
            tenant.user_create("bob").await.expect("bob");
        }
        let service = otp_add_service(state.clone(), inject_bob_session);
        let token = issue_add_ceremony(&state, "alice", "13777777777", "123456").await;

        let res = salvo::test::TestClient::post("http://localhost/otp/add/verify")
            .add_header("Host", DOMAIN, true)
            .json(&serde_json::json!({ "token": token, "code": "123456" }))
            .send(&service)
            .await;
        assert_eq!(
            res.status_code.expect("status code"),
            StatusCode::UNAUTHORIZED,
            "a foreign session must not complete the ceremony"
        );

        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        assert!(tenant.user_by_mobile("13777777777").await.is_err());
    }

    /// Namespace separation: an add-ceremony token must not be consumable
    /// at the LOGIN verify endpoint, even though both share
    /// OTP_CODE_CACHE.
    #[tokio::test]
    async fn add_token_is_not_a_login_token() {
        let (state, _tmp) = otp_test_env().await;
        let service = Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state.clone()))
                .push(Router::with_path("otp/verify").post(verify)),
        );
        let token = issue_add_ceremony(&state, "alice", "13777777777", "123456").await;

        let res = salvo::test::TestClient::post("http://localhost/otp/verify")
            .add_header("Host", DOMAIN, true)
            .json(&serde_json::json!({
                "token": token,
                "name": "alice",
                "mobile": "13777777777",
                "code": "123456",
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
