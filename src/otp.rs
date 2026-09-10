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
#[allow(clippy::upper_case_acronyms)] // OTP is a domain acronym
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

/// Module-level cache for OTP verification codes (flow handle -> 6-digit code).
pub static OTP_CODE_CACHE: LazyLock<EphemCache<String, String>> =
    LazyLock::new(|| EphemCache::new("otp_codes", Some(300)));

/// Flow handle -> ceremony JWT (H1). The ceremony JWT's base64 `sub`
/// carries the RESOLVED username, so handing it to the client on the
/// unauthenticated `request` endpoint leaked a phone→username mapping.
/// The client now receives an opaque random handle instead; the JWT —
/// the server-signed envelope binding (name, mobile, signup) — never
/// leaves the process. Same lifetime as the code cache: the handle is
/// meaningless once the one-shot code is consumed or expired.
static OTP_FLOW_CACHE: LazyLock<EphemCache<String, String>> =
    LazyLock::new(|| EphemCache::new("otp_flows", Some(300)));

impl Tenant {
    /// Strict signup: create the user within this ceremony and
    /// attach the mobile to it. Fails when the username pre-exists, so the
    /// credential is never attached to a user this ceremony did not create.
    /// All-or-nothing: if the attach fails (e.g. the mobile was claimed by
    /// another user between `request` and `verify`), the just-created user
    /// is rolled back so the username is not burned by an orphan row.
    pub async fn signup_user_mobile(&mut self, user_name: &str, mobile: &str) -> Result<()> {
        // G-99: signup provisioning grants the builtin `guest` floor.
        self.signup_provision(user_name).await?;
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
        // G-105: store the canonical spelling — one form per phone.
        let mobile =
            canonical_mobile(mobile).ok_or_else(|| anyhow::anyhow!("invalid mobile number"))?;
        let user = self.user(user_name).await?;
        match OTP::get_by_id(&mut self.database, &mobile).await {
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
        // G-105: fold the input so any spelling of a stored number works.
        let mobile =
            canonical_mobile(mobile).ok_or_else(|| anyhow::anyhow!("invalid mobile number"))?;
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
    /// Requested session lifetime in seconds (G-90), clamped to the
    /// 15-minute ceiling — a caller may shorten its session, never
    /// lengthen it. Omitted → 15 minutes.
    #[serde(default)]
    lifetime: Option<i64>,
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
    /// Endpoint-dependent token field (the name is historical):
    /// - `request`: an OPAQUE flow handle — NOT a JWT. Echo it back to
    ///   `verify` as `token`. The ceremony JWT stays server-side (H1):
    ///   its base64 `sub` would leak the resolved username on this
    ///   unauthenticated endpoint.
    /// - `verify` (success): the session JWT.
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

/// Phase 1 of the OTP ceremony — runs WHILE the tenant guard is held:
/// mints the ceremony JWT (needs the tenant's signing key) and draws the
/// 6-digit code. Cheap, local, no network.
async fn prepare_ceremony<'a>(
    tenant: &mut RefMut<'a, String, Tenant>,
    issuer: &str,
    domain: &str,
    user_name: String,
    mobile: String,
    signup: bool,
) -> Result<(String, String), String> {
    if let Ok(token) = tenant
        .jwt_authenticate(issuer, domain, &user_name, &OtpData { mobile, signup }, 15)
        .await
    {
        use rsa::rand_core::{OsRng, RngCore};

        let mut rng = OsRng;
        let mut buf = [0u8; 1];
        let mut digits = String::with_capacity(6);
        while digits.len() < 6 {
            rng.fill_bytes(&mut buf);
            // Rejection sampling: 256 is not a multiple of 10, so a bare
            // `buf[0] % 10` would bias digits 0-5 (26/256) over 6-9
            // (25/256) and shrink the effective code space.
            if buf[0] < 250 {
                digits.push(char::from((buf[0] % 10) + b'0'));
            }
        }
        Ok((token, digits))
    } else {
        Err("Fail to issue JWT".to_string())
    }
}

/// Phase 2 of the OTP ceremony — runs AFTER the tenant guard is dropped
/// (H6): the SMS dispatch is the only network hop, and a hung Aliyun peer
/// must not pin the tenant's `DashMap` write guard (which would stall
/// every other request for the domain). Parks the ceremony state under an
/// opaque flow handle and returns it.
async fn dispatch_ceremony(
    domain: &str,
    otp_cfg: &OTPDTO,
    mobile: &str,
    code: String,
    ceremony_jwt: String,
) -> Result<String, String> {
    if sendsms(otp_cfg, mobile, code.as_str()).await.is_ok() {
        // H1: return an opaque flow handle, never the ceremony JWT —
        // its `sub` would disclose the resolved username to whoever
        // called this unauthenticated endpoint. Both cache entries
        // are keyed by the handle; `verify` resolves it back.
        let flow = crate::oidc::random_urlsafe_string();
        let flow_key = format!("{}:{}", domain, flow);
        OTP_FLOW_CACHE
            .insert(flow_key.clone(), ceremony_jwt)
            .await
            .map_err(|_| "Fail to start OTP ceremony".to_string())?;
        OTP_CODE_CACHE
            .insert(flow_key, code)
            .await
            .map_err(|_| "Fail to start OTP ceremony".to_string())?;
        Ok(flow)
    } else {
        Err("Fail to send SMS".to_string())
    }
}

#[endpoint(
    summary = "Request OTP",
    request_body = ReqRequest,
    responses(
        (status_code = 200, description = "Success", body = MobileResponse),
        (status_code = 401, description = "Failed", body = MobileResponse),
        (status_code = 429, description = "Dispatch budget exhausted, or account locked after repeated verify failures", body = MobileResponse)
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
        // G-105: one spelling per phone number — canonicalize at the
        // boundary so the ceremony token, throttle key, account lookup
        // and provider dispatch all carry the same form, and refuse
        // non-numbers with a clean 400 instead of an opaque provider
        // failure. (Subsumes the old digits-only throttle key.)
        let Some(mobile) = canonical_mobile(&req_request.mobile) else {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(MobileResponse {
                ok: false,
                code: StatusCode::BAD_REQUEST.as_u16(),
                msg: "Invalid mobile number".to_string(),
                jwt: None,
            }));
            return;
        };
        // per-recipient throttle on top of the per-IP quota —
        // distributed clients must not be able to SMS-bomb one phone.
        if !crate::utils::send_throttle_allows(
            &format!("{domain}|mobile:{}", throttle_digits(&mobile)),
            3,
        )
        .await
        {
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
            // A locked-out account gets no fresh codes: issuing one would
            // burn the recipient's dispatch budget for a ceremony that
            // cannot be verified anyway.
            let gate_key = crate::utils::verify_gate_key(&domain, &req_request.name);
            if !crate::utils::verify_gate_allows(&gate_key).await {
                res.status_code(StatusCode::TOO_MANY_REQUESTS);
                res.render(Json(MobileResponse {
                    ok: false,
                    code: StatusCode::TOO_MANY_REQUESTS.as_u16(),
                    msg: "Too many failed attempts; try again later".to_string(),
                    jwt: None,
                }));
                return;
            }
            if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
                // A tenant without SMS provider config fails closed with a
                // clean error (same shape as the add flow) instead of
                // panicking the request task.
                let cfg = match OTPDTO::load(&mut tenant).await {
                    Some(c) => c,
                    None => {
                        res.status_code(StatusCode::UNAUTHORIZED);
                        res.render(Json(MobileResponse {
                            ok: false,
                            code: StatusCode::UNAUTHORIZED.as_u16(),
                            msg: "Unauthorized: Failed to load OTP config".to_string(),
                            jwt: None,
                        }));
                        return;
                    }
                };
                // Phase 1 under the tenant guard: resolve the ceremony
                // identity and mint its JWT (local, cheap).
                let prepared = if let Ok(user) = tenant.user_by_mobile(&mobile).await {
                    // The signin ceremony binds to the RESOLVED account,
                    // not the claimed name — re-check the gate on the
                    // identity the token will carry, so claiming a
                    // throwaway name with a locked-out account's mobile
                    // cannot keep codes flowing to that phone.
                    let resolved_key = crate::utils::verify_gate_key(&domain, &user.name);
                    if !crate::utils::verify_gate_allows(&resolved_key).await {
                        res.status_code(StatusCode::TOO_MANY_REQUESTS);
                        res.render(Json(MobileResponse {
                            ok: false,
                            code: StatusCode::TOO_MANY_REQUESTS.as_u16(),
                            msg: "Too many failed attempts; try again later".to_string(),
                            jwt: None,
                        }));
                        return;
                    }
                    // Existing credential: signin ceremony (— verify
                    // will resolve, never attach).
                    prepare_ceremony(
                        &mut tenant,
                        issuer.as_str(),
                        domain.as_str(),
                        user.name,
                        mobile.clone(),
                        false,
                    )
                    .await
                } else {
                    // Unknown credential: signup ceremony (— verify
                    // will create the user or fail; it never attaches to a
                    // pre-existing user).
                    prepare_ceremony(
                        &mut tenant,
                        issuer.as_str(),
                        domain.as_str(),
                        req_request.name.clone(),
                        mobile.clone(),
                        true,
                    )
                    .await
                };
                // H6: drop the tenant's write guard BEFORE the SMS network
                // hop — a hung Aliyun peer must not stall every other
                // caller for this domain.
                drop(tenant);
                match prepared {
                    Ok((ceremony_jwt, code)) => {
                        match dispatch_ceremony(domain.as_str(), &cfg, &mobile, code, ceremony_jwt)
                            .await
                        {
                            Ok(flow) => {
                                res.status_code(StatusCode::OK);
                                res.render(Json(MobileResponse {
                                    ok: true,
                                    code: StatusCode::OK.as_u16(),
                                    msg: format!("Success{}", err_msg),
                                    jwt: Some(flow),
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
        (status_code = 401, description = "Failed", body = MobileResponse),
        (status_code = 429, description = "Account locked after repeated verify failures", body = MobileResponse)
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
    // Set once the claimed identity is known; the failure fall-through at
    // the bottom records against it — but only when the ceremony token
    // validated for that identity (`ceremony_valid`), so junk bodies
    // cannot create lockout entries for arbitrary names and server-side
    // failures are not charged to the account.
    let mut gate_key: Option<String> = None;
    let mut ceremony_valid = false;
    if let Some(verify_reqest) = crate::utils::extract::<VerifyRequest>(req, None).await {
        // G-89: attribute the authentication attempt — successes AND
        // failures — to the claimed identity.
        crate::audit::record_target_detail(res, "auth", &verify_reqest.name, "factor=otp");
        // The account gate is checked BEFORE the one-shot code is
        // consumed: a locked-out attacker must not be able to burn the
        // code just issued to the legitimate user.
        let key = crate::utils::verify_gate_key(&domain, &verify_reqest.name);
        if !crate::utils::verify_gate_allows(&key).await {
            res.status_code(StatusCode::TOO_MANY_REQUESTS);
            res.render(Json(MobileResponse {
                ok: false,
                code: StatusCode::TOO_MANY_REQUESTS.as_u16(),
                msg: "Too many failed attempts; try again later".to_string(),
                jwt: None,
            }));
            return;
        }
        gate_key = Some(key);
        let flow_key = format!("{}:{}", domain, verify_reqest.token);
        if let Some(stored_code) = OTP_CODE_CACHE.get_one_shot(&flow_key).await {
            if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
                // H1: the client presents the opaque flow handle; the
                // ceremony JWT it maps to never left the server. The
                // handle is consumed alongside the one-shot code.
                let data_wrap = match OTP_FLOW_CACHE.get_one_shot(&flow_key).await {
                    Some(ceremony) => {
                        tenant
                            .jwt_verify::<OtpData>(issuer.as_str(), &verify_reqest.name, &ceremony)
                            .await
                    }
                    None => Err(anyhow::anyhow!("unknown OTP flow handle")),
                };
                if data_wrap.is_ok() {
                    ceremony_valid = true;
                    let data = data_wrap.unwrap();
                    if data.mobile == verify_reqest.mobile && stored_code == verify_reqest.code {
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
                            let mut previous_fa = session
                                .as_ref()
                                .filter(|(user, _)| user == &verify_reqest.name)
                                .map(|(_, mfa)| mfa.clone())
                                .unwrap_or_default();
                            previous_fa.insert(AuthType::OTP.as_str().to_string());
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
                                if let Some(key) = &gate_key {
                                    crate::utils::clear_verify_failures(key).await;
                                }
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
    // Every failed verify of a VALID ceremony counts against the account,
    // across ceremonies: the one-shot code bounds guesses per ceremony,
    // this bounds the request→verify loop itself. Attempts without a
    // token valid for the claimed identity are not recorded — they guess
    // nothing, and recording them would let junk traffic flood the
    // lockout cache.
    if ceremony_valid && let Some(key) = &gate_key {
        crate::utils::record_verify_failure(key).await;
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
        (status_code = 400, description = "Failed", body = MobileResponse),
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
    if let Some(req_request) = crate::utils::extract::<ReqRequest>(req, None).await
        && !req_request.name.is_empty()
        && let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref())
    {
        crate::audit::record_target_detail(
            res,
            "credential",
            &format!("mobile:{}", req_request.mobile),
            &format!("user={},flow=remove", req_request.name),
        );
        if let Ok(target) = tenant.user(&req_request.name).await
            && let Err(e) = tenant.require_above_user(&caller, target.id).await
        {
            crate::utils::render_admin_error(res, e);
            return;
        }
        if tenant
            .mobile_delete(&req_request.name, &req_request.mobile)
            .await
            .is_ok()
        {
            res.status_code(StatusCode::OK);
            res.render(Json(MobileResponse {
                ok: true,
                code: StatusCode::OK.as_u16(),
                msg: "Success".to_string(),
                jwt: None,
            }));
            return;
        }
    }

    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(MobileResponse {
        ok: false,
        code: StatusCode::BAD_REQUEST.as_u16(),
        msg: "Failure".to_string(),
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
    if let Some(req_request) = crate::utils::extract::<AllMobileRequest>(req, None).await
        && let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref())
        && let Ok(data) = tenant.all_mobiles(req_request.name.as_deref()).await
    {
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

    let err = ApiProblem::validation_error("Failed to parse request body");
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

/// The canonical spelling of a mobile identifier (G-105): separators
/// (spaces, dashes, parens, dots) stripped, a leading `+` preserved,
/// every remaining character an ASCII digit. `None` when what is left is
/// empty or non-numeric. The ceremony proves the number receives SMS
/// under ANY formatting — canonicalization guarantees one spelling per
/// phone for storage, lookup and uniqueness, and this is the single
/// format check that earns its keep because the provider would otherwise
/// fail (or silently succeed) on variants.
pub fn canonical_mobile(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let (plus, rest) = match trimmed.strip_prefix('+') {
        Some(r) => (true, r),
        None => (false, trimmed),
    };
    let cleaned: String = rest
        .chars()
        .filter(|c| !matches!(c, ' ' | '-' | '(' | ')' | '.'))
        .collect();
    if cleaned.is_empty() || !cleaned.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(if plus { format!("+{cleaned}") } else { cleaned })
}

/// The throttle key form of a canonical mobile: digits only, so a `+`
/// country-code prefix cannot rotate around the per-recipient budget
/// (the canonical form itself keeps the `+` for storage/lookup).
fn throttle_digits(canonical: &str) -> String {
    canonical.chars().filter(|c| c.is_ascii_digit()).collect()
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
        // G-132 sudo mode: attaching a login credential requires a freshly
        // AUTHENTICATED session, not a merely rotated one — a stolen
        // session must not be able to make the takeover persistent.
        Ok(v) if !crate::verify::session_is_fresh(v) => {
            crate::verify::mark_reauth_required(res);
            res.render(Json(MobileResponse {
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
        crate::audit::record_target_detail(
            res,
            "credential",
            &format!("mobile:{}", req_request.mobile),
            &format!("user={user},flow=add"),
        );
        // G-105: canonicalize at the boundary (see the request flow) —
        // the ceremony token, throttle key and storage all carry one
        // spelling; non-numbers get a clean 400.
        let Some(mobile) = canonical_mobile(&req_request.mobile) else {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(MobileResponse {
                ok: false,
                code: StatusCode::BAD_REQUEST.as_u16(),
                msg: "Invalid mobile number".to_string(),
                jwt: None,
            }));
            return;
        };
        // per-recipient throttle — adding must not become an SMS
        // bomb either.
        if !crate::utils::send_throttle_allows(
            &format!("{domain}|mobile:{}", throttle_digits(&mobile)),
            3,
        )
        .await
        {
            res.status_code(StatusCode::TOO_MANY_REQUESTS);
            res.render(Json(MobileResponse {
                ok: false,
                code: StatusCode::TOO_MANY_REQUESTS.as_u16(),
                msg: "Too many requests".to_string(),
                jwt: None,
            }));
            return;
        }
        if !mobile.is_empty() {
            if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
                if tenant.user_by_mobile(&mobile).await.is_ok() {
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
                                mobile: mobile.clone(),
                            },
                            15,
                        )
                        .await
                    {
                        Ok(token) => {
                            let code = generate_otp_code();
                            // G-153: drop the tenant write guard BEFORE the
                            // SMS network hop (the H6 pattern from the
                            // login request flow) — a slow provider must
                            // not stall every request for the tenant.
                            drop(tenant);
                            if sendsms(&cfg, &mobile, code.as_str()).await.is_ok() {
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
        crate::audit::record_target_detail(res, "auth", &user, "factor=otp,flow=add");
        if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
            let stored = OTP_CODE_CACHE
                .get_one_shot(&format!("otp_add:{}:{}", domain, verify_request.token))
                .await;
            if let Some(stored_code) = stored
                && let Ok(data) = tenant
                    .jwt_verify::<OtpAddData>(&issuer, &user, &verify_request.token)
                    .await
                && stored_code == verify_request.code
            {
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
        // Signing keys are encrypted at rest (H2); the process-wide
        // encryption key is first-call-wins across test envs.
        let _ = crate::crypto::setup_encryption_key(&"0".repeat(64));
        // The verify-failure gate is process-wide; wrong-code tests record
        // against the fixture account, so each env starts with it cleared
        // to keep tests independent.
        crate::utils::clear_verify_failures(&crate::utils::verify_gate_key(DOMAIN, "alice")).await;
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
        let state = crate::server::ServerState::create_with(storage, false, &[])
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
    /// hop, which needs a live Aliyun endpoint) and seeds BOTH caches under
    /// an opaque flow handle — the same contract `request` hands clients
    /// (H1: the ceremony JWT itself never reaches the caller).
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
        let flow = crate::oidc::random_urlsafe_string();
        let flow_key = format!("{}:{}", DOMAIN, flow);
        OTP_FLOW_CACHE
            .insert(flow_key.clone(), token)
            .await
            .expect("flow insert");
        OTP_CODE_CACHE
            .insert(flow_key, code.to_string())
            .await
            .expect("cache insert");
        flow
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

    /// regression H1: the token `request` hands out is an opaque flow
    /// handle, not the ceremony JWT — no `header.payload.signature`
    /// structure, no base64 `sub` leaking the resolved username.
    #[tokio::test]
    async fn ceremony_handle_is_opaque_not_a_jwt() {
        let (state, _tmp) = otp_test_env().await;
        let flow = issue_ceremony(&state, "123456").await;

        assert_ne!(
            flow.split('.').count(),
            3,
            "the flow handle must not be JWT-shaped"
        );
        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        assert!(
            tenant
                .jwt_verify::<OtpData>(TEST_ISSUER, "alice", &flow)
                .await
                .is_err(),
            "the flow handle must not verify as a ceremony JWT"
        );
    }

    /// regression H1: a raw ceremony JWT is no longer a valid `verify`
    /// token — only the flow handle resolves to the server-side envelope,
    /// so a JWT obtained by any other means cannot drive the ceremony.
    #[tokio::test]
    async fn verify_with_raw_ceremony_jwt_is_rejected() {
        let (state, _tmp) = otp_test_env().await;
        let service = otp_service(state.clone());
        // Mint the ceremony JWT directly (the pre-H1 client-visible token)
        // and seed ONLY the code cache under it — the old contract.
        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        let raw_jwt = tenant
            .jwt_authenticate(
                TEST_ISSUER,
                DOMAIN,
                "alice",
                &OtpData {
                    mobile: MOBILE.to_string(),
                    signup: false,
                },
                15,
            )
            .await
            .expect("ceremony token");
        drop(tenant);
        OTP_CODE_CACHE
            .insert(format!("{}:{}", DOMAIN, raw_jwt), "123456".to_string())
            .await
            .expect("cache insert");

        let (status, body) = post_verify(
            &service,
            &serde_json::json!({
                "token": raw_jwt,
                "name": "alice",
                "mobile": MOBILE,
                "code": "123456",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_ne!(body["ok"], true);
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

    /// regression: verify failures count against the account ACROSS
    /// ceremonies — after the budget (5) is exhausted the account locks
    /// out with 429 even for a correct code, and the gated attempt must
    /// not consume the one-shot code.
    #[tokio::test]
    async fn verify_locks_the_account_after_repeated_failures() {
        let (state, _tmp) = otp_test_env().await;
        let service = otp_service(state.clone());

        // Each wrong-code attempt burns one ceremony (the code is
        // one-shot), so every failure needs a fresh token — exactly the
        // distributed request→verify loop the per-account gate bounds.
        for _ in 0..5 {
            let token = issue_ceremony(&state, "123456").await;
            let (status, _body) = post_verify(
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
        }

        let token = issue_ceremony(&state, "123456").await;
        let (status, _body) = post_verify(
            &service,
            &serde_json::json!({
                "token": token,
                "name": "alice",
                "mobile": MOBILE,
                "code": "123456",
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "a locked-out account must be refused before the code is checked"
        );

        // The gated attempt must not have consumed the one-shot code:
        // after the lock clears, the same ceremony completes.
        crate::utils::clear_verify_failures(&crate::utils::verify_gate_key(DOMAIN, "alice")).await;
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

    /// G-105: the canonical mobile form — separators stripped, leading
    /// `+` preserved, digits required.
    #[test]
    fn canonical_mobile_shapes() {
        assert_eq!(
            canonical_mobile("13800000000").as_deref(),
            Some("13800000000")
        );
        assert_eq!(
            canonical_mobile("138 0000-0000").as_deref(),
            Some("13800000000")
        );
        assert_eq!(
            canonical_mobile(" 138(0000)0000 ").as_deref(),
            Some("13800000000")
        );
        assert_eq!(
            canonical_mobile("+86 138-0000.0000").as_deref(),
            Some("+8613800000000")
        );
        assert_eq!(canonical_mobile("+"), None);
        assert_eq!(canonical_mobile(""), None);
        assert_eq!(canonical_mobile("   "), None);
        assert_eq!(canonical_mobile("call me"), None);
        assert_eq!(canonical_mobile("138x0000000"), None);
        // The throttle key ignores the `+` so a country-code prefix
        // cannot rotate around the per-recipient budget.
        assert_eq!(throttle_digits("+8613800000000"), "8613800000000");
    }

    /// G-105: one spelling per phone — storage and lookup canonicalize,
    /// so formatting rotation can neither split an identity nor evade
    /// uniqueness.
    #[tokio::test]
    async fn mobile_identity_canonicalizes() {
        let (state, _tmp) = otp_test_env().await;
        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        tenant.user_create("mobileuser").await.expect("user");
        tenant.user_create("mobilerival").await.expect("rival");

        tenant
            .mobile_create("mobileuser", "139-1111-2222")
            .await
            .expect("create canonicalizes");

        for queried in ["13911112222", "139 1111 2222", "139-1111-2222"] {
            let owner = tenant.user_by_mobile(queried).await.expect("lookup folds");
            assert_eq!(owner.name, "mobileuser", "query {queried:?}");
        }

        let err = tenant
            .mobile_create("mobilerival", "139 (1111) 2222")
            .await
            .expect_err("uniqueness sees through formatting");
        assert!(err.to_string().contains("already"), "{err}");

        assert!(
            tenant
                .mobile_create("mobileuser", "not-a-number")
                .await
                .is_err(),
            "non-numeric identifiers are refused"
        );
        assert!(
            tenant.user_by_mobile("call me").await.is_err(),
            "lookup of a non-number fails cleanly"
        );

        tenant
            .mobile_delete("mobileuser", "139 1111 2222")
            .await
            .expect("delete folds");
        assert!(tenant.user_by_mobile("13911112222").await.is_err());
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

    /// G-132: attaching a mobile credential requires a freshly
    /// AUTHENTICATED session — a stale one gets 403 and no SMS leaves.
    #[tokio::test]
    async fn add_mobile_refuses_stale_session() {
        let (state, _tmp) = otp_test_env().await;
        let service = Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state.clone()))
                .push(
                    Router::with_path("add")
                        .hoop(inject_stale_alice_session)
                        .post(add),
                ),
        );
        let res = salvo::test::TestClient::post("http://localhost/add")
            .add_header("Host", DOMAIN, true)
            .json(&serde_json::json!({ "mobile": "13800000001" }))
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
    /// fails fast, which is all the throttle probe needs. The endpoint is
    /// a BARE HOST (the production shape, cf. seed.toml's
    /// `dysmsapi.aliyuncs.com`): `call_api` prepends `https://`, so a
    /// value like `http://127.0.0.1:9` would mangle into
    /// `https://http://127.0.0.1:9/` — a real DNS lookup of the hostname
    /// "http" that stalls seconds per request with no client timeout.
    async fn otp_throttle_env() -> (crate::server::ServerState, tempfile::TempDir) {
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
            let config: [(&str, &str); 6] = [
                ("otp.api_secret", "secret"),
                ("otp.api_key", "key"),
                ("otp.template_code", "tpl"),
                ("otp.sign_name", "sign"),
                ("otp.region_id", "cn-hangzhou"),
                ("otp.endpoint", "127.0.0.1:9"),
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

        // The throttle is a fixed 60 s wall-clock window: if a minute
        // boundary falls between the first and the fourth request, the
        // budget resets and the 4th slips through (the C3 flake). Start
        // only with enough runway left in the current window; tokio sleep
        // never wakes early, so landing on the boundary is safe — the
        // fresh window carries the full budget.
        let remaining = 60 - jiff::Timestamp::now().as_second().rem_euclid(60);
        if remaining < 5 {
            tokio::time::sleep(std::time::Duration::from_secs(remaining as u64)).await;
        }

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

    /// regression: a tenant without SMS provider config must fail closed
    /// with a clean error, not panic the request task on the missing
    /// config unwrap.
    #[tokio::test]
    async fn request_without_sms_config_fails_closed() {
        // otp_test_env seeds no otp.* config values.
        let (state, _tmp) = otp_test_env().await;
        let service = Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state))
                .push(Router::with_path("otp/request").post(request)),
        );
        let res = salvo::test::TestClient::post("http://localhost/otp/request")
            .add_header("Host", DOMAIN, true)
            .json(&serde_json::json!({ "name": "alice", "mobile": "13800002222" }))
            .send(&service)
            .await;
        assert_eq!(
            res.status_code.expect("status code"),
            StatusCode::UNAUTHORIZED,
            "missing SMS config must fail closed, not panic"
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
                mfa: HashSet::from([AuthType::OTP.as_str().to_string()]),
                roles: HashSet::new(),
            },
            expect_mfa: false,
            domain: DOMAIN.to_string(),
            auth_time: Some(jiff::Timestamp::now().as_second().max(0) as usize),
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

    /// regression: provider credentials are send-capable secrets — the
    /// config table must hold ciphertext, `OTPDTO::load` must still hand
    /// consumers plaintext, and legacy plaintext values must keep loading
    /// through the fallback.
    #[tokio::test]
    async fn otp_provider_keys_are_encrypted_at_rest() {
        let (state, _tmp) = otp_throttle_env().await;
        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");

        // The env seeds legacy plaintext values; load falls back.
        let legacy = OTPDTO::load(&mut tenant).await.expect("legacy load");
        assert_eq!(legacy.api_secret, "secret");
        assert_eq!(legacy.api_key, "key");

        // Re-saving encrypts at rest.
        legacy.save(&mut tenant).await.expect("save");
        let raw = tenant
            .config_get("otp.api_secret")
            .await
            .expect("raw value");
        let raw = raw.as_str().expect("string");
        assert_ne!(raw, "secret", "the config table must hold ciphertext");
        assert_eq!(
            crate::crypto::decrypt_secret(raw).expect("ciphertext"),
            "secret"
        );

        // And load round-trips back to plaintext for consumers.
        let reloaded = OTPDTO::load(&mut tenant).await.expect("reload");
        assert_eq!(reloaded.api_secret, "secret");
        assert_eq!(reloaded.api_key, "key");
    }
}
