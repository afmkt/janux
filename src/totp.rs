use crate::db::AuthType;
use crate::db::JwtVerify;
use crate::db::Tenant;
use crate::domain::Domain;
use crate::server::ServerState;
use crate::user::User;
use crate::utils::{ApiProblem, ApiResponse, extract};
use anyhow::Result;
use salvo::http::cookie::{Cookie, SameSite};

use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::LazyLock;

use toasty::*;
use totp_rs::{Algorithm, Secret, TOTP};

/// Issued enrollment tokens, keyed `domain:token`. `verify`
/// consumes them one-shot so a captured token cannot mint sessions after
/// the first successful ceremony. TTL matches the token's 15-minute
/// validity.
pub static TOTP_ENROLL_CACHE: LazyLock<crate::cache::EphemCache<String, String>> =
    LazyLock::new(|| crate::cache::EphemCache::new("totp_enroll_tokens", Some(900)));

/// The start of the current TOTP time step. The 30 s period MUST match the
/// one passed to `TOTP::new` in `Totp::totp`.
fn step_start() -> jiff::Timestamp {
    let now = jiff::Timestamp::now().as_second();
    jiff::Timestamp::from_second(now - now.rem_euclid(30)).expect("valid step timestamp")
}

#[derive(Debug, toasty::Model, Clone)]

pub struct Totp {
    #[key]
    #[index]
    pub user_id: uuid::Uuid,
    #[key]
    #[index]
    domain_id: String,

    #[index]
    #[key]
    pub name: String,

    #[index]
    #[default(false)]
    pub active: bool,

    pub secret: String,

    pub last_used: jiff::Timestamp,

    #[auto]
    pub created_at: jiff::Timestamp,
    #[auto]
    pub updated_at: jiff::Timestamp,

    #[belongs_to(key = user_id, references = id)]
    pub user: Deferred<User>,

    #[belongs_to(key = domain_id, references = id)]
    pub domain: Deferred<Domain>,
}

impl Totp {
    fn totp(&self) -> Result<TOTP> {
        TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Raw(self.secret.as_bytes().to_vec())
                .to_bytes()
                .unwrap(),
            Some(self.domain_id.clone()),
            self.user_id.to_string(),
        )
        .map_err(Into::into)
    }
    pub fn code(&self) -> Result<String> {
        let totp = self.totp()?;
        totp.generate_current().map_err(Into::into)
    }
    /// whether `code` can still be accepted — it must match the
    /// current step, and that step must not have been consumed already
    /// (TOTP codes are one-shot).
    pub fn code_is_fresh(&self, code: &str) -> bool {
        self.last_used < step_start() && self.code().ok().as_deref() == Some(code)
    }
    pub fn uri(&self) -> Result<String> {
        let totp = self.totp()?;
        Ok(totp.get_url())
    }
    pub fn qr(&self) -> Result<String> {
        let totp = self.totp()?;
        totp.get_qr_base64().map_err(|s| anyhow::anyhow!(s))
    }
}

impl Tenant {
    pub async fn all_totps(
        &mut self,
        user: Option<&str>,
        domain: Option<&str>,
    ) -> Result<Vec<Totp>> {
        let uid = match user {
            Some(name) => Some(self.user(name).await?.id),
            None => None,
        };
        if let Some(user_id) = uid {
            if let Some(domain_name) = domain {
                Totp::filter(
                    Totp::fields()
                        .user_id()
                        .eq(user_id)
                        .and(Totp::fields().domain_id().eq(domain_name)),
                )
                .exec(&mut self.database)
                .await
                .map_err(Into::into)
            } else {
                Totp::filter(Totp::fields().user_id().eq(user_id))
                    .exec(&mut self.database)
                    .await
                    .map_err(Into::into)
            }
        } else {
            if let Some(domain_name) = domain {
                Totp::filter(Totp::fields().domain_id().eq(domain_name))
                    .exec(&mut self.database)
                    .await
                    .map_err(Into::into)
            } else {
                Totp::all()
                    .exec(&mut self.database)
                    .await
                    .map_err(Into::into)
            }
        }
    }
    pub async fn totp_of(&mut self, user: &str, domain: &str, name: Option<&str>) -> Result<Totp> {
        let user_id = self.user(user).await?.id;
        if let Some(sname) = name {
            let ts = Totp::filter_by_user_id(user_id)
                .filter(
                    Totp::fields()
                        .name()
                        .eq(sname)
                        .and(Totp::fields().domain_id().eq(domain)),
                )
                .exec(&mut self.database)
                .await?;
            if ts.len() > 0 {
                Ok(ts[0].clone())
            } else {
                Err(anyhow::anyhow!("User doesn't have TOTP"))
            }
        } else {
            let ts = Totp::filter_by_user_id(user_id)
                .filter(
                    Totp::fields()
                        .active()
                        .eq(true)
                        .and(Totp::fields().domain_id().eq(domain)),
                )
                .exec(&mut self.database)
                .await?;
            if ts.len() > 0 {
                Ok(ts[0].clone())
            } else {
                Err(anyhow::anyhow!("User doesn't have TOTP"))
            }
        }
    }
    pub async fn new_totp(&mut self, user: &str, name: &str, domain: &str) -> Result<Totp> {
        let secret = Secret::generate_secret().to_string();
        self.add_totp(user, name, domain, secret.as_str()).await
    }
    pub async fn add_totp(
        &mut self,
        user: &str,
        name: &str,
        domain: &str,
        secret: &str,
    ) -> Result<Totp> {
        let user = self.user(user).await?;
        toasty::create!(Totp {
            name: name.to_string(),
            user_id: user.id,
            domain_id: domain.to_string(),
            active: false,
            secret: secret.to_string(),
            // epoch = "never used"; the first accepted code records
            // its step here.
            last_used: jiff::Timestamp::from_second(0).expect("epoch")
        })
        .exec(&mut self.database)
        .await
        .map_err(Into::into)
    }

    /// record the accepted time step. From then on, codes from this
    /// step or an earlier one are refused — TOTP codes are one-shot.
    pub async fn totp_mark_used(
        &mut self,
        user: &str,
        name: &str,
        domain: &str,
        step: jiff::Timestamp,
    ) -> Result<()> {
        let user = self.user(user).await?;
        toasty::update!(Totp::filter(
            Totp::fields()
                .user_id()
                .eq(user.id)
                .and(Totp::fields().name().eq(name))
                .and(Totp::fields().domain_id().eq(domain)))
        { last_used: step })
        .exec(&mut self.database)
        .await
        .map(|_| ())
        .map_err(Into::into)
    }

    pub async fn delete_totp(&mut self, user: &str, name: &str, domain: &str) -> Result<()> {
        let user = self.user(user).await?;
        Totp::filter(
            Totp::fields()
                .user_id()
                .eq(user.id)
                .and(Totp::fields().name().eq(name))
                .and(Totp::fields().domain_id().eq(domain)),
        )
        .delete()
        .exec(&mut self.database)
        .await
        .map_err(Into::into)
    }

    pub async fn active_totp(&mut self, user: &str, name: &str, domain: &str) -> Result<Totp> {
        let user = self.user(user).await?;
        toasty::update!(Totp::filter(Totp::fields().user_id().eq(user.id).and(Totp::fields().domain_id().eq(domain))) {
            active: false
        })
        .exec(&mut self.database)
        .await?;

        toasty::update!(Totp::filter(Totp::fields().user_id().eq(user.id).and(Totp::fields().name().eq(name)).and(Totp::fields().domain_id().eq(domain))) {
            active: true
        }).exec(&mut self.database).await?;

        let ret = Totp::filter(
            Totp::fields()
                .user_id()
                .eq(user.id)
                .and(Totp::fields().name().eq(name))
                .and(Totp::fields().domain_id().eq(domain)),
        )
        .exec(&mut self.database)
        .await?;
        Ok(ret[0].clone())
    }
}

#[derive(Deserialize, Serialize, Debug, ToSchema)]
struct EnrollTotpRequest {
    #[serde(default)]
    pub user: Option<String>,
    pub name: String,
    /// Required when a TOTP with this name is already ACTIVE: a valid
    /// current code proving possession before the active secret is
    /// re-exposed. The code is consumed.
    #[serde(default)]
    pub code: Option<String>,
}

/// Payload of the 15-minute enrollment JWT. A struct (not a `Vec<String>`)
/// because the claim's `data` field is `#[serde(flatten)]`, which can only
/// serialize maps. Binds the token to one (domain, user, name) enrollment.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct TotpEnrollData {
    domain: String,
    user: String,
    name: String,
}

#[derive(Deserialize, Serialize, Debug, ToSchema)]
struct EnrollTotpResponse {
    pub user: String,
    pub name: String,
    pub qr: String,
    pub uri: String,
    pub domain: String,
    pub token: String,
}

#[endpoint(
    summary = "Enroll TOTP",
    request_body = EnrollTotpRequest,
    responses(
        (status_code = 200, description = "Success", body = EnrollTotpResponse),
        (status_code = 401, description = "Failed", body = ApiProblem)
    )
)]
pub async fn enroll(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let user = match depot.obtain_mut::<JwtVerify>() {
        Ok(v) => v.jwt_data.username.clone(),
        Err(_) => {
            res.status_code(StatusCode::UNAUTHORIZED);
            res.render(Json(ApiProblem::unauthorized()));
            return;
        }
    };
    let state = depot.obtain_mut::<ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state)
        .unwrap_or("")
        .to_string();
    let issuer = crate::utils::get_issuer(req, state).unwrap_or_default();
    if let Some(req_request) = extract::<EnrollTotpRequest>(req, None).await {
        // the name can not be empty string ""
        if !req_request.name.is_empty() {
            if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
                let mut totp = tenant
                    .totp_of(&user, &domain, Some(&req_request.name))
                    .await;
                if totp.is_err() {
                    totp = tenant.new_totp(&user, &req_request.name, &domain).await;
                } else if let Ok(existing) = &totp {
                    // re-enrolling an ACTIVE record re-exposes the
                    // live secret — require (and consume) a valid current
                    // code as proof of possession first. An inactive record
                    // holds no working credential, so re-issuing its QR is
                    // harmless.
                    if existing.active {
                        let possessed = req_request
                            .code
                            .as_deref()
                            .is_some_and(|c| existing.code_is_fresh(c));
                        if !possessed
                            || tenant
                                .totp_mark_used(&user, &req_request.name, &domain, step_start())
                                .await
                                .is_err()
                        {
                            res.status_code(StatusCode::UNAUTHORIZED);
                            res.render(Json(ApiProblem::unauthorized()));
                            return;
                        }
                    }
                }
                if let Ok(tp) = totp {
                    // The new TOTP stays inactive until `verify` proves possession
                    // of the secret with a valid code — enrolling must never
                    // deactivate the user's existing, working TOTP.
                    if let Ok(qr) = tp.qr() {
                        let jdata = TotpEnrollData {
                            domain: domain.clone(),
                            user: user.clone(),
                            name: req_request.name.clone(),
                        };
                        if let Ok(token) = tenant
                            .jwt_authenticate(&issuer, &domain, &user, &jdata, 15)
                            .await
                        {
                            // register the token for one-shot
                            // consumption at `verify`.
                            TOTP_ENROLL_CACHE
                                .insert(format!("{}:{}", domain, token), user.clone())
                                .await
                                .ok();
                            let data = EnrollTotpResponse {
                                user,
                                name: req_request.name,
                                qr,
                                uri: tp.uri().unwrap(),
                                domain,
                                token: token.clone(),
                            };
                            res.status_code(StatusCode::OK);
                            res.render(Json(ApiResponse::ok(data)));
                            return;
                        }
                    }
                }
            }
        }
    }
    res.status_code(StatusCode::UNAUTHORIZED);
    res.render(Json(ApiProblem::unauthorized()))
}

#[derive(Deserialize, Serialize, Debug, ToSchema)]
pub struct VerifyTotpRequest {
    user: String,
    name: Option<String>,
    code: String,
    token: Option<String>,
    cookie: Option<String>,
}

async fn verify_totp(
    state: &mut ServerState,
    session: Option<&(String, HashSet<String>)>,
    domain: &str,
    req: &mut Request,
    res: &mut Response,
) {
    let issuer = crate::utils::get_issuer(req, state).unwrap_or_default();
    if let Some(verify_reqest) = extract::<VerifyTotpRequest>(req, None).await {
        if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
            let check = match verify_reqest.token.as_deref() {
                Some(token) => {
                    // enrollment tokens are one-shot — consume before
                    // validation so a captured token cannot mint a second
                    // session with a later code.
                    if TOTP_ENROLL_CACHE
                        .get_one_shot(&format!("{}:{}", domain, token))
                        .await
                        .is_none()
                    {
                        false
                    } else {
                        match tenant
                            .jwt_verify::<TotpEnrollData>(&issuer, &verify_reqest.user, token)
                            .await
                        {
                            // Enrollment tokens bind (domain, user, name); the name
                            // is enforced when the request supplies one.
                            Ok(data) => {
                                data.domain == domain
                                    && data.user == verify_reqest.user
                                    && match verify_reqest.name.as_deref() {
                                        Some(name) => data.name == name,
                                        None => true,
                                    }
                            }
                            Err(_) => false,
                        }
                    }
                }
                None => false,
            };
            if check {
                if let Ok(totp) = tenant
                    .totp_of(&verify_reqest.user, &domain, verify_reqest.name.as_deref())
                    .await
                {
                    // codes are one-shot — `code_is_fresh` refuses a
                    // step that was already consumed (replay), whether with
                    // this token or any other.
                    if totp.code_is_fresh(&verify_reqest.code) {
                        // First successful confirmation activates the TOTP and only
                        // then replaces any previously active ones — possession of
                        // the secret is proven at this point.
                        if totp.active
                            || tenant
                                .active_totp(&verify_reqest.user, &totp.name, &totp.domain_id)
                                .await
                                .is_ok()
                        {
                            // consume the code's step before minting;
                            // if the record cannot be updated, fail closed.
                            if tenant
                                .totp_mark_used(
                                    &verify_reqest.user,
                                    &totp.name,
                                    &totp.domain_id,
                                    step_start(),
                                )
                                .await
                                .is_err()
                            {
                                res.status_code(StatusCode::UNAUTHORIZED);
                                res.render(Json(ApiProblem::unauthorized()));
                                return;
                            }
                            // inherit prior factors only from a session
                            // belonging to the user being authenticated; an
                            // unrelated session contributes none (passkey
                            // pattern).
                            let mut tmp = session
                                .filter(|(user, _)| user == &verify_reqest.user)
                                .map(|(_, mfa)| mfa.clone())
                                .unwrap_or_default();
                            tmp.insert(AuthType::TOTP.as_str().to_string());

                            if let Ok(jwt) = tenant
                                .authenticate_jwt(
                                    &tmp,
                                    &issuer,
                                    domain.as_ref(),
                                    &verify_reqest.user,
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
                                res.render(Json(ApiResponse::ok(jwt)));
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
    res.status_code(StatusCode::UNAUTHORIZED);
    res.render(Json(ApiProblem::unauthorized()))
}

#[endpoint(
    summary = "Request Magic Link",
    request_body = VerifyTotpRequest,
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<String>),
        (status_code = 401, description = "Failed", body = ApiProblem)
    )
)]

pub async fn verify(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let _err_msg = String::from("");
    let jwt_verify_wrap = { depot.obtain::<JwtVerify>().ok().map(|a| a.clone()) };
    if let Some(jwt_verify) = jwt_verify_wrap {
        let state = depot.obtain_mut::<ServerState>().unwrap();
        // the (user, factors) pair is passed through so `verify_totp`
        // can filter inheritance once the authenticated identity is known.
        let session = (jwt_verify.jwt_data.username, jwt_verify.jwt_data.mfa);
        verify_totp(state, Some(&session), &jwt_verify.domain, req, res).await;
    } else {
        let state = depot.obtain_mut::<ServerState>().unwrap();
        let domain = match crate::utils::get_domain(req, state) {
            Some(d) => d.to_string(),
            None => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(ApiProblem::unauthorized()));
                return;
            }
        };
        verify_totp(state, None, &domain, req, res).await;
    }
}

// ── Admin TOTP management endpoints ────────────────────────────────────────

#[derive(Deserialize, Serialize, Debug, ToSchema)]
struct AllTotpRequest {
    pub name: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, ToSchema)]
struct TotpEntry {
    pub name: String,
    pub active: bool,
}

#[endpoint(
    summary = "Return all TOTP entries for a user",
    request_body = AllTotpRequest,
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<Vec<TotpEntry>>),
        (status_code = 401, description = "Failed", body = ApiProblem)
    )
)]
pub async fn list_totp(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain_mut::<ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state)
        .unwrap_or("")
        .to_string();
    if let Some(req_request) = crate::utils::extract::<AllTotpRequest>(req, None).await {
        if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
            if let Ok(data) = tenant.all_totps(req_request.name.as_deref(), None).await {
                let tmp: Vec<TotpEntry> = data
                    .iter()
                    .map(|a| TotpEntry {
                        name: a.name.clone(),
                        active: a.active,
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
    res.render(Json(err))
}

#[derive(Deserialize, Serialize, Debug, ToSchema)]
struct RemoveTotpRequest {
    pub name: String,
    pub totp: String,
}

#[endpoint(
    summary = "Remove a TOTP entry",
    request_body = RemoveTotpRequest,
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<()>),
        (status_code = 401, description = "Failed", body = ApiProblem)
    )
)]
pub async fn remove_totp(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain_mut::<ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state)
        .unwrap_or("")
        .to_string();
    if let Some(req_request) = crate::utils::extract::<RemoveTotpRequest>(req, None).await {
        if !req_request.name.is_empty() && !req_request.totp.is_empty() {
            if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
                if tenant
                    .delete_totp(&req_request.name, &req_request.totp, &domain)
                    .await
                    .is_ok()
                {
                    res.status_code(StatusCode::OK);
                    res.render(Json(ApiResponse::ok(())));
                    return;
                }
            }
        }
    }
    let err = ApiProblem::validation_error("Failure");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{JwtData, JwtVerify};
    use salvo::test::ResponseExt;
    use std::sync::LazyLock;

    const DOMAIN: &str = "localhost";
    const TEST_ISSUER: &str = "http://localhost";

    /// The revocation store is a process-wide singleton, so all tests share one
    /// backing directory that must outlive every individual test's TempDir
    /// (same pattern as the oidc.rs endpoint tests).
    static TEST_STORE_DIR: LazyLock<tempfile::TempDir> =
        LazyLock::new(|| tempfile::tempdir().expect("tempdir"));

    /// toasty spawns the store's connection task on whichever runtime is
    /// current during `init_global`; a `#[tokio::test]` runtime dies with its
    /// test. Initialize once on a dedicated multi-thread runtime whose
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
    async fn totp_test_env() -> (crate::server::ServerState, tempfile::TempDir) {
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
        }
        let state = crate::server::ServerState::create(storage, false)
            .await
            .expect("server state");
        (state, tmp)
    }

    /// Stands in for the `protect` hoop's outcome: an authenticated session
    /// for `alice` already injected into the depot. The policy engine is not
    /// part of these tests.
    #[handler]
    async fn inject_alice_session(
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        depot.inject(JwtVerify {
            can_access: true,
            jwt_data: JwtData {
                user: "alice".to_string(),
                username: "alice".to_string(),
                domain: DOMAIN.to_string(),
                mfa: HashSet::new(),
                roles: HashSet::new(),
            },
            expect_mfa: false,
            domain: DOMAIN.to_string(),
            auth_time: None,
        });
        ctrl.call_next(req, depot, res).await;
    }

    fn totp_service(state: crate::server::ServerState) -> Service {
        Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state))
                .push(
                    Router::with_path("enroll")
                        .hoop(inject_alice_session)
                        .post(enroll),
                )
                .push(Router::with_path("verify").post(verify)),
        )
    }

    /// Same as `totp_service`, but the verify route runs inside an injected
    /// session (probes).
    fn totp_service_with_verify_session(
        state: crate::server::ServerState,
        session: impl salvo::Handler,
    ) -> Service {
        Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state))
                .push(
                    Router::with_path("enroll")
                        .hoop(inject_alice_session)
                        .post(enroll),
                )
                .push(Router::with_path("verify").hoop(session).post(verify)),
        )
    }

    /// Stands in for a session belonging to a DIFFERENT user (mallory)
    /// carrying an OTP factor — the laundering probe.
    #[handler]
    async fn inject_mallory_otp_session(
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        depot.inject(JwtVerify {
            can_access: true,
            jwt_data: JwtData {
                user: "mallory".to_string(),
                username: "mallory".to_string(),
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

    async fn post_enroll(
        service: &Service,
        body: &serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let mut res = salvo::test::TestClient::post("http://localhost/enroll")
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

    async fn totp_record(state: &crate::server::ServerState, name: &str) -> Option<Totp> {
        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        tenant.totp_of("alice", DOMAIN, Some(name)).await.ok()
    }

    fn current_code(totp: &Totp) -> String {
        totp.code().expect("totp code")
    }

    // ── regression tests ─────────────────────────────────────────────────

    #[tokio::test]
    async fn enroll_creates_inactive_totp_and_ignores_body_user() {
        let (state, _tmp) = totp_test_env().await;
        let service = totp_service(state.clone());

        // The body `user` field must be ignored; the session identity wins.
        let (status, body) = post_enroll(
            &service,
            &serde_json::json!({ "user": "mallory", "name": "device1" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"]["user"], "alice");
        assert!(!body["data"]["token"].as_str().unwrap_or("").is_empty());

        let totp = totp_record(&state, "device1")
            .await
            .expect("totp persisted");
        assert!(!totp.active, "enrollment must not auto-activate");
        assert!(
            totp_record(&state, "mallory-device").await.is_none()
                && state
                    .storage
                    .tenant_by_domain(DOMAIN)
                    .expect("tenant")
                    .user("mallory")
                    .await
                    .is_err(),
            "body-supplied user must not be acted upon"
        );
    }

    #[tokio::test]
    async fn verify_with_token_and_code_activates_and_issues_session() {
        let (state, _tmp) = totp_test_env().await;
        let service = totp_service(state.clone());

        let (_status, body) =
            post_enroll(&service, &serde_json::json!({ "name": "device1" })).await;
        let token = body["data"]["token"].as_str().expect("token").to_string();
        let code = current_code(&totp_record(&state, "device1").await.expect("totp"));

        let (status, body) = post_verify(
            &service,
            &serde_json::json!({ "user": "alice", "name": "device1", "code": code, "token": token }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let jwt = body["data"].as_str().expect("session jwt");
        assert!(!jwt.is_empty());

        let totp = totp_record(&state, "device1").await.expect("totp");
        assert!(totp.active, "first confirmed code activates the TOTP");

        // The issued session carries the TOTP factor.
        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        let alice = tenant.user("alice").await.expect("alice");
        let data: JwtData = tenant
            .jwt_verify(TEST_ISSUER, &alice.id.to_string(), jwt)
            .await
            .expect("session jwt verifies");
        assert!(data.mfa.contains(crate::db::AuthType::TOTP.as_str()));
    }

    #[tokio::test]
    async fn enrolling_second_totp_does_not_deactivate_first() {
        let (state, _tmp) = totp_test_env().await;
        let service = totp_service(state.clone());

        let (_status, body) =
            post_enroll(&service, &serde_json::json!({ "name": "device1" })).await;
        let token1 = body["data"]["token"].as_str().expect("token").to_string();
        let code1 = current_code(&totp_record(&state, "device1").await.expect("totp"));
        let (status, _body) = post_verify(
            &service,
            &serde_json::json!({ "user": "alice", "name": "device1", "code": code1, "token": token1 }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(totp_record(&state, "device1").await.expect("totp").active);

        // Enrolling a second device must not touch the working first one.
        let (status, _body) =
            post_enroll(&service, &serde_json::json!({ "name": "device2" })).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            totp_record(&state, "device1").await.expect("totp").active,
            "existing active TOTP must survive a new enrollment"
        );
        assert!(!totp_record(&state, "device2").await.expect("totp").active);
    }

    #[tokio::test]
    async fn confirming_second_totp_replaces_first() {
        let (state, _tmp) = totp_test_env().await;
        let service = totp_service(state.clone());

        let (_status, body) =
            post_enroll(&service, &serde_json::json!({ "name": "device1" })).await;
        let token1 = body["data"]["token"].as_str().expect("token").to_string();
        let code1 = current_code(&totp_record(&state, "device1").await.expect("totp"));
        let (status, _body) = post_verify(
            &service,
            &serde_json::json!({ "user": "alice", "name": "device1", "code": code1, "token": token1 }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (_status, body) =
            post_enroll(&service, &serde_json::json!({ "name": "device2" })).await;
        let token2 = body["data"]["token"].as_str().expect("token").to_string();
        let code2 = current_code(&totp_record(&state, "device2").await.expect("totp"));
        let (status, _body) = post_verify(
            &service,
            &serde_json::json!({ "user": "alice", "name": "device2", "code": code2, "token": token2 }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Replacement happens only after possession of device2 was proven.
        assert!(totp_record(&state, "device2").await.expect("totp").active);
        assert!(
            !totp_record(&state, "device1").await.expect("totp").active,
            "old TOTP is deactivated only when the new one is confirmed"
        );
    }

    #[tokio::test]
    async fn verify_without_token_is_rejected_and_totp_stays_inactive() {
        let (state, _tmp) = totp_test_env().await;
        let service = totp_service(state.clone());

        let (_status, _body) =
            post_enroll(&service, &serde_json::json!({ "name": "device1" })).await;
        let code = current_code(&totp_record(&state, "device1").await.expect("totp"));

        let (status, _body) = post_verify(
            &service,
            &serde_json::json!({ "user": "alice", "name": "device1", "code": code }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(!totp_record(&state, "device1").await.expect("totp").active);
    }

    #[tokio::test]
    async fn verify_with_wrong_code_is_rejected_and_totp_stays_inactive() {
        let (state, _tmp) = totp_test_env().await;
        let service = totp_service(state.clone());

        let (_status, body) =
            post_enroll(&service, &serde_json::json!({ "name": "device1" })).await;
        let token = body["data"]["token"].as_str().expect("token").to_string();

        let (status, _body) = post_verify(
            &service,
            &serde_json::json!({ "user": "alice", "name": "device1", "code": "000000", "token": token }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(!totp_record(&state, "device1").await.expect("totp").active);
    }

    #[tokio::test]
    async fn verify_rejects_token_bound_to_a_different_totp_name() {
        let (state, _tmp) = totp_test_env().await;
        let service = totp_service(state.clone());

        let (_status, body) =
            post_enroll(&service, &serde_json::json!({ "name": "device1" })).await;
        let token1 = body["data"]["token"].as_str().expect("token").to_string();

        let (_status, _body) =
            post_enroll(&service, &serde_json::json!({ "name": "device2" })).await;
        let code2 = current_code(&totp_record(&state, "device2").await.expect("totp"));

        // Token issued for device1 must not authorize device2.
        let (status, _body) = post_verify(
            &service,
            &serde_json::json!({ "user": "alice", "name": "device2", "code": code2, "token": token1 }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(!totp_record(&state, "device2").await.expect("totp").active);
    }

    // ── regression tests ──────────────────────────────────────────────

    /// Factor laundering: completing TOTP verify inside a session belonging
    /// to mallory must not inherit mallory's factors into alice's new JWT.
    #[tokio::test]
    async fn verify_does_not_inherit_factors_from_another_users_session() {
        let (state, _tmp) = totp_test_env().await;
        let service = totp_service_with_verify_session(state.clone(), inject_mallory_otp_session);

        let (_status, body) =
            post_enroll(&service, &serde_json::json!({ "name": "device1" })).await;
        let token = body["data"]["token"].as_str().expect("token").to_string();
        let code = current_code(&totp_record(&state, "device1").await.expect("totp"));

        let (status, body) = post_verify(
            &service,
            &serde_json::json!({ "user": "alice", "name": "device1", "code": code, "token": token }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let jwt = body["data"].as_str().expect("jwt").to_string();
        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        let alice = tenant.user("alice").await.expect("alice");
        let data: JwtData = tenant
            .jwt_verify(TEST_ISSUER, &alice.id.to_string(), &jwt)
            .await
            .expect("decode session jwt");
        assert!(
            data.mfa.contains(AuthType::TOTP.as_str()),
            "this ceremony's own factor must be present"
        );
        assert!(
            !data.mfa.contains(AuthType::OTP.as_str()),
            "mallory's factor must not be inherited by alice"
        );
    }

    // ── regression tests ──────────────────────────────────────────────

    /// A (token, code) pair is one-shot: replaying it must not mint a
    /// second session.
    #[tokio::test]
    async fn verify_rejects_replayed_token_code_pair() {
        let (state, _tmp) = totp_test_env().await;
        let service = totp_service(state.clone());

        let (_status, body) =
            post_enroll(&service, &serde_json::json!({ "name": "device1" })).await;
        let token = body["data"]["token"].as_str().expect("token").to_string();
        let code = current_code(&totp_record(&state, "device1").await.expect("totp"));
        let body =
            serde_json::json!({ "user": "alice", "name": "device1", "code": code, "token": token });

        let (status, _) = post_verify(&service, &body).await;
        assert_eq!(status, StatusCode::OK);

        let (status, _body) = post_verify(&service, &body).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "replayed (token, code) must be refused"
        );
    }

    /// The consumed-step guard is independent of the token: a FRESH token
    /// cannot reuse a code whose step was already accepted.
    #[tokio::test]
    async fn verify_rejects_consumed_code_with_fresh_token() {
        let (state, _tmp) = totp_test_env().await;
        let service = totp_service(state.clone());

        // Two tokens for the same still-inactive enrollment (re-enrolling
        // an inactive record needs no code — it holds no live credential).
        let (_status, body) =
            post_enroll(&service, &serde_json::json!({ "name": "device1" })).await;
        let token1 = body["data"]["token"].as_str().expect("token").to_string();
        let (_status, body) =
            post_enroll(&service, &serde_json::json!({ "name": "device1" })).await;
        let token2 = body["data"]["token"].as_str().expect("token").to_string();
        let code = current_code(&totp_record(&state, "device1").await.expect("totp"));

        let (status, _) = post_verify(
            &service,
            &serde_json::json!({ "user": "alice", "name": "device1", "code": code, "token": token1 }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, _body) = post_verify(
            &service,
            &serde_json::json!({ "user": "alice", "name": "device1", "code": code, "token": token2 }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a consumed step must stay consumed across tokens"
        );
    }

    /// Re-enrolling an ACTIVE record re-exposes the live secret — it must
    /// require (and consume) a valid current code as proof of possession.
    #[tokio::test]
    async fn reenroll_active_totp_requires_possession_code() {
        let (state, _tmp) = totp_test_env().await;
        let service = totp_service(state.clone());

        // Bring device1 to ACTIVE.
        let (_status, body) =
            post_enroll(&service, &serde_json::json!({ "name": "device1" })).await;
        let token = body["data"]["token"].as_str().expect("token").to_string();
        let code = current_code(&totp_record(&state, "device1").await.expect("totp"));
        let (status, _) = post_verify(
            &service,
            &serde_json::json!({ "user": "alice", "name": "device1", "code": code, "token": token }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // The verify consumed the current step — rewind last_used so the
        // current code is fresh again (simulates the next time step
        // without sleeping 30 s).
        {
            let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
            tenant
                .totp_mark_used(
                    "alice",
                    "device1",
                    DOMAIN,
                    jiff::Timestamp::from_second(0).expect("epoch"),
                )
                .await
                .expect("rewind last_used");
        }

        // No code → refused.
        let (status, _body) =
            post_enroll(&service, &serde_json::json!({ "name": "device1" })).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "active re-enroll without a code must be refused"
        );

        // Wrong code → refused.
        let (status, _body) = post_enroll(
            &service,
            &serde_json::json!({ "name": "device1", "code": "000000" }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "active re-enroll with a wrong code must be refused"
        );

        // Valid code → the secret is re-exposed...
        let code = current_code(&totp_record(&state, "device1").await.expect("totp"));
        let (status, body) = post_enroll(
            &service,
            &serde_json::json!({ "name": "device1", "code": code }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "active re-enroll with a valid code must succeed"
        );
        let token = body["data"]["token"].as_str().expect("token").to_string();

        // ...and the code was consumed: it cannot authorize the new token.
        let (status, _body) = post_verify(
            &service,
            &serde_json::json!({ "user": "alice", "name": "device1", "code": code, "token": token }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "the re-enroll possession code must be consumed"
        );
    }
}
