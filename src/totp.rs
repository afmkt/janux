use crate::db::AuthType;
use crate::db::JwtVerify;
use crate::db::Tenant;
use crate::domain::Domain;
use crate::server::ServerState;
use crate::user::User;
use crate::utils::{ApiProblem, ApiResponse, Page, extract};
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
        // The secret is bearer-equivalent (it generates valid codes), so
        // the row stores ciphertext; rows written before encryption at
        // rest hold plaintext and load through the legacy fallback.
        let secret = crate::crypto::decrypt_secret_or_legacy(&self.secret);
        TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Raw(secret.as_bytes().to_vec()).to_bytes().unwrap(),
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
    /// One DB-level page of TOTP entries, ordered by the full composite
    /// primary key so pages are stable and disjoint. The `limit + 1` probe
    /// row (see [`crate::utils::Page`]) is fetched and folded into
    /// `next_offset` internally.
    pub async fn totps_page(
        &mut self,
        user: Option<&str>,
        domain: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Page<Totp>> {
        let (fetch, offset) = crate::utils::page_bounds(limit, offset);
        let uid = match user {
            Some(name) => Some(self.user(name).await?.id),
            None => None,
        };
        let query = if let Some(user_id) = uid {
            if let Some(domain_name) = domain {
                Totp::filter(
                    Totp::fields()
                        .user_id()
                        .eq(user_id)
                        .and(Totp::fields().domain_id().eq(domain_name)),
                )
            } else {
                Totp::filter(Totp::fields().user_id().eq(user_id))
            }
        } else if let Some(domain_name) = domain {
            Totp::filter(Totp::fields().domain_id().eq(domain_name))
        } else {
            Totp::all()
        };
        let rows = query
            .order_by((
                Totp::fields().user_id().asc(),
                Totp::fields().domain_id().asc(),
                Totp::fields().name().asc(),
            ))
            .limit(fetch)
            .offset(offset)
            .exec(&mut self.database)
            .await
            .map_err::<anyhow::Error, _>(Into::into)?;
        Ok(Page::from_rows(rows, limit, offset))
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
            if !ts.is_empty() {
                let mut totp = ts[0].clone();
                self.ensure_secret_encrypted(&mut totp).await;
                Ok(totp)
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
            if !ts.is_empty() {
                let mut totp = ts[0].clone();
                self.ensure_secret_encrypted(&mut totp).await;
                Ok(totp)
            } else {
                Err(anyhow::anyhow!("User doesn't have TOTP"))
            }
        }
    }

    /// Rows written before encryption at rest hold the plaintext secret;
    /// the first read through `totp_of` (the verify/enroll choke point)
    /// re-encrypts them in place, so the database converges to ciphertext
    /// without a migration script. Best effort: without a configured key
    /// or on a write failure the row is left untouched — reads keep
    /// working through the legacy fallback in `Totp::totp`.
    /// Re-encrypt every TOTP secret under an explicit cipher (the
    /// `janux rekey` tool, G-150). Legacy plaintext rows are upgraded to
    /// ciphertext under the new key. Returns `(rekeyed, legacy_upgraded)`.
    pub async fn rekey_totp_secrets(
        &mut self,
        new_cipher: &crate::crypto::SecretCipher,
    ) -> anyhow::Result<(usize, usize)> {
        let mut count = 0;
        let mut legacy = 0;
        for t in Totp::all().exec(&mut self.database).await? {
            let (plain, was_legacy) = match crate::crypto::decrypt_secret(&t.secret) {
                Ok(p) => (p, false),
                Err(_) => (t.secret.clone(), true),
            };
            let ct = crate::crypto::encrypt_secret_with(new_cipher, &plain)?;
            toasty::update!(Totp::filter(
                Totp::fields()
                    .user_id()
                    .eq(t.user_id)
                    .and(Totp::fields().name().eq(t.name.clone()))
                    .and(Totp::fields().domain_id().eq(t.domain_id.clone()))
            ) { secret: ct })
            .exec(&mut self.database)
            .await?;
            count += 1;
            if was_legacy {
                legacy += 1;
            }
        }
        Ok((count, legacy))
    }

    async fn ensure_secret_encrypted(&mut self, totp: &mut Totp) {
        if crate::crypto::decrypt_secret(&totp.secret).is_ok() {
            return; // already ciphertext
        }
        let Ok(encrypted) = crate::crypto::encrypt_secret(&totp.secret) else {
            return;
        };
        let updated = toasty::update!(Totp::filter(
            Totp::fields()
                .user_id()
                .eq(totp.user_id)
                .and(Totp::fields().name().eq(totp.name.clone()))
                .and(Totp::fields().domain_id().eq(totp.domain_id.clone()))
        ) { secret: encrypted.clone() })
        .exec(&mut self.database)
        .await;
        if updated.is_ok() {
            totp.secret = encrypted;
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
            secret: crate::crypto::encrypt_secret(secret)?,
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
        (status_code = 401, description = "Failed", body = ApiProblem),
        (status_code = 429, description = "Account locked after repeated verify failures", body = ApiProblem)
    )
)]
pub async fn enroll(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let user = match depot.obtain_mut::<JwtVerify>() {
        // G-132 sudo mode: enrolling a step-up credential requires a
        // freshly AUTHENTICATED session, not a merely rotated one.
        Ok(v) if !crate::verify::session_is_fresh(v) => {
            crate::verify::mark_reauth_required(res);
            res.render(Json(ApiProblem::forbidden()));
            return;
        }
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
        crate::audit::record_target_detail(
            res,
            "credential",
            &format!("totp:{}", req_request.name),
            &format!("user={user},flow=enroll"),
        );
        // the name can not be empty string ""
        if !req_request.name.is_empty()
            && let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref())
        {
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
                    // The possession check on an active record is a
                    // 6-digit code-guessing surface that re-exposes the
                    // live secret on a hit — it sits behind the same
                    // per-account gate as `verify`, and a locked-out
                    // account gets 429 before any code is checked.
                    let gate_key = crate::utils::verify_gate_key(&domain, &user);
                    if !crate::utils::verify_gate_allows(&gate_key).await {
                        res.status_code(StatusCode::TOO_MANY_REQUESTS);
                        res.render(Json(ApiProblem::too_many_requests(
                            "Too many failed attempts; try again later",
                        )));
                        return;
                    }
                    let possessed = req_request
                        .code
                        .as_deref()
                        .is_some_and(|c| existing.code_is_fresh(c));
                    if !possessed {
                        crate::utils::record_verify_failure(&gate_key).await;
                        res.status_code(StatusCode::UNAUTHORIZED);
                        res.render(Json(ApiProblem::unauthorized()));
                        return;
                    }
                    if tenant
                        .totp_mark_used(&user, &req_request.name, &domain, step_start())
                        .await
                        .is_err()
                    {
                        // Server-side failure — not charged to the account.
                        res.status_code(StatusCode::UNAUTHORIZED);
                        res.render(Json(ApiProblem::unauthorized()));
                        return;
                    }
                    crate::utils::clear_verify_failures(&gate_key).await;
                }
            }
            if let Ok(tp) = totp {
                // The new TOTP stays inactive until `verify` proves possession
                // of the secret with a valid code — enrolling must never
                // deactivate the user's existing, working TOTP.
                // Both QR and otpauth URL must build; a failure falls
                // through to the 401 below instead of panicking.
                if let (Ok(qr), Ok(uri)) = (tp.qr(), tp.uri()) {
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
                            uri,
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
    /// Requested session lifetime in seconds (G-90), clamped to the
    /// 15-minute ceiling — a caller may shorten its session, never
    /// lengthen it. Omitted → 15 minutes.
    #[serde(default)]
    lifetime: Option<i64>,
}

async fn verify_totp(
    state: &mut ServerState,
    session: Option<&(String, HashSet<String>)>,
    domain: &str,
    req: &mut Request,
    res: &mut Response,
) {
    let issuer = crate::utils::get_issuer(req, state).unwrap_or_default();
    // Set once the claimed identity is known; the failure fall-through at
    // the bottom records against it — but only when the enrollment token
    // validated for that identity (`ceremony_valid`), so junk bodies
    // cannot create lockout entries for arbitrary names and server-side
    // failures are not charged to the account.
    let mut gate_key: Option<String> = None;
    let mut ceremony_valid = false;
    if let Some(verify_reqest) = extract::<VerifyTotpRequest>(req, None).await {
        // G-89: attribute the step-up attempt to the claimed identity.
        crate::audit::record_target_detail(res, "auth", &verify_reqest.user, "factor=totp");
        // The account gate is checked BEFORE the one-shot enrollment token
        // is consumed: a locked-out attacker must not be able to burn the
        // token just issued to the legitimate user.
        let key = crate::utils::verify_gate_key(domain, &verify_reqest.user);
        if !crate::utils::verify_gate_allows(&key).await {
            res.status_code(StatusCode::TOO_MANY_REQUESTS);
            res.render(Json(ApiProblem::too_many_requests(
                "Too many failed attempts; try again later",
            )));
            return;
        }
        gate_key = Some(key);
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
            ceremony_valid = check;
            if check
                && let Ok(totp) = tenant
                    .totp_of(&verify_reqest.user, domain, verify_reqest.name.as_deref())
                    .await
                && totp.code_is_fresh(&verify_reqest.code)
                && (totp.active
                    || tenant
                        .active_totp(&verify_reqest.user, &totp.name, &totp.domain_id)
                        .await
                        .is_ok())
            {
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
                        crate::utils::clamped_token_lifetime_minutes(verify_reqest.lifetime, 15),
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
                    res.render(Json(ApiResponse::ok(jwt)));
                    return;
                }
            }
        }
    }

    // Every failed verify of a VALID ceremony counts against the account,
    // across ceremonies: the one-shot enrollment token bounds guesses per
    // ceremony, this bounds the enroll→verify loop itself. Attempts
    // without a token valid for the claimed identity are not recorded —
    // they guess nothing, and recording them would let junk traffic flood
    // the lockout cache.
    if ceremony_valid && let Some(key) = &gate_key {
        crate::utils::record_verify_failure(key).await;
    }
    res.status_code(StatusCode::UNAUTHORIZED);
    res.render(Json(ApiProblem::unauthorized()))
}

#[endpoint(
    summary = "Request Magic Link",
    request_body = VerifyTotpRequest,
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<String>),
        (status_code = 401, description = "Failed", body = ApiProblem),
        (status_code = 429, description = "Account locked after repeated verify failures", body = ApiProblem)
    )
)]

pub async fn verify(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let _err_msg = String::from("");
    let jwt_verify_wrap = { depot.obtain::<JwtVerify>().ok().cloned() };
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
    parameters(
        ("limit" = Option<usize>, Query, description = "Max items per page (server-enforced default and cap)"),
        ("offset" = Option<usize>, Query, description = "Number of items to skip"),
    ),
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<Page<TotpEntry>>),
        (status_code = 401, description = "Failed", body = ApiProblem)
    )
)]
pub async fn list_totp(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain_mut::<ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state)
        .unwrap_or("")
        .to_string();
    let (limit, offset) = crate::utils::page_params(req);
    if let Some(req_request) = crate::utils::extract::<AllTotpRequest>(req, None).await
        && let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref())
        && let Ok(page) = tenant
            .totps_page(req_request.name.as_deref(), None, limit, offset)
            .await
    {
        let page = page.map(|a| TotpEntry {
            name: a.name,
            active: a.active,
        });
        res.status_code(StatusCode::OK);
        res.render(Json(ApiResponse::ok(page)));
        return;
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
        (status_code = 400, description = "Failed", body = ApiProblem),
        (status_code = 401, description = "No verified session", body = ApiProblem),
        (status_code = 403, description = "Level gate refused the target user", body = ApiProblem)
    )
)]
pub async fn remove_totp(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    // H3: MFA removal is a user-lifecycle mutation — the caller must
    // outrank the target on the role ladder (the same gate `user_delete`
    // enforces), or a lower admin could strip root's second factor.
    // Fail closed without a verified session.
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
    if let Some(req_request) = crate::utils::extract::<RemoveTotpRequest>(req, None).await
        && !req_request.name.is_empty()
        && !req_request.totp.is_empty()
        && let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref())
    {
        crate::audit::record_target_detail(
            res,
            "credential",
            &format!("totp:{}", req_request.totp),
            &format!("user={},flow=remove", req_request.name),
        );
        if let Ok(target) = tenant.user(&req_request.name).await
            && let Err(e) = tenant.require_above_user(&caller, target.id).await
        {
            crate::utils::render_admin_error(res, e);
            return;
        }
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
        // TOTP secrets are encrypted at rest; the key is process-wide and
        // first-call-wins, matching the social test envs.
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
            auth_time: Some(jiff::Timestamp::now().as_second().max(0) as usize),
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
            jwt_data: JwtData {
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

    /// G-132: enrolling a step-up credential requires a freshly
    /// AUTHENTICATED session — a stale one gets 403 and no secret is
    /// generated or re-exposed.
    #[tokio::test]
    async fn enroll_refuses_stale_session() {
        let (state, _tmp) = totp_test_env().await;
        let service = Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state.clone()))
                .push(
                    Router::with_path("enroll")
                        .hoop(inject_stale_alice_session)
                        .post(enroll),
                ),
        );
        let (status, _body) =
            post_enroll(&service, &serde_json::json!({ "name": "device1" })).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
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
            auth_time: Some(jiff::Timestamp::now().as_second().max(0) as usize),
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

    /// regression: verify failures count against the account ACROSS
    /// ceremonies — after the budget (5) is exhausted even a valid
    /// enrollment token + correct code gets 429, and the gated attempt
    /// must not consume the one-shot enrollment token. Only failures of
    /// VALID ceremonies count (junk bodies must not flood the lockout
    /// cache), so each attempt carries a fresh enrollment token.
    #[tokio::test]
    async fn verify_locks_after_repeated_wrong_codes() {
        let (state, _tmp) = totp_test_env().await;
        let service = totp_service(state.clone());

        for _ in 0..5 {
            let (_status, body) =
                post_enroll(&service, &serde_json::json!({ "name": "device1" })).await;
            let token = body["data"]["token"].as_str().expect("token").to_string();
            let (status, _body) = post_verify(
                &service,
                &serde_json::json!({ "user": "alice", "name": "device1", "code": "000000", "token": token }),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }

        // Tokenless junk verifies guess nothing and must not extend the
        // lockout accounting either way.
        let (status, _body) = post_verify(
            &service,
            &serde_json::json!({ "user": "alice", "code": "000000" }),
        )
        .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "gate runs first");

        let (_status, body) =
            post_enroll(&service, &serde_json::json!({ "name": "device1" })).await;
        let token = body["data"]["token"].as_str().expect("token").to_string();
        let code = current_code(&totp_record(&state, "device1").await.expect("totp"));

        let (status, _body) = post_verify(
            &service,
            &serde_json::json!({ "user": "alice", "name": "device1", "code": code, "token": token }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "a locked-out account must be refused before the token is consumed"
        );

        // The gated attempt must not have consumed the enrollment token:
        // after the lock clears, the same ceremony completes.
        crate::utils::clear_verify_failures(&crate::utils::verify_gate_key(DOMAIN, "alice")).await;
        let (status, _body) = post_verify(
            &service,
            &serde_json::json!({ "user": "alice", "name": "device1", "code": code, "token": token }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    /// regression: the re-enrollment possession check on an ACTIVE record
    /// re-exposes the live TOTP secret on a hit, so it is a code-guessing
    /// surface that must sit behind the same per-account gate as verify.
    #[tokio::test]
    async fn enroll_reenrollment_code_checks_are_gated() {
        let (state, _tmp) = totp_test_env().await;
        let service = totp_service(state.clone());

        // Activate a TOTP through the normal enroll → verify ceremony.
        let (_status, body) =
            post_enroll(&service, &serde_json::json!({ "name": "device1" })).await;
        let token = body["data"]["token"].as_str().expect("token").to_string();
        let code = current_code(&totp_record(&state, "device1").await.expect("totp"));
        let (status, _body) = post_verify(
            &service,
            &serde_json::json!({ "user": "alice", "name": "device1", "code": code, "token": token }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Failed possession checks on the now-ACTIVE record count against
        // the same account budget as verify failures.
        for _ in 0..5 {
            let (status, _body) = post_enroll(
                &service,
                &serde_json::json!({ "name": "device1", "code": "000000" }),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }

        // While locked, even the CORRECT code must not re-expose the secret.
        let code = current_code(&totp_record(&state, "device1").await.expect("totp"));
        let (status, _body) = post_enroll(
            &service,
            &serde_json::json!({ "name": "device1", "code": code }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "a locked-out account must not re-expose the live TOTP secret"
        );

        crate::utils::clear_verify_failures(&crate::utils::verify_gate_key(DOMAIN, "alice")).await;
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

    /// regression: TOTP secrets are bearer-equivalent (they generate
    /// valid second-factor codes), so the DB row must hold ciphertext —
    /// the plaintext only ever leaves through the enrollment URI/QR, and
    /// codes must still verify from the encrypted row.
    #[tokio::test]
    async fn totp_secret_is_encrypted_at_rest() {
        let (state, _tmp) = totp_test_env().await;
        let service = totp_service(state.clone());

        let (status, body) = post_enroll(&service, &serde_json::json!({ "name": "device1" })).await;
        assert_eq!(status, StatusCode::OK);
        let uri = body["data"]["uri"].as_str().expect("uri").to_string();

        let record = totp_record(&state, "device1").await.expect("totp");
        let plaintext = crate::crypto::decrypt_secret(&record.secret)
            .expect("the stored secret must be ciphertext");
        assert_ne!(
            record.secret, plaintext,
            "the row must not store the plaintext secret"
        );
        assert!(
            !uri.contains(&record.secret),
            "the enrollment URI must not carry the ciphertext"
        );

        // The decrypted secret is the RIGHT plaintext: an independent
        // TOTP built from it generates the same current code as the row.
        let independent = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Raw(plaintext.as_bytes().to_vec())
                .to_bytes()
                .expect("raw"),
            Some(DOMAIN.to_string()),
            "alice".to_string(),
        )
        .expect("totp");
        assert_eq!(
            record.code().expect("code"),
            independent.generate_current().expect("code"),
            "decrypt(encrypt(secret)) must round-trip to the original secret"
        );
    }

    /// regression: rows written before encryption at rest hold the
    /// plaintext secret; they must keep verifying (legacy fallback) and
    /// be re-encrypted in place on the first read through `totp_of`, so
    /// the database converges to ciphertext without a migration script.
    #[tokio::test]
    async fn legacy_plaintext_totp_secret_still_verifies_and_upgrades() {
        let (state, _tmp) = totp_test_env().await;
        let plaintext = "JBSWY3DPEHPK3PXP";
        {
            let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
            let alice = tenant.user("alice").await.expect("alice");
            toasty::create!(Totp {
                name: "legacy".to_string(),
                user_id: alice.id,
                domain_id: DOMAIN.to_string(),
                active: true,
                secret: plaintext.to_string(),
                last_used: jiff::Timestamp::from_second(0).expect("epoch")
            })
            .exec(&mut tenant.database)
            .await
            .expect("legacy row");
        }

        // The code an authenticator would show, computed independently
        // from the plaintext secret.
        let expected = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Raw(plaintext.as_bytes().to_vec())
                .to_bytes()
                .expect("raw"),
            Some(DOMAIN.to_string()),
            "alice".to_string(),
        )
        .expect("totp")
        .generate_current()
        .expect("code");

        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        let record = tenant
            .totp_of("alice", DOMAIN, Some("legacy"))
            .await
            .expect("legacy row reads");
        assert!(
            record.code_is_fresh(&expected),
            "a legacy plaintext secret must still verify"
        );
        assert_eq!(
            crate::crypto::decrypt_secret(&record.secret).expect("ciphertext"),
            plaintext,
            "totp_of must re-encrypt the legacy row in place"
        );

        // The upgrade persisted to the database.
        let reread = tenant
            .totp_of("alice", DOMAIN, Some("legacy"))
            .await
            .expect("reread");
        assert_eq!(
            crate::crypto::decrypt_secret(&reread.secret).expect("ciphertext"),
            plaintext,
            "the upgrade must be visible to the next reader"
        );
    }
}
