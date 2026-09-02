use salvo::logging::Logger;
use salvo::prelude::*;
use salvo::serve_static::static_embed;
// use salvo::serve_static::StaticDir;
use rust_embed::RustEmbed;
use salvo::rate_limiter::{BasicQuota, FixedGuard, MokaStore, RateLimiter};

#[derive(RustEmbed)]
#[folder = "./frontend/dist"]
struct Assets;

pub fn frontend() -> Router {
    Router::with_path("{*path}")
        .get(static_embed::<Assets>())
        .hoop(Logger::new())
}

fn render_embedded_page(res: &mut Response, name: &str) {
    match Assets::get(name) {
        Some(page) => res.render(Text::Html(String::from_utf8_lossy(&page.data).into_owned())),
        None => {
            res.status_code(StatusCode::NOT_FOUND);
        }
    }
}

#[handler]
fn login_page(res: &mut Response) {
    render_embedded_page(res, "login.html");
}

#[handler]
fn consent_page(res: &mut Response) {
    render_embedded_page(res, "consent.html");
}

#[handler]
fn device_login_page(res: &mut Response) {
    render_embedded_page(res, "device.html");
}

#[handler]
fn admin_page(res: &mut Response) {
    render_embedded_page(res, "admin.html");
}

#[handler]
fn root_redirect(res: &mut Response) {
    res.status_code(StatusCode::FOUND);
    res.headers_mut().insert(
        salvo::http::header::LOCATION,
        salvo::http::HeaderValue::from_static("/login"),
    );
}

pub fn pages() -> Router {
    Router::new()
        .push(Router::new().get(root_redirect))
        .push(Router::with_path("login").get(login_page))
        .push(Router::with_path("signup").get(login_page))
        .push(Router::with_path("consent").get(consent_page))
        .push(Router::with_path("device-login").get(device_login_page))
        .push(Router::with_path("admin").get(admin_page))
}

pub fn api() -> Router {
    let limiter = RateLimiter::new(
        FixedGuard::new(),
        MokaStore::new(),
        crate::utils::JanuxIssuer,
        BasicQuota::per_minute(6),
    );

    Router::with_path("api/v1")
        // metrics_hoop is outermost so it also observes 429s produced by
        // the rate limiters pushed further inside.
        .hoop(crate::ops::metrics_hoop)
        .hoop(crate::cors::cors_middleware)
        .push(Router::with_path("healthy").get(crate::ops::healthy))
        .push(
            Router::with_path("health")
                .push(Router::with_path("live").get(crate::ops::live))
                .push(Router::with_path("ready").get(crate::ops::ready)),
        )
        .push(
            // GET + POST are the two methods forward-auth proxies use
            // (Step 1.4); the other five methods were never a meaningful
            // entry point for authorization decisions.
            Router::with_path("auth/verify")
                .post(crate::verify::verify)
                .get(crate::verify::verify),
        )
        .push(
            Router::with_path("auth/refresh")
                .hoop(crate::audit::audit)
                .post(crate::verify::refresh),
        )
        .push(
            Router::with_path("auth/logout")
                .hoop(crate::audit::audit)
                .post(crate::verify::logout),
        )
        .push(
            Router::with_path("auth")
                .hoop(limiter)
                .hoop(crate::verify::session)
                .push(Router::with_path("email/request").post(crate::email::request))
                .push(
                    Router::with_path("email/verify")
                        .hoop(crate::audit::audit)
                        .post(crate::email::verify),
                )
                .push(
                    // session-gated credential add — the parent
                    // `session` hoop injects a valid session and the
                    // handlers act only on the session's own user.
                    Router::with_path("email/add")
                        .hoop(crate::audit::audit)
                        .post(crate::email::add),
                )
                .push(
                    Router::with_path("email/add/verify")
                        .hoop(crate::audit::audit)
                        .post(crate::email::add_verify),
                )
                .push(Router::with_path("otp/request").post(crate::otp::request))
                .push(
                    Router::with_path("otp/verify")
                        .hoop(crate::audit::audit)
                        .post(crate::otp::verify),
                )
                .push(
                    // session-gated credential add (same pattern as
                    // email/add).
                    Router::with_path("otp/add")
                        .hoop(crate::audit::audit)
                        .post(crate::otp::add),
                )
                .push(
                    Router::with_path("otp/add/verify")
                        .hoop(crate::audit::audit)
                        .post(crate::otp::add_verify),
                )
                .push(Router::with_path("passkey/request").post(crate::passkey::request))
                .push(
                    Router::with_path("passkey/verify")
                        .hoop(crate::audit::audit)
                        .post(crate::passkey::verify),
                )
                .push(
                    Router::with_path("passkey/remove")
                        // Session-gated by the parent `auth` hoop;
                        // the handler acts only on the session's own user.
                        .hoop(crate::audit::audit)
                        .post(crate::passkey::remove),
                )
                .push(
                    Router::with_path("social/{id}/request")
                        .post(crate::social::request)
                        .get(crate::social::request),
                )
                .push(
                    // session-gated identity link — starts the same
                    // OAuth dance flagged for the callback to attach the
                    // IdP binding to the session's own account.
                    Router::with_path("social/{id}/link")
                        .hoop(crate::audit::audit)
                        .post(crate::social::link)
                        .get(crate::social::link),
                )
                .push(
                    Router::with_path("social/{id}/verify")
                        .hoop(crate::audit::audit)
                        .post(crate::social::verify)
                        .get(crate::social::verify),
                )
                .push(
                    Router::with_path("social/redeem")
                        .hoop(crate::audit::audit)
                        .post(crate::social::redeem),
                )
                .push(
                    Router::with_path("totp/enroll")
                        // Session-gated by the parent `auth` hoop:
                        // enrollment must work with any valid single-factor
                        // session, otherwise MFA step-up is circular.
                        .hoop(crate::audit::audit)
                        .post(crate::totp::enroll)
                        .get(crate::totp::enroll),
                )
                .push(
                    Router::with_path("totp/verify")
                        .hoop(crate::audit::audit)
                        .post(crate::totp::verify)
                        .get(crate::totp::verify),
                ),
        )
        .push(
            // Admin routes get their own stricter rate limiter (B-2) — separate from the
            // auth-rate limiter to avoid inflating counts when admin calls verify.
            Router::with_path("admin")
                .hoop(RateLimiter::new(
                    FixedGuard::new(),
                    MokaStore::new(),
                    crate::utils::JanuxIssuer,
                    BasicQuota::per_minute(12),
                ))
                .hoop(crate::verify::protect)
                // tenant
                .push(Router::with_path("tenant/list").get(crate::admin::all_tenants))
                .push(
                    Router::with_path("tenant/create")
                        .hoop(crate::audit::audit)
                        .post(crate::admin::new_tenant),
                )
                .push(
                    Router::with_path("tenant/delete")
                        .hoop(crate::audit::audit)
                        .post(crate::admin::remove_tenant),
                )
                .push(Router::with_path("domain/list").get(crate::admin::all_domains))
                .push(
                    Router::with_path("domain/create")
                        .hoop(crate::audit::audit)
                        .post(crate::admin::add_domain),
                )
                .push(
                    Router::with_path("domain/delete")
                        .hoop(crate::audit::audit)
                        .post(crate::admin::delete_domain),
                )
                // user
                .push(Router::with_path("user/list").get(crate::user::all_users))
                .push(
                    Router::with_path("user/create")
                        .hoop(crate::audit::audit)
                        .post(crate::user::add_user),
                )
                .push(
                    Router::with_path("user/activate")
                        .hoop(crate::audit::audit)
                        .post(crate::user::activate_user),
                )
                .push(
                    Router::with_path("user/activate/self")
                        .hoop(crate::audit::audit)
                        .post(crate::user::activate_self),
                )
                .push(
                    Router::with_path("user/delete")
                        .hoop(crate::audit::audit)
                        .post(crate::user::delete_user),
                )
                .push(
                    Router::with_path("user/delete/self")
                        .hoop(crate::audit::audit)
                        .post(crate::user::delete_self),
                )
                .push(
                    Router::with_path("user/add_role")
                        .hoop(crate::audit::audit)
                        .post(crate::user::add_role),
                )
                .push(
                    Router::with_path("user/remove_role")
                        .hoop(crate::audit::audit)
                        .post(crate::user::remove_role),
                )
                .push(
                    Router::with_path("user/remove_email")
                        .hoop(crate::audit::audit)
                        .post(crate::email::remove),
                )
                .push(
                    Router::with_path("user/remove_mobile")
                        .hoop(crate::audit::audit)
                        .post(crate::otp::remove),
                )
                .push(
                    Router::with_path("user/remove_social")
                        .hoop(crate::audit::audit)
                        .post(crate::social::remove),
                )
                .push(Router::with_path("user/roles").get(crate::user::user_roles))
                // role
                .push(Router::with_path("role/list").get(crate::role::all_roles))
                .push(
                    Router::with_path("role/create")
                        .hoop(crate::audit::audit)
                        .post(crate::role::add_role),
                )
                .push(
                    Router::with_path("role/delete")
                        .hoop(crate::audit::audit)
                        .post(crate::role::delete_role),
                )
                // social login providers
                .push(Router::with_path("provider/list").get(crate::social::all_providers))
                .push(
                    Router::with_path("provider/create")
                        .hoop(crate::audit::audit)
                        .post(crate::social::add_provider),
                )
                .push(
                    Router::with_path("provider/delete")
                        .hoop(crate::audit::audit)
                        .post(crate::social::remove_provider),
                )
                // policy
                .push(Router::with_path("policy/list").get(crate::policy::all_policies))
                .push(
                    Router::with_path("policy/create")
                        .hoop(crate::audit::audit)
                        .post(crate::policy::add_policy),
                )
                .push(
                    Router::with_path("policy/delete")
                        .hoop(crate::audit::audit)
                        .post(crate::policy::delete_policy),
                )
                // key
                .push(Router::with_path("key/list").get(crate::key::all_keys))
                .push(
                    Router::with_path("key/create")
                        .hoop(crate::audit::audit)
                        .post(crate::key::add_key),
                )
                .push(
                    Router::with_path("key/delete")
                        .hoop(crate::audit::audit)
                        .post(crate::key::delete_key),
                )
                // totp
                .push(Router::with_path("totp/list").post(crate::totp::list_totp))
                .push(
                    Router::with_path("totp/remove")
                        .hoop(crate::audit::audit)
                        .post(crate::totp::remove_totp),
                )
                // oauth2 client (G8 follow-up)
                .push(Router::with_path("oauth2client/list").get(crate::idp::list_oauth2clients))
                .push(
                    Router::with_path("oauth2client/create")
                        .hoop(crate::audit::audit)
                        .post(crate::idp::new_oauth2client),
                )
                .push(
                    Router::with_path("oauth2client/delete")
                        .hoop(crate::audit::audit)
                        .post(crate::idp::delete_oauth2client),
                )
                .push(
                    Router::with_path("oauth2client/meta")
                        .hoop(crate::audit::audit)
                        .post(crate::oidc_ext::set_client_meta),
                )
                // tenant OIDC feature switches (Dynamic Client Registration)
                .push(Router::with_path("oidc/config").get(crate::oidc_ext::oidc_config))
                .push(
                    Router::with_path("oidc/config")
                        .hoop(crate::audit::audit)
                        .post(crate::oidc_ext::set_oidc_config),
                )
                // observability (process-global telemetry, admin-gated)
                .push(Router::with_path("metrics").get(crate::ops::metrics)),
        )
}

pub fn public_routes() -> Router {
    // OIDC Discovery & Metadata.
    // NOTE: every route is pushed onto a plain root router. Using
    // Router::with_path(".well-known/openid-configuration") as the base would
    // nest ALL of these under that prefix (e.g. /.well-known/openid-configuration/token).
    //
    // the protocol endpoints are rate-limited per client IP
    // (JanuxIssuer carries the identity rules). `/token` and friends
    // force an Argon2id verification per wrong client_secret, so an
    // unauthenticated attacker could otherwise spend server CPU at line
    // rate; `/device-login/info` is an unauthenticated user_code oracle
    // with no attempt budget. The discovery documents stay exempt: cheap,
    // cacheable GETs that every RP fetches.
    let limiter = RateLimiter::new(
        FixedGuard::new(),
        MokaStore::new(),
        crate::utils::JanuxIssuer,
        BasicQuota::per_minute(12),
    );
    Router::new()
        .hoop(crate::ops::metrics_hoop)
        .push(Router::with_path(".well-known/openid-configuration").get(crate::oidc::well_known))
        .push(Router::with_path(".well-known/jwks.json").get(crate::key::jwks_endpoint))
        .push(
            Router::new()
                .hoop(limiter)
                .push(
                    // ── Authorization Endpoint (RFC 6749 §3.1) ───────────────
                    Router::with_path("authorize")
                        .get(crate::oidc::authorize)
                        .post(crate::oidc::authorize),
                )
                .push(
                    // ── Resume after login (SPA, Bearer JWT) ─────────────────
                    Router::with_path("authorize/resume")
                        .get(crate::oidc::authorize_resume)
                        .post(crate::oidc::authorize_resume),
                )
                .push(
                    // ── Consent round-trip (SPA, Bearer JWT) ─────────────────
                    Router::with_path("consent")
                        .post(crate::oidc::consent_submit)
                        .push(Router::with_path("info").get(crate::oidc::consent_info)),
                )
                .push(
                    // ── Token Endpoint (RFC 6749 §3.2) ───────────────────────
                    Router::with_path("token").post(crate::oidc::token),
                )
                .push(
                    // ── UserInfo Endpoint (OpenID Core §5.3) ─────────────────
                    Router::with_path("userinfo").get(crate::oidc::userinfo),
                )
                .push(
                    // ── Token Revocation Endpoint (RFC 7009 / RFC 8414 §3.2) ─
                    Router::with_path("revoke").post(crate::oidc::revoke),
                )
                .push(
                    // ── Token Introspection Endpoint (RFC 7662 / RFC 8414 §3.2) ─
                    Router::with_path("introspect").post(crate::oidc::introspect),
                )
                .push(
                    // ── Device Authorization Grant (RFC 8628) ────────────────
                    Router::with_path("device_authorization")
                        .post(crate::oidc::device_authorization),
                )
                .push(
                    // ── Dynamic Client Registration (RFC 7591 / RFC 7592 §4) ─
                    Router::with_path("register")
                        .post(crate::oidc_ext::register)
                        .push(Router::with_path("{client_id}").get(crate::oidc_ext::register_read)),
                )
                .push(
                    // ── RP-Initiated Logout 1.0 ──────────────────────────────
                    Router::with_path("end_session")
                        .get(crate::oidc_ext::end_session)
                        .post(crate::oidc_ext::end_session),
                )
                .push(
                    // GET /device-login serves the frontend page (pages()); these
                    // are the JSON APIs it calls.
                    Router::with_path("device-login")
                        .push(Router::with_path("info").get(crate::oidc::device_login_info))
                        .push(Router::with_path("approve").post(crate::oidc::device_login_approve)),
                ),
        )
}

pub fn api_with_doc() -> Router {
    let api_router = api();
    let doc = OpenApi::new("Secure Auth Microservice API", "1.0.0").merge_router(&api_router);

    // public_routes() MUST come before frontend(): the SPA catch-all "{*path}"
    // would otherwise shadow every public endpoint (GET -> 404, POST -> 405).
    // pages() comes before public_routes() so GET /consent serves the page
    // while POST /consent still reaches the consent API.
    // request_id is outermost so EVERY response (including 404/405 from the
    // catch-all) carries a correlation id.
    Router::new()
        .hoop(crate::ops::request_id)
        .push(doc.into_router("/api/v1/doc/openapi.json"))
        .push(Scalar::new("/api/v1/doc/openapi.json").into_router("/api/v1/doc/scalar"))
        .push(api_router)
        .push(pages())
        .push(public_routes())
        .push(crate::scim::router())
        .push(frontend())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ServerState with an empty router table — the public endpoints
    /// resolve no tenant and render their cheap error responses, which is
    /// all the limiter probes need (same shape as `utils::tests`).
    async fn empty_state() -> crate::server::ServerState {
        let storage = crate::db::Storage {
            raw_path: std::path::PathBuf::from("/tmp/janux-router-tests"),
            tenants: dashmap::DashMap::new(),
            router: dashmap::DashMap::new(),
            topology: tokio::sync::Mutex::new(()),
        };
        crate::server::ServerState::create(storage, false)
            .await
            .expect("server state")
    }

    fn public_service(state: crate::server::ServerState) -> Service {
        Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state))
                .push(public_routes()),
        )
    }

    fn get_from(peer: &str, path: &str) -> Request {
        let mut req = Request::new();
        req.set_uri(format!("http://localhost{path}").parse().unwrap());
        *req.remote_addr_mut() = peer.parse::<std::net::SocketAddr>().unwrap().into();
        req
    }

    /// regression: the public OIDC endpoints are rate-limited per
    /// client IP (quota 12/min). The 13th request from one IP is refused
    /// while a different IP still passes.
    #[tokio::test]
    async fn public_oidc_endpoints_are_rate_limited_per_ip() {
        let service = public_service(empty_state().await);
        const ATTACKER: &str = "203.0.113.30:5000";
        let path = "/authorize?response_type=code&client_id=x&redirect_uri=http://x/cb";

        for _ in 0..12 {
            let res = service.handle(get_from(ATTACKER, path)).await;
            assert_ne!(
                res.status_code,
                Some(StatusCode::TOO_MANY_REQUESTS),
                "requests within the quota must pass the limiter"
            );
        }
        let res = service.handle(get_from(ATTACKER, path)).await;
        assert_eq!(
            res.status_code,
            Some(StatusCode::TOO_MANY_REQUESTS),
            "the quota must cut off further requests"
        );

        // A different client IP has its own budget.
        let res = service.handle(get_from("203.0.113.31:5000", path)).await;
        assert_ne!(res.status_code, Some(StatusCode::TOO_MANY_REQUESTS));
    }

    /// keeps the discovery documents unlimited on purpose: cheap,
    /// cacheable GETs that every RP fetches.
    #[tokio::test]
    async fn discovery_documents_stay_unlimited() {
        let service = public_service(empty_state().await);

        for _ in 0..15 {
            let res = service
                .handle(get_from(
                    "203.0.113.32:5000",
                    "/.well-known/openid-configuration",
                ))
                .await;
            assert_ne!(
                res.status_code,
                Some(StatusCode::TOO_MANY_REQUESTS),
                "discovery must not be rate-limited"
            );
        }
        for _ in 0..15 {
            let res = service
                .handle(get_from("203.0.113.32:5000", "/.well-known/jwks.json"))
                .await;
            assert_ne!(res.status_code, Some(StatusCode::TOO_MANY_REQUESTS));
        }
    }
}
