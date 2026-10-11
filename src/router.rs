use salvo::logging::Logger;
use salvo::prelude::*;
use salvo::rate_limiter::{BasicQuota, FixedGuard, MokaStore, RateLimiter};

/// The per-domain frontend override root for this request, when the
/// operator configured one (`pages_dir` in the seed config). Resolution
/// goes through the same trusted host chain as every other endpoint, so
/// an unregistered host never reaches a disk dir — it gets the embedded
/// frontend.
fn override_dir(req: &Request, depot: &Depot) -> Option<std::path::PathBuf> {
    let state = depot.obtain::<crate::server::ServerState>().ok()?;
    let domain = crate::utils::get_domain(req, state)?;
    state
        .pages_dirs
        .get(domain)
        .map(|entry| entry.value().clone())
}

async fn serve_page(req: &Request, depot: &Depot, res: &mut Response, name: &str) {
    let dir = override_dir(req, depot);
    crate::pages::serve(req, res, name, dir.as_deref()).await;
}

pub fn frontend() -> Router {
    Router::with_path("{*path}")
        .get(static_asset)
        .hoop(Logger::new())
}
