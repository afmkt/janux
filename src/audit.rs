use salvo::prelude::*;
use tracing::{error, info};

#[handler]
pub async fn audit(req: &mut Request, depot: &mut Depot, res: &mut Response, ctrl: &mut FlowCtrl) {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let start = std::time::Instant::now();

    // Run the next hop/handler in the chain

    ctrl.call_next(req, depot, res).await;

    let elapsed = start.elapsed();
    // Correlation id from the edge hoop (crate::ops::request_id); empty
    // when the route is exercised without it (e.g. isolated test setups).
    let request_id = crate::ops::request_id_of(depot)
        .cloned()
        .unwrap_or_default();
    if let Some(status_code) = res.status_code {
        // 3xx are successful redirects (e.g. the social callback's 303 to
        // the login page), not failures — logging them at error level
        // floods alerting pipelines with normal traffic.
        if status_code.as_u16() < 400 {
            info!(
                request_id = %request_id,
                "OK {}, {}, {}, {duration_ms}",
                method,
                uri,
                status_code.as_u16(),
                duration_ms = elapsed.as_millis()
            );
        } else {
            error!(
                request_id = %request_id,
                "FAILED {}, {}, {}, {duration_ms}",
                method,
                uri,
                status_code.as_u16(),
                duration_ms = elapsed.as_millis()
            );
        }
    } else {
        error!(
            request_id = %request_id,
            "FAILED {}, {}, {}, {duration_ms}",
            method,
            uri,
            "Unknown status code",
            duration_ms = elapsed.as_millis()
        )
    }
}
