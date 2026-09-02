use crate::utils::{ApiProblem, ApiResponse};
use salvo::prelude::*;
use serde::Deserialize;

#[derive(Deserialize, ToSchema)]
pub struct NewTenant {
    pub name: String,
    /// First domain of the new tenant; the standard admin policy set is
    /// bound to it. Without a domain the
    /// tenant stays default-deny locked until one is added.
    pub domain: Option<String>,
    /// First admin user; created and granted the builtin `admin` role.
    pub admin: Option<String>,
}

#[endpoint(
    summary = "Create a new tenant",
    request_body = NewTenant,
    responses(
        (status_code = 200, description = "Tenant created successfully", body = ApiResponse<()>),
        (status_code = 400, description = "Bad request", body = ApiProblem)
    )
)]
pub async fn new_tenant(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let body = match crate::utils::extract::<NewTenant>(req, None).await {
        Some(b) => b,
        None => {
            let err = ApiProblem::validation_error("Failed to parse request body");
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(err));
            return;
        }
    };

    let state = depot.obtain_mut::<crate::server::ServerState>().unwrap();

    // `.map(|_| ())` drops the RefMut before the bootstrap re-borrows.
    let created = state.storage.new_tenant(&body.name).await.map(|_| ());
    match created {
        Ok(()) => {
            // Bootstrap the builtin catalog, the standard admin policies and
            // the first admin as the trust anchor (§4). On failure roll
            // the tenant back instead of leaving a half-provisioned one.
            if let Err(e) = crate::seed::bootstrap_tenant(
                &state.storage,
                &body.name,
                body.domain.as_deref(),
                body.admin.as_deref(),
            )
            .await
            {
                let _ = state.storage.delete_tenant(&body.name).await;
                let err = ApiProblem::validation_error(&e.to_string());
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(err));
                return;
            }
            res.status_code(StatusCode::OK);
            res.render(Json(ApiResponse::ok(())));
        }
        Err(e) => {
            let err = ApiProblem::validation_error(&e.to_string());
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(err));
        }
    }
}

#[derive(Deserialize, ToSchema)]
pub struct AddDomain {
    pub tenant: String,
    pub domain: String,
}

#[derive(Deserialize, ToSchema)]
pub struct SetCors {
    pub domain: String,
    pub share_tenant: Option<bool>,
    pub cors: Vec<String>,
}

#[endpoint(
    summary = "List all tenants",
    responses(
        (status_code = 200, description = "All tenant names", body = ApiResponse<Vec<String>>),
        (status_code = 400, description = "Bad request", body = ApiProblem),
    )
)]
pub async fn all_tenants(_req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    if let Ok(data) = state.storage.all_tenants().await {
        res.status_code(StatusCode::OK);
        res.render(Json(ApiResponse::ok(data)));
        return;
    }
    let err = ApiProblem::validation_error("Failed to parse request body");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err))
}

#[endpoint(
    summary = "Set CORS",
    request_body = SetCors,
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<()>),
        (status_code = 400, description = "Bad request", body = ApiProblem)
    )
)]
pub async fn set_cors(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain_mut::<crate::server::ServerState>().unwrap();
    if let Some(body) = crate::utils::extract::<SetCors>(req, None).await {
        if body.share_tenant.is_some() && body.share_tenant.unwrap() {
            let ret = state
                .storage
                .domain_cors(&body.domain, vec!["tenant".to_string()])
                .await;
            if ret.is_ok() {
                res.status_code(StatusCode::OK);
                res.render(Json(ApiResponse::ok(())));
                return;
            }
        } else {
            let ret = state.storage.domain_cors(&body.domain, body.cors).await;
            if ret.is_ok() {
                res.status_code(StatusCode::OK);
                res.render(Json(ApiResponse::ok(())));
                return;
            }
        }
    }
    let err = ApiProblem::validation_error("Failed to parse request body");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err))
}

#[endpoint(
    summary = "Return all domains in a tenant",
    responses(
        (status_code = 200, description = "All domain names of the tenant", body = ApiResponse<Vec<String>>),
        (status_code = 400, description = "Bad request", body = ApiProblem)
    )
)]
pub async fn all_domains(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain_mut::<crate::server::ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
        let data: Vec<String> = tenant
            .all_domains()
            .await
            .into_iter()
            .map(|d| d.id.clone())
            .collect();
        res.status_code(StatusCode::OK);
        res.render(Json(ApiResponse::ok(data)));
        return;
    }
    let err = ApiProblem::validation_error("Failed to parse request body");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err))
}

#[endpoint(
    summary = "Add domain to tenant",
    request_body = AddDomain,
    responses(
        (status_code = 200, description = "Domain created successfully", body = ApiResponse<()>),
        (status_code = 400, description = "Bad request", body = ApiProblem)
    )
)]
pub async fn add_domain(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    if let Some(body) = crate::utils::extract::<AddDomain>(req, None).await {
        let state = depot.obtain_mut::<crate::server::ServerState>().unwrap();
        let domain = crate::utils::get_domain(req, state).unwrap_or("");
        let tenant_name = {
            match state.storage.tenant_by_domain(domain) {
                Some(tenant) => Some(tenant.name.clone()),
                None => None,
            }
        };
        if let Some(name) = tenant_name
            && name == body.tenant
            && state
                .storage
                .add_domain(&body.domain, &body.tenant)
                .await
                .is_ok()
        {
            res.status_code(StatusCode::OK);
            res.render(Json(ApiResponse::ok(())));
            return;
        }
    };
    let err = ApiProblem::validation_error("Failed to parse request body");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err))
}

#[derive(Deserialize, ToSchema)]
pub struct DeleteTenant {
    pub name: String,
}

#[endpoint(
    summary = "Delete a tenant (db backed up before removal)",
    request_body = DeleteTenant,
    responses(
        (status_code = 200, description = "Tenant deleted successfully", body = ApiResponse<String>),
        (status_code = 400, description = "Bad request", body = ApiProblem)
    )
)]
pub async fn remove_tenant(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let body = match crate::utils::extract::<DeleteTenant>(req, None).await {
        Some(b) => b,
        None => {
            let err = ApiProblem::validation_error("Failed to parse request body");
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(err));
            return;
        }
    };

    let state = depot.obtain_mut::<crate::server::ServerState>().unwrap();

    match state.storage.delete_tenant(&body.name).await {
        Ok(()) => {
            res.status_code(StatusCode::OK);
            res.render(Json(ApiResponse::ok("Tenant deleted successfully")));
        }
        Err(e) => {
            let err = ApiProblem::validation_error(&e.to_string());
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(err));
        }
    }
}

#[derive(Deserialize, ToSchema)]
pub struct DeleteDomain {
    pub tenant: String,
    pub domain: String,
}

#[endpoint(
    summary = "Remove a domain from tenant",
    request_body = DeleteDomain,
    responses(
        (status_code = 200, description = "Domain removed successfully", body = ApiResponse<()>),
        (status_code = 400, description = "Bad request", body = ApiProblem)
    )
)]
pub async fn delete_domain(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    if let Some(body) = crate::utils::extract::<DeleteDomain>(req, None).await {
        let state = depot.obtain_mut::<crate::server::ServerState>().unwrap();
        let domain = crate::utils::get_domain(req, state).unwrap_or("");
        let tenant_name = {
            match state.storage.tenant_by_domain(domain) {
                Some(tenant) => Some(tenant.name.clone()),
                None => None,
            }
        };
        if let Some(name) = tenant_name
            && body.tenant == name
            && state
                .storage
                .remove_domain(&body.domain, &body.tenant)
                .await
                .is_ok()
        {
            res.status_code(StatusCode::OK);
            res.render(Json(ApiResponse::ok(())));
            return;
        }
    };
    let err = ApiProblem::validation_error("Failed to parse request body");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err))
}

// ── OAuth2 client CRUD endpoints (G8 follow-up) ─────────────────────────────
