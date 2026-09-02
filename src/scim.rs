//! SCIM 2.0 provisioning surface (RFC 7643 schema, RFC 7644 protocol).
//!
//! The preferred API for user management (README §7): IdPs drive the user
//! lifecycle through `/scim/v2/Users` under a machine principal minted by
//! the `client_credentials` grant carrying the builtin `scim` role. The
//! surrogate `User.id` is the SCIM resource id; `User.name` is
//! `userName`; `User.external_id` persists the IdP join key.

use crate::db::Tenant;
use crate::role::Caller;
use crate::user::User;
use salvo::http::header;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

const SCIM_CONTENT_TYPE: &str = "application/scim+json";

const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const LIST_RESPONSE_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const PATCH_OP_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const SPC_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";

/// SCIM bulk syncs and IdP retry storms must not share the tight admin
/// quota.
const RATE_LIMIT_PER_MINUTE: usize = 60;

/// Default page cap for list responses (`filter.maxResults` in
/// ServiceProviderConfig).
const MAX_RESULTS: usize = 200;

// ─── Wire types ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimUserRequest {
    // Accepted for SCIM wire compatibility; not needed server-side.
    #[serde(default)]
    #[allow(dead_code)]
    pub schemas: Vec<String>,
    pub user_name: Option<String>,
    #[serde(default)]
    pub active: Option<bool>,
    pub external_id: Option<String>,
    #[serde(default)]
    pub emails: Vec<ScimEmailValue>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimEmailValue {
    pub value: String,
    #[serde(default)]
    pub primary: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScimUser {
    schemas: Vec<String>,
    id: String,
    user_name: String,
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    emails: Vec<ScimEmailValue>,
    meta: ScimMeta,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScimMeta {
    resource_type: String,
    created: String,
    last_modified: String,
    location: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScimListResponse {
    schemas: Vec<String>,
    total_results: usize,
    start_index: usize,
    items_per_page: usize,
    #[serde(rename = "Resources")]
    resources: Vec<ScimUser>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScimError {
    schemas: Vec<String>,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    scim_type: Option<String>,
    detail: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PatchOp {
    #[serde(default)]
    schemas: Vec<String>,
    operations: Vec<PatchOperation>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PatchOperation {
    op: String,
    path: Option<String>,
    value: Option<serde_json::Value>,
}

// ─── Rendering ───────────────────────────────────────────────────────────────

fn render_scim<T: Serialize + Send>(res: &mut Response, status: StatusCode, body: T) {
    res.status_code(status);
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(SCIM_CONTENT_TYPE),
    );
    res.render(Json(body));
}

fn scim_error(res: &mut Response, status: StatusCode, scim_type: Option<&str>, detail: &str) {
    render_scim(
        res,
        status,
        ScimError {
            schemas: vec![ERROR_SCHEMA.to_string()],
            status: status.as_u16().to_string(),
            scim_type: scim_type.map(|s| s.to_string()),
            detail: detail.to_string(),
        },
    );
}

/// Map a Tenant-layer failure onto the SCIM error shape. level-gate
/// refusals become 403; name/externalId conflicts become 409 `uniqueness`.
fn render_tenant_error(res: &mut Response, err: &anyhow::Error) {
    if let Some(admin_err) = err.downcast_ref::<crate::role::AdminError>() {
        match admin_err {
            crate::role::AdminError::Forbidden => {
                scim_error(res, StatusCode::FORBIDDEN, None, &admin_err.to_string());
                return;
            }
            crate::role::AdminError::Conflict(msg) => {
                scim_error(res, StatusCode::CONFLICT, Some("uniqueness"), msg);
                return;
            }
        }
    }
    let msg = err.to_string();
    if msg.contains("already exists") || msg.contains("UNIQUE") {
        scim_error(res, StatusCode::CONFLICT, Some("uniqueness"), &msg);
    } else if msg.contains("not found") {
        scim_error(res, StatusCode::NOT_FOUND, None, &msg);
    } else {
        scim_error(res, StatusCode::BAD_REQUEST, None, &msg);
    }
}

fn rfc3339(ts: jiff::Timestamp) -> String {
    ts.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}

// ─── Attribute mapping ───────────────────────────────────────────────────────

async fn to_scim_user(tenant: &mut Tenant, user: &User) -> ScimUser {
    let mut emails: Vec<ScimEmailValue> = tenant
        .user_email(user.id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|e| ScimEmailValue {
            value: e.id,
            primary: None,
        })
        .collect();
    if let Some(first) = emails.first_mut() {
        first.primary = Some(true);
    }
    ScimUser {
        schemas: vec![USER_SCHEMA.to_string()],
        id: user.id.to_string(),
        user_name: user.name.clone(),
        active: user.active,
        external_id: user.external_id.clone(),
        emails,
        meta: ScimMeta {
            resource_type: "User".to_string(),
            created: rfc3339(user.created_at),
            last_modified: rfc3339(user.updated_at),
            location: format!("/scim/v2/Users/{}", user.id),
        },
    }
}

/// Resolve the `{id}` path segment: surrogate key first, login name as a
/// fallback (IdPs send the id they received; humans may send a userName).
async fn resolve_path_user(tenant: &mut Tenant, id: &str) -> Option<User> {
    if let Ok(uuid) = uuid::Uuid::try_parse(id)
        && let Ok(user) = tenant.user_by_id(uuid).await
    {
        return Some(user);
    }

    tenant.user(id).await.ok()
}

fn caller_or_401(depot: &Depot, res: &mut Response) -> Option<Caller> {
    match crate::utils::caller_from_depot(depot) {
        Some(c) => Some(c),
        None => {
            scim_error(res, StatusCode::UNAUTHORIZED, None, "no verified session");
            None
        }
    }
}

/// Body extraction for the SCIM surface: salvo's `parse_json` only accepts
/// the `application/json` mime subtype, but RFC 7644 clients send
/// `application/scim+json` — parse the payload as JSON regardless of which
/// of the two content types arrived.
async fn extract_scim<T: serde::de::DeserializeOwned>(req: &mut Request) -> Option<T> {
    let payload = req.payload().await.ok()?;
    serde_json::from_slice(payload.as_ref()).ok()
}

// ─── RBAC hoop ───────────────────────────────────────────────────────────────

/// Policies match resource paths exactly (no wildcards), so the
/// dynamic `/scim/v2/Users/{id}` segment is canonicalized to the literal
/// `/scim/v2/Users/{id}` before the policy engine runs — one policy row
/// covers every resource instance.
fn canonical_resource(path: &str) -> String {
    let path = path.split('?').next().unwrap_or(path);
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if segs.len() == 4 && segs[0] == "scim" && segs[1] == "v2" && segs[2] == "Users" {
        "/scim/v2/Users/{id}".to_string()
    } else {
        path.to_string()
    }
}

#[handler]
async fn scim_protect(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let at = (
        crate::utils::get_method(req),
        canonical_resource(req.uri().path()),
    );
    crate::verify::protect_at(req, depot, res, ctrl, Some(at)).await;
}

// ─── Discovery endpoints (public, static) ────────────────────────────────────

#[handler]
pub async fn service_provider_config(res: &mut Response) {
    render_scim(
        res,
        StatusCode::OK,
        serde_json::json!({
            "schemas": [SPC_SCHEMA],
            "patch": { "supported": true },
            "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
            "filter": { "supported": true, "maxResults": MAX_RESULTS },
            "changePassword": { "supported": false },
            "sort": { "supported": false },
            "etag": { "supported": false },
            "authenticationSchemes": [{
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "Authentication via an OAuth2 bearer token (client_credentials grant).",
                "specUri": "http://tools.ietf.org/html/rfc6750"
            }],
            "meta": {
                "resourceType": "ServiceProviderConfig",
                "location": "/scim/v2/ServiceProviderConfig"
            }
        }),
    );
}

#[handler]
pub async fn schemas(res: &mut Response) {
    render_scim(
        res,
        StatusCode::OK,
        serde_json::json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 1,
            "Resources": [{
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
                "id": USER_SCHEMA,
                "name": "User",
                "attributes": [
                    { "name": "userName", "type": "string", "mutability": "readWrite", "required": true, "uniqueness": "server" },
                    { "name": "active", "type": "boolean", "mutability": "readWrite", "required": false },
                    { "name": "externalId", "type": "string", "mutability": "readWrite", "required": false, "uniqueness": "server" },
                    { "name": "emails", "type": "complex", "multiValued": true, "mutability": "readWrite", "required": false }
                ],
                "meta": { "resourceType": "Schema", "location": format!("/scim/v2/Schemas/{USER_SCHEMA}") }
            }]
        }),
    );
}

#[handler]
pub async fn resource_types(res: &mut Response) {
    render_scim(
        res,
        StatusCode::OK,
        serde_json::json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 1,
            "Resources": [{
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "User",
                "name": "User",
                "endpoint": "/Users",
                "schema": USER_SCHEMA,
                "meta": { "resourceType": "ResourceType", "location": "/scim/v2/ResourceTypes/User" }
            }]
        }),
    );
}

// ─── /Users ──────────────────────────────────────────────────────────────────

/// Parse the only supported filter (RFC 7644 §3.4.2.2): `userName eq "x"`.
fn parse_user_name_filter(filter: &str) -> Result<Option<String>, ()> {
    let filter = filter.trim();
    if filter.is_empty() {
        return Ok(None);
    }
    let lower = filter.to_lowercase();
    let Some(rest) = lower.strip_prefix("username") else {
        return Err(());
    };
    let rest = rest.trim_start();
    let Some(rest) = rest.strip_prefix("eq") else {
        return Err(());
    };
    let value = rest.trim();
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        Ok(Some(value[1..value.len() - 1].to_string()))
    } else {
        Err(())
    }
}

#[handler]
pub async fn list_users(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    let Some(mut tenant) = state.storage.tenant_by_domain(domain) else {
        scim_error(res, StatusCode::NOT_FOUND, None, "unknown tenant");
        return;
    };

    let filter = req.query::<String>("filter").unwrap_or_default();
    let names = match parse_user_name_filter(&filter) {
        Ok(n) => n,
        Err(_) => {
            scim_error(
                res,
                StatusCode::BAD_REQUEST,
                Some("invalidFilter"),
                "only `userName eq \"value\"` is supported",
            );
            return;
        }
    };

    let users: Vec<User> = match &names {
        Some(name) => match tenant.user(name).await {
            Ok(u) => vec![u],
            Err(_) => vec![],
        },
        None => tenant.all_users().await.unwrap_or_default(),
    };

    let total = users.len();
    let start_index = req.query::<usize>("startIndex").unwrap_or(1).max(1);
    let count = req
        .query::<usize>("count")
        .unwrap_or(MAX_RESULTS)
        .min(MAX_RESULTS);
    let page: Vec<ScimUser> = {
        let mut page = Vec::new();
        for user in users.iter().skip(start_index - 1).take(count) {
            page.push(to_scim_user(&mut tenant, user).await);
        }
        page
    };
    render_scim(
        res,
        StatusCode::OK,
        ScimListResponse {
            schemas: vec![LIST_RESPONSE_SCHEMA.to_string()],
            total_results: total,
            start_index,
            items_per_page: page.len(),
            resources: page,
        },
    );
}

#[handler]
pub async fn get_user(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let id = req.param::<String>("id").unwrap_or_default();
    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    let Some(mut tenant) = state.storage.tenant_by_domain(domain) else {
        scim_error(res, StatusCode::NOT_FOUND, None, "unknown tenant");
        return;
    };
    match resolve_path_user(&mut tenant, &id).await {
        Some(user) => {
            let body = to_scim_user(&mut tenant, &user).await;
            render_scim(res, StatusCode::OK, body);
        }
        None => scim_error(res, StatusCode::NOT_FOUND, None, "Resource not found"),
    }
}

/// Apply the shared create/update attribute set. Returns the (possibly
/// renamed) user; email attaches are best-effort — an email already claimed
/// by another account is skipped, matching the social-provisioning rule.
async fn apply_attrs(
    tenant: &mut Tenant,
    caller: &Caller,
    mut user: User,
    body: &ScimUserRequest,
) -> anyhow::Result<User> {
    if let Some(new_name) = &body.user_name
        && !new_name.is_empty()
        && *new_name != user.name
    {
        user = tenant.user_rename(caller, &user.name, new_name).await?;
    }

    if let Some(external_id) = &body.external_id {
        let value = if external_id.is_empty() {
            None
        } else {
            Some(external_id.clone())
        };
        if user.external_id != value {
            User::update_by_id(user.id)
                .external_id(value)
                .exec(&mut tenant.database)
                .await
                .map_err(anyhow::Error::from)?;
            user = tenant.user_by_id(user.id).await?;
        }
    }
    match body.active {
        Some(true) if !user.active => {
            tenant.user_activate(caller, &user.name).await?;
            user.active = true;
        }
        Some(false) if user.active => {
            tenant.user_deactivate(caller, &user.name).await?;
            user.active = false;
        }
        _ => {}
    }
    for email in &body.emails {
        if !email.value.is_empty() {
            tenant.email_create(&user.name, &email.value).await.ok();
        }
    }
    Ok(user)
}

#[handler]
pub async fn create_user(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Some(caller) = caller_or_401(depot, res) else {
        return;
    };
    let Some(body) = extract_scim::<ScimUserRequest>(req).await else {
        scim_error(
            res,
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "malformed body",
        );
        return;
    };
    let Some(name) = body
        .user_name
        .as_deref()
        .filter(|n| !n.is_empty())
        .map(|n| n.to_string())
    else {
        scim_error(
            res,
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "userName is required",
        );
        return;
    };
    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    let Some(mut tenant) = state.storage.tenant_by_domain(domain) else {
        scim_error(res, StatusCode::NOT_FOUND, None, "unknown tenant");
        return;
    };

    let user = match tenant.user_create(&name).await {
        Ok(u) => u,
        Err(e) => {
            render_tenant_error(res, &e);
            return;
        }
    };
    let user = match apply_attrs(&mut tenant, &caller, user, &body).await {
        Ok(u) => u,
        Err(e) => {
            // Roll back the just-created account so a conflicting attribute
            // (e.g. a taken externalId) does not burn the username.
            tenant.user_delete(&Caller::Bootstrap, &name).await.ok();
            render_tenant_error(res, &e);
            return;
        }
    };
    let body = to_scim_user(&mut tenant, &user).await;
    res.headers_mut().insert(
        header::LOCATION,
        header::HeaderValue::from_str(&format!("/scim/v2/Users/{}", user.id))
            .expect("valid location header"),
    );
    render_scim(res, StatusCode::CREATED, body);
}

#[handler]
pub async fn put_user(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Some(caller) = caller_or_401(depot, res) else {
        return;
    };
    let id = req.param::<String>("id").unwrap_or_default();
    let Some(body) = extract_scim::<ScimUserRequest>(req).await else {
        scim_error(
            res,
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "malformed body",
        );
        return;
    };
    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    let Some(mut tenant) = state.storage.tenant_by_domain(domain) else {
        scim_error(res, StatusCode::NOT_FOUND, None, "unknown tenant");
        return;
    };
    let Some(user) = resolve_path_user(&mut tenant, &id).await else {
        scim_error(res, StatusCode::NOT_FOUND, None, "Resource not found");
        return;
    };

    // PUT is full replace: drop emails absent from the payload first.
    let keep: std::collections::HashSet<&str> =
        body.emails.iter().map(|e| e.value.as_str()).collect();
    let current = tenant.user_email(user.id).await.unwrap_or_default();
    for email in current {
        if !keep.contains(email.id.as_str()) {
            tenant.email_delete(&user.name, &email.id).await.ok();
        }
    }

    match apply_attrs(&mut tenant, &caller, user, &body).await {
        Ok(user) => {
            let body = to_scim_user(&mut tenant, &user).await;
            render_scim(res, StatusCode::OK, body);
        }
        Err(e) => render_tenant_error(res, &e),
    }
}

#[handler]
pub async fn patch_user(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Some(caller) = caller_or_401(depot, res) else {
        return;
    };
    let id = req.param::<String>("id").unwrap_or_default();
    let Some(patch) = extract_scim::<PatchOp>(req).await else {
        scim_error(
            res,
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "malformed body",
        );
        return;
    };
    if !patch.schemas.iter().any(|s| s == PATCH_OP_SCHEMA) {
        scim_error(
            res,
            StatusCode::BAD_REQUEST,
            Some("invalidSyntax"),
            "expected a PatchOp payload",
        );
        return;
    }
    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    let Some(mut tenant) = state.storage.tenant_by_domain(domain) else {
        scim_error(res, StatusCode::NOT_FOUND, None, "unknown tenant");
        return;
    };
    let Some(mut user) = resolve_path_user(&mut tenant, &id).await else {
        scim_error(res, StatusCode::NOT_FOUND, None, "Resource not found");
        return;
    };

    for op in &patch.operations {
        if op.op.to_lowercase() != "replace" && op.op.to_lowercase() != "add" {
            scim_error(
                res,
                StatusCode::BAD_REQUEST,
                Some("invalidValue"),
                &format!("unsupported op '{}'", op.op),
            );
            return;
        }
        // Attribute map form: no path, value carries the attributes.
        let attrs: Vec<(String, &serde_json::Value)> = match (&op.path, &op.value) {
            (None, Some(serde_json::Value::Object(map))) => {
                map.iter().map(|(k, v)| (k.to_lowercase(), v)).collect()
            }
            (Some(path), Some(value)) => vec![(path.to_lowercase(), value)],
            _ => {
                scim_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    Some("noTarget"),
                    "operation needs a path or a value object",
                );
                return;
            }
        };

        let mut single = ScimUserRequest {
            schemas: vec![],
            user_name: None,
            active: None,
            external_id: None,
            emails: vec![],
        };
        for (attr, value) in attrs {
            match attr.as_str() {
                "active" => {
                    let Some(b) = value.as_bool() else {
                        scim_error(
                            res,
                            StatusCode::BAD_REQUEST,
                            Some("invalidValue"),
                            "active must be a boolean",
                        );
                        return;
                    };
                    single.active = Some(b);
                }
                "username" => {
                    let Some(s) = value.as_str() else {
                        scim_error(
                            res,
                            StatusCode::BAD_REQUEST,
                            Some("invalidValue"),
                            "userName must be a string",
                        );
                        return;
                    };
                    single.user_name = Some(s.to_string());
                }
                "externalid" => {
                    let Some(s) = value.as_str() else {
                        scim_error(
                            res,
                            StatusCode::BAD_REQUEST,
                            Some("invalidValue"),
                            "externalId must be a string",
                        );
                        return;
                    };
                    single.external_id = Some(s.to_string());
                }
                "emails" => {
                    let parsed: Vec<ScimEmailValue> = match serde_json::from_value(value.clone()) {
                        Ok(v) => v,
                        Err(_) => {
                            scim_error(
                                res,
                                StatusCode::BAD_REQUEST,
                                Some("invalidValue"),
                                "emails must be an array of {value}",
                            );
                            return;
                        }
                    };
                    // Replace semantics for the email set.
                    let keep: std::collections::HashSet<&str> =
                        parsed.iter().map(|e| e.value.as_str()).collect();
                    let current = tenant.user_email(user.id).await.unwrap_or_default();
                    for email in current {
                        if !keep.contains(email.id.as_str()) {
                            tenant.email_delete(&user.name, &email.id).await.ok();
                        }
                    }
                    single.emails = parsed;
                }
                other => {
                    scim_error(
                        res,
                        StatusCode::BAD_REQUEST,
                        Some("invalidPath"),
                        &format!("unsupported attribute '{other}'"),
                    );
                    return;
                }
            }
        }
        user = match apply_attrs(&mut tenant, &caller, user, &single).await {
            Ok(u) => u,
            Err(e) => {
                render_tenant_error(res, &e);
                return;
            }
        };
    }

    let body = to_scim_user(&mut tenant, &user).await;
    render_scim(res, StatusCode::OK, body);
}

#[handler]
pub async fn delete_user(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Some(caller) = caller_or_401(depot, res) else {
        return;
    };
    let id = req.param::<String>("id").unwrap_or_default();
    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    let Some(mut tenant) = state.storage.tenant_by_domain(domain) else {
        scim_error(res, StatusCode::NOT_FOUND, None, "unknown tenant");
        return;
    };
    let Some(user) = resolve_path_user(&mut tenant, &id).await else {
        scim_error(res, StatusCode::NOT_FOUND, None, "Resource not found");
        return;
    };
    match tenant.user_delete(&caller, &user.name).await {
        Ok(()) => {
            res.status_code(StatusCode::NO_CONTENT);
        }
        Err(e) => render_tenant_error(res, &e),
    }
}

// ─── Router ──────────────────────────────────────────────────────────────────

pub fn router() -> Router {
    use salvo::rate_limiter::{BasicQuota, FixedGuard, MokaStore, RateLimiter};

    let limiter = || {
        RateLimiter::new(
            FixedGuard::new(),
            MokaStore::new(),
            crate::utils::JanuxIssuer,
            BasicQuota::per_minute(RATE_LIMIT_PER_MINUTE),
        )
    };

    // Discovery documents are static and tenant-free — public per RFC 7644.
    // Everything under /Users is RBAC-gated by the `scim` role policies
    // (canonicalized resource paths, see `scim_protect`).
    Router::with_path("scim/v2")
        .push(Router::with_path("ServiceProviderConfig").get(service_provider_config))
        .push(Router::with_path("Schemas").get(schemas))
        .push(Router::with_path("ResourceTypes").get(resource_types))
        .push(
            Router::with_path("Users")
                .hoop(limiter())
                .hoop(scim_protect)
                .get(list_users),
        )
        .push(
            Router::with_path("Users")
                .hoop(limiter())
                .hoop(scim_protect)
                .hoop(crate::audit::audit)
                .post(create_user),
        )
        .push(
            Router::with_path("Users/{id}")
                .hoop(limiter())
                .hoop(scim_protect)
                .get(get_user),
        )
        .push(
            Router::with_path("Users/{id}")
                .hoop(limiter())
                .hoop(scim_protect)
                .hoop(crate::audit::audit)
                .put(put_user)
                .patch(patch_user)
                .delete(delete_user),
        )
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use salvo::test::ResponseExt;
    use salvo::test::TestClient;
    use std::sync::LazyLock;

    const DOMAIN: &str = "localhost";

    // Revocation-store infrastructure: same pattern as oidc::tests — the
    // store's connection task must outlive every individual test runtime.
    static TEST_STORE_DIR: LazyLock<tempfile::TempDir> =
        LazyLock::new(|| tempfile::tempdir().expect("store tempdir"));
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

    /// Tenant with a signing key and a client_credentials client — the
    /// machine principal the SCIM surface runs under.
    async fn scim_test_env() -> (crate::server::ServerState, tempfile::TempDir) {
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
            let bootstrap = crate::role::Caller::Bootstrap;
            tenant
                .key_create(DOMAIN, "key1")
                .await
                .expect("signing key");
            tenant
                .oauth2client_create(
                    "scim-client",
                    "scim-secret",
                    &[],
                    "client_credentials",
                    "",
                    "client_secret_post",
                    "",
                )
                .await
                .expect("machine client");
            // protect is default-deny: the test tenant is unseeded, so the
            // scim role and its policy rows are created explicitly (the
            // committed seed.toml carries the same rows for real tenants).
            tenant
                .role_create(&bootstrap, "scim", 0)
                .await
                .expect("scim role");
            for resource in ["/scim/v2/Users", "/scim/v2/Users/{id}"] {
                tenant
                    .policy_create(
                        &bootstrap,
                        DOMAIN,
                        None,
                        resource,
                        "scim",
                        &crate::policy::SourceResolver::Nothing,
                        &crate::policy::TargetResolver::Nothing,
                        false,
                        true,
                    )
                    .await
                    .expect("scim policy");
            }
        }
        let state = crate::server::ServerState::create(storage, false)
            .await
            .expect("server state");
        (state, tmp)
    }

    /// Token endpoint + SCIM surface behind one service.
    fn scim_service(state: crate::server::ServerState) -> Service {
        Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state))
                .push(Router::with_path("token").post(crate::oidc::token))
                .push(router()),
        )
    }

    /// Mint the machine principal end-to-end through the grant itself.
    async fn machine_token(service: &Service) -> String {
        let mut res = TestClient::post("http://localhost/token")
            .add_header("Host", DOMAIN, true)
            .raw_form(
                "grant_type=client_credentials&client_id=scim-client&client_secret=scim-secret",
            )
            .send(service)
            .await;
        assert_eq!(
            res.status_code,
            Some(StatusCode::OK),
            "the machine principal must mint"
        );
        let body: serde_json::Value =
            serde_json::from_str(&res.take_string().await.unwrap_or_default()).unwrap();
        body["access_token"]
            .as_str()
            .expect("access_token")
            .to_string()
    }

    /// validate_jwt reads `local_addr`, which TestClient leaves empty —
    /// build SCIM requests by hand with socket addresses (same workaround
    /// as the oidc consent tests).
    fn build(
        method: salvo::http::Method,
        uri: &str,
        bearer: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> Request {
        let mut req = Request::new();
        *req.method_mut() = method;
        req.set_uri(uri.parse().unwrap());
        req.headers_mut()
            .insert(salvo::http::header::HOST, DOMAIN.parse().unwrap());
        if let Some(token) = bearer {
            req.headers_mut().insert(
                salvo::http::header::AUTHORIZATION,
                format!("Bearer {token}").parse().unwrap(),
            );
        }
        *req.remote_addr_mut() = "127.0.0.1:9999"
            .parse::<std::net::SocketAddr>()
            .unwrap()
            .into();
        *req.local_addr_mut() = "127.0.0.1:8080"
            .parse::<std::net::SocketAddr>()
            .unwrap()
            .into();
        if let Some(body) = body {
            req.headers_mut().insert(
                salvo::http::header::CONTENT_TYPE,
                "application/scim+json".parse().unwrap(),
            );
            *req.body_mut() = salvo::http::ReqBody::from(serde_json::to_string(&body).unwrap());
        }
        req
    }

    async fn scim_json(res: &mut salvo::Response) -> serde_json::Value {
        serde_json::from_str(&res.take_string().await.unwrap_or_default()).unwrap()
    }

    #[tokio::test]
    async fn discovery_is_public_and_speaks_scim() {
        let (state, _tmp) = scim_test_env().await;
        let service = scim_service(state);

        let mut res = TestClient::get("http://localhost/scim/v2/ServiceProviderConfig")
            .add_header("Host", DOMAIN, true)
            .send(&service)
            .await;
        assert_eq!(res.status_code, Some(StatusCode::OK));
        let body = scim_json(&mut res).await;
        assert_eq!(body["patch"]["supported"], true);
        assert_eq!(body["filter"]["supported"], true);
        assert_eq!(body["bulk"]["supported"], false);
    }

    #[tokio::test]
    async fn users_surface_requires_a_token() {
        let (state, _tmp) = scim_test_env().await;
        let service = scim_service(state);

        let res = service
            .handle(build(
                salvo::http::Method::GET,
                "http://localhost/scim/v2/Users",
                None,
                None,
            ))
            .await;
        assert_eq!(res.status_code, Some(StatusCode::UNAUTHORIZED));
    }

    #[tokio::test]
    async fn scim_user_lifecycle_end_to_end() {
        let (state, _tmp) = scim_test_env().await;
        let service = scim_service(state);
        let token = machine_token(&service).await;
        let bearer = Some(token.as_str());

        // Create.
        let mut res = service
            .handle(build(
                salvo::http::Method::POST,
                "http://localhost/scim/v2/Users",
                bearer,
                Some(serde_json::json!({
                    "schemas": [USER_SCHEMA],
                    "userName": "jdoe",
                    "active": true,
                    "externalId": "ext-1",
                    "emails": [{"value": "jdoe@example.com", "primary": true}]
                })),
            ))
            .await;
        assert_eq!(res.status_code, Some(StatusCode::CREATED));
        let created = scim_json(&mut res).await;
        let id = created["id"].as_str().expect("id").to_string();
        assert!(uuid::Uuid::try_parse(&id).is_ok(), "SCIM id is the uuid");
        assert_eq!(created["userName"], "jdoe");
        assert_eq!(created["externalId"], "ext-1");
        assert_eq!(created["emails"][0]["value"], "jdoe@example.com");

        // Duplicate userName -> 409 uniqueness.
        let mut res = service
            .handle(build(
                salvo::http::Method::POST,
                "http://localhost/scim/v2/Users",
                bearer,
                Some(serde_json::json!({ "userName": "jdoe" })),
            ))
            .await;
        assert_eq!(res.status_code, Some(StatusCode::CONFLICT));
        assert_eq!(scim_json(&mut res).await["scimType"], "uniqueness");

        // Get by id.
        let mut res = service
            .handle(build(
                salvo::http::Method::GET,
                &format!("http://localhost/scim/v2/Users/{id}"),
                bearer,
                None,
            ))
            .await;
        assert_eq!(res.status_code, Some(StatusCode::OK));
        assert_eq!(scim_json(&mut res).await["userName"], "jdoe");

        // Filter.
        let mut res = service
            .handle(build(
                salvo::http::Method::GET,
                "http://localhost/scim/v2/Users?filter=userName%20eq%20%22jdoe%22",
                bearer,
                None,
            ))
            .await;
        assert_eq!(res.status_code, Some(StatusCode::OK));
        let list = scim_json(&mut res).await;
        assert_eq!(list["totalResults"], 1);
        assert_eq!(list["Resources"][0]["userName"], "jdoe");

        // Unsupported filter -> 400 invalidFilter.
        let mut res = service
            .handle(build(
                salvo::http::Method::GET,
                "http://localhost/scim/v2/Users?filter=emails%20eq%20%22x%22",
                bearer,
                None,
            ))
            .await;
        assert_eq!(res.status_code, Some(StatusCode::BAD_REQUEST));
        assert_eq!(scim_json(&mut res).await["scimType"], "invalidFilter");

        // PATCH deactivate.
        let mut res = service
            .handle(build(
                salvo::http::Method::PATCH,
                &format!("http://localhost/scim/v2/Users/{id}"),
                bearer,
                Some(serde_json::json!({
                    "schemas": [PATCH_OP_SCHEMA],
                    "operations": [{"op": "replace", "path": "active", "value": false}]
                })),
            ))
            .await;
        assert_eq!(res.status_code, Some(StatusCode::OK));
        assert_eq!(scim_json(&mut res).await["active"], false);

        // PATCH rename (SCIM userName update — IdP UPN change).
        let mut res = service
            .handle(build(
                salvo::http::Method::PATCH,
                &format!("http://localhost/scim/v2/Users/{id}"),
                bearer,
                Some(serde_json::json!({
                    "schemas": [PATCH_OP_SCHEMA],
                    "operations": [{"op": "replace", "path": "userName", "value": "jdorian"}]
                })),
            ))
            .await;
        assert_eq!(res.status_code, Some(StatusCode::OK));
        let renamed = scim_json(&mut res).await;
        assert_eq!(renamed["userName"], "jdorian");
        assert_eq!(renamed["id"], id, "the resource id survives a rename");

        // Delete -> 204, then 404.
        let res = service
            .handle(build(
                salvo::http::Method::DELETE,
                &format!("http://localhost/scim/v2/Users/{id}"),
                bearer,
                None,
            ))
            .await;
        assert_eq!(res.status_code, Some(StatusCode::NO_CONTENT));
        let res = service
            .handle(build(
                salvo::http::Method::GET,
                &format!("http://localhost/scim/v2/Users/{id}"),
                bearer,
                None,
            ))
            .await;
        assert_eq!(res.status_code, Some(StatusCode::NOT_FOUND));
    }

    /// RBAC: a session without the `scim` role gets default-deny, even on
    /// a path the scim policies cover.
    #[tokio::test]
    async fn non_scim_sessions_are_denied() {
        let (state, _tmp) = scim_test_env().await;
        {
            let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
            let bootstrap = crate::role::Caller::Bootstrap;
            tenant.user_create("mallory").await.expect("user");
            tenant
                .role_create(&bootstrap, "user", 0)
                .await
                .expect("role");
            tenant
                .user_add_role(&bootstrap, "mallory", "user")
                .await
                .expect("grant");
        }
        let service = scim_service(state.clone());

        let token = {
            let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
            tenant
                .authenticate_jwt(
                    &std::collections::HashSet::new(),
                    "http://localhost",
                    DOMAIN,
                    "mallory",
                    15,
                )
                .await
                .expect("session token")
        };

        let res = service
            .handle(build(
                salvo::http::Method::GET,
                "http://localhost/scim/v2/Users",
                Some(&token),
                None,
            ))
            .await;
        assert_eq!(
            res.status_code,
            Some(StatusCode::UNAUTHORIZED),
            "default-deny: a `user`-role session must not reach the SCIM surface"
        );
    }
}
