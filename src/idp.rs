use crate::domain::Domain;
use crate::utils::ApiProblem;
use crate::utils::ApiResponse;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rsa::rand_core::OsRng;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use toasty::*;

/// OAuth2/OIDC Client registration — tenant-scoped
/// Gapped from gaps.md as G8. Implements RFC 6749 §2 + §4.1.1 client management.
#[derive(Debug, toasty::Model, Clone)]
pub struct OAuth2Client {
    /// Unique opaque client identifier (RFC 6749 §2)
    #[key]
    pub id: String,

    /// Stable opaque service-identity id: the JWT `sub` minted for this
    /// client's machine flows (client_credentials).
    #[auto(uuid(v7))]
    pub uuid: uuid::Uuid,

    /// Derived value — never store plaintext secrets
    #[index]
    pub client_secret_hash: String,

    /// Space-separated grant types this client may use: "authorization_code"
    #[index]
    pub grant_types: String,

    /// Space-separated response types the client expects to receive
    #[index]
    pub response_types: String,

    /// Auth method at /token: "client_secret_post" | "client_secret_basic" | "none"
    pub token_endpoint_auth_method: String,

    /// Default scope (space-separated) offered on /authorize when none specified
    #[index]
    pub scope: String,

    /// Tenant/domain this client belongs to (foreign key string)
    #[index]
    pub domain_id: String,

    /// When in grace period — the old secret_hash stays valid if set
    #[default(None)]
    pub secret_grace_until: Option<jiff::Timestamp>,

    /// Active flag — soft-delete support for admin deletion
    #[default(true)]
    pub active: bool,

    #[auto]
    pub updated_at: jiff::Timestamp,

    #[auto]
    pub created_at: jiff::Timestamp,

    #[has_many]
    pub redirect_uris: Deferred<Vec<RedirectURI>>,

    #[belongs_to(key = domain_id, references = id)]
    pub domain: Deferred<Domain>,
}

#[derive(Debug, toasty::Model, Clone)]
pub struct RedirectURI {
    /// Key — unique redirect URI string (e.g. "https://example.com/callback")
    #[key]
    pub id: String,

    #[index]
    client_id: String,

    #[auto]
    pub updated_at: jiff::Timestamp,

    #[auto]
    pub created_at: jiff::Timestamp,
    #[belongs_to(key = client_id, references = id)]
    pub o_auth2_client: Deferred<OAuth2Client>,
}

/// Relational consent/audit record written by /authorize (OIDC Core §3.1.2.4).
///
/// One row per granted authorization. The latest non-revoked row for a
/// (user_id, client_id) pair decides whether consent can be skipped; its
/// `scope` must cover the requested scopes. `code_hash` is hex(sha256(code)) —
/// the raw authorization code is never persisted.
#[derive(Debug, toasty::Model, Clone)]
pub struct AuthGrant {
    /// Unique grant identifier (UUID) — the jti bound into the auth code grant.
    #[key]
    pub jti: String,

    #[index]
    pub client_id: String,

    #[index]
    pub user_id: String,

    /// Space-separated scopes the user approved (RFC 6749 §3.3).
    pub scope: String,

    /// hex(sha256(auth_code)) — proof-of-ownership reference for audit.
    pub code_hash: String,

    /// Expiry of the associated authorization code (code lifetime, not consent
    /// lifetime — consent validity is governed by `revoked` + scope coverage).
    pub expires_at: jiff::Timestamp,

    #[default(false)]
    pub revoked: bool,

    #[auto]
    pub updated_at: jiff::Timestamp,

    #[auto]
    pub created_at: jiff::Timestamp,
}

/// Extended OIDC client metadata that the `OAuth2Client` table does not
/// carry: RP-Initiated Logout redirect URIs, the Back-Channel Logout
/// delivery URI, and provenance (dynamic registration).
///
/// Stored in the tenant `Config` key-value store under
/// `oidc.client.<client_id>` rather than as table columns: tenant
/// databases created before this feature tolerate `push_schema` failures
/// on existing tables (`connect_tenant`), so a new column would silently
/// never appear there while queries reference it. The `Config` store is
/// the established migration-free extension point (same pattern as
/// `ResendDTO` / `OTPDTO`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientMeta {
    /// Human-readable client name (RFC 7591 §2 `client_name`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    /// Back-Channel Logout 1.0 §2.1 delivery URI; absent = the client
    /// does not participate in back-channel logout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_uri: Option<String>,
    /// URIs accepted as `post_logout_redirect_uri` at `/end_session`
    /// (RP-Initiated Logout 1.0 §2 — "previously registered"). Checked
    /// in addition to the client's registered redirect URIs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub post_logout_redirect_uris: Vec<String>,
    /// True when the client was created through dynamic registration
    /// (RFC 7591) rather than the admin API.
    #[serde(default)]
    pub dynamic: bool,
}

/// Config key prefix for per-client extended metadata.
pub const CLIENT_META_PREFIX: &str = "oidc.client.";
/// Config key holding the tenant's Dynamic Client Registration switch.
pub const DCR_CONFIG_KEY: &str = "oidc.dcr";

#[derive(Serialize, ToSchema)]
pub struct OAuth2ClientDto {
    pub id: String,
    pub redirect_uris: String,
    pub grant_types: String,
    pub response_types: String,
    pub token_endpoint_auth_method: String,
    pub scope: String,
    pub domain_id: String,
    #[salvo(schema(value_type = Option<String>))]
    pub secret_grace_until: Option<jiff::Timestamp>,
    pub active: bool,
    #[salvo(schema(value_type = String))]
    pub updated_at: jiff::Timestamp,
    #[salvo(schema(value_type = String))]
    pub created_at: jiff::Timestamp,
}

impl OAuth2ClientDto {
    /// the `redirect_uris` deferred is never loaded by list/get
    /// queries, so the caller supplies the explicitly-queried URIs.
    /// Whitespace-joined to match the whitespace-split convention used at
    /// client creation.
    pub fn from_client(c: OAuth2Client, redirect_uris: Vec<String>) -> Self {
        Self {
            id: c.id,
            redirect_uris: redirect_uris.join(" "),
            grant_types: c.grant_types,
            response_types: c.response_types,
            token_endpoint_auth_method: c.token_endpoint_auth_method,
            scope: c.scope,
            domain_id: c.domain_id,
            secret_grace_until: c.secret_grace_until,
            active: c.active,
            updated_at: c.updated_at,
            created_at: c.created_at,
        }
    }
}

impl OAuth2Client {
    /// Parse stored grant_types (space-separated) into a Vec.
    pub fn get_grant_types(&self) -> Vec<String> {
        if self.grant_types.is_empty() {
            vec![]
        } else {
            self.grant_types
                .split_whitespace()
                .map(String::from)
                .collect()
        }
    }

    /// Parse stored response_types (space-separated) into a Vec.
    pub fn get_response_types(&self) -> Vec<String> {
        if self.response_types.is_empty() {
            vec![]
        } else {
            self.response_types
                .split_whitespace()
                .map(String::from)
                .collect()
        }
    }

    /// Parse stored default scope (space-separated) into a Vec.
    pub fn get_scope(&self) -> Vec<String> {
        if self.scope.is_empty() {
            vec![]
        } else {
            self.scope.split_whitespace().map(String::from).collect()
        }
    }

    // ── Argon2 password hashing ───────────────────────────────────────────────

    /// Hash a plaintext secret with Argon2id (auto-salt), returning the full encoding.
    pub fn hash_secret(secret: &str) -> anyhow::Result<String> {
        let argon2 = Argon2::default();
        let salt = SaltString::generate(&mut OsRng);
        let encoded = argon2
            .hash_password(secret.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("argon2 hash failed: {0}", e))?;
        Ok(encoded.to_string())
    }

    /// Verify a plaintext password against the stored Argon2id encoding.
    pub fn verify_password(&self, attempted: &str) -> anyhow::Result<bool> {
        let parsed = PasswordHash::new(&self.client_secret_hash)
            .map_err(|e| anyhow::anyhow!("invalid hash format: {0}", e))?;
        Ok(Argon2::default()
            .verify_password(attempted.as_bytes(), &parsed)
            .is_ok())
    }
}

// ── Tenant helper methods ────────────────────────────────────────────────────

impl crate::db::Tenant {
    /// Register a new OAuth2 client for this tenant.
    pub async fn oauth2client_create(
        &mut self,
        id: &str,
        secret: &str,
        redirect_uris: &[&str],
        grant_types: &str,
        response_types: &str,
        auth_method: &str,
        default_scopes: &str,
    ) -> anyhow::Result<()> {
        let secret_hash = OAuth2Client::hash_secret(secret)?;
        toasty::create!(OAuth2Client {
            id,
            client_secret_hash: secret_hash,
            grant_types: grant_types.to_string(),
            response_types: response_types.to_string(),
            token_endpoint_auth_method: auth_method.to_string(),
            scope: default_scopes.to_string(),
            domain_id: self.name.clone(),
            active: true,
        })
        .exec(&mut self.database)
        .await?;
        for uri in redirect_uris {
            RedirectURI::create()
                .id(uri.to_string())
                .client_id(id.to_string())
                .exec(&mut self.database)
                .await?;
        }
        Ok(())
    }

    /// List all active OAuth2 clients for this tenant.
    pub async fn oauth2client_all(&mut self) -> anyhow::Result<Vec<OAuth2Client>> {
        OAuth2Client::filter(
            OAuth2Client::fields()
                .domain_id()
                .eq(self.name.clone())
                .and(OAuth2Client::fields().active().eq(true)),
        )
        .exec(&mut self.database)
        .await
        .map_err(Into::into)
    }

    /// Get a single active OAuth2 client (used on token_endpoint to validate client_id).
    pub async fn oauth2client_get(&mut self, id: &str) -> anyhow::Result<OAuth2Client> {
        let c = OAuth2Client::get_by_id(&mut self.database, id)
            .await
            .map_err(|_e| anyhow::anyhow!("OAuth2 client '{}' not found", id))?;
        if !c.active {
            return Err(anyhow::anyhow!("OAuth2 client '{}' is inactive", id));
        }
        Ok(c)
    }

    /// Redirect URIs registered for a client: `get_by_id`/`filter`
    /// never load `has_many` deferreds, and `.into_inner()` on the unloaded
    /// `redirect_uris` relation panics. Consumers must query the relation
    /// explicitly (same pattern as 's `user_roles`).
    pub async fn oauth2client_redirect_uris(
        &mut self,
        id: &str,
    ) -> anyhow::Result<Vec<RedirectURI>> {
        OAuth2Client::filter_by_id(id)
            .redirect_uris()
            .exec(&mut self.database)
            .await
            .map_err(Into::into)
    }

    /// Soft-delete an OAuth2 client by setting active=false (B-1).
    pub async fn oauth2client_delete(&mut self, id: &str) -> Result<()> {
        OAuth2Client::update_by_id(id)
            .active(false)
            .exec(&mut self.database)
            .await
            .map(|_| ())
    }

    /// Extended OIDC metadata for a client ([`ClientMeta`]), if any was
    /// recorded. Absent entry = default metadata (no logout URIs, static
    /// registration).
    pub async fn client_meta_load(&mut self, client_id: &str) -> Option<ClientMeta> {
        self.config_get(&format!("{CLIENT_META_PREFIX}{client_id}"))
            .await
            .and_then(|v| serde_json::from_value(v).ok())
    }

    /// Persist extended OIDC metadata for a client.
    pub async fn client_meta_save(
        &mut self,
        client_id: &str,
        meta: &ClientMeta,
    ) -> anyhow::Result<()> {
        let value = serde_json::to_value(meta)?;
        self.config_set(&format!("{CLIENT_META_PREFIX}{client_id}"), value)
            .await
            .map(|_| ())
    }

    /// Whether Dynamic Client Registration (RFC 7591) is enabled for this
    /// tenant. Default false — open registration is an abuse vector, so
    /// each tenant opts in explicitly via the admin API.
    pub async fn dcr_enabled(&mut self) -> bool {
        self.config_get(DCR_CONFIG_KEY)
            .await
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }

    /// Flip the Dynamic Client Registration switch for this tenant.
    pub async fn dcr_set_enabled(&mut self, enabled: bool) -> anyhow::Result<()> {
        self.config_set(DCR_CONFIG_KEY, serde_json::json!(enabled))
            .await
            .map(|_| ())
    }

    /// All non-revoked consent grants for a user, across clients. The
    /// back-channel logout fan-out uses this to find every RP that holds
    /// an active authorization for the user being logged out.
    pub async fn auth_grant_all_for_user(
        &mut self,
        user_id: &str,
    ) -> anyhow::Result<Vec<AuthGrant>> {
        AuthGrant::filter(
            AuthGrant::fields()
                .user_id()
                .eq(user_id.to_string())
                .and(AuthGrant::fields().revoked().eq(false)),
        )
        .exec(&mut self.database)
        .await
        .map_err(Into::into)
    }

    /// Latest non-revoked consent grant for (user, client), if any.
    /// WHERE user_id AND client_id AND revoked=false ORDER BY created_at DESC LIMIT 1.
    pub async fn auth_grant_find(
        &mut self,
        user_id: &str,
        client_id: &str,
    ) -> anyhow::Result<Option<AuthGrant>> {
        AuthGrant::filter(
            AuthGrant::fields()
                .user_id()
                .eq(user_id.to_string())
                .and(AuthGrant::fields().client_id().eq(client_id.to_string()))
                .and(AuthGrant::fields().revoked().eq(false)),
        )
        .latest_by(AuthGrant::fields().created_at())
        .first()
        .exec(&mut self.database)
        .await
        .map_err(Into::into)
    }

    /// Revoke all non-revoked grants for (user, client) — REPLACE semantics
    /// when the user accepts a new consent decision.
    pub async fn auth_grant_revoke_for(
        &mut self,
        user_id: &str,
        client_id: &str,
    ) -> anyhow::Result<()> {
        let grants = AuthGrant::filter(
            AuthGrant::fields()
                .user_id()
                .eq(user_id.to_string())
                .and(AuthGrant::fields().client_id().eq(client_id.to_string()))
                .and(AuthGrant::fields().revoked().eq(false)),
        )
        .exec(&mut self.database)
        .await?;
        for g in grants {
            AuthGrant::update_by_jti(&g.jti)
                .revoked(true)
                .exec(&mut self.database)
                .await?;
        }
        Ok(())
    }

    /// Record a new authorization grant (audit + consent record).
    pub async fn auth_grant_create(
        &mut self,
        jti: &str,
        client_id: &str,
        user_id: &str,
        scope: &str,
        code_hash: &str,
        expires_at: jiff::Timestamp,
    ) -> anyhow::Result<()> {
        toasty::create!(AuthGrant {
            jti,
            client_id,
            user_id,
            scope,
            code_hash,
            expires_at,
            revoked: false,
        })
        .exec(&mut self.database)
        .await?;
        Ok(())
    }
}

#[derive(Deserialize, ToSchema)]
pub struct NewOauth2Client {
    pub client_id: String,
    pub secret: String,
    pub redirect_uris: String,
    pub grant_types: String,
    pub response_types: String,
    pub token_endpoint_auth_method: String,
    pub default_scopes: String,
}

#[derive(Deserialize, ToSchema)]
pub struct DeleteOauth2Client {
    pub client_id: String,
}

#[endpoint(
    summary = "Create a new OAuth2 client",
    request_body = NewOauth2Client,
    responses(
        (status_code = 200, description = "Client created successfully", body = ApiResponse<()>),
        (status_code = 400, description = "Bad request", body = ApiProblem),
    )
)]
pub async fn new_oauth2client(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let body = match crate::utils::extract::<NewOauth2Client>(req, None).await {
        Some(b) => b,
        None => {
            let err = ApiProblem::validation_error("Failed to parse request body");
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(err));
            return;
        }
    };

    let state = depot.obtain_mut::<crate::server::ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    let redirect_uris: Vec<&str> = body.redirect_uris.split_whitespace().collect();
    if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
        match tenant
            .oauth2client_create(
                &body.client_id,
                &body.secret,
                &redirect_uris,
                &body.grant_types,
                &body.response_types,
                &body.token_endpoint_auth_method,
                &body.default_scopes,
            )
            .await
        {
            Ok(_) => {
                res.status_code(StatusCode::OK);
                res.render(Json(ApiResponse::ok(())));
            }
            Err(e) => {
                let err = ApiProblem::validation_error(&e.to_string());
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(err));
            }
        }
    } else {
        let err = ApiProblem::not_found("Unknown domain");
        res.status_code(StatusCode::BAD_REQUEST);
        res.render(Json(err));
    }
}

#[endpoint(
    summary = "List all active OAuth2 clients for the current tenant",
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<Vec<OAuth2ClientDto>>),
        (status_code = 400, description = "Bad request", body = ApiProblem),
    )
)]
pub async fn list_oauth2clients(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain_mut::<crate::server::ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
        match tenant.oauth2client_all().await {
            Ok(clients) => {
                // the redirect_uris deferred is unloaded on these
                // rows — query each client's URIs explicitly.
                let mut dtos = Vec::with_capacity(clients.len());
                for c in clients {
                    let uris = match tenant.oauth2client_redirect_uris(&c.id).await {
                        Ok(uris) => uris.into_iter().map(|r| r.id).collect(),
                        Err(e) => {
                            let err = ApiProblem::validation_error(&e.to_string());
                            res.status_code(StatusCode::BAD_REQUEST);
                            res.render(Json(err));
                            return;
                        }
                    };
                    dtos.push(OAuth2ClientDto::from_client(c, uris));
                }
                res.status_code(StatusCode::OK);
                res.render(Json(ApiResponse::ok(dtos)));
            }
            Err(e) => {
                let err = ApiProblem::validation_error(&e.to_string());
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(err));
            }
        }
    } else {
        let err = ApiProblem::not_found("Unknown domain");
        res.status_code(StatusCode::BAD_REQUEST);
        res.render(Json(err));
    }
}

#[endpoint(
    summary = "Deactivate (soft-delete) an OAuth2 client",
    request_body = DeleteOauth2Client,
    responses(
        (status_code = 200, description = "Client deactivated", body = ApiResponse<String>),
        (status_code = 400, description = "Bad request", body = ApiProblem),
    )
)]
pub async fn delete_oauth2client(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let body = match crate::utils::extract::<DeleteOauth2Client>(req, None).await {
        Some(b) => b,
        None => {
            let err = ApiProblem::validation_error("Failed to parse request body");
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(err));
            return;
        }
    };

    let state = depot.obtain_mut::<crate::server::ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
        match tenant.oauth2client_delete(&body.client_id).await {
            Ok(_) => {
                res.status_code(StatusCode::OK);
                res.render(Json(ApiResponse::ok("OAuth2 client deactivated")));
            }
            Err(e) => {
                let err = ApiProblem::validation_error(&e.to_string());
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(err));
            }
        }
    } else {
        let err = ApiProblem::not_found("Unknown domain");
        res.status_code(StatusCode::BAD_REQUEST);
        res.render(Json(err));
    }
}
