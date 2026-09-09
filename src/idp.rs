use crate::domain::Domain;
use crate::utils::ApiProblem;
use crate::utils::{ApiResponse, Page};
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rsa::rand_core::OsRng;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use toasty::*;

/// OAuth2/OIDC Client registration — tenant-scoped
/// Implements RFC 6749 §2 + §4.1.1 client management.
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

    /// Domain this client is registered on (FK → `Domain.id`). The tenant
    /// is implicit — every tenant lives in its own database file — so this
    /// column must NEVER hold the tenant name (it did before the domain
    /// scoping fix, which made the `belongs_to` relation below dead and
    /// let a client registered on one domain answer on all of them).
    #[index]
    pub domain_id: String,

    /// Previous secret hash, kept during a rotation grace window so a client
    /// that cached the old secret keeps authenticating until `secret_grace_until`
    /// (G-96). `None` when no rotation is in flight.
    #[default(None)]
    pub client_prev_secret_hash: Option<String>,

    /// When the grace window ends: until then `client_prev_secret_hash` ALSO
    /// verifies at the token endpoint; after it only the current hash does.
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
    /// Per-client redirect-URI registration.
    ///
    /// G-143: identity is the `(client_id, uri)` pair, NOT the bare URI string.
    /// Under the old single-column `id = uri` key the URI occupied a *global*
    /// keyspace: two clients could never share a callback, a soft-deleted client
    /// permanently squatted its URIs (blocking delete+recreate rotation, G-96),
    /// and a DCR registrant could squat a victim RP's callback. Scoping the key
    /// to the client removes all three: another client may register the same URL,
    /// a deleted client blocks no one, and a client's own URI set is replaceable
    /// without squatting. `client_id` (PK prefix) + `uri` (PK suffix) per client;
    /// the prefix also indexes per-client lookups.
    #[key]
    #[index]
    pub client_id: String,

    /// The redirect URI string — PK suffix, unique per client only (G-143).
    #[key]
    pub uri: String,

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
        Self::verify_hash(&self.client_secret_hash, attempted)
     }

     /// Verify a presented secret against an arbitrary stored Argon2id
     /// encoding — the primitive behind `verify_password` and the rotation
     /// grace path.
     pub fn verify_hash(stored: &str, attempted: &str) -> anyhow::Result<bool> {
        let parsed = PasswordHash::new(stored)
             .map_err(|e| anyhow::anyhow!("invalid hash format: {0}", e))?;
        Ok(Argon2::default()
             .verify_password(attempted.as_bytes(), &parsed)
             .is_ok())
     }

     /// Verify a presented secret, honoring the rotation grace window (G-96):
     /// the current hash always wins; while `secret_grace_until` is in the future
     /// the previous hash (`client_prev_secret_hash`) ALSO verifies, so a client
     /// still presenting an un-rotated secret authenticates through the cutover
     /// rather than being bricked. Both hashes are Argon2id, so a failed attempt
     /// still pays the full stretch.
     pub fn verify_secret_with_grace(&self, attempted: &str) -> anyhow::Result<bool> {
        if self.verify_password(attempted)? {
             return Ok(true);
          }
        if let Some(until) = self.secret_grace_until
               && jiff::Timestamp::now() < until
               && let Some(prev) = &self.client_prev_secret_hash
               && !prev.is_empty()
          {
             return Self::verify_hash(prev, attempted);
          }
        Ok(false)
     }
}

// ── Tenant helper methods ────────────────────────────────────────────────────

impl crate::db::Tenant {
         /// Register a new OAuth2 client on `domain`. Clients are domain-scoped:
     /// `domain_id` stores the registration domain (FK → `Domain.id`), never
     /// the tenant name — the tenant is implicit in the per-tenant database.
     ///
     /// G-96: a delete is a *soft* delete, so this is idempotent over a soft-
     /// deleted slot — re-using the same `client_id` re-creates the client
     /// (fresh uuid + secret, replaced URIs) instead of failing a rotation. A
     /// *live* client's id is still unique; the check is fail-fast, before any
     /// write, so a collision never leaves a half-registered client behind.
     #[allow(clippy::too_many_arguments)]
   pub async fn oauth2client_create(
         &mut self,
       domain: &str,
       id: &str,
       secret: &str,
       redirect_uris: &[&str],
       grant_types: &str,
       response_types: &str,
       auth_method: &str,
       default_scopes: &str,
     ) -> anyhow::Result<()> {
       let secret_hash = OAuth2Client::hash_secret(secret)?;
       self.upsert_client(
            domain,
            id,
            secret_hash,
            redirect_uris,
            grant_types,
            response_types,
            auth_method,
            default_scopes,
        )
        .await
      }

      /// Insert-or-reactivate the client row and its per-client `RedirectURI`
      /// set from a precomputed Argon2 hash. Shared by `oauth2client_create`
      /// (which hashes the plaintext first) and `oauth2client_reactivate`
      /// (which reuses the stored hash). G-96 / G-143.
      #[allow(clippy::too_many_arguments)]
   async fn upsert_client(
         &mut self,
       domain: &str,
       id: &str,
       secret_hash: String,
       redirect_uris: &[&str],
       grant_types: &str,
       response_types: &str,
       auth_method: &str,
       default_scopes: &str,
     ) -> anyhow::Result<()> {
         // ── fail-fast / idempotent-over-dead ─────────────────────────────
         // A same-named client must be ours (domain-scoped) or we report
         // "not found" rather than touch another domain's row; a soft-deleted
         // slot is wiped so the fresh insert mints a clean uuid — which escapes
         // the delete-time machine-token poison marker (G-123), so the client's
         // NEW tokens pass while any leaked OLD tokens stay revoked.
       if let Ok(existing) = OAuth2Client::get_by_id(&mut self.database, id).await {
            if existing.domain_id != domain {
               return Err(anyhow::anyhow!("OAuth2 client '{}' not found", id));
              }
            if existing.active {
               return Err(anyhow::anyhow!("OAuth2 client '{}' already exists", id));
              }
              // G-143: the per-client keyspace means the dead slot's URIs can
              // be dropped without affecting anyone else; do so, then free the
              // `client_id` PK so the fresh insert below succeeds.
            for r in self.oauth2client_redirect_uris(id).await? {
               RedirectURI::delete_by_client_id_and_uri(&mut self.database, id, &r.uri)
                     .await
                     .ok();
              }
            OAuth2Client::delete_by_id(&mut self.database, id).await?;
         }

         // Insert the client row first, then its URIs. Dedup the input so a
         // repeated URI does not collide with its own composite (client_id,
         // uri) PK.
       toasty::create!(OAuth2Client {
           id,
           client_secret_hash: secret_hash,
           grant_types: grant_types.to_string(),
           response_types: response_types.to_string(),
           token_endpoint_auth_method: auth_method.to_string(),
           scope: default_scopes.to_string(),
           domain_id: domain.to_string(),
           active: true,
         })
         .exec(&mut self.database)
         .await?;
        let mut seen = std::collections::HashSet::new();
        for uri in redirect_uris {
            if !seen.insert(uri.to_string()) {
               continue;
              }
            RedirectURI::create()
                   .client_id(id.to_string())
                   .uri(uri.to_string())
                   .exec(&mut self.database)
                   .await?;
         }
       Ok(())
     }

      /// G-96: bring a soft-deleted client back to `active`, preserving its id,
      /// stored secret, and registered URIs (redirect URIs are per-client, so a
      /// deletion never squats another client's callbacks). The service-identity
      /// `uuid` is re-minted so the delete-time poison marker (G-123, keyed by
      /// `uuid`) keeps rejecting tokens issued *before* the deletion, while the
      /// client's freshly issued tokens pass.
   pub async fn oauth2client_reactivate(&mut self, domain: &str, id: &str) -> anyhow::Result<()> {
       let c = OAuth2Client::get_by_id(&mut self.database, id)
             .await
             .map_err(|_e| anyhow::anyhow!("OAuth2 client '{}' not found", id))?;
       if c.domain_id != domain {
           return Err(anyhow::anyhow!("OAuth2 client '{}' not found", id));
         }
       if c.active {
           return Err(anyhow::anyhow!("OAuth2 client '{}' is already active", id));
         }
       OAuth2Client::update_by_id(id)
             .active(true)
             .uuid(uuid::Uuid::now_v7())
             .exec(&mut self.database)
             .await
             .map_err(Into::<anyhow::Error>::into)?;
       Ok(())
     }

      /// G-96: rotate a live client's secret with a grace window. `new_secret`
      /// becomes the current hash; the previous hash is retained as
      /// `client_prev_secret_hash` and kept verifying until `secret_grace_until`
      /// (see `verify_secret_with_grace`), so a client still using the old
      /// secret authenticates through the cutover instead of being bricked.
   pub async fn oauth2client_rotate_secret(
         &mut self,
       domain: &str,
       id: &str,
       new_secret: &str,
       grace_minutes: i64,
     ) -> anyhow::Result<()> {
       let c = OAuth2Client::get_by_id(&mut self.database, id)
             .await
             .map_err(|_e| anyhow::anyhow!("OAuth2 client '{}' not found", id))?;
       if c.domain_id != domain {
           return Err(anyhow::anyhow!("OAuth2 client '{}' not found", id));
         }
       if c.token_endpoint_auth_method == "none" {
           return Err(anyhow::anyhow!("client '{}' has no secret to rotate", id));
         }
       let new_hash = OAuth2Client::hash_secret(new_secret)?;
       let grace_until = jiff::Timestamp::from_second(
            jiff::Timestamp::now().as_second() + grace_minutes * 60,
        )
         .unwrap_or_else(|_| jiff::Timestamp::now());
       OAuth2Client::update_by_id(id)
             .client_secret_hash(new_hash)
             .client_prev_secret_hash(c.client_secret_hash)
             .secret_grace_until(grace_until)
             .exec(&mut self.database)
             .await
             .map_err(Into::<anyhow::Error>::into)?;
       Ok(())
     }

     /// Update a registered client's metadata (RFC 7592 §4, G-125). The
     /// `client_id`, secret, and grace window are immutable here; redirect URIs
     /// are replaced as a set. With the per-client `RedirectURI` keyspace
     /// (G-143) a URI is uniquely identified *within* this client — another
     /// client may share the same callback — so the set replacement drops the
     /// removed rows and binds the added ones, all under the tenant write guard,
     /// which serializes the check-then-act.
     #[allow(clippy::too_many_arguments)]
   pub async fn oauth2client_update(
         &mut self,
       domain: &str,
       id: &str,
       grant_types: &str,
       response_types: &str,
       auth_method: &str,
       scope: &str,
       redirect_uris: &[String],
     ) -> anyhow::Result<()> {
       let c = OAuth2Client::get_by_id(&mut self.database, id)
             .await
             .map_err(|_e| anyhow::anyhow!("OAuth2 client '{}' not found", id))?;
       if c.domain_id != domain {
           return Err(anyhow::anyhow!("OAuth2 client '{}' not found", id));
         }
       let current = self
             .oauth2client_redirect_uris(id)
             .await?
             .into_iter()
             .map(|r| r.uri)
             .collect::<std::collections::HashSet<String>>();

         // Drop the URIs this update removes, then bind the ones not already
         // present. Per-client keyspace makes each op a targeted delete/insert.
       for uri in &current {
            if !redirect_uris.iter().any(|w| w == uri) {
               RedirectURI::delete_by_client_id_and_uri(&mut self.database, id, uri)
                     .await
                     .ok();
              }
         }
       for uri in redirect_uris {
            if !current.contains(uri) {
               RedirectURI::create()
                     .client_id(id.to_string())
                     .uri(uri.clone())
                     .exec(&mut self.database)
                     .await?;
              }
         }
       OAuth2Client::update_by_id(id)
             .grant_types(grant_types.to_string())
             .response_types(response_types.to_string())
             .token_endpoint_auth_method(auth_method.to_string())
             .scope(scope.to_string())
             .exec(&mut self.database)
             .await
             .map_err(Into::<anyhow::Error>::into)?;
       Ok(())
     }

/// One DB-level page of active OAuth2 clients on `domain`, ordered by id
    /// so pages are stable and disjoint. The `limit + 1` probe row (see
    /// [`crate::utils::Page`]) is fetched and folded into `next_offset`
    /// internally.
    pub async fn oauth2client_page(
        &mut self,
        domain: &str,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<Page<OAuth2Client>> {
        let (fetch, offset) = crate::utils::page_bounds(limit, offset);
        let rows = OAuth2Client::filter(
            OAuth2Client::fields()
                .domain_id()
                .eq(domain.to_string())
                .and(OAuth2Client::fields().active().eq(true)),
        )
        .order_by(OAuth2Client::fields().id().asc())
        .limit(fetch)
        .offset(offset)
        .exec(&mut self.database)
        .await
        .map_err::<anyhow::Error, _>(Into::into)?;
        Ok(Page::from_rows(rows, limit, offset))
    }

    /// Batch-fetch the redirect URIs of several clients in one query
    /// (`RedirectURI.client_id` is indexed), replacing a per-client N+1.
    pub async fn redirect_uris_for_clients(
        &mut self,
        client_ids: Vec<String>,
    ) -> anyhow::Result<Vec<RedirectURI>> {
        if client_ids.is_empty() {
            return Ok(Vec::new());
        }
        RedirectURI::filter(toasty::stmt::Expr::in_list(
            RedirectURI::fields().client_id(),
            client_ids,
        ))
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
    /// Soft-delete an OAuth2 client by setting active=false (B-1).
    /// Domain-scoped: a client registered on another domain of the same
    /// tenant is "not found" here — one domain's admin surface must not
    /// deactivate another domain's relying parties.
    ///
    /// G-123: deactivation alone only stops ISSUANCE
    /// (`authenticate_client` rejects inactive clients) — outstanding
    /// machine tokens are stateless 90-day JWTs, so the delete also
    /// poisons the `machine_client:{uuid}` revocation marker and
    /// `validate_token` rejects every live principal of this client from
    /// then on. Order matters: deactivate first, then poison — a poison
    /// failure can never leave an ACTIVE client whose tokens are rejected,
    /// and the error is surfaced so the admin can retry (idempotently).
    pub async fn oauth2client_delete(&mut self, domain: &str, id: &str) -> anyhow::Result<()> {
        let c = OAuth2Client::get_by_id(&mut self.database, id)
            .await
            .map_err(|_e| anyhow::anyhow!("OAuth2 client '{}' not found", id))?;
        if c.domain_id != domain {
            return Err(anyhow::anyhow!("OAuth2 client '{}' not found", id));
        }
        OAuth2Client::update_by_id(id)
            .active(false)
            .exec(&mut self.database)
            .await
            .map_err(Into::<anyhow::Error>::into)?;
        crate::utils::poison_client_machine_tokens(&c.uuid.to_string())
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "client '{}' deactivated, but machine-token revocation failed: {e}",
                    id
                )
            })?;
        Ok(())
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

    /// The grant recorded for a presented authorization-code hash — the
    /// persistent code→grant mapping used for REPLAY detection (G-142):
    /// the one-shot code cache cannot distinguish "expired" from "already
    /// exchanged", but a grant row carrying this `code_hash` proves tokens
    /// were issued. Deliberately NOT restricted to non-revoked rows — a
    /// replay must find its grant even after the first revocation.
    pub async fn auth_grant_by_code_hash(
        &mut self,
        code_hash: &str,
    ) -> anyhow::Result<Option<AuthGrant>> {
        AuthGrant::filter(AuthGrant::fields().code_hash().eq(code_hash.to_string()))
            .latest_by(AuthGrant::fields().created_at())
            .first()
            .exec(&mut self.database)
            .await
            .map_err(Into::into)
    }

    /// Revoke a single grant by jti (the code-replay response, G-142).
    pub async fn auth_grant_revoke_jti(&mut self, jti: &str) -> anyhow::Result<()> {
        AuthGrant::update_by_jti(jti)
            .revoked(true)
            .exec(&mut self.database)
            .await
            .map(|_| ())
            .map_err(Into::into)
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
    crate::audit::record_target_detail(
        res,
        "client",
        &body.client_id,
        &format!(
            "grants={},auth={}",
            body.grant_types, body.token_endpoint_auth_method
        ),
    );

    let state = depot.obtain_mut::<crate::server::ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    let redirect_uris: Vec<&str> = body.redirect_uris.split_whitespace().collect();
    if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
        match tenant
            .oauth2client_create(
                domain,
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
    parameters(
        ("limit" = Option<usize>, Query, description = "Max items per page (server-enforced default and cap)"),
        ("offset" = Option<usize>, Query, description = "Number of items to skip"),
    ),
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<Page<OAuth2ClientDto>>),
        (status_code = 400, description = "Bad request", body = ApiProblem),
    )
)]
pub async fn list_oauth2clients(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain_mut::<crate::server::ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    let (limit, offset) = crate::utils::page_params(req);
    if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
        match tenant.oauth2client_page(domain, limit, offset).await {
            Ok(page) => {
                // The redirect_uris deferred is unloaded on these rows, so
                // fetch the whole page's URIs in one indexed query instead
                // of one round-trip per client.
                let ids: Vec<String> = page.items.iter().map(|c| c.id.clone()).collect();
                let uris = match tenant.redirect_uris_for_clients(ids).await {
                    Ok(uris) => uris,
                    Err(e) => {
                        let err = ApiProblem::validation_error(&e.to_string());
                        res.status_code(StatusCode::BAD_REQUEST);
                        res.render(Json(err));
                        return;
                    }
                };
                let mut by_client: std::collections::HashMap<String, Vec<String>> =
                    std::collections::HashMap::new();
                for uri in uris {
                    by_client.entry(uri.client_id).or_default().push(uri.uri);
                }
                let dtos = page
                    .items
                    .into_iter()
                    .map(|c| {
                        let uris = by_client.remove(&c.id).unwrap_or_default();
                        OAuth2ClientDto::from_client(c, uris)
                    })
                    .collect();
                let page = Page {
                    items: dtos,
                    limit: page.limit,
                    offset: page.offset,
                    next_offset: page.next_offset,
                };
                res.status_code(StatusCode::OK);
                res.render(Json(ApiResponse::ok(page)));
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
    crate::audit::record_target(res, "client", &body.client_id);

    let state = depot.obtain_mut::<crate::server::ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
        match tenant.oauth2client_delete(domain, &body.client_id).await {
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

#[derive(Deserialize, ToSchema)]
pub struct RotateOauth2Client {
    pub client_id: String,
    /// The new plaintext secret. The previous hash is retained as a grace
    /// hash (G-96) until `grace_minutes` from now.
    pub new_secret: String,
     /// Grace window during which the previous secret still verifies, in
    /// minutes. Defaults to 5; `0` rotates with no grace.
     #[serde(default = "default_rotate_grace_minutes")]
    pub grace_minutes: u32,
}

fn default_rotate_grace_minutes() -> u32 {
    5
}

#[endpoint(
    summary = "Re-activate a soft-deleted OAuth2 client (G-96)",
    request_body = DeleteOauth2Client,
    responses(
         (status_code = 200, description = "Client re-activated", body = ApiResponse<String>),
         (status_code = 400, description = "Bad request", body = ApiProblem),
     )
)]
pub async fn reactivate_oauth2client(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let body = match crate::utils::extract::<DeleteOauth2Client>(req, None).await {
        Some(b) => b,
        None => {
            let err = ApiProblem::validation_error("Failed to parse request body");
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(err));
            return;
         }
     };
    crate::audit::record_target_detail(
        res,
        "client",
        &body.client_id,
        "reactivated",
     );

    let state = depot.obtain_mut::<crate::server::ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
        match tenant.oauth2client_reactivate(domain, &body.client_id).await {
            Ok(_) => {
                res.status_code(StatusCode::OK);
                res.render(Json(ApiResponse::ok("OAuth2 client re-activated")));
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
    summary = "Rotate a live OAuth2 client's secret with a grace window (G-96)",
    request_body = RotateOauth2Client,
    responses(
         (status_code = 200, description = "Secret rotated", body = ApiResponse<String>),
         (status_code = 400, description = "Bad request", body = ApiProblem),
     )
)]
pub async fn rotate_oauth2client_secret(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let body = match crate::utils::extract::<RotateOauth2Client>(req, None).await {
        Some(b) => b,
        None => {
            let err = ApiProblem::validation_error("Failed to parse request body");
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(err));
            return;
         }
     };
    crate::audit::record_target_detail(
        res,
        "client",
        &body.client_id,
        &format!("secret rotated, grace={}min", body.grace_minutes),
     );

    let state = depot.obtain_mut::<crate::server::ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
        match tenant
             .oauth2client_rotate_secret(domain, &body.client_id, &body.new_secret, i64::from(body.grace_minutes))
             .await
         {
            Ok(_) => {
                res.status_code(StatusCode::OK);
                res.render(Json(ApiResponse::ok("OAuth2 client secret rotated")));
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

#[cfg(test)]
#[allow(unused_imports)]
mod oauth2_client_lifecycle {
    use super::*;

     /// One tenant, one domain, an empty client table — the shape the
     /// `registration_management_round_trip_rfc7592` test in `oidc_ext` uses.
   async fn client_env() -> (
       crate::db::Storage,
       tempfile::TempDir,
       &'static str,
    ) {
         // Signing keys are encrypted at rest; the process-wide encryption
         // key is first-call-wins across test envs.
       let _ = crate::crypto::setup_encryption_key(&"0".repeat(64));
       let tmp = tempfile::tempdir().expect("tempdir");
       let storage = crate::db::Storage::init(tmp.path())
            .await
            .expect("storage init");
       storage
            .new_tenant("client-test")
            .await
            .expect("tenant");
       storage
            .add_domain("client.local", "client-test")
            .await
            .expect("domain");
       (storage, tmp, "client.local")
     }

     /// G-143: with the per-client `RedirectURI` keyspace two distinct
     /// clients may register the *same* callback, and a delete+recreate of one
     /// leaves the other's URI untouched.
    #[tokio::test]
   async fn per_client_keyspace_shares_a_callback() {
       let (storage, _tmp, domain) = client_env().await;
       let cb = "https://rp.example.com/callback";

          // All operations run on one tenant handle: the embedded backend keeps
          // a single connection, so the sequence is not re-borrowed per step.
          // A second client may bind the very same URI the first did (G-143).
       let mut t = storage.tenant_by_id("client-test").unwrap();
       t.oauth2client_create(
            domain,
              "client-a",
              "secret-a",
              &[cb],
              "authorization_code",
              "code",
              "client_secret_post",
              "openid",
            )
            .await
            .expect("create client-a");
       t.oauth2client_create(
            domain,
              "client-b",
              "secret-b",
              &[cb],
              "authorization_code",
              "code",
              "client_secret_post",
              "openid",
            )
            .await
            .expect("client-b shares the callback — G-143");

          let a = t.oauth2client_redirect_uris("client-a").await.expect("a uris");
          let b = t.oauth2client_redirect_uris("client-b").await.expect("b uris");
          assert_eq!(a.len(), 1, "client-a keeps its own URI row");
          assert_eq!(b.len(), 1, "client-b binds the same callback independently");
          assert_eq!(a[0].uri, cb);
          assert_eq!(b[0].uri, cb);
          assert_eq!(a[0].client_id, "client-a");
          assert_eq!(b[0].client_id, "client-b");

          // Soft-delete client-a, then re-create it (rotation). client-b's URI
          // row must be neither consumed nor squatted by client-a's dead slot.
          t.oauth2client_delete(domain, "client-a").await.expect("delete a");

       t.oauth2client_create(
            domain,
              "client-a",
              "secret-a-rotated",
              &[cb],
              "authorization_code",
              "code",
              "client_secret_post",
              "openid",
            )
            .await
            .expect("delete+recreate is idempotent over the dead slot");

          let b = t.oauth2client_redirect_uris("client-b").await.expect("b uris");
          assert_eq!(
              b.len(),
               1,
               "client-b's URI survived client-a's rotation untouched"
             );
          assert_eq!(b[0].client_id, "client-b");

              // A dead slot is re-usable while a live one still collides.
          let err = t
              .oauth2client_create(
                  domain,
                   "client-a",
                   "x",
                   &[cb],
                   "authorization_code",
                   "code",
                   "client_secret_post",
                   "openid",
                  )
              .await;
          assert!(
              err.is_err(),
               "a live client's id is still unique and collides fail-fast"
             );
          assert!(
              err.unwrap_err().to_string().contains("already exists"),
               "the collision reports 'already exists'"
             );
      }

      /// G-96: a soft-deleted client is brought back via
     /// `oauth2client_reactivate`, preserving its id and stored secret so the
     /// client's URIs and credentials keep working.
    #[tokio::test]
   async fn reactivation_restores_a_soft_deleted_client() {
       let (storage, _tmp, domain) = client_env().await;
       {
           let mut t = storage.tenant_by_id("client-test").unwrap();
           t.oauth2client_create(
                domain,
                 "client-a",
                 "top-secret",
                 &["https://rp.example.com/cb"],
                 "authorization_code",
                 "code",
                 "client_secret_post",
                 "openid",
              )
              .await
              .expect("create");
           t.oauth2client_delete(domain, "client-a")
                 .await
                 .expect("delete");

             // Soft-delete: the row is gone from the live view.
           assert!(
               t.oauth2client_get("client-a").await.is_err(),
               "a soft-deleted client reads as 'inactive'"
            );

           t.oauth2client_reactivate(domain, "client-a")
                 .await
                 .expect("reactivate");

             // Re-activated: the row is live and the *old* secret still
             // verifies.
           let c = t.oauth2client_get("client-a").await.expect("get");
           assert!(c.active, "client is active after reactivation");
           assert!(
               c.verify_secret_with_grace("top-secret").unwrap(),
               "the retained secret still authenticates after reactivation"
             );
       }
     }

     /// G-96: `oauth2client_rotate_secret` installs the new hash now and keeps
     /// the previous one verifying until `secret_grace_until` — a client that
     /// still presents its old secret is not bricked at the cutover. A
     /// `none`-auth client has no secret, so rotation is refused.
    #[tokio::test]
   async fn secret_rotation_keeps_the_old_one_until_grace_expires() {
       let (storage, _tmp, domain) = client_env().await;
       {
           let mut t = storage.tenant_by_id("client-test").unwrap();
           t.oauth2client_create(
                domain,
                 "client-a",
                 "secret-v1",
                 &["https://rp.example.com/cb"],
                 "authorization_code",
                 "code",
                 "client_secret_post",
                 "openid",
              )
              .await
              .expect("create v1");
           t.oauth2client_rotate_secret(domain, "client-a", "secret-v2", 5)
                 .await
                 .expect("rotate with a 5-min grace window");

             // Both the new secret and the (still-within-grace) old one verify.
           let c = t.oauth2client_get("client-a").await.expect("get");
           assert!(
               c.verify_secret_with_grace("secret-v2").unwrap(),
               "the new secret authenticates immediately"
             );
           assert!(
               c.verify_secret_with_grace("secret-v1").unwrap(),
               "the old secret still authenticates inside the grace window"
             );
           assert!(
               !c.verify_secret_with_grace("nope").unwrap_or(false),
               "an unrelated secret never verifies"
             );
           assert!(
               c.secret_grace_until.is_some(),
               "a grace deadline is recorded"
             );
       }

         // A `none`-auth client has no secret — rotation is refused, no-op.
        let (storage2, _t2, domain2) = client_env().await;
       {
           let mut t = storage2.tenant_by_id("client-test").unwrap();
           t.oauth2client_create(
                domain2,
                 "pub-client",
                 "",
                 &["https://rp.example.com/cb2"],
                 "authorization_code",
                 "code",
                 "none",
                 "openid",
              )
              .await
              .expect("create public client");
           let err = t
                 .oauth2client_rotate_secret(domain2, "pub-client", "secret-x", 5)
                 .await;
           assert!(
               err.is_err(),
               "a none-auth client has no secret to rotate"
             );
       }
     }
}
