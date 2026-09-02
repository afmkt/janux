//! Policy engine for Role-Based Access Control (RBAC).
//!
//! This module implements a tenant-scoped, role-based authorization system.
//! Policies are the atomic unit of access control: each policy binds a
//! *domain*, an HTTP *action*, a *resource* path, a *role*, an optional
//! *source* and *target* resolver, an MFA flag, and an allow/deny verdict.
//!
//! ## Core concepts
//!
//! - **Domain** — the tenant-scoped auth realm (the request `host`). A policy
//! only applies when the request domain matches `Policy::domain_id`.
//! - **Role** — assigned to a user via `UserRole`. A user's roles are embedded
//! in the JWT (`JwtData::roles`); at verify time the engine iterates every
//! role and collects matching policies from the in-memory `PolicyCache`.
//! - **Source** — *who or what the request is acting as*. Resolved from the
//! JWT (`SourceResolver::User` → the caller's username, `SourceResolver::Domain`
//! → the caller's domain). A `Nothing` source means the policy applies
//! independently of identity.
//! - **Target** — *what the request is acting on*. Resolved from the request
//! path, query string, or headers. A `Nothing` target means the policy
//! applies to the resource as a whole.
//! - **Resource** — a path template (e.g. `"users/{id}/posts"`) stored as
//! segments. When neither source nor target is set, the request path must
//! match the template exactly. When a target is configured, template
//! segments wrapped in `{ braces }` are captured as named parameters.
//! - **MFA** — when set, the caller must have authenticated with MFA for the
//! policy to permit access; otherwise the engine signals `expect_mfa`.
//!
//! ## Evaluation algorithm
//!
//! 1. The request domain, HTTP method, and the caller's roles are compared
//! against each cached `Policy`.
//! 2. `Policy::can_access` returns `None` when the request doesn't match the
//! policy's domain/action/resource shape (the policy is skipped). It
//! returns `Some(CanAccess)` when the policy is *applicable*, carrying the
//! allow/deny verdict and any MFA requirement.
//! 3. In [`crate::utils::validate_token`] applicable policies are iterated per
//! role: the first explicit *deny* short-circuits to deny, the first
//! explicit *allow* sets the permitted flag, and `expect_mfa` is OR-ed
//! across all matched policies.
//!
//! ## Caching
//!
//! Policies are loaded once per tenant into a [`PolicyCache`]
//! (`DashMap<domain, DashMap<role, Vec<Policy>>>`) at tenant startup
//! ([`Tenant::all_policy_entries`]). Create and delete operations keep the
//! cache in sync so that [`crate::utils::validate_token`] can evaluate without
//! a DB round-trip on the hot path.

use crate::utils::{ApiProblem, ApiResponse};

use crate::db::HttpMethod;
use crate::db::JwtData;
use crate::db::PolicyCache;
use crate::db::Tenant;
use crate::domain::Domain;
use crate::role::Role;
use anyhow::Result;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;

use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use toasty::*;

/// How the *source* (the identity acting in the request) is resolved from the
/// authenticated JWT. Used by a [`Policy`] to decide whether the caller itself
/// is the target of the rule.
///
/// `Nothing` means the policy is identity-independent (it applies to whoever
/// holds the role). `User`, `Domain`, and `Roles` pull the corresponding field
/// from the JWT to be compared against the resolved target.
#[derive(Debug, PartialEq, toasty::Embed, Serialize, Deserialize, ToSchema, Clone)]
pub enum SourceResolver {
    Nothing,
    User,
    Domain,
    Role,
}

/// A resolved source value, produced by [`Policy::resolve_source`]. The variant
/// tells the caller whether to compare a username, domain, or role set
/// against the resolved target.
pub enum Source {
    User(String),
    Domain(String),
    Role(String),
}

/// How the *target* (the resource being accessed) is extracted from the
/// incoming request so it can be compared against the resolved source.
///
/// - `Nothing` — no target extraction; matching is purely path-based.
/// - `FromPath` — capture a named path parameter (e.g. `{user}`) from the
/// request path, matched against the policy's `resource` template.
/// - `FromQuery` — read the target from a named query-string parameter.
/// - `FromHeader` — read the target from a request header (case-insensitive
/// lookup).
#[derive(Debug, PartialEq, toasty::Embed, Serialize, Deserialize, ToSchema, Clone)]
pub enum TargetResolver {
    Nothing,
    FromPath { pname: String },
    FromQuery { qname: String },
    FromHeader { hname: String },
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct PolicyDTO {
    pub domain: String,
    pub resource: String,
    pub action: Option<HttpMethod>,
    pub role: String,
    pub source: SourceResolver,
    pub target: TargetResolver,
    pub mfa: bool,
    pub allowed: bool,
}
impl PolicyDTO {
    // pub async fn from_policy(policy: &Policy) -> Self {
    // PolicyDTO {
    // domain: policy.domain_id.clone(),
    // resource: policy.resource.join("/"),
    // action: policy.action.clone(),
    // role: policy.role_id.clone(),
    // mfa: policy.mfa,
    // allowed: policy.allowed,
    // source: policy.source.clone(),
    // target: policy.target.clone(),
    // }
    // }
    pub async fn save(&self, tenant: &mut Tenant) -> Result<()> {
        tenant
            .policy_create(
                &crate::role::Caller::Bootstrap,
                &self.domain,
                self.action.clone(),
                &self.resource,
                &self.role,
                &self.source,
                &self.target,
                self.mfa,
                self.allowed,
            )
            .await
            .map(|_| ())
    }
}
/// A policy rule that binds a role, domain, HTTP action, and resource path to
/// an allow/deny verdict, optionally gated on source/target identity matching
/// and MFA.
///
/// # Typical policy shapes
///
/// | Source | Target | Use case |
/// |--------|--------|----------|
/// | `Nothing` | `Nothing` | Broad, identity-independent rules (e.g. "any user can list `/posts`") |
/// | `User` | `FromPath { pname }` | Self-scoped access (e.g. "a user can read `/users/{username}` only for themselves") |
/// | `User` | `FromQuery { qname }` | Self-scoped via query param (e.g. `?owner=alice`) |
/// | `User` | `FromHeader { hname }` | Self-scoped via custom header (e.g. `X-User-Id`) |
/// | `Domain` | `FromHeader` | Domain-scoped access where the target is a header like `X-Tenant-Id` |

///
/// # Unique constraint
///
/// The unique key `(resource, domain_id, role_id, action)` ensures there is at
/// most one policy per role/domain/resource/method combination, so evaluation
/// results are deterministic and order-independent (denies always win).
///
/// See [`Policy::can_access`] for concrete evaluation examples.
#[derive(Debug, toasty::Model, Clone)]
#[unique(resource, domain_id, role_id, action)]
pub struct Policy {
    #[key]
    #[auto]
    pub id: uuid::Uuid,

    /// Tenant-scoped domain this policy applies to. Must equal the request's
    /// `Host` header (and the JWT issuer domain) for the policy to match.
    #[index]
    pub domain_id: String,
    /// HTTP method the policy governs. `None` means the rule applies to all
    /// methods for the given resource.
    pub action: Option<HttpMethod>,
    /// Resource path template as segments, e.g. `["users", "{id}"]` for the
    /// path `/users/{id}`. Matched against the request path (or a captured
    /// parameter) by [`Policy::can_access`].
    pub resource: Vec<String>,
    /// Role this policy grants/denies access to.
    #[index]
    pub role_id: String,
    /// Where the *source* identity is read from (JWT user, domain, roles, or
    /// nothing).
    pub source: SourceResolver,
    /// Where the *target* resource identity is read from (path param, query,
    /// header, or nothing).
    pub target: TargetResolver,
    /// When `true`, the caller must have authenticated with MFA for this
    /// policy to permit access. See [`Policy::can_access`].
    pub mfa: bool,
    /// The verdict: `true` to allow, `false` to deny. A matching deny always
    /// overrides any allow across all of the caller's roles.
    pub allowed: bool,

    #[auto]
    pub created_at: jiff::Timestamp,
    #[auto]
    pub updated_at: jiff::Timestamp,

    #[belongs_to(key = domain_id, references = id)]
    pub domain: Deferred<Domain>,

    #[belongs_to(key = role_id, references = id)]
    pub role: Deferred<Role>,
}

/// Outcome of evaluating a single applicable policy via [`Policy::can_access`].
///
/// `can_access` is the allow/deny verdict for *this* policy. `expect_mfa` is
/// `true` when the policy requires MFA but the caller has not yet satisfied
/// that requirement — the caller is asked to re-authenticate with MFA rather
/// than being outright denied.
pub struct CanAccess {
    pub can_access: bool,
    pub expect_mfa: bool,
}

impl Policy {
    /// Evaluate this policy against a single request.
    ///
    /// Returns `None` when the policy does **not apply** to this request
    /// (domain, action, or resource shape don't match) — the engine skips it
    /// and continues checking other policies. Returns `Some(CanAccess)` when
    /// the policy *is* applicable, carrying the allow/deny verdict and MFA
    /// status.
    ///
    /// # Matching rules
    ///
    /// 1. The request `domain` must equal both the JWT's domain and
    /// `self.domain_id`, and the HTTP `act` must equal `self.action` (or
    /// `self.action` is `None`, matching any method).
    /// 2. If both [`SourceResolver`] and [`TargetResolver`] are `Nothing`,
    /// the request `path` segments must match `self.resource` exactly.
    /// 3. Otherwise the source is resolved from the JWT and the target from
    /// the path/query/headers; the request matches only when source and
    /// target denote the same identity (e.g. a user accessing their own
    /// record).
    /// 4. When [`mfa`](Self::mfa) is set the caller must have authenticated
    /// with MFA (TOTP + at least one other factor). If MFA is missing the
    /// result is denied with `expect_mfa = true` so the caller can
    /// re-authenticate; otherwise the `allowed` verdict applies.
    ///
    // Examples are in tests/unit/policy_unit.rs
    pub fn can_access(
        &self,
        act: &HttpMethod,
        domain: &str,
        jwt: &JwtData,
        path: &Vec<&str>,
        query: &HashMap<String, String>,
        header: &HashMap<String, String>,
    ) -> Option<CanAccess> {
        let matched: bool = if domain == jwt.domain
            && domain == self.domain_id
            && (Some(act.clone()) == self.action || self.action.is_none())
        {
            if self.source == SourceResolver::Nothing && self.target == TargetResolver::Nothing {
                // path match exactly
                path.iter().map(|s| s.to_string()).collect::<Vec<String>>() == self.resource
            } else {
                let s = self.resolve_source(jwt);
                let t = self.resolve_target(path, query, header);
                match s {
                    None => t.is_none(),
                    Some(Source::User(name)) => t.map_or(false, |target_name| target_name == name),
                    Some(Source::Domain(name)) => {
                        t.map_or(false, |target_domain| target_domain == name)
                    }
                    Some(Source::Role(name)) => t.map_or(false, |target_role| target_role == name),
                }
            }
        } else {
            false
        };
        if !matched {
            return None;
        } else {
            if !self.mfa {
                return Some(CanAccess {
                    can_access: self.allowed,
                    expect_mfa: self.mfa,
                });
            } else {
                let mfa = jwt.mfa.contains("totp") && jwt.mfa.len() > 1;
                return Some(CanAccess {
                    can_access: mfa && self.allowed,
                    expect_mfa: !mfa,
                });
            }
        }
    }
    /// Resolve the *source* identity for this policy from the JWT, according to
    /// the configured [`SourceResolver`].
    ///
    /// Returns `None` when the resolver is `Nothing` (the policy is not
    /// identity-scoped). Otherwise returns the caller's username, domain

    pub fn resolve_source(&self, jwt: &JwtData) -> Option<Source> {
        match self.source {
            SourceResolver::Nothing => None,
            SourceResolver::Domain => Some(Source::Domain(jwt.domain.clone())),
            SourceResolver::User => Some(Source::User(jwt.user.clone())),
            SourceResolver::Role => Some(Source::Role(self.role_id.clone())),
        }
    }
    /// Resolve the *target* identity the caller is acting upon, extracted from
    /// the request path, query string, or headers.
    ///
    /// Returns `None` when the resolver is `Nothing`. For `FromPath` the
    /// `resource` template is matched segment-by-segment against `path`;
    /// segments wrapped in `{ braces }` are captured as named parameters and
    /// the one named by `pname` is returned. Non-template segments must match
    /// exactly or the whole policy is skipped.
    ///

    pub fn resolve_target(
        &self,
        path: &Vec<&str>,
        query: &HashMap<String, String>,
        header: &HashMap<String, String>,
    ) -> Option<String> {
        match &self.target {
            TargetResolver::Nothing => None,
            TargetResolver::FromPath { pname } => {
                let mut mapping = HashMap::new();
                if self.resource.len() == path.len() {
                    for (pat_seg, act_seg) in self.resource.iter().zip(path.iter()) {
                        if pat_seg.starts_with('{') && pat_seg.ends_with('}') {
                            // This segment is a named param — capture it
                            let name = &pat_seg[1..pat_seg.len() - 1];
                            mapping.insert(name.to_string(), (*act_seg).to_string());
                        } else if pat_seg != act_seg {
                            return None; // No match                                                                                                                                                
                        }
                    }
                    return mapping.get(pname).map(|a| a.clone());
                }
                return None;
            }
            TargetResolver::FromQuery { qname } => query.get(qname).map(|a| a.clone()),
            TargetResolver::FromHeader { hname } => {
                header.get(&hname.to_lowercase()).map(|a| a.clone())
            }
        }
    }
}

impl Tenant {
    /// Load *all* policies from the database into a fresh [`PolicyCache`].
    ///
    /// The cache is organized as `domain → role → Vec<Policy>` so that
    /// [`validate_token`](crate::utils::validate_token) can look up
    /// candidate policies with at most two hash-map probes and no DB query.
    /// Called once when a tenant is first loaded.
    pub async fn all_policy_entries(&mut self) -> Result<PolicyCache> {
        let policies = Policy::all()
            .exec(&mut self.database)
            .await
            .map_err(Into::<anyhow::Error>::into)?;

        let ret = DashMap::new();
        for p in policies {
            ret.entry(p.domain_id.clone())
                .or_insert_with(DashMap::new)
                .entry(p.role_id.clone())
                .or_insert_with(Vec::new)
                .push(p.clone());
        }
        Ok(ret)
    }
    /// Fetch all policies for this tenant's database (no caching).
    pub async fn all_policies(&mut self) -> Result<Vec<Policy>> {
        Policy::all()
            .exec(&mut self.database)
            .await
            .map_err(Into::<anyhow::Error>::into)
    }

    /// Create a new policy record and insert it into the in-memory
    /// [`PolicyCache`], mirroring the DB row.
    ///
    /// `resource` is a slash-separated path template (e.g. `"users/{id}"`).
    ///
    /// gate (rule R5): API callers may only attach policies to roles
    /// strictly below their own effective level — a role can never expand
    /// its own permission set (or a peer's / superior's).
    pub async fn policy_create(
        &mut self,
        caller: &crate::role::Caller,
        domain: &str,
        action: Option<HttpMethod>,
        resource: &str,
        role_name: &str,
        source: &SourceResolver,
        target: &TargetResolver,
        mfa: bool,
        allowed: bool,
    ) -> Result<Policy> {
        let resource_seg: Vec<&str> = resource.split("/").collect();
        let role = self.role(role_name).await?;
        self.require_below(caller, &role).await?;
        let ret = toasty::create!(Policy {
            domain_id: domain.to_string(),
            action,
            mfa,
            resource: resource_seg,
            role_id: role.id,
            source,
            target,
            allowed,
        })
        .exec(&mut self.database)
        .await
        .map_err(Into::<anyhow::Error>::into)?;

        self.policies
            .entry(domain.to_string())
            .or_insert_with(DashMap::new)
            .entry(ret.role_id.clone())
            .or_insert_with(Vec::new)
            .push(ret.clone());

        Ok(ret)
    }
    /// Delete the policy matching `(domain, resource, action, role)` from the
    /// database and remove it from the in-memory [`PolicyCache`], keeping the
    /// cache consistent with the DB.
    ///
    /// gate (rule R6): symmetric to [`Tenant::policy_create`] — detaching
    /// policies is bounded by the same level test, so a role cannot strip the
    /// constraints of a peer's or superior's permission set either.
    pub async fn policy_delete(
        &mut self,
        caller: &crate::role::Caller,
        domain: &str,
        resource: &str,
        action: Option<HttpMethod>,
        role_name: &str,
    ) -> Result<()> {
        let resource_seg: Vec<String> = resource.split("/").map(|s| s.to_string()).collect();
        let role = self.role(role_name).await?;
        self.require_below(caller, &role).await?;

        // toasty cannot filter on the list-typed `resource` column, so
        // select the (domain, role) candidates and match in Rust, deleting
        // by primary key.
        let candidates = Policy::filter(
            Policy::fields()
                .domain_id()
                .eq(domain)
                .and(Policy::fields().role_id().eq(&role.id)),
        )
        .exec(&mut self.database)
        .await
        .map_err(Into::<anyhow::Error>::into)?;
        for p in candidates {
            if p.resource == resource_seg && p.action == action {
                Policy::delete_by_id(&mut self.database, p.id)
                    .await
                    .map_err(Into::<anyhow::Error>::into)?;
            }
        }

        if let Entry::Occupied(mut domain_entry) = self.policies.entry(domain.to_string()) {
            let role_map = domain_entry.get_mut();
            if let Entry::Occupied(mut ps) = role_map.entry(role.id) {
                // Evict exactly the deleted policy. (The former retain matched
                // `action` only and silently evicted unrelated policies of
                // the same role/action with different resources.)
                ps.get_mut()
                    .retain(|p| !(p.action == action && p.resource == resource_seg));

                // Optional: Clean up empty maps to save memory
                if ps.get().is_empty() {
                    ps.remove();
                }
            }
        }
        Ok(())
    }
}

/// Wire-format representation of a [`Policy`] for HTTP responses and request
/// bodies. `resource` is a slash-joined path template (e.g. `"users/{id}"`)
/// rather than the segmented `Vec<String>` stored on the model.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
struct PolicyEntry {
    pub id: Option<uuid::Uuid>,
    pub resource: String,
    pub domain: String,
    pub role: String,
    pub action: Option<HttpMethod>,
    pub source: SourceResolver,
    pub target: TargetResolver,
    pub mfa: bool,
    pub allowed: bool,
}

/// List all policies belonging to the tenant identified by the request `Host`.
///
/// Policies are read directly from the DB (not the cache) so the caller sees
/// the latest configuration. The `resource` field is flattened back from its
/// segmented storage form into a slash-joined path string.
#[endpoint(
    summary = "List all policies in a tenant",
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<Vec<PolicyEntry>>),
        (status_code = 400, description = "Bad request", body = ApiProblem),
    )
)]
pub async fn all_policies(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    if let Some(mut tenant) = state.storage.tenant_by_domain(domain) {
        if let Ok(data) = tenant.all_policies().await {
            let items: Vec<PolicyEntry> = data
                .iter()
                .map(|p| PolicyEntry {
                    id: Some(p.id),
                    resource: p.resource.join("/"),
                    domain: p.domain_id.clone(),
                    role: p.role_id.clone(),
                    action: p.action.clone(),
                    source: p.source.clone(),
                    target: p.target.clone(),
                    mfa: p.mfa,
                    allowed: p.allowed,
                })
                .collect();
            res.status_code(StatusCode::OK);
            res.render(Json(ApiResponse::ok(items)));
            return;
        }
    }
    let err = ApiProblem::validation_error("Failed to parse request body");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err))
}

/// Add a new policy to the tenant identified by the request `Host`.
///
/// The policy's domain is always the domain resolved from the request
/// `Host` — any `domain` supplied in the body is ignored, so a
/// policy-admin of one domain cannot write policies naming another domain
/// served by the same tenant.
///
/// The created policy is inserted into both the database and the tenant's
/// in-memory [`PolicyCache`] so it takes effect immediately for subsequent
/// JWT verification.
#[endpoint(
    summary = "Add policy to tenant",
    request_body = PolicyEntry,
    responses(
        (status_code = 200, description = "Policy created successfully", body = ApiResponse<()>),
        (status_code = 400, description = "Bad request", body = ApiProblem),
        (status_code = 403, description = "Level gate refused the role", body = ApiProblem)
    )
)]
pub async fn add_policy(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    if let Some(body) = crate::utils::extract::<PolicyEntry>(req, None).await {
        let caller = match crate::utils::caller_from_depot(depot) {
            Some(c) => c,
            None => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(ApiProblem::unauthorized()));
                return;
            }
        };
        let state = depot.obtain_mut::<crate::server::ServerState>().unwrap();
        let domain = crate::utils::get_domain(req, state).unwrap_or("");
        if let Some(mut tenant) = state.storage.tenant_by_domain(domain) {
            match tenant
                .policy_create(
                    &caller,
                    domain,
                    body.action,
                    &body.resource,
                    &body.role,
                    &body.source,
                    &body.target,
                    body.mfa,
                    body.allowed,
                )
                .await
            {
                Ok(_) => {
                    res.status_code(StatusCode::OK);
                    res.render(Json(ApiResponse::ok(())));
                }
                Err(e) => crate::utils::render_admin_error(res, e),
            }
            return;
        }
    };
    let err = ApiProblem::validation_error("Failed to parse request body");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err))
}

/// Request body for [`delete_policy`] — identifies a policy by its
/// resource template, HTTP method, and role. The domain is always the one
/// resolved from the request `Host`; a `domain` field present in
/// the body is ignored.
#[derive(Deserialize, ToSchema)]
pub struct DeletePolicy {
    pub resource: String,
    pub action: Option<HttpMethod>,
    pub role: String,
}

/// Remove the policy matching the request body from the tenant identified by
/// the request `Host`.
///
/// The policy is matched within the domain resolved from the request
/// `Host`, never a client-supplied domain string.
///
/// Deletes from the DB and evicts from the in-memory cache, keeping both
/// in sync.
#[endpoint(
    summary = "Remove a policy from tenant",
    request_body = DeletePolicy,
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<()>),
        (status_code = 400, description = "Bad request", body = ApiProblem),
        (status_code = 403, description = "Level gate refused the role", body = ApiProblem)
    )
)]
pub async fn delete_policy(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    if let Some(body) = crate::utils::extract::<DeletePolicy>(req, None).await {
        let caller = match crate::utils::caller_from_depot(depot) {
            Some(c) => c,
            None => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(ApiProblem::unauthorized()));
                return;
            }
        };
        let state = depot.obtain_mut::<crate::server::ServerState>().unwrap();
        let domain = crate::utils::get_domain(req, state).unwrap_or("");
        if let Some(mut tenant) = state.storage.tenant_by_domain(domain) {
            match tenant
                .policy_delete(&caller, domain, &body.resource, body.action, &body.role)
                .await
            {
                Ok(_) => {
                    res.status_code(StatusCode::OK);
                    res.render(Json(ApiResponse::ok(())));
                }
                Err(e) => crate::utils::render_admin_error(res, e),
            }
            return;
        }
    }
    let err = ApiProblem::validation_error("Failed to parse request body");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err))
}
