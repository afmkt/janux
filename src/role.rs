use crate::db::JwtData;
use crate::db::Tenant;
use crate::policy::Policy;
use crate::user::User;
use crate::utils::{ApiProblem, ApiResponse};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use toasty::*;

/// The built-in role catalog (gaps.md ..).
///
/// Levels are the privilege ladder of the system: higher = more privileged.
/// They are fixed in code rather than config because the role-administration
/// gate (rules R1–R6) compares against them — they are the constitution, not
/// a tunable. Membership in the topmost role (`root`) and the policy set
/// attached to it can therefore never be altered through the API.
///
/// `scim` (60) is the machine-provisioning principal (SCIM 2.0): strictly
/// above `user` so the gate lets it deactivate/rename/delete regular
/// synced accounts, strictly below `admin` so a provisioning token can never
/// administer administrators or the admin surface itself.
pub const BUILTIN_ROLES: &[(&str, i64)] = &[
    ("root", 100),
    ("admin", 80),
    ("scim", 60),
    ("user", 40),
    ("guest", 20),
];

/// The level of a built-in role name, if `name` is a catalog member.
pub fn builtin_level(name: &str) -> Option<i64> {
    BUILTIN_ROLES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, l)| *l)
}

/// The principal performing a role-administration operation (gate).
#[derive(Debug, Clone)]
pub enum Caller {
    /// The seed / tenant-bootstrap path — the trust anchor, unrestricted.
    Bootstrap,
    /// An authenticated API caller; the role names come from the verified
    /// JWT and are resolved against the live Role table at decision time.
    Jwt(JwtData),
}

/// A role-administration failure the handlers render with a distinct HTTP
/// status (403/409) instead of the generic 400.
#[derive(Debug)]
pub enum AdminError {
    /// The level gate (rules R1–R6) rejected the operation, or a builtin
    /// role was targeted.
    Forbidden,
    /// `role_create` via the API named a role that already exists.
    Conflict(String),
}

impl std::fmt::Display for AdminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdminError::Forbidden => {
                write!(f, "role level is not below the caller's effective level")
            }
            AdminError::Conflict(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for AdminError {}

#[derive(Debug, toasty::Model, Clone)]
pub struct Role {
    #[key]
    pub id: String,

    /// Privilege rank used by the gate: a caller may only administer
    /// roles whose level is strictly below its own effective level.
    pub level: i64,

    /// Catalog member (seeded): name and level are immutable and the role
    /// cannot be deleted through the API.
    pub builtin: bool,

    #[auto]
    pub created_at: jiff::Timestamp,
    #[auto]
    pub updated_at: jiff::Timestamp,

    #[has_many]
    pub userroles: Deferred<Vec<UserRole>>,

    #[has_many]
    pub policies: Deferred<Vec<Policy>>,
}

#[derive(Debug, toasty::Model, Clone)]
pub struct UserRole {
    #[key]
    #[index]
    pub user_id: uuid::Uuid,
    #[key]
    #[index]
    pub role_id: String,
    #[auto]
    pub created_at: jiff::Timestamp,
    #[auto]
    pub updated_at: jiff::Timestamp,

    #[belongs_to(key = user_id, references = id)]
    pub user: Deferred<User>,

    #[belongs_to(key = role_id, references = id)]
    pub role: Deferred<Role>,
}

impl Tenant {
    /// The highest level among the caller's resolvable roles.
    /// `Bootstrap` is unrestricted;
    /// role names that do not resolve contribute nothing, and a caller whose
    /// roles resolve to nothing has no level at all — default-deny, so it
    /// may administer nothing.
    pub async fn effective_level(&mut self, caller: &Caller) -> Option<i64> {
        match caller {
            Caller::Bootstrap => Some(i64::MAX),
            Caller::Jwt(data) => {
                let mut max: Option<i64> = None;
                for name in &data.roles {
                    if let Ok(role) = self.role(name).await {
                        max = Some(max.map_or(role.level, |m| m.max(role.level)));
                    }
                }
                max
            }
        }
    }

    /// The single gate for rules R1/R2/R4/R5/R6: `Ok` iff the caller is
    /// `Bootstrap` or strictly outranks `role`. Every role mutation funnels
    /// through this one function.
    pub async fn require_below(&mut self, caller: &Caller, role: &Role) -> anyhow::Result<()> {
        self.require_level(caller, role.level).await
    }

    /// The gate expressed against a bare level (rule R3, role creation,
    /// where the role does not exist yet).
    pub async fn require_level(&mut self, caller: &Caller, level: i64) -> anyhow::Result<()> {
        match self.effective_level(caller).await {
            Some(l) if l > level => Ok(()),
            _ => Err(AdminError::Forbidden.into()),
        }
    }

    /// The effective level of a stored user: the highest level among
    /// their role assignments, resolved against the live Role table (not a
    /// JWT snapshot). A user with no resolvable roles has no level.
    pub async fn user_effective_level(&mut self, user_id: uuid::Uuid) -> Option<i64> {
        match self.user_roles(user_id).await {
            Ok(roles) => roles.into_iter().map(|r| r.level).max(),
            Err(_) => None,
        }
    }

    /// The gate for user lifecycle mutations (delete / activate /
    /// deactivate): `Ok` iff the caller is `Bootstrap` or strictly outranks
    /// the target user's effective level. A target with no level is
    /// outranked by any ranked caller; a caller with no level may
    /// administer no one (default-deny). Peers are refused — the comparison
    /// is strict, mirroring `require_level`, so an admin cannot neutralize
    /// a peer or a superior (e.g. tenant admin vs. `root`).
    pub async fn require_above_user(
        &mut self,
        caller: &Caller,
        user_id: uuid::Uuid,
    ) -> anyhow::Result<()> {
        if matches!(caller, Caller::Bootstrap) {
            return Ok(());
        }
        let caller_level = self.effective_level(caller).await;
        let target_level = self.user_effective_level(user_id).await;
        match (caller_level, target_level) {
            (Some(l), Some(t)) if l > t => Ok(()),
            (Some(_), None) => Ok(()),
            _ => Err(AdminError::Forbidden.into()),
        }
    }

    // role CRUD
    pub async fn all_roles(&mut self) -> Result<Vec<Role>> {
        Role::all().exec(&mut self.database).await
    }

    /// Create a role.
    ///
    /// `Bootstrap` keeps the idempotent seed semantics: catalog names are
    /// created with their fixed level and `builtin = true`; an existing role
    /// is returned unchanged. API callers are bounded by rule R3 — builtin
    /// names are reserved, existing names conflict, and the level must lie
    /// in `[0, eff(caller))`, so every API-created role is born strictly
    /// below its creator.
    pub async fn role_create(
        &mut self,
        caller: &Caller,
        name: &str,
        level: i64,
    ) -> anyhow::Result<Role> {
        if let Some(catalog_level) = builtin_level(name) {
            if !matches!(caller, Caller::Bootstrap) {
                return Err(AdminError::Forbidden.into());
            }
            if let Ok(existing) = self.role(name).await {
                return Ok(existing);
            }
            return toasty::create!(Role {
                id: name,
                level: catalog_level,
                builtin: true,
            })
            .exec(&mut self.database)
            .await
            .map_err(Into::into);
        }
        if let Ok(existing) = self.role(name).await {
            return match caller {
                Caller::Bootstrap => Ok(existing),
                Caller::Jwt(_) => {
                    Err(AdminError::Conflict(format!("role '{name}' already exists")).into())
                }
            };
        }
        if !matches!(caller, Caller::Bootstrap) {
            anyhow::ensure!(level >= 0, "role level must be >= 0");
            self.require_level(caller, level).await?;
        }
        toasty::create!(Role {
            id: name,
            level,
            builtin: false,
        })
        .exec(&mut self.database)
        .await
        .map_err(Into::into)
    }

    /// Delete a role. Builtin roles are undeletable regardless of caller;
    /// custom roles require the caller to strictly outrank them (rule R4).
    pub async fn role_delete(&mut self, caller: &Caller, name: &str) -> anyhow::Result<()> {
        let role = self.role(name).await?;
        if role.builtin {
            return Err(AdminError::Forbidden.into());
        }
        self.require_below(caller, &role).await?;
        Role::delete_by_id(&mut self.database, name)
            .await
            .map(|_| ())
            .map_err(Into::into)
    }

    pub async fn role(&mut self, name: &str) -> Result<Role> {
        Role::get_by_id(&mut self.database, name).await
    }
}

#[derive(Serialize, ToSchema)]
struct RoleEntry {
    name: String,
    level: i64,
    builtin: bool,
}

#[endpoint(
    summary = "List all roles in a tenant",
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<Vec<RoleEntry>>),
        (status_code = 400, description = "Bad request", body = ApiProblem),
    )
)]
pub async fn all_roles(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    if let Some(mut tenant) = state.storage.tenant_by_domain(domain)
        && let Ok(data) = tenant.all_roles().await
    {
        res.status_code(StatusCode::OK);
        res.render(Json(ApiResponse::ok(
            data.iter()
                .map(|r| RoleEntry {
                    name: r.id.clone(),
                    level: r.level,
                    builtin: r.builtin,
                })
                .collect::<Vec<_>>(),
        )));
        return;
    }

    let err = ApiProblem::validation_error("Failed to parse request body");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err))
}

#[derive(Serialize, Deserialize, ToSchema)]
struct AddRole {
    name: String,
    /// Privilege level of the new role; must lie in `[0, caller level)`.
    level: i64,
}

#[endpoint(
    summary = "Add role to tenant",
    request_body = AddRole,
    responses(
        (status_code = 200, description = "Role created successfully", body = ApiResponse<()>),
        (status_code = 400, description = "Bad request", body = ApiProblem),
        (status_code = 403, description = "Level gate refused the role", body = ApiProblem),
        (status_code = 409, description = "Role name already exists", body = ApiProblem)
    )
)]
pub async fn add_role(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    if let Some(body) = crate::utils::extract::<AddRole>(req, None).await {
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
            match tenant.role_create(&caller, &body.name, body.level).await {
                Ok(_) => {
                    let resp = ApiResponse::ok(());
                    res.status_code(StatusCode::OK);
                    res.render(Json(resp));
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

#[derive(Deserialize, ToSchema)]
pub struct DeleteRole {
    pub name: String,
}

#[endpoint(
    summary = "Remove a role from tenant",
    request_body = DeleteRole,
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<()>),
        (status_code = 400, description = "Bad request", body = ApiProblem),
        (status_code = 403, description = "Level gate refused the role", body = ApiProblem)
    )
)]
pub async fn delete_role(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    if let Some(body) = crate::utils::extract::<DeleteRole>(req, None).await {
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
            match tenant.role_delete(&caller, &body.name).await {
                Ok(_) => {
                    let resp = ApiResponse::ok(());
                    res.status_code(StatusCode::OK);
                    res.render(Json(resp));
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
