use crate::db::Tenant;
use crate::email::Email;

use crate::otp::OTP;

use crate::passkey::Passkey;

use crate::role::Role;
use crate::role::UserRole;

use crate::social::OAuth2;
use crate::totp::Totp;
use anyhow::Result;

use crate::utils::{ApiProblem, ApiResponse, extract};

use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use toasty::Deferred;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UserDTO {
    pub id: String,
    pub active: bool,
    pub roles: Vec<String>,
}

impl UserDTO {
    // pub fn from_user(user: &User) -> Self {
    // UserDTO {
    // id: user.id.clone(),
    // active: user.active,
    // roles: user.roles(),
    // }
    // }
    pub async fn save(&self, tenant: &mut Tenant) -> Result<()> {
        let mut user = tenant.user(&self.id).await;
        if user.is_err() {
            user = tenant.user_create(&self.id).await;
        }
        if let Ok(user) = user {
            if user.active != self.active {
                if self.active {
                    tenant
                        .user_activate(&crate::role::Caller::Bootstrap, &self.id)
                        .await?;
                } else {
                    tenant
                        .user_deactivate(&crate::role::Caller::Bootstrap, &self.id)
                        .await?;
                }
            }
            // Seeding must be idempotent across restarts: query the roles
            // that actually exist instead of trusting the deferred relation,
            // which is unloaded during the seed phase and would read empty
            // for a pre-existing user, re-inserting duplicates against the
            // (user_id, role_id) UNIQUE constraint.
            let current_roles: Vec<String> = tenant
                .user_roles(user.id)
                .await?
                .into_iter()
                .map(|r| r.id)
                .collect();
            if current_roles != self.roles {
                for role in &self.roles {
                    if !current_roles.contains(role) {
                        tenant
                            .user_add_role(&crate::role::Caller::Bootstrap, &self.id, role)
                            .await?;
                    }
                }
                for role in &current_roles {
                    if !self.roles.contains(role) {
                        tenant
                            .user_del_role(&crate::role::Caller::Bootstrap, &self.id, role)
                            .await?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, toasty::Model, Clone)]
pub struct User {
    /// Opaque surrogate key (UUIDv7, auto-assigned). SCIM `id`, JWT `sub`,
    /// and every FK reference this — never the mutable `name`.
    #[key]
    #[auto]
    pub id: uuid::Uuid,

    /// The login name (SCIM `userName`): unique and mutable; lookups at the
    /// wire boundary resolve name -> id.
    #[unique]
    pub name: String,

    /// IdP-side join key (SCIM `externalId`): the identifier the
    /// provisioning system uses for this account. Unique so a sync source
    /// cannot bind two accounts to the same external identity; NULL for
    /// accounts not provisioned externally.
    #[unique]
    #[default(None)]
    pub external_id: Option<String>,

    pub active: bool,

    #[auto]
    pub created_at: jiff::Timestamp,
    #[auto]
    pub updated_at: jiff::Timestamp,

    #[has_many]
    pub userroles: Deferred<Vec<UserRole>>,

    #[has_many]
    pub passkey: Deferred<Vec<Passkey>>,
    #[has_many]
    pub oauth2: Deferred<Vec<OAuth2>>,
    #[has_many]
    pub email: Deferred<Vec<Email>>,
    #[has_many]
    pub otp: Deferred<Vec<OTP>>,

    #[has_many]
    pub totp: Deferred<Vec<Totp>>,
}

impl User {
    pub fn roles(&self) -> Vec<String> {
        self.userroles
            .clone()
            .into_inner()
            .iter()
            .map(|ur| ur.role_id.clone())
            .collect::<Vec<_>>()
    }
}

impl Tenant {
    // user CRUD
    pub async fn user_create(&mut self, name: &str) -> Result<User> {
        toasty::create!(User {
            name: name,
            active: true
        })
        .exec(&mut self.database)
        .await
        .map_err(Into::into)
    }

    /// Wire-boundary lookup: login name (SCIM `userName`) -> user.
    pub async fn user(&mut self, name: &str) -> Result<User> {
        let mut rows: Vec<User> = User::filter(User::fields().name().eq(name))
            .exec(&mut self.database)
            .await
            .map_err(anyhow::Error::from)?;
        rows.pop()
            .ok_or_else(|| anyhow::anyhow!("user '{name}' not found"))
    }

    /// Surrogate-key lookup (JWT `sub` / SCIM `id` / FK traversal).
    pub async fn user_by_id(&mut self, id: uuid::Uuid) -> Result<User> {
        User::get_by_id(&mut self.database, id)
            .await
            .map_err(Into::into)
    }

    /// gate: the caller must be `Bootstrap` or strictly outrank the
    /// target user (see `require_above_user`). Seed/system paths pass
    /// `Caller::Bootstrap`.
    pub async fn user_activate(&mut self, caller: &crate::role::Caller, name: &str) -> Result<()> {
        let user = self.user(name).await?;
        self.require_above_user(caller, user.id).await?;
        User::update_by_id(user.id)
            .active(true)
            .exec(&mut self.database)
            .await
            .map(|_| ())
            .map_err(Into::into)
    }
    /// gate: same as `user_activate`.
    pub async fn user_deactivate(
        &mut self,
        caller: &crate::role::Caller,
        name: &str,
    ) -> Result<()> {
        let user = self.user(name).await?;
        self.require_above_user(caller, user.id).await?;
        User::update_by_id(user.id)
            .active(false)
            .exec(&mut self.database)
            .await
            .map(|_| ())
            .map_err(Into::into)
    }

    /// gate: same as `user_activate`.
    pub async fn user_delete(&mut self, caller: &crate::role::Caller, name: &str) -> Result<()> {
        let user = self.user(name).await?;
        self.require_above_user(caller, user.id).await?;
        User::delete_by_id(&mut self.database, user.id)
            .await
            .map(|_| ())
            .map_err(Into::into)
    }

    /// Rename a user (SCIM `userName` update). gate: the caller must
    /// outrank the target. The surrogate `id` and every FK are untouched,
    /// so tokens, grants and credentials survive the rename.
    pub async fn user_rename(
        &mut self,
        caller: &crate::role::Caller,
        name: &str,
        new_name: &str,
    ) -> Result<User> {
        let user = self.user(name).await?;
        self.require_above_user(caller, user.id).await?;
        if new_name != user.name {
            anyhow::ensure!(!new_name.is_empty(), "user name must not be empty");
            if self.user(new_name).await.is_ok() {
                return Err(anyhow::anyhow!("user name '{new_name}' already exists"));
            }
            User::update_by_id(user.id)
                .name(new_name)
                .exec(&mut self.database)
                .await
                .map_err(anyhow::Error::from)?;
        }
        self.user_by_id(user.id).await
    }

    /// Self-service lifecycle: the session identity IS the
    /// authorization — a caller may act on exactly themselves, no level
    /// comparison (the strict gate would always refuse self-targeting).
    fn require_self(caller: &crate::role::Caller, user: &User) -> Result<()> {
        match caller {
            crate::role::Caller::Jwt(data) if data.user == user.id.to_string() => Ok(()),
            _ => Err(crate::role::AdminError::Forbidden.into()),
        }
    }

    pub async fn user_activate_self(
        &mut self,
        caller: &crate::role::Caller,
        name: &str,
    ) -> Result<()> {
        let user = self.user(name).await?;
        Self::require_self(caller, &user)?;
        User::update_by_id(user.id)
            .active(true)
            .exec(&mut self.database)
            .await
            .map(|_| ())
            .map_err(Into::into)
    }

    pub async fn user_deactivate_self(
        &mut self,
        caller: &crate::role::Caller,
        name: &str,
    ) -> Result<()> {
        let user = self.user(name).await?;
        Self::require_self(caller, &user)?;
        User::update_by_id(user.id)
            .active(false)
            .exec(&mut self.database)
            .await
            .map(|_| ())
            .map_err(Into::into)
    }

    pub async fn user_delete_self(
        &mut self,
        caller: &crate::role::Caller,
        name: &str,
    ) -> Result<()> {
        let user = self.user(name).await?;
        Self::require_self(caller, &user)?;
        User::delete_by_id(&mut self.database, user.id)
            .await
            .map(|_| ())
            .map_err(Into::into)
    }

    pub async fn all_users(&mut self) -> Result<Vec<User>> {
        User::all()
            .exec(&mut self.database)
            .await
            .map_err(Into::into)
    }
    pub async fn user_roles(&mut self, id: uuid::Uuid) -> Result<Vec<Role>> {
        User::filter_by_id(id)
            .userroles()
            .role()
            .exec(&mut self.database)
            .await
            .map_err(Into::into)
    }
    pub async fn user_passkey(&mut self, id: uuid::Uuid) -> Result<Vec<Passkey>> {
        User::filter_by_id(id)
            .passkey()
            .exec(&mut self.database)
            .await
            .map_err(Into::into)
    }
    pub async fn user_by_email(&mut self, email: &str) -> Result<User> {
        let email = Email::get_by_id(&mut self.database, email).await?;
        email
            .user()
            .exec(&mut self.database)
            .await
            .map_err(Into::into)
    }
    pub async fn user_email(&mut self, id: uuid::Uuid) -> Result<Vec<Email>> {
        User::filter_by_id(id)
            .email()
            .exec(&mut self.database)
            .await
            .map_err(Into::into)
    }

    pub async fn user_oauth2(&mut self, id: uuid::Uuid) -> Result<Vec<OAuth2>> {
        User::filter_by_id(id)
            .oauth2()
            .exec(&mut self.database)
            .await
            .map_err(Into::into)
    }

    pub async fn user_otp(&mut self, id: uuid::Uuid) -> Result<Vec<OTP>> {
        User::filter_by_id(id)
            .otp()
            .exec(&mut self.database)
            .await
            .map_err(Into::into)
    }
    pub async fn user_by_mobile(&mut self, mobile: &str) -> Result<User> {
        let mobile = OTP::get_by_id(&mut self.database, mobile).await?;
        mobile
            .user()
            .exec(&mut self.database)
            .await
            .map_err(Into::into)
    }

    // user role CRUD

    /// Assign an existing role to a user.
    ///
    /// Roles are created only via the seed `roles` list or `admin/role/create`
    /// (prerequisite): naming an unknown role
    /// fails instead of silently inventing an empty one.
    ///
    /// gate (rule R1): API callers may only assign roles strictly below
    /// their own effective level — self-escalation is impossible because the
    /// level test applies to the caller as well.
    pub async fn user_add_role(
        &mut self,
        caller: &crate::role::Caller,
        user_name: &str,
        role_name: &str,
    ) -> Result<()> {
        let user = self.user(user_name).await?;
        let role = self.role(role_name).await?;
        self.require_below(caller, &role).await?;
        toasty::create!(UserRole {
            user_id: user.id,
            role_id: role.id,
        })
        .exec(&mut self.database)
        .await
        .map(|_| ())
        .map_err(Into::into)
    }

    /// Remove a role from a user.
    ///
    /// gate (rule R2): symmetric to grant — a caller may only revoke
    /// roles it could have granted, so peers cannot strip each other's roles.
    pub async fn user_del_role(
        &mut self,
        caller: &crate::role::Caller,
        user_name: &str,
        role_name: &str,
    ) -> Result<()> {
        let user = self.user(user_name).await?;
        let role = self.role(role_name).await?;
        self.require_below(caller, &role).await?;
        UserRole::delete_by_user_id_and_role_id(&mut self.database, user.id, role.id)
            .await
            .map(|_| ())
            .map_err(Into::into)
    }
}

#[endpoint(
    summary = "List all users in a tenant",
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<Vec<String>>),
        (status_code = 400, description = "Bad request", body = ApiProblem)
    )
)]
pub async fn all_users(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    if let Some(mut tenant) = state.storage.tenant_by_domain(domain) {
        if let Ok(data) = tenant.all_users().await {
            res.status_code(StatusCode::OK);
            res.render(Json(ApiResponse::ok(
                data.iter().map(|u| u.name.clone()).collect::<Vec<_>>(),
            )));
            return;
        }
    }
    let err = ApiProblem::validation_error("Failed to parse request body");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err))
}

#[derive(Serialize, Deserialize, ToSchema)]
struct AddUser {
    name: String,
}

#[endpoint(
    summary = "Add user to tenant",
    request_body = AddUser,
    responses(
        (status_code = 200, description = "User created successfully", body = ApiResponse<()>),
        (status_code = 400, description = "Bad request", body = ApiProblem)
    )
)]
pub async fn add_user(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    if let Some(body) = extract::<AddUser>(req, None).await {
        let state = depot.obtain_mut::<crate::server::ServerState>().unwrap();
        let domain = crate::utils::get_domain(req, state).unwrap_or("");
        if let Some(mut tenant) = state.storage.tenant_by_domain(domain) {
            if let Ok(_) = tenant.user_create(&body.name).await {
                let resp = ApiResponse::ok(());
                res.status_code(StatusCode::OK);
                res.render(Json(resp));
                return;
            }
        }
    };
    let err = ApiProblem::validation_error("Failed to parse request body");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err))
}

#[derive(Deserialize, ToSchema)]
pub struct DeleteUser {
    pub user: String,
}

#[endpoint(
    summary = "Remove a user from tenant",
    request_body = DeleteUser,
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<()>),
        (status_code = 400, description = "Bad request", body = ApiProblem),
        (status_code = 401, description = "No verified session", body = ApiProblem),
        (status_code = 403, description = "Level gate refused the target user", body = ApiProblem)
    )
)]
pub async fn delete_user(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    if let Some(body) = extract::<DeleteUser>(req, None).await {
        // fail closed without a session, then enforce the level gate
        // against the target user inside `user_delete`.
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
            match tenant.user_delete(&caller, &body.user).await {
                Ok(_) => {
                    let resp = ApiResponse::ok(());
                    res.status_code(StatusCode::OK);
                    res.render(Json(resp));
                    return;
                }
                Err(e) => {
                    crate::utils::render_admin_error(res, e);
                    return;
                }
            }
        }
    };
    let err = ApiProblem::validation_error("Failed to parse request body");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err))
}

#[endpoint(
    summary = "Remove the user specified in JWT",
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<()>),
        (status_code = 400, description = "Bad request", body = ApiProblem)
    )
)]
pub async fn delete_self(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let caller = match crate::utils::caller_from_depot(depot) {
        Some(c) => c,
        None => {
            res.status_code(StatusCode::UNAUTHORIZED);
            res.render(Json(ApiProblem::unauthorized()));
            return;
        }
    };
    let user_name = match &caller {
        crate::role::Caller::Jwt(data) => data.username.clone(),
        _ => {
            res.status_code(StatusCode::UNAUTHORIZED);
            res.render(Json(ApiProblem::unauthorized()));
            return;
        }
    };
    let state = depot.obtain_mut::<crate::server::ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    if let Some(mut tenant) = state.storage.tenant_by_domain(domain) {
        // self-deletion is identity-checked, not level-gated.
        match tenant.user_delete_self(&caller, &user_name).await {
            Ok(_) => {
                let resp = ApiResponse::ok(());
                res.status_code(StatusCode::OK);
                res.render(Json(resp));
                return;
            }
            Err(e) => {
                crate::utils::render_admin_error(res, e);
                return;
            }
        }
    }

    let err = ApiProblem::validation_error("Failed to parse request body");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err))
}

#[derive(Deserialize, ToSchema)]
pub struct ActivateUser {
    pub user: String,
    pub active: bool,
}

#[endpoint(
    summary = "Activate/deactivate a user",
    request_body = ActivateUser,
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<()>),
        (status_code = 400, description = "Bad request", body = ApiProblem),
        (status_code = 401, description = "No verified session", body = ApiProblem),
        (status_code = 403, description = "Level gate refused the target user", body = ApiProblem)
    )
)]
pub async fn activate_user(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    if let Some(body) = extract::<ActivateUser>(req, None).await {
        // fail closed without a session, then enforce the level gate
        // against the target user inside `user_activate`/`user_deactivate`.
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
            let outcome = if body.active {
                tenant.user_activate(&caller, &body.user).await
            } else {
                tenant.user_deactivate(&caller, &body.user).await
            };
            match outcome {
                Ok(_) => {
                    let resp = ApiResponse::ok(());
                    res.status_code(StatusCode::OK);
                    res.render(Json(resp));
                    return;
                }
                Err(e) => {
                    crate::utils::render_admin_error(res, e);
                    return;
                }
            }
        }
    };
    let err = ApiProblem::validation_error("Failed to parse request body");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err))
}

#[derive(Deserialize, ToSchema)]
pub struct ActivateSelf {
    pub active: bool,
}

#[endpoint(
    summary = "Activate/deactivate the user specified in JWT",
    request_body = ActivateSelf,
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<()>),
        (status_code = 400, description = "Bad request", body = ApiProblem)
    )
)]
pub async fn activate_self(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let caller = match crate::utils::caller_from_depot(depot) {
        Some(c) => c,
        None => {
            res.status_code(StatusCode::UNAUTHORIZED);
            res.render(Json(ApiProblem::unauthorized()));
            return;
        }
    };
    let user_name = match &caller {
        crate::role::Caller::Jwt(data) => data.username.clone(),
        _ => {
            res.status_code(StatusCode::UNAUTHORIZED);
            res.render(Json(ApiProblem::unauthorized()));
            return;
        }
    };

    {
        if let Some(body) = extract::<ActivateSelf>(req, None).await {
            let state = depot.obtain_mut::<crate::server::ServerState>().unwrap();
            let domain = crate::utils::get_domain(req, state).unwrap_or("");
            if let Some(mut tenant) = state.storage.tenant_by_domain(domain) {
                if body.active {
                    // token verification is stateless by design, so a
                    // deactivated user's session stays valid until the token
                    // naturally expires. During that window they must not be
                    // able to undo an admin deactivation — re-activation is
                    // admin-only (`user/activate`). Self-DEactivation below
                    // stays allowed. Reading the user record here is fine:
                    // this endpoint is the central authority, unlike the
                    // distributed token-verification path.
                    if let Ok(user) = tenant.user(&user_name).await
                        && !user.active
                    {
                        let err = ApiProblem::validation_error("Account is deactivated");
                        res.status_code(StatusCode::BAD_REQUEST);
                        res.render(Json(err));
                        return;
                    }
                    // self-activation is identity-checked, not
                    // level-gated.
                    if let Ok(_) = tenant.user_activate_self(&caller, &user_name).await {
                        let resp = ApiResponse::ok(());
                        res.status_code(StatusCode::OK);
                        res.render(Json(resp));
                        return;
                    }
                } else {
                    if let Ok(_) = tenant.user_deactivate_self(&caller, &user_name).await {
                        let resp = ApiResponse::ok(());
                        res.status_code(StatusCode::OK);
                        res.render(Json(resp));
                        return;
                    }
                }
            }
        }
    }
    let err = ApiProblem::validation_error("Failed to parse request body");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err))
}

#[derive(Deserialize, ToSchema)]
pub struct AddRole {
    pub user: String,
    pub role: String,
}

#[endpoint(
    summary = "Add role to the user",
    request_body = AddRole,
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<()>),
        (status_code = 400, description = "Bad request", body = ApiProblem),
        (status_code = 403, description = "Level gate refused the role", body = ApiProblem)
    )
)]
pub async fn add_role(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    if let Some(body) = extract::<AddRole>(req, None).await {
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
            match tenant.user_add_role(&caller, &body.user, &body.role).await {
                Ok(_) => {
                    let resp = ApiResponse::ok(());
                    res.status_code(StatusCode::OK);
                    res.render(Json(resp));
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

#[derive(Deserialize, ToSchema)]
pub struct RemoveRole {
    pub user: String,
    pub role: String,
}

#[endpoint(
    summary = "Remove role from the user",
    request_body = RemoveRole,
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<()>),
        (status_code = 400, description = "Bad request", body = ApiProblem),
        (status_code = 403, description = "Level gate refused the role", body = ApiProblem)
    )
)]
pub async fn remove_role(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    if let Some(body) = extract::<RemoveRole>(req, None).await {
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
            match tenant.user_del_role(&caller, &body.user, &body.role).await {
                Ok(_) => {
                    let resp = ApiResponse::ok(());
                    res.status_code(StatusCode::OK);
                    res.render(Json(resp));
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

#[derive(Deserialize, ToSchema)]
pub struct UserRoleRequest {
    pub user: String,
}

#[endpoint(
    summary = "List all roles of the user",
    request_body = UserRoleRequest,
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<Vec<String>>),
        (status_code = 400, description = "Bad request", body = ApiProblem)
    )
)]
pub async fn user_roles(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    if let Some(body) = extract::<UserRoleRequest>(req, None).await {
        let state = depot.obtain_mut::<crate::server::ServerState>().unwrap();
        let domain = crate::utils::get_domain(req, state).unwrap_or("");
        if let Some(mut tenant) = state.storage.tenant_by_domain(domain) {
            if let Ok(user) = tenant.user(&body.user).await {
                if let Ok(data) = tenant.user_roles(user.id).await {
                    let resp =
                        ApiResponse::ok(data.iter().map(|r| r.id.clone()).collect::<Vec<_>>());
                    res.status_code(StatusCode::OK);
                    res.render(Json(resp));
                    return;
                }
            }
        }
    }
    let err = ApiProblem::validation_error("Failed to parse request body");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{JwtData, JwtVerify};
    use std::collections::HashSet;
    use std::sync::LazyLock;

    const DOMAIN: &str = "localhost";

    /// The revocation store is a process-wide singleton, so all tests share
    /// one backing directory that must outlive every individual test's
    /// TempDir (same pattern as the totp.rs/oidc.rs endpoint tests).
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

    /// In-process tenant with one active user.
    async fn user_test_env() -> (crate::server::ServerState, tempfile::TempDir) {
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
            tenant.user_create("alice").await.expect("user");
        }
        let state = crate::server::ServerState::create(storage, false)
            .await
            .expect("server state");
        (state, tmp)
    }

    /// Stands in for the `protect` hoop's outcome: an authenticated session
    /// for `alice` already injected into the depot. Because verification is
    /// stateless, this session stays "valid" even after alice is deactivated
    /// — exactly the window the handler guard must close.
    #[handler]
    async fn inject_alice_session(
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        let user_id = {
            let state = depot
                .obtain_mut::<crate::server::ServerState>()
                .expect("ServerState");
            let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
            tenant.user("alice").await.expect("alice").id.to_string()
        };
        depot.inject(JwtVerify {
            can_access: true,
            jwt_data: JwtData {
                user: user_id,
                username: "alice".to_string(),
                domain: DOMAIN.to_string(),
                mfa: HashSet::new(),
                roles: HashSet::new(),
            },
            expect_mfa: false,
            domain: DOMAIN.to_string(),
            auth_time: None,
        });
        ctrl.call_next(req, depot, res).await;
    }

    fn activate_self_service(state: crate::server::ServerState) -> Service {
        Service::new(
            Router::new().hoop(salvo::affix_state::inject(state)).push(
                Router::with_path("user/activate/self")
                    .hoop(inject_alice_session)
                    .post(activate_self),
            ),
        )
    }

    async fn post_activate_self(service: &Service, active: bool) -> StatusCode {
        let res = salvo::test::TestClient::post("http://localhost/user/activate/self")
            .add_header("Host", DOMAIN, true)
            .json(&serde_json::json!({ "active": active }))
            .send(service)
            .await;
        res.status_code.expect("status code")
    }

    async fn alice_active(state: &crate::server::ServerState) -> bool {
        state
            .storage
            .tenant_by_domain(DOMAIN)
            .expect("tenant")
            .user("alice")
            .await
            .expect("user")
            .active
    }

    /// verification is stateless, so a deactivated user's session stays
    /// valid until expiry; during that window they must not be able to undo
    /// an admin deactivation. Re-activation is admin-only (`user/activate`).
    #[tokio::test]
    async fn deactivated_user_cannot_reactivate_themselves() {
        let (state, _tmp) = user_test_env().await;
        {
            let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
            tenant
                .user_deactivate(&crate::role::Caller::Bootstrap, "alice")
                .await
                .expect("deactivate");
        }
        let service = activate_self_service(state.clone());

        let status = post_activate_self(&service, true).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "self-reactivation of a deactivated account must be refused"
        );
        assert!(
            !alice_active(&state).await,
            "the account must remain deactivated"
        );
    }

    /// Self-DEactivation stays allowed for an active user.
    #[tokio::test]
    async fn active_user_can_still_self_deactivate() {
        let (state, _tmp) = user_test_env().await;
        let service = activate_self_service(state.clone());

        let status = post_activate_self(&service, false).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!alice_active(&state).await);
    }

    /// An already-active user's no-op activation still succeeds.
    #[tokio::test]
    async fn active_user_self_activation_is_a_noop_success() {
        let (state, _tmp) = user_test_env().await;
        let service = activate_self_service(state.clone());

        let status = post_activate_self(&service, true).await;
        assert_eq!(status, StatusCode::OK);
        assert!(alice_active(&state).await);
    }

    // ── handler-level level gate ──────────────────────────────────────
    //
    // The `protect` hoop is stood in for by injecting the session directly
    // (same pattern as the tests above); full HTTP assertions through
    // `protect` remain blocked on the placeholder token.

    /// Tenant with the builtin catalog, `alice` (no role) and `bob` holding
    /// `admin` — pre-granted via Bootstrap so revocation tests have a target.
    async fn role_admin_env() -> (crate::server::ServerState, tempfile::TempDir) {
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
            for (name, _) in crate::role::BUILTIN_ROLES {
                tenant
                    .role_create(&bootstrap, name, 0)
                    .await
                    .expect("builtin role");
            }
            tenant.user_create("alice").await.expect("user");
            tenant.user_create("bob").await.expect("user");
            tenant.user_create("dave").await.expect("user");
            tenant
                .user_add_role(&bootstrap, "alice", "admin")
                .await
                .expect("grant");
            tenant
                .user_add_role(&bootstrap, "bob", "admin")
                .await
                .expect("grant");
        }
        let state = crate::server::ServerState::create(storage, false)
            .await
            .expect("server state");
        (state, tmp)
    }

    macro_rules! session_injector {
        ($name:ident, $user:expr, [$($role:expr),+]) => {
            #[handler]
            async fn $name(
                req: &mut Request,
                depot: &mut Depot,
                res: &mut Response,
                ctrl: &mut FlowCtrl,
            ) {
                let user_id = {
                    let state = depot
                        .obtain_mut::<crate::server::ServerState>()
                        .expect("ServerState");
                    let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
 // Level-gate tests inject sessions for users that were
 // never created; fall back to a nil id there — only the
 // self-service tests rely on a real uuid match.
                    tenant
                        .user($user)
                        .await
                        .map(|u| u.id.to_string())
                        .unwrap_or_else(|_| uuid::Uuid::nil().to_string())
                };
                depot.inject(JwtVerify {
                    can_access: true,
                    jwt_data: JwtData {
                        user: user_id,
                        username: $user.to_string(),
                        domain: DOMAIN.to_string(),
                        mfa: HashSet::new(),
                        roles: HashSet::from([$($role.to_string()),+]),
                    },
                    expect_mfa: false,
                    domain: DOMAIN.to_string(),
                    auth_time: None,
                });
                ctrl.call_next(req, depot, res).await;
            }
        };
    }

    session_injector!(inject_admin_session, "alice", ["admin"]);
    session_injector!(inject_root_session, "carol", ["root", "admin", "user"]);

    /// The six role-administration endpoints behind one injected session
    /// (the parent hoop applies to every pushed child route).
    fn role_admin_service<H: salvo::Handler + 'static>(
        state: crate::server::ServerState,
        injector: H,
    ) -> Service {
        Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state))
                .hoop(injector)
                .push(Router::with_path("user/add_role").post(add_role))
                .push(Router::with_path("user/remove_role").post(remove_role))
                .push(Router::with_path("role/create").post(crate::role::add_role))
                .push(Router::with_path("role/delete").post(crate::role::delete_role))
                .push(Router::with_path("policy/create").post(crate::policy::add_policy))
                .push(Router::with_path("policy/delete").post(crate::policy::delete_policy)),
        )
    }

    async fn post_json(service: &Service, path: &str, body: serde_json::Value) -> StatusCode {
        let res = salvo::test::TestClient::post(format!("http://localhost/{path}"))
            .add_header("Host", DOMAIN, true)
            .json(&body)
            .send(service)
            .await;
        res.status_code.expect("status code")
    }

    /// E1/E2: an admin cannot grant `admin` or `root` — not to others, not
    /// to itself. This is the original attack at the endpoint level.
    #[tokio::test]
    async fn add_role_denies_escalation() {
        let (state, _tmp) = role_admin_env().await;
        let service = role_admin_service(state, inject_admin_session);

        let status = post_json(
            &service,
            "user/add_role",
            serde_json::json!({ "user": "alice", "role": "root" }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "admin cannot grant root");

        let status = post_json(
            &service,
            "user/add_role",
            serde_json::json!({ "user": "alice", "role": "admin" }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "admin cannot grant admin");
    }

    /// Downward grants succeed (200) and land in the DB.
    #[tokio::test]
    async fn add_role_allows_downward_grant() {
        let (state, _tmp) = role_admin_env().await;
        let service = role_admin_service(state.clone(), inject_admin_session);

        let status = post_json(
            &service,
            "user/add_role",
            serde_json::json!({ "user": "bob", "role": "guest" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        let bob = tenant.user("bob").await.expect("bob");
        let roles: Vec<String> = tenant
            .user_roles(bob.id)
            .await
            .expect("roles")
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert!(roles.contains(&"guest".to_string()), "grant must persist");
    }

    /// E7: root delegates tenant admins.
    #[tokio::test]
    async fn add_role_root_grants_admin() {
        let (state, _tmp) = role_admin_env().await;
        let service = role_admin_service(state.clone(), inject_root_session);

        let status = post_json(
            &service,
            "user/add_role",
            serde_json::json!({ "user": "dave", "role": "admin" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        let dave = tenant.user("dave").await.expect("dave");
        let roles: Vec<String> = tenant
            .user_roles(dave.id)
            .await
            .expect("roles")
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert!(roles.contains(&"admin".to_string()), "grant must persist");
    }

    /// R2 at the endpoint level: admin cannot strip a peer's admin role.
    #[tokio::test]
    async fn remove_role_denies_peer_revocation() {
        let (state, _tmp) = role_admin_env().await;
        let service = role_admin_service(state, inject_admin_session);

        let status = post_json(
            &service,
            "user/remove_role",
            serde_json::json!({ "user": "bob", "role": "admin" }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "peer revocation refused");
    }

    /// R3 at the endpoint level: level bounds, reserved names, conflicts.
    #[tokio::test]
    async fn role_create_enforces_the_level_gate() {
        let (state, _tmp) = role_admin_env().await;
        let service = role_admin_service(state, inject_admin_session);

        let status = post_json(
            &service,
            "role/create",
            serde_json::json!({ "name": "support", "level": 30 }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "30 < 80");

        let status = post_json(
            &service,
            "role/create",
            serde_json::json!({ "name": "ops", "level": 80 }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "not at own level");

        let status = post_json(
            &service,
            "role/create",
            serde_json::json!({ "name": "admin", "level": 1 }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "builtin names reserved");

        let status = post_json(
            &service,
            "role/create",
            serde_json::json!({ "name": "support", "level": 30 }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "duplicate name conflicts");
    }

    /// R4 at the endpoint level: builtin roles are undeletable.
    #[tokio::test]
    async fn role_delete_refuses_builtin_roles() {
        let (state, _tmp) = role_admin_env().await;
        let service = role_admin_service(state, inject_admin_session);

        let status = post_json(
            &service,
            "role/delete",
            serde_json::json!({ "name": "user" }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    /// R5 at the endpoint level: policy writes for own/superior roles refused.
    #[tokio::test]
    async fn policy_create_denies_own_and_superior_roles() {
        let (state, _tmp) = role_admin_env().await;
        let service = role_admin_service(state, inject_admin_session);
        let policy = |role: &str| {
            serde_json::json!({
                "domain": DOMAIN,
                "resource": "/api/v1/admin/tenant/delete",
                "action": null,
                "role": role,
                "source": "Nothing",
                "target": "Nothing",
                "mfa": false,
                "allowed": true
            })
        };

        let status = post_json(&service, "policy/create", policy("admin")).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "own role refused");

        let status = post_json(&service, "policy/create", policy("root")).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "superior role refused");

        let status = post_json(&service, "policy/create", policy("user")).await;
        assert_eq!(status, StatusCode::OK, "downward policy write succeeds");
    }

    /// R6 at the endpoint level: policy deletion is bounded the same way.
    #[tokio::test]
    async fn policy_delete_denies_own_role() {
        let (state, _tmp) = role_admin_env().await;
        let service = role_admin_service(state, inject_admin_session);

        let status = post_json(
            &service,
            "policy/delete",
            serde_json::json!({
                "domain": DOMAIN,
                "resource": "/api/v1/admin/user/add_role",
                "action": null,
                "role": "admin"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    /// the policy domain is the one resolved from the request `Host`,
    /// never the client-supplied body field — a forged `domain` cannot write
    /// or delete policies for another domain served by the same tenant.
    #[tokio::test]
    async fn policy_write_uses_resolved_domain_not_body() {
        let (state, _tmp) = role_admin_env().await;
        const OTHER: &str = "other.localhost";
        const SIBLING_RESOURCE: &str = "/api/v1/app/sibling";
        const RESOURCE: &str = "/api/v1/app/g56";

        state
            .storage
            .add_domain(OTHER, "test-tenant")
            .await
            .expect("second domain");
        {
            let mut tenant = state.storage.tenant_by_domain(OTHER).expect("tenant");
            tenant
                .policy_create(
                    &crate::role::Caller::Bootstrap,
                    OTHER,
                    None,
                    SIBLING_RESOURCE,
                    "user",
                    &crate::policy::SourceResolver::Nothing,
                    &crate::policy::TargetResolver::Nothing,
                    false,
                    true,
                )
                .await
                .expect("seed sibling policy");
        }

        let service = role_admin_service(state.clone(), inject_admin_session);

        let status = post_json(
            &service,
            "policy/create",
            serde_json::json!({
                "domain": OTHER,
                "resource": RESOURCE,
                "action": null,
                "role": "user",
                "source": "Nothing",
                "target": "Nothing",
                "mfa": false,
                "allowed": true
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "downward write succeeds");

        // `tenant_by_domain` returns a DashMap guard — drop it before the
        // next request so the handler can take it.
        {
            let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
            let stored: Vec<_> = tenant
                .all_policies()
                .await
                .expect("policies")
                .into_iter()
                .filter(|p| p.resource.join("/") == RESOURCE)
                .collect();
            assert_eq!(stored.len(), 1, "policy lands in the resolved domain");
            assert_eq!(
                stored[0].domain_id, DOMAIN,
                "domain must come from the resolved host, not the body"
            );
        }

        let status = post_json(
            &service,
            "policy/delete",
            serde_json::json!({
                "domain": OTHER,
                "resource": SIBLING_RESOURCE,
                "action": null,
                "role": "user"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        {
            let mut tenant = state.storage.tenant_by_domain(OTHER).expect("tenant");
            assert!(
                tenant
                    .all_policies()
                    .await
                    .expect("policies")
                    .iter()
                    .any(|p| p.resource.join("/") == SIBLING_RESOURCE),
                "forged-domain delete must not reach the sibling domain's policy"
            );
        }

        let status = post_json(
            &service,
            "policy/delete",
            serde_json::json!({
                "domain": OTHER,
                "resource": RESOURCE,
                "action": null,
                "role": "user"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        {
            let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
            assert!(
                !tenant
                    .all_policies()
                    .await
                    .expect("policies")
                    .iter()
                    .any(|p| p.resource.join("/") == RESOURCE),
                "delete is confined to the resolved domain and removes it"
            );
        }
    }

    /// Fail-closed: without an injected session the handlers return 401.
    #[tokio::test]
    async fn role_admin_handlers_fail_closed_without_session() {
        let (state, _tmp) = role_admin_env().await;
        let service = Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state))
                .push(Router::with_path("user/add_role").post(add_role)),
        );
        let status = post_json(
            &service,
            "user/add_role",
            serde_json::json!({ "user": "alice", "role": "guest" }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // ── user lifecycle level gate ────────────────────────────────────

    session_injector!(inject_dave_session, "dave", ["user"]);

    /// The user-lifecycle endpoints behind one injected session.
    fn user_lifecycle_service<H: salvo::Handler + 'static>(
        state: crate::server::ServerState,
        injector: H,
    ) -> Service {
        Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state))
                .hoop(injector)
                .push(Router::with_path("user/delete").post(delete_user))
                .push(Router::with_path("user/delete/self").post(delete_self))
                .push(Router::with_path("user/activate").post(activate_user)),
        )
    }

    /// Grant dave `root` via Bootstrap so an admin-ranked caller has a
    /// superior target to attack.
    async fn make_dave_root(state: &crate::server::ServerState) {
        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        tenant
            .user_add_role(&crate::role::Caller::Bootstrap, "dave", "root")
            .await
            .expect("grant root");
    }

    async fn user_exists(state: &crate::server::ServerState, name: &str) -> bool {
        state
            .storage
            .tenant_by_domain(DOMAIN)
            .expect("tenant")
            .user(name)
            .await
            .is_ok()
    }

    /// The attack: a tenant admin deletes a user holding `root`,
    /// neutralizing the apex account. Must be refused, and the target must
    /// survive.
    #[tokio::test]
    async fn delete_user_denies_lower_ranked_caller() {
        let (state, _tmp) = role_admin_env().await;
        make_dave_root(&state).await;
        let service = user_lifecycle_service(state.clone(), inject_admin_session);

        let status = post_json(
            &service,
            "user/delete",
            serde_json::json!({ "user": "dave" }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(user_exists(&state, "dave").await, "target must survive");
    }

    /// Same attack via deactivation.
    #[tokio::test]
    async fn activate_user_denies_lower_ranked_caller() {
        let (state, _tmp) = role_admin_env().await;
        make_dave_root(&state).await;
        let service = user_lifecycle_service(state.clone(), inject_admin_session);

        let status = post_json(
            &service,
            "user/activate",
            serde_json::json!({ "user": "dave", "active": false }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            state
                .storage
                .tenant_by_domain(DOMAIN)
                .expect("tenant")
                .user("dave")
                .await
                .expect("dave")
                .active,
            "target must stay active"
        );
    }

    /// Peers are refused too — the comparison is strict.
    #[tokio::test]
    async fn lifecycle_denies_peer_caller() {
        let (state, _tmp) = role_admin_env().await;
        let service = user_lifecycle_service(state.clone(), inject_admin_session);

        // alice (admin) targets bob (admin).
        let status = post_json(
            &service,
            "user/activate",
            serde_json::json!({ "user": "bob", "active": false }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let status = post_json(
            &service,
            "user/delete",
            serde_json::json!({ "user": "bob" }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(user_exists(&state, "bob").await);
    }

    /// Downward lifecycle administration succeeds.
    #[tokio::test]
    async fn lifecycle_allows_higher_ranked_caller() {
        let (state, _tmp) = role_admin_env().await;
        let service = user_lifecycle_service(state.clone(), inject_root_session);

        // carol holds root; alice holds admin.
        let status = post_json(
            &service,
            "user/activate",
            serde_json::json!({ "user": "alice", "active": false }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            !state
                .storage
                .tenant_by_domain(DOMAIN)
                .expect("tenant")
                .user("alice")
                .await
                .expect("alice")
                .active,
            "deactivation must persist"
        );

        let status = post_json(
            &service,
            "user/delete",
            serde_json::json!({ "user": "alice" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!user_exists(&state, "alice").await, "delete must persist");
    }

    /// A target with no roles has no level — any ranked caller outranks it.
    #[tokio::test]
    async fn lifecycle_allows_unranked_target() {
        let (state, _tmp) = role_admin_env().await;
        let service = user_lifecycle_service(state.clone(), inject_admin_session);

        let status = post_json(
            &service,
            "user/delete",
            serde_json::json!({ "user": "dave" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!user_exists(&state, "dave").await);
    }

    /// Self-deletion stays available to any ranked user — the identity
    /// path, not the level gate.
    #[tokio::test]
    async fn delete_self_still_works_for_ranked_user() {
        let (state, _tmp) = role_admin_env().await;
        let service = user_lifecycle_service(state.clone(), inject_dave_session);

        let status = post_json(
            &service,
            "user/delete/self",
            serde_json::json!({ "user": "dave" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!user_exists(&state, "dave").await);
    }

    /// Fail-closed: the lifecycle endpoints return 401 without a session.
    #[tokio::test]
    async fn lifecycle_handlers_fail_closed_without_session() {
        let (state, _tmp) = role_admin_env().await;
        let service = Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state.clone()))
                .push(Router::with_path("user/delete").post(delete_user))
                .push(Router::with_path("user/activate").post(activate_user)),
        );

        let status = post_json(
            &service,
            "user/delete",
            serde_json::json!({ "user": "dave" }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let status = post_json(
            &service,
            "user/activate",
            serde_json::json!({ "user": "dave", "active": false }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(user_exists(&state, "dave").await);
    }

    // ── Rename (SCIM userName update path) ─────────────────────────────────

    /// Rename changes the wire name but keeps the surrogate id stable, so
    /// tokens, grants and credentials survive; conflicting and unranked
    /// renames are refused.
    #[tokio::test]
    async fn rename_keeps_id_and_rejects_conflicts() {
        let (state, _tmp) = user_test_env().await;
        let bootstrap = crate::role::Caller::Bootstrap;
        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        let id = tenant.user("alice").await.expect("alice").id;

        tenant
            .user_rename(&bootstrap, "alice", "alicia")
            .await
            .expect("rename");
        assert!(tenant.user("alice").await.is_err());
        let after = tenant.user("alicia").await.expect("renamed");
        assert_eq!(after.id, id, "the surrogate id must survive a rename");

        // Same-name rename is a no-op success.
        tenant
            .user_rename(&bootstrap, "alicia", "alicia")
            .await
            .expect("same name");

        // Conflict: the target name is taken.
        tenant.user_create("bob").await.expect("bob");
        assert!(
            tenant
                .user_rename(&bootstrap, "alicia", "bob")
                .await
                .is_err(),
            "renaming onto an existing name must be refused"
        );

        // a caller with no resolvable level may rename no one.
        let unranked = crate::role::Caller::Jwt(crate::db::JwtData {
            user: uuid::Uuid::nil().to_string(),
            username: "mallory".to_string(),
            domain: DOMAIN.to_string(),
            mfa: HashSet::new(),
            roles: HashSet::new(),
        });
        assert!(
            tenant
                .user_rename(&unranked, "alicia", "eve")
                .await
                .is_err(),
            "an unranked caller must be refused (default-deny)"
        );
    }
}
