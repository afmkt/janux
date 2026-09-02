use crate::config::OTPDTO;
use crate::config::ResendDTO;
use crate::db::Storage;
use crate::domain::DomainDTO;
use crate::policy::PolicyDTO;
use crate::role::Caller;
use crate::user::UserDTO;
use anyhow::Result;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct TenantDTO {
    name: String,
    domains: Vec<DomainDTO>,
    #[serde(default)]
    roles: Vec<String>,
    policies: Vec<PolicyDTO>,
    users: Vec<UserDTO>,
    resend: ResendDTO,
    alisms: OTPDTO,
}

impl TenantDTO {
    pub async fn save(&self, storage: &mut Storage) -> Result<()> {
        let mut tenant = {
            if let Some(existing) = storage.tenant_by_id(&self.name) {
                existing
            } else {
                storage.new_tenant(&self.name).await?
            }
        };
        for d in self.domains.iter() {
            d.save(&mut tenant).await?;
        }
        // Roles first: policy_create resolves the role by name and fails
        // when it does not exist yet. Seeding is the trust anchor, so
        // it runs as the unrestricted Bootstrap caller.
        for r in self.roles.iter() {
            tenant.role_create(&Caller::Bootstrap, r, 0).await?;
        }
        for u in self.users.iter() {
            u.save(&mut tenant).await?;
        }
        for p in self.policies.iter() {
            p.save(&mut tenant).await?;
        }
        self.resend.save(&mut tenant).await?;
        self.alisms.save(&mut tenant).await?;
        Ok(())
    }
}

/// The standard admin policy set seeded into runtime-created tenants together
/// with the builtin catalog. Mirrors
/// `seed.toml` so a fresh tenant becomes operable by its first admin.
pub const STANDARD_ADMIN_POLICIES: &[(&str, &str)] = &[
    // root: cross-tenant lifecycle
    ("/api/v1/admin/tenant/list", "root"),
    ("/api/v1/admin/tenant/create", "root"),
    ("/api/v1/admin/tenant/delete", "root"),
    // admin: domains
    ("/api/v1/admin/domain/list", "admin"),
    ("/api/v1/admin/domain/create", "admin"),
    ("/api/v1/admin/domain/delete", "admin"),
    // admin: users
    ("/api/v1/admin/user/list", "admin"),
    ("/api/v1/admin/user/create", "admin"),
    ("/api/v1/admin/user/activate", "admin"),
    ("/api/v1/admin/user/delete", "admin"),
    ("/api/v1/admin/user/add_role", "admin"),
    ("/api/v1/admin/user/remove_role", "admin"),
    ("/api/v1/admin/user/remove_email", "admin"),
    ("/api/v1/admin/user/remove_mobile", "admin"),
    ("/api/v1/admin/user/remove_social", "admin"),
    ("/api/v1/admin/user/roles", "admin"),
    // admin: roles
    ("/api/v1/admin/role/list", "admin"),
    ("/api/v1/admin/role/create", "admin"),
    ("/api/v1/admin/role/delete", "admin"),
    // admin: social providers
    ("/api/v1/admin/provider/list", "admin"),
    ("/api/v1/admin/provider/create", "admin"),
    ("/api/v1/admin/provider/delete", "admin"),
    // admin: policies
    ("/api/v1/admin/policy/list", "admin"),
    ("/api/v1/admin/policy/create", "admin"),
    ("/api/v1/admin/policy/delete", "admin"),
    // admin: signing keys
    ("/api/v1/admin/key/list", "admin"),
    ("/api/v1/admin/key/create", "admin"),
    ("/api/v1/admin/key/delete", "admin"),
    // admin: TOTP administration
    ("/api/v1/admin/totp/list", "admin"),
    ("/api/v1/admin/totp/remove", "admin"),
    // admin: OIDC relying parties
    ("/api/v1/admin/oauth2client/list", "admin"),
    ("/api/v1/admin/oauth2client/create", "admin"),
    ("/api/v1/admin/oauth2client/delete", "admin"),
    ("/api/v1/admin/oauth2client/meta", "admin"),
    // admin: OIDC feature switches (Dynamic Client Registration)
    ("/api/v1/admin/oidc/config", "admin"),
    // admin: observability (process-global telemetry)
    ("/api/v1/admin/metrics", "admin"),
    // user: self-service (handlers act on the caller's own account)
    ("/api/v1/admin/user/activate/self", "user"),
    ("/api/v1/admin/user/delete/self", "user"),
];

/// Bootstrap a runtime-created tenant (`admin/tenant/create`): the builtin
/// role catalog, the standard admin policy set bound to the tenant's first
/// domain, and an optional first admin user. Runs as [`Caller::Bootstrap`] —
/// the one path allowed to establish the apex — so the level gate never
/// applies to it; every later mutation inside the tenant goes through R1–R6.
pub async fn bootstrap_tenant(
    storage: &Storage,
    tenant_name: &str,
    domain: Option<&str>,
    admin: Option<&str>,
) -> Result<()> {
    {
        let mut tenant = storage
            .tenant_by_id(tenant_name)
            .ok_or_else(|| anyhow::anyhow!("Tenant '{}' not found", tenant_name))?;
        for (name, _) in crate::role::BUILTIN_ROLES {
            tenant.role_create(&Caller::Bootstrap, name, 0).await?;
        }
    }
    if let Some(domain) = domain {
        storage.add_domain(domain, tenant_name).await?;
        let mut tenant = storage
            .tenant_by_id(tenant_name)
            .ok_or_else(|| anyhow::anyhow!("Tenant '{}' not found", tenant_name))?;
        for (resource, role) in STANDARD_ADMIN_POLICIES {
            tenant
                .policy_create(
                    &Caller::Bootstrap,
                    domain,
                    None,
                    resource,
                    role,
                    &crate::policy::SourceResolver::Nothing,
                    &crate::policy::TargetResolver::Nothing,
                    false,
                    true,
                )
                .await?;
        }
    }
    if let Some(admin) = admin {
        let mut tenant = storage
            .tenant_by_id(tenant_name)
            .ok_or_else(|| anyhow::anyhow!("Tenant '{}' not found", tenant_name))?;
        tenant.user_create(admin).await?;
        tenant
            .user_add_role(&Caller::Bootstrap, admin, "admin")
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    use crate::server::JanuxConfig;

    /// The committed seed.toml is the RBAC bootstrap source of truth
    ///: guard its shape so a typo surfaces at `cargo test` time
    /// instead of as a lockout on first boot.
    #[test]
    fn seed_toml_bootstraps_builtin_roles() {
        let cfg = JanuxConfig::load_from(&["base".into(), "seed".into()])
            .expect("seed.toml must load through the production config path");
        let tenants = cfg.seed.expect("seed.toml must define [[seed]] tenants");
        let tenant = tenants
            .iter()
            .find(|t| t.name == "localhost")
            .expect("localhost tenant seeded");

        assert_eq!(tenant.roles, vec!["root", "admin", "scim", "user", "guest"]);

        // The builtin catalog is the constitution of the level gate —
        // pin it here so a change is a deliberate, reviewed act.
        assert_eq!(
            crate::role::BUILTIN_ROLES,
            &[
                ("root", 100),
                ("admin", 80),
                ("scim", 60),
                ("user", 40),
                ("guest", 20)
            ]
        );
        for r in &tenant.roles {
            assert!(
                crate::role::builtin_level(r).is_some(),
                "seeded role {r} is not a builtin catalog member"
            );
        }

        let admin = tenant
            .users
            .iter()
            .find(|u| u.id == "admin")
            .expect("bootstrap admin seeded");
        assert!(admin.active);
        for role in ["root", "admin", "user"] {
            assert!(
                admin.roles.contains(&role.to_string()),
                "admin lacks {role}"
            );
        }

        // user_add_role no longer creates unknown roles (Step 4), so every
        // role a seeded user carries must be declared above.
        for u in &tenant.users {
            for role in &u.roles {
                assert!(
                    tenant.roles.contains(role),
                    "user {} references undeclared role {}",
                    u.id,
                    role
                );
            }
        }

        // protect is default-deny, so every seeded policy must reference a
        // seeded built-in role and an absolute admin or SCIM path.
        assert!(!tenant.policies.is_empty());
        for p in &tenant.policies {
            assert!(
                tenant.roles.contains(&p.role),
                "policy role {} not seeded",
                p.role
            );
            assert!(
                p.resource.starts_with("/api/v1/admin/") || p.resource.starts_with("/scim/v2/"),
                "policy resource {} is not an admin or SCIM path",
                p.resource
            );
        }
        // Cross-tenant lifecycle stays root-only.
        assert!(
            tenant
                .policies
                .iter()
                .any(|p| p.role == "root" && p.resource == "/api/v1/admin/tenant/list")
        );
    }
}
