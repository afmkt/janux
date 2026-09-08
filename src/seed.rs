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
        // G-136 enabler: a seeded tenant must be able to mint tokens from
        // first boot — without a signing key every ceremony dies with
        // "Fail to issue JWT" and the JWKS stays empty until an admin acts
        // (which itself needs a session). Create one key per seeded domain;
        // idempotent across restarts (stable key id, skipped when the row
        // exists). Requires the process encryption key, which main.rs sets
        // up before seeding. Fully qualified `Tenant::key`: the RefMut
        // guard's 0-arg `key()` would shadow the lookup.
        for d in self.domains.iter() {
            let key_name = format!("seed-{}", d.id);
            if crate::db::Tenant::key(&mut tenant, &key_name)
                .await
                .is_err()
            {
                tenant.key_create(&d.id, &key_name).await?;
            }
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
    ("/api/v1/admin/user/attach_email", "admin"),
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
    ("/api/v1/admin/key/retire", "admin"),
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
    // scim: machine provisioning. The builtin `scim` role is useless
    // without these rows (protect is default-deny), so runtime-created
    // tenants must mirror the seed file. The machine principal itself is
    // NOT bootstrapped: an admin registers it per IdP connection via
    // admin/oauth2client/create with default_scopes = "scim" — that
    // registration is the consent step the client_credentials grant
    // enforces (requested ∩ registered).
    ("/scim/v2/Users", "scim"),
    ("/scim/v2/Users/{id}", "scim"),
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
    admin_email: Option<&str>,
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
        // G-131: the first admin must be able to SIGN IN. Created users are
        // credential-less and strict signup refuses the pre-existing
        // username, while every other attach path (SCIM client,
        // `user/attach_email`) itself needs an admin session for THIS
        // tenant — so the vouched email, when provided, is attached as a
        // verified credential here at the trust anchor.
        if let Some(email) = admin_email {
            tenant
                .email_create_verified(admin, &email.to_lowercase())
                .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    use super::STANDARD_ADMIN_POLICIES;
    use crate::server::JanuxConfig;

    /// The seed.toml shape is the RBAC bootstrap source of truth:
    /// guard it so a typo surfaces at `cargo test` time instead of as
    /// a lockout on first boot. base.toml/seed.toml are gitignored
    /// (local credentials); on CI or a fresh clone the committed
    /// example files (identical shape, dummy secrets) are validated
    /// instead.
    #[test]
    fn seed_toml_bootstraps_builtin_roles() {
        let files: Vec<String> = if std::path::Path::new("seed.toml").exists() {
            vec!["base".into(), "seed".into()]
        } else {
            vec!["base.example".into(), "seed.example".into()]
        };
        let cfg = JanuxConfig::load_from(&files)
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

        // G-131: the bootstrap admin must vouch an email credential —
        // without it the seeded admin can never sign in (strict signup
        // refuses the pre-existing username and no self-service attach
        // path exists for a credential-less account).
        assert!(
            admin.email.as_deref().is_some_and(|e| e.contains('@')),
            "the seeded admin must vouch an email credential (G-131)"
        );

        // G-133: magic links must land on a route that EXISTS — the
        // hosted /login SPA consumes token/username/email from the query.
        // The old /api/v1/auth/email/landing value 404'd out of the box.
        let verify_url = url::Url::parse(&tenant.resend.verify_url).expect("verify_url must parse");
        assert_eq!(
            verify_url.path(),
            "/login",
            "seeded verify_url must point at the hosted login SPA"
        );

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

        // STANDARD_ADMIN_POLICIES claims to mirror the seed file so
        // runtime-created tenants come up like the seeded one. Pin the
        // SCIM rows: without them the builtin `scim` role is dead under
        // default-deny in every tenant created via admin/tenant/create.
        for p in tenant.policies.iter().filter(|p| p.role == "scim") {
            assert!(
                STANDARD_ADMIN_POLICIES.contains(&(p.resource.as_str(), p.role.as_str())),
                "seed policy {} (role {}) is missing from STANDARD_ADMIN_POLICIES",
                p.resource,
                p.role
            );
        }
        assert!(
            STANDARD_ADMIN_POLICIES.contains(&("/scim/v2/Users", "scim")),
            "runtime tenants must seed the SCIM collection policy"
        );
    }

    /// Process-lifetime backing dir for the bootstrap test's Storage (the
    /// revocation-store singleton binds to the FIRST init dir and must
    /// outlive every test).
    static BOOTSTRAP_STORE_DIR: std::sync::LazyLock<tempfile::TempDir> =
        std::sync::LazyLock::new(|| tempfile::tempdir().expect("tempdir"));

    /// regression H8: `bootstrap_tenant` — the path `admin/tenant/create`
    /// walks — must produce an immediately operable tenant: the full
    /// builtin catalog including `scim`, the standard admin policies bound
    /// to the first domain, and the first admin user holding the role.
    /// The HTTP-level lifecycle test cannot look inside a fresh tenant
    /// (sessions are domain-bound and the new domain has no signing key
    /// yet), so the bootstrap contract is pinned here.
    #[tokio::test]
    async fn bootstrap_tenant_provisions_catalog_policies_and_admin() {
        let storage = crate::db::Storage::init(BOOTSTRAP_STORE_DIR.path())
            .await
            .expect("storage init");
        storage.new_tenant("fresh").await.expect("tenant");
        super::bootstrap_tenant(
            &storage,
            "fresh",
            Some("fresh.local"),
            Some("admin@fresh"),
            Some("First-Admin@fresh.example"),
        )
        .await
        .expect("bootstrap");

        let mut tenant = storage.tenant_by_id("fresh").expect("tenant");

        // Full builtin catalog at the pinned levels (the role NAME is the
        // model's `id`).
        let roles = tenant
            .roles_page(crate::utils::MAX_PAGE_LIMIT, 0)
            .await
            .expect("roles")
            .items;
        for (name, level) in crate::role::BUILTIN_ROLES {
            let role = roles
                .iter()
                .find(|r| r.id == *name)
                .unwrap_or_else(|| panic!("bootstrap must create the '{name}' role"));
            assert_eq!(role.level, *level, "'{name}' keeps its builtin level");
        }

        // Standard policies bound to the FIRST domain — including the SCIM
        // rows, without which the `scim` role is dead under default-deny.
        // `resource` is stored as `/`-split segments; join round-trips the
        // original path exactly (the leading "" segment restores the slash).
        let policies = tenant
            .policies_page(crate::utils::MAX_PAGE_LIMIT, 0)
            .await
            .expect("policies")
            .items;
        let has_policy = |resource: &str, role: &str| {
            policies.iter().any(|p| {
                p.domain_id == "fresh.local"
                    && p.role_id == role
                    && p.resource.join("/") == resource
            })
        };
        assert!(
            has_policy("/api/v1/admin/user/create", "admin"),
            "standard admin policies must bind to the first domain"
        );
        assert!(
            has_policy("/scim/v2/Users", "scim"),
            "the scim role must come with its policy rows"
        );

        // The first admin exists and holds the admin role.
        let admin = tenant.user("admin@fresh").await.expect("first admin");
        let granted = tenant.user_roles(admin.id).await.expect("user roles");
        assert!(
            granted.iter().any(|r| r.id == "admin"),
            "the bootstrap admin must hold the admin role"
        );

        // G-131: the vouched email landed as a VERIFIED credential
        // (lowercased), so the first admin can immediately run a
        // magic-link signin instead of being locked out of a
        // credential-less account.
        let by_email = tenant
            .user_by_email("first-admin@fresh.example")
            .await
            .expect("the bootstrap admin email must be attached");
        assert_eq!(by_email.id, admin.id);
        let emails = tenant
            .all_emails(Some("admin@fresh"))
            .await
            .expect("emails");
        assert!(
            emails.iter().any(|e| e.verified),
            "the vouched credential must be verified — signin, not signup"
        );
    }

    /// G-131: a seeded user's vouched email lands as a VERIFIED credential
    /// (lowercased), idempotently across re-seeds — which also makes
    /// "add the email, restart" the repair path for an already-booted
    /// credential-less account.
    #[tokio::test]
    async fn seed_user_email_attaches_verified_credential() {
        let storage = crate::db::Storage::init(BOOTSTRAP_STORE_DIR.path())
            .await
            .expect("storage init");
        storage.new_tenant("email-seed").await.expect("tenant");
        let dto = crate::user::UserDTO {
            id: "seeded".into(),
            active: true,
            roles: vec!["user".into()],
            email: Some("Seeded@Example.com".into()),
        };
        let mut tenant = storage.tenant_by_id("email-seed").expect("tenant");
        // user_add_role never creates unknown roles — declare it first.
        tenant
            .role_create(&crate::role::Caller::Bootstrap, "user", 0)
            .await
            .expect("role");
        dto.save(&mut tenant).await.expect("seed user");
        // Seeding runs on every boot — the attach must be idempotent.
        dto.save(&mut tenant).await.expect("re-seed");

        let owner = tenant
            .user_by_email("seeded@example.com")
            .await
            .expect("vouched email attached lowercase");
        assert_eq!(owner.name, "seeded");
        let emails = tenant.all_emails(Some("seeded")).await.expect("emails");
        assert!(
            emails.iter().any(|e| e.verified),
            "the vouched credential must be verified — signin, not signup"
        );
    }
}
