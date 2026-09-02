use crate::domain::Domain;
use crate::jwt::InvalidJwt;
use crate::key::Key;
use crate::policy::Policy;
use crate::server::JanuxConfig;
use anyhow::Result;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use dashmap::mapref::one::RefMut;
use jiff;
use salvo::oapi::ToSchema;
use serde::de::DeserializeOwned;
use std::collections::HashSet;
use tracing::info;

use crate::jwt::{JwtOidcParams, jwt_authenticate, jwt_decode};

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use toasty_driver_turso;
use tokio::fs::*;

#[derive(Eq, Clone, Hash, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    PassKey,
    Email,
    OTP,
    OAuth2,
    TOTP,
}

impl AuthType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthType::PassKey => "passkey",
            AuthType::Email => "email",
            AuthType::OTP => "otp",
            AuthType::OAuth2 => "oauth2",
            AuthType::TOTP => "totp",
        }
    }
    pub fn _all_str() -> HashSet<&'static str> {
        let mut ret = HashSet::new();
        ret.insert("passkey");
        ret.insert("email");
        ret.insert("otp");
        ret.insert("oauth2");
        ret.insert("totp");
        ret
    }
}

pub fn amr_values(mfa: &HashSet<String>) -> Option<Vec<String>> {
    let mut out: Vec<String> = mfa
        .iter()
        .filter_map(|label| match label.as_str() {
            "passkey" => Some("hwk"),
            "email" => Some("mca"),
            "otp" => Some("sms"),
            "totp" => Some("otp"),
            _ => None, // "oauth2", legacy "Social", anything unknown
        })
        .map(str::to_string)
        .collect();
    if out.is_empty() {
        return None;
    }
    out.sort();
    out.dedup();
    Some(out)
}

pub fn acr_value(mfa: &HashSet<String>) -> Option<String> {
    if mfa.is_empty() {
        return None;
    }
    if mfa.contains("totp") && mfa.len() > 1 {
        Some("2".to_string())
    } else {
        Some("1".to_string())
    }
}

#[derive(Debug, PartialEq, toasty::Embed, Serialize, Deserialize, Clone, ToSchema)]
pub enum HttpMethod {
    #[column(variant = 1)]
    GET,

    #[column(variant = 2)]
    POST,

    #[column(variant = 3)]
    PUT,

    #[column(variant = 4)]
    OPTIONS,

    #[column(variant = 5)]
    DELETE,

    #[column(variant = 6)]
    PATCH,

    #[column(variant = 7)]
    CONNECT,

    #[column(variant = 8)]
    HEAD,

    #[column(variant = 9)]
    TRACE,
}

impl HttpMethod {
    pub fn to_string(&self) -> String {
        match &self {
            HttpMethod::CONNECT => "CONNECT".to_string(),
            HttpMethod::HEAD => "HEAD".to_string(),
            HttpMethod::TRACE => "TRACE".to_string(),
            HttpMethod::PATCH => "PATCH".to_string(),
            HttpMethod::DELETE => "DELETE".to_string(),
            HttpMethod::OPTIONS => "OPTIONS".to_string(),
            HttpMethod::PUT => "PUT".to_string(),
            HttpMethod::POST => "POST".to_string(),
            HttpMethod::GET => "GET".to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JwtData {
    /// The user's surrogate key (`User.id`, UUID) as a string — matches
    /// the token `sub`. Stable across renames.
    pub user: String,
    /// The login name at mint time (SCIM `userName`); informational — all
    /// authorization decisions key off `user`.
    pub username: String,
    pub domain: String,
    pub mfa: HashSet<String>,
    pub roles: HashSet<String>,
}

/// Claims payloads that the shared validation primitive
/// ([`crate::utils::validate_token`]) can decide over.
///
/// Internal session tokens carry [`JwtData`]; OIDC access/refresh tokens are
/// decoded as [`serde_json::Value`] because their payload shapes differ per
/// token kind. The trait exposes exactly the three facts the primitive needs:
/// the tenant-domain binding, the `typ` marker, and — only for internal
/// session claims — the typed data the policy engine evaluates.
pub trait TokenPayload {
    /// The tenant domain the token is bound to, when the payload carries one.
    fn bound_domain(&self) -> Option<&str>;
    /// The token-type marker (`typ`), when the payload carries one.
    fn typ(&self) -> Option<&str>;
    /// The payload as internal session claims. Only `JwtData` tokens can be
    /// evaluated by the tenant policy engine; every other payload is denied
    /// by default when a policy check is requested.
    fn jwt_data(&self) -> Option<&JwtData>;
}

impl TokenPayload for JwtData {
    fn bound_domain(&self) -> Option<&str> {
        Some(&self.domain)
    }
    fn typ(&self) -> Option<&str> {
        None
    }
    fn jwt_data(&self) -> Option<&JwtData> {
        Some(self)
    }
}

impl TokenPayload for serde_json::Value {
    fn bound_domain(&self) -> Option<&str> {
        self.get("domain").and_then(|v| v.as_str())
    }
    fn typ(&self) -> Option<&str> {
        self.get("typ").and_then(|v| v.as_str())
    }
    fn jwt_data(&self) -> Option<&JwtData> {
        None
    }
}

async fn ensure_dir(dir: &Path) -> Result<(), std::io::Error> {
    let exists = try_exists(dir).await?;
    if !exists {
        create_dir_all(dir).await?;
    }
    if metadata(dir).await?.is_dir() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a directory", dir.display()),
        ))
    }
}

#[derive(Clone, Debug)]
pub struct JwtVerify {
    pub can_access: bool,
    pub jwt_data: JwtData,
    pub expect_mfa: bool,
    pub domain: String,
    /// When the user originally authenticated (OIDC Core §2 `auth_time`).
    /// Carried through refresh so token rotation never resets it.
    pub auth_time: Option<usize>,
}

pub type PolicyCache = DashMap<String, DashMap<String, Vec<Policy>>>;

pub struct Tenant {
    pub name: String,
    pub database: toasty::Db,
    pub keys: DashMap<String, Key>, //domain -> Key
    pub policies: PolicyCache,      // domain -> role -> Policy
}

impl Tenant {
    // key CRUD
    /// Issue an internal JWT. `issuer` is the canonical issuer URL for the
    /// request's tenant (`crate::utils::get_issuer`) and becomes the `iss`
    /// claim; `domain` is the registered tenant domain used for signing-key
    /// lookup and as the internal audience.
    pub async fn jwt_authenticate<T: Serialize + Clone>(
        &mut self,
        issuer: &str,
        domain: &str,
        sub: &str,
        data: &T,
        minutes: i32,
    ) -> Result<String> {
        let ekey = self.current_key(domain)?;
        let jwt = jwt_authenticate(
            issuer,
            sub,
            data,
            &ekey,
            minutes,
            JwtOidcParams {
                client_id: domain.to_string(),
                nonce: Some(uuid::Uuid::new_v4().to_string()),
                amr: None,
                acr: None,
                access_token: None,
                auth_time: None,
            },
        )?;
        Ok(jwt)
    }
    pub async fn jwt_verify<T>(&mut self, issuer: &str, sub: &str, token: &str) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let all_data = jwt_decode::<T>(token, 2, self).await?;
        if all_data.claims.iss != issuer {
            return Err(anyhow::anyhow!(
                "Invalid token issuer {} vs. {}",
                all_data.claims.iss,
                issuer
            ));
        }
        if all_data.claims.sub != sub {
            return Err(anyhow::anyhow!(
                "Invalid token subject {} vs. {}",
                all_data.claims.sub,
                sub
            ));
        }
        Ok(all_data.claims.data)
    }

    pub async fn authenticate_jwt(
        &mut self,
        mfa: &HashSet<String>,
        issuer: &str,
        domain: &str,
        user_name: &str,
        minutes: i32,
    ) -> Result<String> {
        let ekey = self.current_key(domain)?;
        let user = self.user(user_name).await?;
        // boundary: login is a central round-trip, so a deactivated user
        // cannot start a NEW session through any factor (email/OTP/TOTP/
        // passkey/social all mint through here). Already-issued tokens are
        // left to expire on their own — JWT verification stays stateless by
        // design; deactivation propagates within one token lifetime because
        // refresh (the only extension point) re-checks the user too.
        if !user.active {
            return Err(anyhow::anyhow!("user '{}' is deactivated", user_name));
        }
        let roles = self.user_roles(user.id).await?;
        let data = JwtData {
            user: user.id.to_string(),
            username: user.name.clone(),
            mfa: mfa.clone(),
            domain: domain.to_string(),
            roles: HashSet::from_iter(roles.into_iter().map(|a| a.id)),
        };
        let jwt = jwt_authenticate(
            issuer,
            &user.id.to_string(),
            &data,
            &ekey,
            minutes,
            JwtOidcParams {
                client_id: domain.to_string(),
                nonce: Some(uuid::Uuid::new_v4().to_string()),
                amr: amr_values(mfa),
                acr: acr_value(mfa),
                access_token: None,
                // Fresh authentication just happened — stamp now (OIDC Core §2).
                auth_time: None,
            },
        )?;
        crate::ops::token_issued("session");
        Ok(jwt)
    }
    /// Refresh an internal session JWT.
    ///
    /// Runs through the SAME rotation logic as the OIDC `handle_refresh`:
    /// the presented
    /// token is validated via the shared primitive (which also enforces the
    /// revocation gate), a successor is signed BEFORE any state is
    /// mutated, and the atomic commit point revokes the presented token in
    /// the persistent `InvalidJwt` store. The old token never survives its
    /// refresh, and presenting an already-rotated (or logged-out) token is
    /// refused — the internal path no longer diverges from the OIDC one.
    pub async fn refresh_jwt(
        &mut self,
        issuer: &str,
        domain: &str,
        jwt: &str,
        minutes: i32,
    ) -> Result<String> {
        // Signature, expiry, issuer and revocation in one primitive. Revoked
        // (logged-out OR already-rotated) tokens fail here, so a stolen
        // token cannot be refreshed back into a session. The policy engine
        // is deliberately NOT consulted: the pre-consolidation path ran it
        // and discarded its verdict, and tenants hold no grants for
        // `auth/refresh` — gating rotation on RBAC would break every
        // existing session. Validity alone decides, as before.
        let decision = crate::utils::validate_token::<JwtData>(
            self,
            issuer,
            domain,
            jwt,
            crate::utils::ValidateOpts::default(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        // boundary: refresh is the only point where a stateless session
        // can be EXTENDED, and it is a central round-trip by definition — so
        // the user's live state is re-checked here, not at verify time (JWT
        // validation must stay stateless/distributed). A deactivated user's
        // current token runs out its lifetime but can never be renewed. A
        // DELETED user fails closed too: deletion cascades every
        // credential (see `user_delete_cascades_credentials`), so no new
        // login is possible — the refresh boundary must not keep extending
        // the old session either. Checked before any mutation so a refused
        // request does not consume the presented token.
        let user_id = uuid::Uuid::try_parse(&decision.claims.data.user)
            .map_err(|_| anyhow::anyhow!("token subject is not a valid user id"))?;
        let user = match self.user_by_id(user_id).await {
            Ok(user) if user.active => user,
            Ok(_) => {
                return Err(anyhow::anyhow!(
                    "user '{}' is deactivated",
                    decision.claims.data.username
                ));
            }
            Err(_) => {
                return Err(anyhow::anyhow!(
                    "user '{}' no longer exists",
                    decision.claims.data.username
                ));
            }
        };
        // Sign the successor BEFORE consuming the presented token (same
        // safety ordering as handle_refresh): a signing failure must never
        // strand the client with a revoked token and no response.
        let key = self.current_key(domain)?;
        let mut d = decision.claims.data;
        // Keep the informational name claim current across rotation.
        d.username = user.name.clone();
        let new_jwt = jwt_authenticate(
            issuer,
            &d.user,
            &d,
            &key,
            minutes,
            JwtOidcParams {
                client_id: domain.to_string(),
                nonce: Some(uuid::Uuid::new_v4().to_string()),
                // Same factor set as the original token — re-derive so the
                // claim stays populated through rotation.
                amr: amr_values(&d.mfa),
                acr: acr_value(&d.mfa),
                access_token: None,
                // Preserve the ORIGINAL authentication time: refresh does not
                // re-authenticate the user, so stamping now would break
                // max_age decisions at relying parties (OIDC Core section 2).
                auth_time: decision.claims.auth_time,
            },
        )?;
        // Atomic commit point: revoke the presented token (insert-wins). An
        // expired-but-within-leeway token is rotated exactly like a live one
        // — the old behavior of handing the same expired token back
        // is gone. Exactly one concurrent presenter of the same token wins;
        // every loser is refused as reuse.
        let exp = jiff::Timestamp::from_second(decision.claims.exp as i64)?;
        match crate::utils::revoke_token(self, jwt, Some(exp), "internal refresh rotation").await {
            Ok(true) => {
                crate::ops::token_refreshed("session");
                Ok(new_jwt)
            }
            Ok(false) => Err(anyhow::anyhow!(
                "refresh token reuse detected; the token was already rotated"
            )),
            Err(e) => Err(e),
        }
    }

    pub async fn new(name: &str, db: toasty::Db) -> Result<Tenant> {
        let mut ret = Tenant {
            name: name.to_string(),
            database: db,
            keys: DashMap::new(),
            policies: DashMap::new(),
        };
        ret.policies = ret.all_policy_entries().await?;
        ret.keys = ret.active_key_cache().await?;
        Ok(ret)
    }
}

async fn connect_tenant(dir: &Path) -> toasty::Result<toasty::Db> {
    ensure_dir(dir).await?;
    let path = PathBuf::from(dir).join("janux.db");
    let driver = toasty_driver_turso::Turso::file(path).concurrent_writes();
    info!("create tenant {}", dir.display());
    let db = toasty::Db::builder()
        .models(toasty::models!(crate::*))
        .build(driver)
        .await
        .unwrap();
    match db.push_schema().await {
        Ok(_) => Ok(db),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("table") && msg.contains("already exists") {
                Ok(db)
            } else {
                Err(e)
            }
        }
    }
}

/// Process-wide tenant registry and domain router.
///
/// Concurrency model (README §6): same-tenant requests are serialized
/// within this process by the `RefMut` write guard handed out by
/// `tenant_by_domain` / `tenant_by_id`, which handlers hold from tenant
/// resolution to the end of the request. The check-then-act sequences
/// inside a tenant (identity claims, `user.active` transitions, refresh
/// rotation, key/policy cache updates) rely on that serialization — it
/// is deliberate design, not an accident of DashMap. Tenant/domain
/// lifecycle mutations run outside any tenant guard and are serialized
/// separately by `topology`. The guarantee is per-process: nothing here
/// coordinates across instances sharing a data dir.
pub struct Storage {
    pub raw_path: std::path::PathBuf,
    pub tenants: DashMap<String, Tenant>,
    pub router: DashMap<String, String>,
    /// Serializes topology mutations (tenant/domain create and delete).
    /// The maps above are concurrent, but the multi-step sequences that
    /// keep `router` and the per-tenant databases in agreement are not
    /// atomic on their own: two racing `add_domain` calls for the same
    /// domain could both pass the registration check and persist the
    /// domain into two different tenant databases. Read paths
    /// (`tenant_by_domain`, …) never take this lock.
    pub topology: tokio::sync::Mutex<()>,
}

impl Storage {
    pub async fn domain_cors(&self, domain: &str, cors: Vec<String>) -> Result<()> {
        let tenant = self.tenant_by_domain(domain);
        if tenant.is_some() {
            tenant.unwrap().domain_cors(domain, cors).await
        } else {
            Err(anyhow::anyhow!("Unknown domain '{}'", domain))
        }
    }
    pub async fn load_domain(&self, domain: &str) -> Result<Domain> {
        let tenant = self.tenant_by_domain(domain);
        if tenant.is_some() {
            tenant.unwrap().domain(domain).await
        } else {
            Err(anyhow::anyhow!("Unknown domain '{}'", domain))
        }
    }
    pub async fn load_domain_cors(&self, domain: &str) -> Result<Vec<String>> {
        if let Ok(d) = self.load_domain(domain).await {
            if d.cors.len() == 1 && d.cors[0] == "tenant" {
                if let Some(mut t) = self.tenant_by_domain(domain) {
                    //share among tenant
                    let all = t.all_domains().await;
                    return Ok(all.iter().map(|a| a.id.clone()).collect());
                }
            } else if d.cors.len() == 0 {
                return Ok(vec![]);
            //allow nothing
            } else {
                //custom cors
                return Ok(d.cors);
            }
        }
        Err(anyhow::anyhow!("Error loading domain"))
    }
    pub async fn add_domain(&self, domain: &str, tenant: &str) -> Result<()> {
        // Check-then-create-then-register must be atomic, or two racing
        // adds could persist the same domain into two tenant databases.
        let _guard = self.topology.lock().await;
        if self.router.contains_key(domain) {
            return Err(anyhow::anyhow!(
                "Domain '{}' is already registered to a tenant",
                domain
            ));
        }
        let mut tenant_handle = self
            .tenants
            .get_mut(tenant)
            .ok_or_else(|| anyhow::anyhow!("Tenant '{}' not found", tenant))?;
        tenant_handle
            .domain_create(domain, vec![], None, None, None)
            .await?;
        self.router.insert(domain.to_string(), tenant.to_string());
        Ok(())
    }
    pub async fn remove_domain(&self, domain: &str, tenant: &str) -> Result<()> {
        let _guard = self.topology.lock().await;
        let tenant_name = self
            .router
            .get(domain)
            .ok_or_else(|| anyhow::anyhow!("Domain '{}' not found", domain))?
            .clone();
        if tenant_name != tenant {
            return Err(anyhow::anyhow!("Tenant mismatch"));
        }
        let mut tenant = self
            .tenants
            .get_mut(&tenant_name)
            .ok_or_else(|| anyhow::anyhow!("Tenant '{}' not found", tenant_name))?;
        tenant.domain_delete(domain).await?;

        self.router.remove(domain);
        Ok(())
    }

    pub async fn all_tenants(&self) -> Result<Vec<String>> {
        let mut ret = Vec::new();
        for t in self.tenants.iter() {
            ret.push(t.value().name.clone());
        }
        Ok(ret)
    }

    /// Resolve the tenant serving `domain`.
    ///
    /// The returned `RefMut` is a shard **write lock** on the tenant map:
    /// while a handler holds it, no other same-tenant request in this
    /// process makes progress. That serialization is what the
    /// check-then-act flows rely on (README §6), so the guard must be
    /// held to the END of the multi-step flow — never dropped mid-flow
    /// and re-acquired, and never replaced by `tenants.get()` (a read
    /// ref) in a path that mutates.
    pub fn tenant_by_domain(&self, domain: &str) -> Option<RefMut<'_, String, Tenant>> {
        // Timed for janux_tenant_guard_wait_seconds: the shard-lock wait is
        // the head-of-line cost accepted in README §6, and this histogram is
        // how it becomes visible. Recording includes the uncontended fast
        // path on purpose — contention shows up as tail latency.
        let start = std::time::Instant::now();
        let ret = self
            .router
            .get(domain)
            .and_then(|id| self.tenants.get_mut(id.value()));
        crate::ops::record_guard_wait(start.elapsed());
        ret
    }
    /// Resolve a tenant by name. Same guard contract as
    /// [`Self::tenant_by_domain`] (README §6).
    pub fn tenant_by_id(&self, id: &str) -> Option<RefMut<'_, String, Tenant>> {
        let start = std::time::Instant::now();
        let ret = self.tenants.get_mut(id);
        crate::ops::record_guard_wait(start.elapsed());
        ret
    }

    pub async fn new_tenant(&self, name: &str) -> Result<RefMut<'_, String, Tenant>> {
        // Tenant names share the resolution namespace with domains; the
        // collision check below must be atomic with respect to
        // concurrent add_domain calls.
        let _guard = self.topology.lock().await;
        // validate before the name touches a filesystem path.
        let path = self.tenant_path(name)?;
        if self.router.contains_key(name) {
            return Err(anyhow::anyhow!("Tenant '{}' already exists", name));
        }
        if path.exists() {
            return Err(anyhow::anyhow!(
                "Tenant '{}' directory exists but was not loaded",
                name
            ));
        }
        let db = connect_tenant(&path).await?;
        let tenant = Tenant::new(name, db).await?;

        match self.tenants.entry(name.to_string()) {
            Entry::Occupied(_v) => {
                return Err(anyhow::anyhow!("Tenant '{}' already exists", name));
            }
            Entry::Vacant(v) => {
                v.insert(tenant);
            }
        }
        let ret = self.tenant_by_id(name);
        assert!(ret.is_some());
        Ok(ret.unwrap())
    }

    pub async fn delete_tenant(&self, name: &str) -> Result<()> {
        // Deleting a tenant removes its router entries; racing with
        // add_domain could otherwise leave a dangling router entry
        // pointing at a deleted tenant.
        let _guard = self.topology.lock().await;
        // 1. Validate tenant exists
        let tenant_exists = self.tenants.contains_key(name);
        if !tenant_exists {
            return Err(anyhow::anyhow!("Tenant '{}' not found", name));
        }

        // 2. Remove all router entries for this tenant
        let domains: Vec<String> = self
            .router
            .iter()
            .filter(|entry| entry.value() == name)
            .map(|entry| entry.key().clone())
            .collect();
        for domain in &domains {
            self.router.remove(domain);
        }

        // 3. Remove tenant from in-memory storage
        self.tenants.remove(name);
        let directory = self.directory();
        // 4. Backup the db file before deletion. re-derive the
        // location through the validated path — never join a raw name.
        let tenant_dir = self.tenant_path(name)?;
        if tenant_dir.is_dir() {
            let pdir = directory
                .parent()
                .map_or_else(|| directory.as_path(), |a| a);
            let backup_dir = pdir.join("backups");
            ensure_dir(backup_dir.as_path()).await?;

            let timestamp = std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs();

            let backup_name = format!("{}-{:x}", name, timestamp);
            let backup_path = backup_dir.join(&backup_name);
            create_dir_all(&backup_path).await.ok(); // ignore race if concurrent delete

            // Copy janux.db to backup (async)
            let db_src = tenant_dir.join("janux.db");
            if let Ok(content) = read(&db_src).await {
                match write(backup_path.join("janux.db"), &content).await {
                    Err(e) => {
                        tracing::error!(tenant = name, "Failed to backup db: {}", e);
                    }
                    Ok(()) => {
                        tracing::info!(tenant = name, backup = %backup_path.display(), "Tenant db backed up");
                    }
                }
            }
        }

        // 5. Remove tenant directory on disk (async)
        if try_exists(&tenant_dir).await.ok().unwrap_or(false) {
            remove_dir_all(&tenant_dir).await?;
        }

        tracing::info!(tenant = name, "Tenant deleted successfully");
        Ok(())
    }

    async fn load_tenant(&mut self, name: &str) -> Result<()> {
        // a directory on disk is not a valid tenant name by
        // construction — refuse to load it instead of mounting it.
        let path = self.tenant_path(name)?;
        match self.tenants.entry(name.into()) {
            Entry::Occupied(_v) => {
                return Err(anyhow::anyhow!("Tenant '{}' already loaded", name));
            }
            Entry::Vacant(v) => {
                let db = connect_tenant(&path).await?;
                let mut tenant = Tenant::new(name, db).await?;
                let domains = tenant.all_domains().await;
                v.insert(tenant);
                for d in domains {
                    match self.router.entry(d.id.clone()) {
                        Entry::Vacant(v) => {
                            v.insert(name.into());
                        }
                        Entry::Occupied(v) => {
                            return Err(anyhow::anyhow!(
                                "Domain: '{}' is served by tenant '{}' already, can not server by tenant '{}' again.",
                                d.id,
                                v.get(),
                                name
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn seed(&mut self, config: &JanuxConfig) -> Result<Self> {
        if let Some(data) = &config.seed {
            for d in data {
                d.save(self).await?;
            }
        }
        Storage::init(&self.raw_path).await
    }

    fn directory(&self) -> std::path::PathBuf {
        self.raw_path.join("tenants")
    }

    /// tenant names become filesystem path components under
    /// `directory()`. The strict charset rules out `../`, absolute paths,
    /// and every other path metacharacter; the length bound keeps the
    /// name within filesystem component limits.
    pub fn valid_tenant_name(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= 64
            && name
                .chars()
                .all(|c| matches!(c, 'a'..='z' | '0'..='9' | '-'))
    }

    /// the on-disk location of a tenant. Rejects invalid names and
    /// asserts the join stays inside the tenant root — defense in depth
    /// on top of the charset, so no future caller can reintroduce a
    /// traversal by bypassing the check.
    fn tenant_path(&self, name: &str) -> Result<PathBuf> {
        if !Self::valid_tenant_name(name) {
            return Err(anyhow::anyhow!(
                "Invalid tenant name '{}': 1-64 characters of [a-z0-9-]",
                name
            ));
        }
        let dir = self.directory();
        let path = dir.join(name);
        if path.parent() != Some(dir.as_path()) {
            return Err(anyhow::anyhow!("Tenant path escapes the data directory"));
        }
        Ok(path)
    }

    pub async fn init(path: &Path) -> Result<Self> {
        let dir = path.join("tenants");
        ensure_dir(dir.as_path()).await?;
        // One process-wide revocation store shared by every writer and every
        // revocation check (first init wins; seed re-runs are no-ops).
        InvalidJwt::init_global(path).await?;
        let mut storage = Self {
            raw_path: path.to_path_buf(),
            tenants: DashMap::new(),
            router: DashMap::new(),
            topology: tokio::sync::Mutex::new(()),
        };
        let mut entries = read_dir(dir.as_path()).await?;
        let mut loaded = 0usize;
        let mut failed = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.is_dir() {
                let tenant_name = path.file_name().and_then(|n| n.to_str()).unwrap();
                if let Err(e) = storage.load_tenant(tenant_name).await {
                    tracing::error!(tenant = tenant_name, "Failed to load tenant: {}", e);
                    failed.push((tenant_name.to_string(), e));
                } else {
                    loaded += 1;
                }
            }
        }
        let total = loaded + failed.len();
        if !failed.is_empty() && loaded == 0 {
            for (name, err) in &failed {
                tracing::error!(tenant = name, "Tenant boot failed: {}", err);
            }
            anyhow::bail!(
                "No tenants could be loaded from '{}'. Failed {}/{}: {}. Aborting.",
                dir.display(),
                total,
                total,
                failed
                    .iter()
                    .map(|(n, _)| n.clone())
                    .collect::<Vec<String>>()
                    .join(", ")
            );
        }
        if !failed.is_empty() {
            tracing::warn!(
                loaded,
                "Loaded {}/{} tenants. Failed: {}.",
                loaded,
                total,
                failed
                    .iter()
                    .map(|(n, _)| n.clone())
                    .collect::<Vec<String>>()
                    .join(", ")
            );
        }
        Ok(storage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::LazyLock;

    const DOMAIN: &str = "localhost";
    const TEST_ISSUER: &str = "http://localhost";

    /// The revocation store is a process-wide singleton, so all tests share one
    /// backing directory that must outlive every individual test's TempDir
    /// (same pattern as the totp.rs/oidc.rs endpoint tests).
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
                InvalidJwt::init_global(TEST_STORE_DIR.path())
                    .await
                    .expect("init revocation store");
            }))
            .await
            .expect("store init task");
    }

    /// In-process tenant with a signing key and one user.
    async fn refresh_test_env() -> (Storage, tempfile::TempDir) {
        init_revocation_store().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage = Storage::init(tmp.path()).await.expect("storage init");
        storage.new_tenant("test-tenant").await.expect("tenant");
        storage
            .add_domain(DOMAIN, "test-tenant")
            .await
            .expect("domain");
        {
            let mut tenant = storage.tenant_by_id("test-tenant").expect("tenant");
            tenant
                .key_create(DOMAIN, "key1")
                .await
                .expect("signing key");
            tenant.user_create("alice").await.expect("user");
        }
        (storage, tmp)
    }

    fn refresh<'a>(
        tenant: &'a mut Tenant,
        token: &'a str,
    ) -> impl std::future::Future<Output = Result<String>> + 'a {
        tenant.refresh_jwt(TEST_ISSUER, DOMAIN, token, 15)
    }

    #[tokio::test]
    async fn refresh_of_live_token_issues_a_new_one() {
        let (storage, _tmp) = refresh_test_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        let token = tenant
            .authenticate_jwt(&HashSet::new(), TEST_ISSUER, DOMAIN, "alice", 15)
            .await
            .expect("token");

        let refreshed = refresh(&mut tenant, &token)
            .await
            .expect("refresh of a valid token succeeds");
        assert!(!refreshed.is_empty());
        assert_ne!(refreshed, token, "rotation must issue a NEW token");
    }

    /// regression: logout revokes the token in the `InvalidJwt` store;
    /// refresh must consult that store too, otherwise a logged-out (stolen)
    /// token can be refreshed back into a fresh valid session and logout is
    /// defeatable.
    #[tokio::test]
    async fn refresh_rejects_a_revoked_token() {
        let (storage, _tmp) = refresh_test_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        let token = tenant
            .authenticate_jwt(&HashSet::new(), TEST_ISSUER, DOMAIN, "alice", 15)
            .await
            .expect("token");

        // Logout: revoke the presented token (src/verify.rs `logout`).
        InvalidJwt::global()
            .invalid(&token, &mut tenant)
            .await
            .expect("revoke");
        assert!(
            InvalidJwt::global().is_valid(&token).await,
            "token must be recorded as revoked"
        );

        let refreshed = refresh(&mut tenant, &token).await;
        assert!(
            refreshed.is_err(),
            "a revoked (logged-out) token must not be refreshable"
        );
    }

    // ── Step 1.3 / internal refresh rotates like the OIDC path ────────

    /// The asymmetry: the internal path used to keep the old token
    /// alive after a refresh. Rotation must revoke the presented token and
    /// hand out a distinct successor that is itself a valid session.
    #[tokio::test]
    async fn refresh_rotation_revokes_the_presented_token() {
        let (storage, _tmp) = refresh_test_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        let alice = tenant.user("alice").await.expect("alice");
        let token = tenant
            .authenticate_jwt(&HashSet::new(), TEST_ISSUER, DOMAIN, "alice", 15)
            .await
            .expect("token");

        let refreshed = refresh(&mut tenant, &token)
            .await
            .expect("refresh succeeds");
        assert!(
            InvalidJwt::global().is_valid(&token).await,
            "the presented token must be revoked by its own rotation"
        );
        assert!(
            !InvalidJwt::global().is_valid(&refreshed).await,
            "the successor must not be revoked"
        );
        let session = crate::utils::validate_token::<JwtData>(
            &mut tenant,
            TEST_ISSUER,
            DOMAIN,
            &refreshed,
            crate::utils::ValidateOpts {
                domain_bound: true,
                ..Default::default()
            },
        )
        .await
        .expect("the successor validates as a session");
        assert_eq!(session.claims.data.user, alice.id.to_string());
    }

    /// Reuse refusal: presenting an already-rotated token again must fail.
    /// The OIDC path always had this (insert-wins commit point); the
    /// internal path now shares it.
    #[tokio::test]
    async fn refresh_rejects_reuse_of_a_rotated_token() {
        let (storage, _tmp) = refresh_test_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        let token = tenant
            .authenticate_jwt(&HashSet::new(), TEST_ISSUER, DOMAIN, "alice", 15)
            .await
            .expect("token");

        refresh(&mut tenant, &token).await.expect("first rotation");
        assert!(
            refresh(&mut tenant, &token).await.is_err(),
            "a token that was already rotated must be refused as reuse"
        );
    }

    /// The second defect: refreshing an expired-but-within-leeway token
    /// used to hand the SAME expired token back. It is now rotated like any
    /// live token — new successor, old token revoked.
    #[tokio::test]
    async fn refresh_rotates_an_expired_within_leeway_token() {
        let (storage, _tmp) = refresh_test_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        let key = tenant.current_key(DOMAIN).expect("signing key");
        let alice = tenant.user("alice").await.expect("alice exists");
        let data = JwtData {
            user: alice.id.to_string(),
            username: "alice".into(),
            domain: DOMAIN.into(),
            mfa: HashSet::new(),
            roles: HashSet::new(),
        };
        // Negative lifetime: expired 60s ago — inside jwt_decode's 2-minute
        // leeway, exactly the window the old behavior leaked through.
        let token = crate::jwt::jwt_authenticate(
            TEST_ISSUER,
            &alice.id.to_string(),
            &data,
            &key,
            -1,
            crate::jwt::JwtOidcParams {
                client_id: DOMAIN.to_string(),
                nonce: None,
                amr: None,
                acr: None,
                access_token: None,
                auth_time: None,
            },
        )
        .expect("expired token");

        let refreshed = refresh(&mut tenant, &token)
            .await
            .expect("an expired-within-leeway token rotates instead of bouncing back");
        assert_ne!(refreshed, token, "the same expired token must not return");
        assert!(
            InvalidJwt::global().is_valid(&token).await,
            "the expired token must be revoked by its rotation"
        );
    }

    // ── Step 4: role assignment never creates roles ─────────────────────────

    /// prerequisite: `user_add_role`
    /// must resolve an existing role instead of silently inventing an empty
    /// one — roles are created only via the seed `roles` list or
    /// `admin/role/create`, mirroring `policy_create`'s pre-existing-role
    /// requirement.
    #[tokio::test]
    async fn user_add_role_rejects_unknown_roles() {
        let (storage, _tmp) = refresh_test_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        let bootstrap = crate::role::Caller::Bootstrap;

        tenant
            .user_add_role(&bootstrap, "alice", "ghost")
            .await
            .expect_err("assigning an undeclared role must fail");

        tenant
            .role_create(&bootstrap, "user", 0)
            .await
            .expect("role");
        tenant
            .user_add_role(&bootstrap, "alice", "user")
            .await
            .expect("assigning a declared role succeeds");
    }

    // ── bounded role hierarchy ────────────────────────────────────────

    /// Tenant with the builtin catalog and three users: alice holds `admin`,
    /// bob holds `user`, carol holds `root`+`admin`+`user` — the standard
    /// level-gate test vectors.
    async fn role_gate_env() -> (Storage, tempfile::TempDir) {
        let (storage, tmp) = refresh_test_env().await;
        {
            let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
            let bootstrap = crate::role::Caller::Bootstrap;
            for (name, _) in crate::role::BUILTIN_ROLES {
                tenant
                    .role_create(&bootstrap, name, 0)
                    .await
                    .expect("builtin role");
            }
            tenant.user_create("bob").await.expect("user");
            tenant.user_create("carol").await.expect("user");
            tenant
                .user_add_role(&bootstrap, "alice", "admin")
                .await
                .expect("grant");
            tenant
                .user_add_role(&bootstrap, "bob", "user")
                .await
                .expect("grant");
            for role in ["root", "admin", "user"] {
                tenant
                    .user_add_role(&bootstrap, "carol", role)
                    .await
                    .expect("grant");
            }
        }
        (storage, tmp)
    }

    fn jwt_caller(user: &str, roles: &[&str]) -> crate::role::Caller {
        crate::role::Caller::Jwt(JwtData {
            user: user.to_string(),
            username: user.to_string(),
            domain: DOMAIN.to_string(),
            mfa: HashSet::new(),
            roles: roles.iter().map(|s| s.to_string()).collect(),
        })
    }

    fn is_forbidden(err: &anyhow::Error) -> bool {
        matches!(
            err.downcast_ref::<crate::role::AdminError>(),
            Some(crate::role::AdminError::Forbidden)
        )
    }

    fn is_conflict(err: &anyhow::Error) -> bool {
        matches!(
            err.downcast_ref::<crate::role::AdminError>(),
            Some(crate::role::AdminError::Conflict(_))
        )
    }

    /// §1.3: effective level is the max over resolvable JWT roles; Bootstrap
    /// is unrestricted; unresolvable names contribute nothing.
    #[tokio::test]
    async fn effective_level_is_the_max_resolvable_role_level() {
        let (storage, _tmp) = role_gate_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        assert_eq!(
            tenant
                .effective_level(&crate::role::Caller::Bootstrap)
                .await,
            Some(i64::MAX)
        );
        assert_eq!(
            tenant
                .effective_level(&jwt_caller("alice", &["admin"]))
                .await,
            Some(80)
        );
        assert_eq!(
            tenant
                .effective_level(&jwt_caller("carol", &["root", "admin", "user"]))
                .await,
            Some(100)
        );
        assert_eq!(
            tenant.effective_level(&jwt_caller("bob", &["user"])).await,
            Some(40)
        );
        assert_eq!(
            tenant
                .effective_level(&jwt_caller("mallory", &["ghost"]))
                .await,
            None
        );
    }

    /// R1 (E1/E2/E7/E8): grants require a strictly higher level; nobody
    /// grants `root`; self-targeting is subsumed, not special-cased.
    #[tokio::test]
    async fn grant_requires_strictly_higher_level() {
        let (storage, _tmp) = role_gate_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        let alice = jwt_caller("alice", &["admin"]);
        let carol = jwt_caller("carol", &["root", "admin", "user"]);

        let err = tenant
            .user_add_role(&alice, "alice", "root")
            .await
            .expect_err("admin cannot self-grant root");
        assert!(is_forbidden(&err));
        let err = tenant
            .user_add_role(&alice, "alice", "admin")
            .await
            .expect_err("admin cannot self-grant admin");
        assert!(is_forbidden(&err));
        let err = tenant
            .user_add_role(&alice, "bob", "admin")
            .await
            .expect_err("admin cannot grant a peer role");
        assert!(is_forbidden(&err));

        tenant
            .user_add_role(&alice, "bob", "guest")
            .await
            .expect("downward grant succeeds");

        tenant
            .user_add_role(&carol, "bob", "admin")
            .await
            .expect("root delegates tenant admins");

        let err = tenant
            .user_add_role(&carol, "bob", "root")
            .await
            .expect_err("nobody grants root");
        assert!(is_forbidden(&err));
    }

    /// R2: revocation is symmetric to grant — peers cannot strip each other's
    /// roles.
    #[tokio::test]
    async fn revoke_is_symmetric_to_grant() {
        let (storage, _tmp) = role_gate_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        let alice = jwt_caller("alice", &["admin"]);
        let carol = jwt_caller("carol", &["root", "admin", "user"]);

        tenant
            .user_add_role(&carol, "bob", "admin")
            .await
            .expect("setup");

        let err = tenant
            .user_del_role(&alice, "bob", "admin")
            .await
            .expect_err("admin cannot strip a peer's admin role");
        assert!(is_forbidden(&err));
        tenant
            .user_del_role(&carol, "bob", "admin")
            .await
            .expect("root revokes admin");

        tenant
            .user_add_role(&alice, "bob", "guest")
            .await
            .expect("setup guest");
        tenant
            .user_del_role(&alice, "bob", "guest")
            .await
            .expect("downward revocation stays allowed");
    }

    /// R5/R6 (E3/E9/E10): policy writes are bounded by the same level test —
    /// a role can never expand its own permission set, and the apex role's
    /// policy set is seed-only.
    #[tokio::test]
    async fn policy_writes_are_bound_by_level() {
        let (storage, _tmp) = role_gate_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        let alice = jwt_caller("alice", &["admin"]);
        let carol = jwt_caller("carol", &["root", "admin", "user"]);
        let bootstrap = crate::role::Caller::Bootstrap;
        let nothing = crate::policy::SourceResolver::Nothing;
        let no_target = crate::policy::TargetResolver::Nothing;

        let err = tenant
            .policy_create(
                &alice,
                DOMAIN,
                None,
                "/api/v1/admin/tenant/delete",
                "admin",
                &nothing,
                &no_target,
                false,
                true,
            )
            .await
            .expect_err("admin cannot empower its own role");
        assert!(is_forbidden(&err));
        let err = tenant
            .policy_create(
                &alice,
                DOMAIN,
                None,
                "/api/v1/app/a",
                "root",
                &nothing,
                &no_target,
                false,
                true,
            )
            .await
            .expect_err("admin cannot empower root");
        assert!(is_forbidden(&err));

        tenant
            .policy_create(
                &alice,
                DOMAIN,
                None,
                "/api/v1/app/b",
                "user",
                &nothing,
                &no_target,
                false,
                true,
            )
            .await
            .expect("admin writes user policy");
        tenant
            .policy_create(
                &alice,
                DOMAIN,
                None,
                "/api/v1/app/c",
                "guest",
                &nothing,
                &no_target,
                false,
                true,
            )
            .await
            .expect("admin writes guest policy");

        tenant
            .policy_create(
                &carol,
                DOMAIN,
                None,
                "/api/v1/app/d",
                "admin",
                &nothing,
                &no_target,
                false,
                true,
            )
            .await
            .expect("root outranks admin");
        let err = tenant
            .policy_create(
                &carol,
                DOMAIN,
                None,
                "/api/v1/app/e",
                "root",
                &nothing,
                &no_target,
                false,
                true,
            )
            .await
            .expect_err("even root cannot expand root's policy set");
        assert!(is_forbidden(&err));

        tenant
            .policy_create(
                &bootstrap,
                DOMAIN,
                None,
                "/api/v1/app/f",
                "root",
                &nothing,
                &no_target,
                false,
                true,
            )
            .await
            .expect("bootstrap policy");
        let err = tenant
            .policy_delete(&alice, DOMAIN, "/api/v1/app/f", None, "root")
            .await
            .expect_err("admin cannot delete root's policy");
        assert!(is_forbidden(&err));
        tenant
            .policy_delete(&alice, DOMAIN, "/api/v1/app/b", None, "user")
            .await
            .expect("admin deletes user policy");
        tenant
            .policy_delete(&carol, DOMAIN, "/api/v1/app/d", None, "admin")
            .await
            .expect("root deletes admin policy");
    }

    /// R3: created roles are born strictly below their creator; builtin names
    /// are reserved; existing names conflict; negative levels are rejected.
    #[tokio::test]
    async fn role_create_is_bound_by_creator_level() {
        let (storage, _tmp) = role_gate_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        let alice = jwt_caller("alice", &["admin"]);
        let carol = jwt_caller("carol", &["root", "admin", "user"]);

        tenant
            .role_create(&alice, "support", 30)
            .await
            .expect("30 < 80");
        tenant
            .role_create(&alice, "edge", 79)
            .await
            .expect("79 < 80");

        let err = tenant
            .role_create(&alice, "ops", 80)
            .await
            .expect_err("at own level");
        assert!(is_forbidden(&err));
        let err = tenant
            .role_create(&alice, "super", 120)
            .await
            .expect_err("above own level");
        assert!(is_forbidden(&err));
        let err = tenant
            .role_create(&alice, "admin", 5)
            .await
            .expect_err("builtin names are reserved");
        assert!(is_forbidden(&err));
        let err = tenant
            .role_create(&carol, "root", 50)
            .await
            .expect_err("reserved for root callers too");
        assert!(is_forbidden(&err));
        let err = tenant
            .role_create(&alice, "support", 30)
            .await
            .expect_err("existing name conflicts");
        assert!(is_conflict(&err));
        tenant
            .role_create(&alice, "neg", -1)
            .await
            .expect_err("negative levels are rejected");

        tenant
            .role_create(&carol, "platform", 99)
            .await
            .expect("root may create just below the apex");
    }

    /// R4: builtin roles are undeletable regardless of caller; custom roles
    /// are deletable only from strictly above.
    #[tokio::test]
    async fn builtin_roles_are_undeletable_and_deletion_is_bounded() {
        let (storage, _tmp) = role_gate_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        let alice = jwt_caller("alice", &["admin"]);
        let carol = jwt_caller("carol", &["root", "admin", "user"]);
        let bootstrap = crate::role::Caller::Bootstrap;

        let err = tenant
            .role_delete(&carol, "admin")
            .await
            .expect_err("builtin undeletable even for root");
        assert!(is_forbidden(&err));
        let err = tenant
            .role_delete(&alice, "guest")
            .await
            .expect_err("builtin undeletable");
        assert!(is_forbidden(&err));

        tenant
            .role_create(&alice, "support", 30)
            .await
            .expect("setup");
        tenant.user_create("dave").await.expect("user");
        tenant
            .user_add_role(&bootstrap, "dave", "guest")
            .await
            .expect("grant");
        let dave = jwt_caller("dave", &["guest"]);
        let err = tenant
            .role_delete(&dave, "support")
            .await
            .expect_err("20 is not above 30");
        assert!(is_forbidden(&err));
        tenant
            .role_delete(&alice, "support")
            .await
            .expect("80 > 30");
    }

    /// §2 corollary: delegated power keeps decreasing — a holder of a custom
    /// mid-level role can only administer roles below it.
    #[tokio::test]
    async fn transitive_delegation_stays_bounded() {
        let (storage, _tmp) = role_gate_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        let alice = jwt_caller("alice", &["admin"]);
        let nothing = crate::policy::SourceResolver::Nothing;
        let no_target = crate::policy::TargetResolver::Nothing;

        tenant
            .role_create(&alice, "support", 30)
            .await
            .expect("create");
        tenant.user_create("dave").await.expect("user");
        tenant
            .user_add_role(&alice, "dave", "support")
            .await
            .expect("grant");

        let dave = jwt_caller("dave", &["support"]);
        tenant
            .user_add_role(&dave, "bob", "guest")
            .await
            .expect("30 > 20");
        let err = tenant
            .user_add_role(&dave, "bob", "support")
            .await
            .expect_err("30 is not above 30");
        assert!(is_forbidden(&err));
        let err = tenant
            .user_add_role(&dave, "bob", "user")
            .await
            .expect_err("30 is not above 40");
        assert!(is_forbidden(&err));
        let err = tenant
            .policy_create(
                &dave,
                DOMAIN,
                None,
                "/api/v1/app/g",
                "user",
                &nothing,
                &no_target,
                false,
                true,
            )
            .await
            .expect_err("policy write bound too");
        assert!(is_forbidden(&err));
        tenant
            .policy_create(
                &dave,
                DOMAIN,
                None,
                "/api/v1/app/h",
                "guest",
                &nothing,
                &no_target,
                false,
                true,
            )
            .await
            .expect("30 > 20 policy");
    }

    /// §1.3 default-deny: a caller whose JWT roles resolve to nothing has no
    /// level and may administer nothing.
    #[tokio::test]
    async fn unresolvable_roles_carry_no_level() {
        let (storage, _tmp) = role_gate_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        let mallory = jwt_caller("mallory", &["ghost"]);
        let nothing = crate::policy::SourceResolver::Nothing;
        let no_target = crate::policy::TargetResolver::Nothing;

        let err = tenant
            .user_add_role(&mallory, "alice", "guest")
            .await
            .expect_err("grant refused");
        assert!(is_forbidden(&err));
        let err = tenant
            .role_create(&mallory, "x", 0)
            .await
            .expect_err("create refused");
        assert!(is_forbidden(&err));
        let err = tenant
            .policy_create(
                &mallory,
                DOMAIN,
                None,
                "/api/v1/app/i",
                "guest",
                &nothing,
                &no_target,
                false,
                true,
            )
            .await
            .expect_err("policy write refused");
        assert!(is_forbidden(&err));
    }

    /// §4: Bootstrap is the unrestricted trust anchor — idempotent catalog
    /// seeding, root grants, and custom seed roles.
    #[tokio::test]
    async fn bootstrap_role_create_is_idempotent_and_unrestricted() {
        let (storage, _tmp) = role_gate_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        let bootstrap = crate::role::Caller::Bootstrap;

        for (name, level) in crate::role::BUILTIN_ROLES {
            let role = tenant
                .role_create(&bootstrap, name, 0)
                .await
                .expect("idempotent reseed");
            assert_eq!(role.level, *level, "catalog level is fixed");
            assert!(role.builtin);
        }
        tenant
            .user_add_role(&bootstrap, "bob", "root")
            .await
            .expect("the seed anchor may grant root");
        let role = tenant
            .role_create(&bootstrap, "legacy", 55)
            .await
            .expect("custom seed role");
        assert_eq!(role.level, 55);
        assert!(!role.builtin);
    }

    // ── session validation is policy-free ─────────────────────────────

    /// Tenant whose only policy requires MFA for `alice`'s role.
    async fn mfa_policy_env() -> (Storage, tempfile::TempDir) {
        let (storage, tmp) = refresh_test_env().await;
        {
            let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
            let bootstrap = crate::role::Caller::Bootstrap;
            tenant
                .role_create(&bootstrap, "user", 0)
                .await
                .expect("role");
            tenant
                .user_add_role(&bootstrap, "alice", "user")
                .await
                .expect("role assignment");
            tenant
                .policy_create(
                    &bootstrap,
                    DOMAIN,
                    Some(HttpMethod::POST),
                    "/api/v1/app/data",
                    "user",
                    &crate::policy::SourceResolver::Nothing,
                    &crate::policy::TargetResolver::Nothing,
                    true, // mfa required
                    true, // allowed
                )
                .await
                .expect("policy");
        }
        (storage, tmp)
    }

    /// The step-up deadlock: a single-factor session is denied by the
    /// policy engine (`expect_mfa`), yet session validation — the same
    /// primitive without the policy opt-in — must still accept it so the
    /// self-service auth endpoints can add the missing factor.
    #[tokio::test]
    async fn session_validation_ignores_the_policy_engine() {
        let (storage, _tmp) = mfa_policy_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        let token = tenant
            .authenticate_jwt(
                &HashSet::from(["email".to_string()]),
                TEST_ISSUER,
                DOMAIN,
                "alice",
                15,
            )
            .await
            .expect("token");

        // With the policy engine opted in, the same token is denied for the
        // protected resource…
        let denied = crate::utils::validate_token::<JwtData>(
            &mut tenant,
            TEST_ISSUER,
            DOMAIN,
            &token,
            crate::utils::ValidateOpts {
                policy: Some(crate::utils::PolicyCtx {
                    act: &HttpMethod::POST,
                    path: "/api/v1/app/data",
                    query: &HashMap::new(),
                    header: &HashMap::new(),
                }),
                ..Default::default()
            },
        )
        .await
        .expect("policy validation");
        assert!(!denied.can_access);
        assert!(denied.expect_mfa);

        // …but without the policy opt-in it is accepted: that is how the
        // session reaches the auth endpoints that complete the second
        // factor.
        let session = crate::utils::validate_token::<JwtData>(
            &mut tenant,
            TEST_ISSUER,
            DOMAIN,
            &token,
            crate::utils::ValidateOpts {
                domain_bound: true,
                ..Default::default()
            },
        )
        .await
        .expect("session accepted despite the MFA policy denial");
        let alice = tenant.user("alice").await.expect("alice");
        assert_eq!(session.claims.data.user, alice.id.to_string());
        assert!(session.claims.data.mfa.contains("email"));
    }

    #[tokio::test]
    async fn session_validation_rejects_foreign_issuer_and_domain() {
        let (storage, _tmp) = refresh_test_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        let token = tenant
            .authenticate_jwt(&HashSet::new(), TEST_ISSUER, DOMAIN, "alice", 15)
            .await
            .expect("token");

        let session_opts = crate::utils::ValidateOpts {
            domain_bound: true,
            ..Default::default()
        };
        assert!(
            crate::utils::validate_token::<JwtData>(
                &mut tenant,
                "https://evil.example.com",
                DOMAIN,
                &token,
                session_opts,
            )
            .await
            .is_err(),
            "wrong issuer must be rejected"
        );
        assert!(
            crate::utils::validate_token::<JwtData>(
                &mut tenant,
                TEST_ISSUER,
                "other.example.com",
                &token,
                session_opts,
            )
            .await
            .is_err(),
            "token bound to another tenant domain must be rejected"
        );
    }

    /// `/userinfo` semantics (Step 1.1): refresh-typed tokens are rejected
    /// when `reject_typ` says so, and accepted when it does not — the flag
    /// is what keeps introspection able to report on refresh tokens while
    /// userinfo refuses them.
    #[tokio::test]
    async fn reject_typ_flag_controls_refresh_token_acceptance() {
        let (storage, _tmp) = refresh_test_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        let key = tenant.current_key(DOMAIN).expect("signing key");
        let token = crate::jwt::jwt_authenticate(
            TEST_ISSUER,
            "alice",
            &serde_json::json!({ "typ": "refresh", "scope": "openid" }),
            &key,
            15,
            crate::jwt::JwtOidcParams {
                client_id: DOMAIN.to_string(),
                nonce: None,
                amr: None,
                acr: None,
                access_token: None,
                auth_time: None,
            },
        )
        .expect("refresh-typed token");

        assert!(
            matches!(
                crate::utils::validate_token::<serde_json::Value>(
                    &mut tenant,
                    TEST_ISSUER,
                    DOMAIN,
                    &token,
                    crate::utils::ValidateOpts {
                        reject_typ: Some("refresh"),
                        ..Default::default()
                    },
                )
                .await,
                Err(crate::utils::TokenReject::TypeMismatch)
            ),
            "userinfo-style validation must refuse refresh tokens"
        );
        assert!(
            crate::utils::validate_token::<serde_json::Value>(
                &mut tenant,
                TEST_ISSUER,
                DOMAIN,
                &token,
                crate::utils::ValidateOpts::default(),
            )
            .await
            .is_ok(),
            "introspection-style validation must still accept them"
        );
    }

    // ── user.active enforced at the stateful boundaries ────────────────
    //
    // JWT verification is deliberately stateless (no central authority to
    // consult in a distributed setup), so `active` is NOT checked at verify
    // time. Instead it is enforced where the client is already round-tripping
    // to the authority: login (no new sessions) and refresh (no extension).
    // Deactivation therefore propagates within one token lifetime.

    /// A deactivated user cannot start a new session — every factor mints
    /// through `authenticate_jwt`.
    #[tokio::test]
    async fn deactivated_user_cannot_authenticate() {
        let (storage, _tmp) = refresh_test_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        tenant
            .user_deactivate(&crate::role::Caller::Bootstrap, "alice")
            .await
            .expect("deactivate");
        assert!(
            tenant
                .authenticate_jwt(&HashSet::new(), TEST_ISSUER, DOMAIN, "alice", 15)
                .await
                .is_err(),
            "a deactivated user must not obtain a session"
        );
    }

    /// The refresh boundary: a deactivated user's current token runs out its
    /// lifetime but can never be renewed. Reactivation lifts the block.
    #[tokio::test]
    async fn refresh_rejects_a_deactivated_user() {
        let (storage, _tmp) = refresh_test_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        let token = tenant
            .authenticate_jwt(&HashSet::new(), TEST_ISSUER, DOMAIN, "alice", 15)
            .await
            .expect("token");

        tenant
            .user_deactivate(&crate::role::Caller::Bootstrap, "alice")
            .await
            .expect("deactivate");
        assert!(
            refresh(&mut tenant, &token).await.is_err(),
            "a deactivated user must not refresh back into a session"
        );

        // The refused attempt must not have consumed the token — the user
        // check runs before the rotation commit point.
        tenant
            .user_activate(&crate::role::Caller::Bootstrap, "alice")
            .await
            .expect("activate");
        assert!(
            refresh(&mut tenant, &token).await.is_ok(),
            "reactivation restores the ability to refresh"
        );
    }

    /// Verification itself must stay stateless: a deactivated user's live
    /// token still decodes/verifies until it expires. This pins the design
    /// decision so a future "fix" doesn't quietly re-add a verify-time check.
    #[tokio::test]
    async fn verification_stays_stateless_for_deactivated_users() {
        let (storage, _tmp) = refresh_test_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        let alice = tenant.user("alice").await.expect("alice");
        let token = tenant
            .authenticate_jwt(&HashSet::new(), TEST_ISSUER, DOMAIN, "alice", 15)
            .await
            .expect("token");

        tenant
            .user_deactivate(&crate::role::Caller::Bootstrap, "alice")
            .await
            .expect("deactivate");
        let session = crate::utils::validate_token::<JwtData>(
            &mut tenant,
            TEST_ISSUER,
            DOMAIN,
            &token,
            crate::utils::ValidateOpts {
                domain_bound: true,
                ..Default::default()
            },
        )
        .await
        .expect("stateless verification must not consult user state");
        assert_eq!(session.claims.data.user, alice.id.to_string());
    }

    // ── tenant names are path-safe ────────────────────────────────────

    #[test]
    fn tenant_name_charset_is_strict() {
        assert!(Storage::valid_tenant_name("test-tenant"));
        assert!(Storage::valid_tenant_name("a"));
        assert!(Storage::valid_tenant_name("tenant-01"));
        assert!(!Storage::valid_tenant_name(""));
        assert!(!Storage::valid_tenant_name(".."));
        assert!(!Storage::valid_tenant_name("../evil"));
        assert!(!Storage::valid_tenant_name("a/b"));
        assert!(!Storage::valid_tenant_name("/abs"));
        assert!(!Storage::valid_tenant_name("UPPER"));
        assert!(!Storage::valid_tenant_name("white space"));
        assert!(!Storage::valid_tenant_name("dot.name"));
        assert!(!Storage::valid_tenant_name(&"a".repeat(65)));
    }

    /// Traversal names must be rejected before anything touches the
    /// filesystem: no directory or DB may appear outside the tenant root.
    #[tokio::test]
    async fn new_tenant_rejects_path_traversal_names() {
        init_revocation_store().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage = Storage::init(tmp.path()).await.expect("storage init");

        for name in [
            "../evil",
            "../../evil",
            "/tmp/janux-g72-abs",
            "a/b",
            "..",
            ".",
        ] {
            assert!(
                storage.new_tenant(name).await.is_err(),
                "name {name:?} must be rejected"
            );
        }

        // Nothing may have been created outside the tenant root...
        assert!(!tmp.path().join("evil").exists());
        assert!(!std::path::Path::new("/tmp/janux-g72-abs").exists());
        // ...and the tenants directory holds no stray entries.
        let mut entries = tokio::fs::read_dir(tmp.path().join("tenants"))
            .await
            .expect("read_dir");
        let mut count = 0;
        while let Some(entry) = entries.next_entry().await.expect("entry") {
            let _ = entry;
            count += 1;
        }
        assert_eq!(count, 0, "rejected names must not create directories");
    }

    /// Valid names still work end-to-end, and deletion stays inside the
    /// data directory.
    #[tokio::test]
    async fn tenant_lifecycle_stays_inside_the_data_dir() {
        init_revocation_store().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage = Storage::init(tmp.path()).await.expect("storage init");

        storage.new_tenant("g72-tenant").await.expect("create");
        assert!(
            tmp.path()
                .join("tenants")
                .join("g72-tenant")
                .join("janux.db")
                .exists()
        );

        storage.delete_tenant("g72-tenant").await.expect("delete");
        assert!(!tmp.path().join("tenants").join("g72-tenant").exists());
    }

    // ── Topology mutations are concurrency-safe ────────────────────────────
    //
    // The router (domain -> tenant) must agree with the per-tenant
    // databases at all times. Before the topology lock, two racing
    // add_domain calls for the same domain could both pass the
    // registration check and persist the domain into two different
    // tenant databases — a split-brain the next restart refuses to boot.

    /// Racing `add_domain` calls for the same domain must produce exactly
    /// one winner; the domain record may exist in one tenant database only.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_add_domain_has_exactly_one_winner() {
        init_revocation_store().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage = std::sync::Arc::new(Storage::init(tmp.path()).await.expect("storage init"));
        storage.new_tenant("tenant-a").await.expect("tenant a");
        storage.new_tenant("tenant-b").await.expect("tenant b");

        let mut handles = Vec::new();
        for i in 0..8 {
            let s = storage.clone();
            let tenant = if i % 2 == 0 { "tenant-a" } else { "tenant-b" };
            handles.push(tokio::spawn(async move {
                s.add_domain("contested.example.com", tenant).await
            }));
        }
        let mut wins = 0;
        for h in handles {
            if h.await.expect("task").is_ok() {
                wins += 1;
            }
        }
        assert_eq!(wins, 1, "exactly one add may win the domain");

        let owner = storage
            .router
            .get("contested.example.com")
            .expect("router entry")
            .clone();
        let loser = if owner == "tenant-a" {
            "tenant-b"
        } else {
            "tenant-a"
        };
        assert!(
            storage
                .tenant_by_id(&owner)
                .expect("owner")
                .domain("contested.example.com")
                .await
                .is_ok(),
            "winner's database must hold the domain"
        );
        assert!(
            storage
                .tenant_by_id(loser)
                .expect("loser")
                .domain("contested.example.com")
                .await
                .is_err(),
            "loser's database must not hold the domain"
        );
    }

    /// Racing an add against a remove must end in a consistent state:
    /// the router entry exists if and only if exactly one tenant database
    /// holds the domain record.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_add_and_remove_stay_consistent() {
        init_revocation_store().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage = std::sync::Arc::new(Storage::init(tmp.path()).await.expect("storage init"));
        storage.new_tenant("tenant-a").await.expect("tenant a");
        storage.new_tenant("tenant-b").await.expect("tenant b");

        for round in 0..10 {
            let domain = format!("d{round}.example.com");
            storage
                .add_domain(&domain, "tenant-a")
                .await
                .expect("seed domain");

            let remover = {
                let s = storage.clone();
                let d = domain.clone();
                tokio::spawn(async move { s.remove_domain(&d, "tenant-a").await })
            };
            let adder = {
                let s = storage.clone();
                let d = domain.clone();
                tokio::spawn(async move { s.add_domain(&d, "tenant-b").await })
            };
            let _ = remover.await.expect("remover");
            let _ = adder.await.expect("adder");

            match storage.router.get(&domain) {
                Some(owner) => {
                    let owner = owner.clone();
                    assert!(
                        storage
                            .tenant_by_id(&owner)
                            .expect("owner")
                            .domain(&domain)
                            .await
                            .is_ok(),
                        "round {round}: router points at a tenant without the domain"
                    );
                    let other = if owner == "tenant-a" {
                        "tenant-b"
                    } else {
                        "tenant-a"
                    };
                    assert!(
                        storage
                            .tenant_by_id(other)
                            .expect("other")
                            .domain(&domain)
                            .await
                            .is_err(),
                        "round {round}: domain leaked into a second tenant"
                    );
                }
                None => {
                    for t in ["tenant-a", "tenant-b"] {
                        assert!(
                            storage
                                .tenant_by_id(t)
                                .expect("tenant")
                                .domain(&domain)
                                .await
                                .is_err(),
                            "round {round}: unregistered domain still in tenant '{t}'"
                        );
                    }
                }
            }
        }
    }

    // ── user deletion cascades its credentials ─────────────────────────
    //
    // Toasty lowers a model delete as DisassociateAll { delete: true } over
    // every has_many relation: a child whose belongs_to is NON-NULLABLE is
    // deleted, a nullable one is detached. All credential models (Email,
    // OTP, Passkey, Totp, OAuth2, UserRole) declare a non-nullable
    // belongs_to, so deleting a user cascades them all. This test pins that
    // behavior — if a credential ever gains a nullable belongs_to, it
    // silently switches from cascade-delete to detach and this guard fails.

    /// Deleting a user removes its attached credentials and role grants.
    #[tokio::test]
    async fn user_delete_cascades_credentials() {
        init_revocation_store().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage = Storage::init(tmp.path()).await.expect("storage init");
        storage.new_tenant("test-tenant").await.expect("tenant");
        storage
            .add_domain(DOMAIN, "test-tenant")
            .await
            .expect("domain");

        let bootstrap = crate::role::Caller::Bootstrap;
        let alice_id;
        {
            let mut tenant = storage.tenant_by_id("test-tenant").expect("tenant");
            tenant.user_create("alice").await.expect("user");
            tenant
                .email_create("alice", "alice@example.com")
                .await
                .expect("email");
            tenant
                .mobile_create("alice", "+15551234567")
                .await
                .expect("mobile");
            tenant
                .new_totp("alice", "default", DOMAIN)
                .await
                .expect("totp");
            tenant
                .role_create(&bootstrap, "user", 0)
                .await
                .expect("role");
            tenant
                .user_add_role(&bootstrap, "alice", "user")
                .await
                .expect("grant");

            // Sanity: everything is attached before deletion.
            alice_id = tenant.user("alice").await.expect("alice").id;
            assert!(tenant.user_by_email("alice@example.com").await.is_ok());
            assert!(tenant.user_by_mobile("+15551234567").await.is_ok());
            assert_eq!(tenant.user_roles(alice_id).await.expect("roles").len(), 1);
            assert_eq!(
                tenant
                    .all_totps(Some("alice"), None)
                    .await
                    .expect("totps")
                    .len(),
                1
            );
        }

        {
            let mut tenant = storage.tenant_by_id("test-tenant").expect("tenant");
            tenant
                .user_delete(&bootstrap, "alice")
                .await
                .expect("delete");
        }

        let mut tenant = storage.tenant_by_id("test-tenant").expect("tenant");
        // The user is gone.
        assert!(tenant.user("alice").await.is_err());
        // Cascade: the email and mobile credentials must not survive.
        assert!(
            tenant.user_by_email("alice@example.com").await.is_err(),
            "email credential must be deleted with its user"
        );
        assert!(
            tenant.user_by_mobile("+15551234567").await.is_err(),
            "mobile credential must be deleted with its user"
        );
        // Cascade: role grants and TOTP records must not survive.
        assert!(
            tenant.user_roles(alice_id).await.expect("roles").is_empty(),
            "role grants must be deleted with their user"
        );
        let leftover_totps: Vec<crate::totp::Totp> =
            crate::totp::Totp::filter(crate::totp::Totp::fields().user_id().eq(alice_id))
                .exec(&mut tenant.database)
                .await
                .expect("totp query");
        assert!(
            leftover_totps.is_empty(),
            "TOTP records must be deleted with their user"
        );
    }

    /// The refresh boundary: a deleted user's session can run out its
    /// lifetime but must never be EXTENDED — refresh fails closed on the
    /// missing user record, exactly like deactivation.
    #[tokio::test]
    async fn refresh_rejects_a_deleted_user() {
        let (storage, _tmp) = refresh_test_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        let token = tenant
            .authenticate_jwt(&HashSet::new(), TEST_ISSUER, DOMAIN, "alice", 15)
            .await
            .expect("token");

        tenant
            .user_delete(&crate::role::Caller::Bootstrap, "alice")
            .await
            .expect("delete");

        assert!(
            refresh(&mut tenant, &token).await.is_err(),
            "a deleted user must not refresh back into a session"
        );
    }
}
