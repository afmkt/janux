use crate::domain::Domain;
use crate::jwt::InvalidJwt;
use crate::key::Key;
use crate::policy::Policy;
use crate::server::JanuxConfig;
use anyhow::Result;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use dashmap::mapref::one::RefMut;
use salvo::oapi::ToSchema;
use serde::de::DeserializeOwned;
use std::collections::HashSet;
use tracing::info;

use crate::jwt::{JwtOidcParams, jwt_authenticate, jwt_decode};

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use tokio::fs::*;

/// How many delete-time DB snapshots to keep per tenant (H2). The backups
/// are raw database files next to the data dir; unbounded accumulation
/// turns a deletion into a permanent disclosure surface.
const TENANT_BACKUP_RETENTION: usize = 5;

#[derive(Eq, Clone, Hash, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
#[allow(clippy::upper_case_acronyms)] // OTP/TOTP are domain acronyms
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

/// The `acr` vocabulary is the factor names themselves — the same vocabulary
/// discovery advertises in `acr_values_supported` (G-94), not opaque numeric
/// levels. A multi-factor session reports the *strongest* factor achieved per
/// the order below; the full method list always travels in `amr` (RFC 8176).
/// Internal labels map to their external names (`oauth2`/legacy `Social` →
/// `social`). The canonical step-up session (`{email, totp}`) reports `totp`,
/// preserving the old `"2"` = MFA semantics.
pub fn acr_value(mfa: &HashSet<String>) -> Option<String> {
    if mfa.is_empty() {
        return None;
    }
    // Strongest first: hardware-backed user-verified passkeys are
    // phishing-resistant; TOTP step-up next; then possession factors;
    // federated login inherits the external IdP's (unknown) assurance.
    const STRENGTH_ORDER: &[(&str, &str)] = &[
        ("passkey", "passkey"),
        ("totp", "totp"),
        ("otp", "otp"),
        ("email", "email"),
        ("oauth2", "social"),
        ("Social", "social"),
    ];
    if let Some((_, external)) = STRENGTH_ORDER
        .iter()
        .find(|(internal, _)| mfa.contains(*internal))
    {
        return Some(external.to_string());
    }
    // Unknown factor label (forward-compat): deterministic first-sorted label
    // so a non-empty set never loses the claim.
    mfa.iter().min().cloned()
}

#[derive(Debug, PartialEq, toasty::Embed, Serialize, Deserialize, Clone, ToSchema)]
#[allow(clippy::upper_case_acronyms)] // HTTP method names are uppercase by convention
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

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            HttpMethod::CONNECT => "CONNECT",
            HttpMethod::HEAD => "HEAD",
            HttpMethod::TRACE => "TRACE",
            HttpMethod::PATCH => "PATCH",
            HttpMethod::DELETE => "DELETE",
            HttpMethod::OPTIONS => "OPTIONS",
            HttpMethod::PUT => "PUT",
            HttpMethod::POST => "POST",
            HttpMethod::GET => "GET",
        };
        f.write_str(s)
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

pub trait TokenPayload {
    fn bound_domain(&self) -> Option<&str>;
    fn typ(&self) -> Option<&str>;
    fn jwt_data(&self) -> Option<&JwtData>;
    /// The `client:<id>` username convention machine principals
    /// (`client_credentials`) carry from mint time. `validate_token` uses it
    /// to scope the client-deletion revocation-marker check (G-123) to
    /// machine tokens only, so user sessions never pay the extra store
    /// lookup.
    fn machine_username(&self) -> Option<&str> {
        None
    }
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
    fn machine_username(&self) -> Option<&str> {
        self.username.strip_prefix("client:")
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
    fn machine_username(&self) -> Option<&str> {
        self.get("username")
            .and_then(|v| v.as_str())
            .and_then(|u| u.strip_prefix("client:"))
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
        let all_data = jwt_decode::<T>(token, crate::jwt::VERIFICATION_GRACE_MINUTES, self).await?;
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
    pub async fn refresh_jwt(
        &mut self,
        issuer: &str,
        domain: &str,
        jwt: &str,
        minutes: i32,
    ) -> Result<String> {
        let decision = match crate::utils::validate_token::<JwtData>(
            self,
            issuer,
            domain,
            jwt,
            crate::utils::ValidateOpts::default(),
        )
        .await
        {
            Ok(decision) => decision,
            Err(crate::utils::TokenReject::Revoked) => {
                // H4: presenting an already-rotated (or logged-out) token
                // is a theft indicator — decode it (the signature is still
                // verified) to recover the chain identity and poison the
                // whole family, so the successor minted from the stolen
                // token stops rotating too (RFC 9700 §4.14.2 replay
                // response, mirroring the OIDC refresh path).
                if let Ok(tkn) =
                    jwt_decode::<JwtData>(jwt, crate::jwt::VERIFICATION_GRACE_MINUTES, self).await
                    && let Some(auth_time) = tkn.claims.auth_time
                {
                    crate::utils::poison_session_family(&tkn.claims.sub, auth_time).await;
                    tracing::warn!(
                        target: "auth::refresh",
                        sub = tkn.claims.sub.as_str(),
                        "internal session token replay detected; session family revoked"
                    );
                }
                return Err(anyhow::anyhow!(
                    "refresh token reuse detected; the session family has been revoked"
                ));
            }
            Err(e) => return Err(anyhow::anyhow!("{e}")),
        };
        // H4: a family poisoned by an earlier reuse detection refuses
        // every surviving chain member — the stolen token's successors
        // must not keep rotating (RFC 9700 §4.14.2 replay response,
        // mirroring the OIDC refresh path).
        if let Some(auth_time) = decision.claims.auth_time
            && crate::utils::session_family_poisoned(&decision.claims.sub, auth_time).await
        {
            return Err(anyhow::anyhow!(
                "session token reuse was detected; the whole session chain has been revoked"
            ));
        }
        // G-151: absolute cap on the refresh CHAIN. Rotation preserves the
        // original `auth_time`, so without this a session refreshed every
        // 15 minutes never re-authenticates; the OIDC path bounds families
        // at 30 days and the internal chain — which gates the admin API —
        // now matches. A missing `auth_time` fails closed: the chain's age
        // cannot be proven.
        match decision.claims.auth_time {
            Some(auth_time)
                if jiff::Timestamp::now()
                    .as_second()
                    .saturating_sub(auth_time as i64)
                    <= crate::utils::INTERNAL_SESSION_MAX_AGE_SEC => {}
            _ => {
                return Err(anyhow::anyhow!(
                    "session exceeded its absolute lifetime; re-authentication required"
                ));
            }
        }
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
        let key = self.current_key(domain)?;
        // G-128: roles are authorization state, not authentication history —
        // reload them from the DB on every rotation (exactly as the login
        // path in `authenticate_jwt` does), so a revoked role stops
        // propagating within one token lifetime and a fresh grant is picked
        // up on the next refresh. `mfa` deliberately stays as-minted: it
        // records the factors proven at `auth_time` (and feeds amr/acr),
        // not the current credential inventory.
        let roles = self.user_roles(user.id).await?;
        let mut d = decision.claims.data;
        d.username = user.name.clone();
        d.roles = HashSet::from_iter(roles.into_iter().map(|a| a.id));
        // G-90: a client-shortened session stays shortened across
        // rotation — re-mint with the lifetime the presented token
        // itself carried (exp − iat), clamped into [1, `minutes`].
        // Callers that never requested a custom lifetime see no change
        // (presented == default).
        let presented_minutes = decision
            .claims
            .exp
            .saturating_sub(decision.claims.iat)
            .saturating_div(60)
            .clamp(1, minutes.max(1) as usize) as i32;
        let new_jwt = jwt_authenticate(
            issuer,
            &d.user,
            &d,
            &key,
            presented_minutes,
            JwtOidcParams {
                client_id: domain.to_string(),
                nonce: Some(uuid::Uuid::new_v4().to_string()),
                amr: amr_values(&d.mfa),
                acr: acr_value(&d.mfa),
                access_token: None,
                auth_time: decision.claims.auth_time,
            },
        )?;
        let exp = jiff::Timestamp::from_second(decision.claims.exp as i64)?;
        match crate::utils::revoke_token(self, jwt, Some(exp), "internal refresh rotation").await {
            Ok(true) => {
                crate::ops::token_refreshed("session");
                Ok(new_jwt)
            }
            Ok(false) => {
                // H4: presenting an already-rotated token indicates theft —
                // poison the whole session family so the successor minted
                // from the stolen token stops rotating too, instead of
                // living out its lifetime plus endless refreshes.
                if let Some(auth_time) = decision.claims.auth_time {
                    crate::utils::poison_session_family(&decision.claims.sub, auth_time).await;
                    tracing::warn!(
                        target: "auth::refresh",
                        sub = decision.claims.sub.as_str(),
                        "internal session token reuse detected; session family revoked"
                    );
                }
                Err(anyhow::anyhow!(
                    "refresh token reuse detected; the session family has been revoked"
                ))
            }
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

/// M3 micro-migration: tenant DBs created before `Email.verified` lack the
/// column, and toasty's `push_schema` only issues `CREATE TABLE` (never
/// `ALTER`), so an old DB would fail every email query with "no such
/// column". Add the column idempotently before the schema push:
/// - fresh DB: no `emails` table yet → tolerated; `push_schema` creates the
///   table with the column;
/// - pre-M3 DB: column added; legacy rows default to NOT verified — the
///   honest state, since their provenance is unrecorded. They converge to
///   verified on the next ownership proof (magic-link signin, email-add
///   ceremony, or a social login whose upstream IdP asserts
///   `email_verified`);
/// - post-M3 DB: duplicate column → tolerated.
///
/// A genuine failure (I/O error) is logged and left to surface through the
/// toasty connection that opens the same file immediately after.
async fn migrate_email_verified(path: &Path) {
    async fn run(path: &Path) -> anyhow::Result<()> {
        let path_str = path.display().to_string();
        let db = turso::Builder::new_local(&path_str).build().await?;
        let conn = db.connect()?;
        conn.execute(
            "ALTER TABLE emails ADD COLUMN verified BOOLEAN NOT NULL DEFAULT FALSE",
            (),
        )
        .await?;
        Ok(())
    }
    if let Err(e) = run(path).await {
        let msg = e.to_string();
        let tolerated = msg.contains("duplicate column")
            || msg.contains("already exists")
            || msg.contains("no such table");
        if !tolerated {
            tracing::warn!(
                db = %path.display(),
                "email `verified` column migration skipped: {msg}"
            );
        }
    }
}

/// G-97 micro-migration: tenant DBs created before `Key.retired` lack the
/// column, and toasty's `push_schema` only issues `CREATE TABLE` (never
/// `ALTER`), so an old DB would fail every key query with "no such column".
/// Same shape and tolerance rules as `migrate_email_verified`: fresh DBs
/// get the column from `push_schema`, pre-G-97 DBs get it added with the
/// honest default (every existing row keeps signing — nothing is retired
/// retroactively), post-G-97 DBs tolerate the duplicate.
async fn migrate_key_retired(path: &Path) {
    async fn run(path: &Path) -> anyhow::Result<()> {
        let path_str = path.display().to_string();
        let db = turso::Builder::new_local(&path_str).build().await?;
        let conn = db.connect()?;
        conn.execute(
            "ALTER TABLE keys ADD COLUMN retired BOOLEAN NOT NULL DEFAULT FALSE",
            (),
        )
        .await?;
        Ok(())
    }
    if let Err(e) = run(path).await {
        let msg = e.to_string();
        let tolerated = msg.contains("duplicate column")
            || msg.contains("already exists")
            || msg.contains("no such table");
        if !tolerated {
            tracing::warn!(
                db = %path.display(),
                "key `retired` column migration skipped: {msg}"
            );
        }
    }
}

async fn connect_tenant(dir: &Path) -> toasty::Result<toasty::Db> {
    ensure_dir(dir).await?;
    let path = PathBuf::from(dir).join("janux.db");
    migrate_email_verified(&path).await;
    migrate_key_retired(&path).await;
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

pub struct Storage {
    pub raw_path: std::path::PathBuf,
    pub tenants: DashMap<String, Tenant>,
    pub router: DashMap<String, String>,
    pub topology: tokio::sync::Mutex<()>,
}

impl Storage {
    pub async fn domain_cors(&self, domain: &str, cors: Vec<String>) -> Result<()> {
        let tenant = self.tenant_by_domain(domain);
        if let Some(mut item) = tenant {
            item.domain_cors(domain, cors).await
        } else {
            Err(anyhow::anyhow!("Unknown domain '{}'", domain))
        }
    }
    pub async fn load_domain(&self, domain: &str) -> Result<Domain> {
        let tenant = self.tenant_by_domain(domain);
        if let Some(mut item) = tenant {
            item.domain(domain).await
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
            } else if d.cors.is_empty() {
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
        // Drop the pages-override binding too, so re-registering this
        // domain later does not resurrect a stale override dir at boot.
        tenant
            .config_delete(&crate::pages::pages_config_key(domain))
            .await?;

        self.router.remove(domain);
        Ok(())
    }

    pub async fn all_tenants(&self) -> Result<Vec<String>> {
        let mut ret = Vec::new();
        for t in self.tenants.iter() {
            ret.push(t.value().name.clone());
        }
        // Sorted so paginated views of the directory are stable across
        // requests (DashMap iteration order is arbitrary).
        ret.sort();
        Ok(ret)
    }

    pub fn tenant_by_domain(&self, domain: &str) -> Option<RefMut<'_, String, Tenant>> {
        let start = std::time::Instant::now();
        let ret = self
            .router
            .get(domain)
            .and_then(|id| self.tenants.get_mut(id.value()));
        crate::ops::record_guard_wait(start.elapsed());
        ret
    }
    pub fn tenant_by_id(&self, id: &str) -> Option<RefMut<'_, String, Tenant>> {
        let start = std::time::Instant::now();
        let ret = self.tenants.get_mut(id);
        crate::ops::record_guard_wait(start.elapsed());
        ret
    }

    /// All loaded tenant ids (G-126: the back-channel worker sweeps every
    /// tenant; ordering is unspecified).
    pub fn tenant_ids(&self) -> Vec<String> {
        self.tenants.iter().map(|e| e.key().clone()).collect()
    }

    pub async fn new_tenant(&self, name: &str) -> Result<RefMut<'_, String, Tenant>> {
        let _guard = self.topology.lock().await;
        let path = self.tenant_path(name)?;
        // Duplicate check against the TENANT map (M8). The old check looked
        // at `router`, which is keyed by DOMAIN: it never caught a real
        // tenant duplicate (that fell through to the misleading "directory
        // exists but was not loaded" error below) and wrongly refused a new
        // tenant whose name merely collided with a registered domain.
        if self.tenants.contains_key(name) {
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
        let _guard = self.topology.lock().await;
        let tenant_exists = self.tenants.contains_key(name);
        if !tenant_exists {
            return Err(anyhow::anyhow!("Tenant '{}' not found", name));
        }

        let domains: Vec<String> = self
            .router
            .iter()
            .filter(|entry| entry.value() == name)
            .map(|entry| entry.key().clone())
            .collect();
        for domain in &domains {
            self.router.remove(domain);
        }

        self.tenants.remove(name);
        let directory = self.directory();
        let tenant_dir = self.tenant_path(name)?;
        if tenant_dir.is_dir() {
            let pdir = directory.parent().unwrap_or(directory.as_path());
            let backup_dir = pdir.join("backups");
            ensure_dir(backup_dir.as_path()).await?;

            let timestamp = std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs();

            let backup_name = format!("{}-{:x}", name, timestamp);
            let backup_path = backup_dir.join(&backup_name);
            create_dir_all(&backup_path).await.ok(); // ignore race if concurrent delete

            let db_src = tenant_dir.join("janux.db");
            if let Ok(content) = read(&db_src).await {
                match write(backup_path.join("janux.db"), &content).await {
                    Err(e) => {
                        tracing::error!(tenant = name, "Failed to backup db: {}", e);
                    }
                    Ok(()) => {
                        // H2: the turso/libSQL store keeps un-checkpointed
                        // transactions in the WAL sidecar — a backup of
                        // janux.db alone can miss (or corrupt) the newest
                        // writes, so carry the sidecars when present.
                        for sidecar in ["janux.db-wal", "janux.db-shm"] {
                            let src = tenant_dir.join(sidecar);
                            if let Ok(bytes) = read(&src).await
                                && let Err(e) = write(backup_path.join(sidecar), &bytes).await
                            {
                                tracing::error!(tenant = name, "Failed to backup {sidecar}: {e}");
                            }
                        }
                        tracing::info!(tenant = name, backup = %backup_path.display(), "Tenant db backed up");
                    }
                }
            }

            // H2: prune to the newest TENANT_BACKUP_RETENTION snapshots of
            // THIS tenant — backups are raw DB files that accumulate
            // forever otherwise. Entries whose suffix is not a hex
            // timestamp are left alone (fail-safe against odd names).
            let prefix = format!("{name}-");
            let mut snapshots: Vec<(u64, PathBuf)> = Vec::new();
            if let Ok(mut entries) = read_dir(&backup_dir).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();
                    if let Some(file) = path.file_name().and_then(|f| f.to_str())
                        && let Some(suffix) = file.strip_prefix(prefix.as_str())
                        && let Ok(ts) = u64::from_str_radix(suffix, 16)
                    {
                        snapshots.push((ts, path));
                    }
                }
            }
            snapshots.sort_by_key(|(ts, _)| std::cmp::Reverse(*ts));
            for (_, stale) in snapshots.iter().skip(TENANT_BACKUP_RETENTION) {
                if let Err(e) = remove_dir_all(stale).await {
                    tracing::warn!(
                        tenant = name,
                        backup = %stale.display(),
                        "Failed to prune stale tenant backup: {e}"
                    );
                }
            }
        }

        if try_exists(&tenant_dir).await.ok().unwrap_or(false) {
            remove_dir_all(&tenant_dir).await?;
        }

        tracing::info!(tenant = name, "Tenant deleted successfully");
        Ok(())
    }

    async fn load_tenant(&mut self, name: &str) -> Result<()> {
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
                                "Domain: '{}' is served by tenant '{}' already, can not serve by tenant '{}' again.",
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
            // Before loading, enforce the single-root invariant: at most one
            // tenant may define a user holding the `root` role. The root role
            // is the cross-tenant platform authority; two roots would both be
            // apex-level and the model has no way to arbitrate between them.
            let root_tenants: Vec<&str> = data
                .iter()
                .filter(|t| t.has_root_user())
                .map(|t| t.tenant_name())
                .collect();
            if root_tenants.len() > 1 {
                return Err(anyhow::anyhow!(
                    "single-root invariant violated: {} tenants define a root user: {:?}. \
                     Only one tenant may hold the `root` role.",
                    root_tenants.len(),
                    root_tenants
                ));
            }
            for d in data {
                d.save(self).await?;
            }
        }
        Storage::init(&self.raw_path).await
    }

    fn directory(&self) -> std::path::PathBuf {
        self.raw_path.join("tenants")
    }

    pub fn valid_tenant_name(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= 64
            && name
                .chars()
                .all(|c| matches!(c, 'a'..='z' | '0'..='9' | '-'))
    }

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

// ─── Backup & restore (G-88) ─────────────────────────────────────────────────

/// Manifest describing a backup created by [`backup_data_dir`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    /// Bumped when the layout changes; restore refuses unknown versions.
    pub version: u32,
    /// RFC 3339 creation time.
    pub created_at: String,
    /// Tenant names found under `tenants/`.
    pub tenants: Vec<String>,
    /// Every copied file, relative to the backup root.
    pub files: Vec<String>,
}

const BACKUP_MANIFEST_VERSION: u32 = 1;

/// Every `*.db` file under `dir`, recursively.
async fn collect_db_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let mut entries = read_dir(dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.is_dir() {
            Box::pin(collect_db_files(&path, out)).await?;
        } else if path.extension().is_some_and(|e| e == "db") {
            out.push(path);
        }
    }
    Ok(())
}

/// Copy `src` into `dst` recursively; returns the copied files relative
/// to `dst`.
async fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<Vec<String>> {
    let mut files = Vec::new();
    let mut stack = vec![(src.to_path_buf(), dst.to_path_buf())];
    while let Some((s, d)) = stack.pop() {
        ensure_dir(&d).await?;
        let mut entries = read_dir(&s).await?;
        while let Some(entry) = entries.next_entry().await? {
            let from = entry.path();
            let to = d.join(entry.file_name());
            if from.is_dir() {
                stack.push((from, to));
            } else {
                tokio::fs::copy(&from, &to).await?;
                if let Ok(rel) = to.strip_prefix(dst) {
                    files.push(rel.to_string_lossy().to_string());
                }
            }
        }
    }
    Ok(files)
}

/// Take a COLD backup of the data directory (G-88).
///
/// Tenant databases are exclusively locked while the server holds them,
/// so this validates first: every `*.db` under `data_dir` must open and
/// answer a trivial query — which fails loudly while the server is
/// running instead of copying torn files. Then the whole tree (tenant
/// schemas, the `jwt.db` revocation store, delete-time snapshots under
/// `backups/`, ACME state) is copied verbatim into
/// `dest/backup-<unix-ts>/` and a manifest is written next to it.
///
/// Config files (base.toml/seed.toml) live OUTSIDE the data dir and are
/// the operator's to version; a backup plus the config files plus the
/// `encryption_key` are the complete restore set — without the key the
/// at-rest secrets (signing keys, provider credentials) are unrecoverable.
pub async fn backup_data_dir(data_dir: &Path, dest: &Path) -> Result<(PathBuf, BackupManifest)> {
    if !data_dir.is_dir() {
        anyhow::bail!("data dir {} does not exist", data_dir.display());
    }
    let mut dbs = Vec::new();
    collect_db_files(data_dir, &mut dbs).await?;
    for db in &dbs {
        let path_str = db.display().to_string();
        let handle = turso::Builder::new_local(&path_str)
            .build()
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "cannot open {} — is the server still running? ({e})",
                    db.display()
                )
            })?;
        let conn = handle.connect().map_err(|e| {
            anyhow::anyhow!(
                "cannot open {} — is the server still running? ({e})",
                db.display()
            )
        })?;
        // Probe with a write-lock round trip: `BEGIN IMMEDIATE` fails with
        // SQLITE_BUSY while the server holds the database, and neither
        // statement returns rows (turso's `execute` rejects result sets).
        conn.execute("BEGIN IMMEDIATE", ()).await.map_err(|e| {
            anyhow::anyhow!(
                "cannot lock {} — is the server still running? ({e})",
                db.display()
            )
        })?;
        conn.execute("ROLLBACK", ()).await.map_err(|e| {
            anyhow::anyhow!(
                "cannot read {} — is the server still running? ({e})",
                db.display()
            )
        })?;
    }

    let stamp = jiff::Timestamp::now().as_second();
    let root = dest.join(format!("backup-{stamp}"));
    ensure_dir(&root).await?;
    let files = copy_dir_recursive(data_dir, &root).await?;

    let mut tenants = Vec::new();
    let tenants_dir = data_dir.join("tenants");
    if tenants_dir.is_dir() {
        let mut entries = read_dir(&tenants_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            if entry.path().is_dir()
                && let Some(name) = entry.path().file_name().and_then(|n| n.to_str())
            {
                tenants.push(name.to_string());
            }
        }
    }
    tenants.sort();

    let manifest = BackupManifest {
        version: BACKUP_MANIFEST_VERSION,
        created_at: jiff::Timestamp::now().to_string(),
        tenants,
        files,
    };
    tokio::fs::write(
        root.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )
    .await?;
    Ok((root, manifest))
}

/// Restore a backup created by [`backup_data_dir`] (cold: the server must
/// be stopped). Refuses to touch a non-empty `data_dir` unless `force`,
/// in which case the existing tree is removed first — this is disaster
/// recovery, not a merge.
pub async fn restore_data_dir(
    backup_dir: &Path,
    data_dir: &Path,
    force: bool,
) -> Result<BackupManifest> {
    let raw = tokio::fs::read(backup_dir.join("manifest.json"))
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "{} is not a janux backup (no manifest.json)",
                backup_dir.display()
            )
        })?;
    let manifest: BackupManifest = serde_json::from_slice(&raw)?;
    if manifest.version != BACKUP_MANIFEST_VERSION {
        anyhow::bail!(
            "unsupported backup manifest version {} (this build writes {BACKUP_MANIFEST_VERSION})",
            manifest.version
        );
    }
    if data_dir.is_dir() {
        let mut entries = read_dir(data_dir).await?;
        if entries.next_entry().await?.is_some() {
            if !force {
                anyhow::bail!(
                    "data dir {} is not empty — pass force to replace it",
                    data_dir.display()
                );
            }
            tokio::fs::remove_dir_all(data_dir).await?;
        }
    }
    ensure_dir(data_dir).await?;
    copy_dir_recursive(backup_dir, data_dir).await?;
    Ok(manifest)
}

// ─── Encryption-key rotation (G-150) ─────────────────────────────────────────

/// What `janux rekey` rewrote.
#[derive(Debug, Default, serde::Serialize)]
pub struct RekeyReport {
    pub tenants: usize,
    pub signing_keys: usize,
    pub provider_secrets: usize,
    pub totp_secrets: usize,
    pub config_secrets: usize,
    /// Rows that were still LEGACY PLAINTEXT and got upgraded to
    /// ciphertext under the new key on the way through.
    pub legacy_upgraded: usize,
}

/// Re-encrypt every at-rest secret in the data dir under a NEW AES-256
/// key (G-150): signing-key privates, social provider secrets, TOTP
/// secrets, and the config-stored mail/SMS credentials. COLD operation —
/// the server must be stopped (`Storage::init` takes the same exclusive
/// locks the backup probe checks for).
///
/// The OLD key is the process-wide encryption key (the caller sets it up
/// from config before calling); the NEW key is explicit because the
/// process-wide `OnceLock` cannot be swapped in place. Legacy plaintext
/// rows (written before encryption at rest) are upgraded to ciphertext
/// under the new key. Argon2 client-secret HASHES are one-way and need no
/// rekey. After a successful run the caller MUST persist the new key in
/// the config — the data dir no longer decrypts with the old one.
pub async fn rekey_data_dir(data_dir: &Path, new_key_hex: &str) -> Result<RekeyReport> {
    let new_cipher = crate::crypto::parse_key_hex(new_key_hex)?;
    let storage = Storage::init(data_dir).await?;
    let mut report = RekeyReport::default();
    for id in storage.tenant_ids() {
        let Some(mut tenant) = storage.tenant_by_id(&id) else {
            continue;
        };
        report.tenants += 1;

        // Signing-key privates (ciphertext bytes; pre-H2 rows are
        // plaintext PEM).
        for key in tenant.all_keys().await? {
            let stored = String::from_utf8_lossy(&key.private).to_string();
            let (plain, was_legacy) = match crate::crypto::decrypt_secret(&stored) {
                Ok(p) => (p, false),
                Err(_) => (stored, true),
            };
            let ct = crate::crypto::encrypt_secret_with(&new_cipher, &plain)?;
            Key::update_by_id(key.id.as_str())
                .private(ct.into_bytes())
                .exec(&mut tenant.database)
                .await?;
            report.signing_keys += 1;
            if was_legacy {
                report.legacy_upgraded += 1;
            }
        }

        // Social provider secrets.
        for p in tenant.all_providers().await {
            let (plain, was_legacy) = match crate::crypto::decrypt_secret(&p.client_secret) {
                Ok(s) => (s, false),
                Err(_) => (p.client_secret.clone(), true),
            };
            let ct = crate::crypto::encrypt_secret_with(&new_cipher, &plain)?;
            crate::social::SocialProvider::update_by_id(p.id.as_str())
                .client_secret(ct)
                .exec(&mut tenant.database)
                .await?;
            report.provider_secrets += 1;
            if was_legacy {
                report.legacy_upgraded += 1;
            }
        }

        // TOTP secrets (composite key — the loop lives in totp.rs).
        let (n, legacy) = tenant.rekey_totp_secrets(&new_cipher).await?;
        report.totp_secrets += n;
        report.legacy_upgraded += legacy;

        // Config-stored provider credentials (JSON-encoded ciphertext;
        // legacy rows hold the plaintext string).
        for name in [
            crate::config::RESEND_KEY,
            crate::config::OTP_API_SECRET,
            crate::config::OTP_API_KEY,
        ] {
            let Some(value) = tenant.config_get(name).await else {
                continue;
            };
            let Some(stored) = value.as_str() else {
                continue;
            };
            let (plain, was_legacy) = match crate::crypto::decrypt_secret(stored) {
                Ok(s) => (s, false),
                Err(_) => (stored.to_string(), true),
            };
            let ct = crate::crypto::encrypt_secret_with(&new_cipher, &plain)?;
            tenant.config_set(name, serde_json::json!(ct)).await?;
            report.config_secrets += 1;
            if was_legacy {
                report.legacy_upgraded += 1;
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::LazyLock;

    const DOMAIN: &str = "localhost";
    const TEST_ISSUER: &str = "http://localhost";

    static TEST_STORE_DIR: LazyLock<tempfile::TempDir> =
        LazyLock::new(|| tempfile::tempdir().expect("tempdir"));

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

    async fn refresh_test_env() -> (Storage, tempfile::TempDir) {
        init_revocation_store().await;
        // Signing keys are encrypted at rest (H2); the process-wide
        // encryption key is first-call-wins across test envs.
        let _ = crate::crypto::setup_encryption_key(&"0".repeat(64));
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

    #[tokio::test]
    async fn refresh_rejects_a_revoked_token() {
        let (storage, _tmp) = refresh_test_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        let token = tenant
            .authenticate_jwt(&HashSet::new(), TEST_ISSUER, DOMAIN, "alice", 15)
            .await
            .expect("token");

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

    /// regression H4: reuse detection must POISON the chain — the
    /// successor minted from a stolen token may not keep rotating once
    /// the replay surfaces; it expires with its (now unrefreshable)
    /// family instead of extending the stolen session indefinitely.
    #[tokio::test]
    async fn refresh_reuse_poisons_the_whole_session_chain() {
        let (storage, _tmp) = refresh_test_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        let token = tenant
            .authenticate_jwt(&HashSet::new(), TEST_ISSUER, DOMAIN, "alice", 15)
            .await
            .expect("token");

        let successor = refresh(&mut tenant, &token).await.expect("first rotation");
        assert!(
            refresh(&mut tenant, &token).await.is_err(),
            "replaying the rotated token must be refused"
        );
        assert!(
            refresh(&mut tenant, &successor).await.is_err(),
            "the successor of a replayed token must die with the family"
        );
    }

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

    /// regression: an already-rotated token that is expired but still
    /// within the verification leeway must not mint a SECOND successor —
    /// the revocation record has to survive gc for the whole window in
    /// which the token can still rotate.
    #[tokio::test]
    async fn refresh_rejects_reuse_of_an_expired_rotated_token_after_gc() {
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

        refresh(&mut tenant, &token)
            .await
            .expect("first rotation of the expired-within-leeway token");
        InvalidJwt::global().gc().await.expect("gc");
        assert!(
            refresh(&mut tenant, &token).await.is_err(),
            "the rotated token must stay refused as reuse after gc (no second successor)"
        );
    }

    /// regression H2: the stored private key is AES-GCM ciphertext, not
    /// plaintext PEM — a DB or backup disclosure must not hand out the
    /// material to forge tokens — and the decrypted key still signs.
    #[tokio::test]
    async fn signing_key_private_is_encrypted_at_rest() {
        let (storage, _tmp) = refresh_test_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        // `current_key` reads the row loaded from the DB at tenant init —
        // `private` is exactly what rests on disk.
        let key = tenant.current_key(DOMAIN).expect("key row");
        let stored = String::from_utf8(key.private.clone()).expect("utf8");
        assert!(
            !stored.contains("BEGIN PRIVATE KEY"),
            "the private key must not be stored as plaintext PEM"
        );
        let decrypted = crate::crypto::decrypt_secret(&stored)
            .expect("the stored value must decrypt with the process encryption key");
        assert_eq!(
            key.private_pem().expect("private_pem"),
            decrypted,
            "private_pem must hand consumers the plaintext"
        );
        assert!(decrypted.contains("PRIVATE KEY"));
        // And it still signs verifiable tokens end to end.
        let token = tenant
            .authenticate_jwt(&HashSet::new(), TEST_ISSUER, DOMAIN, "alice", 15)
            .await
            .expect("signing with the encrypted key works");
        assert!(!token.is_empty());
    }

    /// regression H2 (legacy): rows written before encryption at rest hold
    /// plaintext PEM; `private_pem` must fall back to them so pre-existing
    /// tenants keep signing after the upgrade (rotate to upgrade the row).
    #[tokio::test]
    async fn legacy_plaintext_signing_key_still_loads() {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).expect("keygen");
        let pem = kp.serialize_pem();
        let key = crate::key::Key {
            id: "legacy-key".to_string(),
            public: kp.public_key_pem().into_bytes(),
            private: pem.clone().into_bytes(),
            domain_id: DOMAIN.to_string(),
            retired: false,
            domain: Default::default(),
        };
        assert_eq!(
            key.private_pem().expect("legacy fallback"),
            pem,
            "a plaintext row must load unchanged"
        );
    }

    /// regression H2b: tenant-delete backups are pruned to the newest
    /// TENANT_BACKUP_RETENTION snapshots of that tenant, and the fresh
    /// backup carries the DB (plus WAL sidecars when the store left any).
    #[tokio::test]
    async fn tenant_delete_backups_are_pruned_to_retention() {
        let (storage, tmp) = refresh_test_env().await;
        storage.new_tenant("prune-me").await.expect("tenant");
        storage
            .add_domain("prune.local", "prune-me")
            .await
            .expect("domain");
        assert!(
            storage.tenant_by_domain("prune.local").is_some(),
            "the domain routes before the delete"
        );

        // Pre-seed seven stale snapshots with ancient hex timestamps.
        let backups = tmp.path().join("backups");
        std::fs::create_dir_all(&backups).expect("backups dir");
        for ts in 1..=7u64 {
            std::fs::create_dir_all(backups.join(format!("prune-me-{ts:x}")))
                .expect("stale backup");
        }

        storage.delete_tenant("prune-me").await.expect("delete");

        // Cascade: the domain stops routing the moment the tenant is gone.
        assert!(
            storage.tenant_by_domain("prune.local").is_none(),
            "tenant delete must drop the domain's router entry"
        );

        let remaining: Vec<String> = std::fs::read_dir(&backups)
            .expect("read backups")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(
            remaining.len(),
            TENANT_BACKUP_RETENTION,
            "retention must prune stale snapshots: {remaining:?}"
        );
        // The oldest stale entries are gone; the fresh (largest timestamp)
        // backup survives and holds the database file.
        assert!(
            !remaining.iter().any(|n| n == "prune-me-1"),
            "the oldest snapshot must be pruned"
        );
        let newest = remaining
            .iter()
            .max_by_key(|n| {
                n.strip_prefix("prune-me-")
                    .and_then(|s| u64::from_str_radix(s, 16).ok())
                    .unwrap_or(0)
            })
            .expect("newest backup");
        assert!(
            backups.join(newest).join("janux.db").exists(),
            "the fresh backup must contain the database file"
        );
    }

    /// regression H12: the domain→tenant router is persisted state, not
    /// memory-only decoration — a fresh `Storage::init` over the same data
    /// directory (a restart) rebuilds it from each tenant's `Domain` rows
    /// with no re-seeding. (Cross-node invalidation remains out of scope:
    /// single-instance deployment is the documented M1 constraint.)
    #[tokio::test]
    async fn router_is_rebuilt_from_disk_on_restart() {
        let (storage, tmp) = refresh_test_env().await;
        // A tenant + domain added at RUNTIME (never seeded from config).
        storage.new_tenant("second").await.expect("second tenant");
        storage
            .add_domain("second.local", "second")
            .await
            .expect("domain");
        assert!(storage.tenant_by_domain("second.local").is_some());
        drop(storage);

        // "Restart": a fresh Storage over the same directory.
        let restarted = Storage::init(tmp.path()).await.expect("re-init");
        assert!(
            restarted.tenant_by_domain(DOMAIN).is_some(),
            "the env's domain must route again after restart"
        );
        assert!(
            restarted.tenant_by_domain("second.local").is_some(),
            "a runtime-added domain must route again after restart"
        );
        assert!(
            restarted
                .tenant_by_domain("never-registered.local")
                .is_none(),
            "unknown domains must not route"
        );
    }

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

    #[tokio::test]
    async fn policy_create_root_resource_requires_root_power() {
        // G-129 (resource-power axis): the level gate bounds the target
        // role's LEVEL; this gate bounds what the binding CONFERS. An
        // admin must not attach the cross-tenant lifecycle surface to a
        // puppet role below itself — the old escalation chain was
        // role_create@79 → bind tenant/delete → user_add_role(self).
        let (storage, _tmp) = role_gate_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        let alice = jwt_caller("alice", &["admin"]);
        let carol = jwt_caller("carol", &["root", "admin", "user"]);
        let bootstrap = crate::role::Caller::Bootstrap;
        let nothing = crate::policy::SourceResolver::Nothing;
        let no_target = crate::policy::TargetResolver::Nothing;
        tenant
            .role_create(&alice, "ops", 79)
            .await
            .expect("puppet role one level below admin");

        for resource in [
            "/api/v1/admin/tenant/delete",
            "/api/v1/admin/tenant/create",
            "/api/v1/admin/tenant/list",
            // template evasions: a `{param}` segment covering the root path
            "/api/v1/admin/tenant/{op}",
            "/api/v1/admin/{surface}/delete",
            // leading-slash-less form (inert at runtime, refused anyway)
            "api/v1/admin/tenant/delete",
        ] {
            let err = tenant
                .policy_create(
                    &alice, DOMAIN, None, resource, "ops", &nothing, &no_target, false, true,
                )
                .await
                .expect_err("admin must not bind root-powered resources");
            assert!(is_forbidden(&err), "expected Forbidden for {resource}");
        }

        // Deny rows are gated the same way: root-powered bindings are
        // root's to make and root's to remove.
        let err = tenant
            .policy_create(
                &alice,
                DOMAIN,
                None,
                "/api/v1/admin/tenant/delete",
                "ops",
                &nothing,
                &no_target,
                false,
                false,
            )
            .await
            .expect_err("deny bindings are root-powered too");
        assert!(is_forbidden(&err));

        // Resolver shapes do not smuggle the binding past the gate: the
        // resource template is what decides, whatever source/target say.
        let err = tenant
            .policy_create(
                &alice,
                DOMAIN,
                None,
                "/api/v1/admin/tenant/delete",
                "ops",
                &crate::policy::SourceResolver::User,
                &crate::policy::TargetResolver::FromQuery {
                    qname: "name".into(),
                },
                false,
                true,
            )
            .await
            .expect_err("resolver shape must not bypass the resource gate");
        assert!(is_forbidden(&err));

        // A root-level caller may delegate the lifecycle surface downward,
        // and Bootstrap (the seed path) is unrestricted.
        tenant
            .policy_create(
                &carol,
                DOMAIN,
                None,
                "/api/v1/admin/tenant/list",
                "ops",
                &nothing,
                &no_target,
                false,
                true,
            )
            .await
            .expect("root may bind tenant/list to a sub-level role");
        tenant
            .policy_create(
                &bootstrap,
                DOMAIN,
                None,
                "/api/v1/admin/tenant/delete",
                "ops",
                &nothing,
                &no_target,
                false,
                true,
            )
            .await
            .expect("bootstrap binds freely");

        // Non-root resources are untouched: admin keeps its own surface.
        tenant
            .policy_create(
                &alice,
                DOMAIN,
                None,
                "/api/v1/admin/user/list",
                "ops",
                &nothing,
                &no_target,
                false,
                true,
            )
            .await
            .expect("admin still binds non-root resources downward");
    }

    #[tokio::test]
    async fn policy_delete_root_resource_requires_root_power() {
        // R6 symmetry (G-129): stripping a root-delegated lifecycle
        // binding is itself an act of root power.
        let (storage, _tmp) = role_gate_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        let alice = jwt_caller("alice", &["admin"]);
        let carol = jwt_caller("carol", &["root", "admin", "user"]);
        let nothing = crate::policy::SourceResolver::Nothing;
        let no_target = crate::policy::TargetResolver::Nothing;
        tenant.role_create(&alice, "ops", 79).await.expect("role");
        tenant
            .policy_create(
                &carol,
                DOMAIN,
                None,
                "/api/v1/admin/tenant/list",
                "ops",
                &nothing,
                &no_target,
                false,
                true,
            )
            .await
            .expect("root delegates tenant/list");

        let err = tenant
            .policy_delete(&alice, DOMAIN, "/api/v1/admin/tenant/list", None, "ops")
            .await
            .expect_err("admin must not strip a root-powered binding");
        assert!(is_forbidden(&err));
        tenant
            .policy_delete(&carol, DOMAIN, "/api/v1/admin/tenant/list", None, "ops")
            .await
            .expect("root removes its own delegation");
    }

    #[tokio::test]
    async fn user_create_gates_the_username_charset() {
        // G-105: the username is the one identifier never verified
        // out-of-band; the creation choke point (signup, admin, SCIM and
        // seed all funnel through `user_create`) keeps it URL-, log- and
        // claim-safe. Case is preserved, not folded.
        let (storage, _tmp) = role_gate_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");

        for ok in ["admin@test.local", "user_1", "a-b.c@d", "XyZ"] {
            tenant.user_create(ok).await.expect(ok);
        }
        let long = "u".repeat(255);
        for bad in [
            "has space",
            "amp&name",
            "slash/name",
            "q?mark",
            "hash#tag",
            "pct%nt",
            "ctrl\u{1}",
            "new\nline",
            "",
            long.as_str(),
        ] {
            assert!(
                tenant.user_create(bad).await.is_err(),
                "must refuse {bad:?}"
            );
        }
    }

    #[tokio::test]
    async fn role_delete_cascades_policies_and_memberships() {
        // G-154: deleting only the Role row used to leave dangling Policy
        // rows (DB AND cache) plus UserRole memberships behind — and
        // re-creating a same-named role silently resurrected every stale
        // policy without passing policy_create's gates again.
        let (storage, _tmp) = role_gate_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        let alice = jwt_caller("alice", &["admin"]);
        let nothing = crate::policy::SourceResolver::Nothing;
        let no_target = crate::policy::TargetResolver::Nothing;
        tenant
            .role_create(&alice, "temp", 50)
            .await
            .expect("custom role");
        tenant
            .policy_create(
                &alice,
                DOMAIN,
                None,
                "/api/v1/app/x",
                "temp",
                &nothing,
                &no_target,
                false,
                true,
            )
            .await
            .expect("policy");
        tenant
            .user_add_role(&alice, "bob", "temp")
            .await
            .expect("membership");
        assert!(
            tenant
                .policies
                .get(DOMAIN)
                .is_some_and(|m| m.contains_key("temp")),
            "the cache serves the new role's policies"
        );

        tenant.role_delete(&alice, "temp").await.expect("delete");

        // Cache entry evicted...
        assert!(
            !tenant
                .policies
                .get(DOMAIN)
                .is_some_and(|m| m.contains_key("temp")),
            "the cache must not keep the deleted role's policies"
        );
        // ...DB rows gone (a fresh load finds nothing for the role)...
        let fresh = tenant.all_policy_entries().await.expect("reload");
        assert!(
            !fresh.get(DOMAIN).is_some_and(|m| m.contains_key("temp")),
            "the policy rows must be deleted, not just evicted"
        );
        // ...and the membership no longer resolves.
        let bob = tenant.user("bob").await.expect("bob");
        let roles = tenant.user_roles(bob.id).await.expect("roles");
        assert!(
            !roles.iter().any(|r| r.id == "temp"),
            "memberships of a deleted role must be removed"
        );

        // Re-creating the name resurrects nothing.
        tenant
            .role_create(&alice, "temp", 50)
            .await
            .expect("recreate");
        let fresh = tenant.all_policy_entries().await.expect("reload");
        assert!(
            !fresh.get(DOMAIN).is_some_and(|m| m.contains_key("temp")),
            "a same-named role must start with a clean policy set"
        );
    }

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

        tenant
            .user_activate(&crate::role::Caller::Bootstrap, "alice")
            .await
            .expect("activate");
        assert!(
            refresh(&mut tenant, &token).await.is_ok(),
            "reactivation restores the ability to refresh"
        );
    }

    #[tokio::test]
    async fn refresh_reloads_roles_so_revocation_propagates() {
        // G-128: refresh is the only extension point for internal sessions,
        // so it must re-mint roles from the DB — not copy them from the
        // presented token — or a demoted admin keeps rotating a stale role
        // set forever while the policy engine (which reads roles from the
        // token) keeps honoring it.
        let (storage, _tmp) = role_gate_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        // alice holds "admin" at mint time (granted by role_gate_env).
        let token = tenant
            .authenticate_jwt(&HashSet::new(), TEST_ISSUER, DOMAIN, "alice", 15)
            .await
            .expect("token");
        let minted = crate::utils::validate_token::<JwtData>(
            &mut tenant,
            TEST_ISSUER,
            DOMAIN,
            &token,
            crate::utils::ValidateOpts::default(),
        )
        .await
        .expect("decode minted token");
        assert!(
            minted.claims.data.roles.contains("admin"),
            "the mint-time role set must contain the granted admin role"
        );

        let bootstrap = crate::role::Caller::Bootstrap;
        tenant
            .user_del_role(&bootstrap, "alice", "admin")
            .await
            .expect("revoke admin");
        tenant
            .user_add_role(&bootstrap, "alice", "guest")
            .await
            .expect("grant guest");

        let refreshed = refresh(&mut tenant, &token)
            .await
            .expect("refresh succeeds for an active user");
        let rotated = crate::utils::validate_token::<JwtData>(
            &mut tenant,
            TEST_ISSUER,
            DOMAIN,
            &refreshed,
            crate::utils::ValidateOpts::default(),
        )
        .await
        .expect("decode refreshed token");
        assert!(
            !rotated.claims.data.roles.contains("admin"),
            "a revoked role must not survive rotation"
        );
        assert!(
            rotated.claims.data.roles.contains("guest"),
            "a freshly granted role must be picked up on rotation"
        );
    }

    #[tokio::test]
    async fn refresh_rejects_chain_past_absolute_cap() {
        // G-151: rotation preserves the original `auth_time`, so without
        // the absolute cap a session refreshed every 15 minutes would
        // never re-authenticate. Past the cap the chain must die; inside
        // it, an aged-but-valid chain still rotates.
        let (storage, _tmp) = refresh_test_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");
        let key = tenant.current_key(DOMAIN).expect("key");
        let alice_id = {
            let u = tenant.user("alice").await.expect("alice");
            u.id.to_string()
        };
        let mint = |auth_time: usize| {
            crate::jwt::jwt_authenticate(
                TEST_ISSUER,
                &alice_id,
                &JwtData {
                    user: alice_id.clone(),
                    username: "alice".into(),
                    domain: DOMAIN.into(),
                    mfa: HashSet::new(),
                    roles: HashSet::new(),
                },
                &key,
                15,
                crate::jwt::JwtOidcParams {
                    client_id: DOMAIN.into(),
                    nonce: None,
                    amr: None,
                    acr: None,
                    access_token: None,
                    auth_time: Some(auth_time),
                },
            )
            .expect("token")
        };

        let now = jiff::Timestamp::now().as_second().max(0) as usize;
        let aged = mint(now - crate::utils::INTERNAL_SESSION_MAX_AGE_SEC as usize - 60);
        let err = refresh(&mut tenant, &aged)
            .await
            .expect_err("chains past the absolute cap must re-authenticate");
        assert!(err.to_string().contains("absolute lifetime"), "{err}");

        let recent = mint(now - 60);
        assert!(
            refresh(&mut tenant, &recent).await.is_ok(),
            "an aged-but-in-cap chain still rotates"
        );
    }

    #[tokio::test]
    async fn refresh_preserves_client_shortened_lifetime() {
        // G-90: a session minted with a client-shortened lifetime keeps
        // it across rotation instead of silently jumping back to the
        // 15-minute default.
        let (storage, _tmp) = refresh_test_env().await;
        let mut tenant = storage.tenant_by_domain(DOMAIN).expect("tenant");

        let short = tenant
            .authenticate_jwt(&HashSet::new(), TEST_ISSUER, DOMAIN, "alice", 5)
            .await
            .expect("5-minute session");
        let rotated = refresh(&mut tenant, &short).await.expect("refresh");
        let decoded = crate::jwt::jwt_decode::<JwtData>(
            &rotated,
            crate::jwt::VERIFICATION_GRACE_MINUTES,
            &mut tenant,
        )
        .await
        .expect("decode");
        assert_eq!(
            decoded.claims.exp - decoded.claims.iat,
            300,
            "rotation must preserve the 5-minute lifetime"
        );

        // And the default-lifetime chain is unchanged by the mechanism.
        let full = tenant
            .authenticate_jwt(&HashSet::new(), TEST_ISSUER, DOMAIN, "alice", 15)
            .await
            .expect("15-minute session");
        let rotated = refresh(&mut tenant, &full).await.expect("refresh");
        let decoded = crate::jwt::jwt_decode::<JwtData>(
            &rotated,
            crate::jwt::VERIFICATION_GRACE_MINUTES,
            &mut tenant,
        )
        .await
        .expect("decode");
        assert_eq!(
            decoded.claims.exp - decoded.claims.iat,
            900,
            "a default-lifetime chain keeps rotating at the default"
        );
    }

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

    #[tokio::test]
    async fn user_delete_cascades_credentials() {
        init_revocation_store().await;
        // new_totp encrypts the secret at rest; the key is process-wide
        // and first-call-wins, matching the social test envs.
        let _ = crate::crypto::setup_encryption_key(&"0".repeat(64));
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
                    .totps_page(Some("alice"), None, crate::utils::MAX_PAGE_LIMIT, 0)
                    .await
                    .expect("totps")
                    .items
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

        assert!(tenant.user("alice").await.is_err());

        assert!(
            tenant.user_by_email("alice@example.com").await.is_err(),
            "email credential must be deleted with its user"
        );
        assert!(
            tenant.user_by_mobile("+15551234567").await.is_err(),
            "mobile credential must be deleted with its user"
        );

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
    /// M3 deploy safety: a tenant DB written before `Email.verified` gains
    /// the column on the next load (toasty's `push_schema` only CREATEs,
    /// never ALTERs), legacy rows come back unverified — the honest default
    /// — and email queries work again.
    #[tokio::test]
    async fn legacy_tenant_db_gains_email_verified_column_on_reload() {
        let tmp = tempfile::tempdir().expect("tempdir");

        // First boot on the current schema; attach a proven email.
        {
            let storage = crate::db::Storage::init(tmp.path()).await.expect("init");
            storage.new_tenant("legacy").await.expect("tenant");
            let mut tenant = storage.tenant_by_id("legacy").expect("tenant");
            tenant.user_create("alice").await.expect("user");
            tenant
                .email_create_verified("alice", "alice@example.com")
                .await
                .expect("email");
        }

        // Simulate a pre-M3 database: drop the column behind toasty's back.
        let db_path = tmp
            .path()
            .join("tenants")
            .join("legacy")
            .join("janux.db")
            .display()
            .to_string();
        {
            let db = turso::Builder::new_local(&db_path)
                .build()
                .await
                .expect("open legacy db");
            let conn = db.connect().expect("connect");
            conn.execute("ALTER TABLE emails DROP COLUMN verified", ())
                .await
                .expect("drop column");
        }

        // Reload: the micro-migration must restore the column, the legacy
        // row comes back unverified, and queries work.
        let storage = crate::db::Storage::init(tmp.path())
            .await
            .expect("reload storage");
        let mut tenant = storage.tenant_by_id("legacy").expect("tenant");
        let emails = tenant
            .all_emails(Some("alice"))
            .await
            .expect("email query works after migration");
        assert_eq!(emails.len(), 1, "the legacy row survives");
        assert_eq!(emails[0].id, "alice@example.com");
        assert!(
            !emails[0].verified,
            "legacy rows default to unverified until re-proven"
        );

        // And the convergence path works on the migrated schema.
        tenant
            .email_mark_verified("alice@example.com")
            .await
            .expect("mark verified");
        let emails = tenant.all_emails(Some("alice")).await.expect("emails");
        assert!(emails[0].verified);
    }

    /// G-97 micro-migration: a tenant DB created before `Key.retired`
    /// gains the column on reload, the legacy row comes back NOT retired
    /// (nothing is retired retroactively — it keeps signing), and the
    /// key queries + signer seat work on the migrated schema.
    #[tokio::test]
    async fn legacy_tenant_db_gains_key_retired_column_on_reload() {
        // Signing keys are encrypted at rest (H2); the process-wide
        // encryption key is first-call-wins across test envs.
        let _ = crate::crypto::setup_encryption_key(&"0".repeat(64));
        let tmp = tempfile::tempdir().expect("tempdir");

        // First boot on the current schema; create a signing key.
        {
            let storage = crate::db::Storage::init(tmp.path()).await.expect("init");
            storage.new_tenant("legacy").await.expect("tenant");
            storage
                .add_domain("localhost", "legacy")
                .await
                .expect("domain");
            let mut tenant = storage.tenant_by_id("legacy").expect("tenant");
            tenant
                .key_create("localhost", "key1")
                .await
                .expect("signing key");
        }

        // Simulate a pre-G-97 database: drop the column behind toasty's back.
        let db_path = tmp
            .path()
            .join("tenants")
            .join("legacy")
            .join("janux.db")
            .display()
            .to_string();
        {
            let db = turso::Builder::new_local(&db_path)
                .build()
                .await
                .expect("open legacy db");
            let conn = db.connect().expect("connect");
            conn.execute("ALTER TABLE keys DROP COLUMN retired", ())
                .await
                .expect("drop column");
        }

        // Reload: the micro-migration must restore the column and the
        // legacy row must come back signable.
        let storage = crate::db::Storage::init(tmp.path())
            .await
            .expect("reload storage");
        let mut tenant = storage.tenant_by_id("legacy").expect("tenant");
        // Fully qualified: `tenant.key` would resolve to the DashMap
        // guard's 0-arg `key()`, not `Tenant::key` (same trap as the
        // delete_key handler's H9 comment).
        let key = Tenant::key(&mut tenant, "key1")
            .await
            .expect("key query works after migration");
        assert!(!key.retired, "legacy rows keep signing");
        assert_eq!(
            tenant.current_key("localhost").expect("seated").id,
            "key1",
            "the migrated row is seated as the domain signer"
        );
    }

    /// G-88: backup validates the DBs open, copies the tree and writes a
    /// manifest; restore refuses to merge into a non-empty data dir, and
    /// the restored tree boots as a working Storage with the original
    /// data. (jwt.db is only asserted when present — the revocation-store
    /// singleton is first-wins per process, so which env's data dir holds
    /// it depends on test order.)
    #[tokio::test]
    async fn backup_and_restore_round_trip() {
        let _ = crate::crypto::setup_encryption_key(&"0".repeat(64));
        let tmp = tempfile::tempdir().expect("tempdir");
        let data = tmp.path().join("data");
        {
            let storage = crate::db::Storage::init(&data).await.expect("init");
            storage.new_tenant("bk").await.expect("tenant");
            storage.add_domain("bk.local", "bk").await.expect("domain");
            let mut tenant = storage.tenant_by_id("bk").expect("tenant");
            tenant.user_create("alice").await.expect("user");
        } // storage drops here → locks released (the cold-backup precondition)

        let (backup_dir, manifest) = crate::db::backup_data_dir(&data, &tmp.path().join("backups"))
            .await
            .expect("backup");
        assert_eq!(manifest.version, 1);
        assert_eq!(manifest.tenants, vec!["bk".to_string()]);
        assert!(
            manifest
                .files
                .iter()
                .any(|f| f.ends_with("tenants/bk/janux.db")),
            "the tenant schema must be in the backup: {:?}",
            manifest.files
        );
        assert!(backup_dir.join("manifest.json").exists());

        // Restore refuses to merge into a non-empty data dir...
        let restored = tmp.path().join("restored");
        tokio::fs::create_dir_all(restored.join("tenants"))
            .await
            .expect("dir");
        assert!(
            crate::db::restore_data_dir(&backup_dir, &restored, false)
                .await
                .is_err(),
            "restore must refuse a non-empty data dir without force"
        );

        // ...and into a fresh dir the restored tree boots as a working
        // Storage with the original data.
        let fresh = tmp.path().join("fresh-restore");
        crate::db::restore_data_dir(&backup_dir, &fresh, false)
            .await
            .expect("restore into a fresh dir");
        let storage = crate::db::Storage::init(&fresh)
            .await
            .expect("reloaded storage");
        let mut tenant = storage.tenant_by_id("bk").expect("tenant restored");
        assert!(
            tenant.user("alice").await.is_ok(),
            "user data must survive the round trip"
        );
    }

    /// G-150: `janux rekey` re-encrypts every at-rest secret under the
    /// new key — the old process key no longer decrypts, the new cipher
    /// decrypts everything, and the signing-key PEM survives intact.
    #[tokio::test]
    async fn rekey_reencrypts_every_secret_under_the_new_key() {
        let _ = crate::crypto::setup_encryption_key(&"0".repeat(64));
        let tmp = tempfile::tempdir().expect("tempdir");
        let new_hex = "b7".repeat(32);
        {
            let storage = crate::db::Storage::init(tmp.path()).await.expect("init");
            storage.new_tenant("rk").await.expect("tenant");
            storage.add_domain("rk.local", "rk").await.expect("domain");
            let mut tenant = storage.tenant_by_id("rk").expect("tenant");
            tenant.key_create("rk.local", "key1").await.expect("key");
            tenant
                .provider_create("prov", "cid", "provider-secret", "https://issuer.example")
                .await
                .expect("provider");
            crate::config::ResendDTO {
                from: "noreply@rk.local".into(),
                resend_key: "re_secret".into(),
                template: "./template/email/verify.html".into(),
                verify_url: "http://rk.local/login".into(),
                base_url: None,
            }
            .save(&mut tenant)
            .await
            .expect("resend config");
        }

        let report = crate::db::rekey_data_dir(tmp.path(), &new_hex)
            .await
            .expect("rekey");
        assert_eq!(report.tenants, 1);
        assert_eq!(report.signing_keys, 1);
        assert_eq!(report.provider_secrets, 1);
        assert!(report.config_secrets >= 1, "{report:?}");

        let cipher = crate::crypto::parse_key_hex(&new_hex).expect("cipher");
        let storage = crate::db::Storage::init(tmp.path()).await.expect("reload");
        let mut tenant = storage.tenant_by_id("rk").expect("tenant");

        // The OLD process key no longer decrypts the signing private;
        // the new cipher does, and the PEM is intact.
        let key = Tenant::key(&mut tenant, "key1").await.expect("key row");
        let stored = String::from_utf8(key.private.clone()).expect("utf8");
        assert!(
            crate::crypto::decrypt_secret(&stored).is_err(),
            "the old key must not decrypt rekeyed rows"
        );
        let pem = crate::crypto::decrypt_secret_with(&cipher, &stored).expect("new key decrypts");
        assert!(pem.contains("PRIVATE KEY"), "PEM survives the rekey");

        let providers = tenant.all_providers().await;
        assert_eq!(
            crate::crypto::decrypt_secret_with(&cipher, &providers[0].client_secret)
                .expect("provider secret"),
            "provider-secret"
        );

        let raw = tenant
            .config_get(crate::config::RESEND_KEY)
            .await
            .and_then(|v| v.as_str().map(str::to_string))
            .expect("resend key row");
        assert_eq!(
            crate::crypto::decrypt_secret_with(&cipher, &raw).expect("config secret"),
            "re_secret"
        );
    }

    /// M8: `new_tenant`'s duplicate check must consult the TENANT map. A
    /// tenant whose name collides with a registered domain is a new tenant
    /// (`router` is domain-keyed — the old check wrongly refused it), and a
    /// real duplicate is refused with the honest "already exists" error
    /// instead of the misleading "directory exists but was not loaded".
    #[tokio::test]
    async fn new_tenant_duplicate_check_uses_the_tenant_map() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage = crate::db::Storage::init(tmp.path())
            .await
            .expect("storage init");
        storage.new_tenant("alpha").await.expect("alpha");
        storage.add_domain("beta", "alpha").await.expect("domain");

        // "beta" is a registered domain but not a tenant — must be creatable.
        storage
            .new_tenant("beta")
            .await
            .expect("a domain name is not a tenant name");

        // A real duplicate is refused with the honest error. (`Tenant` is not
        // `Debug`, so `expect_err` is unavailable — match instead.)
        let err = match storage.new_tenant("alpha").await {
            Ok(_) => panic!("a duplicate tenant must be refused"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("already exists"),
            "duplicate tenant must report 'already exists', got: {err}"
        );
    }
}
