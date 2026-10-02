// src/dump.rs
//
// `janux dump` — a cold, read-only export of the tenant data in a data dir
// to a `janux-dump/1` TOML bundle, for migration to another auth system.
//
// Per-credential classification (each factor records one):
//
//   Portable   — usable material travels as-is. Two sub-gates:
//              * verifier carry (Argon2 client-secret hash, TOTP base32
//                shared secret) is emitted by default; a target that speaks
//                Argon2id or TOTP can use them with no human action.
//              * decrypted AES material (social provider client_secret,
//                mail/SMS keys, signing-key private halves) is gated by
//                `--secrets --yes`.
//
//   Repro      — metadata only; the target re-provisions on first use.
//                (Social bindings are `Repro`: the user authenticates via
//                the provider at the target after the provider config is
//                loaded.)
//
//   Advisory   — cannot survive a dump/load round-trip. Passkeys are
//                rp-scoped WebAuthn credentials with no ratified CXP
//                portability as of 2026-04; we emit rp_id / created_at /
//                name plus a warning, not the bytes.
//
// The dump never fails hard on a non-portable factor: it degrades
// gracefully and records a per-user liveness warning. janux is multi-
// factor, so a user with any surviving factor can still log in at the
// target; a user with none lands in
// `account_warnings.locked_out` and must be provisioned by an admin.
//
// The report shape is a v1 skeleton — the per-class extractors (identity
// + roles + emails + mobiles) are wired in; the decryption-bearing
// factor loaders (TOTP, social bindings, passkey advisories, OAuth2
// clients, social provider config, mail/SMS, signing keys, domains)
// fill in as they land.

use std::path::Path;

use anyhow::Result;
use serde::Serialize;

use crate::config::{OTPDTO, ResendDTO};
use crate::idp::OAuth2Client;
use crate::db::{HttpMethod, Storage};
use crate::policy::{Policy, SourceResolver, TargetResolver};
use crate::user::User;

#[allow(unused_imports)]
mod _models {
   pub use crate::config::{OTPDTO, ResendDTO};
   pub use crate::idp::OAuth2Client;
   pub use crate::key::Key;
   pub use crate::passkey::Passkey;
   pub use crate::role::UserRole;
   pub use crate::social::{OAuth2, SocialProvider};
   pub use crate::totp::Totp;
}

/// Sentinel for a secret-bearing field that is present at rest but
/// redacted from this dump because `--secrets` was not passed.
pub const REDACTED: &str = "****redacted****";

/// Per-credential classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
   /// The material travels verbatim; a target can use it immediately.
    Portable,
   /// Only metadata travels; the target re-provisions on first use.
    Repro,
   /// The factor cannot survive a dump/load; advisory metadata + warning.
    Advisory,
}

// ─── Per-credential factor shapes ─────────────────────────────────────────

/// A TOTP factor attached to a user.
#[derive(Debug, Clone, Serialize)]
pub struct TotpFactor {
   pub name: String,
   pub active: bool,
   pub status: Class,
   /// janux pins SHA1 / 6 digits / 30s period on the verifier side
   /// (see totp.rs `TOTP::new`); the shared secret is what travels.
    pub algorithm: &'static str,
    pub digits: u32,
    pub period: u32,
   /// The base32 TOTP shared secret when `--secrets` is set; otherwise
   /// [`REDACTED`].
    pub secret: String,
    pub domain_id: String,
    pub created_at: jiff::Timestamp,
}

/// A passkey *advisory* entry — the bytes do NOT travel.
#[derive(Debug, Clone, Serialize)]
pub struct PasskeyAdvisory {
   pub passkey_id: String,
   pub active: bool,
   pub status: Class,
   pub reason: &'static str,
   /// The RP the credential was issued to; a target that wants to offer
   /// a re-enrollment prompt must own this `rp_id` domain (or accept a
   /// sub-domain under it).
   #[serde(skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    pub name: String,
    pub created_at: jiff::Timestamp,
}

/// A social binding — the user authenticated via an external provider.
#[derive(Debug, Clone, Serialize)]
pub struct SocialBinding {
   pub provider_id: String,
   pub provider_user_id: String,
   pub status: Class,
   /// A target that knows the same `provider_id` (provider config) AND
   /// the same `provider_user_id` row can link the binding; if any of
   /// those diverge the user must re-authenticate via the provider at
   /// the target on first login.
    pub created_at: jiff::Timestamp,
}

/// An OAuth2 client record. The Argon2 hash travels as a portable
/// verifier.
#[derive(Debug, Clone, Serialize)]
pub struct Oauth2ClientEntry {
   pub client_id: String,
   pub client_uuid: uuid::Uuid,
   pub active: bool,
   pub status: Class,
   /// Argon2id hash — self-describing: a target that speaks Argon2id can
   /// verify a presented secret without re-running the work factor.
    pub client_secret_hash: String,
   /// Grace-window predecessor, if a rotation was in flight at dump time.
   #[serde(skip_serializing_if = "Option::is_none")]
    pub client_prev_secret_hash: Option<String>,
   #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_grace_until: Option<jiff::Timestamp>,
    pub grant_types: String,
    pub response_types: String,
    pub token_endpoint_auth_method: String,
    pub scope: String,
    pub redirect_uris: Vec<String>,
    pub domain_id: String,
    pub created_at: jiff::Timestamp,
}

/// Email address attached to a user.
#[derive(Debug, Clone, Serialize)]
pub struct EmailEntry {
   pub address: String,
   pub verified: bool,
}

/// Phone number attached to a user (SMS / OTP).
#[derive(Debug, Clone, Serialize)]
pub struct MobileEntry {
   pub mobile: String,
}

// ─── Top-level report ─────────────────────────────────────────────────────

/// A user account with its attached factors.
#[derive(Debug, Clone, Serialize)]
pub struct UserEntry {
   pub user_id: uuid::Uuid,
   pub name: String,
   #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub active: bool,
   pub roles: Vec<String>,
   #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub emails: Vec<EmailEntry>,
   #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mobiles: Vec<MobileEntry>,
   #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub totp_factors: Vec<TotpFactor>,
   #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub social_bindings: Vec<SocialBinding>,
   #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passkey_advisories: Vec<PasskeyAdvisory>,

        /// Best-effort account-liveness verdict, computed from the factors
        /// above.
    pub liveness: Liveness,
}

/// Whether the user can sign into a target that loads this dump.
///
/// `LoginImmediately`   — at least one active portable factor (TOTP
///                       shared secret, Argon2 client-secret hash).
/// `LoginAfterSocial`   — no portable factor, but at least one social
///                       binding (the user signs in via the provider at
///                       the target after the provider config is
///                       loaded).
/// `LockedOut`          — the user has *only* non-portable factors
///                       (passkeys, rp-scoped). Must be provisioned by
///                       an admin or vouched via federation.
/// `NoFactor`           — the user carries no factors at all on janux.
///                       A pre-feature account, a seed stub, or a
///                       misconfig.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Liveness {
   LoginImmediately,
   LoginAfterSocial,
   LockedOut,
   NoFactor,
}

/// Per-tenant machine config section.
#[derive(Debug, Clone, Serialize, Default)]
pub struct TenantConfig {
   pub name: String,
   #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mail: Option<MailEntry>,
   #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sms: Option<SmsEntry>,
   #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub social_providers: Vec<SocialProviderEntry>,
   #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signing_keys: Vec<SigningKeyEntry>,
   #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<DomainEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub oauth2_clients: Vec<Oauth2ClientEntry>,
     #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<PolicyEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MailEntry {
   pub from: String,
   /// Decrypted when `--secrets` is set; otherwise [`REDACTED`].
    pub resend_key: String,
    pub template: String,
    pub verify_url: String,
   #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    pub status: Class,
}

#[derive(Debug, Clone, Serialize)]
pub struct SmsEntry {
   pub api_key: String,
   pub api_secret: String,
   pub template_code: String,
   pub sign_name: String,
   pub region_id: String,
   pub endpoint: String,
   pub status: Class,
}

#[derive(Debug, Clone, Serialize)]
pub struct SocialProviderEntry {
   pub id: String,
   pub client_id: String,
   pub issuer_url: String,
   pub scopes: Vec<String>,
   pub status: Class,
   /// Decrypted client secret when `--secrets` is set; otherwise
   /// [`REDACTED`]. A non-redacted value lets a target re-register the
   /// provider without contacting the identity upstream.
    pub client_secret: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SigningKeyEntry {
   pub id: String,
   pub retired: bool,
   pub domain_id: String,
   /// The public half always travels — a target only needs to *verify*
   /// tokens the source issued.
    pub public_pem: String,
   /// The private half travels only when `--secrets` is set; otherwise
   /// [`REDACTED`]. Without it the target can verify but not re-sign.
    pub private_pem: String,
   pub status: Class,
}

#[derive(Debug, Clone, Serialize)]
pub struct DomainEntry {
   pub name: String,
   #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cors: Vec<String>,
   #[serde(skip_serializing_if = "Option::is_none")]
    pub acme_email: Option<String>,
   /// Whether the tenant holds a cert / key PEM for this domain at
   /// rest.
    /// The bytes are NOT emitted: a target that owns the ACME account
   /// can re-issue; without ACME it must upload.
   #[serde(skip_serializing_if = "Option::is_none")]
    pub has_cert: Option<bool>,
   #[serde(skip_serializing_if = "Option::is_none")]
    pub has_key: Option<bool>,
}

/// A single RBAC policy row in a tenant. The policy engine is
/// default-deny: every (domain, resource, method) is denied unless a
/// row permits it. A target that loads this bundle re-creates the
/// policy graph by upserting these rows; a target that does NOT
/// understand janux RBAC can read the rows as an access matrix
/// (role -> resource -> allow/deny) and decide what to do.
///
/// `source`/`target` are self-scoping resolvers: they say *where*
/// the identity that is compared comes from (JWT user, domain,
/// role, path param, query, header, or nothing). An empty
/// `resource` matches any path in the domain.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyEntry {
   pub id: uuid::Uuid,
   pub domain_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<HttpMethod>,
   pub resource: Vec<String>,
   pub role_id: String,
   pub source: SourceResolver,
   pub target: TargetResolver,
   pub mfa: bool,
   pub allowed: bool,
   pub created_at: jiff::Timestamp,
}


/// Top-of-bundle manifest: the contract a target loader checks before
/// attempting anything destructive.
#[derive(Debug, Clone, Serialize, Default)]
pub struct DumpManifest {
   pub schema: &'static str,
   pub source: &'static str,
   /// The janux-side identity namespace users were provisioned under,
   /// so a target can compute `janux:user:<name>` if it wants to
   /// round-trip the username.
    pub source_user_prefix: &'static str,
    pub generated_at: jiff::Timestamp,
    pub secrets_emit: bool,
   /// `--domain` set to a single tenant. `None` = every tenant in the
   /// data dir was dumped.
   #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct AccountWarnings {
   /// login_immediately / login_after_social / locked_out / no_factor.
   #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub login_immediately: Vec<String>,
   #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub login_after_social: Vec<String>,
   #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locked_out: Vec<String>,
   #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub no_factor: Vec<String>,
}

/// The whole dump output.
#[derive(Debug, Clone, Serialize, Default)]
pub struct DumpReport {
   pub manifest: DumpManifest,
   #[serde(rename = "users", default, skip_serializing_if = "Vec::is_empty")]
    pub user_entries: Vec<UserEntry>,
   #[serde(rename = "tenants", default, skip_serializing_if = "Vec::is_empty")]
    pub tenant_configs: Vec<TenantConfig>,
    pub account_warnings: AccountWarnings,
}

// ─── Options ──────────────────────────────────────────────────────────────

/// Options for the cold dump operation.
#[derive(Debug, Clone)]
pub struct DumpOptions {
   pub data_dir: std::path::PathBuf,
    /// Decrypt AES-encrypted fields and emit them in the clear.
    pub secrets: bool,
    /// Restrict to one domain (its owning tenant).
    pub domain: Option<String>,
}

#[allow(dead_code)]
impl DumpOptions {
   pub fn new(data_dir: impl Into<std::path::PathBuf>) -> Self {
      Self {
         data_dir: data_dir.into(),
         secrets: false,
         domain: None,
          }
   }
}

// ─── Entry point ──────────────────────────────────────────────────────────

/// Walk the data dir, build a `janux-dump/1` bundle.
pub async fn dump_data_dir(
   data_dir: &Path,
   secrets: bool,
   domain: Option<&str>,
) -> Result<DumpReport> {
       // The --secrets path decrypts AES-encrypted fields. The caller
       // (main.rs) has already installed the process-wide key from
       // JANUX_ENCRYPTION_KEY before calling in; decrypt_secret will fail
       // with a clean "key not set" error if that setup was skipped.
    let _ = secrets;
   let mut report = DumpReport::default();
   let storage = Storage::init(data_dir).await?;

    // `--domain` filters to that tenant's owning id; `None` = all
    // tenants.
   let tenant_ids: Vec<String> = match domain {
      Some(d) => storage
          .tenant_by_domain(d)
          .map(|_| d.to_string())
          .into_iter()
          .collect(),
      None => storage.tenant_ids(),
    };

   let mut immediate: Vec<String> = Vec::new();
   let mut after_social: Vec<String> = Vec::new();
   let mut locked_out: Vec<String> = Vec::new();
   let mut no_factor: Vec<String> = Vec::new();

   for id in tenant_ids {
      let Some(mut tenant) = storage.tenant_by_id(&id) else {
         continue;
        };

        // ── Users ──
       for u in tenant.all_users().await? {
          let entry = build_user_entry(&mut tenant, &id, u, secrets).await?;
          let liveness = classify(&entry);
          match liveness {
             Liveness::LoginImmediately => immediate.push(entry.name.clone()),
             Liveness::LoginAfterSocial => after_social.push(entry.name.clone()),
             Liveness::LockedOut => locked_out.push(entry.name.clone()),
             Liveness::NoFactor => no_factor.push(entry.name.clone()),
              }
          report.user_entries.push(entry);
         }

         // ── Tenant-level config ──
         report.tenant_configs.push(build_tenant_config(&mut tenant, &id, secrets).await?);
      }

   report.account_warnings = AccountWarnings {
      login_immediately: immediate,
      login_after_social: after_social,
      locked_out,
      no_factor,
      };
   report.manifest = DumpManifest {
      schema: "janux-dump/1",
      source: "janux",
      source_user_prefix: "janux:user:",
      generated_at: jiff::Timestamp::now(),
      secrets_emit: secrets,
      domain: domain.map(|s| s.to_string()),
      };

   Ok(report)
}

/// Render the report as a `janux-dump/1` TOML string.
pub fn to_toml(report: &DumpReport) -> Result<String> {
   toml::to_string_pretty(report).map_err(Into::into)
}

// ─── Extractors ───────────────────────────────────────────────────────────

/// Build a per-tenant `TenantConfig`. Every tenant-level loader runs
/// here: mail/SMS/social providers/signing keys/domains/OAuth2 clients
/// and the RBAC policy graph. Decryption-bearing fields are gated on --secrets.
async fn build_tenant_config(
   tenant: &mut crate::db::Tenant,
    id: &str,
     secrets: bool,
) -> Result<TenantConfig> {
   Ok(TenantConfig {
      name: id.to_string(),
      mail: load_mail(tenant, secrets).await,
      sms: load_sms(tenant, secrets).await,
      social_providers: load_social_providers(tenant, secrets).await?,
      signing_keys: load_signing_keys(tenant, secrets).await?,
      domains: load_domains(tenant).await,
      oauth2_clients: load_oauth2_clients(tenant).await?,
      policies: load_policies(tenant).await?,
       })
}

// ─── Tenant-level loaders ─────────────────────────────────────────────────

/// Load the tenant's Resend (mail) config, if any.
async fn load_mail(
   tenant: &mut crate::db::Tenant,
     secrets: bool,
) -> Option<MailEntry> {
   let dto = ResendDTO::load(tenant).await?;
   Some(MailEntry {
      from: dto.from,
      resend_key: redacted_or(dto.resend_key, secrets),
      template: dto.template,
      verify_url: dto.verify_url,
      base_url: dto.base_url,
      status: Class::Portable,
   })
}

/// Load the tenant's SMS (OTP) config, if any.
async fn load_sms(
   tenant: &mut crate::db::Tenant,
     secrets: bool,
) -> Option<SmsEntry> {
   let dto = OTPDTO::load(tenant).await?;
   Some(SmsEntry {
      api_key: redacted_or(dto.api_key, secrets),
      api_secret: redacted_or(dto.api_secret, secrets),
      template_code: dto.template_code,
      sign_name: dto.sign_name,
      region_id: dto.region_id,
      endpoint: dto.endpoint,
      status: Class::Portable,
   })
}

/// Load every social login provider the tenant has registered.
async fn load_social_providers(
   tenant: &mut crate::db::Tenant,
     secrets: bool,
) -> Result<Vec<SocialProviderEntry>> {
   Ok(tenant
           .all_providers()
           .await
           .into_iter()
           .map(|p| SocialProviderEntry {
               id: p.id,
               client_id: p.client_id,
               issuer_url: p.issuer_url,
               scopes: p.scopes,
               status: Class::Portable,
               client_secret: redacted_or(p.client_secret, secrets),
               })
           .collect())
}

/// Load every OAuth2 client registered on the tenant. The Argon2id
/// hash on `client_secret_hash` is self-describing and portable:
/// a target that speaks Argon2id can verify a presented secret
/// without re-running the work factor (verifier material, not
/// decrypted secret, so it emits always with no `--secrets` gate).
async fn load_oauth2_clients(
    tenant: &mut crate::db::Tenant,
) -> Result<Vec<Oauth2ClientEntry>> {
       // `OAuth2Client::all()` returns every client in this tenant's
       // toasty database (a tenant lives in its own DB file, so the
       // tenant is implicit). For each client we resolve the `has_many`
       // `redirect_uris` deferred explicitly via
       // `oauth2client_redirect_uris` -- `into_inner()` on an unloaded
       // deferred panics. URI resolution needs `&mut tenant`, so the
       // loop is sequential: clients are few in practice.
    let clients = OAuth2Client::all().exec(&mut tenant.database).await?;
    let mut out = Vec::with_capacity(clients.len());
    for c in clients {
        let uris = tenant
                    .oauth2client_redirect_uris(&c.id)
                    .await
                    .map(|v| v.into_iter().map(|r| r.uri).collect())
                    .unwrap_or_default();
        out.push(Oauth2ClientEntry {
            client_id: c.id,
            client_uuid: c.uuid,
            active: c.active,
            status: Class::Portable,
            client_secret_hash: c.client_secret_hash,
            client_prev_secret_hash: c.client_prev_secret_hash,
            secret_grace_until: c.secret_grace_until,
            grant_types: c.grant_types,
            response_types: c.response_types,
            token_endpoint_auth_method: c.token_endpoint_auth_method,
            scope: c.scope,
            redirect_uris: uris,
            domain_id: c.domain_id,
            created_at: c.created_at,
              });
              }
    Ok(out)
}

/// Load every RBAC policy row in the tenant. The policy engine is
/// default-deny: a (domain, resource, method) tuple is denied unless a
/// row permits it. The full graph travels so a target can
/// faithfully re-create the access matrix; policies are verifier
/// metadata (no decryption), so this loader is not gated on
/// --secrets.
///
/// Self-scoping resolvers travel too: an empty `resource` matches
/// any path in the domain, and `source`/`target` say where the
/// compared identity is read from.
async fn load_policies(
    tenant: &mut crate::db::Tenant,
) -> Result<Vec<PolicyEntry>> {
    let rows = Policy::all()
               .exec(&mut tenant.database)
               .await?;
    Ok(rows
               .into_iter()
               .map(|p| PolicyEntry {
                    id: p.id,
                    domain_id: p.domain_id,
                    action: p.action,
                    resource: p.resource,
                    role_id: p.role_id,
                    source: p.source,
                    target: p.target,
                    mfa: p.mfa,
                    allowed: p.allowed,
                    created_at: p.created_at,
                     })
               .collect())
}


/// Load every signing key the tenant holds; public half always,
/// private half gated on --secrets.
async fn load_signing_keys(
   tenant: &mut crate::db::Tenant,
     secrets: bool,
) -> Result<Vec<SigningKeyEntry>> {
   Ok(tenant
           .all_keys()
           .await?
           .into_iter()
           .map(|k| {
              let public_pem = String::from_utf8_lossy(&k.public).to_string();
              let private_pem = if secrets {
                     crate::crypto::decrypt_secret_or_legacy(
                           &String::from_utf8_lossy(&k.private)
                          )
                   } else {
                     REDACTED.to_string()
                   };
              let status = if secrets {
                 Class::Portable
                 } else {
                     Class::Repro
                 };
              SigningKeyEntry {
                  id: k.id,
                  retired: k.retired,
                  domain_id: k.domain_id,
                  public_pem,
                  private_pem,
                  status,
                 }
           })
           .collect())
}

/// Load the tenant's registered domains (no secrets).
async fn load_domains(
   tenant: &mut crate::db::Tenant,
) -> Vec<DomainEntry> {
   let domains = tenant.all_domains().await;
   domains
            .into_iter()
            .map(|d| {
              let has_cert = d.cert.as_ref().map(|v| !v.is_empty());
              let has_key = d.key.as_ref().map(|v| !v.is_empty());
              DomainEntry {
                  name: d.id,
                  cors: d.cors,
                  acme_email: d.acme_email,
                  has_cert,
                  has_key,
                  }
            })
            .collect()
}
/// Build a `UserEntry` for one user, gathering identity + roles +
/// email + mobile + TOTP + social + passkey advisories.
async fn build_user_entry(
   tenant: &mut crate::db::Tenant,
    tenant_name: &str,
    u: User,
     secrets: bool,
) -> Result<UserEntry> {
       // Identity and roles are unencrypted; always emit.
    let role_ids = collect_roles(tenant, u.id).await?;
    let emails = collect_emails(tenant, &u.name).await?;
    let mobiles = collect_mobiles(tenant, &u.name).await?;
    let totp_factors =
           collect_totp_factors(tenant, tenant_name, &u.name, secrets).await?;
    let social_bindings =
           collect_social_bindings(tenant, u.id).await?;
    let passkey_advisories =
           collect_passkey_advisories(tenant, u.id).await?;

    Ok(UserEntry {
        user_id: u.id,
        name: u.name,
        external_id: u.external_id,
        active: u.active,
        roles: role_ids,
        emails,
        mobiles,
        totp_factors,
        social_bindings,
        passkey_advisories,
        liveness: Liveness::NoFactor,
       })
}

// ─── Per-user factor loaders ─────────────────────────────────────────────

/// Load every TOTP factor attached to a user. The base32 shared
/// secret is portable but is bearer-equivalent (anyone holding it
/// can generate codes), so it is gated on `--secrets`. Metadata
/// (name / algorithm / digits / period / created_at / active) always
/// travels.
async fn collect_totp_factors(
   tenant: &mut crate::db::Tenant,
    tenant_name: &str,
    user_name: &str,
     secrets: bool,
) -> Result<Vec<TotpFactor>> {
       // A generous limit — a single user cannot have more than a
       // handful of TOTP factors.
    let page = tenant.totps_page(Some(user_name), None, 1024, 0).await?;
    Ok(page
              .items
             .into_iter()
             .map(|t| {
                let secret = if secrets {
                       crate::crypto::decrypt_secret_or_legacy(&t.secret)
                    } else {
                       REDACTED.to_string()
                    };
                TotpFactor {
                    name: t.name,
                    active: t.active,
                    status: Class::Portable,
                    algorithm: "SHA1",
                    digits: 6,
                    period: 30,
                    secret,
                    domain_id: tenant_name.to_string(),
                    created_at: t.created_at,
                }
             })
             .collect())
}

/// Load every social login binding attached to a user. Bindings
/// travel as `Repro` metadata — the target must host the same
/// `provider_id` (loaded by [`load_social_providers`]) AND the same
/// `provider_user_id` row to admit the user without an external
/// sign-in.
async fn collect_social_bindings(
   tenant: &mut crate::db::Tenant,
     user_id: uuid::Uuid,
) -> Result<Vec<SocialBinding>> {
    Ok(tenant
             .all_oauth2(None)
             .await?
             .into_iter()
             .filter(|o| o.user_id == user_id)
             .map(|o| SocialBinding {
                    provider_id: o.provider_id,
                    provider_user_id: o.provider_user_id,
                    status: Class::Repro,
                    created_at: o.created_at,
                 })
             .collect())
}

/// Load passkey advisories for a user. Passkeys are rp-scoped
/// WebAuthn credentials that cannot travel to a target RP under a
/// different `rp_id`. The advisory carries only `active` /
/// `rp_id` (from `domain_id`) / `created_at` so a target can
/// offer "re-enroll at this domain" UX; the credential bytes
/// are never emitted.
async fn collect_passkey_advisories(
   tenant: &mut crate::db::Tenant,
     user_id: uuid::Uuid,
) -> Result<Vec<PasskeyAdvisory>> {
    Ok(tenant
             .passkey(None, None)
             .await?
             .into_iter()
             .filter(|p| p.user_id == user_id)
             .map(|p| PasskeyAdvisory {
                    passkey_id: p.id,
                    active: p.active,
                    status: Class::Advisory,
                    reason: "RP-scoped WebAuthn credential; not portable to a target RP",
                    rp_id: Some(p.domain_id),
                    name: p.public_key,
                    created_at: p.created_at,
                 })
             .collect())
}

/// Collect the role ids assigned to a user. Returns a `Vec<String>` of
/// `Role.id` values so the TOML is a flat `roles = [...]` list the
/// target can match against its own role catalog (or use verbatim if it
/// trusts the source's catalog).
async fn collect_roles(tenant: &mut crate::db::Tenant, user_id: uuid::Uuid) -> Result<Vec<String>> {
   Ok(tenant
          .user_roles(user_id)
          .await?
          .into_iter()
          .map(|r| r.id)
          .collect())
}

/// Collect the email addresses attached to a user (canonical form as
/// stored on `Email.id`). Each email entry carries its `verified` flag
/// so a target can know which addresses to trust.
async fn collect_emails(
   tenant: &mut crate::db::Tenant,
   user_name: &str,
) -> Result<Vec<EmailEntry>> {
   Ok(tenant
          .all_emails(Some(user_name))
          .await?
          .into_iter()
          .map(|e| EmailEntry {
             address: e.id,
             verified: e.verified,
              })
          .collect())
}

/// Collect the mobile numbers attached to a user. The canonical spelling
/// is on `OTP.id` — that is the only form stored.
async fn collect_mobiles(
   tenant: &mut crate::db::Tenant,
   user_name: &str,
) -> Result<Vec<MobileEntry>> {
   Ok(tenant
          .all_mobiles(Some(user_name))
          .await?
          .into_iter()
          .map(|m| MobileEntry { mobile: m.id })
          .collect())
}

/// Decide whether a user can sign into a target that loads this dump.
///
/// A target that loads `janux-dump/1` accepts the user's *portable*
/// factors (TOTP shared secret, Argon2 client-secret hash) as
/// usable-on-arrival. `social_bindings` travel as `Repro` metadata: the
/// target must host the same `provider_id` to admit the user without an
/// external sign-in. `passkey_advisories` are non-portable — the target
/// must re-enroll the user at its own `rp_id`.
///
/// Liveness is a best-effort summary, not a gate — it never blocks the
/// dump.
fn classify(entry: &UserEntry) -> Liveness {
   let active_totp = entry
        .totp_factors
        .iter()
        .any(|f| f.active && f.status == Class::Portable);
   let any_social = !entry.social_bindings.is_empty();
    // Any factor, including non-portable, to distinguish `NoFactor`
    // from `LockedOut`.
   let any_factor =
      active_totp || any_social || !entry.passkey_advisories.is_empty();

   if active_totp {
      Liveness::LoginImmediately
   } else if any_social {
      Liveness::LoginAfterSocial
   } else if any_factor {
      Liveness::LockedOut
   } else {
      Liveness::NoFactor
   }
}

/// Redaction helper for use inside the per-class extractors.
#[allow(dead_code)]
fn redacted_or(plaintext: String, emit: bool) -> String {
   if emit {
      plaintext
   } else {
      REDACTED.to_string()
   }
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
   use super::*;

       /// An empty report serializes to a valid `janux-dump/1` TOML
       /// string with the manifest at the top.
       #[test]
     fn empty_report_serializes() {
        let mut r = DumpReport::default();
        r.manifest = DumpManifest {
           schema: "janux-dump/1",
           source: "janux",
           source_user_prefix: "janux:user:",
           generated_at: jiff::Timestamp::now(),
           secrets_emit: false,
           domain: None,
            };
        let out = to_toml(&r).expect("serialize");
        assert!(out.contains("schema = \"janux-dump/1\""));
        assert!(out.contains("[manifest]"));
        }

        /// Redaction: when emission is off, the sentinel replaces the
        /// at-rest value; when on, the plaintext passes through.
        #[test]
     fn redaction_gates_secret_fields() {
        assert_eq!(redacted_or("s3cr3t".to_string(), true), "s3cr3t");
        assert_eq!(
           redacted_or("s3cr3t".to_string(), false),
           REDACTED.to_string()
            );
        }

        /// Liveness: no factors at all → `NoFactor`, not `LockedOut`.
        #[test]
     fn liveness_no_factor() {
        let mut e = UserEntry {
           user_id: uuid::Uuid::nil(),
           name: "alice".to_string(),
           external_id: None,
           active: true,
           roles: Vec::new(),
           emails: Vec::new(),
           mobiles: Vec::new(),
           totp_factors: Vec::new(),
           social_bindings: Vec::new(),
           passkey_advisories: Vec::new(),
           liveness: Liveness::NoFactor,
            };
        e.liveness = classify(&e);
        assert_eq!(e.liveness, Liveness::NoFactor);
        }

        /// Liveness: a social binding but no portable factor →
        /// `LoginAfterSocial`.
        #[test]
     fn liveness_after_social() {
        let mut e = UserEntry {
           user_id: uuid::Uuid::nil(),
           name: "bob".to_string(),
           external_id: None,
           active: true,
           roles: Vec::new(),
           emails: Vec::new(),
           mobiles: Vec::new(),
           totp_factors: Vec::new(),
           social_bindings: vec![SocialBinding {
              provider_id: "google".to_string(),
              provider_user_id: "123".to_string(),
              status: Class::Repro,
              created_at: jiff::Timestamp::now(),
               }],
           passkey_advisories: Vec::new(),
           liveness: Liveness::NoFactor,
            };
        e.liveness = classify(&e);
        assert_eq!(e.liveness, Liveness::LoginAfterSocial);
        }

        /// Liveness: an active portable TOTP — `LoginImmediately`.
        #[test]
     fn liveness_immediately_from_totp() {
        let mut e = UserEntry {
           user_id: uuid::Uuid::nil(),
           name: "carol".to_string(),
           external_id: None,
           active: true,
           roles: Vec::new(),
           emails: Vec::new(),
           mobiles: Vec::new(),
           totp_factors: vec![TotpFactor {
              name: "yubikey".to_string(),
              active: true,
              status: Class::Portable,
              algorithm: "SHA1",
              digits: 6,
              period: 30,
              secret: "JBSWY3DPEHPK3PXP".to_string(),
              domain_id: "example.com".to_string(),
              created_at: jiff::Timestamp::now(),
               }],
           social_bindings: Vec::new(),
           passkey_advisories: Vec::new(),
           liveness: Liveness::NoFactor,
            };
        e.liveness = classify(&e);
        assert_eq!(e.liveness, Liveness::LoginImmediately);
        }

        /// Liveness: a passkey-only user — `LockedOut` (rp-scoped, not
        /// portable).
        #[test]
     fn liveness_locked_out_from_passkey() {
        let mut e = UserEntry {
           user_id: uuid::Uuid::nil(),
           name: "dave".to_string(),
           external_id: None,
           active: true,
           roles: Vec::new(),
           emails: Vec::new(),
           mobiles: Vec::new(),
           totp_factors: Vec::new(),
           social_bindings: Vec::new(),
           passkey_advisories: vec![PasskeyAdvisory {
              passkey_id: "abc".to_string(),
              active: true,
              status: Class::Advisory,
              reason: "RP-scoped WebAuthn credential",
              rp_id: Some("example.com".to_string()),
              name: "laptop".to_string(),
              created_at: jiff::Timestamp::now(),
               }],
           liveness: Liveness::NoFactor,
            };
        e.liveness = classify(&e);
        assert_eq!(e.liveness, Liveness::LockedOut);
        }

         // Regression: a full user-with-factors dump produces a TOML
         // bundle that names the user, carries the schema marker, and
         // gates on --secrets.
      #[tokio::test]
    async fn dump_data_dir_roundtrip_identities() {
        let _ = crate::crypto::setup_encryption_key(&"0".repeat(64));
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage = crate::db::Storage::init(tmp.path())
             .await
             .expect("storage init");
        storage.new_tenant("test-tenant").await.expect("tenant");
        storage
             .add_domain("localhost", "test-tenant")
             .await
             .expect("domain");
        {
           let mut tenant = storage.tenant_by_id("test-tenant").expect("tenant");
           tenant.key_create("localhost", "key1").await.expect("key");
           tenant.user_create("alice").await.expect("user");
           // Attach a mobile + email so the loaders have something to
           // pull.
           tenant.mobile_create("alice", "+13800000000").await.expect("mobile");
           tenant.email_create("alice", "alice@example.com").await.expect("email");
        }

          // No --secrets: the user entry must carry name/mobile/email
          // even though no decryption happened.
        let report = dump_data_dir(tmp.path(), false, None)
             .await
             .expect("dump");
        let alice = report
             .user_entries
             .iter()
             .find(|u| u.name == "alice")
             .expect("alice present");
        assert_eq!(alice.name, "alice");
        assert_eq!(
            alice.mobiles.iter().map(|m| m.mobile.as_str()).collect::<Vec<_>>(),
            vec!["+13800000000"]
         );
        assert_eq!(
            alice.emails.iter().map(|e| e.address.as_str()).collect::<Vec<_>>(),
            vec!["alice@example.com"]
         );
        assert_eq!(alice.liveness, Liveness::NoFactor);

          // The manifest carries the schema marker and secrets_emit=false.
        assert_eq!(report.manifest.schema, "janux-dump/1");
        assert!(!report.manifest.secrets_emit);

          // TOML round-trips.
        let toml = to_toml(&report).expect("serialize");
        assert!(toml.contains("alice"), "TOML must name alice");
        assert!(toml.contains("alice@example.com"), "TOML must carry email");
        assert!(toml.contains("+13800000000"), "TOML must carry mobile");
     }


           // Regression: a TOTP factor is always emitted with
           // metadata (name, algorithm, digits, period, domain_id,
           // created_at) and its secret redacted to the sentinel when
           // --secrets is off. With --secrets the plaintext base32
           // secret travels.
        #[tokio::test]
    async fn dump_data_dir_totp_redaction() {
        let _ = crate::crypto::setup_encryption_key(&"0".repeat(64));
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage = crate::db::Storage::init(tmp.path())
              .await
               .expect("storage init");
        storage.new_tenant("test-tenant").await.expect("tenant");
        storage
               .add_domain("localhost", "test-tenant")
               .await
               .expect("domain");
        const SECRET: &str = "JBSWY3DPEHPK3PXP";
         {
           let mut tenant =
                  storage.tenant_by_id("test-tenant").expect("tenant");
           tenant.key_create("localhost", "key1").await.expect("key");
           tenant.user_create("alice").await.expect("user");
            // Active so the liveness check counts it; a 0-step seed
            // keeps the row dormant until first verify.
           tenant
                    .add_totp("alice", "yubikey", "test-tenant", SECRET)
                    .await
                    .expect("totp");
         }

             // No --secrets: factor present, secret redacted.
        let report = dump_data_dir(tmp.path(), false, None)
                .await
                .expect("dump");
        let alice = report
                .user_entries
                .iter()
                .find(|u| u.name == "alice")
                .expect("alice present");
        assert_eq!(alice.totp_factors.len(), 1,
            "expected exactly one TOTP factor");
        let t = &alice.totp_factors[0];
        assert_eq!(t.name, "yubikey");
        assert_eq!(t.secret, REDACTED);
          // add_totp() seeds the row inactive (active=false); liveness
// is therefore NoFactor. The point of this test is that the
// metadata travels regardless of active state so the target
// can decide.
            assert_eq!(alice.liveness, Liveness::NoFactor);
          // With --secrets the plaintext base32 secret travels.
        let report_s = dump_data_dir(tmp.path(), true, None)
                .await
                .expect("dump w/ secrets");
        let alice_s = report_s
                .user_entries
                .iter()
                .find(|u| u.name == "alice")
                .expect("alice present in secrets dump");
        assert_eq!(
            alice_s.totp_factors[0].secret,
            SECRET,
            "with --secrets the plaintext secret must travel"
        );
          // And the manifest records the difference.
        assert!(!report.manifest.secrets_emit);
        assert!(report_s.manifest.secrets_emit);
       }


              // Regression: an OAuth2 client registered on the tenant is
              // emitted in `TenantConfig.oauth2_clients` with its
              // Argon2id hash (verifier material, emits always),
              // redirect URIs resolved per client, and status=Portable.
           #[tokio::test]
    async fn dump_data_dir_includes_oauth2_clients() {
        let _ = crate::crypto::setup_encryption_key(&"0".repeat(64));
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage = crate::db::Storage::init(tmp.path())
                    .await
                    .expect("storage init");
        storage.new_tenant("test-tenant").await.expect("tenant");
        storage
                    .add_domain("localhost", "test-tenant")
                    .await
                    .expect("domain");
            {
           let mut tenant = storage.tenant_by_id("test-tenant").expect("tenant");
           tenant.key_create("localhost", "key1").await.expect("key");
           tenant
                    .oauth2client_create(
                         "localhost",
                         "svc",
                         "s3cr3t",
                         &["https://client.example.com/cb"],
                         "authorization_code",
                         "token",
                         "client_secret_post",
                         "openid profile",
                       true,
                    ).await
                    .expect("oauth2 client");
            }

                // No --secrets: Argon2id hash travels (verifier material,
                // not a decrypted secret). The redirect URIs resolve
                // per-client too.
        let report = dump_data_dir(tmp.path(), false, None).await.expect("dump");
        let tc = report.tenant_configs.iter().find(|t| t.name == "test-tenant")
                    .expect("tenant present");
        assert_eq!(tc.oauth2_clients.len(), 1,
            "expected exactly one OAuth2 client on the tenant");
        let c = &tc.oauth2_clients[0];
        assert_eq!(c.client_id, "svc");
        assert_eq!(c.domain_id, "localhost");
        assert_eq!(c.status, Class::Portable);
            // The Argon2id hash is emitted (verifier material, portable),
            // independent of --secrets.
        assert!(c.client_secret_hash.starts_with("$argon2"),
            "Argon2id hash must travel: actual: {}", c.client_secret_hash);
        assert_eq!(c.redirect_uris, vec!["https://client.example.com/cb"]);

                // With --secrets: same shape, manifest flags secrets_emit.
        let report_s = dump_data_dir(tmp.path(), true, None).await.expect("dump");
        let tc_s = report_s.tenant_configs.iter().find(|t| t.name == "test-tenant")
                     .expect("tenant present in secrets dump");
        assert_eq!(tc_s.oauth2_clients.len(), 1);
        assert_eq!(tc_s.oauth2_clients[0].client_id, "svc");
        assert!(!report.manifest.secrets_emit);
        assert!(report_s.manifest.secrets_emit);

                // TOML round-trips.
        let toml = to_toml(&report_s).expect("serialize");
        assert!(toml.contains("svc"), "TOML must contain the OAuth2 client id");
        assert!(toml.contains("$argon2"),
            "TOML must contain the Argon2id hash prefix");
            }



             // Regression: an RBAC policy registered on the tenant is
             // emitted in `TenantConfig.policies` with its full
             // self-scoping shape (resource / role / source / target /
             // mfa / allowed). Policies are verifier metadata, so they
             // travel regardless of --secrets.
          #[tokio::test]
    async fn dump_data_dir_includes_policies() {
        let _ = crate::crypto::setup_encryption_key(&"0".repeat(64));
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage = crate::db::Storage::init(tmp.path())
                  .await
                  .expect("storage init");
        storage.new_tenant("test-tenant").await.expect("tenant");
        storage
                  .add_domain("localhost", "test-tenant")
                  .await
                  .expect("domain");
           {
            let mut tenant =
                  storage.tenant_by_id("test-tenant").expect("tenant");
            tenant.key_create("localhost", "key1").await.expect("key");
            tenant.user_create("alice").await.expect("user");
             // A grant for the builtin "user" role over /api/v1/app,
             // bootstrap caller bypasses the level gate.
            let bootstrap = crate::role::Caller::Bootstrap;
            let nothing = crate::policy::SourceResolver::Nothing;
            let no_target = crate::policy::TargetResolver::Nothing;
            // The builtin "user" role must exist before a policy can
            // bind to it.
           tenant
                     .role_create(&bootstrap, "user", 0)
                     .await
                     .expect("role create");
           tenant
                     .policy_create(
                           &bootstrap,
                           "test-tenant",
                           Some(crate::db::HttpMethod::GET),
                          "/api/v1/app",
                           "user",
                           &nothing,
                           &no_target,
                          false,
                          true,
                     )
                     .await
                     .expect("policy create");
             }

              // The policy must appear on the tenant config.
        let report = dump_data_dir(tmp.path(), false, None)
                  .await
                  .expect("dump");
        let tc = report
                  .tenant_configs
                  .iter()
                  .find(|t| t.name == "test-tenant")
                  .expect("tenant present");
        assert_eq!(tc.policies.len(), 1,
             "expected exactly one policy on the tenant");
        let p = &tc.policies[0];
        assert_eq!(p.role_id, "user");
        assert_eq!(p.resource, vec!["", "api", "v1", "app"]);
        assert!(matches!(
             p.action,
             Some(crate::db::HttpMethod::GET)));
        assert!(p.allowed);
        assert!(!p.mfa);
        assert_eq!(p.source, crate::policy::SourceResolver::Nothing);
        assert_eq!(p.target, crate::policy::TargetResolver::Nothing);

              // TOML round-trips the policy.
        let toml = to_toml(&report).expect("serialize");
        assert!(toml.contains("user"), "TOML must name the role");
        // The resource segments are emitted per-segment; assert the
        // joined path appears in the TOML.
        assert!(
             toml.contains("app"),
             "TOML must carry the resource path");
        assert!(!report.manifest.secrets_emit);
         }

}