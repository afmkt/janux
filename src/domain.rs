use crate::db::Tenant;

use crate::idp::OAuth2Client;
use crate::key::Key;

use crate::policy::Policy;

use crate::totp::Totp;

use anyhow::Result;
use serde::Deserialize;
use toasty::*;

#[derive(Debug, Clone, Deserialize)]
pub struct DomainDTO {
    pub id: String,
    pub cors: Vec<String>,
    pub acme_email: Option<String>,
    pub cert: Option<String>,
    pub key: Option<String>,
    /// Filesystem root of the per-domain frontend page overrides (scaffold
    /// dumped by `janux dump-frontend`). Config-file-only by design — see
    /// `crate::pages`. Stored in the tenant Config store (`pages.<domain>`,
    /// the migration-free extension point) rather than as a Domain column.
    pub pages_dir: Option<String>,
}
impl DomainDTO {
    pub async fn save(&self, tenant: &mut Tenant) -> Result<()> {
        if tenant.domain(&self.id).await.is_ok() {
            tenant
                .domain_update(
                    &self.id,
                    self.cors.clone(),
                    self.acme_email.clone(),
                    self.cert.clone(),
                    self.key.clone(),
                )
                .await?;
        } else {
            tenant
                .domain_create(
                    &self.id,
                    self.cors.clone(),
                    self.acme_email.clone(),
                    self.cert.clone(),
                    self.key.clone(),
                )
                .await?;
        }
        // Declarative: an absent `pages_dir` REMOVES a previously seeded
        // binding, so deleting it from the config file actually disables
        // the override on restart (seeding is otherwise upsert-only).
        match &self.pages_dir {
            Some(dir) => {
                tenant
                    .config_set(
                        &crate::pages::pages_config_key(&self.id),
                        serde_json::json!(dir),
                    )
                    .await?;
            }
            None => {
                tenant
                    .config_delete(&crate::pages::pages_config_key(&self.id))
                    .await?;
            }
        }
        Ok(())
    }
}
#[derive(Debug, toasty::Model, Clone)]
pub struct Domain {
    #[key]
    pub id: String,

    // vec@([]) -> Forbid CORS
    // vec!(["tenant"]) -> Allow domains within the same tenant
    // vec!([...]) -> Explicit allow list
    #[default(vec![])]
    pub cors: Vec<String>,

    pub acme_email: Option<String>,
    pub cert: Option<String>,
    pub key: Option<String>,

    #[has_many]
    pub policies: Deferred<Vec<Policy>>,

    #[has_many]
    pub keys: Deferred<Vec<Key>>,

    #[has_many]
    pub totps: Deferred<Vec<Totp>>,

    #[has_many]
    pub oauth2_clients: Deferred<Vec<OAuth2Client>>,
}

impl Tenant {
    // domain CRUD

    pub async fn domain_create(
        &mut self,
        name: &str,
        cors: Vec<String>,
        acme_email: Option<String>,
        cert: Option<String>,
        key: Option<String>,
    ) -> Result<Domain> {
        toasty::create!(Domain {
            id: name,
            cors,
            acme_email,
            key,
            cert,
        })
        .exec(&mut self.database)
        .await
        .map_err(Into::into)
    }
    pub async fn domain_update(
        &mut self,
        name: &str,
        cors: Vec<String>,
        acme_email: Option<String>,
        cert: Option<String>,
        key: Option<String>,
    ) -> Result<()> {
        toasty::update!(Domain::filter(Domain::fields().id().eq(name)) {
            cors,
            acme_email,
            key,
            cert,
        })
        .exec(&mut self.database)
        .await
        .map_err(Into::into)
    }
    pub async fn domain_cors(&mut self, name: &str, cors: Vec<String>) -> Result<()> {
        if cors.len() > 1 {
            for c in &cors {
                if c.as_str() == "tenant" {
                    return Err(anyhow::anyhow!(
                        "Invalid cors setting, 'tenant' can not be mixed with other domains"
                    ));
                }
            }
        }
        Domain::update_by_id(name)
            .cors(cors)
            .exec(&mut self.database)
            .await
            .map_err(Into::into)
    }
    pub async fn domain_delete(&mut self, name: &str) -> Result<()> {
        Domain::delete_by_id(&mut self.database, name)
            .await
            .map(|_| ())
            .map_err(Into::<anyhow::Error>::into)
    }
    pub async fn domain(&mut self, domain: &str) -> Result<Domain> {
        Domain::get_by_id(&mut self.database, domain)
            .await
            .map_err(Into::into)
    }
    pub async fn all_domains(&mut self) -> Vec<Domain> {
        let ret = Domain::all()
            .exec(&mut self.database)
            .await
            .unwrap_or_default();
        ret.into_iter().collect()
    }
}
