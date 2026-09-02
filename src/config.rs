use crate::db::Tenant;
use crate::utils::{ApiProblem, ApiResponse};
use anyhow::Result;
use salvo::prelude::*;
use serde::Deserialize;
#[derive(Debug, toasty::Model, Clone)]
pub struct Config {
    #[key]
    pub id: String,

    pub value: String,

    #[auto]
    pub created_at: jiff::Timestamp,
    #[auto]
    pub updated_at: jiff::Timestamp,
}

impl Tenant {
    pub async fn config_set(&mut self, name: &str, data_json: serde_json::Value) -> Result<Config> {
        let jsonx = serde_json::to_string(&data_json);
        if jsonx.is_err() {
            return Err(anyhow::anyhow!("Failed to serialize config data to JSON"));
        }
        let json = jsonx.unwrap();
        match Config::get_by_id(&mut self.database, name).await {
            Ok(mut record) => {
                record
                    .update()
                    .value(json.clone())
                    .exec(&mut self.database)
                    .await?;
                record.value = json;
                Ok(record)
            }
            Err(_) => toasty::create!(Config {
                id: name.to_string(),
                value: json,
            })
            .exec(&mut self.database)
            .await
            .map_err(Into::into),
        }
    }

    /// Get a config entry by type and name.
    pub async fn config_get(&mut self, name: &str) -> Option<serde_json::Value> {
        Config::get_by_id(&mut self.database, name)
            .await
            .ok()
            .and_then(|r| serde_json::from_str(&r.value).ok())
    }

    /// Get all config entries for a given type.
    pub async fn config_list(&mut self, prefix: &str) -> Vec<(String, serde_json::Value)> {
        match Config::all().exec(&mut self.database).await.ok() {
            Some(rows) => rows
                .into_iter()
                .filter_map(|r| {
                    if r.id.starts_with(prefix) {
                        serde_json::from_str(&r.value)
                            .ok()
                            .map(|v| (r.id.clone(), v))
                    } else {
                        None
                    }
                })
                .collect(),
            None => vec![],
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ResendDTO {
    pub from: String,
    pub resend_key: String,
    pub template: String,
    pub verify_url: String,
    /// Optional override of the Resend API base URL — a proxy or a test
    /// server (resend-rs documents this use case). `None` = the official
    /// Resend endpoint.
    pub base_url: Option<String>,
}

const RESEND_FROM: &str = "resend.from";
const RESEND_KEY: &str = "resend.key";
const RESEND_TEMPLATE: &str = "resend.template";
const RESEND_VERIFY_URL: &str = "resend.verify_url";
const RESEND_BASE_URL: &str = "resend.base_url";

impl ResendDTO {
    pub async fn load(tenant: &mut Tenant) -> Option<Self> {
        let from = tenant.config_get(RESEND_FROM).await?;
        let key = tenant.config_get(RESEND_KEY).await?;
        let template = tenant.config_get(RESEND_TEMPLATE).await?;
        let verify_url = tenant.config_get(RESEND_VERIFY_URL).await?;
        // Optional — tenants configured before this key existed keep
        // working against the official endpoint.
        let base_url = tenant
            .config_get(RESEND_BASE_URL)
            .await
            .and_then(|v| v.as_str().map(str::to_string));

        Some(Self {
            from: from.as_str()?.to_string(),
            resend_key: key.as_str()?.to_string(),
            template: template.as_str()?.to_string(),
            verify_url: verify_url.as_str()?.to_string(),
            base_url,
        })
    }
    pub async fn save(&self, tenant: &mut Tenant) -> Result<()> {
        tenant
            .config_set(RESEND_FROM, serde_json::json!(&self.from))
            .await?;
        tenant
            .config_set(RESEND_KEY, serde_json::json!(&self.resend_key))
            .await?;
        tenant
            .config_set(RESEND_TEMPLATE, serde_json::json!(&self.template))
            .await?;
        tenant
            .config_set(RESEND_VERIFY_URL, serde_json::json!(&self.verify_url))
            .await?;
        if let Some(base_url) = &self.base_url {
            tenant
                .config_set(RESEND_BASE_URL, serde_json::json!(base_url))
                .await?;
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize, Clone)]
#[allow(clippy::upper_case_acronyms)] // OTP is a domain acronym
pub struct OTPDTO {
    pub api_secret: String,
    pub api_key: String,
    pub template_code: String,
    pub sign_name: String,
    pub region_id: String,
    pub endpoint: String,
}

const OTP_API_SECRET: &str = "otp.api_secret";
const OTP_API_KEY: &str = "otp.api_key";
const OTP_TEMPLATE_CODE: &str = "otp.template_code";
const OTP_SIGN_NAME: &str = "otp.sign_name";
const OTP_REGION_ID: &str = "otp.region_id";
const OTP_ENDPOINT: &str = "otp.endpoint";

impl OTPDTO {
    pub async fn load(tenant: &mut Tenant) -> Option<Self> {
        let api_secret = tenant.config_get(OTP_API_SECRET).await?;
        let api_key = tenant.config_get(OTP_API_KEY).await?;
        let template_code = tenant.config_get(OTP_TEMPLATE_CODE).await?;
        let sign_name = tenant.config_get(OTP_SIGN_NAME).await?;
        let region_id = tenant.config_get(OTP_REGION_ID).await?;
        let endpoint = tenant.config_get(OTP_ENDPOINT).await?;

        Some(Self {
            api_secret: api_secret.as_str()?.to_string(),
            api_key: api_key.as_str()?.to_string(),
            template_code: template_code.as_str()?.to_string(),
            sign_name: sign_name.as_str()?.to_string(),
            region_id: region_id.as_str()?.to_string(),
            endpoint: endpoint.as_str()?.to_string(),
        })
    }
    pub async fn save(&self, tenant: &mut Tenant) -> Result<()> {
        tenant
            .config_set(OTP_API_SECRET, serde_json::json!(&self.api_secret))
            .await?;
        tenant
            .config_set(OTP_API_KEY, serde_json::json!(&self.api_key))
            .await?;
        tenant
            .config_set(OTP_TEMPLATE_CODE, serde_json::json!(&self.template_code))
            .await?;
        tenant
            .config_set(OTP_SIGN_NAME, serde_json::json!(&self.sign_name))
            .await?;
        tenant
            .config_set(OTP_REGION_ID, serde_json::json!(&self.region_id))
            .await?;
        tenant
            .config_set(OTP_ENDPOINT, serde_json::json!(&self.endpoint))
            .await?;
        Ok(())
    }
}

#[endpoint(
    summary = "List all configuraions in a tenant",
    responses(
        (status_code = 200, description = "Success — list of (key, value) pairs", body = serde_json::Value),
        (status_code = 400, description = "Bad request", body = ApiProblem),
    )
)]
pub async fn all_configs(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    if let Some(mut tenant) = state.storage.tenant_by_domain(domain) {
        let data = tenant.config_list("").await;
        res.status_code(StatusCode::OK);
        res.render(Json(ApiResponse::ok(data)));
        return;
    }
    let err = ApiProblem::validation_error("Failed to parse request body");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err))
}
