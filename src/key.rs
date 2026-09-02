use crate::db::Tenant;
use crate::domain::Domain;
use crate::utils::{ApiProblem, ApiResponse};
use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use dashmap::DashMap;

use rsa::pkcs8::DecodePublicKey;

use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, Jwk, JwkSet, PublicKeyUse, RSAKeyParameters, RSAKeyType,
};

use rsa::RsaPublicKey;

use rsa::traits::PublicKeyParts;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use toasty::*;
#[derive(Debug, toasty::Model, Clone)]
#[unique(public, private)]
pub struct Key {
    #[key]
    pub id: String,

    pub public: Vec<u8>,
    pub private: Vec<u8>,
    #[index]
    pub domain_id: String,
    #[belongs_to(key = domain_id, references = id)]
    pub domain: Deferred<Domain>,
}
impl Key {
    pub fn public_pem(&self) -> Result<String> {
        String::from_utf8(self.public.clone()).map_err(Into::into)
    }
    pub fn private_pem(&self) -> Result<String> {
        String::from_utf8(self.private.clone()).map_err(Into::into)
    }
}

impl Tenant {
    /// Populates the per-domain active key cache, which is used as a default signer
    /// when issuing new JWTs.
    ///
    /// A domain may have multiple keys (e.g. during rotation), but signing only needs
    /// one. Any key in the DB can sign tokens — the `kid` carried by each JWT header
    /// uniquely routes verification to the correct key regardless of which one this
    /// cache holds.
    ///
    /// Since iteration order of `all_keys()` is nondeterministic, if a domain has
    /// multiple keys the "active" key is chosen arbitrarily. This is intentional:
    /// any key works for signing. To remove a key from consideration entirely,
    /// delete it from the database.
    pub async fn active_key_cache(&mut self) -> Result<DashMap<String, Key>> {
        let ret = DashMap::new();
        let ks = self.all_keys().await?;
        for k in ks {
            ret.insert(k.domain_id.clone(), k);
        }
        Ok(ret)
    }

    pub fn current_key(&self, domain: &str) -> Result<Key> {
        match self.keys.get(domain) {
            Some(key) => Ok(key.value().clone()),
            None => Err(anyhow::anyhow!("No active key")),
        }
    }

    pub async fn key_create(&mut self, domain: &str, name: &str) -> Result<()> {
        let alg = &rcgen::PKCS_RSA_SHA256;
        let pruned_key = rcgen::KeyPair::generate_for(alg)?;
        let private = pruned_key.serialize_pem().into_bytes();
        let public = pruned_key.public_key_pem().into_bytes();

        toasty::create!(Key {
            id: name,
            public,
            private,
            domain_id: domain,
        })
        .exec(&mut self.database)
        .await
        .map(|_| ())
        .map_err::<anyhow::Error, _>(Into::into)?;

        // Insert the new key into the in-memory cache so it is visible for signing.
        if let Ok(key) = self.key(name).await {
            self.keys.insert(domain.to_string(), key);
        }

        Ok(())
    }

    pub async fn key(&mut self, name: &str) -> Result<Key> {
        Key::get_by_id(&mut self.database, name)
            .await
            .map_err(Into::into)
    }

    pub async fn all_keys(&mut self) -> Result<Vec<Key>> {
        Key::all()
            .exec(&mut self.database)
            .await
            .map_err(Into::into)
    }

    pub async fn key_delete(&mut self, name: &str) -> Result<()> {
        let k = self.key(name).await?;

        // Remove from persistent storage
        if let Err(e) = Key::delete_by_id(&mut self.database, name).await {
            return Err(anyhow::anyhow!(
                "failed to delete key '{}' from DB: {}",
                name,
                e
            ));
        }
        if let Some((s, k)) = self.keys.remove(&k.domain_id) {
            assert!(s == k.domain_id);
            let domain = self.domain(&k.domain_id).await?;
            if let Some(new_key) = domain.keys.get().iter().next() {
                self.keys.insert(k.domain_id, new_key.clone());
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct KeyEntry {
    pub name: String,
    pub public: String,
    pub domain: String,
}

#[endpoint(
    summary = "List all keys in a tenant",
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<Vec<KeyEntry>>),
        (status_code = 400, description = "Bad request", body = ApiProblem),
    )
)]
pub async fn all_keys(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    if let Some(mut tenant) = state.storage.tenant_by_domain(domain)
        && let Ok(keys) = tenant.all_keys().await
    {
        res.status_code(StatusCode::OK);
        res.render(Json(ApiResponse::ok(
            keys.iter()
                .map(|entry| {
                    if let Ok(dk) = entry.public_pem() {
                        return KeyEntry {
                            name: entry.id.clone(),
                            public: dk,
                            domain: entry.domain_id.clone(),
                        };
                    }
                    KeyEntry {
                        name: entry.id.clone(),
                        public: String::from("Invalid public key"),
                        domain: entry.domain_id.clone(),
                    }
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
struct Addkey {
    domain: String,
    name: String,
}

#[endpoint(
    summary = "Add scope to tenant",
    request_body = Addkey,
    responses(
        (status_code = 200, description = "Scope created successfully", body = ApiResponse<()>),
        (status_code = 400, description = "Bad request", body = ApiProblem)
    )
)]
pub async fn add_key(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    if let Some(body) = crate::utils::extract::<Addkey>(req, None).await {
        let state = depot.obtain_mut::<crate::server::ServerState>().unwrap();
        let domain = crate::utils::get_domain(req, state).unwrap_or("");
        if let Some(mut tenant) = state.storage.tenant_by_domain(domain)
            && tenant.key_create(&body.domain, &body.name).await.is_ok()
        {
            let resp = ApiResponse::ok(());
            res.status_code(StatusCode::OK);
            res.render(Json(resp));
            return;
        }
    };
    let err = ApiProblem::validation_error("Failed to parse request body");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err))
}

#[derive(Deserialize, ToSchema)]
pub struct DeleteKey {
    pub name: String,
}

#[endpoint(
    summary = "Remove a scope from tenant",
    request_body = DeleteKey,
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<()>),
        (status_code = 400, description = "Bad request", body = ApiProblem)
    )
)]
pub async fn delete_key(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    if let Some(body) = crate::utils::extract::<DeleteKey>(req, None).await {
        let state = depot.obtain_mut::<crate::server::ServerState>().unwrap();
        let domain = crate::utils::get_domain(req, state).unwrap_or("");
        if let Some(mut tenant) = state.storage.tenant_by_domain(domain)
            && tenant.key_delete(&body.name).await.is_ok()
        {
            let resp = ApiResponse::ok(());
            res.status_code(StatusCode::OK);
            res.render(Json(resp));
            return;
        }
    };
    let err = ApiProblem::validation_error("Failed to parse request body");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err))
}

// #[endpoint(
// summary = "OIDC Discovery Configuration",
// responses((status_code = 200, description = "Success", body = serde_json::Value))
// )]
// pub async fn oidc_configuration(req: &mut Request, res: &mut Response) {
// let host = req
// .headers()
// .get("HOST")
// .and_then(|v| v.to_str().ok())
// .unwrap_or("localhost");
// let base_url = format!("https://{}", host);

// let config = serde_json::json!({
// "issuer": base_url,
// "jwks_uri": format!("{}/.well-known/jwks.json", base_url),
// "id_token_signing_alg_values_supported": ["RS256"],
// "subject_types_supported": ["public"],
// });

// res.render(Json(config));
// }

#[endpoint(
    summary = "JSON Web Key Set (JWKS)",
    responses((status_code = 200, description = "Success", body = serde_json::Value))
)]
pub async fn jwks_endpoint(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let domain = crate::utils::get_domain(req, state).unwrap_or("");

    let mut jwk_set = JwkSet { keys: vec![] };

    if let Some(mut tenant) = state.storage.tenant_by_domain(domain)
        && let Ok(keys) = tenant.all_keys().await
    {
        for key_model in keys {
            // Convert stored PEM public key into a jsonwebtoken JWK
            if let Ok(public_pem) = key_model.public_pem()
                && let Ok(jwk) = pem_to_jwk(&public_pem, &key_model.id)
            {
                jwk_set.keys.push(jwk);
            }
        }
    }

    res.render(Json(jwk_set));
}

fn pem_to_jwk(pub_pem: &str, kid: &str) -> Result<Jwk, Box<dyn std::error::Error>> {
    let pub_key = RsaPublicKey::from_public_key_pem(pub_pem)?;

    let n_bytes = pub_key.n().to_bytes_be();
    let e_bytes = pub_key.e().to_bytes_be();

    let n = URL_SAFE_NO_PAD.encode(n_bytes);
    let e = URL_SAFE_NO_PAD.encode(e_bytes);

    let jwk = Jwk {
        common: CommonParameters {
            key_id: Some(kid.to_string()),
            public_key_use: Some(PublicKeyUse::Signature),
            ..Default::default()
        },
        algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
            key_type: RSAKeyType::RSA,
            n,
            e,
        }),
    };

    Ok(jwk)
}
