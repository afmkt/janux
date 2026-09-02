use crate::cache::EphemCache;
use crate::key::Key;
use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::ToSpan;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::EncodingKey;
use jsonwebtoken::Header;
use jsonwebtoken::Validation;
// use rsa::RsaPublicKey;
// use rsa::pkcs8::DecodePublicKey;
// use rsa::traits::PublicKeyParts;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claim<T> {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: usize,
    pub iat: usize,
    pub nbf: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_hash: Option<String>,
    #[serde(flatten)]
    pub data: T,
}

// ──────────────────────────────────────────
// Internal vs. OIDC token generation
// ──────────────────────────────────────────

/// Parameters for the OIDC `/token` path.
#[derive(Debug, Clone)]
pub struct JwtOidcParams {
    /// client_id of the registered OAuth2 client (-> JWT aud)
    pub client_id: String,
    /// nonce from the original AuthorizeRequest / authorization code session
    pub nonce: Option<String>,
    /// MFA factors used for this authentication, e.g. ["pwd", "otp"]
    pub amr: Option<Vec<String>>,
    /// Auth Context Class Reference -- strongest factor achieved (e.g. "1", "2")
    pub acr: Option<String>,
    /// Access token value used to derive at_hash; None for flows without an access token
    pub access_token: Option<String>,
    /// Original authentication time (unix seconds). None stamps `now` (a fresh
    /// authentication just occurred); refresh flows MUST pass the original
    /// auth_time through so RPs can rely on max_age (OIDC Core §2).
    pub auth_time: Option<usize>,
}

/// Generate a JWT for the **OIDC `/token` endpoint**.
/// Populates all claims with correct semantic values expected by external relying parties
/// (per OpenID Connect Core 1.0 sections 2 and 5.1).
pub fn jwt_authenticate<T>(
    issuer: &str,
    subject: &str,
    data: &T,
    key: &Key,
    minutes: i32,
    params: JwtOidcParams,
) -> anyhow::Result<String>
where
    T: Serialize + Clone,
{
    // Per OIDC Core section 5.1 -- aud MUST be the client_id for IdP tokens.
    let now = jiff::Timestamp::now();
    let exp_time = now
        .checked_add(minutes.minutes())
        .map_err(|_e| anyhow::anyhow!("failed to calculate the expiration time"))?;

    // Compute at_hash per OIDC Core section 3.3.2.10.
    let at_hash = params
        .access_token
        .as_ref()
        .and_then(|at| compute_at_hash(at));

    let claim = Claim {
        iss: issuer.to_string(),
        sub: subject.to_string(),
        aud: params.client_id, // client_id -- not the issuer!
        exp: exp_time.as_second() as usize,
        iat: now.as_second() as usize,
        nbf: now.as_second() as usize,
        nonce: params.nonce, // from authorization code session (not random)
        // Original authentication time when supplied (refresh flows); a fresh
        // authentication stamps `now`. OIDC Core §2.
        auth_time: Some(params.auth_time.unwrap_or(now.as_second() as usize)),
        acr: params.acr.clone(), // strongest authentication factor achieved
        amr: params.amr.clone(), // list of auth methods used
        at_hash,
        data: data.clone(),
    };

    encode_jwt(&claim, key)
}

/// Mint an OIDC Back-Channel Logout token (OpenID Connect Back-Channel
/// Logout 1.0 §2.4). Unlike ID tokens it carries no `nonce` (the spec
/// forbids it) and no `auth_time`/`acr`/`amr`/`at_hash` — only the
/// envelope claims plus the caller-supplied payload, which MUST contain
/// the `jti` and the `events` claim marking it as a logout token.
/// `aud` is the client_id of the RP the token is issued for.
pub fn jwt_logout<T>(
    issuer: &str,
    subject: &str,
    client_id: &str,
    key: &Key,
    seconds: i64,
    data: &T,
) -> anyhow::Result<String>
where
    T: Serialize + Clone,
{
    let now = jiff::Timestamp::now();
    let exp_time = now
        .checked_add(seconds.seconds())
        .map_err(|_e| anyhow::anyhow!("failed to calculate the expiration time"))?;

    let claim = Claim {
        iss: issuer.to_string(),
        sub: subject.to_string(),
        aud: client_id.to_string(),
        exp: exp_time.as_second() as usize,
        iat: now.as_second() as usize,
        nbf: now.as_second() as usize,
        nonce: None,
        auth_time: None,
        acr: None,
        amr: None,
        at_hash: None,
        data: data.clone(),
    };

    encode_jwt(&claim, key)
}

/// Encode a Claim into a JWT with the given RSA signing key.
fn encode_jwt<T: Serialize>(claim: &Claim<T>, key: &Key) -> anyhow::Result<String> {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key.id.clone());

    jsonwebtoken::encode(&header, claim, &EncodingKey::from_rsa_pem(&key.private)?)
        .map_err(Into::into)
}

fn compute_at_hash(access_token: &str) -> Option<String> {
    let mut hasher = Sha256::new();

    hasher.update(access_token.as_bytes());
    let digest = hasher.finalize();

    // Take first 16 bytes (half of SHA-256 output) and base64url encode with no padding.
    Some(URL_SAFE_NO_PAD.encode(&digest[..16]))
}

pub async fn jwt_decode<T>(
    token: &str,
    grace: i32,
    tenant: &mut crate::db::Tenant,
) -> anyhow::Result<jsonwebtoken::TokenData<Claim<T>>>
where
    T: DeserializeOwned,
{
    let header = jsonwebtoken::decode_header(token)?;
    let kid = header
        .kid
        .ok_or_else(|| anyhow::anyhow!("Token header is broken, missing kid"))?;
    let key = tenant.key(&kid).await?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.leeway = (grace * 60) as u64;
    // Every token this server issues carries an aud claim (aud = client_id
    // for OIDC tokens per OIDC Core §5.1, aud = domain for internal ones),
    // but the audience is the relying party, not this IdP — and the expected
    // value differs per token kind and caller. jsonwebtoken's default would
    // reject ANY token carrying aud when no expected audience is configured
    // (RFC 7519 §4.1.3), so audience checks are left to the callers, which
    // already validate iss/sub/client_id for their context.
    validation.validate_aud = false;
    let data = jsonwebtoken::decode::<Claim<T>>(
        token,
        &DecodingKey::from_rsa_pem(&key.public)?,
        &validation,
    )?;
    Ok(data)
}

#[derive(Debug, toasty::Model, Clone)]
pub struct InvalidJWT {
    #[key]
    id: String,
    #[index]
    expire_at: jiff::Timestamp,
}

pub struct InvalidJwt {
    db: toasty::Db,
    cache: LazyLock<EphemCache<String, jiff::Timestamp>>,
}

/// The single process-wide revocation store. There is exactly one `jwt.db`
/// per data dir, so the store is a module-level singleton (same pattern as
/// the OIDC_* caches): every writer (/revoke, refresh rotation, logout) and
/// every revocation check (userinfo, the API middleware) must see the SAME
/// instance, or revocations silently don't propagate between them.
static INVALID_JWT: tokio::sync::OnceCell<InvalidJwt> = tokio::sync::OnceCell::const_new();

impl InvalidJwt {
    /// Initialize the process-wide revocation store backed by `<dir>/jwt.db`.
    /// The first call wins; later calls (e.g. `Storage::init` re-running
    /// during seed) reuse the existing store.
    pub async fn init_global(dir: &Path) -> Result<()> {
        INVALID_JWT
            .get_or_try_init(|| InvalidJwt::create(dir))
            .await
            .map(|_| ())
    }

    /// The process-wide revocation store. Panics only if accessed before
    /// `init_global` — a startup-ordering bug, since `Storage::init` runs
    /// before any request is served.
    pub fn global() -> &'static InvalidJwt {
        INVALID_JWT
            .get()
            .expect("InvalidJwt store not initialized — Storage::init must run first")
    }

    /// The process-wide store if initialized, without panicking. For
    /// observability paths (ops::metrics) where a missing store should
    /// degrade gracefully instead of crashing the scrape.
    pub fn try_global() -> Option<&'static InvalidJwt> {
        INVALID_JWT.get()
    }

    async fn connect(dir: &Path) -> toasty::Result<toasty::Db> {
        let path: PathBuf = PathBuf::from(dir).join("jwt.db");
        let driver = toasty_driver_turso::Turso::file(path).concurrent_writes();
        let db = toasty::Db::builder()
            .models(toasty::models!(crate::jwt::InvalidJWT))
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
    pub async fn create(dir: &Path) -> Result<Self> {
        let mut db = InvalidJwt::connect(dir).await?;
        // TTL and capacity are backstops only: every revocation expires on
        // its own within the 30-day refresh-family window and gc() prunes
        // the rest, so the cache normally tracks exactly the live set.
        let cache: LazyLock<EphemCache<String, jiff::Timestamp>> = LazyLock::new(|| {
            EphemCache::with_capacity("invalid_cache", Some(30 * 24 * 3600), 100_000)
        });
        // Expired records are skipped on hydration — they can never reject a
        // token again and would only crowd live revocations out of the cache.
        let now = jiff::Timestamp::now();
        let records = InvalidJWT::filter(InvalidJWT::fields().expire_at().ge(now))
            .exec(&mut db)
            .await?;
        for r in records {
            cache
                .insert(r.id, r.expire_at)
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
        }
        Ok(InvalidJwt { db, cache })
    }

    /// Revocation entries are keyed by the SHA-256 of the identifier rather
    /// than the identifier itself: refresh tokens are ~1KB JWT strings and
    /// the store persists one row per rotation, so hashing keeps the DB and
    /// the cache small. Lookups hash the same way and additionally check the
    /// raw identifier, so records written before hashing was introduced stay
    /// effective until they expire.
    fn revocation_id(id: &str) -> String {
        let digest = sha2::Sha256::digest(id.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    }

    /// Takes `&self` so the shared ServerState (injected per request) can
    /// revoke tokens without exclusive access; `toasty::Db` is a cheap
    /// Arc-backed handle, so we clone it for the mutable exec calls.
    ///
    /// Returns `true` when this call revoked the token and `false` when it
    /// was already revoked. The cache insert is the atomic winner point, so
    /// exactly one of several concurrent callers racing on the same token
    /// (e.g. competing refresh-token rotations) observes `true`.
    pub async fn invalid(&self, token: &str, tenant: &mut crate::db::Tenant) -> Result<bool> {
        let tkn = jwt_decode::<serde_json::Value>(token, 2, tenant).await?;
        let exp_ts = jiff::Timestamp::from_second(tkn.claims.exp as i64)?;
        self.invalid_raw(token, exp_ts).await
    }

    /// Invalidate an opaque identifier without decoding a JWT — used for
    /// revocation markers such as the one covering a whole refresh-token
    /// family. Returns `true` when the identifier was newly invalidated.
    ///
    /// The cache insert is the atomic winner point for concurrent callers,
    /// but the persistent write is what must survive: when it fails the
    /// cache entry is rolled back, because a memory-only revocation would
    /// consume the token until restart — a retry at the refresh rotation
    /// commit point would then trip replay detection and revoke the whole
    /// family over a transient persistence error.
    pub async fn invalid_raw(&self, id: &str, expire_at: jiff::Timestamp) -> Result<bool> {
        let key = Self::revocation_id(id);
        if self.cache.insert(key.clone(), expire_at).await.is_err() {
            return Ok(false);
        }
        let mut db = self.db.clone();
        if let Err(e) = toasty::create!(InvalidJWT {
            id: key.clone(),
            expire_at
        })
        .exec(&mut db)
        .await
        {
            self.cache.remove(&key).await;
            return Err(anyhow::anyhow!(e));
        }
        crate::ops::record_revocation();
        Ok(true)
    }
    /// Number of revocation records currently stored. Observability only
    /// (the `janux_revocation_records_stored` gauge) — the verification
    /// path never consults this.
    pub async fn len(&self) -> Result<u64> {
        let mut db = self.db.clone();
        Ok(InvalidJWT::all().count().exec(&mut db).await?)
    }
    /// Whether `token` has been revoked. Cache-first, with a read-through
    /// to the persistent store on miss: a cache eviction, a restart
    /// between revocation and check, or a revocation recorded by another
    /// instance sharing the data dir must not resurrect a revoked token.
    /// Persistent hits are backfilled into the cache.
    pub async fn is_valid(&self, token: &str) -> bool {
        let key = Self::revocation_id(token);
        if self.cache.contains_key(&key).await {
            return true;
        }
        // Records written before revocation ids were hashed keyed the raw
        // identifier; keep honoring them until they expire.
        if self.cache.contains_key(token).await {
            return true;
        }
        // read-through: consult the persistent store before accepting
        // the token. Expired records are skipped — they can no longer
        // reject anything (gc prunes them on its own schedule).
        let mut db = self.db.clone();
        let now = jiff::Timestamp::now();
        for id in [&key, token] {
            if let Ok(record) = InvalidJWT::get_by_id(&mut db, id).await
                && record.expire_at > now
            {
                self.cache
                    .insert(id.to_string(), record.expire_at)
                    .await
                    .ok();
                return true;
            }
        }
        false
    }
    pub async fn gc(&self) -> Result<()> {
        let mut db = self.db.clone();
        let now = jiff::Timestamp::now();
        let expired = InvalidJWT::filter(InvalidJWT::fields().expire_at().lt(now))
            .exec(&mut db)
            .await?;
        for entry in &expired {
            self.cache.remove(&entry.id).await;
            InvalidJWT::delete_by_id(&mut db, &entry.id).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// regression: a revocation recorded by ANOTHER instance sharing
    /// the data dir — present in `jwt.db` but absent from this instance's
    /// cache — must still reject the token. The read-through finds it. An
    /// unknown identifier must stay accepted.
    #[tokio::test]
    async fn read_through_finds_revocations_missed_by_the_cache() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let a = InvalidJwt::create(tmp.path()).await.expect("instance A");
        let b = InvalidJwt::create(tmp.path()).await.expect("instance B");

        let token = "g71-revoked-token";
        let exp = jiff::Timestamp::now()
            .checked_add(1.hours())
            .expect("future expiry");
        assert!(b.invalid_raw(token, exp).await.expect("revoke"));

        // A's cache never saw the write — only the shared persistent
        // store has it, so this exercises the read-through.
        assert!(
            a.is_valid(token).await,
            "read-through must find the revocation in the shared store"
        );
        assert!(
            !a.is_valid("g71-never-revoked").await,
            "an unknown identifier must stay accepted"
        );
    }
}
