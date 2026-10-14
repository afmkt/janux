//! E2E: an API key is a full session everywhere, *except* it may not mint
//! another API key.
//!
//! The policy decision (see `apikey.md`): a long-lived API key is accepted
//! wherever a session is — including credential add/remove — because it is the
//! same principal with the same roles. The one refusal is **self-mint**: a key
//! that could mint a successor before its `exp` would escape its own lifetime
//! bound via an unbounded rotation chain, so `reject_if_apikey` blocks the
//! `api-key` endpoint when the presenter is itself an API key.

use crate::fixtures::TestApiClient;

/// A session may mint an API key, and the minted token carries the
/// `api_key+jwt` marker and an `access_token` to use as a Bearer credential.
#[tokio::test]
async fn session_mints_an_api_key() {
    let base_url = super::shared_server().await;
    let session = TestApiClient::admin_bearer_token().await;

    let url = format!("{}/api/v1/auth/api-key", base_url.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .post(&url)
        .header("Host", "localhost")
        .header("Authorization", format!("Bearer {session}"))
        .json(&serde_json::json!({ "lifetime_seconds": 3600 }))
        .send()
        .await
        .expect("mint request");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "a session must be able to mint an API key"
    );
    let body: serde_json::Value = resp.json().await.expect("mint json body");
    assert_eq!(body["ok"], true, "mint body: {body}");
    assert_eq!(
        body["data"]["typ"].as_str(),
        Some("api_key+jwt"),
        "the minted key must carry the api_key+jwt marker"
    );
    assert!(
        body["data"]["access_token"].as_str().is_some(),
        "the minted key must include an access_token, got {body}"
    );
}

/// An API key presented to the mint endpoint is refused (403): a key that could
/// self-mint would escape its `exp` and live forever.
#[tokio::test]
async fn api_key_cannot_self_mint() {
    let base_url = super::shared_server().await;
    let session = TestApiClient::admin_bearer_token().await;
    let client = reqwest::Client::new();

    // 1. Mint an API key from the session.
    let url = format!("{}/api/v1/auth/api-key", base_url.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .header("Host", "localhost")
        .header("Authorization", format!("Bearer {session}"))
        .json(&serde_json::json!({ "lifetime_seconds": 3600 }))
        .send()
        .await
        .expect("mint request");
    let body: serde_json::Value = resp.json().await.expect("mint json body");
    let api_key = body["data"]["access_token"]
        .as_str()
        .expect("a minted access_token");

    // 2. Present that API key to the mint endpoint → must be refused.
    let resp2 = client
        .post(&url)
        .header("Host", "localhost")
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&serde_json::json!({ "lifetime_seconds": 3600 }))
        .send()
        .await
        .expect("self-mint request");

    assert_eq!(
        resp2.status(),
        reqwest::StatusCode::FORBIDDEN,
        "an API key must not be able to mint another API key"
    );
}
