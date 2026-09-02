// Spec-generation tool: it re-includes the whole module tree but only
// exercises `router::api()`, so everything wired up elsewhere (e.g.
// `InvalidJwt::gc`, spawned from src/main.rs) reads as "dead" here.
#![allow(dead_code)]

use salvo::oapi::OpenApi;

#[path = "../db.rs"]
pub mod db;

#[path = "../router.rs"]
pub mod router;

#[path = "../scim.rs"]
pub mod scim;

#[path = "../email.rs"]
pub mod email;
#[path = "../server.rs"]
pub mod server;
#[path = "../verify.rs"]
pub mod verify;

#[path = "../admin.rs"]
pub mod admin;

#[path = "../user.rs"]
pub mod user;

#[path = "../otp.rs"]
pub mod otp;

#[path = "../ops.rs"]
pub mod ops;

#[path = "../aliclient.rs"]
pub mod aliclient;

#[path = "../role.rs"]
pub mod role;

#[path = "../policy.rs"]
pub mod policy;

#[path = "../cors.rs"]
mod cors;

#[path = "../key.rs"]
mod key;

#[path = "../utils.rs"]
mod utils;

#[path = "../audit.rs"]
mod audit;

#[path = "../social.rs"]
mod social;

#[path = "../passkey.rs"]
mod passkey;

#[path = "../totp.rs"]
mod totp;

#[path = "../idp.rs"]
mod idp;

#[path = "../cache.rs"]
mod cache;

#[path = "../crypto.rs"]
mod crypto;

#[path = "../jwt.rs"]
mod jwt;

#[path = "../oidc.rs"]
mod oidc;

#[path = "../oidc_ext.rs"]
mod oidc_ext;

#[path = "../config.rs"]
mod config;

#[path = "../seed.rs"]
mod seed;

#[path = "../domain.rs"]
mod domain;

fn main() {
    let api_router = router::api();
    let openapi = OpenApi::new("Secure Auth Microservice API", "1.0.0").merge_router(&api_router);
    let json_output = openapi
        .to_json()
        .expect("Failed to convert Salvo OpenApi definition into JSON metadata string");
    let json: serde_json::Value =
        serde_json::from_str(&json_output).expect("Failed to parse inner Salvo OpenAPI string");
    let pretty = serde_json::to_string_pretty(&json).expect("Failed to pretty print OpenAPI JSON");
    println!("{}", pretty);
}
