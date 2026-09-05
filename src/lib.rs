// src/lib.rs
//
// Library target for janux. Declares all modules as public so they're
// testable from both lib-level #[cfg(test)] and external crate/dependency contexts.
//
// The binary targets (src/main.rs, src/bin/) still work — main.rs imports
// through the library just like before.

#[path = "cache.rs"]
pub mod cache;
#[path = "crypto.rs"]
pub mod crypto;
#[path = "db.rs"]
pub mod db;
#[path = "domain.rs"]
pub mod domain;
#[path = "email.rs"]
pub mod email;
#[path = "idp.rs"]
pub mod idp;
#[path = "jwt.rs"]
pub mod jwt;
#[path = "key.rs"]
pub mod key;
#[path = "oidc.rs"]
pub mod oidc;
#[path = "oidc_ext.rs"]
pub mod oidc_ext;
#[path = "policy.rs"]
pub mod policy;
#[path = "role.rs"]
pub mod role;
#[path = "seed.rs"]
pub mod seed;
#[path = "social.rs"]
pub mod social;
#[path = "utils.rs"]
pub mod utils;

// These are server-bound (salvo/http) — declared for completeness but not needed
// by the current unit test harness. We declare them so they're available for
// e2e / integration tests that may need to inspect types.
#[path = "admin.rs"]
pub mod admin;
#[path = "aliclient.rs"]
pub mod aliclient;
#[path = "audit.rs"]
pub mod audit;
#[path = "config.rs"]
pub mod config;
#[path = "cors.rs"]
pub mod cors;
#[path = "ops.rs"]
pub mod ops;
#[path = "otp.rs"]
pub mod otp;
#[path = "pages.rs"]
pub mod pages;
#[path = "passkey.rs"]
pub mod passkey;
#[path = "router.rs"]
pub mod router;
#[path = "scim.rs"]
pub mod scim;
#[path = "server.rs"]
pub mod server;
#[path = "totp.rs"]
pub mod totp;
#[path = "user.rs"]
pub mod user;
#[path = "verify.rs"]
pub mod verify;

// Re-export types needed by the unit test harness (tests/unit_tests)
pub use crate::cache::EphemCache;
pub use crate::crypto::{decrypt_client_secret, encrypt_client_secret, setup_encryption_key};
pub use crate::db::HttpMethod;
pub use crate::db::JwtData;
pub use crate::policy::{CanAccess, Policy, PolicyDTO, SourceResolver, TargetResolver};
