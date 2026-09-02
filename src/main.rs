mod admin;
mod aliclient;
mod audit;
mod cache;
mod config;
mod cors;
mod crypto;
mod db;
mod domain;
mod email;
mod idp;
mod jwt;
mod key;
mod oidc;
mod oidc_ext;
mod ops;
mod otp;
mod passkey;
mod policy;
mod role;
mod router;
mod scim;
mod seed;
mod server;
mod social;
mod totp;
mod user;
mod utils;
mod verify;
use std::path::Path;

use crate::server::JanuxConfig;
use crate::server::ServerState;
use clap::Parser;

/// CLI arguments parsed with clap derive.
#[derive(clap::Parser, Debug)]
#[command(name = "janux", version, about = "Janux authentication server")]
struct Cli {
    /// Paths to TOML configuration files. May be repeated; later files are
    /// merged over earlier ones (default: base.toml + seed.toml)
    #[arg(short, long)]
    config: Vec<String>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    tracing_subscriber::fmt().init();

    // Use --config if provided, fall back to JANUX_CONFIG_FILE env var,
    // then the default base.toml + seed.toml pair
    let config_paths = if cli.config.is_empty() {
        match std::env::var("JANUX_CONFIG_FILE") {
            Ok(path) => vec![path],
            Err(_) => vec!["base".into(), "seed".into()],
        }
    } else {
        cli.config
    };

    let server_config: JanuxConfig = JanuxConfig::load_from(&config_paths).unwrap_or_else(|e| {
        panic!(
            "Failed to load configuration files: {:?}: {e}",
            config_paths
        )
    });

    if let Some(ref key) = server_config.encryption_key {
        crypto::setup_encryption_key(key).expect("failed to initialize encryption key");
    } else {
        eprintln!("FATAL: JANUX_ENCRYPTION_KEY is not configured in server config");
        std::process::exit(1);
    }

    let mut db = db::Storage::init(Path::new(&server_config.data_dir))
        .await
        .unwrap();
    db = db
        .seed(&server_config)
        .await
        .expect("Can not seed data from configuraion file");
    let state = ServerState::create(db, server_config.trust_forwarded_headers)
        .await
        .expect("Can not create server state");

    // Hourly garbage collection of expired revocation records: keeps the
    // persistent InvalidJwt store and its in-memory cache bounded to the
    // live revocation set (revoked tokens and refresh-token families). The
    // store is a process-wide singleton, so the task borrows it directly —
    // no ServerState handle needed.
    tokio::spawn(async {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            if let Err(e) = jwt::InvalidJwt::global().gc().await {
                tracing::warn!(error = %e, "expired revocation records gc failed");
            }
        }
    });

    let item_config = state
        .load_server_config()
        .await
        .expect("Failed to load server config from database");

    let result = server_config
        .run(item_config, move || {
            // Inject ServerState by value (it is a cheap Arc clone). Do NOT
            // inject Arc<ServerState> — handlers obtain_mut::<ServerState>().
            router::api_with_doc().hoop(salvo::affix_state::inject(state.clone()))
        })
        .await;
    if let Err(e) = result {
        eprintln!("Critical Error: Server failed to start: {:?}", e);
        std::process::exit(1);
    }
}
