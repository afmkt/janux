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
mod pages;
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

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Dump the embedded frontend into DIR as a scaffold for per-domain
    /// page overrides, then exit (the server does NOT start). Prune DIR to
    /// the files you want to override, point a domain at it with
    /// `pages_dir` in the seed config, and restart. Serving is per-file:
    /// anything missing from DIR falls back to the embedded frontend.
    DumpFrontend {
        /// Target directory (created if missing; existing files overwritten)
        dir: std::path::PathBuf,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    tracing_subscriber::fmt().init();

    if let Some(Commands::DumpFrontend { dir }) = cli.command {
        match pages::dump_frontend(&dir) {
            Ok(n) => {
                println!(
                    "Dumped {n} frontend files to {} (janux {}, marker {})",
                    dir.display(),
                    pages::version(),
                    pages::VERSION_MARKER
                );
                return;
            }
            Err(e) => {
                eprintln!("Failed to dump frontend to {}: {e}", dir.display());
                std::process::exit(1);
            }
        }
    }

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
