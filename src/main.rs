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
    /// Back up the data directory, then exit (the server does NOT start).
    /// COLD operation: stop the server first — the databases are
    /// exclusively locked while it holds them, and the backup validates
    /// that every database opens before copying. Creates
    /// DEST/backup-<timestamp>/ with a manifest.json. The config files
    /// (base.toml/seed.toml) and the encryption_key live outside the data
    /// dir — back them up separately; without the key the at-rest secrets
    /// in the backup are unrecoverable.
    Backup {
        /// Destination directory (a timestamped backup dir is created inside)
        dest: std::path::PathBuf,
    },
    /// Restore a backup created by `janux backup`, then exit (the server
    /// does NOT start). COLD operation: stop the server first. Refuses to
    /// replace a non-empty data dir unless --force.
    Restore {
        /// The timestamped backup directory (containing manifest.json)
        src: std::path::PathBuf,
        /// Replace a non-empty data dir (disaster recovery, not a merge)
        #[arg(long)]
        force: bool,
    },
    /// Re-encrypt every at-rest secret (signing-key privates, social
    /// provider secrets, TOTP secrets, stored mail/SMS credentials) under
    /// a NEW encryption key, then exit (the server does NOT start). COLD
    /// operation: stop the server first. The current `encryption_key`
    /// from the config is the OLD key; after a successful run you MUST
    /// replace it with the new one or nothing decrypts at the next boot.
    /// Legacy plaintext rows are upgraded to ciphertext on the way
    /// through (G-150).
    Rekey {
        /// New encryption key: 64 hex chars (32 bytes), e.g. `openssl rand -hex 32`
        new_key: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    tracing_subscriber::fmt().init();

    if let Some(Commands::DumpFrontend { dir }) = &cli.command {
        match pages::dump_frontend(dir) {
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

    // Backup/restore are COLD operations handled before anything opens
    // the data dir (Storage::init would take the very locks the backup
    // validation checks for).
    match &cli.command {
        Some(Commands::Backup { dest }) => {
            match db::backup_data_dir(Path::new(&server_config.data_dir), dest).await {
                Ok((dir, manifest)) => {
                    println!(
                        "Backed up {} tenant(s), {} file(s) to {}",
                        manifest.tenants.len(),
                        manifest.files.len(),
                        dir.display()
                    );
                    return;
                }
                Err(e) => {
                    eprintln!("Backup failed: {e:#}");
                    std::process::exit(1);
                }
            }
        }
        Some(Commands::Restore { src, force }) => {
            match db::restore_data_dir(src, Path::new(&server_config.data_dir), *force).await {
                Ok(manifest) => {
                    println!(
                        "Restored {} tenant(s) into {} (backup created {})",
                        manifest.tenants.len(),
                        server_config.data_dir,
                        manifest.created_at
                    );
                    return;
                }
                Err(e) => {
                    eprintln!("Restore failed: {e:#}");
                    std::process::exit(1);
                }
            }
        }
        _ => {}
    }

    // G-149: trusting X-Forwarded-* hands tenant resolution and every
    // per-IP limiter to whoever can set those headers. Restricting header
    // supply to a `trusted_proxies` allow-list is what makes `true` safe on
    // a directly reachable port; say so loudly, flag the (spoofable) case
    // where the list is empty.
    if server_config.trust_forwarded_headers {
        if server_config.trusted_proxies.is_empty() {
            tracing::warn!(
                "trust_forwarded_headers is on with NO trusted_proxies allow-list: every \
                   network peer may forge X-Forwarded-Host/Uri/Method/For to pick the tenant/ \
                   issuer context and bypass the per-IP rate limiters, so a directly reachable \
                   server can be tenant-spoofed and limiter-bypassed — set trusted_proxies to \
                   your reverse-proxy address(es) to restrict header authority (G-149)."
            );
        } else {
            let n = server_config.trusted_proxies.len();
            tracing::warn!(
                "trust_forwarded_headers is on, restricted to {n} trusted proxy peer(s) \
                       (G-149): only requests from a listed IP/CIDR may supply X-Forwarded-* for \
                       tenant selection and per-IP rate limiting; other sources fall back to the \
                       raw connection."
            );
        }
    }

    // G-150: the example key is public knowledge — accepting it silently
    // would mean at-rest encryption protects nothing.
    if server_config.encryption_key.as_deref()
        == Some("1234567812345678123456781234567812345678123456781234567812345678")
    {
        tracing::warn!(
            "encryption_key is the well-known example key from base.example.toml — secrets at \
             rest are effectively plaintext. Generate a fresh 32-byte hex key (e.g. `openssl \
             rand -hex 32`) before any real deployment."
        );
    }

    if let Some(ref key) = server_config.encryption_key {
        crypto::setup_encryption_key(key).expect("failed to initialize encryption key");
    } else {
        eprintln!("FATAL: JANUX_ENCRYPTION_KEY is not configured in server config");
        std::process::exit(1);
    }

    // G-150: key rotation runs AFTER the old key is installed (decryption
    // side) and BEFORE the server boots — it re-encrypts every at-rest
    // secret under the new key and exits.
    if let Some(Commands::Rekey { new_key }) = &cli.command {
        match db::rekey_data_dir(Path::new(&server_config.data_dir), new_key).await {
            Ok(report) => {
                println!(
                    "Rekeyed {} tenant(s): {} signing key(s), {} provider secret(s), {} TOTP secret(s), {} config secret(s); {} legacy plaintext row(s) upgraded.",
                    report.tenants,
                    report.signing_keys,
                    report.provider_secrets,
                    report.totp_secrets,
                    report.config_secrets,
                    report.legacy_upgraded
                );
                println!(
                    "IMPORTANT: set encryption_key to the NEW value in your config now — \
                     the data dir no longer decrypts with the old key."
                );
                return;
            }
            Err(e) => {
                eprintln!("Rekey failed: {e:#}");
                std::process::exit(1);
            }
        }
    }

    let mut db = db::Storage::init(Path::new(&server_config.data_dir))
        .await
        .unwrap();
    db = db
        .seed(&server_config)
        .await
        .expect("Can not seed data from configuraion file");
    let state = ServerState::create_with(
        db,
        server_config.trust_forwarded_headers,
        &server_config.trusted_proxies,
    )
    .await
    .expect("Can not create server state");

    // G-126: durable back-channel logout worker — a 60 s sweep plus an
    // immediate wakeup whenever a logout queues deliveries. Replaces the
    // old detached 3-attempt task that lost notifications on restart or
    // any RP outage longer than a few seconds.
    tokio::spawn(crate::oidc_ext::run_backchannel_worker(state.clone()));

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

    let disable_rate_limits = server_config.disable_rate_limits;
    let result = server_config
        .run(item_config, move || {
            // Inject ServerState by value (it is a cheap Arc clone). Do NOT
            // inject Arc<ServerState> — handlers obtain_mut::<ServerState>().
            router::api_with_doc(disable_rate_limits)
                .hoop(salvo::affix_state::inject(state.clone()))
        })
        .await;
    if let Err(e) = result {
        eprintln!("Critical Error: Server failed to start: {:?}", e);
        std::process::exit(1);
    }
}
