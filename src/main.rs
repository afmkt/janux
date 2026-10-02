mod admin;
mod aliclient;
mod audit;
mod cache;
mod config;
mod cors;
mod crypto;
mod db;
mod domain;
mod dump;
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
       /// Print the JWKS (public keys only) to stdout for a PostgREST-style
       /// verifier, then exit (the server does NOT start). With no DOMAIN the
       /// set of EVERY tenant in the data dir is exported (with a warning); with
       /// DOMAIN only that domain's owning tenant is exported. PostgREST consumes
       /// it via `jwt-secret = "@jwks.json"` (it does not fetch JWKS over HTTP).
       /// The private signing key is never emitted.
    Jwks {
           /// Domain name restricting the export to that domain's owning tenant.
           /// Omit to export every tenant.
        domain: Option<String>,
        },

     /// Export every tenant's users, credentials and machine config to a
     /// `janux-dump/1` TOML bundle for migration to another auth system,
     /// then exit (the server does NOT start). COLD operation: stop the
     /// server first. The output classifies each factor as portable /
     /// repro / advisory. With --secrets --yes the encrypted fields are
     /// decrypted and emitted in the clear; without it every
     /// secret-bearing field is redacted to a sentinel and the dump is
     /// still usable -- it just carries the metadata a target needs to
     /// re-provision.
    Dump {
            /// Restrict the dump to one registered domain's owning
            /// tenant. Omit to dump every tenant in the data dir.
        #[arg(long)]
      domain: Option<String>,
            /// Include decrypted secret material (TOTP shared secrets,
            /// social provider client secrets, mail / SMS keys).
            /// Requires --yes.
        #[arg(long, default_value_t = false)]
      secrets: bool,
            /// Confirmation that --secrets may emit plaintext.
            /// Required when --secrets is set.
        #[arg(long, default_value_t = false)]
      yes: bool,
            /// Write to FILE instead of stdout. Default: stdout.
        #[arg(long)]
      output: Option<std::path::PathBuf>,
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

     // JWKS export is a cold, read-only operation needing only the public key
     // material (never the encryption key), so run it before the encryption-key
     // requirement and before seeding the storage.
    if let Some(Commands::Jwks { domain }) = &cli.command {
        match db::export_jwks(Path::new(&server_config.data_dir), domain.as_deref())
             .await
        {
            Ok(()) => return,
            Err(e) => {
                eprintln!("JWKS export failed: {e:#}");
                std::process::exit(1);
            }
        }
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

     // Cold dump: a read-only export of every tenant to a janux-dump/1
     // bundle for migration to another auth system. With --secrets the
     // in-process key (installed above) decrypts the at-rest material;
     // without it the dump is still produced with secrets redacted.
     // Exits after writing.
    if let Some(Commands::Dump { domain, secrets, yes, output }) = &cli.command {
            // --secrets requires --yes so a typo can't silently print secrets
             // to a logged stdout / redirected file.
        if *secrets && !*yes {
            eprintln!("--secrets requires --yes (decrypting and printing secrets is not silent)");
            std::process::exit(2);
            }
        let report = dump::dump_data_dir(
             Path::new(&server_config.data_dir),
               *secrets,
             domain.as_deref(),
           ).await;
        let report = match report {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Dump failed: {e:#}");
                std::process::exit(1);
               }
           };
        let text = match dump::to_toml(&report) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("TOML render failed: {e:#}");
                std::process::exit(1);
               }
           };
        let warn_groups = report.account_warnings.login_immediately.len()
                + report.account_warnings.login_after_social.len()
                + report.account_warnings.locked_out.len()
                + report.account_warnings.no_factor.len();
        match output {
            Some(path) => {
                std::fs::write(path, &text)
                      .unwrap_or_else(|e| panic!("failed write {}: {e:#}", path.display()));
                eprintln!(
                      "Wrote janux-dump/1 to {} ({} user(s), {} tenant(s), {} warning member(s))",
                     path.display(),
                     report.user_entries.len(),
                     report.tenant_configs.len(),
                     warn_groups
                       );
               }
            None => print!("{text}"),
           }
        return;
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
        server_config.forward_auth_redirect,
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
