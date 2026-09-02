use crate::db::Storage;
use crate::db::Tenant;
use crate::seed::TenantDTO;
use anyhow::Result;
use config::{Config, ConfigError, Environment, File};

use salvo::conn::rustls::{Keycert, RustlsAcceptor, RustlsConfig};
use salvo::conn::tcp::TcpAcceptor;
use salvo::conn::{Acceptor, Listener, TcpListener};
use salvo::prelude::*;
use serde::Deserialize;

use salvo::acme::{AcmeAcceptor, AcmeListener};
use std::collections::{HashMap, HashSet};
use tokio::task::JoinSet;

use salvo::server::ServerHandle;

use tokio::signal;
#[derive(Debug, Deserialize, Clone)]
pub struct BindConfig {
    pub address: String,
    pub port: u16,
}
impl BindConfig {
    pub fn string(&self) -> String {
        format!("{}:{}", self.address, self.port)
    }
}

#[derive(Debug, Clone)]
pub struct Acme {
    emails: HashSet<String>,
    domains: HashSet<String>,
}

impl Acme {
    pub fn merge(&self, other: &Acme) -> Self {
        let mut merged_emails = self.emails.clone();
        merged_emails.extend(other.emails.iter().cloned());

        let mut merged_domains = self.domains.clone();
        merged_domains.extend(other.domains.iter().cloned());

        Acme {
            emails: merged_emails,
            domains: merged_domains,
        }
    }
}
#[derive(Debug, Deserialize, Clone)]
pub struct Tls {
    cert: String,
    key: String,
}

#[derive(Debug, Clone)]
pub struct Http {
    domains: HashSet<String>,
}

impl Http {
    pub fn merge(&self, other: &Http) -> Self {
        let mut merged_domains = self.domains.clone();
        merged_domains.extend(other.domains.iter().cloned());

        Http {
            domains: merged_domains,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VHostConfig {
    pub acme: Option<Acme>,
    pub tls: Option<HashMap<String, Tls>>,
    pub http: Option<Http>,
}

impl VHostConfig {
    pub fn acme_parameter(&self) -> Option<(Vec<String>, Vec<String>)> {
        if let Some(acme) = &self.acme
            && !acme.domains.is_empty()
        {
            return Some((
                acme.domains.clone().into_iter().collect(),
                acme.emails.clone().into_iter().collect(),
            ));
        }

        None
    }
    pub fn tls_parameter(&self) -> Option<RustlsConfig> {
        if let Some(tls) = &self.tls {
            if tls.is_empty() {
                return None;
            }
            let mut iter = tls.iter();
            if let Some((_domain, tls)) = iter.next() {
                let first_keycert = Keycert::new()
                    .cert_from_path(tls.cert.clone())
                    .expect("Failed to load cert")
                    .key_from_path(tls.key.clone())
                    .expect("Failed to load key");
                let mut config = RustlsConfig::new(first_keycert);
                for (domain, tls) in iter {
                    let keycert = Keycert::new()
                        .cert_from_path(tls.cert.clone())
                        .expect("Failed to load cert")
                        .key_from_path(tls.key.clone())
                        .expect("Failed to load key");
                    config = config.keycert(domain.clone(), keycert);
                }
                return Some(config);
            }
        }
        None
    }
    pub fn http_parameter(&self) -> Option<Vec<String>> {
        if let Some(http) = &self.http {
            if http.domains.is_empty() {
                return None;
            } else {
                return Some(http.domains.clone().into_iter().collect());
            }
        }
        None
    }

    pub fn merge(&self, other: &VHostConfig) -> Self {
        let acme = match (&self.acme, &other.acme) {
            (Some(a), Some(b)) => Some(a.merge(b)),
            (Some(a), None) => Some(a.clone()),
            (None, Some(b)) => Some(b.clone()),
            (None, None) => None,
        };
        let http = match (&self.http, &other.http) {
            (Some(a), Some(b)) => Some(a.merge(b)),
            (Some(a), None) => Some(a.clone()),
            (None, Some(b)) => Some(b.clone()),
            (None, None) => None,
        };
        match (&self.tls, &other.tls) {
            (Some(a), Some(b)) => {
                let mut merged_tls = a.clone();
                for (domain, tls) in b {
                    merged_tls.insert(domain.clone(), tls.clone());
                }
                VHostConfig {
                    acme,
                    tls: Some(merged_tls),
                    http,
                }
            }
            (Some(a), None) => VHostConfig {
                acme,
                tls: Some(a.clone()),
                http,
            },
            (None, Some(b)) => VHostConfig {
                acme,
                tls: Some(b.clone()),
                http,
            },
            (None, None) => VHostConfig {
                acme,
                tls: None,
                http,
            },
        }
    }

    pub async fn from_tenant(tenant: &mut Tenant) -> Result<Self> {
        let domains = tenant.all_domains().await;
        let mut acme = Acme {
            emails: HashSet::new(),
            domains: HashSet::new(),
        };
        let mut tls: HashMap<String, Tls> = HashMap::new();
        let mut http = Http {
            domains: HashSet::new(),
        };
        for domain in domains {
            if let Some(acme_email) = domain.acme_email.clone() {
                acme.emails.insert(acme_email);
            }
            if let Some(cert) = domain.cert.clone()
                && let Some(key) = domain.key.clone()
            {
                let tls_entry = Tls { cert, key };
                tls.insert(domain.id.clone(), tls_entry);
            }

            http.domains.insert(domain.id.clone());
        }

        Ok(VHostConfig {
            acme: if !acme.domains.is_empty() {
                Some(acme)
            } else {
                None
            },
            tls: if !tls.is_empty() { Some(tls) } else { None },
            http: if !http.domains.is_empty() {
                Some(http)
            } else {
                None
            },
        })
    }
}

async fn listen_shutdown_signal(handle: ServerHandle) {
    // Wait Shutdown Signal
    let ctrl_c = async {
        // Handle Ctrl+C signal
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        // Handle SIGTERM on Unix systems
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(windows)]
    let terminate = async {
        // Handle Ctrl+C on Windows (alternative implementation)
        signal::windows::ctrl_c()
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    // Wait for either signal to be received
    tokio::select! {
        _ = ctrl_c => println!("ctrl_c signal received"),
        _ = terminate => println!("terminate signal received"),
    };

    // Graceful Shutdown Server
    handle.stop_graceful(None);
}

enum Acceptors {
    Tcp(TcpAcceptor),
    Acme(AcmeAcceptor<TcpAcceptor>),
    Tls(RustlsAcceptor<TcpAcceptor>),
}

async fn create_acceptor(
    config: &VHostConfig,
    tcp_listener: TcpListener<String>,
    acme_dir: &std::path::Path,
) -> Result<Acceptors> {
    if let Some((domains, emails)) = config.acme_parameter() {
        let acceptor = tcp_listener
            .acme()
            .cache_path(acme_dir)
            .domains(domains)
            .contacts(emails)
            .bind()
            .await;
        Ok(Acceptors::Acme(acceptor))
    } else if let Some(tls) = config.tls_parameter() {
        let acceptor = tcp_listener.rustls(tls).bind().await;
        Ok(Acceptors::Tls(acceptor))
    } else if let Some(_http) = config.http_parameter() {
        let acceptor = tcp_listener.bind().await;
        Ok(Acceptors::Tcp(acceptor))
    } else {
        Err(anyhow::anyhow!(
            "No valid listener configuration (ACME, TLS, or HTTP) found"
        ))
    }
}

async fn run_server<A>(acceptor: A, router: Router)
where
    A: Acceptor + Send + 'static,
{
    let server = Server::new(acceptor);
    let handle = server.handle();
    tokio::spawn(listen_shutdown_signal(handle));
    server.serve(router).await;
}

#[derive(Debug, Deserialize, Clone)]
pub struct JanuxConfig {
    pub data_dir: String,
    pub bind: BindConfig,
    pub seed: Option<Vec<TenantDTO>>,
    #[serde(default)]
    pub encryption_key: Option<String>,
    /// Whether `X-Forwarded-Host` / `X-Forwarded-Uri` / `X-Forwarded-Method`
    /// headers are trusted for tenant and path resolution.
    ///
    /// Set this ONLY when every request reaches janux through a reverse proxy
    /// that owns (overwrites) these headers — e.g. Caddy `forward_auth` with
    /// `header_up X-Forwarded-Host {host}`. When `false` (the default) the
    /// headers are ignored and resolution uses the raw `Host` header and the
    /// real request path, which is safe even when the port is exposed
    /// directly.
    #[serde(default)]
    pub trust_forwarded_headers: bool,
}

impl JanuxConfig {
    /// Load config from one or more TOML file paths.
    ///
    /// Files are merged in order: later files override earlier ones (tables
    /// merge recursively; arrays and scalars are replaced wholesale).
    /// Precedence: environment variables (JANUX_*) override all files.
    pub fn load_from(file_paths: &[String]) -> Result<Self, ConfigError> {
        let run_mode = std::env::var("RUN_ENV").unwrap_or_else(|_| "development".into());
        let mut builder = Config::builder();
        for path in file_paths {
            builder = builder.add_source(File::with_name(path));
        }
        let s = builder
            .add_source(File::with_name(&format!("config/{}", run_mode)).required(false))
            .add_source(Environment::with_prefix("JANUX").separator("__"))
            .build()?;
        s.try_deserialize()
    }

    pub async fn run<F>(&self, config: VHostConfig, factory: F) -> Result<()>
    where
        F: Fn() -> Router + Send + Sync + 'static,
    {
        let mut bind_addresses: HashSet<String> = HashSet::new();
        let mut set = JoinSet::new();

        let acme_dir = std::path::PathBuf::from(self.data_dir.clone()).join("acme");
        let bind_addr = self.bind.string();
        if !bind_addresses.insert(bind_addr.clone()) {
            return Err(anyhow::anyhow!("Duplicated bind address/port"));
        }
        let router = factory();
        set.spawn(async move {
            let tcp_listener = TcpListener::new(bind_addr);
            let acpt = create_acceptor(&config, tcp_listener, acme_dir.as_path()).await?;
            match acpt {
                Acceptors::Acme(acpt) => {
                    run_server(acpt, router).await;
                }
                Acceptors::Tls(acpt) => {
                    run_server(acpt, router).await;
                }
                Acceptors::Tcp(acpt) => {
                    run_server(acpt, router).await;
                }
            }
            Ok(())
        });

        while let Some(res) = set.join_next().await {
            match res {
                Ok(Ok(_)) => {}              // Task finished successfully
                Ok(Err(e)) => return Err(e), // Task returned an error
                Err(e) => return Err(anyhow::anyhow!("Task panicked: {}", e)), // Task panicked
            }
        }
        Ok(())
    }
}

pub struct ServerStateInner {
    pub storage: Storage,
    /// Deployment-wide switch for trusting `X-Forwarded-*` headers during
    /// tenant/path resolution (see `JanuxConfig::trust_forwarded_headers`).
    pub trust_forwarded_headers: bool,
}

/// Shared server state, cheap to clone (Arc inside) so it can be injected
/// into every request depot via `affix_state::inject`.
///
/// Handlers access it with `depot.obtain_mut::<ServerState>()` and reach the
/// inner fields through `Deref` (`state.storage`). The revocation store is
/// NOT carried here — it is the process-wide `InvalidJwt::global()` singleton,
/// so it never needs to be cloned along with the state.
/// NOTE: the injected value MUST be `ServerState` itself — injecting
/// `Arc<ServerState>` registers under a different TypeId and every
/// `obtain_mut::<ServerState>()` lookup silently fails.
#[derive(Clone)]
pub struct ServerState {
    inner: std::sync::Arc<ServerStateInner>,
}

impl std::ops::Deref for ServerState {
    type Target = ServerStateInner;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl ServerState {
    pub async fn create(storage: Storage, trust_forwarded_headers: bool) -> Result<ServerState> {
        Ok(ServerState {
            inner: std::sync::Arc::new(ServerStateInner {
                storage,
                trust_forwarded_headers,
            }),
        })
    }

    pub async fn load_server_config(&self) -> Result<VHostConfig> {
        let mut config = VHostConfig {
            acme: None,
            tls: None,
            http: None,
        };
        for tname in self.storage.all_tenants().await? {
            if let Some(mut tenant) = self.storage.tenants.get_mut(&tname) {
                let tmp = VHostConfig::from_tenant(&mut tenant).await?;
                config = config.merge(&tmp);
            }
        }
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn load_from_merges_multiple_files() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = dir.path().join("base.toml");
        let override_path = dir.path().join("override.toml");

        let mut base = std::fs::File::create(&base_path).unwrap();
        writeln!(
            base,
            r#"
data_dir = "/tmp/base"
encryption_key = "base-key"

[bind]
address = "127.0.0.1"
port = 8080
"#
        )
        .unwrap();

        let mut ovr = std::fs::File::create(&override_path).unwrap();
        writeln!(
            ovr,
            r#"
trust_forwarded_headers = true

[bind]
port = 9090
"#
        )
        .unwrap();

        let base_stem = base_path.with_extension("").to_string_lossy().to_string();
        let override_stem = override_path
            .with_extension("")
            .to_string_lossy()
            .to_string();
        let config = JanuxConfig::load_from(&[base_stem, override_stem]).unwrap();

        assert_eq!(config.data_dir, "/tmp/base");
        assert_eq!(config.encryption_key.as_deref(), Some("base-key"));
        assert_eq!(config.bind.address, "127.0.0.1");
        assert_eq!(config.bind.port, 9090);
        assert!(config.trust_forwarded_headers);
    }
}
