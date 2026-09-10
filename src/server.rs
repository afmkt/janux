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

/// Bound on the graceful-shutdown drain (M8). Unbounded, a single hung
/// connection (slow client, stalled poll) pins the process forever;
/// container runtimes SIGKILL anyway — 9s stays inside docker's default
/// 10s stop-grace window so the process exits on its own terms.
const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(9);

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

    // Graceful Shutdown Server, bounded (M8): in-flight requests get
    // SHUTDOWN_GRACE to drain, then connections are force-closed.
    handle.stop_graceful(Some(SHUTDOWN_GRACE));
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
      /// Source addresses (IPs or CIDR blocks) of the reverse proxy/ies janux
      /// trusts to *supply* `X-Forwarded-*` headers. This peer allow-list closes
      /// the G-149 hole: it constrains which TCP sources may speak
      /// `X-Forwarded-*`, so a directly reachable client can no longer tenant-
      /// spoof (forged `X-Forwarded-Host`) or bypass the per-IP limiters
      /// (forged `X-Forwarded-For`).
      ///
       /// Honored only when `trust_forwarded_headers = true`:
       ///     - Non-empty: a forwarded header is honored only when the peer
       ///       matches an entry; an unmatched source falls back to the
       ///       raw `Host` header, exactly as if the switch were `false`.
       ///     - Empty: preserves the pre-G-149 every-peer behavior, which is
       ///       logged loudly at boot; keep it only until your proxy is named
       ///       in the list, e.g. `trusted_proxies = ["10.0.0.5","172.16.0.0/12"]`.
      #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// TEST HARNESS ONLY (G-136 enabler): widen every per-IP rate-limit
    /// quota (auth 6/min, OIDC public 12/min, admin 12/min, SCIM 60/min)
    /// to absurdity. The conformance suite drives the whole protocol from
    /// a single IP and would otherwise exhaust the quotas in seconds.
    /// NEVER enable on a reachable host — the limiters are the primary
    /// CPU-spend and enumeration brake on unauthenticated endpoints.
    #[serde(default)]
    pub disable_rate_limits: bool,
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

/// A parsed peer allow-list of addresses that janux trusts to *supply*
/// `X-Forwarded-*` headers (G-149). Each entry is an exact IP or a CIDR
/// block. An empty list means "trust every peer" —
/// see [`ServerState::trusts_forwarded`].
#[derive(Debug, Clone, Default)]
pub(crate) struct TrustedProxies {
     // (network address as u32, prefix length) for IPv4 entries.
   v4: Vec<(u32, u8)>,
     // (network address as u128, prefix length) for IPv6 entries.
   v6: Vec<(u128, u8)>,
}

impl TrustedProxies {
   fn is_empty(&self) -> bool {
       self.v4.is_empty() && self.v6.is_empty()
    }

    /// Parse a list of IP / CIDR strings. Any malformed entry is an error, so
    /// a misconfiguration is a boot-time failure rather than a silent fallback
    /// to "trust everyone".
  fn parse(entries: &[String]) -> Result<Self, String> {
      let mut v4 = Vec::new();
      let mut v6 = Vec::new();
      for entry in entries {
          let trimmed = entry.trim();
          if trimmed.is_empty() {
              continue;
           }
          let (ip, prefix) = match trimmed.split_once('/') {
              Some((a, b)) => {
                  let bits = b.trim().parse::<u8>().map_err(|_| format!("bad prefix in {entry}"))?;
                    (a.trim(), Some(bits))
                }
              None => (trimmed, None),
           };
          if let Ok(ip) = ip.parse::<std::net::Ipv4Addr>() {
              let bits = prefix.unwrap_or(32);
              if bits > 32 {
                  return Err(format!("prefix {bits} exceeds 32 for IPv4 address {ip}"));
               }
              v4.push((u32::from(ip) & mask32(bits), bits));
           } else if let Ok(ip) = ip.parse::<std::net::Ipv6Addr>() {
              let bits = prefix.unwrap_or(128);
              if bits > 128 {
                  return Err(format!("prefix {bits} exceeds 128 for IPv6 address {ip}"));
               }
               v6.push((u128::from_be_bytes(ip.octets()) & mask128(bits), bits));
           } else {
              return Err(format!("not an IP address or CIDR block: {entry:?}"));
           }
       }
      Ok(Self { v4, v6 })
   }

    /// Does `peer` fall inside any entry?
  fn contains(&self, peer: std::net::IpAddr) -> bool {
      match peer {
          std::net::IpAddr::V4(ip) => self.v4.iter().any(|&(net, bits)| u32::from(ip) & mask32(bits) == net),
          std::net::IpAddr::V6(ip) => self.v6.iter().any(|&(net, bits)| u128::from_be_bytes(ip.octets()) & mask128(bits) == net),
       }
   }
}

/// `(max << (width - bits))` — a full mask for `bits == 0` (match-all-
/// within the family) and a host mask as the width is approached.
fn mask32(bits: u8) -> u32 {
   u32::MAX.wrapping_shl((32 - bits) as u32)
}

fn mask128(bits: u8) -> u128 {
   u128::MAX.wrapping_shl((128 - bits) as u32)
}

pub struct ServerStateInner {
    pub storage: Storage,
    /// Deployment-wide switch for trusting `X-Forwarded-*` headers during
    /// tenant/path resolution (see `JanuxConfig::trust_forwarded_headers`).
    pub trust_forwarded_headers: bool,
      /// Compiled peer allow-list constraining which TCP sources may supply
      /// `X-Forwarded-*` headers (G-149). Empty with the switch on means
      /// trust-every-peer (the legacy, unsafe-if-reachable behavior).
    pub(crate) trusted_proxies: TrustedProxies,
    /// domain -> canonicalized frontend override root (`crate::pages`).
    /// Built once at boot from the tenant Config store (seeded via
    /// `pages_dir` in the seed config); overrides are config-file-only, so
    /// the cache never needs invalidation at runtime.
    pub pages_dirs: dashmap::DashMap<String, std::path::PathBuf>,
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

/// Collect the per-domain frontend override dirs from the tenant Config
/// stores (key `pages.<domain>`, seeded via `DomainDTO::pages_dir`) and
/// run the boot-time version drift check on each. Canonicalized once here
/// so request-time confinement compares against an absolute, `..`-free
/// root; a dir that cannot be canonicalized (missing at boot) is kept as
/// an absolute path — per-file lookups then miss and fall back to the
/// embedded frontend.
async fn load_pages_dirs(storage: &Storage) -> dashmap::DashMap<String, std::path::PathBuf> {
    let map = dashmap::DashMap::new();
    // Snapshot the domain list first: tenant_by_domain re-borrows the
    // router map, so holding an iterator across the await would deadlock
    // on a DashMap shard.
    let domains: Vec<String> = storage
        .router
        .iter()
        .map(|entry| entry.key().clone())
        .collect();
    for domain in domains {
        let Some(mut tenant) = storage.tenant_by_domain(&domain) else {
            continue;
        };
        let Some(dir) = tenant
            .config_get(&crate::pages::pages_config_key(&domain))
            .await
            .and_then(|v| v.as_str().map(str::to_string))
        else {
            continue;
        };
        let path = std::path::PathBuf::from(&dir);
        let root = std::fs::canonicalize(&path)
            .or_else(|_| std::path::absolute(&path))
            .unwrap_or(path);
        crate::pages::check_drift(&domain, &root);
        map.insert(domain, root);
    }
    map
}

impl ServerState {
     /// Like [`ServerState::create`], but compiles the `trusted_proxies` peer
     /// allow-list (G-149). Booting fails on a malformed entry — the
     /// structural validation that keeps `trust_forwarded_headers` from
     /// silently accepting a bad list.
   pub async fn create_with(
         storage: Storage,
         trust_forwarded_headers: bool,
         trusted_proxies: &[String],
     ) -> Result<ServerState> {
         let trusted_proxies =
             TrustedProxies::parse(trusted_proxies).map_err(|e| anyhow::anyhow!("{e}"))?;
         let pages_dirs = load_pages_dirs(&storage).await;
         Ok(ServerState {
             inner: std::sync::Arc::new(ServerStateInner {
                 storage,
                 trust_forwarded_headers,
                 trusted_proxies,
                 pages_dirs,
              }),
           })
       }

       /// Should this request's `X-Forwarded-*` headers be trusted? `false`
       /// whenever the master switch is off, or when a peer allow-list is set
       /// and the request's TCP peer is not on it. An empty allow-list with the
       /// switch on preserves the legacy "trust every peer" behavior.
     pub(crate) fn trusts_forwarded(&self, req: &Request) -> bool {
         if !self.trust_forwarded_headers {
             return false;
           }
         if self.trusted_proxies.is_empty() {
             return true;
           }
         let Some(peer) = req.remote_addr().ip() else {
             return false;
           };
         self.trusted_proxies.contains(peer)
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
        assert!(config.trusted_proxies.is_empty());  // G-149
        assert!(config.trust_forwarded_headers);
    }

#[test]
fn trusted_proxies_parses_ips_and_cidrs() {
    let net = TrustedProxies::parse(&[
        "10.1.2.3".into(),
        "10.0.0.0/24".into(),
        "2001:db8::/32".into(),
        "   ".into(),
    ])
    .expect("valid list");
    assert!(!net.is_empty());
    assert!(net.contains(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10,1,2,3))));
    assert!(net.contains(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10,0,0,5))));
    assert!(net.contains(std::net::IpAddr::V6(std::net::Ipv6Addr::new(0x2001,0x0db8,0,0,0,0,0,1))));
    assert!(!net.contains(std::net::IpAddr::V4(std::net::Ipv4Addr::new(8,8,8,8))));
 }

#[test]
fn trusted_proxies_empty_when_no_entries() {
    assert!(TrustedProxies::parse(&[]).expect("empty").is_empty());
    assert!(TrustedProxies::parse(&["    ".into()]).expect("whitespace").is_empty());
 }

#[test]
fn trusted_proxies_rejects_garbage() {
    assert!(TrustedProxies::parse(&["not-an-ip".into()]).is_err());
    assert!(TrustedProxies::parse(&["10.0.0.0/33".into()]).is_err());
    assert!(TrustedProxies::parse(&["10.0.0.0/abcd".into()]).is_err());
    assert!(TrustedProxies::parse(&["2001::db8/999".into()]).is_err());
 }
}