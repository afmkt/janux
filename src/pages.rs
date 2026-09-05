//! Per-domain frontend page overrides.
//!
//! The built-in frontend is embedded at compile time ([`Assets`]). An
//! operator can override any subset of it per domain:
//!
//! 1. `janux dump-frontend <dir>` writes the embedded frontend to `<dir>`
//!    as a scaffold, plus a `.janux-version` marker recording the binary
//!    version that produced it.
//! 2. The operator prunes/edits `<dir>` (branding, copy, or full flows)
//!    and points a domain at it via `pages_dir` in the seed config
//!    (persisted in the tenant Config store, key `pages.<domain>`).
//! 3. At request time [`serve`] resolves per file: disk override first,
//!    embedded asset second, 404 last. A pruned scaffold therefore only
//!    overrides the files the operator kept.
//!
//! Overrides are config-file-only by design: whoever can edit the config
//! already holds the encryption keys, so no upload API (and no new
//! privilege boundary) exists. Disk paths are confined under the override
//! root — see [`confine`].

use anyhow::Result;
use rust_embed::RustEmbed;
use salvo::http::StatusCode;
use salvo::http::header::{CONTENT_TYPE, ETAG, HeaderValue, IF_NONE_MATCH};
use salvo::prelude::*;
use std::path::{Path, PathBuf};

#[derive(RustEmbed)]
#[folder = "./frontend/dist"]
pub struct Assets;

/// Marker file written by [`dump_frontend`]: the janux version that
/// produced the scaffold. Boot compares it against the running binary and
/// warns on drift (the embedded fallback assets evolve while a dumped
/// scaffold stays frozen).
pub const VERSION_MARKER: &str = ".janux-version";

/// Tenant Config store key holding the override dir for a domain.
pub fn pages_config_key(domain: &str) -> String {
    format!("pages.{domain}")
}

/// Version stamped into dumped scaffolds and compared on boot.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Dump every embedded frontend asset into `dir` (created if missing) and
/// stamp it with [`VERSION_MARKER`]. Returns the number of assets written.
///
/// Existing files are overwritten — the dump is a scaffold refresh, and
/// operator edits live in version control or a copied dir, not in place.
pub fn dump_frontend(dir: &Path) -> Result<usize> {
    std::fs::create_dir_all(dir)?;
    let mut count = 0usize;
    for name in Assets::iter() {
        if name == VERSION_MARKER {
            continue;
        }
        let Some(file) = Assets::get(name.as_ref()) else {
            continue;
        };
        let Some(dest) = confine(dir, name.as_ref()) else {
            continue;
        };
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(dest, file.data)?;
        count += 1;
    }
    std::fs::write(dir.join(VERSION_MARKER), version())?;
    Ok(count)
}

/// Confine a client-supplied relative path under `root`.
///
/// The request path is untrusted network input joined onto an
/// operator-configured filesystem root, so it is percent-decoded FIRST
/// (a literal `%2e%2e%2f` must not survive as an opaque segment) and any
/// `..` segment rejects the lookup outright. Empty and `.` segments are
/// dropped (normalization). The final `starts_with` check is component-
/// based and catches platform edge cases such as a Windows drive prefix
/// (`C:`) replacing the root during `push`.
///
/// Returns `None` when the path escapes, is malformed UTF-8, or normalizes
/// to the root itself.
pub fn confine(root: &Path, rel: &str) -> Option<PathBuf> {
    let decoded = percent_encoding::percent_decode_str(rel)
        .decode_utf8()
        .ok()?;
    let mut out = root.to_path_buf();
    let mut pushed = false;
    for seg in decoded.split(['/', '\\']) {
        match seg {
            "" | "." => continue,
            ".." => return None,
            s => {
                out.push(s);
                pushed = true;
            }
        }
    }
    if !pushed || !out.starts_with(root) {
        return None;
    }
    Some(out)
}

/// Serve one frontend asset: disk override (confined under `pages_dir`)
/// first, embedded asset second, 404 last. Honors conditional requests:
/// both tiers carry an ETag and an `If-None-Match` hit answers 304 with no
/// body (the behavior the replaced `static_embed` handler provided).
pub async fn serve(req: &Request, res: &mut Response, rel: &str, pages_dir: Option<&Path>) {
    if let Some(root) = pages_dir
        && let Some(path) = confine(root, rel)
        && let Ok(meta) = tokio::fs::metadata(&path).await
        && meta.is_file()
    {
        let etag = disk_etag(&meta);
        if revalidates(req, &etag) {
            not_modified(res, &etag);
            return;
        }
        if let Ok(data) = tokio::fs::read(&path).await {
            prepare(res, rel, &etag);
            res.body(data);
            return;
        }
        // Vanished between metadata and read (operator pruned the dir
        // live) — fall through to the embedded tier.
    }
    if let Some(file) = Assets::get(rel) {
        let etag = embedded_etag(&file);
        if revalidates(req, &etag) {
            not_modified(res, &etag);
            return;
        }
        prepare(res, rel, &etag);
        // Zero-copy for the static (release) embed: `Cow::Borrowed` goes
        // straight into `ResBody` via `From<&'static [u8]>`/`Bytes::from_static`.
        match file.data {
            std::borrow::Cow::Borrowed(bytes) => res.body(bytes),
            std::borrow::Cow::Owned(bytes) => res.body(bytes),
        };
        return;
    }
    res.status_code(StatusCode::NOT_FOUND);
}

fn prepare(res: &mut Response, name: &str, etag: &str) {
    let mime = mime_guess::from_path(name).first_or_octet_stream();
    if let Ok(v) = HeaderValue::from_str(mime.as_ref()) {
        res.headers_mut().insert(CONTENT_TYPE, v);
    }
    if let Ok(v) = HeaderValue::from_str(etag) {
        res.headers_mut().insert(ETAG, v);
    }
    res.status_code(StatusCode::OK);
}

fn not_modified(res: &mut Response, etag: &str) {
    if let Ok(v) = HeaderValue::from_str(etag) {
        res.headers_mut().insert(ETAG, v);
    }
    res.status_code(StatusCode::NOT_MODIFIED);
}

/// Strong validator for embedded assets: the compile-time (release) or
/// on-load (debug/dynamic) sha256 of the asset bytes.
fn embedded_etag(file: &rust_embed::EmbeddedFile) -> String {
    format!("\"{}\"", hex::encode(file.metadata.sha256_hash()))
}

/// Weak validator for disk overrides: mtime + size. Weak because mtime
/// granularity can hide same-second edits; content changes still produce
/// a new validator in every realistic edit cycle.
fn disk_etag(meta: &std::fs::Metadata) -> String {
    let (secs, nanos) = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| (d.as_secs(), d.subsec_nanos()))
        .unwrap_or((0, 0));
    format!("W/\"{:x}-{:x}-{:x}\"", secs, nanos, meta.len())
}

/// RFC 9110 §13.1.2 weak comparison: `If-None-Match` matches when any
/// candidate equals the validator with both `W/` prefixes stripped, or is
/// `*`.
fn revalidates(req: &Request, etag: &str) -> bool {
    let Some(inm) = req
        .headers()
        .get(IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let bare = etag.strip_prefix("W/").unwrap_or(etag);
    inm.split(',')
        .map(str::trim)
        .any(|cand| cand == "*" || cand.strip_prefix("W/").unwrap_or(cand) == bare)
}

/// Boot-time drift check for one configured override dir: warn when the
/// scaffold was dumped by a different janux version (or carries no marker
/// at all), because the embedded fallback assets it mixes with may have
/// moved on (hashed bundle names, discovery contract changes).
pub fn check_drift(domain: &str, dir: &Path) {
    if !dir.is_dir() {
        tracing::warn!(
            domain,
            dir = %dir.display(),
            "pages_dir does not exist; every request falls back to the embedded frontend"
        );
        return;
    }
    match std::fs::read_to_string(dir.join(VERSION_MARKER)) {
        Ok(stamp) if stamp.trim() == version() => {}
        Ok(stamp) => tracing::warn!(
            domain,
            dir = %dir.display(),
            dumped_by = %stamp.trim(),
            running = version(),
            "pages override scaffold was dumped by a different janux version; \
             embedded fallback assets may have drifted — re-run `janux dump-frontend` \
             into a fresh dir and re-apply your edits"
        ),
        Err(_) => tracing::warn!(
            domain,
            dir = %dir.display(),
            "pages override dir has no {VERSION_MARKER} marker (not dumped by \
             `janux dump-frontend`?); version drift cannot be detected"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use salvo::test::ResponseExt;

    #[test]
    fn confine_accepts_plain_relative_paths() {
        let root = Path::new("/srv/pages");
        assert_eq!(
            confine(root, "login.html"),
            Some(PathBuf::from("/srv/pages/login.html"))
        );
        assert_eq!(
            confine(root, "/assets/app.css"),
            Some(PathBuf::from("/srv/pages/assets/app.css"))
        );
        assert_eq!(
            confine(root, "./a/./b.js"),
            Some(PathBuf::from("/srv/pages/a/b.js"))
        );
    }

    #[test]
    fn confine_rejects_traversal() {
        let root = Path::new("/srv/pages");
        assert_eq!(confine(root, "../base.toml"), None);
        assert_eq!(confine(root, "a/../../etc/passwd"), None);
        assert_eq!(confine(root, "..%2f..%2fetc%2fpasswd"), None);
        assert_eq!(confine(root, "%2e%2e/%2e%2e/etc/passwd"), None);
        assert_eq!(confine(root, "..\\..\\windows\\system32"), None);
        // Double-encoded traversal decodes to a literal "%2e%2e%2fetc"
        // filename — harmless, but it must stay confined under the root.
        let doubled = confine(root, "%252e%252e%252fetc");
        assert!(
            doubled.as_ref().is_none_or(|p| p.starts_with(root)),
            "double-encoded input must never escape the root: {doubled:?}"
        );
    }

    #[test]
    fn confine_rejects_root_itself_and_garbage() {
        let root = Path::new("/srv/pages");
        assert_eq!(confine(root, ""), None);
        assert_eq!(confine(root, "/"), None);
        assert_eq!(confine(root, "%ff%fe"), None);
    }

    #[test]
    fn dump_writes_scaffold_and_version_marker() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("pages");
        let n = dump_frontend(&target).expect("dump");
        assert!(n > 0, "the embedded frontend must not be empty");
        assert_eq!(
            std::fs::read_to_string(target.join(VERSION_MARKER)).expect("marker"),
            version()
        );
        assert!(target.join("login.html").is_file());
        // Re-dump over an existing scaffold is a refresh, not an error.
        dump_frontend(&target).expect("re-dump");
    }

    #[tokio::test]
    async fn serve_prefers_disk_override_then_embedded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::write(root.join("login.html"), b"<html>override</html>").expect("write");
        let req = Request::new();

        // Overridden file comes from disk.
        let mut res = Response::new();
        serve(&req, &mut res, "login.html", Some(root)).await;
        assert_eq!(res.status_code, Some(StatusCode::OK));
        assert_eq!(
            res.take_string().await.expect("body"),
            "<html>override</html>"
        );

        // A file missing on disk falls back to the embedded asset.
        let mut res = Response::new();
        serve(&req, &mut res, "consent.html", Some(root)).await;
        assert_eq!(res.status_code, Some(StatusCode::OK));
        assert!(res.take_string().await.expect("body").starts_with("<!"));

        // Traversal attempts never reach the filesystem outside the root;
        // they fall through to the embedded tier, which 404s.
        let mut res = Response::new();
        serve(&req, &mut res, "../base.toml", Some(root)).await;
        assert_eq!(res.status_code, Some(StatusCode::NOT_FOUND));
    }

    #[tokio::test]
    async fn serve_revalidates_with_etag_on_both_tiers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::write(root.join("login.html"), b"<html>override</html>").expect("write");

        // Disk tier: first response carries a weak validator; echoing it in
        // If-None-Match answers 304 with no body.
        let mut res = Response::new();
        serve(&Request::new(), &mut res, "login.html", Some(root)).await;
        let etag = res
            .headers()
            .get(ETAG)
            .expect("disk etag")
            .to_str()
            .expect("ascii")
            .to_string();
        assert!(etag.starts_with("W/\""), "disk tier uses a weak validator");
        let mut req = Request::new();
        req.headers_mut()
            .insert(IF_NONE_MATCH, etag.parse().unwrap());
        let mut res = Response::new();
        serve(&req, &mut res, "login.html", Some(root)).await;
        assert_eq!(res.status_code, Some(StatusCode::NOT_MODIFIED));

        // Embedded tier: strong sha256 validator, same 304 round-trip.
        let mut res = Response::new();
        serve(&Request::new(), &mut res, "consent.html", None).await;
        let etag = res
            .headers()
            .get(ETAG)
            .expect("embedded etag")
            .to_str()
            .expect("ascii")
            .to_string();
        assert!(
            !etag.starts_with("W/") && etag.len() == 66,
            "embedded tier uses a strong sha256 validator: {etag}"
        );
        let mut req = Request::new();
        req.headers_mut()
            .insert(IF_NONE_MATCH, etag.parse().unwrap());
        let mut res = Response::new();
        serve(&req, &mut res, "consent.html", None).await;
        assert_eq!(res.status_code, Some(StatusCode::NOT_MODIFIED));

        // A foreign validator must not revalidate.
        let mut req = Request::new();
        req.headers_mut()
            .insert(IF_NONE_MATCH, "\"deadbeef\"".parse().unwrap());
        let mut res = Response::new();
        serve(&req, &mut res, "consent.html", None).await;
        assert_eq!(res.status_code, Some(StatusCode::OK));
    }

    #[tokio::test]
    async fn serve_without_override_dir_uses_embedded() {
        let req = Request::new();
        let mut res = Response::new();
        serve(&req, &mut res, "login.html", None).await;
        assert_eq!(res.status_code, Some(StatusCode::OK));
        let mut res = Response::new();
        serve(&req, &mut res, "nope.html", None).await;
        assert_eq!(res.status_code, Some(StatusCode::NOT_FOUND));
    }
}
