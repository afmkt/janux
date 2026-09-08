//! Build script.
//!
//! G-158: this script used to probe for Playwright browser installs (via
//! a glob string passed to `fs::metadata`, which can never match) and
//! warn on every build — for a test tier that never drove a browser.
//! The e2e suite is HTTP-level (reqwest against a real server process);
//! nothing to install, nothing to detect.

fn main() {
    println!("cargo:rerun-if-changed=tests/");
    println!("cargo:rerun-if-env-changed=JANUX_TEST_BASE_URL");
}
