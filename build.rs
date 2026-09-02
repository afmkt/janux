//! Build script for E2E tests.
//!
//! Ensures Playwright browsers are installed before running E2E tests.
//! If playwright-browsers are missing, it runs `npx playwright install` automatically.

// use std::path::Path;
// use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=tests/");
    println!("cargo:rerun-if-env-changed=JANUX_TEST_BASE_URL");
    println!("cargo:rerun-if-env-changed=PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD");

    // Check if playwright browsers are already installed
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
    let browser_paths = [
        format!(
            "{}/Library/Caches/ms-playwright/chromium-*/chrome-mac/Chromium.app/Contents/MacOS/Chromium",
            home
        ),
        format!(
            "{}/.cache/ms-playwright/chromium-*/chrome-linux/chrome",
            home
        ),
        format!(
            "{}/AppData/Local/ms-playwright/chromium-*/chrome-win/chrome.exe",
            home
        ),
    ];

    let browsers_installed = browser_paths
        .iter()
        .any(|path| std::fs::metadata(path).is_ok());

    if !browsers_installed && std::env::var("PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD").is_err() {
        println!(
            "cargo:warning=Playwright browsers not found. Run 'just e2e-setup' or 'npx playwright install' to install them."
        );
    }
}
