//! Unit tests for crypto module.

// Note: setup_encryption_key() uses global state (OnceLock), so only one test can set the key ever.
// The "key validation" tests that used to live here are removed for this reason.
