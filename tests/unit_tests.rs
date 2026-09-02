// Entry point for all unit tests.
// Source modules are loaded via #[path] from the unit/ subdirectory.

#[path = "unit/amr_unit.rs"]
mod amr_unit;
#[path = "unit/cache_unit.rs"]
mod cache_unit;
#[path = "unit/crypto_unit.rs"]
mod crypto_unit;
#[path = "unit/key_unit.rs"]
mod key_unit;
#[path = "unit/policy_unit.rs"]
mod policy_unit;
#[path = "unit/utils_unit.rs"]
mod utils_unit;
