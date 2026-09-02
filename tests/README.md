# Janux Auth Test Suite

This directory contains all test code for the Janux auth server, organized into three tiers:

- **Unit tests** — Fast, isolated tests for individual modules (no DB or network required)
- **Integration tests** — API-level tests with auto-started server  
- **E2E tests** — HTTP-level tests verifying full user flows with auto-started server

## Quick Start

```bash
# Run unit tests only (no server needed)
cargo test --lib

# Install Playwright browsers (one-time setup)
just e2e-setup

# Run everything (auto-starts server, no env vars needed)
just test
```

## Configuration

All test configuration lives in `tests/test_config.toml`. No environment variables required.

Key settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `server.port` / `bind.port` | 18092 | Base port for test server |
| `encryption_key` | hex string | AES-256 key (64 hex chars) |
| `[[seed]]` | seeded users | Default tenant with admin@test.local + user@test.local |

The test suite auto-selects an available port in range `[base_port, base_port + 20000)` to avoid collisions.

## Unit Tests

Located in `tests/unit/`. Run:

```bash
cargo test --lib                    # All unit tests
cargo test crypto_unit              # Individual module
cargo test policy_unit  
cargo test cache_unit
cargo test key_unit
cargo test utils_unit
```

### Test modules

| Module | What it tests | Key coverage areas |
|--------|--------------|-------------------|
| `crypto_unit` | AES-256-GCM encryption | Key validation, round-trip encrypt/decrypt, nonce randomization, tampered ciphertext rejection |
| `policy_unit` | RBAC policy engine | Path matching, source/target resolution, MFA gating, domain/action checks, edge cases |
| `cache_unit` | EphemCache (Moka) | Insert/get, duplicate rejection, one-shot deletes, cleanup, unicode keys/values |
| `key_unit` | RSA key management & at_hash | Key hex validation, base64url encoding, JWT claim structure |
| `utils_unit` | API helpers | ApiProblem variants, ApiResponse serialization, HttpMethod enum tests, JWT/JwtVerify struct construction |

## Integration Tests

Located in `tests/z_integration_tests.rs`. Server is auto-started.

```bash
just test-integration
# or manually:
cargo test --test z_integration_tests
```

### Test categories

| Category | Endpoints Tested | Notes |
|----------|-----------------|-------|
| Health | `GET /api/v1/healthy` | Basic connectivity check |
| Tenant CRUD | `POST/GET/DELETE /admin/tenant/*` | Full tenant lifecycle (create → verify → delete) |
| Domain mgmt | `GET/POST/DELETE /admin/domain/*` | CORS and domain config |
| User lifecycle | `/admin/user/create, list, delete, activate, roles` | Complete user management flow |
| Role mgmt | `/admin/role/create, list, delete` | Role creation/deletion |
| Policy mgmt | `/admin/policy/create, list, delete` | RBAC policy CRUD |
| Social providers | `/admin/provider/*` | OAuth2 provider registration |  
| Key/JWKS | `/admin/key/*`, `/.well-known/jwks.json` | JWT key rotation |
| Auth flows | `/auth/email/request` | Passwordless auth channels |
| User self-mgmt | `/user/delete/self, /activate/self` | Self-service endpoints |

## E2E Tests

Located in `tests/e2e/`. Server is auto-started from `test_config.toml`.

```bash
just test-e2e                       # Run all e2e tests
cargo test --test all_tests         # Same

# Headed mode:
JUST test-e2e-headed                # Interactive browser
```

### Test modules

| Module | Flow Tested | 
|--------|------------|
| `signin_flow` | Login page loads, form structure, wrong credentials handling |
| `signup_flow` | Registration page, signup form elements, OIDC authorize/token endpoints |
| `passkey_flow` | WebAuthn challenge flow, passkey verify/reject |
| `oidc_flow` | Well-known discovery, userinfo, revoke, introspect, token, JWKS |
| `tenant_lifecycle` | Server health, tenant CRUD, domain mgmt, email/refresh/logout endpoints |

### How tests work

Tests use a shared config loader that reads from `tests/test_config.toml`. No env vars — just:

```rust
// Every test file uses this shared helper:
let base_url = e2e_config::base_url();  // → "http://127.0.0.1:18092" (from config)
```

The server auto-launches from `common.rs`'s `TestEnv::new()` with a temp data dir and seeded tenant, then kills itself when the test process exits.

## Running All Tests

```bash
# Full suite (unit → integration → e2e)
just test                             # Everything, auto-starts server
```

## CI Integration

This suite is designed for GitHub Actions (or equivalent):

1. `cargo install just` — if not installed
2. `just e2e-setup` — install Playwright browsers 
3. Run: `just test`

No env vars, no manual server setup.

## Adding New Tests

### Unit tests
Create `tests/unit/<name>_unit.rs`, add to `mod.rs`:

```rust
// tests/unit/mod.rs
mod crypto_unit;   // existing
mod my_feature;    // new module
```

### Integration tests
Add to `z_integration_tests.rs`:

```rust
#[tokio::test]  
async fn my_api_endpoint_test() {
    let env = TestEnv::new_with_auth().await;
    // ...
}
```

### E2E tests
Create `tests/e2e/<flow>.rs`, add to `all_tests.rs`:

```rust
// tests/e2e/all_tests.rs
mod my_flow;   // new module

// In your flow file:
#[tokio::test]
async fn test_my_feature() {
    let base_url = e2e_config::base_url();
    // ...
}
```
