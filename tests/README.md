# Janux Auth Test Suite

Test tiers, from fastest to most end-to-end:

- **Lib suite** (`cargo test --lib`) — ~310 tests living next to the code
  in `src/**` `#[cfg(test)]` modules: data-layer gates, factor ceremony
  semantics, OIDC handler behavior via salvo `TestClient` services.
- **Unit tests** (`tests/unit_tests.rs` → `tests/unit/*_unit.rs`) —
  external-crate tests for pure contracts (policy engine, crypto,
  at_hash, AMR/ACR, cache, API helpers). No DB, no network.
- **Integration tests** (`tests/z_integration_tests.rs`) — a real server
  subprocess is auto-started (`tests/common.rs` `TestEnv`), provisioned
  with a real root+admin session; API-level flows over HTTP.
- **E2E tests** (`tests/e2e/all_tests.rs`) — HTTP-level end-to-end
  against one shared auto-started server: discovery, JWKS, factor
  surfaces, admin RBAC, hosted SPA pages. **No browser automation** —
  the old "Playwright-driven" claims described tests that never existed
  and were removed (gaps.md G-158); browser-driven UI coverage is a
  tracked future item.
- **Conformance suite** (`tests/compliant/`, Python + uv) — black-box
  OIDC/OAuth2/SCIM standards tests (discovery, code flow + PKCE, refresh
  rotation, revocation, introspection, device flow, JWKS, SCIM
  discovery) against a spawned server with a mock mail provider.

All Rust tiers share process-wide singletons (revocation store,
throttle caches) and **must run single-threaded** (`--test-threads=1`) —
the `just` targets and CI both do.

## Quick start

```bash
just unit          # lib suite + tests/unit (matches the CI command)
just integration   # integration tests
just e2e           # HTTP-level e2e
just compliant     # conformance suite (needs uv; builds the binary itself)
just test          # unit + integration + e2e
```

## Configuration

Rust-tier configuration lives in `tests/test_config.toml` (no env vars):

| Setting | Default | Description |
|---------|---------|-------------|
| `bind.port` | 18092 | Base port for the test server |
| `encryption_key` | hex string | AES-256 key (64 hex chars) |
| `[[seed]]` | seeded users | Default tenant with admin@test.local + user@test.local |

The suite auto-selects an available port in `[base_port, base_port + 20000)`.
The conformance suite generates its own server config
(`tests/compliant/harness/config.py`) — including
`disable_rate_limits = true`, the test-only knob that widens the per-IP
quotas so a single-IP suite run does not 429 itself.

## Unit test modules (`tests/unit/`)

Run one module: `cargo test --test unit_tests crypto_unit`.

| Module | What it tests |
|--------|--------------|
| `amr_unit` | RFC 8176 `amr` derivation, `acr` factor-name vocabulary (G-94), claim round-trips |
| `crypto_unit` | AES-256-GCM at rest: key validation order, round-trip, unique nonces, tampered/truncated ciphertext rejection, legacy fallback |
| `key_unit` | `at_hash` (OIDC Core §3.1.3.6): pinned spec vector, reference construction, base64url shape |
| `policy_unit` | RBAC policy engine: path matching (incl. the G-129 path constraint), source/target resolution, MFA gating, domain/action checks |
| `cache_unit` | EphemCache (Moka): insert/get, one-shot deletes, cleanup, unicode |
| `utils_unit` | ApiProblem/ApiResponse shapes, HttpMethod, JWT/JwtVerify construction |

The RSA key LIFECYCLE (generation, encryption at rest, kid routing,
retirement, JWKS) needs a database and lives in the lib suite
(`src/key.rs`, `src/db.rs`).

## Integration tests

`tests/z_integration_tests.rs`; server auto-started per test env.

```bash
just integration
```

Covers: health, tenant lifecycle (create → bootstrap → delete → backup),
domains, users/roles/policies CRUD under real sessions, social providers,
keys/JWKS, auth channel contracts, self-service endpoints.

## E2E tests

`tests/e2e/`; one shared server for the whole run
(`all_tests::shared_server`), provisioned WITH a real root+admin session
(`shared_admin_token`) so authenticated probes exercise the real
protect → policy → handler stack.

| Module | Flow tested |
|--------|------------|
| `signin_flow` | Login SPA serves, password-shaped verify refused 401, admin surface fails closed, roles lookup under a real session |
| `signup_flow` | SPA entry, health, parameterless `/authorize` contract |
| `passkey_flow` | Passkey request/verify wire contracts, admin SPA path |
| `oidc_flow` | Discovery (provisioned doc), userinfo/token/revoke/introspect error semantics, JWKS populated |
| `host_resolution` | Tenant resolution from Host, unprovisioned-host skeletons |
| `tenant_lifecycle` | Unauthenticated-contract probes (the authenticated lifecycle runs in the integration tier) |

## Conformance suite

```bash
just compliant        # or: cd tests/compliant && uv run pytest -q
```

Spawns `target/debug/janux` with a generated config and a mock Resend,
then runs black-box standards tests. See `tests/compliant/README.md` for
the spec mapping and the (all-landed) server enablers. The external OIDF
certification driver under `tests/compliant/oidf/` is manual (gaps.md
G-124).

## CI

`.github/workflows/ci.yml` runs: fmt + clippy (`-D warnings`) + OpenAPI
drift check + frontend lint/test + lib/unit suites (single-threaded) →
integration → e2e → conformance, plus `cargo audit` and a Docker build
check. Release workflows re-run the lib/unit suite before publishing and
smoke-test every artifact (G-135).

## Adding tests

- **Lib/unit**: next to the code in `src/**` `mod tests`, or a new
  `tests/unit/<name>_unit.rs` registered in `tests/unit_tests.rs`
  (`#[path = "unit/<name>_unit.rs"] mod <name>_unit;`).
- **Integration**: add to `tests/z_integration_tests.rs` using
  `TestEnv::new_with_auth()`.
- **E2E**: create `tests/e2e/<flow>.rs`, register it in
  `tests/e2e/all_tests.rs`, and drive the shared server via
  `super::shared_server()` / `super::shared_admin_token()`.
- **Conformance**: add under `tests/compliant/tests_op/` (OIDC/OAuth2)
  or `tests_scim/`, using the `janux_env` / `admin` fixtures.
