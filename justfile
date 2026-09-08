dev:
    # concurrently will launch both backend and front end
    cd frontend && npm run dev

run:
    cd frontend && npm run build
    cargo run --bin janux

build:
    cd frontend && npm run build
    cargo build    

release:
    cd frontend && npm run build
    cargo build --release

openapi:
    cargo run -q --bin openapi > frontend/openapi.json
    cd frontend && npm run openapi

# ─── Test commands ─────────────────────────────────────────────
#
# G-159: `unit` used to run only the tests/unit_tests target and skip
# the lib suite (~300 tests, the bulk of coverage) that CI runs. Both
# tiers now match the CI command exactly. The suites share process-wide
# singletons (revocation store, throttle caches), hence --test-threads=1.

unit:
    @echo "Running unit tests (lib suite + tests/unit)..."
    cargo test --lib --test unit_tests -- --test-threads=1


integration:
    @echo "Running integration tests..."
    cargo test --test z_integration_tests -- --test-threads=1


e2e:
    @echo "Running HTTP-level e2e tests (real server subprocess)..."
    cargo test --test all_tests -- --test-threads=1


compliant:
    @echo "Running the OIDC/SCIM conformance suite (needs uv)..."
    cd tests/compliant && uv run pytest -q


backup:
    @echo "Backing up the data dir (stop the server first)..."
    cargo run --bin janux -- backup ./backups


test: unit integration e2e
