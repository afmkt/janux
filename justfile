
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


unit:
    @echo "Running unit tests..."
    cargo test --test unit_tests


integration:
    @echo "Running integration tests..."
    cargo test --test z_integration_tests -- --test-threads=1


e2e:
    cargo test --test all_tests -- --test-threads=1


e2e-setup:
    @echo "Installing Playwright browsers..."
    npx playwright install --with-deps chromium


e2e-headed:
    @echo "Running E2E tests in headed mode..."
    cargo test --test all_tests --nocapture  -- env_filter=info::debug


test: unit integration e2e
