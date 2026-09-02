# OIDF conformance-suite driver

The OpenID Foundation conformance suite (`gitlab.com/openid/conformance-suite`,
MIT, free) is the authoritative arbiter for the OIDC profiles janux
implements. This directory wires it into the janux test workflow.

## Division of labor

| Track | Tool |
|---|---|
| OP protocol conformance (Basic + Config profiles) | OIDF suite, driven by `run_oidf.py` |
| RP protocol conformance for social login (`social.rs`) | OIDF suite RP plans (suite acts as fake OP; register it as a janux social provider) |
| SCIM, device flow, revocation/introspection depth, janux invariants | custom suite in `../tests_op`, `../tests_scim` |

## Running the suite locally

1. Clone and start the suite (see its wiki "Developers Build & Run"):

   ```sh
   git clone https://gitlab.com/openid/conformance-suite.git
   cd conformance-suite
   docker compose -f docker-compose-prebuilt.yml up -d   # or per the wiki
   ```

   The API is then at `https://localhost:8443` (self-signed cert → pass
   `--insecure` to `run_oidf.py`). Create an API token in the web UI.

2. janux must be reachable **from inside the suite containers**. Use
   `http://host.docker.internal:<port>` as the issuer and make sure a tenant
   domain resolves for that host (janux derives issuer + tenant from the
   `Host` header).

3. Register the static clients the OP plan needs (see
   `openid.net/certification/connect_op_testing`): two `client_secret_basic`
   clients and one `client_secret_post` client, all with redirect URI
   `https://www.certification.openid.net/test/a/<alias>/callback` (hosted
   suite) or the local suite's callback URL.

4. Fill in `plans/op-basic.example.json`, then:

   ```sh
   uv run oidf/run_oidf.py --suite https://localhost:8443 --insecure \
       --token $OIDF_API_TOKEN create oidf/plans/op-basic.example.json --save /tmp/plan-id
   uv run oidf/run_oidf.py --suite https://localhost:8443 --insecure \
       --token $OIDF_API_TOKEN run "$(cat /tmp/plan-id)" --export /tmp/oidf-results.json
   ```

## Browser steps

OP tests redirect into janux's login flow and wait. Complete the magic-link
login for the printed URL (the mock-Resend trick from the custom harness
works here too if the janux under test points `resend.base_url` at it).
`run_oidf.py` prints the URL whenever a test parks waiting for the user agent.

## Known blockers

- janux's hardcoded per-IP rate limits (12/min on the OIDC endpoints) will
  429 the suite; a test-mode override must land in janux first.
- RP plans for social login: register the suite's exported issuer via
  `admin/provider/create` (`issuer_url` = the suite's discovery URL), then
  drive `/api/v1/auth/social/{id}/request` — the suite auto-approves.
