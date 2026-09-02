from __future__ import annotations

import os

import pytest

from harness.config import write_spec
from harness.env import AdminApi, JanuxEnv, magic_link_login, make_http
from harness.jwtutil import load_jwks
from harness.oidc import fetch_discovery, fetch_jwks
from harness.resend import MockResend
from harness.server import JanuxServer

ADMIN_LOGIN_BLOCKED = (
    "black-box admin login is blocked by janux seed gaps: seeded tenants have "
    "no signing key (ceremony JWTs cannot be issued) and seeded users have no "
    "email credential; needs the janux seed extensions — see README "
    "'Janux enablers'"
)


def pytest_addoption(parser):
    parser.addoption(
        "--janux-url",
        default=os.environ.get("JANUX_BASE_URL"),
        help="attach to an already-running janux instead of spawning one",
    )
    parser.addoption(
        "--janux-domain",
        default=os.environ.get("JANUX_DOMAIN", "conf.local"),
        help="tenant domain of the attached janux instance",
    )


@pytest.fixture(scope="session")
def janux_env(request, tmp_path_factory):
    attach = request.config.getoption("--janux-url")
    if attach:
        domain = request.config.getoption("--janux-domain")
        http = make_http(attach, domain)
        env = JanuxEnv(
            base_url=attach, domain=domain, issuer=f"http://{domain}", http=http
        )
        yield env
        http.close()
        return

    root = tmp_path_factory.mktemp("janux-conformance")
    spec = write_spec(root)
    resend = MockResend(spec.resend_port)
    server = JanuxServer(spec, log_dir=root).start()
    http = make_http(spec.base_url, spec.domain)
    env = JanuxEnv(
        base_url=spec.base_url,
        domain=spec.domain,
        issuer=spec.issuer,
        http=http,
        resend=resend,
    )
    yield env
    http.close()
    server.stop()
    resend.stop()


@pytest.fixture(scope="session")
def discovery(janux_env):
    return fetch_discovery(janux_env)


@pytest.fixture(scope="session")
def jwks_dict(janux_env, discovery):
    return fetch_jwks(janux_env, discovery)


@pytest.fixture(scope="session")
def jwks(jwks_dict):
    return load_jwks(jwks_dict)


@pytest.fixture(scope="session")
def admin(janux_env):
    if janux_env.resend is None:
        pytest.skip("attached mode: no mock resend to intercept the admin login email")
    try:
        jwt = magic_link_login(janux_env, f"admin@{janux_env.domain}", f"admin@{janux_env.domain}")
    except (AssertionError, TimeoutError, ValueError):
        pytest.skip(ADMIN_LOGIN_BLOCKED)
    return AdminApi(janux_env, jwt)


@pytest.fixture(scope="session")
def registered_client(janux_env, admin):
    client_id = "conf-rp"
    secret = "conf-rp-secret"
    redirect_uri = "https://rp.example.com/callback"
    r = admin.create_oauth2_client(
        client_id,
        secret,
        [redirect_uri],
        grant_types=("authorization_code", "refresh_token"),
        auth_method="client_secret_post",
        scopes=("openid", "offline_access", "profile", "email"),
    )
    if r.status_code != 200:
        pytest.skip(f"oauth2 client registration failed ({r.status_code}: {r.text})")
    return {
        "client_id": client_id,
        "secret": secret,
        "redirect_uri": redirect_uri,
        "auth_method": "client_secret_post",
    }
