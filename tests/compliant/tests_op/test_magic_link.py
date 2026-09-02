import pytest

from harness.env import magic_link_login
from harness.jwtutil import unverified_claims
from harness.oidc import unique_user

pytestmark = pytest.mark.xfail(
    strict=True,
    reason=(
        "seeded tenants have no signing key, so jwt_authenticate cannot issue "
        "the ceremony JWT ('Fail to issue JWT'); needs the janux seed "
        "extension — see README 'Janux enablers'"
    ),
)


def test_magic_link_signup_yields_session_jwt(janux_env):
    user = unique_user(janux_env.domain)
    jwt = magic_link_login(janux_env, user, user)
    claims = unverified_claims(jwt)
    assert claims.get("user") == user or claims.get("sub") == user, claims


def test_magic_link_signin_works_after_signup(janux_env):
    user = unique_user(janux_env.domain)
    magic_link_login(janux_env, user, user)
    jwt = magic_link_login(janux_env, user, user)
    claims = unverified_claims(jwt)
    assert claims.get("user") == user or claims.get("sub") == user, claims
