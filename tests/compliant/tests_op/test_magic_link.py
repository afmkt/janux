from harness.env import magic_link_login
from harness.jwtutil import unverified_claims
from harness.oidc import unique_user

# Was a module-wide strict xfail while seeded tenants had no signing key
# (G-136 enabler #3). The seed now creates one key per domain, so these
# ceremonies run for real.


def session_username(claims: dict) -> str | None:
    # janux session JWTs FLATTEN JwtData into the claim set (serde
    # flatten): the login name is the top-level `username`; `sub` is the
    # opaque user UUID (SCIM id), not the username.
    return claims.get("username")


def test_magic_link_signup_yields_session_jwt(janux_env):
    user = unique_user(janux_env.domain)
    jwt = magic_link_login(janux_env, user, user)
    claims = unverified_claims(jwt)
    assert session_username(claims) == user, claims
    assert claims.get("sub"), "session JWT must carry a subject"


def test_magic_link_signin_works_after_signup(janux_env):
    user = unique_user(janux_env.domain)
    magic_link_login(janux_env, user, user)
    jwt = magic_link_login(janux_env, user, user)
    claims = unverified_claims(jwt)
    assert session_username(claims) == user, claims
    assert claims.get("sub"), "session JWT must carry a subject"
