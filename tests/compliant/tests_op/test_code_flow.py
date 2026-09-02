import pytest

from harness.jwtutil import validate_id_token
from harness.oidc import run_code_flow, token_request, unique_user


@pytest.fixture()
def flow(janux_env, registered_client):
    def run(**overrides):
        kwargs = dict(
            client_id=registered_client["client_id"],
            redirect_uri=registered_client["redirect_uri"],
            secret=registered_client["secret"],
            auth_method=registered_client["auth_method"],
        )
        kwargs.update(overrides)
        return run_code_flow(janux_env, **kwargs)

    return run


def test_full_code_flow_with_pkce_s256(janux_env, registered_client, flow, jwks):
    res = flow(scope="openid")
    assert res.returned_state == res.state, "state must round-trip through the flow"
    assert res.consent_shown, "first authorization for a user/client pair requires consent"

    tr = res.token_response
    assert tr["status_code"] == 200, f"token exchange failed: {tr}"
    assert tr["token_type"].lower() == "bearer"
    assert tr.get("expires_in", 0) > 0
    assert tr.get("access_token"), "access_token missing"
    assert tr.get("id_token"), "openid scope must yield an id_token"

    claims = validate_id_token(
        tr["id_token"],
        jwks,
        issuer=janux_env.issuer,
        client_id=registered_client["client_id"],
        nonce=res.nonce,
    )
    assert claims.get("auth_time"), "auth_time is advertised in claims_supported"


def test_consent_not_repeated_for_existing_grant(janux_env, flow):
    user = unique_user(janux_env.domain)
    first = flow(user=user, exchange=False)
    assert first.consent_shown
    second = flow(user=user, exchange=False)
    assert not second.consent_shown, (
        "an unrevoked covering grant must skip the consent screen"
    )


def test_authorization_code_is_single_use(janux_env, registered_client, discovery, flow):
    res = flow(exchange=False)
    params = {"code": res.code, "redirect_uri": registered_client["redirect_uri"]}
    if res.verifier:
        params["code_verifier"] = res.verifier
    first = token_request(
        janux_env,
        discovery,
        grant_type="authorization_code",
        client_id=registered_client["client_id"],
        secret=registered_client["secret"],
        **params,
    )
    assert first.status_code == 200, first.text
    second = token_request(
        janux_env,
        discovery,
        grant_type="authorization_code",
        client_id=registered_client["client_id"],
        secret=registered_client["secret"],
        **params,
    )
    assert second.status_code == 400, f"replayed code must be rejected: {second.text}"
    assert second.json()["error"] == "invalid_grant"


def test_pkce_verifier_mismatch_rejected(janux_env, registered_client, discovery, flow):
    res = flow(exchange=False)
    params = {
        "code": res.code,
        "redirect_uri": registered_client["redirect_uri"],
        "code_verifier": "wrong-verifier-" + "x" * 40,
    }
    r = token_request(
        janux_env,
        discovery,
        grant_type="authorization_code",
        client_id=registered_client["client_id"],
        secret=registered_client["secret"],
        **params,
    )
    assert r.status_code == 400, f"PKCE mismatch must be rejected: {r.text}"
    assert r.json()["error"] == "invalid_grant"


def test_wrong_client_secret_rejected(janux_env, registered_client, discovery, flow):
    res = flow(exchange=False)
    params = {
        "code": res.code,
        "redirect_uri": registered_client["redirect_uri"],
        "code_verifier": res.verifier,
    }
    r = token_request(
        janux_env,
        discovery,
        grant_type="authorization_code",
        client_id=registered_client["client_id"],
        secret="wrong-secret",
        **params,
    )
    assert r.status_code in (400, 401), r.text
    assert r.json()["error"] == "invalid_client"


def test_consent_denied_returns_access_denied(janux_env, flow):
    res = flow(consent_decision="deny", exchange=False)
    assert "error=access_denied" in res.callback_url
    assert f"state={res.state}" in res.callback_url


def test_refresh_flow_with_rotation(janux_env, registered_client, discovery, flow):
    res = flow(scope="openid offline_access")
    tr = res.token_response
    assert tr["status_code"] == 200, tr
    refresh = tr.get("refresh_token")
    assert refresh, "offline_access scope must yield a refresh_token"

    r = token_request(
        janux_env,
        discovery,
        grant_type="refresh_token",
        client_id=registered_client["client_id"],
        secret=registered_client["secret"],
        refresh_token=refresh,
    )
    assert r.status_code == 200, f"refresh failed: {r.text}"
    rotated = r.json()
    assert rotated.get("access_token")
    assert rotated.get("refresh_token"), "refresh must rotate (single-winner design)"

    replay = token_request(
        janux_env,
        discovery,
        grant_type="refresh_token",
        client_id=registered_client["client_id"],
        secret=registered_client["secret"],
        refresh_token=refresh,
    )
    assert replay.status_code == 400, (
        f"rotated-out refresh_token must be rejected: {replay.text}"
    )


def test_userinfo_returns_subject(janux_env, registered_client, flow):
    res = flow(scope="openid")
    tr = res.token_response
    assert tr["status_code"] == 200, tr
    r = janux_env.http.get(
        "/userinfo",
        headers={"Authorization": f"Bearer {tr['access_token']}"},
    )
    assert r.status_code == 200, r.text
    assert r.json().get("sub") == res.id_token_claims["sub"]


def test_revocation_kills_refresh_token(janux_env, registered_client, discovery, flow):
    res = flow(scope="openid offline_access")
    tr = res.token_response
    assert tr["status_code"] == 200, tr
    refresh = tr["refresh_token"]

    r = janux_env.http.post(
        janux_env.path_of(discovery["revocation_endpoint"]),
        data={
            "token": refresh,
            "token_type_hint": "refresh_token",
            "client_id": registered_client["client_id"],
            "client_secret": registered_client["secret"],
        },
    )
    assert r.status_code == 200, f"RFC 7009 revocation failed: {r.text}"

    replay = token_request(
        janux_env,
        discovery,
        grant_type="refresh_token",
        client_id=registered_client["client_id"],
        secret=registered_client["secret"],
        refresh_token=refresh,
    )
    assert replay.status_code == 400, f"revoked refresh_token still works: {replay.text}"


def test_introspection_reports_active_token(janux_env, registered_client, discovery, flow):
    res = flow(scope="openid")
    tr = res.token_response
    assert tr["status_code"] == 200, tr

    r = janux_env.http.post(
        janux_env.path_of(discovery["introspection_endpoint"]),
        data={
            "token": tr["access_token"],
            "client_id": registered_client["client_id"],
            "client_secret": registered_client["secret"],
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("active") is True, body
    assert body.get("client_id") == registered_client["client_id"]
