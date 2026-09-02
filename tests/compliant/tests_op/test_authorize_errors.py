from urllib.parse import parse_qs, urlparse

REDIRECT_URI = "https://rp.example.com/callback"


def error_of(response):
    assert response.status_code == 302, (
        f"authorize error must still answer 302, got {response.status_code}"
    )
    loc = response.headers["location"]
    parsed = urlparse(loc)
    return parsed, parse_qs(parsed.query)


def test_unsupported_response_type_rejected(janux_env):
    r = janux_env.http.get(
        "/authorize",
        params={
            "response_type": "token",
            "client_id": "whatever",
            "redirect_uri": REDIRECT_URI,
        },
    )
    parsed, q = error_of(r)
    assert q["error"] == ["unsupported_response_type"]


def test_missing_client_id_rejected(janux_env):
    r = janux_env.http.get(
        "/authorize",
        params={"response_type": "code", "redirect_uri": REDIRECT_URI},
    )
    parsed, q = error_of(r)
    assert q["error"] == ["invalid_client"]


def test_unknown_client_never_redirects_to_redirect_uri(janux_env):
    r = janux_env.http.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "ghost-client",
            "redirect_uri": REDIRECT_URI,
            "state": "s-1",
        },
    )
    parsed, q = error_of(r)
    assert not r.headers["location"].startswith(REDIRECT_URI), (
        "RFC 6749 §4.1.2.1: must not redirect to an unvalidated URI"
    )
    assert q["error"] == ["invalid_client"]


def test_state_echoed_on_authorize_error(janux_env):
    r = janux_env.http.get(
        "/authorize",
        params={
            "response_type": "token",
            "client_id": "whatever",
            "redirect_uri": REDIRECT_URI,
            "state": "echo-me",
        },
    )
    _, q = error_of(r)
    assert q["state"] == ["echo-me"]


def test_unregistered_redirect_uri_not_used(janux_env, registered_client):
    r = janux_env.http.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": registered_client["client_id"],
            "redirect_uri": "https://attacker.example.com/steal",
            "state": "s-2",
        },
    )
    parsed, q = error_of(r)
    assert not r.headers["location"].startswith("https://attacker.example.com"), (
        "redirect URI validation failure must not redirect to the attacker URI"
    )


def test_missing_redirect_uri_rejected(janux_env, registered_client):
    r = janux_env.http.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": registered_client["client_id"],
        },
    )
    _, q = error_of(r)
    assert q["error"] == ["invalid_request"]


def test_public_client_requires_pkce(janux_env, admin):
    client_id = "conf-public"
    r = admin.create_oauth2_client(
        client_id,
        "",
        [REDIRECT_URI],
        auth_method="none",
    )
    if r.status_code != 200:
        import pytest

        pytest.skip(f"could not register public client: {r.status_code} {r.text}")
    r = janux_env.http.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid",
        },
    )
    _, q = error_of(r)
    assert q["error"] == ["invalid_request"]
