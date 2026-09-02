"""OIDC extension profiles: Dynamic Client Registration (RFC 7591),
RP-Initiated Logout 1.0, Back-Channel Logout 1.0 — black-box surface that
needs no admin session.

Admin-gated behavior (enabling DCR, registering back-channel URIs, the
full code-flow + logout round-trip) is blocked by the janux seed gaps —
see README 'Janux enablers' — and lives behind the `admin` fixture skip.
"""

from __future__ import annotations

import pytest

# ── Discovery metadata ────────────────────────────────────────────────────────


def test_end_session_endpoint_anchored_at_issuer(discovery):
    assert "end_session_endpoint" in discovery, (
        "RP-Initiated Logout requires end_session_endpoint in discovery"
    )
    assert discovery["end_session_endpoint"].startswith(discovery["issuer"])


def test_backchannel_logout_advertised_without_session_support(discovery):
    # The OP is stateless (README §2): logout tokens carry `sub`, never
    # `sid`, so session support must be advertised as false.
    assert discovery.get("backchannel_logout_supported") is True
    assert discovery.get("backchannel_logout_session_supported") is False


def test_registration_endpoint_tracks_dcr_gate(discovery):
    # The seeded conformance tenant has not opted into Dynamic Client
    # Registration, so discovery must not advertise the endpoint.
    assert "registration_endpoint" not in discovery


# ── /register: tenant gate and validation (DCR disabled) ─────────────────────


def test_register_rejected_while_dcr_disabled(janux_env):
    r = janux_env.http.post(
        "/register",
        json={"redirect_uris": ["https://rp.example.com/callback"]},
    )
    assert r.status_code == 400
    body = r.json()
    assert body["error"] == "invalid_client_metadata"
    assert "registration" in body.get("error_description", "").lower() or (
        "dynamic" in body.get("error_description", "").lower()
    )


# ── /end_session: RP-Initiated Logout error semantics ────────────────────────


def test_end_session_bare_logout_is_ok(janux_env):
    # No client, no redirect URI: a valid logout of nothing in particular.
    r = janux_env.http.get("/end_session")
    assert r.status_code == 200


def test_end_session_rejects_unregistered_post_logout_uri(janux_env):
    # RP-Initiated Logout 1.0 §2: post_logout_redirect_uri must be
    # previously registered. An unvalidated URI must never get a redirect.
    r = janux_env.http.get(
        "/end_session",
        params={
            "client_id": "no-such-client",
            "post_logout_redirect_uri": "https://evil.example/cb",
            "state": "abc",
        },
        follow_redirects=False,
    )
    assert r.status_code == 400
    assert "location" not in r.headers


def test_end_session_rejects_redirect_without_client(janux_env):
    r = janux_env.http.get(
        "/end_session",
        params={"post_logout_redirect_uri": "https://rp.example.com/cb"},
        follow_redirects=False,
    )
    assert r.status_code == 400
    assert "location" not in r.headers


def test_end_session_ignores_garbage_id_token_hint(janux_env):
    # A hint that fails validation is ignored; without any other client
    # identification a redirect request still fails closed.
    r = janux_env.http.get(
        "/end_session",
        params={
            "id_token_hint": "not-a-jwt",
            "post_logout_redirect_uri": "https://rp.example.com/cb",
        },
        follow_redirects=False,
    )
    assert r.status_code == 400
    assert "location" not in r.headers
