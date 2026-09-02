from __future__ import annotations

import base64
import dataclasses
import hashlib
import secrets
from urllib.parse import parse_qs, urlparse

import httpx

from .env import JanuxEnv, magic_link_login
from .jwtutil import unverified_claims

DISCOVERY_PATH = "/.well-known/openid-configuration"


def pkce_pair(method: str = "S256") -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).rstrip(b"=").decode()
    if method.upper() == "PLAIN":
        return verifier, verifier
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def fetch_discovery(env: JanuxEnv) -> dict:
    r = env.http.get(DISCOVERY_PATH)
    assert r.status_code == 200, f"discovery failed: {r.status_code} {r.text}"
    return r.json()


def fetch_jwks(env: JanuxEnv, discovery: dict) -> dict:
    r = env.http.get(env.path_of(discovery["jwks_uri"]))
    assert r.status_code == 200, f"jwks failed: {r.status_code} {r.text}"
    return r.json()


def token_request(
    env: JanuxEnv,
    discovery: dict,
    *,
    grant_type: str,
    client_id: str,
    secret: str | None = None,
    auth_method: str = "client_secret_post",
    **params: str,
) -> httpx.Response:
    data: dict = {"grant_type": grant_type, **params}
    headers: dict = {}
    if auth_method == "client_secret_basic":
        raw = f"{client_id}:{secret or ''}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()
    elif auth_method == "client_secret_post":
        data["client_id"] = client_id
        if secret is not None:
            data["client_secret"] = secret
    elif auth_method == "none":
        data["client_id"] = client_id
    else:
        raise ValueError(f"unsupported auth_method {auth_method!r}")
    return env.http.post(
        env.path_of(discovery["token_endpoint"]), data=data, headers=headers
    )


@dataclasses.dataclass
class CodeFlowResult:
    callback_url: str
    code: str
    returned_state: str | None
    nonce: str
    state: str
    verifier: str | None
    session_jwt: str
    consent_shown: bool
    token_response: dict
    id_token_claims: dict | None


def unique_user(domain: str) -> str:
    return f"conf-{secrets.token_hex(6)}@{domain}"


def run_code_flow(
    env: JanuxEnv,
    *,
    client_id: str,
    redirect_uri: str,
    secret: str | None = None,
    auth_method: str = "client_secret_post",
    scope: str = "openid",
    pkce: str | None = "S256",
    user: str | None = None,
    consent_decision: str = "accept",
    exchange: bool = True,
    verifier_override: str | None = None,
) -> CodeFlowResult:
    state = f"rp-state-{secrets.token_hex(8)}"
    nonce = f"rp-nonce-{secrets.token_hex(8)}"
    verifier: str | None = None
    challenge: str | None = None
    if pkce:
        verifier, challenge = pkce_pair(pkce)

    params: dict = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "nonce": nonce,
    }
    if challenge:
        params["code_challenge"] = challenge
        params["code_challenge_method"] = pkce

    r = env.http.get("/authorize", params=params)
    assert r.status_code == 302, f"authorize expected 302, got {r.status_code}: {r.text}"
    loc = r.headers["location"]
    parsed = urlparse(loc)
    assert parsed.path == "/login", f"expected redirect to /login, got {loc}"
    csrf = parse_qs(parsed.query)["state"][0]

    user = user or unique_user(env.domain)
    jwt = magic_link_login(
        env,
        user,
        user,
        park={"client_id": client_id, "state": csrf, "redirect_uri": redirect_uri},
    )
    bearer = {"Authorization": f"Bearer {jwt}"}

    r = env.http.get("/authorize/resume", params={"state": csrf}, headers=bearer)
    assert r.status_code == 200, f"resume failed: {r.status_code} {r.text}"
    hop = r.json()["redirect"]

    consent_shown = False
    if urlparse(hop).path == "/consent":
        consent_shown = True
        csrf2 = parse_qs(urlparse(hop).query)["state"][0]
        r = env.http.post(
            "/consent",
            json={"state": csrf2, "decision": consent_decision},
            headers=bearer,
        )
        assert r.status_code == 200, f"consent failed: {r.status_code} {r.text}"
        hop = r.json()["redirect"]

    cb = urlparse(hop)
    cq = parse_qs(cb.query)
    returned_state = cq.get("state", [None])[0]

    result = CodeFlowResult(
        callback_url=hop,
        code=cq.get("code", [None])[0],
        returned_state=returned_state,
        nonce=nonce,
        state=state,
        verifier=verifier,
        session_jwt=jwt,
        consent_shown=consent_shown,
        token_response={},
        id_token_claims=None,
    )
    if not exchange:
        return result

    assert result.code, f"no code in callback: {hop}"
    discovery = fetch_discovery(env)
    token_params = {"code": result.code, "redirect_uri": redirect_uri}
    if verifier is not None:
        token_params["code_verifier"] = verifier_override or verifier
    r = token_request(
        env,
        discovery,
        grant_type="authorization_code",
        client_id=client_id,
        secret=secret,
        auth_method=auth_method,
        **token_params,
    )
    result.token_response = {"status_code": r.status_code, **r.json()}
    if r.status_code == 200 and r.json().get("id_token"):
        result.id_token_claims = unverified_claims(r.json()["id_token"])
    return result
