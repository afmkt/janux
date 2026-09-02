from __future__ import annotations

import dataclasses
from urllib.parse import parse_qs, urlparse

import httpx

from .resend import MockResend


def make_http(base_url: str, domain: str, timeout: float = 15.0) -> httpx.Client:
    return httpx.Client(
        base_url=base_url,
        headers={"Host": domain},
        follow_redirects=False,
        timeout=timeout,
    )


@dataclasses.dataclass
class JanuxEnv:
    base_url: str
    domain: str
    issuer: str
    http: httpx.Client
    resend: MockResend | None = None

    def path_of(self, absolute_url: str) -> str:
        parts = urlparse(absolute_url)
        if parts.netloc in ("", self.domain):
            return parts.path + (f"?{parts.query}" if parts.query else "")
        return absolute_url


def magic_link_login(
    env: JanuxEnv,
    name: str,
    email: str,
    park: dict | None = None,
) -> str:
    if env.resend is None:
        raise RuntimeError("no mock resend attached to this environment")
    body: dict = {"name": name, "email": email}
    if park:
        body.update(park)
    r = env.http.post("/api/v1/auth/email/request", json=body)
    assert r.status_code == 200, f"email/request failed: {r.status_code} {r.text}"
    link = env.resend.magic_link(email)
    q = parse_qs(urlparse(link).query)
    r = env.http.post(
        "/api/v1/auth/email/verify",
        json={
            "token": q["token"][0],
            "name": q["username"][0],
            "email": q["email"][0],
        },
    )
    assert r.status_code == 200, f"email/verify failed: {r.status_code} {r.text}"
    data = r.json()
    assert data.get("ok") and data.get("jwt"), f"verify response: {data}"
    return data["jwt"]


class AdminApi:
    def __init__(self, env: JanuxEnv, jwt: str):
        self.env = env
        self.headers = {"Authorization": f"Bearer {jwt}"}

    def _post(self, path: str, body: dict) -> httpx.Response:
        return self.env.http.post(path, json=body, headers=self.headers)

    def create_oauth2_client(
        self,
        client_id: str,
        secret: str,
        redirect_uris: list[str],
        grant_types: tuple[str, ...] = ("authorization_code", "refresh_token"),
        response_types: tuple[str, ...] = ("code",),
        auth_method: str = "client_secret_post",
        scopes: tuple[str, ...] = ("openid", "offline_access"),
    ) -> httpx.Response:
        return self._post(
            "/api/v1/admin/oauth2client/create",
            {
                "client_id": client_id,
                "secret": secret,
                "redirect_uris": " ".join(redirect_uris),
                "grant_types": " ".join(grant_types),
                "response_types": " ".join(response_types),
                "token_endpoint_auth_method": auth_method,
                "default_scopes": " ".join(scopes),
            },
        )

    def list_oauth2_clients(self) -> httpx.Response:
        return self.env.http.get("/api/v1/admin/oauth2client/list", headers=self.headers)

    def delete_oauth2_client(self, client_id: str) -> httpx.Response:
        return self._post("/api/v1/admin/oauth2client/delete", {"client_id": client_id})

    def set_client_meta(
        self,
        client_id: str,
        client_name: str | None = None,
        backchannel_logout_uri: str | None = None,
        post_logout_redirect_uris: list[str] | None = None,
    ) -> httpx.Response:
        body: dict = {"client_id": client_id}
        if client_name is not None:
            body["client_name"] = client_name
        if backchannel_logout_uri is not None:
            body["backchannel_logout_uri"] = backchannel_logout_uri
        if post_logout_redirect_uris is not None:
            body["post_logout_redirect_uris"] = post_logout_redirect_uris
        return self._post("/api/v1/admin/oauth2client/meta", body)

    def oidc_config(self) -> httpx.Response:
        return self.env.http.get("/api/v1/admin/oidc/config", headers=self.headers)

    def set_dcr_enabled(self, enabled: bool) -> httpx.Response:
        return self._post("/api/v1/admin/oidc/config", {"dcr_enabled": enabled})
