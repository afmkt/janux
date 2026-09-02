from __future__ import annotations

import base64
import json
import time

from jwcrypto import jwk, jwt


def load_jwks(jwks_dict: dict) -> jwk.JWKSet:
    return jwk.JWKSet(keys=[jwk.JWK(**key) for key in jwks_dict.get("keys", [])])


def _part(token: str, index: int) -> dict:
    seg = token.split(".")[index]
    seg += "=" * (-len(seg) % 4)
    return json.loads(base64.urlsafe_b64decode(seg))


def unverified_header(token: str) -> dict:
    return _part(token, 0)


def unverified_claims(token: str) -> dict:
    return _part(token, 1)


def validate_id_token(
    token: str,
    keyset: jwk.JWKSet,
    *,
    issuer: str,
    client_id: str,
    nonce: str | None = None,
    leeway: int = 30,
) -> dict:
    verified = jwt.JWT(jwt=token, key=keyset, algs=["RS256"])
    claims = json.loads(verified.claims)
    now = time.time()

    assert claims.get("iss") == issuer, f"iss {claims.get('iss')!r} != {issuer!r}"

    aud = claims.get("aud")
    auds = aud if isinstance(aud, list) else [aud]
    assert client_id in auds, f"aud {aud!r} does not contain {client_id!r}"
    if len(auds) > 1:
        assert claims.get("azp") == client_id, "multi-audience ID token must carry azp == client_id"

    assert "sub" in claims and claims["sub"], "ID token missing sub"
    assert "exp" in claims, "ID token missing exp"
    assert claims["exp"] >= now - leeway, "ID token expired"
    assert "iat" in claims, "ID token missing iat"

    if nonce is not None:
        assert claims.get("nonce") == nonce, (
            f"nonce mismatch: {claims.get('nonce')!r} != {nonce!r}"
        )

    return claims
