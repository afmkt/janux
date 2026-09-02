import pytest

PRIVATE_RSA_FIELDS = {"d", "p", "q", "dp", "dq", "qi"}

NO_KEYS_REASON = (
    "seeded tenants get no signing key (key_create is admin-only and the "
    "seeded admin cannot log in black-box); needs the janux seed extension — "
    "see README 'Janux enablers'"
)


@pytest.fixture()
def keys(jwks_dict):
    if not jwks_dict.get("keys"):
        pytest.skip(NO_KEYS_REASON)
    return jwks_dict["keys"]


@pytest.mark.xfail(strict=True, reason=NO_KEYS_REASON)
def test_jwks_not_empty(jwks_dict):
    assert jwks_dict.get("keys"), "JWKS must contain at least one signing key"


def test_jwks_is_valid_keyset_document(jwks_dict):
    assert isinstance(jwks_dict.get("keys"), list)


def test_keys_are_rsa_with_kid(keys):
    for key in keys:
        assert key.get("kty") == "RSA", f"non-RSA key advertised: {key.get('kty')}"
        assert key.get("kid"), "every signing key must carry a kid"
        assert key.get("n") and key.get("e"), "RSA key missing public components"


def test_no_private_material_in_jwks(keys):
    for key in keys:
        leaked = PRIVATE_RSA_FIELDS & set(key)
        assert not leaked, f"private key material {leaked} exposed in JWKS"


def test_key_usage_consistent_with_signing(discovery, keys):
    algs = set(discovery["id_token_signing_alg_values_supported"])
    for key in keys:
        if "use" in key:
            assert key["use"] == "sig"
        if "alg" in key:
            assert key["alg"] in algs, (
                f"JWKS alg {key['alg']} not advertised in discovery ({algs})"
            )
