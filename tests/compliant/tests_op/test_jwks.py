import pytest

PRIVATE_RSA_FIELDS = {"d", "p", "q", "dp", "dq", "qi"}

# The seed extension landed (G-136 enabler #3): every seeded domain gets a
# signing key at seed time, so an empty JWKS is now a real failure, not a
# known gap.
NO_KEYS_REASON = (
    "seeded tenants must advertise a signing key — the seed creates one per "
    "domain (TenantDTO::save); an empty JWKS means that regressed"
)


@pytest.fixture()
def keys(jwks_dict):
    assert jwks_dict.get("keys"), NO_KEYS_REASON
    return jwks_dict["keys"]


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
