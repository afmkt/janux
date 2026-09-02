import pytest

REQUIRED_METADATA = [
    "issuer",
    "jwks_uri",
    "authorization_endpoint",
    "token_endpoint",
    "response_types_supported",
    "subject_types_supported",
    "id_token_signing_alg_values_supported",
]

KNOWN_GRANTS = {
    "authorization_code",
    "refresh_token",
    "client_credentials",
    "urn:ietf:params:oauth:grant-type:device_code",
}


def test_discovery_served_for_known_tenant(janux_env):
    r = janux_env.http.get("/.well-known/openid-configuration")
    assert r.status_code == 200


def test_discovery_unknown_tenant_is_not_found(janux_env):
    r = janux_env.http.get(
        "/.well-known/openid-configuration", headers={"Host": "unknown.example"}
    )
    assert r.status_code == 404


@pytest.mark.parametrize("field", REQUIRED_METADATA)
def test_required_metadata_present(discovery, field):
    assert field in discovery, f"discovery is missing required field {field}"


def test_issuer_matches_tenant_host(janux_env, discovery):
    assert discovery["issuer"] == janux_env.issuer


@pytest.mark.parametrize(
    "field",
    [
        "jwks_uri",
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "revocation_endpoint",
        "introspection_endpoint",
    ],
)
def test_endpoints_anchored_at_issuer(discovery, field):
    if field not in discovery:
        pytest.skip(f"{field} not advertised")
    assert discovery[field].startswith(discovery["issuer"]), (
        f"{field} must be anchored at the issuer"
    )


def test_response_types_code_only(discovery):
    assert discovery["response_types_supported"] == ["code"]


def test_pkce_s256_advertised(discovery):
    assert "S256" in discovery.get("code_challenge_methods_supported", [])


def test_subject_types_valid(discovery):
    assert set(discovery["subject_types_supported"]) <= {"public", "pairwise"}


def test_signing_algs_include_rs256(discovery):
    assert "RS256" in discovery["id_token_signing_alg_values_supported"]


def test_token_auth_methods_valid(discovery):
    methods = discovery.get("token_endpoint_auth_methods_supported", [])
    assert set(methods) <= {
        "none",
        "client_secret_post",
        "client_secret_basic",
        "private_key_jwt",
        "tls_client_auth",
    }


def test_advertised_grants_are_implemented(discovery):
    assert set(discovery.get("grant_types_supported", [])) <= KNOWN_GRANTS


@pytest.mark.xfail(
    strict=True,
    reason=(
        "janux implements client_credentials at /token but does not advertise it "
        "in grant_types_supported (oidc.rs SUPPORTED_GRANT_TYPES vs well_known)"
    ),
)
def test_client_credentials_advertised(discovery):
    assert "client_credentials" in discovery.get("grant_types_supported", [])


def test_device_flow_endpoints_consistent(discovery):
    has_grant = (
        "urn:ietf:params:oauth:grant-type:device_code"
        in discovery.get("grant_types_supported", [])
    )
    has_endpoint = "device_authorization_endpoint" in discovery
    assert has_grant == has_endpoint
