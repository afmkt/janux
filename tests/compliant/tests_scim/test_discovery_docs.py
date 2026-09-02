SPC_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
LIST_RESPONSE = "urn:ietf:params:scim:api:messages:2.0:ListResponse"


def scim_get(janux_env, path):
    return janux_env.http.get(f"/scim/v2/{path}")


def assert_scim_content_type(r):
    assert r.headers.get("content-type", "").startswith("application/scim+json"), (
        f"RFC 7644 §3.8: expected application/scim+json, got {r.headers.get('content-type')}"
    )


def test_service_provider_config(janux_env):
    r = scim_get(janux_env, "ServiceProviderConfig")
    assert r.status_code == 200
    assert_scim_content_type(r)
    body = r.json()
    assert body["schemas"] == [SPC_SCHEMA]
    assert body["patch"]["supported"] is True
    assert body["bulk"]["supported"] is False
    assert body["filter"]["supported"] is True
    assert body["filter"]["maxResults"] > 0
    assert body["changePassword"]["supported"] is False
    assert body["sort"]["supported"] is False
    schemes = [s["type"] for s in body["authenticationSchemes"]]
    assert "oauthbearertoken" in schemes
    assert body["meta"]["resourceType"] == "ServiceProviderConfig"


def test_schemas_lists_user_schema(janux_env):
    r = scim_get(janux_env, "Schemas")
    assert r.status_code == 200
    assert_scim_content_type(r)
    body = r.json()
    assert body["schemas"] == [LIST_RESPONSE]
    users = [res for res in body["Resources"] if res["id"] == USER_SCHEMA]
    assert users, "User schema missing from /Schemas"
    attrs = {a["name"]: a for a in users[0]["attributes"]}
    assert attrs["userName"]["required"] is True


def test_resource_types_declares_users_endpoint(janux_env):
    r = scim_get(janux_env, "ResourceTypes")
    assert r.status_code == 200
    assert_scim_content_type(r)
    body = r.json()
    assert body["schemas"] == [LIST_RESPONSE]
    user_types = [res for res in body["Resources"] if res["name"] == "User"]
    assert user_types, "User resource type missing"
    assert user_types[0]["endpoint"] == "/Users"
    assert user_types[0]["schema"] == USER_SCHEMA


def test_users_requires_authentication(janux_env):
    r = scim_get(janux_env, "Users")
    assert r.status_code == 401, (
        f"unauthenticated /Users must be 401, got {r.status_code}"
    )
