"""SCIM 2.0 user provisioning track (G-124).

Black-box CRUD against the live server driven by a machine principal
minted through the client_credentials grant — the exact shape of a real
IdP integration. Pins the RFC 7644 behaviors: create/get/list/filter/
pagination, PATCH add/replace/remove semantics (G-146), case-insensitive
userName (G-145), uniqueness, and delete. Before this track the suite
only covered the discovery documents and the unauthenticated 401.
"""

from uuid import uuid4

import pytest

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
LIST_RESPONSE = "urn:ietf:params:scim:api:messages:2.0:ListResponse"


class ScimApi:
    def __init__(self, env, token: str):
        self.env = env
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/scim+json",
        }

    def get(self, path: str, params: dict | None = None):
        return self.env.http.get(f"/scim/v2/{path}", headers=self.headers, params=params)

    def post(self, path: str, body: dict):
        return self.env.http.post(f"/scim/v2/{path}", json=body, headers=self.headers)

    def patch(self, path: str, body: dict):
        return self.env.http.patch(f"/scim/v2/{path}", json=body, headers=self.headers)

    def put(self, path: str, body: dict):
        return self.env.http.put(f"/scim/v2/{path}", json=body, headers=self.headers)

    def delete(self, path: str):
        return self.env.http.delete(f"/scim/v2/{path}", headers=self.headers)


@pytest.fixture(scope="module")
def scim(janux_env, scim_token) -> ScimApi:
    return ScimApi(janux_env, scim_token)


def unique_name(domain: str) -> str:
    return f"scim-{uuid4().hex[:10]}@{domain}"


def test_machine_principal_lists_users(scim):
    r = scim.get("Users")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["schemas"] == [LIST_RESPONSE]
    assert isinstance(body["Resources"], list)
    # The seeded admin/user accounts exist.
    assert body["totalResults"] >= 2, body


def test_user_crud_lifecycle(scim, janux_env):
    name = unique_name(janux_env.domain)
    email_a = f"{name}-a@example.com"
    email_b = f"{name}-b@example.com"

    # Create.
    r = scim.post(
        "Users",
        {
            "schemas": [USER_SCHEMA],
            "userName": name,
            "active": True,
            "externalId": "ext-crud",
            "emails": [{"value": email_a, "primary": True}],
        },
    )
    assert r.status_code == 201, r.text
    user = r.json()
    uid = user["id"]
    assert user["userName"] == name
    assert user["externalId"] == "ext-crud"
    assert user["emails"][0]["value"] == email_a
    assert user["meta"]["resourceType"] == "User"
    assert user["meta"]["location"].endswith(f"/scim/v2/Users/{uid}")

    # Get by id.
    r = scim.get(f"Users/{uid}")
    assert r.status_code == 200
    assert r.json()["id"] == uid

    # Duplicate userName → 409 (RFC 7644 §7.8 uniqueness).
    r = scim.post("Users", {"schemas": [USER_SCHEMA], "userName": name})
    assert r.status_code == 409, r.text

    # PATCH replace (singular).
    r = scim.patch(
        f"Users/{uid}",
        {
            "schemas": [PATCH_OP],
            "Operations": [{"op": "replace", "path": "active", "value": False}],
        },
    )
    assert r.status_code == 200, r.text
    assert scim.get(f"Users/{uid}").json()["active"] is False

    # G-146: PATCH add APPENDS to a multi-valued attribute.
    r = scim.patch(
        f"Users/{uid}",
        {
            "schemas": [PATCH_OP],
            "Operations": [{"op": "add", "path": "emails", "value": [{"value": email_b}]}],
        },
    )
    assert r.status_code == 200, r.text
    emails = {e["value"] for e in scim.get(f"Users/{uid}").json().get("emails", [])}
    assert emails == {email_a, email_b}, "add must append, not replace"

    # G-146: PATCH remove with a value filter drops just that value.
    r = scim.patch(
        f"Users/{uid}",
        {
            "schemas": [PATCH_OP],
            "Operations": [{"op": "remove", "path": "emails", "value": [{"value": email_b}]}],
        },
    )
    assert r.status_code == 200, r.text
    emails = {e["value"] for e in scim.get(f"Users/{uid}").json().get("emails", [])}
    assert emails == {email_a}

    # PUT replaces the resource.
    r = scim.put(
        f"Users/{uid}",
        {
            "schemas": [USER_SCHEMA],
            "userName": name,
            "active": True,
            "externalId": "ext-put",
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["externalId"] == "ext-put"

    # Delete → 204, then 404.
    r = scim.delete(f"Users/{uid}")
    assert r.status_code == 204, r.text
    assert scim.get(f"Users/{uid}").status_code == 404


def test_filter_is_case_insensitive(scim, janux_env):
    # G-145 (RFC 7644 §5/§7.8): userName folds at the SCIM boundary and
    # filters resolve regardless of the presented case.
    mixed = f"Mixed-{uuid4().hex[:8]}@{janux_env.domain}"
    r = scim.post("Users", {"schemas": [USER_SCHEMA], "userName": mixed})
    assert r.status_code == 201, r.text
    folded = mixed.lower()
    assert r.json()["userName"] == folded, "create folds case at the boundary"

    for queried in (mixed, folded, mixed.upper()):
        r = scim.get("Users", params={"filter": f'userName eq "{queried}"'})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["totalResults"] == 1, f"filter {queried!r}: {body}"
        assert body["Resources"][0]["userName"] == folded


def test_list_pagination(scim, janux_env):
    # G-144: DB-level pagination with totalResults from a COUNT — pages
    # are disjoint slices of a stable order.
    for _ in range(3):
        r = scim.post(
            "Users",
            {"schemas": [USER_SCHEMA], "userName": unique_name(janux_env.domain)},
        )
        assert r.status_code == 201, r.text

    r = scim.get("Users", params={"count": 2, "startIndex": 1})
    assert r.status_code == 200
    page1 = r.json()
    assert page1["itemsPerPage"] == 2
    assert page1["startIndex"] == 1
    assert page1["totalResults"] >= 3
    ids1 = {u["id"] for u in page1["Resources"]}

    r = scim.get("Users", params={"count": 2, "startIndex": 3})
    assert r.status_code == 200
    page2 = r.json()
    ids2 = {u["id"] for u in page2["Resources"]}
    assert ids2, "startIndex=3 must still return rows"
    assert not (ids1 & ids2), "pages must be disjoint"


def test_unknown_user_404(scim):
    r = scim.get(f"Users/{uuid4()}")
    assert r.status_code == 404
