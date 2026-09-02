from __future__ import annotations

import dataclasses
import socket
from pathlib import Path

ENCRYPTION_KEY = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

ADMIN_RESOURCES = [
    "/api/v1/admin/oauth2client/list",
    "/api/v1/admin/oauth2client/create",
    "/api/v1/admin/oauth2client/delete",
    "/api/v1/admin/oauth2client/meta",
    "/api/v1/admin/oidc/config",
    "/api/v1/admin/user/list",
    "/api/v1/admin/user/roles",
    "/api/v1/admin/provider/list",
    "/api/v1/admin/provider/create",
    "/api/v1/admin/provider/delete",
    "/api/v1/admin/key/list",
    "/api/v1/admin/policy/list",
]

CONFIG_TEMPLATE = """data_dir = "{data_dir}"
encryption_key = "{encryption_key}"
trust_forwarded_headers = false

[bind]
address = "127.0.0.1"
port = {port}

[[seed]]
name = "{tenant}"
domains = [{{ id = "{domain}", cors = [] }}]
roles = ["root", "admin", "user", "guest"]
users = [
    {{ id = "admin@{domain}", active = true, roles = ["admin"] }},
    {{ id = "user@{domain}", active = true, roles = ["user"] }},
]
{policies}
[seed.resend]
from = "noreply@{domain}"
resend_key = "conformance-test-key"
template = "./template/email/verify.html"
verify_url = "http://{domain}/api/v1/auth/email/verify"
base_url = "http://127.0.0.1:{resend_port}"

[seed.alisms]
api_secret = "test-secret"
api_key = "test-key"
template_code = "TEST_123"
sign_name = "Conformance"
region_id = "cn-shanghai"
endpoint = "dysmsapi.aliyuncs.com"
"""

POLICY_TEMPLATE = """
[[seed.policies]]
domain = "{domain}"
resource = "{resource}"
role = "admin"
source = "Nothing"
target = "Nothing"
mfa = false
allowed = true
"""


@dataclasses.dataclass(frozen=True)
class ServerSpec:
    port: int
    resend_port: int
    tenant: str
    domain: str
    data_dir: Path
    config_path: Path

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def issuer(self) -> str:
        return f"http://{self.domain}"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def write_spec(
    root: Path,
    tenant: str = "conf-tenant",
    domain: str = "conf.local",
) -> ServerSpec:
    port = free_port()
    resend_port = free_port()
    root.mkdir(parents=True, exist_ok=True)
    data_dir = root / "data"
    config_path = root / "janux-conformance.toml"
    policies = "".join(
        POLICY_TEMPLATE.format(domain=domain, resource=r) for r in ADMIN_RESOURCES
    )
    config_path.write_text(
        CONFIG_TEMPLATE.format(
            data_dir=str(data_dir),
            encryption_key=ENCRYPTION_KEY,
            port=port,
            tenant=tenant,
            domain=domain,
            policies=policies,
            resend_port=resend_port,
        )
    )
    return ServerSpec(
        port=port,
        resend_port=resend_port,
        tenant=tenant,
        domain=domain,
        data_dir=data_dir,
        config_path=config_path,
    )
