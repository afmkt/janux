#!/usr/bin/env python3
"""up.py -- run / tear down a janux + Caddy forward-auth example.

Usage:
      ./up.py single-host   <build|up|down|logs|ps|rekey>
      ./up.py split-hosts   <build|up|down|logs|ps|trust-ca>

Each sub-directory (single-host/, split-hosts/) is a self-contained
`docker compose` project: caddy (public front) + janux (auth) + nginx
(the "simple service", a static site). This wrapper, per project:

    1. renders base.toml / seed.toml from the *.example.toml templates
       (regenerating the encryption_key; you never edit a generated .toml
        by hand),
    2. exports CADDY_TLS so Caddy uses its local CA, and
    3. for split-hosts, maps the two hostnames into /etc/hosts and -- on
       macOS -- trusts that CA in the system keychain.

TLS is MANDATORY, not optional: janux's session cookie is `Secure` and
HOST-ONLY (no Domain attribute; src/verify.rs::set_session_cookie), so it
transmits ONLY over https. Caddy also auto-redirects http -> https on
localhost, which is itself a secure context. On Linux, open
https://127.0.0.1/ (its self-signed cert need not be trusted for the
browser to reach the server); on macOS trust caddy's CA once.

Both setups publish :80/:443, so run only ONE at a time. See README.md.
"""
from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SETUPS = ("single-host", "split-hosts")

# hostnames the split-hosts front must resolve to this loopback, so the
# browser reaches caddy instead of the public Internet.
SPLIT_HOSTS = ("app.example.com", "auth.example.com")
HOSTS_FILE = Path("/etc/hosts")
_MARK = "janux-example-split-hosts"
# Caddy 2.x global TLS via env. "tls internal" is the value that survives this
# Caddy's `handle` parser -- a `global { tls internal }` Caddyfile block does
# NOT, so the env is the one TLS control.
CADDY_TLS_VALUE = "tls internal"


# --- config rendering -----------------------------------------------------
def _render(src: Path, dst: Path, regen_key: bool) -> None:
    text = src.read_text()
    if regen_key:
        key = os.urandom(32).hex()   # 64 hex chars == 32 bytes, AES-256-GCM
        text, n = re.subn(r"^encryption_key\s*=.*$",
                          f'encryption_key = "{key}"', text,
                          count=1, flags=re.MULTILINE)
        assert n == 1, f"{src}: no encryption_key line to replace"
        print(f"      fresh 32-byte encryption_key -> {dst.name}")
    dst.write_text(text)
    print(f"      rendered {dst}")


def prepare_configs(setup_dir: Path) -> None:
    """Copy *.example.toml -> *.toml (gitignored) so `up` works from a clone."""
    for example, target, regen in (
            ("base.example.toml", "base.toml", True),
            ("seed.example.toml", "seed.toml", False)):
        src = setup_dir / example
        if not src.exists():
            print(f"      ! missing {src}", file=sys.stderr)
            continue
        _render(src, setup_dir / target, regen)


# --- /etc/hosts for split-hosts ------------------------------------------
def _hosts_block(add: bool) -> str:
    lines = [f"# {_MARK}"]
    if add:
        lines += [f"127.0.0.1 {h}" for h in SPLIT_HOSTS]
    lines.append(f"# {_MARK}_END")
    return "\n".join(lines) + "\n"


def update_hosts(add: bool) -> None:
    if not HOSTS_FILE.exists():
        return
    content = HOSTS_FILE.read_text()
    pat = re.compile(r"#\s*" + re.escape(_MARK) + r"\b.*?#\s*" +
                          re.escape(_MARK) + r"_END\n?", re.DOTALL)
    new = pat.sub(_hosts_block(add), content, count=1)
    if new == content:
        new = content.rstrip() + "\n\n" + _hosts_block(add)
    try:
        HOSTS_FILE.write_text(new)
    except PermissionError:
        print("      ! /etc/hosts needs root; re-run the hosts step via sudo",
               file=sys.stderr)


# --- macOS CA trust -------------------------------------------------------
def trust_caddy_root() -> None:
    """Best-effort macOS: extract caddy's locally-generated root CA and trust it."""
    if sys.platform != "darwin":
        print("      (CA trust is a no-op off macOS -- https://127.0.0.1/ works)")
        return
    out = subprocess.run(
            ["docker", "compose", "-f", "split-hosts/compose.yml", "exec",
             "-T", "caddy", "caddy", "certificate", "local", "ca"],
            capture_output=True, text=True, cwd=HERE)
    if "BEGIN CERTIFICATE" not in out.stdout:
        print("      ! could not extract caddy's local CA (is caddy up?)",
              file=sys.stderr)
        return
    cert = HERE / ".caddy_root.crt"
    cert.write_text(out.stdout)
    subprocess.run(
            ["security", "add-trusted-cert", "-r", "trustAsRoot",
             "-k", "/Library/Keychains/System.keychain", str(cert)],
            check=False)
    print(f"      trusted caddy local CA -> {cert}")


# --- compose wrappers -----------------------------------------------------
def compose(setup: str, *args: str) -> None:
    env = dict(os.environ, CADDY_TLS=CADDY_TLS_VALUE)
    cmd = ["docker", "compose", f"-f{setup}/compose.yml", *args]
    print("+ " + " ".join(shlex.quote(c) for c in cmd))
    rc = subprocess.run(cmd, cwd=HERE, env=env).returncode
    if rc != 0:
        sys.exit(rc)


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in SETUPS:
        print("usage: ./up.py <" + "|".join(SETUPS) +
                "> <build|up|down|logs|ps|rekey|trust-ca>", file=sys.stderr)
        sys.exit(2)
    setup = sys.argv[1]
    action = sys.argv[2] if len(sys.argv) > 2 else "up"
    setup_dir = HERE / setup
    if not setup_dir.is_dir():
        print(f"      no such example: {setup_dir}", file=sys.stderr)
        sys.exit(1)

    extra = sys.argv[3:]

    if action == "build":
        prepare_configs(setup_dir)
        compose(setup, "build")

    elif action == "up":
        print(f"==> {setup}: rendering config")
        prepare_configs(setup_dir)
        if setup == "split-hosts":
            print(f"==> mapping {', '.join(SPLIT_HOSTS)} -> 127.0.0.1")
            update_hosts(add=True)
        compose(setup, "up", "-d", *extra)
        target = ("https://app.example.com/app"
                    if setup == "split-hosts" else "https://localhost/app")
        print(f"==> {setup} is detached. Open {target}")
        if setup == "split-hosts":
            print("      macOS: run './up.py split-hosts trust-ca' first.")
            print("      Linux: https://127.0.0.1/app works; cert warns once.")

    elif action == "down":
        compose(setup, "down", "-v")
        if setup == "split-hosts":
            print(f"==> unmapping {', '.join(SPLIT_HOSTS)}")
            update_hosts(add=False)

    elif action == "trust-ca":
        if setup == "split-hosts":
            trust_caddy_root()
        else:
            print("      single-host is https://localhost -- trusted by default "
                    "on macOS; no CA step.")

    elif action == "rekey":
        # Rotate the at-rest key without disturbing the rest of the file.
        _render(setup_dir / "base.example.toml",
                     setup_dir / "base.toml", True)
        print("==> rotated encryption_key; restart the auth service to apply.")

    elif action in ("logs", "ps"):
        compose(setup, action, *extra)

    else:
        print(f"      unknown action: {action}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
