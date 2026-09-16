#!/usr/bin/env python3
"""up.py -- bring up / tear down a janux + Caddy forward-auth example.

Usage:
           ./up.py <single-host|split-hosts> <up|down|down --purge|trust-ca>
                   [--verbose|--debug|-x]

Each sub-directory (single-host/, split-hosts/) is a self-contained
`docker compose` project: caddy (public front) + janux (auth) + nginx
(the "simple service", a static site). This wrapper, per project:

 1. assumes the gitignored base.toml / seed.toml already exist -- they are
     created ONCE, out of band, from the committed *.example.toml templates
     via a manual `cp` (see the README). They hold local, often-secret
     values, so up.py NEVER renders or clobbers them; it only checks that
     they exist and points at the *.example.toml to copy when one is missing.
 2. maps the Caddyfront site hostnames (parsed out of the Caddyfile) into
      /etc/hosts and -- on macOS -- trusts caddy's local CA in the system
    keychain. TLS itself is configured in each Caddyfile via a per-site
      `tls internal` directive (this caddy build ignores the CADDY_TLS env
    var and rejects a `global { tls internal }` block, so no env plumbing
    is needed). On `down` the same hostnames are removed from /etc/hosts.

TLS is MANDATORY, not optional: janux's session cookie is `Secure` and
HOST-ONLY (no Domain attribute; src/verify.rs::set_session_cookie), so it
transmits ONLY over https. Caddy also auto-redirects http -> https on
localhost, which is itself a secure context. On Linux, open
https://127.0.0.1/ (its self-signed cert need not be trusted for the
browser to reach the server); on macOS trust caddy's CA once with
`./up.py <setup> trust-ca`.

By default every phase logs a timestamped INFO line to stderr so you can
follow what the script does; add --verbose / --debug / -x for DEBUG detail
(paths, the extracted hostnames, the exact /etc/hosts block written).

Both setups publish :80/:443, so run only ONE at a time. See README.md.
"""

from __future__ import annotations

import logging
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SETUPS = ("single-host", "split-hosts")
HOSTS_FILE = Path("/etc/hosts")

# One timestamped stream tells the operator, step by step, what up.py is doing.
# INFO  -> what each phase does (config, /etc/hosts, compose, CA trust).
# DEBUG -> extra detail (paths, extracted hosts, the exact /etc/hosts block),
#          enabled with --verbose / --debug / -x.
log = logging.getLogger("up.py")


def configure_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)-5s up.py: %(message)s",
        datefmt="%H:%M:%S",
     )


def _marker(setup: str) -> str:
     # /etc/hosts gets a per-setup block tagged with this marker so `down`
     # removes exactly the lines `up` added, even if several examples coexist.
    return f"janux-example-{setup}"


# --- config presence check ------------------------------------------------
# base.toml / seed.toml are gitignored and are created ONCE, out of band, from
# the committed *.example.toml templates (a manual `cp`, see the README). They
# carry local, often-secret values -- the process encryption key and the
# [seed.resend] creds -- so up.py MUST NOT render or clobber them: a copy step
# would wipe the real credentials on every `up`. We only assert that they exist
# and, when one is missing, point at the *.example.toml template to copy.
REQUIRED_CONFIGS = (
          ("base.example.toml", "base.toml"),
          ("seed.example.toml", "seed.toml"),
      )


def require_configs(setup_dir: Path) -> None:
    missing = [
             (example, target)
        for example, target in REQUIRED_CONFIGS
        if not (setup_dir / target).exists()
     ]
    if missing:
        log.error(
              "  missing required config: %s",
             ", ".join(target for _example, target in missing),
         )
        for example, target in missing:
            if (setup_dir / example).exists():
                log.info("    create it from the template:   cp %s %s", example, target)
            else:
                log.warning(
                     "    template %s is also missing; %s cannot be generated here",
                    example,
                    target,
                 )
        log.info(
             "  after copying, set a real encryption_key in base.toml "
             "(openssl rand -hex 32) and your [seed.resend] creds in seed.toml")
        raise SystemExit(1)
    log.info("  using existing base.toml / seed.toml (not clobbered; secrets preserved)")


# --- /etc/hosts mapping ---------------------------------------------------
# `up` maps the Caddyfront's site hostnames (parsed out of the Caddyfile) to
# 127.0.0.1 in /etc/hosts so the browser reaches caddy instead of the public
# Internet; `down` removes exactly those lines again. Loopback-ish names
# (localhost / 127.x / ::1) are left alone -- /etc/hosts already resolves them.
def _caddy_host(token: str) -> str:
     # Normalize a Caddy listen address to a bare hostname ('' if it has none).
    # Handles: `host`, `host:80`, `scheme://host:80`, `[::1]:80`, `*.host`.
    t = token.strip()
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://(.+)$", t)     # scheme://...
    if m:
        t = m.group(1)
    t = t.strip("[]")            # [::1]:80 -> ::1:80
    t = re.sub(r":\d+$", "", t)    # host:80 -> host
    t = t.strip()
    if t in ("", "*", "_"):     # bare port / wildcard / MX-like: no hostname
        return ""
    return t


def _is_loopback(host: str) -> bool:
    return (
        host == "localhost"
        or host.endswith(".localhost")
        or host == "::1"
        or host.startswith("127.")
     )


def extract_caddy_hosts(caddyfile: Path) -> list[str]:
     # Site hostnames a Caddyfile binds to, minus loopback names.
    #
    # A site address is the identifier(s) at the top level that precede a block
    # `{`. We walk the file tracking brace depth: at depth 0 the only `{`-
    # opening line is a site header, so the tokens before that `{` are the
    # listen addresses (one or more, comma/space separated, possibly scheme-
    # prefixed). Loopback-ish names are dropped because /etc/hosts already
    # resolves them, leaving the real domains the front must map.
    text = caddyfile.read_text() if caddyfile.exists() else ""
    hosts: list[str] = []
    depth = 0
    for raw in text.splitlines():
        code = raw.split("#", 1)[0]      # Caddy treats # as end-of-line comment
        if not code.strip():
            continue
        if depth == 0 and "{" in code:
            for tok in re.split(r"[, ]+", code.split("{", 1)[0]):
                host = _caddy_host(tok)
                if host and not _is_loopback(host):
                    hosts.append(host)
        depth = max(0, depth + code.count("{") - code.count("}"))
     # de-dup, keep first-seen order
    seen: set[str] = set()
    out = [h for h in hosts if not (h in seen or seen.add(h))]
    log.debug("> caddy sites (%s): %s", caddyfile.name, ", ".join(out) or "<none>")
    return out


def _hosts_block(marker: str, add: bool, hosts: list[str]) -> str:
    lines = [f"# {marker}"]
    if add:
        lines += [f"127.0.0.1 {h}" for h in hosts]
    lines.append(f"# {marker}_END")
    return "\n".join(lines) + "\n"


def update_hosts(setup: str, add: bool, hosts: list[str]) -> None:
    if not HOSTS_FILE.exists():
        log.debug("/%s does not exist; skipping /etc/hosts", HOSTS_FILE)
        return
    if not hosts:
        log.debug("no hostnames to %s in /etc/hosts", "map" if add else "unmap")
        return
    content = HOSTS_FILE.read_text()
    marker = _marker(setup)
    pat = re.compile(
        r"#\s*" + re.escape(marker) + r"\b.*?#\s*" + re.escape(marker) + r"_END\n?",
        re.DOTALL,
     )
    new = pat.sub(_hosts_block(marker, add, hosts), content, count=1)
    if new == content:
        new = content.rstrip() + "\n\n" + _hosts_block(marker, add, hosts)
    action = "added " if add else "removed"
    try:
        HOSTS_FILE.write_text(new)
    except PermissionError:
        # Rewriting /etc/hosts needs root. Rather than bailing out, re-run just
        # this one step via sudo so the operator supplies their password and the
        # setup continues. `sudo tee` writes the computed block while preserving
        # the file's existing ownership and 0644 mode (it truncates the existing
        # file in place instead of recreating it); `sudo` prompts for the
        # password on the TTY when credentials are required.
        log.info("    /etc/hosts needs root; re-running this step via sudo "
                     "(you'll be prompted for your password)")
        proc = subprocess.run(
                     ["sudo", "tee", str(HOSTS_FILE)],
                     input=new, text=True, check=False,
                     )
        if proc.returncode != 0:
            log.warning("    sudo write to %s failed (rc=%s); skipping /etc/hosts",
                         HOSTS_FILE, proc.returncode)
            return
    log.info("  /etc/hosts: %s %s", action, ", ".join(hosts))
    log.debug("  /etc/hosts block for %s:\n%s", marker,
              _hosts_block(marker, add, hosts).rstrip())


# --- macOS CA trust -------------------------------------------------------
def trust_caddy_root(setup: str) -> None:
     # Best-effort macOS: extract THIS setup's caddy local root CA and trust it.
    #
    # The CA lives in caddy's persisted data volume at
    # /data/caddy/pki/authorities/local/root.crt. We read it straight out of
    # the running container because caddy v2.x dropped the old `caddy
    # certificate local ca` CLI subcommand that used to print it.
    if sys.platform != "darwin":
        log.info("(CA trust is a no-op off macOS -- https://127.0.0.1/ works)")
        return
    out = subprocess.run(
         [
             "docker", "compose", "-f", f"{setup}/compose.yml",
             "exec", "-T", "caddy", "cat",
             "/data/caddy/pki/authorities/local/root.crt",
         ],
        capture_output=True, text=True, cwd=HERE,
      )
    if "BEGIN CERTIFICATE" not in out.stdout:
        log.warning("  could not extract caddy's local CA (is caddy up?)")
        return
    cert = HERE / f".{setup}-caddy-root.crt"
    cert.write_text(out.stdout)
    log.debug("  wrote caddy root CA -> %s", cert)
     # System keychain trust is machine-wide and is what browsers/CLI clients
     # actually consult, so it needs root (`sudo security`). Fall back to the
     # user's login keychain when that call fails for any reason.
    rc = subprocess.run(
         [
             "sudo", "security", "add-trusted-cert", "-r", "trustAsRoot", "-k",
             "/Library/Keychains/System.keychain", str(cert),
         ],
        check=False,
     ).returncode
    if rc != 0:
        log.warning("  system keychain trust failed (rc=%s); using login keychain",
                    rc)
        subprocess.run(
             [
                 "security", "add-trusted-cert", "-k",
                os.path.expanduser("~/Library/Keychains/login.keychain"),
                str(cert),
             ],
            check=False,
         )
    log.info("  trusted caddy local CA -> %s", cert)


# --- compose wrappers -----------------------------------------------------
def compose(setup: str, *args: str) -> None:
    cmd = ["docker", "compose", f"-f{setup}/compose.yml", *args]
    log.info("+ %s", " ".join(shlex.quote(x) for x in cmd))
    rc = subprocess.run(cmd, cwd=HERE).returncode
    if rc != 0:
        log.error("  compose %s failed (rc=%s)", " ".join(args), rc)
        sys.exit(rc)


def main() -> None:
    argv = sys.argv[1:]
    verbose = any(a in argv for a in ("--verbose", "--debug", "-x"))
    if len(argv) < 1 or argv[0] not in SETUPS:
        print(
             "usage: ./up.py <"
             + "|".join(SETUPS)
             + "> <up|down|down --purge|trust-ca> [--verbose|--debug|-x]",
            file=sys.stderr,
         )
        sys.exit(2)
    setup = argv[0]
    action = argv[1] if len(argv) > 1 else "up"
     # `down --purge` (or -v/-p) also wipes the named volumes.
    purge = (action == "purge") or any(f in argv[2:] for f in ("--purge", "-v", "-p"))
    configure_logging(verbose)
    setup_dir = HERE / setup
    log.info("== %s: action=%s (purge=%s)", setup, action, purge)
    if not setup_dir.is_dir():
        log.error("no such example: %s", setup_dir)
        sys.exit(1)

    if action == "up":
        log.info("== %s: checking config", setup)
        require_configs(setup_dir)
        hosts = extract_caddy_hosts(setup_dir / "Caddyfile")
        if hosts:
            log.info("== mapping %s -> 127.0.0.1", ", ".join(hosts))
            update_hosts(setup, add=True, hosts=hosts)
        else:
            log.info("== no hostnames to map (nothing added to /etc/hosts)")
        compose(setup, "up", "-d")
        target = (
             "https://app.example.com/app"
            if setup == "split-hosts"
            else "https://localhost/app"
         )
        log.info("== %s is detached. Open %s", setup, target)
        if sys.platform == "darwin":
            log.warning(
                 "macOS: run './up.py %s trust-ca' once so the browser trusts "
                 "caddy's local CA (self-signed); otherwise click the warning.",
                 setup)
        else:
            log.info("Linux: https://127.0.0.1/app works; cert warns once.")

     # `down` keeps the named volumes (incl. caddy's PKI, so a previously
     # trusted CA stays valid). `purge` / `down --purge` also wipe volumes,
     # regenerating caddy's local CA on the next `up` -- so re-run `trust-ca`
     # afterwards, or the browser keeps rejecting the stale root.
    elif action in ("down", "purge"):
        if purge:
            log.info("== stopping %s and PURGING named volumes", setup)
            compose(setup, "down", "-v")
            log.info("  purged named volumes for %s "
                      "(CA regenerates on `up`; re-run `trust-ca`)", setup)
        else:
            log.info("== stopping %s (keeping named volumes)", setup)
            compose(setup, "down")
        hosts = extract_caddy_hosts(setup_dir / "Caddyfile")
        if hosts:
            log.info("== unmapping %s from /etc/hosts", ", ".join(hosts))
            update_hosts(setup, add=False, hosts=hosts)
        else:
            log.info("== nothing to unmap from /etc/hosts")

    elif action == "trust-ca":
        log.info("== trusting caddy local CA for %s", setup)
        trust_caddy_root(setup)

    else:
        log.error("unknown action: %s", action)
        sys.exit(2)


if __name__ == "__main__":
    main()
