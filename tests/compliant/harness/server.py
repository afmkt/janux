from __future__ import annotations

import subprocess
import time
from pathlib import Path

import httpx

from .config import ServerSpec

AUTH_DIR = Path(__file__).resolve().parents[3]
JANUX_BIN = AUTH_DIR / "target" / "debug" / "janux"


def ensure_binary(build: bool = True) -> Path:
    if JANUX_BIN.exists():
        return JANUX_BIN
    if not build:
        raise FileNotFoundError(f"{JANUX_BIN} missing; run `cargo build --bin janux` in {AUTH_DIR}")
    subprocess.run(
        ["cargo", "build", "--bin", "janux"],
        cwd=AUTH_DIR,
        check=True,
    )
    return JANUX_BIN


class JanuxServer:
    def __init__(self, spec: ServerSpec, log_dir: Path | None = None):
        self.spec = spec
        self._proc: subprocess.Popen | None = None
        self._log = (log_dir or spec.config_path.parent) / "janux-server.log"

    @property
    def base_url(self) -> str:
        return self.spec.base_url

    def start(self, healthy_timeout: float = 60.0):
        binary = ensure_binary()
        self._log.parent.mkdir(parents=True, exist_ok=True)
        out = open(self._log, "wb")
        self._proc = subprocess.Popen(
            [str(binary), "--config", str(self.spec.config_path)],
            cwd=AUTH_DIR,
            stdout=out,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
        )
        if not self.wait_healthy(healthy_timeout):
            tail = ""
            try:
                tail = self._log.read_text(errors="replace")[-3000:]
            except OSError:
                pass
            self.stop()
            raise RuntimeError(f"janux never became healthy; log tail:\n{tail}")
        return self

    def wait_healthy(self, timeout: float = 60.0) -> bool:
        url = f"{self.base_url}/api/v1/healthy"
        deadline = time.monotonic() + timeout
        with httpx.Client(timeout=2.0) as client:
            while time.monotonic() < deadline:
                if self._proc and self._proc.poll() is not None:
                    return False
                try:
                    if client.get(url).status_code == 200:
                        return True
                except httpx.HTTPError:
                    pass
                time.sleep(0.25)
        return False

    def stop(self):
        if self._proc:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=5)
            self._proc = None
