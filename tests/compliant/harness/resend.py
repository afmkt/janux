from __future__ import annotations

import html
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            payload = {"raw": raw.decode("utf-8", "replace")}
        self.server.mock._record(self.path, payload)
        body = json.dumps({"id": "mock-email-id"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, fmt, *args):
        pass


class MockResend:
    """Local stand-in for the Resend API; janux's resend base_url points here."""

    def __init__(self, port: int):
        self._httpd = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
        self._httpd.mock = self
        self._lock = threading.Lock()
        self.requests: list[dict] = []
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, daemon=True, name="mock-resend"
        )
        self._thread.start()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._httpd.server_address[1]}"

    def _record(self, path: str, payload: dict):
        with self._lock:
            self.requests.append({"path": path, "payload": payload})

    def emails_to(self, to: str) -> list[dict]:
        with self._lock:
            out = []
            for rec in self.requests:
                p = rec["payload"]
                recipients = p.get("to") or []
                if isinstance(recipients, str):
                    recipients = [recipients]
                if to in recipients:
                    out.append(p)
            return out

    def wait_for_email(self, to: str, timeout: float = 15.0) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            mails = self.emails_to(to)
            if mails:
                return mails[-1]
            time.sleep(0.1)
        raise TimeoutError(f"no email captured for {to!r} within {timeout}s")

    def magic_link(self, to: str, timeout: float = 15.0) -> str:
        mail = self.wait_for_email(to, timeout)
        content = mail.get("html") or mail.get("text") or ""
        content = html.unescape(content)
        m = re.search(r'href="([^"]*token=[^"]*)"', content)
        if not m:
            m = re.search(r"(https?://[^\s\"'<>]*token=[^\s\"'<>]*)", content)
        if not m:
            raise ValueError(f"no magic link found in email to {to!r}: {content[:400]}")
        return m.group(1)

    def reset(self):
        with self._lock:
            self.requests.clear()

    def stop(self):
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)
