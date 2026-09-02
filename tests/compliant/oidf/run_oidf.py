#!/usr/bin/env python3
"""Drive an OpenID Foundation conformance-suite instance against janux.

Mirrors the official `scripts/run-test-plan.py` workflow of the
conformance-suite (gitlab.com/openid/conformance-suite): create a test
plan over the REST API, start each test, poll for completion and export
results. OP tests that need a browser step (login at janux) pause and
print the URL to complete.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

import httpx

DEFAULT_SUITE = os.environ.get("OIDF_SUITE_URL", "https://www.certification.openid.net")
TERMINAL_STATES = {"FINISHED", "INTERRUPTED", "BROKEN"}


class Suite:
    def __init__(self, base_url: str, token: str | None, verify: bool = True):
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self.http = httpx.Client(
            base_url=base_url.rstrip("/"), headers=headers, verify=verify, timeout=30
        )

    def _check(self, r: httpx.Response) -> dict:
        if r.status_code >= 400:
            sys.exit(f"suite API error {r.status_code}: {r.text}")
        return r.json()

    def info(self) -> dict:
        return self._check(self.http.get("/api/info"))

    def create_plan(self, config: dict) -> dict:
        return self._check(self.http.post("/api/plan", json=config))

    def get_plan(self, plan_id: str) -> dict:
        return self._check(self.http.get("/api/plan", params={"plan": plan_id}))

    def start_test(self, plan_id: str, test_name: str) -> dict:
        return self._check(
            self.http.post("/api/test", params={"plan": plan_id, "test": test_name})
        )

    def get_result(self, plan_id: str, test_name: str) -> dict:
        return self._check(
            self.http.get("/api/result", params={"plan": plan_id, "test": test_name})
        )


def wait_for_result(
    suite: Suite, plan_id: str, test_name: str, timeout: float, poll: float
) -> dict:
    deadline = time.monotonic() + timeout
    hinted = False
    while time.monotonic() < deadline:
        res = suite.get_result(plan_id, test_name)
        status = res.get("status", "")
        if not hinted and res.get("url"):
            print(
                f"    browser step required — open:\n    {res['url']}\n"
                "    (complete the login/consent at janux, then wait here)"
            )
            hinted = True
        if status in TERMINAL_STATES:
            return res
        time.sleep(poll)
    sys.exit(f"timed out waiting for {test_name}")


def cmd_info(suite: Suite, args) -> None:
    print(json.dumps(suite.info(), indent=2))


def cmd_create(suite: Suite, args) -> None:
    config = json.loads(args.config.read_text())
    plan = suite.create_plan(config)
    plan_id = plan.get("_id") or plan.get("planId")
    print(f"created plan {plan_id}")
    if args.save:
        args.save.write_text(plan_id)
        print(f"plan id written to {args.save}")


def cmd_run(suite: Suite, args) -> None:
    plan = suite.get_plan(args.plan)
    tests = plan.get("tests", [])
    names = [t.get("testName") or t.get("name") for t in tests]
    names = [n for n in names if n]
    if args.test:
        names = [n for n in names if args.test in n]
    if not names:
        sys.exit(f"no tests found in plan {args.plan}")

    summary: list[dict] = []
    for name in names:
        print(f"▶ {name}")
        suite.start_test(args.plan, name)
        res = wait_for_result(suite, args.plan, name, args.timeout, args.poll)
        result = res.get("result", res.get("status", "UNKNOWN"))
        print(f"  → {result}")
        summary.append(
            {
                "test": name,
                "status": res.get("status"),
                "result": result,
                "log": res.get("_id"),
            }
        )

    print("\n── summary " + "─" * 40)
    for row in summary:
        print(f"{row['result']:<12} {row['test']}")
    if args.export:
        args.export.write_text(json.dumps(summary, indent=2))
        print(f"\nresults exported to {args.export}")
    failed = [r for r in summary if r["result"] in ("FAILED", "INTERRUPTED", "BROKEN")]
    if failed:
        sys.exit(1)


def cmd_results(suite: Suite, args) -> None:
    plan = suite.get_plan(args.plan)
    for t in plan.get("tests", []):
        name = t.get("testName") or t.get("name")
        res = suite.get_result(args.plan, name)
        print(f"{res.get('result', res.get('status', 'UNKNOWN')):<12} {name}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", default=DEFAULT_SUITE, help="conformance suite base URL")
    parser.add_argument(
        "--token",
        default=os.environ.get("OIDF_API_TOKEN"),
        help="API token from the suite web UI (or OIDF_API_TOKEN)",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="skip TLS verification (local docker suite uses a self-signed cert)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("info", help="print suite version info").set_defaults(fn=cmd_info)

    p = sub.add_parser("create", help="create a test plan from a JSON config")
    p.add_argument("config", type=argparse.FileType("r"), help="plan config JSON")
    p.add_argument("--save", type=argparse.FileType("w"), help="write the plan id here")
    p.set_defaults(fn=cmd_create)

    p = sub.add_parser("run", help="run all (or filtered) tests of a plan")
    p.add_argument("plan", help="plan id")
    p.add_argument("--test", help="substring filter on test names")
    p.add_argument("--timeout", type=float, default=600, help="per-test wait seconds")
    p.add_argument("--poll", type=float, default=3, help="poll interval seconds")
    p.add_argument("--export", type=argparse.FileType("w"), help="write JSON summary")
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("results", help="print current results of a plan")
    p.add_argument("plan", help="plan id")
    p.set_defaults(fn=cmd_results)

    args = parser.parse_args()
    suite = Suite(args.suite, args.token, verify=not args.insecure)
    args.fn(suite, args)


if __name__ == "__main__":
    main()
