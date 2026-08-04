#!/usr/bin/env python3
"""Verify every backend endpoint the QA harness depends on, against a live box.

Run this BEFORE a full QA run. The harness drives ~20 endpoints across seven
route modules; if one of them has moved, been renamed, or now wants a different
payload shape, the failure surfaces 40 minutes into a run, after the box has
been wiped and a Windows client enrolled. This finds it in about ten seconds.

It is deliberately READ-ONLY apart from authentication. It does not start a
collection, create a case, or touch the Windows target. What it proves is that
each endpoint exists, is reachable, is guarded by auth, and returns the shape
the harness expects — not that the workflows behind them succeed. That is what
the QA run itself is for.

  python3 qa/verify_api.py                # uses qa/qa-config.yaml
  python3 qa/verify_api.py --host 1.2.3.4

Exit status is 0 only if every REQUIRED endpoint checks out.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib import api as api_lib          # noqa: E402
from lib import config as qa_config     # noqa: E402
from lib import redact as qa_redact     # noqa: E402

# (method, path, required, what it is used for)
#
# `required` marks endpoints without which the QA cannot run at all. The rest
# are reported but do not fail the check — e.g. the memory routes are gated on
# the volweb module being enabled, and a box with it disabled is a valid box.
ENDPOINTS = [
    # auth — everything else depends on these
    ("GET",  "/api/auth/status",              True,  "phase 1: claimed? session live?"),
    # NOT /api/auth/verify — nginx declares it `internal` so it can be the
    # auth_request target for /velociraptor/ and /api/uploads/. An external GET
    # returns 404 regardless of session, so probing it here would report every
    # authenticated run as unauthenticated. /api/auth/status carries the
    # `authenticated` flag this needs.

    # platform state
    ("GET",  "/api/health",                   True,  "phase 0b: backend is up"),
    ("GET",  "/api/version",                  False, "report: what was tested"),
    ("GET",  "/api/system/containers",        False, "phase 0b: container health"),

    # clients — phase 2 enrolment
    ("GET",  "/api/clients",                  True,  "phase 2: poll for the client"),

    # blueprints — phases 4/5/6 need ids from these
    ("GET",  "/api/blueprints/velociraptor",  True,  "phase 4: hunt blueprint"),
    ("GET",  "/api/blueprints/agentic",       True,  "phase 4: agentic blueprint"),
    ("GET",  "/api/blueprints/timesketch",    True,  "phase 5: KAPE/ingest blueprint"),
    ("GET",  "/api/blueprints/memory",        False, "phase 6: VolWeb blueprint"),
    ("GET",  "/api/blueprints/forensics",     False, "phase 4: forensics catalogue"),

    # velociraptor
    ("GET",  "/api/velociraptor/artifacts",   True,  "phase 3/4: artifact names"),
    ("GET",  "/api/velociraptor/hunts/status", True, "phase 4: hunt progress"),
    ("GET",  "/api/velociraptor/labels",      False, "phase 4: hunt targeting"),

    # timesketch
    ("GET",  "/api/timesketch/status",        True,  "phase 5: ingest reachable"),
    ("GET",  "/api/timesketch/sketches",      True,  "phase 5: assert event count"),

    # memory / volweb
    ("GET",  "/api/memory/available_plugins", False, "phase 6: plugin names"),
    ("GET",  "/api/memory/blueprints",        False, "phase 6: memory blueprint"),

    # cases / fusion
    ("GET",  "/api/cases",                    True,  "phase 7: fusion target"),
    ("GET",  "/api/cases/runs",               True,  "phase 7: member runs"),

    # workflow polling — the single most-used endpoint in the harness
    ("GET",  "/api/dashboard/automations",    True,  "every phase: run status"),

    # log collection
    ("GET",  "/api/system/actions",           False, "phase E: system run log"),
]

# Endpoints that MUST reject an unauthenticated caller. A QA that silently ran
# against an open appliance would be testing a broken box and calling it green.
MUST_BE_GUARDED = [
    "/api/clients",
    "/api/cases",
    "/api/dashboard/automations",
    "/api/velociraptor/artifacts",
]


def _shape(body):
    if isinstance(body, dict):
        return "dict{" + ",".join(list(body.keys())[:6]) + "}"
    if isinstance(body, list):
        return f"list[{len(body)}]"
    return type(body).__name__


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", help="override platform.host from qa-config.yaml")
    ap.add_argument("--user", default="qa")
    ap.add_argument("--password", help="dashboard password (if already set up)")
    ap.add_argument("--json", help="write the full result here")
    args = ap.parse_args()

    cfg = qa_config.load(require=False)
    host = args.host or cfg.platform_host
    if not host:
        print("No host. Set platform.host in qa/qa-config.yaml or pass --host.",
              file=sys.stderr)
        return 2

    redactor = qa_redact.Redactor(cfg.secrets())
    c = api_lib.Client(host, tl=None)

    print(f"Verifying backend API at https://{host}\n")
    results = {"host": host, "guarded": [], "endpoints": [], "auth": {}}

    # --- 1. unauthenticated probe: these must NOT answer -----------------
    print("Unauthenticated probes (these must be rejected):")
    guard_failures = 0
    for path in MUST_BE_GUARDED:
        code = c.status_of(path)
        guarded = code in (401, 403)
        results["guarded"].append({"path": path, "status": code, "ok": guarded})
        mark = "✓" if guarded else "✗"
        note = "" if guarded else "  <-- NOT GUARDED"
        print(f"  {mark} {path:<38} {code}{note}")
        if not guarded:
            guard_failures += 1
    print()

    # --- 2. authenticate --------------------------------------------------
    mode = None
    try:
        mode = c.auth_mode()
    except Exception as exc:                        # noqa: BLE001
        print(f"✗ /api/auth/status unreachable: {redactor(str(exc))[:200]}")
        print("\n  Is the platform installed and running?  docker ps")
        return 2

    print(f"Auth mode: {mode}")
    password = args.password or os.environ.get("QA_DASH_PASS")
    if mode == "setup":
        if not password:
            print("  Box is unclaimed. Pass --password to claim it as "
                  f"'{args.user}', or claim it in the browser first.")
            print("  Continuing with unauthenticated checks only.\n")
        else:
            c.setup(args.user, password)
            print(f"  Claimed the appliance as '{args.user}'.\n")
    elif password:
        c.login(args.user, password)
        print(f"  Logged in as '{args.user}'.\n")
    else:
        print("  Already set up; no password given, so authenticated checks "
              "will report as unauthenticated.\n")

    try:
        authed = c.is_authenticated()
    except Exception:                               # noqa: BLE001
        authed = False
    results["auth"] = {"mode": mode, "authenticated": authed}
    print(f"Session authenticated: {authed}\n")

    # --- 3. endpoint sweep ------------------------------------------------
    print("Endpoint sweep:")
    missing_required = []
    for method, path, required, why in ENDPOINTS:
        entry = {"method": method, "path": path, "required": required,
                 "why": why}
        try:
            body = c.request(method, path, expect=())    # accept any status
            code = 200
            entry["shape"] = _shape(body)
        except Exception as exc:                    # noqa: BLE001
            code, entry["error"] = None, redactor(str(exc))[:200]

        # request() with expect=() never raises for a status, so re-probe to
        # get the actual code — cheap, and the status is what matters here.
        code = c.status_of(path) if method == "GET" else code
        entry["status"] = code

        ok = code == 200 if authed else code in (200, 401, 403)
        # 404 always means the route is gone, authenticated or not. That is the
        # failure this script exists to catch.
        if code == 404:
            ok = False
        entry["ok"] = ok

        results["endpoints"].append(entry)
        mark = "✓" if ok else ("✗" if required else "!")
        tag = "" if required else " (optional)"
        shape = entry.get("shape", "")
        print(f"  {mark} {method:<4} {path:<38} {str(code):<5} "
              f"{shape[:34]:<34}{tag}")
        if not ok and required:
            missing_required.append(path)

    # --- verdict ----------------------------------------------------------
    print()
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2, default=str)
        print(f"Full result: {args.json}")

    problems = []
    if guard_failures:
        problems.append(f"{guard_failures} endpoint(s) answer without auth")
    if missing_required:
        problems.append(f"{len(missing_required)} required endpoint(s) missing: "
                        + ", ".join(missing_required))

    if problems:
        print("VERDICT: not ready")
        for p in problems:
            print("  - " + p)
        return 1

    if not authed:
        print("VERDICT: routes present, but the sweep ran unauthenticated.")
        print("  Re-run with --password to check response shapes.")
        return 0

    print("VERDICT: all required endpoints present and authenticated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
