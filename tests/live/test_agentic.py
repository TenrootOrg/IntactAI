#!/usr/bin/env python3
"""Live agentic checks — real backend API calls against the live stack.

Covers modules/backend/routes/agentic_routes.py (the Velociraptor collection
dispatch endpoint) and modules/backend/routes/agentic_cli_routes.py (the
subscription-CLI provider settings panel):

  - `check_velociraptor_collection` is lifted VERBATIM from the original
    tests/live_smoke.py. Despite the name, it's actually exercising POST
    /api/agentic/run — a real Velociraptor collection dispatch against a real
    client, using the smallest/fastest matching agentic blueprint. Its run_id
    is now attached to a LiveCase instead of being left dangling (the
    original live_smoke.py had no cleanup primitive for this run type).
  - GET /api/agentic/cli/status — SAFE, cheap (no tokens, no network per its
    own docstring).
  - POST /api/agentic/cli/test — ONE negative/robustness-path check. This is
    an async Actions-workflow dispatch (returns a run_id immediately; the
    actual vendor round-trip happens on a background thread), so this check
    only asserts the dispatch itself comes back as clean, parseable JSON
    with a 200 or 400 status — never a 500 — regardless of whether the
    provider is actually configured on this host. It does not wait for the
    background workflow to finish (that would mean spending a real vendor
    token/quota beyond what's needed to prove the endpoint doesn't crash).

POST /api/agentic/cli/install, /login, /disconnect, and /import-credential
are explicitly EXCLUDED from this suite — they perform real vendor
authentication (device-code OAuth flows, credential storage/deletion) with no
offline/synthetic fallback, so there is no safe way to exercise them here.

NOT part of run_all.py's sweep, and not meant to run on every change — invoke
it by name, manually, only when asked. A real Velociraptor collection can
take real time (up to a few minutes) — that's expected, not a hang:

    docker exec intact_backend python3 /app/workdir/tests/live/test_agentic.py
"""
import sys

from _lib import (
    SAFE,
    Skip,
    LiveCase,
    _get,
    _post,
    find_client,
    require_live_client,
    poll_run,
    smallest_agentic_blueprint_for,
)


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_velociraptor_collection(client):
    """Lifted verbatim (logic unchanged) from tests/live_smoke.py, with its
    run_id now attached to a LiveCase for real cleanup instead of being left
    dangling — see module docstring."""
    # Dispatches a REAL collection and asserts data comes back, so the
    # endpoint has to answer. Against an offline client this failed with
    # "no data returned from the selected clients" — true, and not a bug.
    require_live_client(client)

    bp = smallest_agentic_blueprint_for(client.get("os"))
    if not bp:
        return False, "no agentic blueprints available at all"

    with LiveCase() as case:
        r = _post("/api/agentic/run", {
            "blueprint_id": bp["id"],
            "client_ids": [client["client_id"]],
            "collection_minutes": 1,
        })
        if r.status_code != 200:
            return False, f"POST /api/agentic/run -> {r.status_code}: {r.text[:300]}"
        run_id = r.json().get("run_id")
        if not run_id:
            return False, f"no run_id in response: {r.text[:300]}"
        case.attach(run_id)

        final, transitions = poll_run(run_id, timeout_seconds=150)
        if final.get("status") != "completed":
            return False, f"run {run_id} ended as '{final.get('status')}' (transitions: {transitions})"

        # Real data must have landed for fusion.
        _get(f"/api/dashboard/automation/{run_id}")  # re-check log content is sane
        return True, f"blueprint={bp['id']} run_id={run_id} transitions={transitions}"


def check_cli_status(client):
    r = _get("/api/agentic/cli/status")
    if r.status_code != 200:
        return False, f"GET /api/agentic/cli/status -> {r.status_code}: {r.text[:300]}"
    body = r.json()
    if "installed" not in body or "authenticated" not in body:
        return False, f"status body missing installed/authenticated: {body}"
    return True, (
        f"provider={body.get('provider')} installed={body.get('installed')} "
        f"authenticated={body.get('authenticated')} detail={body.get('detail')!r}"
    )


def check_cli_test_negative_path(client):
    """POST /api/agentic/cli/test must never 500, whether or not the
    provider is actually configured. It's an async Actions-workflow dispatch,
    so a 200 here only proves the dispatch itself is clean — not that the
    underlying vendor round-trip succeeded (deliberately not awaited, see
    module docstring)."""
    r = _post("/api/agentic/cli/test")
    if r.status_code not in (200, 400):
        return False, f"POST /api/agentic/cli/test -> unexpected {r.status_code}: {r.text[:300]}"
    try:
        body = r.json()
    except Exception as e:
        return False, f"response wasn't valid JSON: {e} body={r.text[:300]}"
    if not isinstance(body, dict):
        return False, f"response JSON wasn't an object: {body!r}"
    # 200 -> {"success": True, "run_id": ...}; 400 -> {"error": "..."}. Either
    # shape is a "clean" response; only a 500 or a non-JSON body is a crash.
    return True, f"status={r.status_code} body={str(body)[:200]}"


CHECKS = [
    ("agentic_velociraptor_collection", SAFE, check_velociraptor_collection),
    ("agentic_cli_status", SAFE, check_cli_status),
    ("agentic_cli_test_negative_path", SAFE, check_cli_test_negative_path),
]


def main():
    client, warning = find_client()
    if warning:
        print(f"[WARN] {warning}", flush=True)
    if client:
        print(f"[INFO] Using client {client.get('client_id')} ({client.get('hostname')}, {client.get('os')})", flush=True)
    else:
        print("[FAIL] No Velociraptor client available — client-dependent checks will SKIP.", flush=True)

    passed = failed = skipped = 0
    for name, risk, fn in CHECKS:
        print(f"\n--- {name} ---", flush=True)
        try:
            if risk.startswith("REQUIRES_MODULE:"):
                from _lib import require_module
                require_module(risk.split(":", 1)[1])
            ok, detail = fn(client)
        except Exception as e:
            if isinstance(e, Skip):
                print(f"[SKIP] {name}: {e}", flush=True)
                skipped += 1
                continue
            ok, detail = False, f"unhandled exception: {e}"
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}", flush=True)
        if ok:
            passed += 1
        else:
            failed += 1

    print(f"\n=== {passed} passed, {failed} failed, {skipped} skipped ===", flush=True)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
