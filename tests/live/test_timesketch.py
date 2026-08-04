#!/usr/bin/env python3
"""Live Timesketch checks — real backend API calls against the live stack.

Covers modules/backend/routes/timesketch_routes.py and
timesketch_llm_routes.py.

  - timesketch_status    — GET /api/timesketch/status, SAFE read.
  - timesketch_sketches  — GET /api/timesketch/sketches, SAFE read (shells
    out to the timesketch_api_client CLI internally; a real Timesketch API
    round-trip, not a mock).
  - timesketch_llm_config — GET /api/timesketch/config/llm, SAFE read ONLY.
    The PUT variant (which rewrites timesketch.conf and restarts 3
    containers) is never called anywhere in this file — config mutation is
    EXCLUDED per the plan.
  - timesketch_start_multi — a REAL POST /api/timesketch/start-multi against
    a live Velociraptor client: KAPE collection (kape_target='RegistryHives'
    — per timesketch_routes.py's own comment this wraps in 1-5 min, vs.
    15+ min for the default '_KapeTriage', so it's the fastest real KAPE
    scope available) -> Plaso processing -> Timesketch import, polled via
    the shared /api/dashboard/automation/<id> endpoint (start-multi has no
    dedicated status route of its own — the orchestrator writes straight to
    the workflow row) to a terminal state.

    `plaso` is enabled on this host right now, so this run is expected to
    genuinely complete rather than degrade. The check still looks at
    modules_enabled()['plaso'] first and downgrades a 'failed' terminal
    result to a documented Skip (not a Fail) when plaso is disabled, so this
    file stays correct if plaso is ever turned back off — a real signal
    today, a clean Skip if the module regresses to disabled later.

NOT part of run_all.py's sweep, and not meant to run on every change — invoke
it by name, manually, only when asked:

    docker exec intact_backend python3 /app/workdir/tests/live/test_timesketch.py
"""
import sys

from _lib import REQUIRES_MODULE, SAFE, Skip, _get, _post, find_client, modules_enabled, poll_run, tagged


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_status(client):
    r = _get("/api/timesketch/status")
    if r.status_code != 200:
        return False, f"GET /api/timesketch/status -> {r.status_code}: {r.text[:300]}"
    body = r.json()
    if "jobs" not in body or not isinstance(body["jobs"], list):
        return False, f"'jobs' missing or not a list: {str(body)[:300]}"
    return True, f"{len(body['jobs'])} job(s) visible"


def check_sketches(client):
    r = _get("/api/timesketch/sketches")
    if r.status_code != 200:
        return False, f"GET /api/timesketch/sketches -> {r.status_code}: {r.text[:300]}"
    body = r.json()
    if "sketches" not in body or not isinstance(body["sketches"], list):
        return False, f"'sketches' missing or not a list: {str(body)[:300]}"
    if body.get("error"):
        # Route degrades to {"sketches": [], "error": ...} on a CLI/API
        # failure rather than a 500 — surface it, but a real Timesketch API
        # error here is a genuine finding, not something to silently pass.
        return False, f"sketches call reported an error: {body['error']}"
    return True, f"{len(body['sketches'])} sketch(es) visible"


def check_llm_config(client):
    r = _get("/api/timesketch/config/llm")
    if r.status_code != 200:
        return False, f"GET /api/timesketch/config/llm -> {r.status_code}: {r.text[:300]}"
    body = r.json()
    for key in ("google_ai_key", "google_ai_model", "ollama_url", "ollama_model"):
        if key not in body:
            return False, f"expected {key!r} in response: {str(body)[:300]}"
    # If a real key is configured it must be masked (route masks it —
    # previously returned the full plaintext key to any caller).
    key = body.get("google_ai_key") or ""
    if key and not key.startswith("••••"):
        return False, f"google_ai_key does not look masked: {key!r}"
    return True, f"google_ai_model={body.get('google_ai_model')!r}"


def check_start_multi(client):
    if not client:
        raise Skip("no Velociraptor client available for start-multi")

    r = _post("/api/timesketch/start-multi", {
        "clients": [{"client_id": client["client_id"], "client_name": client.get("hostname") or client["client_id"]}],
        # Fastest real KAPE scope available (per timesketch_routes.py's own
        # comment: RegistryHives wraps in 1-5 min vs. 15+ for _KapeTriage).
        "kape_target": "RegistryHives",
        "timeout_seconds": 1800,
        "monitor_timeout": 1800,
        "sketch_name": tagged("ts-sketch"),
    })
    if r.status_code != 200:
        return False, f"POST /api/timesketch/start-multi -> {r.status_code}: {r.text[:300]}"
    body = r.json()
    run_id = body.get("run_id")
    if not run_id:
        return False, f"no run_id in response: {r.text[:300]}"

    # KAPE (RegistryHives, ~1-5 min) + Plaso + Timesketch import (~3-10 min)
    # — give it real headroom rather than a tight timeout.
    final, transitions = poll_run(run_id, timeout_seconds=900, interval=15)
    status = final.get("status")

    if status != "completed" and not modules_enabled().get("plaso"):
        raise Skip(
            f"run {run_id} ended as '{status}' with plaso disabled — expected degraded "
            f"behavior, not a real signal (transitions: {transitions})"
        )

    if status != "completed":
        return False, f"run {run_id} ended as '{status}' (transitions: {transitions})"
    return True, f"run_id={run_id} transitions={transitions}"


CHECKS = [
    ("timesketch_status", REQUIRES_MODULE("timesketch"), check_status),
    ("timesketch_sketches", REQUIRES_MODULE("timesketch"), check_sketches),
    ("timesketch_llm_config", REQUIRES_MODULE("timesketch"), check_llm_config),
    ("timesketch_start_multi", REQUIRES_MODULE("timesketch"), check_start_multi),
]


def main():
    client, warning = find_client()
    if warning:
        print(f"[WARN] {warning}", flush=True)
    if client:
        print(f"[INFO] Using client {client.get('client_id')} ({client.get('hostname')}, {client.get('os')})", flush=True)
    else:
        print("[INFO] No Velociraptor client available — client-dependent checks will SKIP.", flush=True)

    passed = failed = skipped = 0
    for name, risk, fn in CHECKS:
        print(f"\n--- {name} ---", flush=True)
        try:
            if risk.startswith("REQUIRES_MODULE:"):
                from _lib import require_module
                require_module(risk.split(":", 1)[1])
            ok, detail = fn(client)
        except Skip as e:
            print(f"[SKIP] {name}: {e}", flush=True)
            skipped += 1
            continue
        except Exception as e:
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
