#!/usr/bin/env python3
"""Live Velociraptor checks — real backend API calls against the live stack,
real gRPC to the real Velociraptor server, and (where a client is actually
online) a real endpoint collection.

Covers modules/backend/routes/velociraptor_routes.py:
  - `check_hunt_status_reconciliation` is lifted VERBATIM from the original
    tests/live_smoke.py, including its "must observe 'running' before
    'completed'" regression check — a genuinely valuable existing assertion
    (a prior bug let the dashboard show a hunt as 'completed' before
    Velociraptor had actually reported every client's flow finished).
  - Three SAFE reads: GET /api/velociraptor/hunts/status, GET
    /api/velociraptor/labels, GET /api/velociraptor/artifacts.
  - A real TimeSketch/KAPE collection dispatch (POST
    /api/velociraptor/timesketch), gated behind the `timesketch` module
    ALSO being enabled (it isn't required for the rest of this file — the
    other checks only need `velociraptor`, which is always-on). Uses '_J'
    (just the $J/USN journal — the smallest KAPE target documented in
    services/kape_service.py's own docstring) instead of the '_KapeTriage'
    default, and a longer poll timeout than the bestpractice hunt since a
    real KAPE run is heavier (VSS enumeration + upload, not just a VQL
    query). The run is attached to a LiveCase so it's cleaned up on exit.

Every check in this file needs a real, enrolled Velociraptor client (or, for
the TimeSketch dispatch, at minimum attempts to reach one) — if
`_lib.find_client()` reports no client ever enrolled, client-dependent checks
SKIP cleanly rather than raising a raw AttributeError on `None`.

NOT part of run_all.py's sweep, and not meant to run on every change — invoke
it by name, manually, only when asked. Real hunts take real time (up to a few
minutes) — that's expected, not a hang:

    docker exec intact_backend python3 /app/workdir/tests/live/test_velociraptor_live.py
"""
import sys

from _lib import (
    REQUIRES_MODULE,
    SAFE,
    Skip,
    LiveCase,
    _get,
    _post,
    find_client,
    require_live_client,
    poll_run,
    require_module,
)


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_hunt_status_reconciliation(client):
    """Lifted verbatim from tests/live_smoke.py (same VQL, same regression
    check) — see module docstring."""
    # Needs the endpoint to ANSWER, not merely to have a record: this check
    # asserts the run passes through 'running', which an offline client can
    # never produce — the hunt completes instantly with nothing collected.
    require_live_client(client)

    r = _post("/api/velociraptor/bestpractice", {
        "artifacts": ["Windows.System.Pslist"] if client.get("os") == "windows" else ["Generic.Client.Info"],
        "blueprint_name": "LiveSmokeTest",
        "per_artifact": True,
        "client_id": client["client_id"],
    })
    if r.status_code != 200:
        return False, f"POST /api/velociraptor/bestpractice -> {r.status_code}: {r.text[:300]}"
    results = r.json().get("results", [])
    if not results or not results[0].get("run_id"):
        return False, f"no run_id in dispatch response: {r.text[:300]}"
    run_id = results[0]["run_id"]

    final, transitions = poll_run(run_id, timeout_seconds=120)
    statuses_seen = [s for _, s in transitions]
    if "running" not in statuses_seen:
        return False, f"never observed 'running' before completion (transitions: {transitions}) — the status-race regression may be back"
    if final.get("status") != "completed":
        return False, f"run {run_id} ended as '{final.get('status')}' (transitions: {transitions})"
    return True, f"run_id={run_id} transitions={transitions}"


def check_hunts_status(client):
    r = _get("/api/velociraptor/hunts/status")
    if r.status_code != 200:
        return False, f"GET /api/velociraptor/hunts/status -> {r.status_code}: {r.text[:300]}"
    hunts = r.json().get("hunts")
    if not isinstance(hunts, list):
        return False, f"'hunts' missing or not a list: {str(r.json())[:300]}"
    return True, f"{len(hunts)} recent hunt(s) visible"


def check_labels(client):
    r = _get("/api/velociraptor/labels")
    if r.status_code != 200:
        return False, f"GET /api/velociraptor/labels -> {r.status_code}: {r.text[:300]}"
    labels = r.json().get("labels")
    if not isinstance(labels, list):
        return False, f"'labels' missing or not a list: {str(r.json())[:300]}"
    return True, f"{len(labels)} distinct client label(s): {labels[:10]}"


def check_artifacts(client):
    r = _get("/api/velociraptor/artifacts")
    if r.status_code != 200:
        return False, f"GET /api/velociraptor/artifacts -> {r.status_code}: {r.text[:300]}"
    body = r.json()
    artifacts = body.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        return False, f"'artifacts' missing/empty: {str(body)[:300]}"
    if body.get("count") != len(artifacts):
        return False, f"count ({body.get('count')}) != len(artifacts) ({len(artifacts)})"
    return True, f"{len(artifacts)} artifact definitions available (cached={body.get('cached')})"


def check_timesketch_kape_collection(client):
    # Second, narrower gate ON TOP of this file's overall
    # REQUIRES_MODULE("velociraptor") risk tag — only dispatch a real KAPE
    # collection if TimeSketch is ALSO enabled (this endpoint's whole point
    # is feeding the TimeSketch import pipeline).
    require_module("timesketch")
    if client is None:
        raise Skip("no Velociraptor client enrolled at all")

    with LiveCase() as case:
        r = _post("/api/velociraptor/timesketch", {
            "client_id": client["client_id"],
            "client_name": client.get("hostname", "Unknown"),
            # '_J' (just the $J/USN journal) is the smallest KAPE target
            # documented in kape_service.py's own docstring — far cheaper
            # than the '_KapeTriage' default (full triage bundle).
            "kape_target": "_J",
            "timeout_seconds": 600,
            "cpu_limit": 80,
        })
        if r.status_code != 200:
            return False, f"POST /api/velociraptor/timesketch -> {r.status_code}: {r.text[:300]}"
        body = r.json()
        run_id = body.get("run_id")
        if not run_id:
            return False, f"no run_id in response: {body}"
        case.attach(run_id)

        # Heavier than the bestpractice hunt (real endpoint KAPE collection +
        # upload, not just a hunt dispatch), so give it more time.
        final, transitions = poll_run(run_id, timeout_seconds=420, interval=10)
        if final.get("status") != "completed":
            return False, f"run {run_id} ended as '{final.get('status')}' (transitions: {transitions})"
        return True, f"flow_id={body.get('flow_id')} run_id={run_id} transitions={transitions}"


CHECKS = [
    ("velociraptor_hunt_status_reconciliation", REQUIRES_MODULE("velociraptor"), check_hunt_status_reconciliation),
    ("velociraptor_hunts_status", SAFE, check_hunts_status),
    ("velociraptor_labels", SAFE, check_labels),
    ("velociraptor_artifacts", SAFE, check_artifacts),
    ("velociraptor_timesketch_kape_collection", REQUIRES_MODULE("velociraptor"), check_timesketch_kape_collection),
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
