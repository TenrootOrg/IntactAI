#!/usr/bin/env python3
"""Live dashboard checks — real backend API calls against the live stack.

Covers modules/backend/routes/dashboard_routes.py: pure reads, all SAFE.
GET /api/dashboard/automations (the workflow list) and, if any run exists,
GET /api/dashboard/automation/<id> and GET /api/dashboard/automation/<id>/logs
against a real run_id pulled straight out of the list response — never a
fabricated id. The /api/dashboard/automation/<id>/stop endpoint is exercised
naturally elsewhere (any test file that creates+stops a real run); this file
only adds a light-touch negative-path check: stopping a run_id that doesn't
exist returns a sensible 404, not a 500 or a false "stopped".

NOT part of run_all.py's sweep, and not meant to run on every change — invoke
it by name, manually, only when asked:

    docker exec intact_backend python3 /app/workdir/tests/live/test_dashboard.py
"""
import sys

from _lib import SAFE, _get, _post


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_automations_list():
    r = _get("/api/dashboard/automations")
    if r.status_code != 200:
        return False, f"GET /api/dashboard/automations -> {r.status_code}: {r.text[:300]}"
    body = r.json()
    runs = body.get("runs")
    if not isinstance(runs, list):
        return False, f"'runs' missing or not a list: {str(body)[:300]}"
    if body.get("total") != len(runs):
        return False, f"total ({body.get('total')}) != len(runs) ({len(runs)})"
    return True, f"{len(runs)} run(s) visible"


def check_automation_detail_and_logs():
    r = _get("/api/dashboard/automations")
    if r.status_code != 200:
        return False, f"GET /api/dashboard/automations -> {r.status_code}: {r.text[:300]}"
    runs = r.json().get("runs", [])
    if not runs:
        return True, "no runs exist yet — nothing to check detail/logs against (not a failure)"

    run_id = runs[0]["id"]

    d = _get(f"/api/dashboard/automation/{run_id}")
    if d.status_code != 200:
        return False, f"GET /api/dashboard/automation/{run_id} -> {d.status_code}: {d.text[:300]}"
    detail = d.json()
    if detail.get("id") != run_id:
        return False, f"detail id mismatch: expected {run_id}, got {detail.get('id')}"

    lg = _get(f"/api/dashboard/automation/{run_id}/logs")
    if lg.status_code != 200:
        return False, f"GET /api/dashboard/automation/{run_id}/logs -> {lg.status_code}: {lg.text[:300]}"
    logs_body = lg.json()
    if "logs" not in logs_body or not isinstance(logs_body["logs"], list):
        return False, f"'logs' missing or not a list: {str(logs_body)[:300]}"

    return True, f"run_id={run_id} status={detail.get('status')} logs={len(logs_body['logs'])} entries"


def check_stop_nonexistent_run_404():
    r = _post("/api/dashboard/automation/_livetest_nonexistent_run_id_xyz/stop")
    if r.status_code != 404:
        return False, f"expected 404 stopping a nonexistent run, got {r.status_code}: {r.text[:300]}"
    return True, f"nonexistent run_id correctly 404s: {r.text[:200]}"


CHECKS = [
    ("dashboard_automations_list", SAFE, check_automations_list),
    ("dashboard_automation_detail_and_logs", SAFE, check_automation_detail_and_logs),
    ("dashboard_stop_nonexistent_run_404", SAFE, check_stop_nonexistent_run_404),
]


def main():
    passed = failed = skipped = 0
    for name, risk, fn in CHECKS:
        print(f"\n--- {name} ---", flush=True)
        try:
            if risk.startswith("REQUIRES_MODULE:"):
                from _lib import require_module
                require_module(risk.split(":", 1)[1])
            ok, detail = fn()
        except Exception as e:
            from _lib import Skip
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
