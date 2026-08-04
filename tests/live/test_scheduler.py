#!/usr/bin/env python3
"""Live scheduler checks — real backend API calls against the live stack.

Covers modules/backend/routes/scheduler_routes.py end to end against a real
scheduled job backed by a real (fastest available) agentic blueprint and a
real enrolled Velociraptor client: create -> PUT (edit interval_value,
verify it persists via a follow-up GET) -> POST toggle -> POST run (manual
trigger) -> confirm a real workflow run actually got dispatched -> DELETE.

check_scheduler here is lifted from the original tests/live_smoke.py
(the "must actually dispatch a workflow run, not just accept the trigger
call" assertion is a genuinely valuable existing regression check) with its
job named via tagged("scheduler-job") instead of the old hardcoded
"LiveSmokeTest (delete me)", and the PUT/toggle checks inserted before the
existing trigger+delete steps.

NOT part of run_all.py's sweep, and not meant to run on every change — invoke
it by name, manually, only when asked:

    docker exec intact_backend python3 /app/workdir/tests/live/test_scheduler.py
"""
import sys
import time

from _lib import SAFE, Skip, _delete, _get, _post, _put, find_client, smallest_agentic_blueprint_for, tagged


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_scheduler(client):
    if not client:
        raise Skip("no Velociraptor client available for scheduler test")
    bp = smallest_agentic_blueprint_for(client.get("os"))
    if not bp:
        return False, "no agentic blueprints available for scheduler test"
    job_id = None
    try:
        r = _post("/api/scheduler/jobs", {
            "name": tagged("scheduler-job"),
            "blueprint_id": bp["id"],
            "blueprint_type": "agentic",
            "client_ids": [client["client_id"]],
            "interval_value": 1,
            "interval_unit": "days",
            "options": {"collection_minutes": 1},
        })
        if r.status_code != 201:
            return False, f"POST /api/scheduler/jobs -> {r.status_code}: {r.text[:300]}"
        job_id = r.json().get("id") or r.json().get("job_id")
        if not job_id:
            return False, f"no job id in response: {r.text[:300]}"

        # --- PUT: edit interval_value, verify it persists via a follow-up GET ---
        upd = _put(f"/api/scheduler/jobs/{job_id}", {"interval_value": 3})
        if upd.status_code != 200:
            return False, f"PUT /api/scheduler/jobs/{job_id} -> {upd.status_code}: {upd.text[:300]}"

        g = _get(f"/api/scheduler/jobs/{job_id}")
        if g.status_code != 200:
            return False, f"GET /api/scheduler/jobs/{job_id} after PUT -> {g.status_code}: {g.text[:300]}"
        persisted_interval = g.json().get("interval_value")
        if int(persisted_interval) != 3:
            return False, f"interval_value edit didn't persist: expected 3, got {persisted_interval!r}"

        # --- toggle: disable then confirm, so the check exercises a real transition ---
        tog = _post(f"/api/scheduler/jobs/{job_id}/toggle", {"enabled": False})
        if tog.status_code != 200:
            return False, f"POST /api/scheduler/jobs/{job_id}/toggle -> {tog.status_code}: {tog.text[:300]}"
        if tog.json().get("enabled") not in (False, 0):
            return False, f"toggle to disabled didn't take: {tog.text[:300]}"

        tog2 = _post(f"/api/scheduler/jobs/{job_id}/toggle", {"enabled": True})
        if tog2.status_code != 200:
            return False, f"POST /api/scheduler/jobs/{job_id}/toggle (re-enable) -> {tog2.status_code}: {tog2.text[:300]}"
        if tog2.json().get("enabled") not in (True, 1):
            return False, f"toggle back to enabled didn't take: {tog2.text[:300]}"

        # --- manual trigger + delete (original live_smoke.py logic) ---
        trig = _post(f"/api/scheduler/jobs/{job_id}/run")
        if trig.status_code != 200:
            return False, f"POST /api/scheduler/jobs/{job_id}/run -> {trig.status_code}: {trig.text[:300]}"

        # Give the background thread a moment, then confirm a real workflow
        # run was created and dispatched without a TypeError/argument crash.
        time.sleep(15)
        runs = _get("/api/dashboard/automations")
        recent = [x for x in runs.json().get("runs", []) if x.get("name", "").startswith("Scheduled:")]
        if not recent:
            return False, "no 'Scheduled: ...' workflow row appeared after manual trigger"
        row = recent[0]
        if row.get("status") == "failed" and "error" in str(row.get("error", "")).lower():
            return False, f"scheduled run failed: {row.get('error')}"
        return True, (
            f"job_id={job_id} interval_value edit persisted, toggle round-trip OK, "
            f"triggered_run_status={row.get('status')}"
        )
    finally:
        if job_id:
            try:
                _delete(f"/api/scheduler/jobs/{job_id}")
            except Exception:
                pass


CHECKS = [
    ("scheduler_crud_toggle_trigger", SAFE, check_scheduler),
]


def main():
    client, warning = find_client()
    if warning:
        print(f"[WARN] {warning}", flush=True)
    if client:
        print(f"[INFO] Using client {client.get('client_id')} ({client.get('hostname')}, {client.get('os')})", flush=True)
    else:
        print("[FAIL] No Velociraptor client available — client-dependent checks will fail.", flush=True)

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
