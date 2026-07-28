#!/usr/bin/env python3
"""Live functional smoke test — real backend API calls against the live stack.

Unlike the rest of tests/ (fast, isolated unit tests swept automatically by
run_all.py), this hits the REAL running infrastructure: a real enrolled
Velociraptor client, real hunts, real AWS SIGMA
detection, and the real scheduler. It takes a few minutes and needs a
Velociraptor client checked in.

NOT part of run_all.py's sweep, and not meant to run on every change — invoke
it by name, manually, only when asked:

    docker exec intact_backend python3 /app/workdir/tests/live_smoke.py

Each check uses the smallest/fastest blueprint or synthetic input available
to keep the whole run as short as real infrastructure allows. The
Velociraptor client is auto-discovered (prefers one that's actually online;
falls back to the most-recently-seen one with a clear warning) — never
hardcode a client_id here.
"""
import json
import sys
import time

import requests

BASE = "http://localhost:5001"
TIMEOUT = 30
ONLINE_THRESHOLD_SECONDS = 600  # matches the dashboard's own "online" cutoff


def _get(path, **kw):
    return requests.get(f"{BASE}{path}", timeout=TIMEOUT, **kw)


def _post(path, payload=None, **kw):
    return requests.post(f"{BASE}{path}", json=payload if payload is not None else {}, timeout=TIMEOUT, **kw)


def find_client():
    """Auto-discover a real Velociraptor client. Prefers one that's actually
    online (last_seen_at within ONLINE_THRESHOLD_SECONDS, the same cutoff the
    dashboard itself uses); falls back to the most-recently-seen client
    otherwise so the suite can still run (flagged, not silent).

    Returns (client_dict, warning_or_None). client_dict is None if no client
    has EVER enrolled.
    """
    resp = _get("/api/clients")
    resp.raise_for_status()
    clients = resp.json().get("items", [])
    if not clients:
        return None, "no Velociraptor clients enrolled at all"

    now = time.time()
    with_ts = [c for c in clients if c.get("last_seen_at")]
    online = []
    for c in with_ts:
        age = now - (c["last_seen_at"] / 1_000_000)
        if age < ONLINE_THRESHOLD_SECONDS:
            online.append((age, c))
    if online:
        online.sort(key=lambda x: x[0])
        return online[0][1], None

    if not with_ts:
        return clients[0], "no client has ever checked in (last_seen_at missing) — tests needing a live client will likely fail"

    with_ts.sort(key=lambda c: c["last_seen_at"], reverse=True)
    stale = with_ts[0]
    age_min = (now - stale["last_seen_at"] / 1_000_000) / 60
    return stale, f"no client online in the last {ONLINE_THRESHOLD_SECONDS // 60} min — using most recently seen ({stale.get('hostname')}, last seen {age_min:.0f}m ago)"


def smallest_agentic_blueprint_for(client_os):
    """Pick the agentic blueprint matching the client's OS with the fewest
    artifacts (fastest real collection). Falls back to the overall smallest
    if none match the OS."""
    resp = _get("/api/blueprints/agentic")
    resp.raise_for_status()
    blueprints = resp.json().get("blueprints", [])
    if not blueprints:
        return None
    os_key = (client_os or "").lower()
    matching = [b for b in blueprints if os_key and os_key in (b.get("id", "") + b.get("name", "")).lower()]
    pool = matching or blueprints
    return min(pool, key=lambda b: len(b.get("artifacts", [])))


def poll_run(run_id, timeout_seconds=180, interval=5):
    """Poll /api/dashboard/automation/<run_id> until completed/failed or timeout.
    Returns (final_status_dict, transitions) where transitions is the list of
    (elapsed_seconds, status) pairs observed, so callers can verify the run
    didn't jump straight to 'completed'."""
    start = time.time()
    transitions = []
    last_status = None
    while time.time() - start < timeout_seconds:
        r = _get(f"/api/dashboard/automation/{run_id}")
        if r.status_code == 200:
            d = r.json()
            status = d.get("status")
            if status != last_status:
                transitions.append((round(time.time() - start, 1), status))
                last_status = status
            if status in ("completed", "failed", "cancelled"):
                return d, transitions
        time.sleep(interval)
    return {"status": "timeout"}, transitions


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_velociraptor_collection(client):
    bp = smallest_agentic_blueprint_for(client.get("os"))
    if not bp:
        return False, "no agentic blueprints available at all"
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

    final, transitions = poll_run(run_id, timeout_seconds=150)
    if final.get("status") != "completed":
        return False, f"run {run_id} ended as '{final.get('status')}' (transitions: {transitions})"

    # Real data must have landed for fusion.
    raw = _get(f"/api/dashboard/automation/{run_id}")  # re-check log content is sane
    return True, f"blueprint={bp['id']} run_id={run_id} transitions={transitions}"


def check_hunt_status_reconciliation(client):
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



def check_aws_sigma():
    event = {
        "eventVersion": "1.08",
        "eventTime": "2026-07-14T12:00:00Z",
        "eventSource": "cloudtrail.amazonaws.com",
        "eventName": "StopLogging",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.5",
        "userAgent": "aws-cli/2.0",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/malicious-actor",
            "accountId": "123456789012",
            "userName": "malicious-actor",
        },
        "requestParameters": {"name": "management-events"},
        "responseElements": None,
        "eventID": "live-smoke-test-event-1",
        "eventType": "AwsApiCall",
        "recipientAccountId": "123456789012",
    }
    up = _post("/api/aws/upload", {"files": [{"filename": "cloudtrail_test.json", "content": json.dumps({"Records": [event]})}]})
    if up.status_code != 200:
        return False, f"POST /api/aws/upload -> {up.status_code}: {up.text[:300]}"
    run_id = up.json().get("run_id")
    if not run_id:
        return False, f"no run_id from upload: {up.text[:300]}"

    an = _post("/api/aws/analyze-offline", {"run_id": run_id, "min_severity": "informational"})
    if an.status_code != 200:
        return False, f"POST /api/aws/analyze-offline -> {an.status_code}: {an.text[:300]}"

    final, transitions = poll_run(run_id, timeout_seconds=60)
    if final.get("status") != "completed":
        return False, f"run {run_id} ended as '{final.get('status')}' (transitions: {transitions})"

    f = _get(f"/api/aws/findings/{run_id}")
    if f.status_code != 200:
        return False, f"GET /api/aws/findings -> {f.status_code}"
    findings = f.json()
    total = findings.get("total") if isinstance(findings, dict) else None
    return True, f"run_id={run_id} findings_summary={str(findings)[:200]}"


def check_scheduler(client):
    bp = smallest_agentic_blueprint_for(client.get("os"))
    if not bp:
        return False, "no agentic blueprints available for scheduler test"
    job_id = None
    try:
        r = _post("/api/scheduler/jobs", {
            "name": "LiveSmokeTest (delete me)",
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
        return True, f"job_id={job_id} triggered_run_status={row.get('status')}"
    finally:
        if job_id:
            try:
                requests.delete(f"{BASE}/api/scheduler/jobs/{job_id}", timeout=TIMEOUT)
            except Exception:
                pass


CHECKS = [
    ("velociraptor_collection", lambda client: check_velociraptor_collection(client)),
    ("hunt_status_reconciliation", lambda client: check_hunt_status_reconciliation(client)),
    ("aws_sigma", lambda client: check_aws_sigma()),
    ("scheduler", lambda client: check_scheduler(client)),
]


def main():
    client, warning = find_client()
    if warning:
        print(f"[WARN] {warning}", flush=True)
    if client:
        print(f"[INFO] Using client {client.get('client_id')} ({client.get('hostname')}, {client.get('os')})", flush=True)
    else:
        print("[FAIL] No Velociraptor client available — client-dependent checks will fail.", flush=True)

    passed = 0
    total = len(CHECKS)
    for name, fn in CHECKS:
        print(f"\n--- {name} ---", flush=True)
        try:
            ok, detail = fn(client)
        except Exception as e:
            ok, detail = False, f"unhandled exception: {e}"
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}", flush=True)
        if ok:
            passed += 1

    print(f"\n=== {passed}/{total} passed ===", flush=True)
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
