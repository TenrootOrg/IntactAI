#!/usr/bin/env python3
"""Live memory-forensics (VolWeb) checks — real backend API calls against the
live stack.

Covers modules/backend/routes/memory_routes.py. Memory forensics is gated
entirely on `config.yaml: modules.volweb.enabled` (see the route's own
_is_module_enabled() — the "Memory" feature is just an operator-facing
label for the VolWeb stack, there's no separate `memory` config key), so
every check here is REQUIRES_MODULE("volweb").

Checks:
  - memory_blueprint_crud     — full create/get/update/list/delete cycle
    against /api/memory/blueprints (SAFE — cleans up after itself). Note
    this is a DIFFERENT URL surface than /api/blueprints/memory (covered by
    test_blueprints_crud.py) even though both write to the same underlying
    'memory' blueprint table (services/storage/blueprint_store.py) — worth
    exercising in its own right since memory_routes.py owns its own
    route handlers, not a delegation to blueprint_routes.py.
  - memory_available_plugins  — GET /api/memory/available_plugins, SAFE read.
  - memory_run_and_poll       — a REAL POST /api/memory/run acquisition +
    analysis against a live Velociraptor client, polled via the dedicated
    GET /api/memory/run/<id>/status endpoint (NOT the shared
    /api/dashboard/automation/<id> — memory_routes.py's own status handler
    is what surfaces memory-run-specific terminal states/progress/logs_tail;
    the shared dashboard endpoint would work too since both read the same
    workflow row, but the dedicated endpoint is the one this feature area
    actually ships and is what's worth regression-testing).
  - memory_run_stop           — starts a run and calls
    POST /api/memory/run/<id>/stop almost immediately, asserting the run
    lands in 'cancelled' (confirmed by reading services/workflow_service.py:
    request_stop() sets status='cancelled' directly and a guard at line ~483
    ignores any late 'failed'/'completed' write from the killed pipeline
    thread racing behind it, so 'cancelled' is the real terminal state to
    expect, not 'failed').

Per the plan's explicit caution: a real memory-forensics analysis job under
load can spike VolWeb toward 8-11GB, and this host's headroom is genuinely
tight. Both run-based checks read /proc/meminfo (MemAvailable) at check time
and raise Skip — rather than attempting a real acquisition — whenever
available memory is below MIN_HEADROOM_GB. This is a live, run-time decision
(not a one-time judgment baked in at write time) so the checks correctly
activate on their own once the host has real headroom again.

NOT part of run_all.py's sweep, and not meant to run on every change — invoke
it by name, manually, only when asked:

    docker exec intact_backend python3 /app/workdir/tests/live/test_memory_forensics.py
"""
import sys
import time

from _lib import REQUIRES_MODULE, SAFE, Skip, _delete, _get, _post, _put, find_client, require_live_client, tagged

# VolWeb's own containers cap real analysis jobs at mem_limit 3-4g each
# (backend/workers/yara-scan) — a real job can combine toward 8-11GB. Refuse
# to start a real acquisition+analysis run unless there's comfortably more
# than that sitting idle system-wide.
MIN_HEADROOM_GB = 6.0


def _mem_available_gb():
    """Read /proc/meminfo's MemAvailable (kernel's own reclaimable-memory
    estimate, the same number `free -h`'s 'available' column shows).
    Returns None if unreadable (containers without host /proc visibility,
    unusual sandboxing, etc.) — treated as "unknown", which callers must
    treat as NOT safe to proceed."""
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    kb = int(line.split()[1])
                    return kb / (1024 * 1024)
    except Exception:
        return None
    return None


def _poll_memory_status(run_id, timeout_seconds=600, interval=10):
    """Poll the DEDICATED /api/memory/run/<id>/status endpoint (not the
    shared dashboard one) until a terminal status or timeout. Returns
    (final_status_dict, transitions)."""
    start = time.time()
    transitions = []
    last_status = None
    while time.time() - start < timeout_seconds:
        r = _get(f"/api/memory/run/{run_id}/status")
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

def check_memory_blueprint_crud():
    name = tagged("memory-bp")
    bp_id = None
    try:
        payload = {
            "name": name,
            "description": "live test memory blueprint (via /api/memory/blueprints)",
            "settings": {
                "mode": "plugin",
                "plugin_set": ["volatility3.plugins.windows.pslist.PsList"],
                "cpu_limit": 50,
                "max_bytes": 1073741824,
            },
        }
        r = _post("/api/memory/blueprints", payload)
        if r.status_code != 201:
            return False, f"POST /api/memory/blueprints -> {r.status_code}: {r.text[:300]}"
        bp_id = r.json().get("blueprint", {}).get("id")
        if not bp_id:
            return False, f"no id in create response: {r.text[:300]}"

        g = _get(f"/api/memory/blueprints")
        ids = [b.get("id") for b in g.json().get("blueprints", [])]
        if bp_id not in ids:
            return False, f"created blueprint not found in list: {g.text[:300]}"
        created = next(b for b in g.json().get("blueprints", []) if b.get("id") == bp_id)
        if created.get("name") != name:
            return False, f"listed blueprint name mismatch: {created}"

        updated = dict(payload)
        updated["description"] = "updated by live test"
        u = _put(f"/api/memory/blueprints/{bp_id}", updated)
        if u.status_code != 200:
            return False, f"PUT /api/memory/blueprints/{bp_id} -> {u.status_code}: {u.text[:300]}"
        if u.json().get("blueprint", {}).get("description") != "updated by live test":
            return False, f"update didn't persist: {u.text[:300]}"

        d = _delete(f"/api/memory/blueprints/{bp_id}")
        if d.status_code != 200:
            return False, f"DELETE /api/memory/blueprints/{bp_id} -> {d.status_code}: {d.text[:300]}"
        deleted_id, bp_id = bp_id, None

        g2 = _get(f"/api/memory/blueprints")
        ids2 = [b.get("id") for b in g2.json().get("blueprints", [])]
        if deleted_id in ids2:
            return False, f"blueprint {deleted_id} still listed after delete"

        return True, f"id={deleted_id} full create/get(list)/update/list/delete cycle OK"
    finally:
        if bp_id:
            try:
                _delete(f"/api/memory/blueprints/{bp_id}")
            except Exception:
                pass


def check_available_plugins():
    r = _get("/api/memory/available_plugins")
    if r.status_code != 200:
        return False, f"GET /api/memory/available_plugins -> {r.status_code}: {r.text[:300]}"
    body = r.json()
    groups = body.get("groups")
    if not isinstance(groups, list) or not groups:
        return False, f"expected a non-empty 'groups' list: {str(body)[:300]}"
    for g in groups:
        if "label" not in g or not isinstance(g.get("plugins"), list):
            return False, f"malformed group entry: {g}"
    total_plugins = sum(len(g["plugins"]) for g in groups)
    return True, f"{len(groups)} group(s), {total_plugins} plugin(s) total"


def check_memory_run_and_poll(client):
    # A memory acquisition needs the endpoint to respond, not just exist.
    require_live_client(client)
    headroom = _mem_available_gb()
    if headroom is None or headroom < MIN_HEADROOM_GB:
        raise Skip(
            "insufficient memory headroom for a real acquisition run - see docker stats/free -h "
            f"(MemAvailable={headroom!r} GB, need >= {MIN_HEADROOM_GB} GB)"
        )

    r = _post("/api/memory/run", {
        "client_id": client["client_id"],
        "client_name": client.get("hostname"),
        "mode": "yara",  # yara-only: skips the (heavier) full plugin sweep
        "case_name": tagged("memory-run-case"),
    })
    if r.status_code != 202:
        return False, f"POST /api/memory/run -> {r.status_code}: {r.text[:300]}"
    run_id = r.json().get("run_id")
    if not run_id:
        return False, f"no run_id in response: {r.text[:300]}"

    final, transitions = _poll_memory_status(run_id, timeout_seconds=600, interval=10)
    if final.get("status") != "completed":
        return False, f"run {run_id} ended as '{final.get('status')}' (transitions: {transitions})"
    return True, f"run_id={run_id} transitions={transitions}"


def check_memory_run_stop(client):
    if not client:
        raise Skip("no Velociraptor client available for a memory stop test")
    headroom = _mem_available_gb()
    if headroom is None or headroom < MIN_HEADROOM_GB:
        raise Skip(
            "insufficient memory headroom for a real acquisition run - see docker stats/free -h "
            f"(MemAvailable={headroom!r} GB, need >= {MIN_HEADROOM_GB} GB)"
        )

    r = _post("/api/memory/run", {
        "client_id": client["client_id"],
        "client_name": client.get("hostname"),
        "mode": "yara",
        "case_name": tagged("memory-stop-case"),
    })
    if r.status_code != 202:
        return False, f"POST /api/memory/run -> {r.status_code}: {r.text[:300]}"
    run_id = r.json().get("run_id")
    if not run_id:
        return False, f"no run_id in response: {r.text[:300]}"

    stop = _post(f"/api/memory/run/{run_id}/stop")
    if stop.status_code != 200:
        return False, f"POST /api/memory/run/{run_id}/stop -> {stop.status_code}: {stop.text[:300]}"

    final, transitions = _poll_memory_status(run_id, timeout_seconds=120, interval=5)
    if final.get("status") != "cancelled":
        return False, (
            f"expected terminal status 'cancelled' after an immediate stop, got "
            f"'{final.get('status')}' (transitions: {transitions})"
        )
    return True, f"run_id={run_id} correctly landed in 'cancelled' (transitions: {transitions})"


CHECKS = [
    ("memory_blueprint_crud", REQUIRES_MODULE("volweb"), lambda client: check_memory_blueprint_crud()),
    ("memory_available_plugins", REQUIRES_MODULE("volweb"), lambda client: check_available_plugins()),
    ("memory_run_and_poll", REQUIRES_MODULE("volweb"), check_memory_run_and_poll),
    ("memory_run_stop", REQUIRES_MODULE("volweb"), check_memory_run_stop),
]


def main():
    client, warning = find_client()
    if warning:
        print(f"[WARN] {warning}", flush=True)
    if client:
        print(f"[INFO] Using client {client.get('client_id')} ({client.get('hostname')}, {client.get('os')})", flush=True)
    else:
        print("[INFO] No Velociraptor client available — client-dependent checks will SKIP.", flush=True)

    headroom = _mem_available_gb()
    print(f"[INFO] MemAvailable ~= {headroom!r} GB (need >= {MIN_HEADROOM_GB} GB for the two real run checks)", flush=True)

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
