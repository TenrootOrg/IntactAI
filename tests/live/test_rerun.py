"""Live: the Rerun button relaunches a run with its original configuration.

Deliberately rerun-then-STOP. A real collection or hunt runs for minutes and
touches live endpoints; this suite only needs to prove that the replay
dispatches with the right configuration, which is decided the instant the new
run is created. Letting it finish would add minutes per case and leave real
collections on real clients behind.

What this covers that the unit tests cannot: that the spec's endpoint and
payload are actually ACCEPTED by the live route. The unit tests assert the
spec's shape; only a real POST proves the shape still matches what the route
expects after someone edits it.

Run: docker exec intact_backend python /app/workdir/tests/live/test_rerun.py
"""

import sys
import time

if "/app/workdir/tests" not in sys.path:
    sys.path.insert(0, "/app/workdir/tests")

from live._lib import _get, _post, REQUIRES_MODULE, find_client  # noqa: E402


def _runs():
    r = _get("/api/dashboard/automations")
    r.raise_for_status()
    return r.json().get("automations") or r.json().get("runs") or []


def _stop(run_id):
    """Stop promptly — every second here is a real collection on a real host."""
    try:
        _post(f"/api/dashboard/automation/{run_id}/stop")
    except Exception:
        pass


def _spec(run_id):
    r = _get(f"/api/dashboard/automation/{run_id}/rerun-spec")
    r.raise_for_status()
    return r.json()


def check_rerun_spec_matches_a_live_route():
    """The spec must be accepted by the endpoint it names, then be stoppable.

    Failure here means the spec drifted from the route — the exact break the
    server-side-dispatch design was avoiding, surfacing as a 400 rather than
    silently launching something different.
    """
    candidates = [r for r in _runs()
                  if r.get("type") in ("velociraptor_collection", "velociraptor_hunt")
                  and r.get("status") in ("completed", "failed", "cancelled")]
    if not candidates:
        return None, "no finished collection/hunt run to replay"

    for src in candidates:
        spec = _spec(src["id"])
        if not spec.get("supported"):
            continue          # older run with no stored config — expected

        resp = _post(spec["endpoint"], spec["payload"])
        if resp.status_code != 200:
            return False, (f"rerun of {src['id']} -> POST {spec['endpoint']} "
                           f"returned {resp.status_code}: {resp.text[:200]}")
        new_id = (resp.json() or {}).get("run_id")
        if not new_id:
            return False, f"no run_id from {spec['endpoint']}: {resp.text[:200]}"

        # Stop immediately. Verified below that it actually left 'running'.
        _stop(new_id)
        deadline = time.time() + 30
        final = None
        while time.time() < deadline:
            row = next((r for r in _runs() if r.get("id") == new_id), None)
            final = (row or {}).get("status")
            if final in ("cancelled", "completed", "failed"):
                break
            time.sleep(2)
        if final == "running":
            return False, (f"rerun {new_id} did not stop within 30s — a test that "
                           f"leaves live collections running is worse than no test")
        return True, f"replayed {src['id']} -> {new_id} via {spec['endpoint']}, stopped as '{final}'"

    return None, "no finished run had a stored configuration to replay"


def check_system_runs_refuse_rerun():
    """Upgrade/purge must never be replayable from the run list."""
    sysruns = [r for r in _runs()
               if r.get("type") in ("online_upgrade", "upgrade", "system_purge",
                                    "prepare_package", "support_bundle")]
    if not sysruns:
        return None, "no system runs present to check"
    for r in sysruns[:5]:
        spec = _spec(r["id"])
        if spec.get("supported"):
            return False, f"{r['type']} run {r['id']} reported rerunnable — it must not be"
    return True, f"{len(sysruns[:5])} system run(s) correctly refused"


CHECKS = [
    ("rerun_spec_matches_live_route", lambda: check_rerun_spec_matches_a_live_route()),
    ("system_runs_refuse_rerun", lambda: check_system_runs_refuse_rerun()),
]


if __name__ == "__main__":
    failures = 0
    for name, fn in CHECKS:
        try:
            ok, msg = fn()
        except Exception as e:                      # noqa: BLE001
            ok, msg = False, f"unexpected {type(e).__name__}: {e}"
        if ok is None:
            print(f"SKIP {name}: {msg}")
        elif ok:
            print(f"PASS {name}: {msg}")
        else:
            failures += 1
            print(f"FAIL {name}: {msg}")
    print("OK" if not failures else f"{failures} FAILED")
    sys.exit(1 if failures else 0)
