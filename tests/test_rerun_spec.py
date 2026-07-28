"""Rerun: which runs can be relaunched, and with exactly what.

The Rerun button replays a finished run's ORIGINAL configuration. Two ways
that goes wrong, both silent:

  * a run that never recorded its config gets "rerun" with defaults -- a
    different job wearing the same name. Observed on this host: two
    velociraptor_collection rows from an older release kept only
    client_name/collected_data/hostnames, so a type-based check would have
    launched them with no clients and a default blueprint;
  * a system operation becomes rerunnable, putting "repeat that purge" or
    "repeat that half-finished upgrade" one click away in a list.

So replayability is decided from what the run actually STORED, never from its
type alone, and the supported set is investigation runs only.

The endpoint returns a spec for the browser to POST rather than dispatching
server-side, so these tests assert the spec — the endpoint and the payload —
which is the whole contract.

Run: docker exec intact_backend python /app/workdir/tests/test_rerun_spec.py
"""

import sys

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from flask import Flask  # noqa: E402
import routes.dashboard_routes as D  # noqa: E402

_app = Flask(__name__)


def _spec(run):
    """Call the endpoint with `run` as the stored record."""
    orig_get = D.get_automation_run
    orig_vis = D._run_visible_in_active_workspace
    D.get_automation_run = lambda rid: run
    D._run_visible_in_active_workspace = lambda r: True
    try:
        with _app.app_context():
            resp = D.rerun_spec("r1")
            return (resp[0] if isinstance(resp, tuple) else resp).get_json()
    finally:
        D.get_automation_run = orig_get
        D._run_visible_in_active_workspace = orig_vis


def _run(atype, details, status="failed"):
    return {"run_id": "r1", "automation_type": atype, "status": status,
            "details": details}


COLLECTION = {"blueprint_id": "agentic_quick_wins",
              "client_ids": ["C.aaa", "C.bbb"], "collection_minutes": 15}
HUNT = {"artifacts": ["Generic.Client.Info"], "blueprint": "BestPractice",
        "expire_minutes": 60, "timeout_seconds": 3600, "cpu_limit": 50}


def test_collection_rebuilds_its_launch_payload():
    d = _spec(_run("velociraptor_collection", COLLECTION))
    assert d["supported"] is True, d
    assert d["endpoint"] == "/api/agentic/run", d
    assert d["payload"] == {"blueprint_id": "agentic_quick_wins",
                            "client_ids": ["C.aaa", "C.bbb"],
                            "collection_minutes": 15}, d["payload"]


def test_hunt_rebuilds_its_launch_payload():
    d = _spec(_run("velociraptor_hunt", HUNT))
    assert d["supported"] is True, d
    assert d["endpoint"] == "/api/velociraptor/bestpractice"
    p = d["payload"]
    assert p["artifacts"] == ["Generic.Client.Info"]
    assert p["expire_minutes"] == 60 and p["cpu_limit"] == 50


def test_hunt_falls_back_to_the_singular_artifact_field():
    """Older hunt rows stored `artifact` (one) rather than `artifacts`.
    Without the fallback they look unreplayable and the button disappears."""
    d = _spec(_run("velociraptor_hunt", {"artifact": "Windows.Sys.Programs"}))
    assert d["supported"] is True, d
    assert d["payload"]["artifacts"] == ["Windows.Sys.Programs"]


def test_run_without_stored_config_is_refused_not_defaulted():
    """THE case this guard exists for. A type-based check would happily
    rebuild an empty payload and launch a different job."""
    d = _spec(_run("velociraptor_collection",
                   {"client_name": "WIN11", "hostnames": {}, "collected_data": []}))
    assert d["supported"] is False, d
    assert "blueprint_id" in d["reason"] and "client_ids" in d["reason"], d["reason"]


def test_partial_config_is_refused():
    """Blueprint present, clients missing -> still not reproducible."""
    d = _spec(_run("velociraptor_collection", {"blueprint_id": "x", "client_ids": []}))
    assert d["supported"] is False, d
    assert "client_ids" in d["reason"]


def test_system_operations_are_never_rerunnable():
    """A rerun one click away in a list is how a purge or a half-finished
    upgrade gets re-triggered by accident."""
    for atype in ("online_upgrade", "upgrade", "system_purge", "prepare_package",
                  "upgrade_package_upload", "support_bundle", "settings"):
        d = _spec(_run(atype, {"modules": {"elk": "9.4.2"}, "trigger": "manual"}))
        assert d["supported"] is False, f"{atype} must not be rerunnable: {d}"


def test_defaults_only_fill_optional_fields():
    """A missing collection_minutes may default; a missing client list may not."""
    d = _spec(_run("velociraptor_collection",
                   {"blueprint_id": "b", "client_ids": ["C.x"]}))
    assert d["supported"] is True
    assert d["payload"]["collection_minutes"] == 30


def test_payload_carries_nothing_beyond_the_launch_fields():
    """Runtime bookkeeping (flow_id, phase, scheduled_job_id) must not be
    replayed as launch input — it describes the OLD run, not the new one."""
    noisy = dict(COLLECTION, flow_id="F.123", phase="collecting",
                 scheduled_job_id="job_9", collected_data=[{"x": 1}])
    p = _spec(_run("velociraptor_collection", noisy))["payload"]
    assert set(p) == {"blueprint_id", "client_ids", "collection_minutes"}, p


def test_missing_run_is_a_404_not_a_crash():
    orig = D.get_automation_run
    D.get_automation_run = lambda rid: None
    try:
        with _app.app_context():
            resp = D.rerun_spec("nope")
            body, code = resp if isinstance(resp, tuple) else (resp, 200)
            assert code == 404, code
    finally:
        D.get_automation_run = orig


def test_every_supported_type_declares_its_required_fields():
    """A type in _RERUN_SPECS with no _RERUN_REQUIRED entry silently accepts
    an empty config — exactly the defaulting this design rejects."""
    missing = [t for t in D._RERUN_SPECS if not D._RERUN_REQUIRED.get(t)]
    assert not missing, (
        f"{missing} can be rerun but declare no required fields, so a run that "
        f"stored nothing would launch with defaults")


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as e:
                failures += 1
                print(f"FAIL {name}: {e}")
            except Exception as e:      # noqa: BLE001
                failures += 1
                print(f"FAIL {name}: unexpected {type(e).__name__}: {e}")
    print("OK" if not failures else f"{failures} FAILED")
    sys.exit(1 if failures else 0)
