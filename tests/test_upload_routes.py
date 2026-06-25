"""Upload-pipeline tests for routes.upload_routes.

- decode_tus_metadata: the base64 key/value tus metadata parser.
- _resolve_upload_run: keeps an upload + its processing a SINGLE workflow even if
  the backend restarted mid-upload, by recovering the pre-create run from storage
  (details.upload_id) when the in-memory map is gone.

Run:  docker exec intact_backend python /app/tests/test_upload_routes.py
"""

import sys
import base64
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

import routes.upload_routes as U          # noqa: E402
import services.workflow_service as ws    # noqa: E402


def _b64(s):
    return base64.b64encode(s.encode()).decode()


# --------------------------------------------------------------------------
# decode_tus_metadata
# --------------------------------------------------------------------------
def test_decode_empty_metadata():
    assert U.decode_tus_metadata("") == {}
    assert U.decode_tus_metadata(None) == {}


def test_decode_single_pair():
    meta = f"purpose {_b64('velociraptor')}"
    assert U.decode_tus_metadata(meta) == {"purpose": "velociraptor"}


def test_decode_multiple_pairs():
    meta = f"purpose {_b64('timesketch')},filename {_b64('Collection-host.zip')}"
    out = U.decode_tus_metadata(meta)
    assert out["purpose"] == "timesketch"
    assert out["filename"] == "Collection-host.zip"


def test_decode_valueless_key():
    out = U.decode_tus_metadata("flagonly")
    assert out == {"flagonly": ""}


def test_decode_password_metadata_roundtrip():
    meta = f"password {_b64('S3cret pass!')}"
    assert U.decode_tus_metadata(meta)["password"] == "S3cret pass!"


# --------------------------------------------------------------------------
# _resolve_upload_run
# --------------------------------------------------------------------------
class _runs:
    """Patch services.workflow_service.get_all_automation_runs for a block."""
    def __init__(self, runs):
        self.runs = runs
    def __enter__(self):
        self._saved = ws.get_all_automation_runs
        ws.get_all_automation_runs = lambda: self.runs
    def __exit__(self, *a):
        ws.get_all_automation_runs = self._saved


def test_inmemory_hit_returns_run_id():
    U._upload_runs["uid1"] = "run_1"
    try:
        assert U._resolve_upload_run("uid1") == "run_1"      # pop=False keeps it
        assert U._upload_runs.get("uid1") == "run_1"
    finally:
        U._upload_runs.pop("uid1", None)


def test_inmemory_pop_removes_mapping():
    U._upload_runs["uid2"] = "run_2"
    assert U._resolve_upload_run("uid2", pop=True) == "run_2"
    assert "uid2" not in U._upload_runs


def test_recovers_from_storage_when_map_empty():
    # Simulate a restart: map empty, but the run exists in storage with upload_id.
    U._upload_runs.clear()
    with _runs([{"run_id": "run_recovered", "details": {"upload_id": "uidX"}}]):
        assert U._resolve_upload_run("uidX") == "run_recovered"


def test_recovery_accepts_id_or_run_id_key():
    U._upload_runs.clear()
    with _runs([{"id": "run_byid", "details": {"upload_id": "uidY"}}]):
        assert U._resolve_upload_run("uidY") == "run_byid"


def test_recovery_returns_none_for_unknown_upload():
    U._upload_runs.clear()
    with _runs([{"run_id": "r", "details": {"upload_id": "other"}}]):
        assert U._resolve_upload_run("nope") is None


def test_empty_upload_id_returns_none():
    assert U._resolve_upload_run("") is None
    assert U._resolve_upload_run(None) is None


def test_recovery_survives_storage_exception():
    U._upload_runs.clear()
    class _boom:
        def __enter__(s):
            s._saved = ws.get_all_automation_runs
            def explode(): raise RuntimeError("storage down")
            ws.get_all_automation_runs = explode
        def __exit__(s, *a):
            ws.get_all_automation_runs = s._saved
    with _boom():
        assert U._resolve_upload_run("uid") is None   # best-effort, never raises


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1; print(f"FAIL {fn.__name__}"); traceback.print_exc()
    print(f"\n{len(fns)-failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
