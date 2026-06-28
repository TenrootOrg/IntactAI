"""Tests for label-targeted Velociraptor hunts.

A hunt can be scoped to clients carrying specific Velociraptor labels; if none
are given it targets ALL clients. Verifies the label sanitiser, the VQL clause
builder, and that _create_single_velo_hunt actually injects include_labels into
the hunt() VQL (mocked gRPC stub).

Run:  docker exec intact_backend python /app/workdir/tests/test_hunt_labels.py
"""

import sys

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from pyvelociraptor import api_pb2          # noqa: E402
from routes import velociraptor_routes as VR  # noqa: E402


class _Resp:
    def __init__(self, response="", log=""):
        self.Response = response
        self.log = log


class _Stub:
    """Captures the VQL it's asked to run and returns a fixed HuntId."""
    def __init__(self, hunt_id="H.TEST"):
        self.last_vql = None
        self._hid = hunt_id

    def Query(self, request_obj, timeout=None):
        self.last_vql = request_obj.Query[0].VQL
        return [_Resp(response='[{"HuntId":"%s"}]' % self._hid)]


# ---- _sanitize_hunt_labels --------------------------------------------------

def test_sanitize_drops_non_strings_and_blanks():
    assert VR._sanitize_hunt_labels(["a", "", "  ", 3, None, "b"]) == ["a", "b"]


def test_sanitize_strips_and_dedupes():
    assert VR._sanitize_hunt_labels([" lab ", "lab", "lab2"]) == ["lab", "lab2"]


def test_sanitize_non_list_is_empty():
    assert VR._sanitize_hunt_labels(None) == []
    assert VR._sanitize_hunt_labels("lab") == []


def test_sanitize_caps_count():
    assert len(VR._sanitize_hunt_labels([f"l{i}" for i in range(200)])) == 64


def test_sanitize_drops_overlong():
    assert VR._sanitize_hunt_labels(["x" * 257, "ok"]) == ["ok"]


# ---- _hunt_labels_clause ----------------------------------------------------

def test_clause_empty_when_no_labels():
    assert VR._hunt_labels_clause([]) == ""
    assert VR._hunt_labels_clause(None) == ""


def test_clause_emits_include_labels():
    c = VR._hunt_labels_clause(["lab1", "lab2"])
    assert 'include_labels=["lab1", "lab2"]' in c
    assert c.endswith(",\n")


# ---- _create_single_velo_hunt VQL -------------------------------------------

def test_hunt_vql_includes_labels_when_given():
    stub = _Stub()
    hid, err = VR._create_single_velo_hunt(
        stub, ["Generic.Client.Info"], "desc", 3600, 600, 80, 1000, 1000,
        log_fn=lambda *a, **k: None, include_labels=["lab1", "lab2"])
    assert hid == "H.TEST" and err is None
    assert 'include_labels=["lab1", "lab2"]' in stub.last_vql
    assert "hunt(" in stub.last_vql


def test_hunt_vql_omits_labels_when_none():
    stub = _Stub()
    VR._create_single_velo_hunt(
        stub, ["Generic.Client.Info"], "desc", 3600, 600, 80, 1000, 1000,
        log_fn=lambda *a, **k: None)
    assert "include_labels" not in stub.last_vql


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
