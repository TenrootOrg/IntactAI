"""Tests for the Velociraptor readiness gate (post-upgrade reimport race fix).

The old gate only checked that a LAZY gRPC channel object could be built, so it
passed before the API accepted connections; the imports that followed hit
'Connection refused' and logged errors that flipped online-upgrade runs to
'failed'. The new gate probes the API with a real VQL query and retries with
backoff, and transient gRPC failures are classified so they log at warning.

Run:  docker exec intact_backend python /app/workdir/tests/test_velociraptor_ready_gate.py
"""

import sys

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services import velociraptor_init_service as V   # noqa: E402


class _Patch:
    def __init__(self, **kw):
        self.kw, self.saved = kw, {}

    def __enter__(self):
        for k, v in self.kw.items():
            self.saved[k] = getattr(V, k)
            setattr(V, k, v)
        return self

    def __exit__(self, *a):
        for k, v in self.saved.items():
            setattr(V, k, v)


class _NoSleepTime:
    sleep = staticmethod(lambda *a, **k: None)


def test_is_transient_grpc_classifies_connection_issues():
    assert V._is_transient_grpc(Exception("status = StatusCode.UNAVAILABLE"))
    assert V._is_transient_grpc(Exception("connect: Connection refused (111)"))
    assert V._is_transient_grpc(Exception("failed to connect to all addresses"))


def test_is_transient_grpc_false_for_real_errors():
    assert not V._is_transient_grpc(Exception("Unable to parse artifact YAML"))
    assert not V._is_transient_grpc(Exception("permission denied"))


def test_wait_ready_returns_true_once_api_answers():
    # API answers on the 3rd probe -> gate should retry then succeed.
    n = {"i": 0}
    def fake_answers(timeout=8):
        n["i"] += 1
        return n["i"] >= 3
    with _Patch(_velociraptor_api_answers=fake_answers, time=_NoSleepTime):
        ok = V.wait_for_velociraptor_ready(attempts=10, delay=2)
    assert ok is True
    assert n["i"] == 3, "should stop probing as soon as the API answers"


def test_wait_ready_returns_false_when_never_answers():
    n = {"i": 0}
    def fake_answers(timeout=8):
        n["i"] += 1
        return False
    with _Patch(_velociraptor_api_answers=fake_answers, time=_NoSleepTime):
        ok = V.wait_for_velociraptor_ready(attempts=4, delay=2)
    assert ok is False
    assert n["i"] == 4, "should probe exactly `attempts` times before giving up"


def test_lazy_channel_alone_is_not_treated_as_ready():
    # Regression for the original bug: a channel that exists but whose queries
    # fail must NOT count as ready. _velociraptor_api_answers returns False when
    # the stub query raises, so the gate keeps waiting.
    class _DeadChannel:
        def close(self): pass

    class _Stub:
        def __init__(self, ch): pass
        def Query(self, *a, **k):
            raise Exception("StatusCode.UNAVAILABLE: connection refused")

    with _Patch(setup_velociraptor_connection=lambda: _DeadChannel(),
                api_pb2_grpc=type("M", (), {"APIStub": _Stub})):
        assert V._velociraptor_api_answers(timeout=1) is False


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
