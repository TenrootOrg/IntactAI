"""Tests for the online agentic collector helpers (services/agentic/collectors/_base.py).

get_client_os() reads each enrolled client's OS from the Velociraptor server so the
collection can drop wrong-OS artifacts per client (Windows-only VQL on a Linux box
errors + a broad scanner crawls the endpoint). It must normalize the OS to lower
case, skip unknowns, and never raise.

We drive it with a fake gRPC stub (no live Velociraptor needed).

Run:  docker exec intact_backend python /app/services/agentic/tests/test_collectors_base.py
"""

import sys
import json
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.agentic.collectors._base import get_client_os   # noqa: E402


class _Resp:
    def __init__(self, response):
        self.Response = response


class _Stub:
    """Minimal stand-in for the Velociraptor APIStub: .Query() yields _Resp rows."""
    def __init__(self, rows=None, raises=None, empty=False):
        self._rows, self._raises, self._empty = rows, raises, empty

    def Query(self, request, timeout=None):
        if self._raises:
            raise self._raises
        if self._empty:
            yield _Resp("")           # a response with no body
            return
        yield _Resp(json.dumps(self._rows))


def test_maps_and_lowercases_os():
    stub = _Stub([
        {"client_id": "C.1", "OS": "Windows"},
        {"client_id": "C.2", "OS": "linux"},
        {"client_id": "C.3", "OS": "Darwin"},
    ])
    out = get_client_os(stub, ["C.1", "C.2", "C.3"])
    assert out == {"C.1": "windows", "C.2": "linux", "C.3": "darwin"}


def test_skips_rows_with_empty_os():
    stub = _Stub([
        {"client_id": "C.1", "OS": ""},
        {"client_id": "C.2", "OS": "linux"},
        {"client_id": "C.3"},                 # no OS key
    ])
    out = get_client_os(stub, ["C.1", "C.2", "C.3"])
    assert out == {"C.2": "linux"}


def test_empty_response_yields_empty_map():
    assert get_client_os(_Stub(empty=True), ["C.1"]) == {}


def test_stub_exception_is_swallowed():
    # Best-effort: a gRPC failure must not blow up the collection, just yield {}.
    assert get_client_os(_Stub(raises=RuntimeError("grpc down")), ["C.1"]) == {}


def test_whitespace_os_is_trimmed_and_skipped():
    out = get_client_os(_Stub([{"client_id": "C.1", "OS": "  "}]), ["C.1"])
    assert out == {}


# ---------------------------------------------------------------------------
# VQL injection boundary.
#
# Both helpers build `WHERE client_id IN ('{"', '".join(client_ids)}')` — a
# single quote in one element closes the literal and the rest is parsed as VQL.
# The scheduler's PUT route is validated now, but a job poisoned BEFORE that fix
# is still on disk and fires on its next tick, where the route guard cannot
# reach it. These assert the sink refuses on its own.
# ---------------------------------------------------------------------------

POISON = "C.aaa' OR 1=1 --"


class _RecordingStub(_Stub):
    """Captures the VQL actually sent, so a test can prove nothing was sent."""

    def __init__(self, rows=None):
        super().__init__(rows or [])
        self.queries = []

    def Query(self, request, timeout=None):
        self.queries.append(request.Query[0].VQL)
        yield from super().Query(request, timeout=timeout)


def test_get_client_os_never_sends_a_quote_bearing_id():
    stub = _RecordingStub([{"client_id": "C.1", "OS": "windows"}])
    out = get_client_os(stub, [POISON])
    assert out == {}, out
    assert stub.queries == [], f"poisoned id reached the server: {stub.queries}"


def test_get_client_hostnames_never_sends_a_quote_bearing_id():
    from services.agentic.collectors._base import get_client_hostnames
    stub = _RecordingStub([{"client_id": "C.1", "Hostname": "H"}])
    out = get_client_hostnames(stub, [POISON])
    assert out == {}, out
    assert stub.queries == [], f"poisoned id reached the server: {stub.queries}"


def test_a_poisoned_id_does_not_take_valid_ones_down_with_it():
    """Filter, don't abort: one bad id in a batch must not silently cancel
    collection against the operator's legitimate hosts."""
    stub = _RecordingStub([{"client_id": "C.1", "OS": "windows"}])
    out = get_client_os(stub, [POISON, "C.1"])
    assert out == {"C.1": "windows"}, out
    assert len(stub.queries) == 1
    assert POISON not in stub.queries[0]
    assert "C.1" in stub.queries[0]


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
