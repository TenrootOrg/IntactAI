"""Tests for storage helpers (services/storage/workflow_store).

_json_or_default serializes a JSON-bearing column, preserving None as the supplied
default (so empty list/dict columns stay valid JSON, not the string "null").

Run:  docker exec intact_backend python /app/workdir/tests/test_storage_workflow.py
"""

import sys
import json
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.storage.workflow_store import _json_or_default   # noqa: E402


def test_none_returns_default():
    assert _json_or_default(None, "[]") == "[]"
    assert _json_or_default(None, "{}") == "{}"


def test_list_is_json_encoded():
    assert _json_or_default([1, 2, 3], "[]") == json.dumps([1, 2, 3])


def test_dict_is_json_encoded():
    assert _json_or_default({"a": 1}, "{}") == json.dumps({"a": 1})


def test_empty_list_not_treated_as_none():
    # [] is not None -> must serialize to "[]", not fall back to the default sentinel.
    assert _json_or_default([], "DEFAULT") == "[]"


def test_roundtrip_parses_back():
    payload = {"logs": [{"m": "x"}], "n": 2}
    assert json.loads(_json_or_default(payload, "{}")) == payload


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
