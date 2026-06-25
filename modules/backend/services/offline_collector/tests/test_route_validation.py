"""API-contract tests for the offline-collector generate endpoint.

Drives the real Flask route (routes.velociraptor_offline_routes) with a test
client and asserts the input-validation rejections (HTTP 400) — the contract the
UI relies on. Only invalid bodies are posted, so no real generation is triggered
(validation returns before any gRPC / background work).

Run:  docker exec intact_backend python /app/services/offline_collector/tests/test_route_validation.py
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from flask import Flask                                              # noqa: E402
from routes.velociraptor_offline_routes import velociraptor_offline_bp  # noqa: E402

_app = Flask(__name__)
_app.register_blueprint(velociraptor_offline_bp)
_client = _app.test_client()
GEN = "/api/velociraptor/offline/generate"


def _post(body):
    r = _client.post(GEN, json=body)
    return r.status_code, (r.get_json() or {})


def test_missing_config_id_rejected():
    code, body = _post({"os": "linux"})
    assert code == 400 and "config_id" in body.get("error", "")


def test_invalid_os_rejected():
    code, body = _post({"config_id": "x", "os": "freebsd"})
    assert code == 400 and "os must be" in body.get("error", "")


def test_pgp_scheme_rejected():
    code, body = _post({"config_id": "x", "os": "linux", "encryption_scheme": "pgp"})
    assert code == 400 and "none, password, or x509" in body.get("error", "")


def test_unknown_scheme_rejected():
    code, body = _post({"config_id": "x", "os": "linux", "encryption_scheme": "rot13"})
    assert code == 400


def test_password_scheme_requires_password():
    code, body = _post({"config_id": "x", "os": "linux", "encryption_scheme": "password"})
    assert code == 400 and "encryption_password is required" in body.get("error", "")


def test_password_with_triple_quote_rejected():
    code, body = _post({"config_id": "x", "os": "linux",
                        "encryption_scheme": "password", "encryption_password": "a'''b"})
    assert code == 400 and "triple" in body.get("error", "")


def test_progress_timeout_too_small_rejected():
    code, body = _post({"config_id": "x", "os": "linux", "progress_timeout": 5})
    assert code == 400 and "60" in body.get("error", "")


def test_progress_timeout_too_large_rejected():
    code, _ = _post({"config_id": "x", "os": "linux", "progress_timeout": 999999})
    assert code == 400


def test_progress_timeout_non_numeric_rejected():
    code, body = _post({"config_id": "x", "os": "linux", "progress_timeout": "abc"})
    assert code == 400 and "whole number" in body.get("error", "")


def test_legacy_and_musl_mutually_exclusive():
    code, body = _post({"config_id": "x", "os": "linux", "legacy": True, "musl": True})
    assert code == 400 and "mutually exclusive" in body.get("error", "")


def test_musl_is_linux_only():
    code, body = _post({"config_id": "x", "os": "windows", "musl": True})
    assert code == 400 and "Linux-only" in body.get("error", "")


def test_legacy_not_available_for_macos():
    code, body = _post({"config_id": "x", "os": "darwin", "legacy": True})
    assert code == 400 and "macOS" in body.get("error", "")


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
