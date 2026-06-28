"""Tests for enforce_iris_admin_password() — IRIS admin password from config.yaml.

IRIS only honours IRIS_ADM_PASSWORD at first-init; an existing admin keeps its old
password. This helper re-asserts config.yaml's value by (1) hashing it with IRIS's
own flask-bcrypt standalone inside intact_iris_app (no DB access needed) and (2)
writing the hash straight into iris_db via psql (local auth). Docker + config are
mocked.

Run:  docker exec intact_backend python /app/workdir/tests/test_iris_admin_password.py
"""

import sys
import types

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.upgrade import iris as I   # noqa: E402

FAKE_HASH = "$2b$12$" + "C" * 53   # looks like a bcrypt hash (starts with $2)


class _Patch:
    def __init__(self, **kw):
        self.kw, self.saved = kw, {}

    def __enter__(self):
        for k, v in self.kw.items():
            self.saved[k] = getattr(I, k)
            setattr(I, k, v)
        return self

    def __exit__(self, *a):
        for k, v in self.saved.items():
            setattr(I, k, v)


class _FakeConfig:
    def __init__(self, cfg):
        self._cfg = cfg

    def install(self):
        m = types.ModuleType("config")
        m.load_main_config = lambda: self._cfg
        self._prev = sys.modules.get("config")
        sys.modules["config"] = m

    def remove(self):
        if self._prev is not None:
            sys.modules["config"] = self._prev
        else:
            sys.modules.pop("config", None)


def _ok(stdout=""):
    return {"success": True, "stdout": stdout, "error": ""}


def _runner(hashval=FAKE_HASH, update="UPDATE 1", app_running=True, db_running=True):
    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        if "docker ps" in cmd and "intact_iris_app" in cmd:
            return _ok("intact_iris_app\n" if app_running else "")
        if "docker ps" in cmd and "intact_iris_db" in cmd:
            return _ok("intact_iris_db\n" if db_running else "")
        if "intact_iris_db psql" in cmd:
            return _ok(update)
        if "intact_iris_app" in cmd and "python3 -c" in cmd:   # the hash step
            return _ok(hashval)
        return _ok("")
    return run, calls


def _with_cfg(cfg, fn):
    fc = _FakeConfig(cfg); fc.install()
    try:
        return fn()
    finally:
        fc.remove()


def _hash_cmd(calls):
    return next((c for c in calls if "intact_iris_app" in c and "python3 -c" in c and "flask_bcrypt" in c), None)


def _psql_cmd(calls):
    return next((c for c in calls if "intact_iris_db psql" in c), None)


def _run(cfg, runner):
    with _Patch(run_command=runner):
        _with_cfg(cfg, lambda: I.enforce_iris_admin_password(logger=lambda *a, **k: None))


def test_happy_path_two_step_hash_then_update():
    run, calls = _runner()
    _run({"modules": {"iris": {"id": "administrator", "password": "S3cr3t!pw"}}}, run)
    hc, pc = _hash_cmd(calls), _psql_cmd(calls)
    assert hc, "should compute the bcrypt hash inside intact_iris_app"
    assert pc, "should UPDATE the password in iris_db via psql"
    # pc is shlex-quoted, so check the stable, quote-free fragments.
    assert "UPDATE" in pc and FAKE_HASH in pc
    assert 'WHERE' in pc and "administrator" in pc


def test_plaintext_password_never_in_sql():
    run, calls = _runner()
    secret = "p@ss w0rd'weird"
    _run({"modules": {"iris": {"id": "administrator", "password": secret}}}, run)
    pc = _psql_cmd(calls)
    assert secret not in pc, "the SQL must contain only the bcrypt hash, never the plaintext"
    # password reaches the hash step via env, not the python body
    hc = _hash_cmd(calls)
    # password reaches the hasher via env (-e), and the snippet reads it from
    # os.environ rather than having it inlined (hc is shlex-quoted, so check the
    # quote-free fragments).
    assert "-e IRIS_RESET_PW=" in hc and "os.environ[" in hc and "IRIS_RESET_PW" in hc


def test_no_password_in_config_skips():
    run, calls = _runner()
    _run({"modules": {"iris": {"id": "administrator"}}}, run)
    assert _hash_cmd(calls) is None and _psql_cmd(calls) is None


def test_app_not_running_skips():
    run, calls = _runner(app_running=False)
    _run({"modules": {"iris": {"id": "administrator", "password": "x"}}}, run)
    assert _hash_cmd(calls) is None and _psql_cmd(calls) is None


def test_db_not_running_skips():
    run, calls = _runner(db_running=False)
    _run({"modules": {"iris": {"id": "administrator", "password": "x"}}}, run)
    assert _hash_cmd(calls) is None and _psql_cmd(calls) is None


def test_bad_hash_skips_update():
    # hash step returns garbage (not starting with $2) -> never touch the DB
    run, calls = _runner(hashval="ERROR: boom")
    _run({"modules": {"iris": {"id": "administrator", "password": "x"}}}, run)
    assert _hash_cmd(calls) is not None and _psql_cmd(calls) is None


def test_update_zero_rows_does_not_raise():
    run, calls = _runner(update="UPDATE 0")
    _run({"modules": {"iris": {"id": "administrator", "password": "x"}}}, run)
    assert _psql_cmd(calls) is not None   # attempted, handled gracefully


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
