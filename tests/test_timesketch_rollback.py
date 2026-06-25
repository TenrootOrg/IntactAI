"""Tests for the Timesketch rollback DB-restore-with-Postgres-reconcile (option a).

_rollback_restore_db tries the cheap path first (restore the dump into the rolled-
back postgres), and ONLY if postgres won't come up because the data-dir major no
longer matches the rolled-back pin does it run the dump->wipe->restore migration.
This guards the air-gap incident where a legacy PG15 volume + a PG13 pin left a
crash-looping postgres after a failed upgrade — and crucially must NEVER wipe a
volume whose major already matches.

Docker is fully mocked, so this is fast and deterministic.

Run:  docker exec intact_backend python /app/workdir/tests/test_timesketch_rollback.py
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.upgrade import timesketch as T   # noqa: E402


class _Patch:
    def __init__(self, **kw):
        self.kw, self.saved = kw, {}

    def __enter__(self):
        for k, v in self.kw.items():
            self.saved[k] = getattr(T, k)
            setattr(T, k, v)
        return self

    def __exit__(self, *a):
        for k, v in self.saved.items():
            setattr(T, k, v)


class _NoSleep:
    sleep = staticmethod(lambda *a, **k: None)


def _runner(pg_healthy, calls):
    def run(cmd, **kw):
        calls.append(cmd)
        if "pg_isready" in cmd:
            return {"success": pg_healthy, "stdout": "accepting connections" if pg_healthy else ""}
        return {"success": True, "stdout": "", "error": ""}
    return run


def _noop_log(*a, **k):
    pass


def test_healthy_postgres_restores_normally_no_migration():
    calls, migrated, restored = [], [], []
    with _Patch(run_command=_runner(True, calls), time=_NoSleep,
                _migrate_pg_major=lambda *a, **k: (migrated.append(a), True)[1],
                _restore_timesketch_db=lambda *a, **k: (restored.append(a), True)[1]):
        T._rollback_restore_db("/wd", "/env", "/dump.sql", "vol", logger=_noop_log)
    assert restored, "should restore the dump when postgres is healthy"
    assert not migrated, "must NOT migrate when postgres is healthy"


def test_major_mismatch_triggers_dump_wipe_restore():
    calls, migrated, restored = [], [], []
    with _Patch(run_command=_runner(False, calls), time=_NoSleep,
                _read_volume_pg_major=lambda *a, **k: "15",
                _read_pinned_pg_major=lambda *a, **k: "13",
                _read_pg_volume_name=lambda *a, **k: "vol",
                _migrate_pg_major=lambda *a, **k: (migrated.append(a), True)[1],
                _restore_timesketch_db=lambda *a, **k: (restored.append(a), True)[1]):
        T._rollback_restore_db("/wd", "/env", "/dump.sql", "vol", logger=_noop_log)
    assert migrated, "PG15-volume vs PG13-pin must trigger the migration"
    assert not restored, "the plain restore path must NOT run on a mismatch (migrate restores)"
    # stack composed down before wiping, brought up after
    assert any("compose down" in c for c in calls), "must compose down before volume wipe"
    assert any("compose up" in c for c in calls), "must bring the stack back up after"


def test_matching_major_but_unhealthy_never_wipes():
    # Postgres unhealthy for some OTHER reason but the volume major matches the pin
    # -> we must NOT wipe a correct volume.
    migrated = []
    with _Patch(run_command=_runner(False, []), time=_NoSleep,
                _read_volume_pg_major=lambda *a, **k: "13",
                _read_pinned_pg_major=lambda *a, **k: "13",
                _read_pg_volume_name=lambda *a, **k: "vol",
                _migrate_pg_major=lambda *a, **k: (migrated.append(a), True)[1],
                _restore_timesketch_db=lambda *a, **k: True):
        T._rollback_restore_db("/wd", "/env", "/dump.sql", "vol", logger=_noop_log)
    assert not migrated, "must never wipe a volume whose major already matches"


def test_unknown_volume_major_does_not_wipe():
    # Can't read the data-dir major -> refuse to wipe (conservative).
    migrated = []
    with _Patch(run_command=_runner(False, []), time=_NoSleep,
                _read_volume_pg_major=lambda *a, **k: None,
                _read_pinned_pg_major=lambda *a, **k: "13",
                _read_pg_volume_name=lambda *a, **k: "vol",
                _migrate_pg_major=lambda *a, **k: (migrated.append(a), True)[1]):
        T._rollback_restore_db("/wd", "/env", "/dump.sql", "vol", logger=_noop_log)
    assert not migrated, "must not wipe when the data-dir major is unknown"


def test_no_dump_is_a_noop():
    migrated, restored = [], []
    with _Patch(_migrate_pg_major=lambda *a, **k: (migrated.append(1), True)[1],
                _restore_timesketch_db=lambda *a, **k: (restored.append(1), True)[1]):
        T._rollback_restore_db("/wd", "/env", None, "vol", logger=_noop_log)
    assert not migrated and not restored, "no dump -> nothing to do"


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
