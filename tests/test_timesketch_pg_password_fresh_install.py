"""A first-time Timesketch install must keep the postgres credential it wrote.

ensure_postgres_password() writes secrets/postgres.env, then ALTERs the password
inside the running database, then rewrites the app configs. If the ALTER fails
it DELETES the file again -- deliberately, and correctly for an upgrade: a
password the database does not know about is worse than none, and removing it
lets the next attempt retry cleanly.

That rollback is wrong for a FIRST-TIME install driven by the upgrade. There is
no intact_timesketch_postgres container yet, so there is nothing to ALTER; the
credential in the file IS what initdb will bake in. The ALTER failed, the
rollback deleted the file, and compose died with

    env file .../modules/timesketch/secrets/postgres.env not found

MODULE_FAILED: TIMESKETCH -- while the run still reported `completed`.

Observed 2026-08-02 installing Timesketch onto a backend-only intact-20260726
box. Note this survived a first fix attempt: hoisting the provisioning call
above the module loop (20c2071) made it RUN at the right time, but it still
deleted its own output, so the symptom was identical. The ordering fix was
necessary and not sufficient.

Run: docker exec intact_backend python /app/workdir/tests/test_timesketch_pg_password_fresh_install.py
"""

import os
import sys
import tempfile

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

import services.upgrade.timesketch as ts  # noqa: E402


class _Docker:
    """Fake run_command. `pg_running` decides whether the postgres container
    exists; `alter_ok` whether an ALTER against it succeeds."""

    def __init__(self, pg_running, alter_ok=True):
        self.pg_running = pg_running
        self.alter_ok = alter_ok
        self.commands = []

    def __call__(self, cmd, **kw):
        self.commands.append(cmd)
        if cmd.startswith("docker inspect intact_timesketch_postgres"):
            return {"success": self.pg_running, "stdout": ""}
        if "ALTER USER" in cmd:
            return {"success": self.alter_ok, "stdout": ""}
        return {"success": True, "stdout": ""}


def _run(pg_running, alter_ok=True):
    d = tempfile.mkdtemp(prefix="ts-")
    os.makedirs(os.path.join(d, "config"), exist_ok=True)
    orig = ts.run_command
    ts.run_command = _Docker(pg_running, alter_ok)
    try:
        res = ts.ensure_postgres_password(d, logger=lambda m, l="info": None)
    finally:
        cmds = ts.run_command.commands
        ts.run_command = orig
    return res, os.path.join(d, "secrets", "postgres.env"), cmds


def test_fresh_install_keeps_the_env_file():
    """The bug. No postgres container -> nothing to ALTER -> the file we just
    wrote is what initdb will read, so it must survive."""
    res, pg_env, _ = _run(pg_running=False)
    assert os.path.isfile(pg_env), (
        "postgres.env was deleted on a fresh install — compose will fail with "
        "'env file ./secrets/postgres.env not found'")
    assert os.path.getsize(pg_env) > 0, "postgres.env is empty"


def test_fresh_install_does_not_attempt_an_alter():
    """Running psql against a container that does not exist is pure noise, and
    its failure is what triggered the rollback."""
    _, _, cmds = _run(pg_running=False)
    assert not any("ALTER USER" in c for c in cmds), (
        "still trying to ALTER a database that does not exist yet")


def test_fresh_install_reports_a_change():
    res, _, _ = _run(pg_running=False)
    assert res.get("changed") is True, res


def test_written_credential_is_not_the_shipped_default():
    """The whole point of the function: get off timesketch/timesketch."""
    _, pg_env, _ = _run(pg_running=False)
    body = open(pg_env).read()
    assert body.startswith("POSTGRES_PASSWORD="), body
    assert "timesketch\n" not in body, "still writing the shipped default"


def test_upgrade_with_a_failing_alter_still_rolls_back():
    """The dangerous case the rollback exists for MUST keep working: a real
    database that rejected the change must not be left with a password it does
    not know about."""
    res, pg_env, cmds = _run(pg_running=True, alter_ok=False)
    assert any("ALTER USER" in c for c in cmds), "never attempted the ALTER"
    assert not os.path.exists(pg_env), (
        "ALTER failed against a RUNNING database but postgres.env was kept — "
        "Timesketch would come up unable to authenticate to its own database")
    assert res.get("error") == "alter-failed", res


def test_upgrade_with_a_working_alter_keeps_the_file():
    res, pg_env, cmds = _run(pg_running=True, alter_ok=True)
    assert any("ALTER USER" in c for c in cmds)
    assert os.path.isfile(pg_env), res
    assert res.get("changed") is True, res


def test_is_idempotent_when_the_secret_already_exists():
    """It runs before every module loop now, so a no-op on an existing secret
    is what stops each upgrade rotating a live DB password."""
    d = tempfile.mkdtemp(prefix="ts-")
    os.makedirs(os.path.join(d, "secrets"))
    p = os.path.join(d, "secrets", "postgres.env")
    with open(p, "w") as f:
        f.write("POSTGRES_PASSWORD=already-set\n")
    orig = ts.run_command
    ts.run_command = _Docker(pg_running=True)
    try:
        res = ts.ensure_postgres_password(d, logger=lambda m, l="info": None)
    finally:
        ts.run_command = orig
    assert res.get("changed") is False and res.get("reason") == "already-set", res
    assert open(p).read() == "POSTGRES_PASSWORD=already-set\n", "rotated a live credential"


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
