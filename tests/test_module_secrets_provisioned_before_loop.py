"""Per-module secrets must exist BEFORE the module loop tries to compose-up.

refresh_module_compose_file() runs for every sidecar on every upgrade, so a
release that ships new compose files without bumping those modules' pins writes
`env_file: ./secrets/postgres.env` (Timesketch) and `./secrets/agent.env`
(Portainer) onto a box that has neither. resume_upgrade_workflow provisions both
-- but the block sat ~450 lines BELOW the module loop whose compose-up needs
them.

That ordering happens to work for an UPGRADE: upgrade_timesketch() calls
ensure_postgres_password() itself on the way through. It does not work for a
FIRST-TIME install driven by the upgrade. install_timesketch_offline() never
calls it, so `docker compose up` dies with

    env file .../modules/timesketch/secrets/postgres.env not found

and the module is reported MODULE_FAILED -- while the run still finishes
`completed`, which is the part that makes it easy to miss.

Observed 2026-08-02 installing Timesketch onto a backend-only intact-20260726
box. The comment sitting directly above the block already predicted this case
("Upgrading from intact-20260726 is exactly that case") -- it just ran too late
to prevent it.

Run: docker exec intact_backend python /app/workdir/tests/test_module_secrets_provisioned_before_loop.py
"""

import inspect
import sys

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.upgrade import resume_upgrade_workflow  # noqa: E402
from services.upgrade.timesketch import (  # noqa: E402
    ensure_postgres_password, install_timesketch_offline, upgrade_timesketch)

SRC = inspect.getsource(resume_upgrade_workflow)
LOOP = "for module_name in upgrade_order:"


def _pos(needle):
    i = SRC.find(needle)
    assert i != -1, f"anchor vanished from resume_upgrade_workflow: {needle!r}"
    return i


def test_secret_provisioning_runs_before_the_module_loop():
    """The whole bug: a first-time install inside the loop needs the secret the
    block creates."""
    assert _pos("Timesketch DB password") < _pos(LOOP), (
        "per-module secret provisioning moved back below the module loop — a "
        "first-time Timesketch install will fail on the missing "
        "secrets/postgres.env")


def test_portainer_agent_secret_is_provisioned_too():
    """Same block, same failure shape (`env_file: ./secrets/agent.env`)."""
    assert _pos("Portainer agent secret") < _pos(LOOP), (
        "Portainer agent secret provisioning is below the module loop")


def test_provisioning_failure_never_aborts_the_upgrade():
    """A secret we could not write must not take the whole run down — the
    module that needs it will fail on its own and report itself."""
    seg = SRC[_pos("Portainer agent secret"):_pos(LOOP)]
    assert "except Exception" in seg, (
        "the provisioning block is no longer wrapped — an exception would abort "
        "the entire Phase-2 resume")


def test_the_upgrade_path_still_provisions_for_itself():
    """upgrade_timesketch() calling ensure_postgres_password() is why the old
    ordering looked fine. Keep it: it is the belt to the block's braces."""
    assert "ensure_postgres_password" in inspect.getsource(upgrade_timesketch), (
        "upgrade_timesketch no longer provisions the DB password itself")


def test_first_time_install_still_relies_on_the_hoisted_block():
    """Documents WHY the hoist is load-bearing. If install_timesketch_offline
    ever calls ensure_postgres_password directly this becomes belt-and-braces
    rather than the only thing standing between a fresh install and a failed
    compose-up -- worth noticing deliberately rather than by surprise."""
    body = inspect.getsource(install_timesketch_offline)
    if "ensure_postgres_password" in body:
        return          # it provisions for itself now; the hoist is redundant
    assert _pos("Timesketch DB password") < _pos(LOOP), (
        "install_timesketch_offline does NOT provision the postgres password "
        "itself, so the hoisted block is the only thing that creates it before "
        "compose-up — and it is no longer above the loop")


def test_provisioning_is_idempotent():
    """It runs on every resume. Safe only because an existing secret is a
    no-op — otherwise every upgrade would rotate the DB password."""
    body = inspect.getsource(ensure_postgres_password)
    assert "exists" in body or "isfile" in body, (
        "ensure_postgres_password no longer short-circuits on an existing "
        "secret — running it before every module loop would rotate the "
        "Timesketch DB password on each upgrade")


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
