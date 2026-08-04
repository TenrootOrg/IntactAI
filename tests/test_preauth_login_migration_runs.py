"""A box upgraded from a pre-auth release must not land locked out.

migrate_basic_auth_to_app_login() exists to carry a pre-auth appliance onto the
app login. Its only call site on the offline path was inside
upgrade_intact_offline() -- which executes in PHASE 1, and Phase 1 runs on the
OLD backend's code, because the image swap happens at the end of it.

A genuinely pre-auth release (intact-20260615 and earlier) has no
auth_service.py and zero occurrences of that function. So the migration could
only ever fire when the SOURCE box already had the new auth code -- i.e. when
it was a no-op. On the one upgrade it was written for, it was unreachable.

Observed 2026-08-02 upgrading 20260615 -> 20260802: the appliance came up with
first_login absent, no stored credential, and auth_mode() mapping ABSENT ->
MODE_LOGIN. That is a locked-out box whose only way back in is hand-editing
config.yaml on the host -- and the recovery hint that says so is rendered on
the login page the operator cannot reach.

The fix calls it at BOOT, not in Phase 2. Phase 2 is not guaranteed to run:
that same upgrade had Phase 2 refused by the disk preflight, so a Phase-2-only
fix would still have left the box locked out. Boot always happens.

Run: docker exec intact_backend python /app/workdir/tests/test_preauth_login_migration_runs.py
"""

import inspect
import os
import re
import sys

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

APP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "modules", "backend", "app.py")
if not os.path.isfile(APP):                      # running from inside the image
    APP = "/app/app.py"
SRC = open(APP).read()


def _pos(needle, hay=None):
    h = hay if hay is not None else SRC
    i = h.find(needle)
    assert i != -1, f"anchor vanished from app.py: {needle!r}"
    return i


def test_boot_calls_the_migration():
    """The whole fix: it must be invoked at startup at all."""
    assert "migrate_basic_auth_to_app_login" in SRC, (
        "app.py no longer calls migrate_basic_auth_to_app_login at boot — a box "
        "upgraded from a pre-auth release will land with no credential and no "
        "way in through the UI")


def test_migration_runs_before_the_pending_upgrade_branch():
    """It must NOT be nested inside the pending/not-pending split. Phase 2 can
    be refused (disk preflight) and never run; boot still has to repair auth."""
    resume_branch = 'print(f"[STARTUP] Found pending upgrade'
    assert _pos("migrate_basic_auth_to_app_login") < _pos(resume_branch), (
        "the auth migration moved below the Phase-2 resume branch — a box "
        "whose Phase 2 was refused would stay locked out")


def test_migration_is_not_inside_a_pending_conditional():
    """Guard the indentation too: sitting under `if pending:`/`if not pending:`
    would reintroduce the same hole more subtly than reordering does."""
    line = next(l for l in SRC.splitlines()
                if "migrate_basic_auth_to_app_login(" in l and "import" not in l)
    indent = len(line) - len(line.lstrip())
    assert indent <= 12, (
        f"call is indented {indent} spaces — it looks nested inside a "
        f"conditional branch rather than running unconditionally at boot")


def test_failure_to_migrate_never_breaks_boot():
    """An appliance that cannot migrate must still start. A crash here would
    turn a login problem into a dead platform."""
    seg = SRC[_pos("migrate_basic_auth_to_app_login"):]
    seg = seg[:seg.find("if pending:")]
    assert "except Exception" in seg, (
        "the boot-time migration call is not wrapped in a try/except — an "
        "exception would abort backend startup")


def test_migration_is_idempotent_on_an_already_migrated_box():
    """Its trigger is the ABSENCE of first_login and it always writes that key,
    so every later boot is a cheap early return. Pinned because 'runs on every
    boot' is only safe while that holds."""
    from services.upgrade.intact import migrate_basic_auth_to_app_login as m
    body = inspect.getsource(m)
    assert "FIRST_LOGIN_ABSENT" in body, (
        "migration no longer keys off FIRST_LOGIN_ABSENT — running it on every "
        "boot is only safe while absence is the trigger")
    assert re.search(r"if flag != .*FIRST_LOGIN_ABSENT:\s*\n(?:\s*#.*\n)*\s*return",
                     body), (
        "migration no longer returns early when first_login is present")


def test_absent_first_login_means_login_not_setup():
    """The reason an unmigrated box is LOCKED OUT rather than merely open: no
    credential plus MODE_LOGIN is a door with no key. If this ever flips to
    MODE_SETUP the failure mode changes from lockout to land-grab, and the
    migration matters even more."""
    from services import auth_service
    body = inspect.getsource(auth_service.auth_mode)
    assert "MODE_LOGIN" in body.split("return")[-1], (
        "auth_mode() no longer falls through to MODE_LOGIN for an absent flag")


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
