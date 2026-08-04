"""A successful auth migration that nobody can see locks the operator out.

WHAT HAPPENED
-------------
On the 20260726 -> 20260803 upgrade the operator could not sign in. Nothing was
broken. intact-20260726 is a PRE-AUTH release -- `first_login` does not appear
in its config.yaml and the string does not appear anywhere in its backend code;
the appliance was gated by nginx Basic Auth. So the upgrade did exactly what
migrate_basic_auth_to_app_login() was written to do: recovered the existing
Basic Auth credential, hashed it into the new store, and wrote
first_login: false, deliberately NOT leaving a claimable setup page exposed on
the network.

The migration runs at backend BOOT -- it has to, because Phase 1 of an upgrade
executes the OLD code. So all of its output went to `docker logs intact_backend`
behind a [STARTUP] prefix. On the operator's upgrade log:

    grep -c "STARTUP"  ->  0

They were locked out of a working appliance by a correct security decision they
were never told about. The `first_login: true` they had seen in the release's
config.yaml is the PACKAGE's copy, which never overwrites the live one -- it
holds the box's secrets and is preserved on purpose.

So the fix is not to weaken the migration. It is to say, in the log the operator
is actually reading, who to sign in as and where the password lives.

Run: docker exec intact_backend python /app/workdir/tests/test_dashboard_login_is_reported.py
"""

import inspect
import os
import re
import sys
import types

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

import services.upgrade as up  # noqa: E402
from services.upgrade import intact  # noqa: E402

failures = []


def check(name, cond, detail=""):
    if cond:
        print(f"  PASS  {name}")
    else:
        failures.append(f"{name}: {detail}")
        print(f"  FAIL  {name}: {detail}")


class _Auth:
    """Stand-in for services.auth_service."""
    FIRST_LOGIN_TRUE = "true"
    FIRST_LOGIN_FALSE = "false"
    FIRST_LOGIN_ABSENT = "absent"
    FIRST_LOGIN_ERROR = "error"

    def __init__(self, flag, user="admin"):
        self._flag, self._user = flag, user

    def read_first_login(self):
        return self._flag

    def username(self):
        return self._user


def _report(flag, user="admin", workdir=None):
    """Run report_dashboard_login against a stubbed auth_service and return
    (lines, levels)."""
    svc = sys.modules.get("services")
    if svc is None:
        svc = types.ModuleType("services")
        sys.modules["services"] = svc
    prev = getattr(svc, "auth_service", None)
    svc.auth_service = _Auth(flag, user)
    sys.modules["services.auth_service"] = svc.auth_service
    prev_wd = intact.WORKDIR
    if workdir:
        intact.WORKDIR = workdir
    out = []
    try:
        intact.report_dashboard_login(
            logger=lambda m, l="info": out.append((m, l)))
    finally:
        intact.WORKDIR = prev_wd
        if prev is not None:
            svc.auth_service = prev
    return [m for m, _ in out], [l for _, l in out]


def _box_with_secret(tmpdir, value="x" * 32):
    sec = os.path.join(tmpdir, "modules", "nginx", "secrets")
    os.makedirs(sec, exist_ok=True)
    with open(os.path.join(sec, "nginx_basic_auth_password"), "w") as f:
        f.write(value + "\n")
    return tmpdir


def test_a_migrated_box_is_told_who_to_sign_in_as():
    """The exact case that locked the operator out: migration succeeded,
    first_login went to false, and the recovered secret is sitting on disk in
    a file the operator has never had a reason to open."""
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        lines, _ = _report("false", user="admin", workdir=_box_with_secret(d))
    body = "\n".join(lines)
    check("it names the username", "admin" in body, body)
    check("it says the password is unchanged",
          re.search(r"UNCHANGED|unchanged", body) is not None, body)
    check("it points at the file holding the secret",
          "nginx_basic_auth_password" in body, body)
    check("it gives a command that reads it",
          "cat " in body, body)


def test_a_box_without_the_basic_auth_file_is_not_sent_to_a_missing_path():
    """Boxes installed after the app login have no nginx Basic Auth secret.
    Telling those operators to cat a file that does not exist would send them
    chasing a red herring during a failed sign-in."""
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        lines, _ = _report("false", user="qa", workdir=d)
    body = "\n".join(lines)
    check("it still names the username", "qa" in body, body)
    check("it does not point at a nonexistent file",
          "nginx_basic_auth_password" not in body, body)


def test_it_never_prints_the_password_itself():
    """Upgrade logs get downloaded, pasted into tickets and attached to QA
    reports. The path is safe to print; the secret is not."""
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        sec = os.path.join(d, "modules", "nginx", "secrets")
        os.makedirs(sec)
        with open(os.path.join(sec, "nginx_basic_auth_password"), "w") as f:
            f.write("S3cr3tDoNotLeakThisValue00000000\n")
        lines, _ = _report("false", workdir=d)
    body = "\n".join(lines)
    check("the secret value never appears",
          "S3cr3tDoNotLeakThisValue00000000" not in body, body)
    check("but the path does", "nginx_basic_auth_password" in body, body)


def test_setup_mode_is_reported_as_urgent():
    """first_login: true means an unauthenticated, claimable setup page is
    being served right now. That is a warning, not a status line."""
    lines, levels = _report("true")
    body = "\n".join(lines)
    check("it says SETUP", "SETUP" in body, body)
    check("it is raised at warning level", "warning" in levels, str(levels))
    check("it says to act immediately",
          "IMMEDIATELY" in body or "immediately" in body, body)


def test_an_unreadable_config_is_not_reported_as_success():
    lines, levels = _report("error")
    check("unreadable config warns", "warning" in levels, str(levels))
    check("it does not claim a working login",
          "Sign in as" not in "\n".join(lines), str(lines))


def test_a_pre_auth_box_is_told_the_migration_has_not_run():
    """first_login absent is the 20260726 state. Saying nothing here is what
    produced the lockout."""
    lines, _ = _report("absent")
    body = "\n".join(lines)
    check("it explains the key is missing", "first_login" in body, body)
    check("it says when the migration runs",
          "backend start" in body or "next backend" in body, body)


def test_it_survives_auth_service_being_unimportable():
    """Reporting is a courtesy at the very end of a successful upgrade. It must
    never be able to turn one into a failure."""
    svc = sys.modules.get("services")
    prev = getattr(svc, "auth_service", None)
    if svc is not None and hasattr(svc, "auth_service"):
        del svc.auth_service
    sys.modules.pop("services.auth_service", None)
    out = []
    try:
        intact.report_dashboard_login(logger=lambda m, l="info": out.append(m))
        raised = False
    except Exception:
        raised = True
    finally:
        if prev is not None and svc is not None:
            svc.auth_service = prev
            sys.modules["services.auth_service"] = prev
    check("a missing auth_service does not raise", not raised, "it raised")


def test_the_finalizer_actually_calls_it():
    """A reporter nobody invokes is the bug, not the fix. Comments and
    docstrings are stripped first -- a previous test in this repo passed by
    matching prose in the comment that described the code."""
    src = inspect.getsource(up)
    src = re.sub(r'"""[\s\S]*?"""', '', src)
    src = re.sub(r"'''[\s\S]*?'''", '', src)
    src = "\n".join(l.split('#')[0] for l in src.splitlines())
    check("resume_upgrade_workflow calls report_dashboard_login",
          "report_dashboard_login(" in src,
          "no live call site outside comments/docstrings")


def test_it_reports_after_the_final_version_table():
    """Ordering is the whole point: the operator reads the end of the log. If
    this lands mid-run it scrolls away under the module output."""
    src = inspect.getsource(up)
    table = src.find("FINAL VERSION TABLE")
    call = src.find("report_dashboard_login(logger=log)")
    check("the login block follows the version table",
          table != -1 and call != -1 and call > table,
          f"table at {table}, call at {call}")


def test_the_migration_never_invents_a_password():
    """The lockout mechanism itself.

    The old code, finding nothing to recover, called
    ensure_nginx_basic_auth_secret() to GENERATE a random 32-character password,
    stored it as the login and marked setup complete. Since no shipped release
    ever had Basic Auth (auth_basic: 0 in 20260615, 0 in 20260726, 3 only in
    development), that branch ran on EVERY real appliance. A password the
    operator did not choose and cannot know is not a credential.

    Comments and docstrings are stripped first -- this file's own prose names
    the function, and a previous test in this repo passed by matching the
    comment that described the code rather than the code."""
    src = inspect.getsource(intact.migrate_basic_auth_to_app_login)
    src = re.sub(r'"""[\s\S]*?"""', '', src)
    src = "\n".join(l.split('#')[0] for l in src.splitlines())
    check("it never generates a password",
          "ensure_nginx_basic_auth_secret" not in src,
          "the generate-a-secret fallback is back")
    check("it does not read a secret off disk as a credential",
          "nginx_basic_auth_password" not in src,
          "it is recovering a password the operator never chose")


def test_setup_mode_is_the_default_outcome_for_a_pre_auth_box():
    """What the operator asked for: land on the setup page and choose the
    credentials yourself. With no operator-chosen password in config.yaml --
    the state of every real appliance -- first_login must end up true."""
    src = inspect.getsource(intact.migrate_basic_auth_to_app_login)
    src = re.sub(r'"""[\s\S]*?"""', '', src)
    src = "\n".join(l.split('#')[0] for l in src.splitlines())
    check("write_first_login(True) is the fall-through",
          "write_first_login(True)" in src, "the setup-page path is gone")
    check("False is reachable only from the config.yaml branch",
          src.index("write_first_login(False)") < src.index("write_first_login(True)")
          and "_read_dashboard_credentials" in src,
          "the carry-across path no longer guards the False write")


def test_an_operator_chosen_password_is_still_honoured():
    """dashboard.password in config.yaml is a real choice the operator made.
    Overriding it with a setup page would throw away a deliberate setting."""
    src = inspect.getsource(intact.migrate_basic_auth_to_app_login)
    src = re.sub(r'"""[\s\S]*?"""', '', src)
    src = "\n".join(l.split('#')[0] for l in src.splitlines())
    check("config.yaml dashboard.password is still read",
          "_read_dashboard_credentials" in src, "the carry-across path is gone")
    check("and still results in a stored credential",
          "set_credential(" in src, "nothing stores it any more")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            print(f"\n{name}")
            fn()
    print("\n" + ("FAILED: " + "; ".join(failures) if failures else "ALL PASSED"))
    sys.exit(1 if failures else 0)
