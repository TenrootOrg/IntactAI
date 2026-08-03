"""An upgrade signs the operator out. Nothing told them that.

WHAT THE OPERATOR SAW
---------------------
Mid-upgrade the backend restarts to load the new code. Every session dies with
it, and on a pre-auth box the auth migration additionally lands them on the
SETUP page. From the chair: the progress view freezes, an unexpected login
screen appears, and after signing in the page has nothing to show -- the run id
lived only in the frontend store, which the reload destroyed.

Reported as "it's stuck at some point". The run in question completed normally:

    status: completed | progress: 100
    Post-upgrade health: OK (29 checks, 2.2s)
    PHASE 2 COMPLETE - Status: success

A correct upgrade that looks like a hang is a bug in the telling, not the doing.
Two fixes: warn BEFORE the screen changes, and make the running run
discoverable from the SERVER so the page can reattach itself.

Run: docker exec intact_backend python /app/workdir/tests/test_upgrade_signout_is_explained.py
"""

import inspect
import os
import re
import sys

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

import services.upgrade as up  # noqa: E402

REPO = os.environ.get("INTACT_PATH", "/app/workdir")
failures = []


def check(name, cond, detail=""):
    if cond:
        print(f"  PASS  {name}")
    else:
        failures.append(f"{name}: {detail}")
        print(f"  FAIL  {name}: {detail}")


def _code(obj):
    """Source with comments and docstrings stripped -- this file's own prose
    names every string it asserts on, and a test in this repo has already
    passed by matching the comment that described the code."""
    src = inspect.getsource(obj)
    src = re.sub(r'"""[\s\S]*?"""', '', src)
    return "\n".join(l.split('#')[0] for l in src.splitlines())


def test_the_operator_is_warned_before_the_screen_changes():
    src = _code(up)
    check("it says they will need to sign in again",
          "SIGN IN AGAIN" in src, "no warning before the screen changes")
    check("it explains WHY, not just what",
          "WHY:" in src and "no session to carry across" in src,
          "'sign in again' with no reason reads as a fault")
    check("it names the cause: this release adds a login",
          "adds a dashboard login" in src,
          "the operator cannot tell an intended change from a bug")
    check("it says the upgrade keeps running",
          "KEEPS RUNNING" in src, "nothing tells them it continues")
    check("it says reloading cannot interrupt the run",
          "cannot interrupt" in src,
          "operators avoid touching a screen they think is load-bearing")
    check("it explains the SETUP page",
          "SETUP page" in src,
          "a pre-auth box gets an unexplained setup screen")


def test_the_warning_comes_before_the_restart_is_scheduled():
    """After the fact is not a warning. It has to be the last thing they read."""
    src = inspect.getsource(up)
    warn = src.find("SIGN IN AGAIN")
    restart = src.find("schedule_backend_restart(run_id=run_id", warn if warn > 0 else 0)
    check("the warning precedes schedule_backend_restart",
          warn != -1 and restart != -1 and warn < restart,
          f"warn at {warn}, restart at {restart}")


def test_every_restart_site_warns():
    """There are two of them. One warned and one silent is the same bug for
    whichever operator hits the silent path."""
    src = inspect.getsource(up)
    sites = src.count("schedule_backend_restart(run_id=run_id")
    warns = src.count("SIGN IN AGAIN")
    check("all restart sites warn", warns >= sites,
          f"{sites} restart sites, {warns} warnings")


def test_the_running_run_is_discoverable_from_the_server():
    """The frontend cannot remember across a reload it does not survive."""
    p = os.path.join(REPO, "modules/backend/routes/upgrade_routes.py")
    src = open(p).read()
    check("an active-run endpoint exists",
          "/api/upgrade/active" in src, "nothing to reattach to")
    body = src[src.find("/api/upgrade/active"):]
    for state in ("running", "awaiting_restart"):
        check(f"it counts '{state}' as active", f"'{state}'" in body,
              f"a run in {state} would look finished")


def test_the_frontend_reattaches_on_load():
    p = os.path.join(REPO, "modules/nginx/html/js/stores/workflows.js")
    src = open(p).read()
    src_nc = "\n".join(l.split('//')[0] for l in src.splitlines())
    check("the store can reattach", "reattachToActiveRun" in src_nc,
          "no reattach path")
    check("and it is actually called", src_nc.count("reattachToActiveRun") >= 2,
          "defined but never invoked")
    check("it asks the server", "/api/upgrade/active" in src_nc,
          "not wired to the endpoint")


def test_reattach_can_never_break_the_page():
    """It runs on every dashboard load. A throw here would take out the whole
    workflows view to solve a cosmetic problem."""
    p = os.path.join(REPO, "modules/nginx/html/js/stores/workflows.js")
    src = open(p).read()
    fn = src[src.find("async reattachToActiveRun"):]
    fn = fn[:fn.find("\n        async load()")]
    check("it is wrapped in try/catch", "try {" in fn and "catch" in fn,
          "an exception would break the dashboard")
    check("it does not hijack an open modal", "this.modalOpen" in fn,
          "it would reopen over whatever the operator was reading")


def test_the_freeze_point_itself_tells_you_to_refresh():
    """The operator's screenshot ended at "Recreating backend -> ...". That is
    the last line that can reach a page still talking to the old backend, so the
    view freezes there -- on a run that completed 100% with zero warnings. A
    refresh instruction anywhere later is a message nobody receives.

    Asserted against prepare_recreate_handoff specifically -- the function that
    actually writes that line -- not the whole module, so it cannot be satisfied
    by some other function's text."""
    src = _code(up.prepare_recreate_handoff)
    check("it says the log stops updating here",
          "STOPS UPDATING HERE" in src, "the freeze is unexplained")
    check("it says to refresh", "REFRESH THE PAGE" in src and "Ctrl+Shift+R" in src,
          "no action given")
    check("it says refreshing cannot interrupt the run",
          "cannot interrupt" in src,
          "operators will not touch a screen they think is load-bearing")
    check("it promises the log continues after the refresh",
          "reopens where it left off" in src, "no reason to bother refreshing")


def test_the_refresh_notice_is_the_last_thing_logged():
    """Ordering is the entire point. Printed before the recreate line it scrolls
    away; printed after the spawn it never arrives."""
    src = inspect.getsource(up.prepare_recreate_handoff)
    recreate = src.find("Recreating backend ->")
    notice = src.find("STOPS UPDATING HERE")
    check("the notice follows the recreate line",
          recreate != -1 and notice != -1 and notice > recreate,
          f"recreate at {recreate}, notice at {notice}")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            print(f"\n{name}")
            fn()
    print("\n" + ("FAILED: " + "; ".join(failures) if failures else "ALL PASSED"))
    sys.exit(1 if failures else 0)
