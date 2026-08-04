"""install.sh must repair the "configured but no credential" total lockout.

auth_service fails CLOSED when config.yaml says the dashboard login is already
set up (first_login: false) but no auth_password_hash is stored: it refuses every
login rather than falling open. That is the right call, but it means the operator
is locked out with no in-band way back — the only exit is knowing to set
first_login: true by hand on the host.

That state is easy to reach and gives no warning at install time:
  - restoring a config.yaml backup onto a fresh or wiped data/intact.db (exactly
    what happened on 2026-07-30 after a wipe-and-reinstall),
  - carrying config.yaml over to a rebuilt box,
  - any purge/restore that recreates the DB without the secrets table.

ensure_dashboard_login_is_reachable() detects it at the end of an install and
flips first_login back to true. Three properties have to hold, and each has
already bitten once:

  1. It must only ever fire when there is genuinely NO credential. If it fired
     on an inconclusive probe it would open a claimable setup page on a box with
     a perfectly good login.

  2. The credential probe must not read bare stdout. Importing services.storage
     prints "[STORAGE] ..." banners to STDOUT, so a plain capture returns banner
     text glued to the answer and the comparison silently never matches — the
     repair looks wired up and does nothing. Found by live-testing it.

  3. The config.yaml write must truncate IN PLACE. Docker bind-mounts that file
     BY INODE, so write-temp-then-rename leaves the container's /app/config.yaml
     pinned to the old bytes, reading first_login: false forever.

And the security property: this must NOT move into the app's runtime path. The
lockout counter must never auto-flip first_login, or an attacker fails 10 logins
on purpose to claim the setup page. An installer run is explicit and
operator-initiated; a login attempt is not.

Static assertions over install.sh + lib/modules.sh. No install performed.

Run: docker exec intact_backend python3 /app/workdir/tests/test_installer_repairs_locked_out_login.py
"""

import os
import re
import sys

REPO = os.environ.get("INTACT_PATH", "/app/workdir")
INSTALL_SH = os.path.join(REPO, "install.sh")
MODULES_SH = os.path.join(REPO, "lib", "modules.sh")
AUTH_SERVICE = os.path.join(REPO, "modules", "backend", "services", "auth_service.py")

FN = "ensure_dashboard_login_is_reachable"


def _read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _code_only(text):
    """Strip whole-line comments so prose about a construct never reads as the
    construct itself."""
    return "\n".join(ln for ln in text.splitlines()
                     if not ln.lstrip().startswith("#"))


def _fn_body():
    code = _read(MODULES_SH)
    start = code.index(f"{FN}() {{")
    # to the next top-level closing brace
    end = code.index("\n}\n", start)
    return _code_only(code[start:end])


# --- wiring --------------------------------------------------------------------


def test_the_repair_function_exists():
    assert f"{FN}() {{" in _read(MODULES_SH), \
        f"{FN} is gone — a restored config.yaml on a fresh DB locks the operator out"


def test_it_is_actually_called_by_the_installer():
    """An uncalled repair function is the same as no repair function."""
    calls = [ln for ln in _code_only(_read(INSTALL_SH)).splitlines()
             if re.search(rf'^\s*{FN}\s*$', ln)]
    assert calls, f"{FN} is defined but never called from install.sh"


def test_it_runs_after_the_backend_is_verified_up():
    """It asks the backend whether a credential exists, so the backend has to be
    running — and before the report, so a repair lands in the ATTENTION block
    rather than scrolling past."""
    code = _code_only(_read(INSTALL_SH))
    verify_at = code.index("verify_installation")
    call_at = code.index(f"\n    {FN}")
    report_at = code.index("print_installation_report")
    assert verify_at < call_at, \
        "the repair runs before verify_installation — the backend may be down"
    assert call_at < report_at, \
        "the repair runs after print_installation_report — it would not be reported"


# --- property 1: only fire on a definite "no credential" -----------------------


def test_it_only_acts_on_an_explicit_false():
    """Absent or true already means setup mode; acting on those is pointless and
    an absent key must not be read as false."""
    body = _fn_body()
    assert re.search(r'"\$first_login"\s*==\s*"False"', body), \
        "the guard no longer checks for an explicit false"
    assert "return 0" in body, "the function has no early-return guard at all"


def test_a_definite_no_credential_is_required_before_writing():
    """Inconclusive (backend down, import error, no sentinel) must be a no-op —
    otherwise a healthy login gets a claimable setup page opened next to it."""
    body = _fn_body()
    m = re.search(r'\[\[\s*"\$has_cred"\s*==\s*"([^"]+)"\s*\]\]\s*\|\|\s*return 0', body)
    assert m, ("the credential check no longer gates the write with a "
               "fail-safe early return")
    assert "no" in m.group(1), \
        f"the repair triggers on {m.group(1)!r}, which is not a 'no credential' answer"


# --- property 2: the probe must survive banner noise on stdout -----------------


def test_the_credential_probe_uses_a_sentinel_not_bare_stdout():
    """services.storage prints [STORAGE] banners to STDOUT. A bare capture glues
    them to the answer and the comparison never matches — silently disabling the
    repair while looking correct."""
    body = _fn_body()
    assert "INTACT_CRED:" in body, (
        "the credential probe no longer marks its answer with a sentinel; "
        "banner output on stdout will be captured as part of the value")
    assert re.search(r"grep\s+-o\s+'INTACT_CRED:", body), \
        "the probe does not extract its answer by sentinel"


# --- property 3: truncate in place ---------------------------------------------


def test_the_config_write_truncates_in_place():
    """config.yaml is bind-mounted BY INODE. Replacing the inode leaves the
    container reading the old content forever."""
    body = _fn_body()
    assert re.search(r'open\(p,\s*["\']w["\']\)', body), \
        "the config.yaml write no longer opens the file for truncation in place"
    for forbidden in ("os.replace", "os.rename", "shutil.move", "NamedTemporaryFile"):
        assert forbidden not in body, (
            f"the config.yaml write uses {forbidden} — that swaps the inode and "
            f"the bind-mounted /app/config.yaml goes stale")
    assert "sed -i" not in body, \
        "sed -i rewrites the file via a temp + rename, swapping the inode"


def test_it_edits_exactly_one_line():
    body = _fn_body()
    assert re.search(r'len\(hits\)\s*!=\s*1', body), \
        "the write no longer asserts it found exactly one first_login line"


# --- the security property ------------------------------------------------------


def test_the_app_never_auto_flips_first_login():
    """The whole reason this lives in the installer. If the runtime auth path
    could flip first_login, an attacker fails 10 logins deliberately to open a
    claimable setup page."""
    if not os.path.exists(AUTH_SERVICE):
        return
    code = _code_only(_read(AUTH_SERVICE))
    # Locate the lockout logic and assert it never writes the flag.
    for m in re.finditer(r'def (\w*lock\w*|\w*fail\w*)\(', code):
        start = m.start()
        chunk = code[start:start + 1500]
        assert "write_first_login(True)" not in chunk, (
            f"{m.group(1)} writes first_login=True — an attacker can force the "
            f"setup page by failing logins on purpose")


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
