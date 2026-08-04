"""The auth audit log must be created 0600, not merely chmodded at install.

Found by the QA harness's post-install permission sweep on a freshly installed
box: every other hardened file was 0600, and data/auth/audit.jsonl was 0644
root:root.

The cause is an ordering one, which is why no static test caught it.
install.sh chmods the file to 0600 during the install. But the file is created
on the FIRST AUTH EVENT — a login, a setup, a lockout — which is always after
the install has finished. `open(path, "a")` creates with the process umask, and
the backend container runs as root with umask 022, so the file was recreated
0644 within seconds of the box coming up. The hardening was real, and reliably
undone.

What it exposes: usernames, source IPs and user agents for every login, setup
and lockout. Not passwords, but an attacker-useful map of who administers the
appliance and from where — readable by any account on the host.

The fix creates the file with an explicit mode via os.open, and repairs an
existing 0644 file on the next write so boxes installed before the fix do not
stay wrong forever.

Run: python3 tests/test_audit_log_is_created_0600.py
"""

import os
import re
import sys
import tempfile

REPO = os.environ.get("INTACT_PATH") or os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))
AUTH_SERVICE = os.path.join(REPO, "modules", "backend", "services",
                            "auth_service.py")


def _source():
    with open(AUTH_SERVICE, encoding="utf-8") as fh:
        return fh.read()


def _strip_comments(src):
    """Docstrings and comments in this file legitimately discuss the very
    patterns being searched for. Matching those would make the test pass on its
    own explanation."""
    src = re.sub(r'""".*?"""', "", src, flags=re.S)
    src = re.sub(r"'''.*?'''", "", src, flags=re.S)
    return "\n".join(l for l in src.splitlines()
                     if not l.lstrip().startswith("#"))


# --- the code path -------------------------------------------------------


def test_the_audit_log_is_not_opened_with_a_bare_append():
    """`open(AUDIT_LOG, "a")` is the bug. It creates with the umask."""
    code = _strip_comments(_source())
    assert not re.search(r"open\(\s*AUDIT_LOG\s*,\s*['\"]a", code), \
        "audit.jsonl is opened with a bare append again, so it will be " \
        "created 0644 by the root backend container"


def test_the_audit_log_is_created_with_an_explicit_mode():
    code = _strip_comments(_source())
    assert "os.open(AUDIT_LOG" in code, \
        "audit.jsonl is no longer created via os.open with an explicit mode"
    assert "0o600" in code, "the explicit 0600 mode is gone"


def test_an_existing_world_readable_log_is_repaired():
    """Boxes installed before the fix already carry a 0644 file. Without a
    repair they stay wrong forever, because the file is only created once."""
    code = _strip_comments(_source())
    assert re.search(r"os\.chmod\(\s*AUDIT_LOG\s*,\s*0o600", code), \
        "an existing 0644 audit log is never repaired"


# --- behaviour -----------------------------------------------------------


def _writer_from_source():
    """Exercise the real function with AUTH_DIR pointed at a temp dir.

    Imported rather than reimplemented: a copy of the logic here would keep
    passing after the real one regressed.
    """
    tmp = tempfile.mkdtemp()
    os.environ["INTACT_AUTH_DIR"] = tmp
    sys.path.insert(0, os.path.join(REPO, "modules", "backend"))
    for mod in list(sys.modules):
        if mod.startswith("services.auth_service"):
            del sys.modules[mod]
    from services import auth_service                     # noqa: E402
    return auth_service, tmp


def test_a_fresh_log_lands_0600_under_a_022_umask():
    try:
        auth_service, tmp = _writer_from_source()
    except Exception as exc:                              # noqa: BLE001
        print(f"  (skipped: backend deps unavailable — {exc})")
        return

    old = os.umask(0o022)
    try:
        auth_service.audit("qa_test_event")
        path = auth_service.AUDIT_LOG
        assert os.path.exists(path), "no audit log was written"
        mode = os.stat(path).st_mode & 0o777
        assert mode == 0o600, \
            f"audit log created {oct(mode)} under umask 022 — the exact " \
            f"failure seen on a freshly installed box"
    finally:
        os.umask(old)


def test_an_existing_0644_log_is_tightened_on_the_next_write():
    try:
        auth_service, tmp = _writer_from_source()
    except Exception as exc:                              # noqa: BLE001
        print(f"  (skipped: backend deps unavailable — {exc})")
        return

    path = auth_service.AUDIT_LOG
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("{}\n")
    os.chmod(path, 0o644)

    auth_service.audit("qa_test_event")
    mode = os.stat(path).st_mode & 0o777
    assert mode == 0o600, \
        f"a pre-existing 0644 audit log stayed {oct(mode)}; boxes installed " \
        f"before the fix would never be repaired"


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
