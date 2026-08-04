"""Secret files must end up 0600 on BOTH the install and the upgrade path.

install.sh's fix_source_permissions() sweeps the tree with
`find ... -exec chmod 644` and exempts only a path-literal list of nine
patterns. That list has no entry for data/velociraptor/, data/intact.db,
modules/*/config/ or data/auth/ — so the installer was ACTIVELY resetting these
to world-readable on every install and every upgrade:

  data/velociraptor/server.config.yaml  3 PEM private keys, incl. the CA that
                                        signs every enrolled endpoint. Readable
                                        => mint client certs, impersonate the
                                        server, own the fleet.
  data/velociraptor/api.config.yaml     API client key => arbitrary VQL anywhere
  data/intact.db (+ -wal/-shm)          the `secrets` table is PLAINTEXT and
                                        holds auth_session_key, which signs the
                                        dashboard cookie. Readable => forge a
                                        session, bypassing the login, the
                                        lockout and the audit log.
  modules/timesketch/config/*.conf      live SECRET_KEY + OPENSEARCH_PASSWORD
  data/auth/audit.jsonl                 login / lockout history

Two properties are pinned here, and the second is the one that will actually
break:

  1. install.sh hardens them AFTER the 644 sweep. Before it, the sweep undoes
     the hardening and the source diff looks identical either way.

  2. The bash list and the Python list are THE SAME SET. The in-UI upgrade never
     runs install.sh (services/upgrade/intact.py: "install.sh's bash bootstrap
     never runs again"), so each path hardens independently. The realistic
     failure is someone adding a secret to one side only — upgraded boxes then
     silently stay at 644, and nothing else would catch it.

Also guarded: IRIS secrets must NOT appear in either list. install.sh chmods
them 600 while the upgrade chmods them 644 on purpose (iris.py:399-423), because
iris_app runs as nobody/65534 and cannot read a root-owned 0600 secret — it then
reads an empty password and crashloops. Reconciling that is a separate ticket;
pulling IRIS in here would reintroduce the crash.

Note git cannot enforce any of this: git stores only 100644/100755, and all
these files are gitignored runtime artifacts. Only code running on the box can
set the mode, which is why both paths must implement it.

Static assertions + a live mode check when the files exist.

Run: docker exec intact_backend python3 /app/workdir/tests/test_secret_files_are_not_world_readable.py
"""

import os
import re
import sys

REPO = os.environ.get("INTACT_PATH", "/app/workdir")
INSTALL_SH = os.path.join(REPO, "install.sh")
BASE_PY = os.path.join(REPO, "modules", "backend", "services", "upgrade", "base.py")
UPGRADE_INIT = os.path.join(REPO, "modules", "backend", "services", "upgrade", "__init__.py")


def _read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _code_only(text):
    return "\n".join(ln for ln in text.splitlines()
                     if not ln.lstrip().startswith("#"))


def _bash_paths():
    """Paths inside install.sh's shared-secret-hardening block.

    Delimited by explicit markers rather than by grepping every `chmod 600` in
    the file: install.sh legitimately hardens other things (config.yaml, the
    azure certs, the IRIS root CA key) whose modes are set elsewhere in the
    upgrade path, and folding those into the parity check would compare two
    sets that were never meant to match.
    """
    code = _read(INSTALL_SH)          # NOT _code_only: the markers are comments
    start = code.index("BEGIN shared-secret-hardening")
    end = code.index("END shared-secret-hardening")
    return set(re.findall(r'chmod 600 "\$\{SCRIPT_DIR\}/([^"]+)"', code[start:end]))


def _python_paths():
    """Contents of _SECRET_PATHS_0600 in base.py."""
    m = re.search(r'_SECRET_PATHS_0600 = \((.*?)\n\)', _read(BASE_PY), re.S)
    assert m, "_SECRET_PATHS_0600 not found in base.py"
    return {q for q in re.findall(r'"([^"]+)"', m.group(1))}


# --- property 1: order ---------------------------------------------------------


def test_install_sh_hardens_after_the_644_sweep():
    """A hardening block placed before the sweep is silently undone by it."""
    code = _code_only(_read(INSTALL_SH))
    sweep = code.index("-exec chmod 644")
    first = code.index('chmod 600 "${SCRIPT_DIR}/data/velociraptor/server.config.yaml"')
    assert sweep < first, (
        "install.sh hardens the secret files BEFORE the chmod 644 sweep, so the "
        "sweep resets them straight back to world-readable")


# --- property 2: the two paths agree ------------------------------------------


def test_the_two_code_paths_harden_the_same_files():
    """THE test. A fresh install and an in-UI upgrade must leave a box in the
    same state; they share no code, so only this keeps them in step."""
    bash, py = _bash_paths(), _python_paths()
    assert bash, "install.sh no longer chmod 600s any secret file"
    assert py, "_SECRET_PATHS_0600 is empty"
    assert bash == py, (
        "install.sh and the Python upgrade path harden DIFFERENT files — a box "
        "upgraded via the UI would not match a freshly installed one.\n"
        f"  only in install.sh: {sorted(bash - py)}\n"
        f"  only in base.py   : {sorted(py - bash)}")


def test_every_known_secret_is_covered():
    """Guard against the set being trimmed to make the parity test pass."""
    for required in ("data/velociraptor/server.config.yaml",
                     "data/velociraptor/api.config.yaml",
                     "data/intact.db",
                     "modules/timesketch/config/timesketch.conf"):
        assert required in _python_paths(), f"{required} is no longer hardened"


def test_the_sqlite_sidecars_are_hardened_too():
    """-wal and -shm carry the same rows as the DB and are recreated by SQLite,
    so hardening intact.db alone leaks the secrets table anyway."""
    py = _python_paths()
    for side in ("data/intact.db-wal", "data/intact.db-shm"):
        assert side in py, f"{side} is not hardened; it holds the same rows as intact.db"


# --- the upgrade hook must actually run ---------------------------------------


def test_the_upgrade_actually_calls_the_hardening():
    """An uncalled function is the same as no function."""
    code = _code_only(_read(UPGRADE_INIT))
    assert "harden_secret_permissions" in code, \
        "the upgrade flow never references harden_secret_permissions"
    assert re.search(r'^\s*harden_secret_permissions\(', code, re.MULTILINE), \
        "harden_secret_permissions is imported but never called"


def test_the_hardening_cannot_fail_an_upgrade():
    """A chmod failure must not turn a clean upgrade into a failed one."""
    code = _read(UPGRADE_INIT)
    at = code.index("harden_secret_permissions(logger=log)")
    window = code[max(0, at - 400):at + 200]
    assert "try:" in window and "except" in window, \
        "the hardening call is not wrapped in try/except; a chmod error would " \
        "abort the upgrade"


# --- IRIS must stay out --------------------------------------------------------


def test_iris_secrets_are_not_hardened_here():
    """install.sh sets IRIS secrets 600, the upgrade sets them 644 on purpose
    (iris.py:399-423) because iris_app runs as nobody/65534. Pulling them into
    this list would reintroduce the documented crashloop."""
    for name, paths in (("install.sh", _bash_paths()), ("base.py", _python_paths())):
        bad = [p for p in paths if "iris" in p.lower()]
        assert not bad, (
            f"{name} hardens IRIS paths {bad} — iris_app runs as uid 65534 and "
            f"cannot read a root-owned 0600 secret; this crashloops it")


# --- live check ----------------------------------------------------------------


def test_the_files_are_actually_0600_on_this_box():
    """Skips cleanly where a file does not exist (not every deployment has all
    of them). Uses a mask so ANY group/other bit fails, not just 644."""
    bad = []
    for rel in sorted(_python_paths()):
        path = os.path.join(REPO, rel)
        if not os.path.exists(path):
            continue
        mode = os.stat(path).st_mode & 0o777
        if mode & 0o077:
            bad.append(f"{rel} is {oct(mode)}")
    assert not bad, "secret files readable beyond their owner: " + "; ".join(bad)



# --- the compose files require these secrets, so provisioning must be unconditional


def test_env_file_secrets_are_provisioned_outside_the_per_module_upgrades():
    """_upgrade_noop_module() SKIPS a module whose version pins did not change,
    but refresh_module_compose_file() runs for every sidecar on every upgrade.
    So a release shipping the new Portainer/Timesketch compose files without
    bumping those pins would write a compose declaring
    `env_file: ./secrets/agent.env` and `./secrets/postgres.env` onto a box that
    has neither -- and the next `docker compose up` dies with "env file not
    found". Upgrading from intact-20260726 is exactly that case.

    Both generators must therefore run UNCONDITIONALLY -- never inside a branch
    that a version no-op can skip.

    They used to be asserted to live in the upgrade's final phase. That was one
    way to be unconditional, but it put them AFTER the module loop whose
    compose-up consumes them, which broke a first-time install: the secret did
    not exist yet when Timesketch's `docker compose up` ran, and the module was
    reported MODULE_FAILED inside a run that still said `completed` (2026-08-02,
    installing Timesketch onto a backend-only intact-20260726 box).

    So the requirement is stronger than "final phase": unconditional AND before
    the loop. Both helpers are idempotent no-ops once their secret exists, so
    running early costs nothing and cannot rotate a live credential.
    """
    # Scope to resume_upgrade_workflow. __init__.py has THREE module loops (the
    # online path, the Phase-2 resume, the offline apply); anchoring on the
    # first occurrence of each pattern silently compared positions in two
    # different functions.
    whole = _read(UPGRADE_INIT)
    body = whole[whole.index("def resume_upgrade_workflow("):]
    loop = body.index("for module_name in upgrade_order:")

    # Both are wired through one provisioning block. Locate THAT, not the bare
    # names -- the names also appear in the import line at the top of the file,
    # which is deeply indented and would fail the nesting check for no reason.
    block = body.index('for _label, _fn, _mod in (')
    for name in ("_ensure_agent_secret", "_ensure_ts_pg_password"):
        assert name in body, f"{name} is not wired into the upgrade flow"
        assert name in body[block:loop], (
            f"{name} is not in the provisioning block that runs before the "
            f"module loop — a first-time install of that module composes up "
            f"before its secret exists")

    assert block < loop, (
        "the secret provisioning block moved to or below the module loop")
    line = body[:block].rsplit("\n", 1)[-1]
    assert len(line) - len(line.lstrip()) <= 4, (
        "the provisioning block looks nested inside a conditional — it must "
        "run for every upgrade, including ones where the module is a no-op")


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
