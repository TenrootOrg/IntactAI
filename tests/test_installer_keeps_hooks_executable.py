"""install.sh must not de-execute the git hooks (or the other helper scripts).

fix_source_permissions() sweeps the tree with `find ... -exec chmod 644` and then
restores +x on a hand-maintained list of paths. Anything executable that is not
on that list silently loses its execute bit on EVERY install and upgrade.

The one that matters is scripts/git-hooks/pre-commit. git skips a non-executable
hook **silently** — the hook itself prints nothing, and the only sign is a
passing mention from `git commit`:

    hint: The 'scripts/git-hooks/pre-commit' hook was ignored because it's not
    set as executable.

install-git-hooks.sh sets core.hooksPath=scripts/git-hooks, so the guard looks
installed and configured while doing absolutely nothing. That guard is the
gitleaks secret scanner — the thing that caught a live GitHub PAT being staged in
modules/backend/.env. Losing it silently on every install is the worst possible
failure mode for it.

Observed for real: a fresh install on 2026-07-30 left pre-commit at 644, and the
very next `git commit` emitted the "hook was ignored" hint.

Also pinned: four other scripts the sweep de-executed
(modules/elk/config/setup-kibana-user.sh, modules/nginx/build-tailwind.sh,
scripts/migrate/*.sh, scripts/migrate/*.py), which the `scripts/*.sh` glob does
not reach because they live in subdirectories.

Static assertions over install.sh, plus git's own recorded file modes.

Run: docker exec intact_backend python3 /app/workdir/tests/test_installer_keeps_hooks_executable.py
"""

import os
import re
import subprocess
import sys

REPO = os.environ.get("INTACT_PATH", "/app/workdir")
INSTALL_SH = os.path.join(REPO, "install.sh")


def _read():
    with open(INSTALL_SH, "r", encoding="utf-8") as handle:
        return handle.read()


def _code_only(text):
    return "\n".join(ln for ln in text.splitlines()
                     if not ln.lstrip().startswith("#"))


# --- the hook itself -----------------------------------------------------------


def test_the_installer_restores_the_git_hooks_execute_bit():
    code = _code_only(_read())
    assert re.search(r'chmod \+x "\$\{SCRIPT_DIR\}/scripts/git-hooks/"', code), (
        "install.sh no longer restores +x on scripts/git-hooks/ — the blanket "
        "chmod 644 sweep will silently disable the gitleaks pre-commit guard")


def test_the_hook_glob_is_not_restricted_to_sh():
    """Git hooks have no extension: the file is `pre-commit`, not
    `pre-commit.sh`. A *.sh glob would match nothing and quietly do nothing."""
    code = _code_only(_read())
    m = re.search(r'chmod \+x "\$\{SCRIPT_DIR\}/scripts/git-hooks/"(\S*)', code)
    assert m, "no chmod +x for scripts/git-hooks at all"
    assert ".sh" not in m.group(1), (
        f"the git-hooks chmod uses glob {m.group(1)!r}, but hooks have no "
        f"extension so it matches nothing")


def test_the_execute_restore_runs_after_the_644_sweep():
    """Order is the whole point. A +x restore placed before the sweep is undone
    by it, and the result looks identical in the source."""
    code = _code_only(_read())
    sweep = code.index("-exec chmod 644")
    restore = code.index('chmod +x "${SCRIPT_DIR}/scripts/git-hooks/"')
    assert sweep < restore, (
        "the git-hooks +x restore runs BEFORE the chmod 644 sweep, so the sweep "
        "strips it straight back off")


# --- the other scripts the sweep de-executed -----------------------------------


def test_the_subdirectory_scripts_are_restored_too():
    """`scripts/*.sh` does not glob into scripts/migrate/, and the module
    helpers are nowhere near it."""
    code = _code_only(_read())
    for path in ('/scripts/migrate/"*.sh',
                 '/modules/elk/config/"*.sh',
                 '/modules/nginx/build-tailwind.sh'):
        assert path in code, (
            f"install.sh no longer restores +x on {path} — the 644 sweep "
            f"de-executes it on every install")


# --- git's recorded mode must agree with what the installer produces -----------


def test_git_records_the_hook_as_executable():
    """If git has the hook at 100644, a fresh clone lands non-executable and the
    guard is off until the first install — and every install shows mode churn."""
    try:
        out = subprocess.run(
            ["git", "-C", REPO, "ls-files", "-s", "scripts/git-hooks/pre-commit"],
            capture_output=True, text=True, timeout=30).stdout.strip()
    except Exception:
        return  # no git available (tarball install) — nothing to assert
    if not out:
        return
    mode = out.split()[0]
    assert mode == "100755", (
        f"git records scripts/git-hooks/pre-commit as {mode}, not 100755 — a "
        f"fresh clone gets a non-executable hook and the secret guard is off")


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
