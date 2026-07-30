"""install.sh must harden the code it sources BEFORE it sources it.

The installer runs as root and `source`s six lib/*.sh files at script-load
time (install.sh:~80). fix_source_permissions() sets sane modes across the whole
tree — but it is called from main(), hundreds of lines later. So for the entire
window between extraction and main(), a group/world-writable lib/*.sh is a local
root-escalation path: anyone who can write there gets their code run as root.

This is not theoretical. actions/upload-artifact strips every Unix mode bit from
the release zip, so the extracted tree's permissions come from the target box's
umask. On a umask-000 host (common on Vagrant/dev VMs) a fresh extract lands as
0777 dirs / 0666 files — verified from a real screenshot of an extracted release.
On a umask-022 host the same zip looks fine, which is why this stayed latent.

Two fixes are pinned here:

  1. `umask 022` early enough that it also covers LOG_FILE. The install log is
     created by later redirects and carries command output that has leaked
     credentials before, so it must not be created world-writable.

  2. A scoped `chmod go-w` on install.sh + lib/*.sh + scripts/*.sh, placed above
     the source statements.

Both are easy to break by reordering, and the failure is silent — the installer
works fine either way on a normal umask-022 box. Hence static assertions on
ORDER, not just presence.

Two things this must also keep true, both easy to get wrong:

  - The pre-source block cannot use log_info/log_warn. lib/common.sh is not
    sourced yet, so those functions do not exist and the call would be a no-op
    at best.
  - It must NOT abort on failure. On a vboxsf/9p/NTFS mount chmod is a silent
    no-op and everything is forced 0777; failing closed there would refuse to
    install on exactly the test VMs that exhibit the problem.

Static assertions over install.sh. No install performed.

Run: docker exec intact_backend python3 /app/workdir/tests/test_installer_hardens_before_sourcing.py
"""

import os
import re
import sys

REPO = os.environ.get("INTACT_PATH", "/app/workdir")
INSTALL_SH = os.path.join(REPO, "install.sh")


def _read():
    with open(INSTALL_SH, "r", encoding="utf-8") as handle:
        return handle.read()


def _lines():
    return _read().splitlines()


def _first_line_matching(pattern):
    """1-indexed line number of the first line matching `pattern`, or None.
    Whole-line comments are skipped so prose about a construct never counts as
    the construct itself."""
    rx = re.compile(pattern)
    for i, ln in enumerate(_lines(), start=1):
        if ln.lstrip().startswith("#"):
            continue
        if rx.search(ln):
            return i
    return None


# --- umask ---------------------------------------------------------------------


def test_umask_is_set_at_all():
    at = _first_line_matching(r'^\s*umask\s+0?22\b')
    assert at, ("install.sh does not set a umask, so every file it creates "
                "inherits the operator's — world-writable on a umask-000 box")


def test_umask_precedes_the_log_file_definition():
    """LOG_FILE is created by later redirects; if the umask lands after it the
    install log itself can be world-writable, and it carries command output."""
    umask_at = _first_line_matching(r'^\s*umask\s+0?22\b')
    log_at = _first_line_matching(r'^\s*LOG_FILE=')
    assert umask_at and log_at, "could not locate umask and LOG_FILE"
    assert umask_at < log_at, (
        f"umask is set at line {umask_at}, after LOG_FILE at {log_at} — the "
        f"install log would be created with the operator's umask")


def test_umask_precedes_every_source():
    umask_at = _first_line_matching(r'^\s*umask\s+0?22\b')
    first_source = _first_line_matching(r'^\s*source\s')
    assert umask_at and first_source, "could not locate umask and the first source"
    assert umask_at < first_source, (
        f"umask at line {umask_at} runs after the first source at {first_source}")


# --- the pre-source hardening --------------------------------------------------


def _hardening_lines():
    """Line numbers of the scoped chmod go-w calls."""
    return [i for i, ln in enumerate(_lines(), start=1)
            if not ln.lstrip().startswith("#")
            and re.search(r'chmod\s+go-w', ln)]


def test_the_code_is_hardened_before_it_is_sourced():
    hardening = _hardening_lines()
    first_source = _first_line_matching(r'^\s*source\s+"\$\{SCRIPT_DIR\}/lib/')
    assert hardening, ("install.sh no longer hardens install.sh/lib/scripts "
                       "before sourcing — a writable lib/*.sh is run as root")
    assert first_source, "could not find the lib/*.sh source statements"
    assert max(hardening) < first_source, (
        f"the chmod go-w calls (lines {hardening}) run at or after the first "
        f"lib source (line {first_source}); the sourcing is unprotected")


def test_all_three_targets_are_covered():
    """install.sh itself, lib/*.sh, and scripts/*.sh are all executed as root."""
    body = "\n".join(ln for ln in _lines() if not ln.lstrip().startswith("#"))
    for target in (r'\$\{SCRIPT_DIR\}/install\.sh',
                   r'\$\{SCRIPT_DIR\}"?/lib/\*\.sh',
                   r'\$\{SCRIPT_DIR\}"?/scripts/\*\.sh'):
        assert re.search(r'chmod\s+go-w\s+"?' + target, body), \
            f"chmod go-w does not cover {target}"


def test_the_hardening_stays_scoped():
    """A blanket `chmod -R` over SCRIPT_DIR would also hit data/,
    client_installers/ and modules/timesketch/config/ — writable bind mounts
    holding live container-written files. install.sh re-runs on every upgrade, so
    that would strip group-write from a populated appliance."""
    body = "\n".join(ln for ln in _lines() if not ln.lstrip().startswith("#"))
    bad = re.findall(r'chmod\s+(?:-R|--recursive)\s+[^\n]*\$\{SCRIPT_DIR\}"?\s*$',
                     body, re.MULTILINE)
    assert not bad, (
        f"a recursive chmod over SCRIPT_DIR was reintroduced: {bad} — this hits "
        f"data/ and the writable bind mounts, not just the executable code")


def test_go_w_not_a_mode_number():
    """`chmod 644` would strip the execute bit; `go-w` preserves it. The later
    chmod +x in fix_source_permissions relies on this block not clobbering it."""
    body = "\n".join(ln for ln in _lines() if not ln.lstrip().startswith("#"))
    first_source = _first_line_matching(r'^\s*source\s+"\$\{SCRIPT_DIR\}/lib/')
    pre = "\n".join(ln for ln in _lines()[:first_source - 1]
                    if not ln.lstrip().startswith("#"))
    numeric = re.findall(r'chmod\s+[0-7]{3,4}\s', pre)
    assert not numeric, (
        f"the pre-source block uses a numeric mode {numeric}; that strips the "
        f"execute bit off lib/*.sh and scripts/*.sh — use go-w")


# --- constraints on the pre-source region --------------------------------------


def _pre_source_region():
    first_source = _first_line_matching(r'^\s*source\s+"\$\{SCRIPT_DIR\}/lib/')
    start = min(_hardening_lines())
    return "\n".join(ln for ln in _lines()[start - 1:first_source - 1]
                     if not ln.lstrip().startswith("#"))


def test_the_pre_source_block_does_not_use_the_logging_helpers():
    """log_info/log_warn come from lib/common.sh, which is not sourced yet."""
    region = _pre_source_region()
    used = re.findall(r'\blog_(?:info|warn|error|success)\b', region)
    assert not used, (
        f"the pre-source block calls {set(used)}, but lib/common.sh has not been "
        f"sourced yet — those functions do not exist at that point")


def test_the_hardening_does_not_abort_the_install():
    """On a vboxsf/9p/NTFS mount chmod is a silent no-op and everything is 0777.
    Failing closed would refuse to install on exactly those VMs."""
    region = _pre_source_region()
    assert not re.search(r'^\s*exit\s+[1-9]', region, re.MULTILINE), (
        "the pre-source hardening exits non-zero on failure; on a filesystem "
        "that ignores chmod this makes the installer unusable")


def test_it_still_warns_when_chmod_did_not_take():
    """Silently continuing would hide a live root-escalation path."""
    region = _pre_source_region()
    assert re.search(r'-perm\s+/0?22', region), (
        "nothing checks whether lib/*.sh is still group/world-writable after "
        "the chmod, so a no-op chmod passes unnoticed")
    assert re.search(r'WARNING', region), \
        "the still-writable case produces no visible warning"


# --- the late sweep must survive unchanged -------------------------------------


def test_fix_source_permissions_still_exists_and_still_hardens_config_yaml():
    """Both changes are additive. If this regressed, the real hardening is gone
    and the pre-source block only covers executable code."""
    body = _read()
    assert "fix_source_permissions()" in body, \
        "fix_source_permissions was removed"
    assert re.search(r'chmod 600 "\$\{SCRIPT_DIR\}/config\.yaml"', body), \
        "install.sh no longer chmods 600 config.yaml"


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
