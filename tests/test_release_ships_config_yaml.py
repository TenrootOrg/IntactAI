"""The release package must ship a ready-to-edit, secret-free config.yaml.

config.yaml is gitignored (it holds options.github_token — a real ghp_ PAT —
plus the dashboard login and every module password), so a release built from a
clean tag checkout contained only config.yaml.example. Whoever extracted the
package therefore had no config.yaml to edit before running install.sh, and
install.sh's own "review it before continuing" advice was impossible to follow.

The packager now writes the template out AS config.yaml.

The second half matters more than the first. package.py copies the WHOLE repo
into source/intact/, and while CI runs from a clean checkout with no
config.yaml, the same packager is documented as running LOCALLY — where it does
exist, populated. Copying it would ship that operator's live PAT to everyone who
downloads the release. So config.yaml is explicitly EXCLUDED from the copy and
regenerated from the template: safe by construction rather than by remembering.

Both halves are pinned here because either alone is wrong:
  - exclude without regenerate -> no config.yaml in the package (the original
    complaint, unfixed)
  - regenerate without exclude -> copytree copies the operator's real file
    first and the template overwrite is the only thing standing between a live
    PAT and the release. Relying on ordering for that is too fragile.

Run: docker exec intact_backend python3 /app/workdir/tests/test_release_ships_config_yaml.py
"""

import os
import re
import sys

REPO = os.environ.get("INTACT_PATH", "/app/workdir")
PACKAGE_PY = os.path.join(REPO, "modules", "backend", "services", "upgrade", "package.py")
EXAMPLE = os.path.join(REPO, "config.yaml.example")


def _read(p):
    with open(p, "r", encoding="utf-8") as h:
        return h.read()


def _copy_block():
    """The shutil.copytree call that mirrors the repo into source/intact/."""
    body = _read(PACKAGE_PY)
    at = body.index('f"{package_dir}/source/intact"')
    return body[at - 400:at + 2500]


def test_the_operators_config_is_excluded_from_the_repo_copy():
    """Without this, a LOCAL package build ships the builder's real PAT."""
    # Strip comment lines FIRST. The explanatory comment inside the
    # ignore_patterns() call contains "(a real ghp_ PAT)," — searching the raw
    # text for the closing ")," matches inside that prose and truncates the
    # slice before the entry, failing on correct code.
    block = "\n".join(ln for ln in _copy_block().splitlines()
                      if not ln.lstrip().startswith("#"))
    start = block.index("ignore_patterns")
    ignore = block[start:block.index("),", start)]
    assert re.search(r"['\"]config\.yaml['\"]", ignore), (
        "config.yaml is no longer excluded from the release copytree — a "
        "package built on a live box would ship that operator's github_token")


def test_config_yaml_is_regenerated_from_the_template():
    block = _copy_block()
    assert "config.yaml.example" in block and "copyfile" in block, \
        "the packager no longer writes config.yaml from config.yaml.example"
    assert re.search(r"_out\s*=\s*os\.path\.join\([^)]*['\"]config\.yaml['\"]\)", block), \
        "the packager no longer produces a config.yaml in the package"


def test_the_shipped_template_carries_no_secret():
    """It is about to be shipped under the name config.yaml, so it must be
    clean. This is the check that makes the rename safe."""
    import yaml
    if not os.path.isfile(EXAMPLE):
        return
    cfg = yaml.safe_load(_read(EXAMPLE)) or {}
    token = (cfg.get("options") or {}).get("github_token") or ""
    assert not token, \
        "config.yaml.example has a populated github_token — it must ship empty"
    assert not cfg.get("dashboard"), \
        "config.yaml.example carries a dashboard block; that is operator state"
    assert cfg.get("first_login") is True, \
        "config.yaml.example must ship first_login: true so a fresh install " \
        "lands in setup mode"


def test_no_real_token_pattern_anywhere_in_the_template():
    """Belt and braces — catches a token pasted somewhere other than
    options.github_token."""
    if not os.path.isfile(EXAMPLE):
        return
    body = _read(EXAMPLE)
    for pat in (r"ghp_[A-Za-z0-9]{20,}", r"github_pat_[A-Za-z0-9_]{20,}",
                r"gho_[A-Za-z0-9]{20,}"):
        assert not re.search(pat, body), \
            f"config.yaml.example contains something matching {pat}"


def test_the_template_is_still_tracked():
    """The rename must not have swapped which file is the tracked artifact —
    config.yaml.example stays in git, config.yaml stays out."""
    gi = os.path.join(REPO, ".gitignore")
    if not os.path.isfile(gi):
        return
    body = _read(gi)
    assert re.search(r'^config\.yaml$', body, re.MULTILINE), \
        "config.yaml is no longer gitignored — the operator's live file with " \
        "its PAT would become committable"


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
