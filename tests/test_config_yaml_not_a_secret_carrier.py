"""config.yaml is tracked, and what lands in git must always be the template.

History: config.yaml used to be tracked with real values, and a live GitHub PAT
(ghp_...) ended up baked into a backend image layer. The fix at the time was to
untrack it and ship config.yaml.example instead — which closed the leak but
meant a clone or an extracted release had no config.yaml to edit before running
install.sh, and install.sh's own "review it before continuing" advice was
impossible to follow.

The design now: config.yaml is TRACKED, and
scripts/git-hooks/sanitize-config-yaml.sh rewrites the STAGED copy back to
shipping defaults on every commit — github_token emptied, module passwords to
123123, first_login to true. So a checkout always has a ready-to-edit
config.yaml while git never receives a credential. config.yaml.example no
longer exists.

The load-bearing detail is that the sanitizer edits the INDEX, not the working
tree: it reads the staged blob, sanitizes it, writes a new blob with
`git hash-object -w`, and repoints the index with
`git update-index --cacheinfo`. Editing the file on disk instead would wipe the
operator's live PAT every time they committed — the fix would eat the thing it
protects.

This is defence in depth, not a guarantee: `git commit --no-verify` skips it,
which is why .github/workflows/secret-scan.yml re-checks the pushed result.
This file pins the local half.

Run: docker exec intact_backend python3 /app/workdir/tests/test_config_yaml_not_a_secret_carrier.py
"""

import os
import re
import subprocess
import sys

REPO = os.environ.get("INTACT_PATH", "/app/workdir")
CONFIG = os.path.join(REPO, "config.yaml")
SANITIZER = os.path.join(REPO, "scripts", "git-hooks", "sanitize-config-yaml.sh")
PRECOMMIT = os.path.join(REPO, "scripts", "git-hooks", "pre-commit")
GITIGNORE = os.path.join(REPO, ".gitignore")


def _read(p):
    with open(p, "r", encoding="utf-8") as h:
        return h.read()


# --- the arrangement exists ----------------------------------------------------


def test_the_example_is_gone():
    assert not os.path.exists(os.path.join(REPO, "config.yaml.example")), \
        "config.yaml.example is back; there should be exactly one config file"


def test_config_yaml_is_tracked_not_ignored():
    """The whole point — a checkout must come with an editable config.yaml."""
    body = _read(GITIGNORE)
    assert not re.search(r'^config\.yaml$', body, re.MULTILINE), \
        "config.yaml is gitignored again, so a fresh clone has no config to edit"


def test_the_sanitizer_exists_and_is_executable():
    assert os.path.exists(SANITIZER), \
        "the config.yaml sanitizer is gone — commits would carry a live PAT"
    assert os.access(SANITIZER, os.X_OK), \
        "the sanitizer is not executable; git would skip it silently"


def test_the_precommit_hook_invokes_it():
    """An uninvoked sanitizer is the same as no sanitizer."""
    assert "sanitize-config-yaml.sh" in _read(PRECOMMIT), \
        "pre-commit no longer runs the config.yaml sanitizer"


def test_a_sanitizer_failure_blocks_the_commit():
    """Failing open here would publish a credential."""
    body = _read(PRECOMMIT)
    at = body.index("sanitize-config-yaml.sh")
    assert "exit 1" in body[at:at + 500], \
        "a sanitizer failure no longer blocks the commit; it must fail closed"


# --- the load-bearing mechanism -----------------------------------------------


def test_the_sanitizer_edits_the_index_not_the_working_tree():
    """If it rewrote config.yaml on disk, every commit would destroy the
    operator's real PAT and passwords."""
    body = _read(SANITIZER)
    assert "git hash-object -w" in body, \
        "the sanitizer no longer writes a new blob; it must not edit in place"
    assert "update-index" in body, \
        "the sanitizer no longer repoints the index at the sanitized blob"
    assert "cat-file blob" in body, \
        "the sanitizer no longer reads the STAGED content; reading the working " \
        "file would sanitize what is on disk, not what is committed"


def test_it_sanitizes_all_three_fields():
    # The rules live in sanitize_config.py; the .sh is the git plumbing around
    # them. Split out so the rewriting logic can be unit-tested directly —
    # see tests/test_config_sanitizer.py.
    body = _read(os.path.join(REPO, "scripts", "git-hooks", "sanitize_config.py"))
    for field, why in (
        ("github_token", "a live PAT to a private org — the one that actually leaked"),
        ("password", "module passwords are operator state"),
        ("first_login", "a checkout must land in setup mode, or the first install "
                        "fails closed with no credential = locked out"),
    ):
        assert field in body, f"the sanitizer no longer resets {field} ({why})"


# --- what is actually committed ------------------------------------------------


def _committed_config():
    try:
        out = subprocess.run(["git", "-C", REPO, "show", "HEAD:config.yaml"],
                             capture_output=True, text=True, timeout=30)
        return out.stdout if out.returncode == 0 else None
    except Exception:
        return None


def test_the_committed_config_carries_no_secret():
    """The real assertion: whatever is in git right now must be clean."""
    body = _committed_config()
    if body is None:
        return          # not committed yet, or no git — nothing to check
    import yaml
    cfg = yaml.safe_load(body) or {}
    token = (cfg.get("options") or {}).get("github_token") or ""
    assert not token, "the COMMITTED config.yaml has a populated github_token"
    assert cfg.get("first_login") is True, \
        "the committed config.yaml lacks first_login: true — a fresh install " \
        "would fail closed with no credential"
    for name, mod in (cfg.get("modules") or {}).items():
        if isinstance(mod, dict) and "password" in mod:
            # Portainer's shipped default is deliberately >=12 chars because
            # Portainer refuses shorter ones — forcing it to 123123 would
            # silently change shipped behaviour, so the sanitizer preserves it.
            assert str(mod["password"]) in ("123123", "1234qwer!@#$"), \
                f"the committed config.yaml has a non-default password for {name}"


def test_no_token_pattern_in_the_committed_config():
    body = _committed_config()
    if body is None:
        return
    for pat in (r"ghp_[A-Za-z0-9]{20,}", r"github_pat_[A-Za-z0-9_]{20,}",
                r"gho_[A-Za-z0-9]{20,}"):
        assert not re.search(pat, body), \
            f"the committed config.yaml contains something matching {pat}"


def test_the_working_config_is_tight():
    """0600 matters once the file HOLDS something. It does not before.

    Git cannot record 0600 (only 100644/100755), so a fresh clone or an
    extracted release always arrives group-readable -- and at that moment the
    file is the blank template the sanitizer guarantees: empty github_token,
    shipped module passwords. There is nothing to protect yet, and install.sh
    chmods it the moment there is.

    Asserting unconditionally made this fail in CI, where the checkout is by
    definition pristine. That is a false positive on the one control that is
    supposed to mean something -- and a check that cries wolf on every push is
    how a real 0644 on a live appliance gets waved through.

    So: skip while the file still carries no credential; assert hard the moment
    it does."""
    if not os.path.exists(CONFIG):
        return
    body = _read(CONFIG)
    token = re.search(r"^\s*github_token:\s*(.*)$", body, re.M)
    token_val = (token.group(1).strip().strip("'\"") if token else "")
    pristine = not token_val and not re.search(
        r"^\s*password:\s*(?!'?(123123|1234qwer!@#\$)'?\s*(#.*)?$)\S",
        body, re.M)
    if pristine:
        return          # blank template — nothing to protect yet
    mode = os.stat(CONFIG).st_mode & 0o777
    assert not (mode & 0o077), \
        f"config.yaml is {oct(mode)} — it holds the operator's live PAT once edited"


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
