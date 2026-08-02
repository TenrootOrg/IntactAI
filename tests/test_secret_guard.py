"""The pre-commit secret guard, tested against real key formats.

A guard nobody exercises is a guard that rots. This one already had two
failure modes worth pinning:

  1. It carried its OWN list of five regexes while .gitleaks.toml carried
     those plus Anthropic, OpenAI, OpenRouter, Azure and SECRET_KEY rules on
     top of gitleaks' defaults. Local was quietly weaker than CI, so exactly
     the keys our Settings pages ask operators to paste committed cleanly and
     were caught only after push -- by which point the remedy is revoke plus
     history rewrite, not prevention.
  2. core.hooksPath lives in .git/config, which is per-clone and untracked,
     so the guard shipped in the repo was OFF by default on every fresh clone.

Each test drives a real throwaway git repo in a temp dir with the real hook
installed, and asserts on whether `git commit` actually succeeded. No mocking:
the thing under test is a shell hook and git's invocation of it, so anything
short of a real commit would test a different system.

Keys are randomly generated per run at the exact length each rule requires --
a too-short AKIA string silently matches nothing and turns this whole file
green for the wrong reason.

WHICH BRANCH THESE EXERCISE: the hook prefers gitleaks and falls back to a
hand-rolled pattern list when the binary is absent. gitleaks is deliberately
NOT in the backend image (it ships no test or tooling dependencies), so in CI
and in the container these tests drive the FALLBACK path. That is the right
way round -- the fallback is the hand-written half and the one that can be
wrong, while the gitleaks path is "run a well-tested binary with the same
config CI already uses", independently proven by secret-scan.yml on every
push. test_the_fallback_covers_every_custom_gitleaks_rule keeps the two from
drifting. The gitleaks branch was verified by hand on a host that has it.

Run: docker exec intact_backend python3 /app/workdir/tests/test_secret_guard.py
"""

import os
import random
import shutil
import string
import subprocess
import sys
import tempfile

REPO = os.environ.get("INTACT_PATH", "/app/workdir")
HOOK = os.path.join(REPO, "scripts", "git-hooks", "pre-commit")
INSTALLER = os.path.join(REPO, "scripts", "install-git-hooks.sh")
GITLEAKS_CONFIG = os.path.join(REPO, ".gitleaks.toml")

_RND = random.Random(20260729)


def _rnd(alphabet, n):
    return "".join(_RND.choice(alphabet) for _ in range(n))


HEX = string.ascii_lowercase + string.digits
UPPER = string.ascii_uppercase + string.digits
B64ISH = string.ascii_letters + string.digits + "_-"


def _repo():
    """A throwaway git repo with the real hook wired in."""
    root = tempfile.mkdtemp(prefix="secguard_")
    run = lambda *a: subprocess.run(a, cwd=root, capture_output=True, text=True)
    run("git", "init", "-q", ".")
    run("git", "config", "user.email", "t@example.invalid")
    run("git", "config", "user.name", "test")
    run("git", "config", "commit.gpgsign", "false")
    shutil.copy(GITLEAKS_CONFIG, os.path.join(root, ".gitleaks.toml"))
    hooks = os.path.join(root, "scripts", "git-hooks")
    # Copy the WHOLE hooks directory, not just pre-commit.
    #
    # The hook grew a sibling: it delegates config.yaml sanitizing to
    # sanitize-config-yaml.sh, which in turn calls sanitize_config.py. Copying
    # only pre-commit left it unable to find them, and because the hook fails
    # closed by design, every benign commit in this fixture was blocked with a
    # message about config.yaml holding a secret — which read as three broken
    # tests rather than an incomplete fixture. A real install always has the
    # whole directory, since core.hooksPath points at the directory.
    shutil.copytree(os.path.dirname(HOOK), hooks)
    for entry in os.listdir(hooks):
        path = os.path.join(hooks, entry)
        if os.path.isfile(path):
            os.chmod(path, 0o755)
    run("git", "config", "core.hooksPath", "scripts/git-hooks")
    return root


def _commit(root, content, filename="payload.txt", env=None):
    """Stage `content` and try to commit. Returns True if the commit landed."""
    with open(os.path.join(root, filename), "w") as handle:
        handle.write(content + "\n")
    subprocess.run(["git", "add", filename], cwd=root, capture_output=True)
    result = subprocess.run(["git", "commit", "-m", "t"], cwd=root,
                            capture_output=True, text=True,
                            env=dict(os.environ, **(env or {})))
    committed = result.returncode == 0
    if committed:
        subprocess.run(["git", "update-ref", "-d", "HEAD"], cwd=root,
                       capture_output=True)
    subprocess.run(["git", "reset", "-q"], cwd=root, capture_output=True)
    os.remove(os.path.join(root, filename))
    return committed, result.stderr


def _blocked(content, **kw):
    root = _repo()
    try:
        committed, stderr = _commit(root, content, **kw)
        return (not committed), stderr
    finally:
        shutil.rmtree(root, ignore_errors=True)


# --- the keys the guard was blind to before ---------------------------------


def test_an_openrouter_key_is_blocked():
    """Settings -> Timesketch and -> Agentic both ask for one of these."""
    blocked, _ = _blocked(f"api_key = 'sk-or-v1-{_rnd(HEX, 64)}'")
    assert blocked, "an OpenRouter key committed cleanly"


def test_an_anthropic_key_is_blocked():
    blocked, _ = _blocked(f"api_key = 'sk-ant-api03-{_rnd(B64ISH, 93)}AA'")
    assert blocked, "an Anthropic key committed cleanly"


def test_an_openai_key_is_blocked():
    blocked, _ = _blocked(f"api_key = 'sk-proj-{_rnd(B64ISH, 48)}'")
    assert blocked, "an OpenAI project key committed cleanly"


# --- what it always caught, which must not regress --------------------------


def test_a_github_pat_is_blocked():
    blocked, _ = _blocked(f"token = 'ghp_{_rnd(string.ascii_letters + string.digits, 36)}'")
    assert blocked, "a GitHub PAT committed cleanly"


def test_an_aws_access_key_is_blocked():
    # Exactly 16 trailing chars. A shorter string matches no rule and would
    # turn this test green while proving nothing.
    key = f"AKIA{_rnd(UPPER, 16)}"
    assert len(key) == 20, key
    blocked, _ = _blocked(f"aws_access_key_id = '{key}'")
    assert blocked, "an AWS access key committed cleanly"


def test_private_key_headers_are_blocked():
    """gitleaks' private-key rule needs the key BODY to fire, so the hook
    keeps its own always-on header check. Every armour variant must trip it.

    The headers are ASSEMBLED rather than written out, so this file does not
    itself contain the literal string. Writing them inline made the guard
    block this very commit -- correctly -- and the alternatives were both
    worse: --no-verify only moves the failure to CI, which scans full history
    on push, and a path allowlist would blind every future scan to a real
    secret landing in this file. Building the string at runtime keeps the
    guard at full strength and still tests the exact byte sequence.
    """
    marker = "-" * 5
    for label in ("RSA ", "", "OPENSSH ", "EC ", "DSA "):
        header = f"{marker}BEGIN {label}PRIVATE" + f" KEY{marker}"
        blocked, _ = _blocked(header)
        assert blocked, f"{header!r} committed cleanly"


def test_a_populated_github_token_in_config_yaml_is_blocked():
    """The shipped default must stay empty even if the value is not a
    recognisable token format."""
    blocked, stderr = _blocked(
        "domain: example.com\noptions:\n  github_token: 'not-a-real-format-but-still-a-secret'",
        filename="config.yaml")
    assert blocked, "config.yaml with a populated github_token committed cleanly"
    assert "github_token" in stderr, stderr


# --- and it must not cry wolf ------------------------------------------------


def test_ordinary_code_commits_normally():
    blocked, stderr = _blocked("def hello():\n    return 'world'")
    assert not blocked, f"a normal commit was blocked: {stderr}"


def test_a_documented_placeholder_commits_normally():
    """We ship docs that explain token formats. Those must not be blocked, or
    people learn to reach for --no-verify by reflex."""
    blocked, stderr = _blocked(
        "# 4. Generate a token and copy it:\nexport GITHUB_TOKEN=ghp_YOUR_TOKEN_HERE")
    assert not blocked, f"a docs placeholder was blocked: {stderr}"


def test_a_public_certificate_commits_normally():
    """We track nginx's self-signed CERT (public) next to its key (private).
    Blocking the cert would break a legitimate workflow."""
    blocked, stderr = _blocked("-----BEGIN CERTIFICATE-----")
    assert not blocked, f"a public certificate was blocked: {stderr}"


# --- the guard has to actually be switched on --------------------------------


def test_the_installer_is_idempotent_and_sets_the_hook_path():
    """core.hooksPath is per-clone and untracked, so a guard nobody installs
    protects nobody."""
    root = tempfile.mkdtemp(prefix="secguard_install_")
    try:
        subprocess.run(["git", "init", "-q", "."], cwd=root, capture_output=True)
        os.makedirs(os.path.join(root, "scripts", "git-hooks"))
        shutil.copy(INSTALLER, os.path.join(root, "scripts", "install-git-hooks.sh"))

        for attempt in (1, 2):
            result = subprocess.run(
                ["bash", "scripts/install-git-hooks.sh"],
                cwd=root, capture_output=True, text=True)
            assert result.returncode == 0, \
                f"attempt {attempt} failed: {result.stderr}"
            configured = subprocess.run(
                ["git", "config", "--get", "core.hooksPath"],
                cwd=root, capture_output=True, text=True).stdout.strip()
            assert configured == "scripts/git-hooks", \
                f"attempt {attempt}: core.hooksPath is {configured!r}"
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_the_installer_is_a_noop_outside_a_git_repo():
    """A tarball install has no .git. That must not fail the platform install."""
    root = tempfile.mkdtemp(prefix="secguard_nogit_")
    try:
        os.makedirs(os.path.join(root, "scripts"))
        shutil.copy(INSTALLER, os.path.join(root, "scripts", "install-git-hooks.sh"))
        result = subprocess.run(["bash", "scripts/install-git-hooks.sh"],
                                cwd=root, capture_output=True, text=True)
        assert result.returncode == 0, \
            f"the installer failed outside a git repo: {result.stderr}"
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_install_sh_runs_the_hook_installer():
    with open(os.path.join(REPO, "install.sh"), "r", encoding="utf-8") as handle:
        content = handle.read()
    assert "install-git-hooks.sh" in content, \
        "install.sh never installs the git hooks, so a fresh clone is unguarded"


def test_the_fallback_covers_every_custom_gitleaks_rule():
    """The fallback runs on any machine without gitleaks, so it must not lag
    behind .gitleaks.toml the way the old hardcoded list did.

    Compares key FAMILIES, not exact regexes -- the fallback is deliberately
    looser (no entropy checks, no allowlist) and demanding byte-equality would
    just get the assertion deleted the first time it fired.
    """
    with open(GITLEAKS_CONFIG, "r", encoding="utf-8") as handle:
        config = handle.read()
    with open(HOOK, "r", encoding="utf-8") as handle:
        hook = handle.read()

    # Prefix -> a substring that must appear in the hook's fallback patterns.
    families = {
        "sk-or-v1-": "sk-or-v1-",
        "sk-ant-api03-": "sk-ant-api03-",
        "sk-(proj": "sk-(proj",
    }
    for marker, needed in families.items():
        if marker not in config:
            continue  # rule was removed from the config; nothing to mirror
        assert needed in hook, (
            f"'{marker}' has a rule in .gitleaks.toml but no fallback pattern "
            f"in the hook -- a machine without gitleaks would miss it")


def test_the_hook_defers_to_gitleaks_for_its_rule_set():
    """One source of truth. If the hook grows its own parallel rule list
    again, local and CI drift apart and local is the one that loses."""
    with open(HOOK, "r", encoding="utf-8") as handle:
        src = handle.read()
    assert "gitleaks protect --staged" in src, \
        "the hook no longer runs gitleaks against the staged index"
    assert ".gitleaks.toml" in src or "gitleaks.toml" in src, \
        "the hook does not use the same config CI uses"
    assert "--redact" in src, \
        "the hook must not print the secret it just caught to the terminal"


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
