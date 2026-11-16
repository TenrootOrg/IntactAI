#!/usr/bin/env python3
"""Tests for scripts/git-hooks/sanitize_config.py.

sanitize_config.py's own docstring has referenced this file since it was
written -- "so it can be unit-tested directly -- see tests/test_config_sanitizer.py"
-- but the file never existed. That is not a cosmetic gap: the same docstring
records two regex bugs that shipped from the earlier heredoc version and says a
unit test "would have caught [them] in seconds".

THE LOAD-BEARING TEST is test_tracked_config_is_already_sanitized (and its
twin for the tracked modules/*/.env). The hook and config.yaml are two
hand-maintained things that must agree about what a shipping default is -- now
simply "every password empty" -- and they silently stopped agreeing once: the working Portainer
password shipped in 71835af while SHIPPED still listed only the retired
`1234qwer!@#$`, so the next staged commit would have rewritten it to `123123` --
a value Portainer refuses outright, reintroducing the exact bug that commit
fixed. Asserting "sanitizing the tracked file changes nothing" pins them
together permanently: rotate a shipped default without telling the hook and this
test fails, instead of an install failing months later.

Run:  python3 tests/test_config_sanitizer.py
"""

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "scripts", "git-hooks"))

import sanitize_config as S  # noqa: E402


_FAILURES = []


def check(name, cond, detail=""):
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}{('  — ' + detail) if detail else ''}")
        _FAILURES.append(name)


# ---------------------------------------------------------------------------
# The invariant that keeps the hook and config.yaml in sync
# ---------------------------------------------------------------------------

def test_tracked_config_is_already_sanitized():
    """The tracked config.yaml IS the shipped template, so sanitizing it must
    be a no-op. If this fails, either a real secret got committed or a shipped
    default was rotated without updating sanitize_config.py."""
    path = os.path.join(_ROOT, "config.yaml")
    if not os.path.isfile(path):
        check("tracked config.yaml present", False, path)
        return
    text = open(path, encoding="utf-8").read()
    out, changed = S.sanitize_main_config(text)
    check(
        "sanitizing the tracked config.yaml changes nothing",
        out == text and not changed,
        f"would rewrite: {sorted(set(changed))}",
    )


def test_sanitize_is_idempotent():
    """Running the hook twice must equal running it once."""
    text = (
        "modules:\n"
        "  elk:\n"
        "    password: hunter2\n"
        "  portainer:\n"
        "    password: some-operator-secret\n"
    )
    once, _ = S.sanitize_main_config(text)
    twice, changed2 = S.sanitize_main_config(once)
    check("sanitize is idempotent", once == twice and not changed2)


# ---------------------------------------------------------------------------
# Module passwords ship EMPTY
# ---------------------------------------------------------------------------

def _value_of(out, key="password"):
    for ln in out.splitlines():
        if ln.strip().startswith(key + ":"):
            return ln.split(":", 1)[1].strip()
    return None


def test_every_module_password_is_emptied():
    """No per-module exception any more: Portainer used to get its own
    replacement (it refuses < 12 chars) and that table drifted from config.yaml
    once. Every module's value goes to ''."""
    for module in ("elk", "portainer", "iris", "velociraptor"):
        text = f"modules:\n  {module}:\n    password: an-operators-real-secret\n"
        out, changed = S.sanitize_main_config(text)
        check(f"{module} password emptied", _value_of(out) == "''", out)
        check(f"{module} reported", "password" in changed)


def test_known_defaults_are_emptied_too():
    """The old shipped values are public; they must not survive a commit."""
    for pw in ("'123123'", "'Ch4nge-Me!Intact2026'", "'1234qwer!@#$'", "123123"):
        out, changed = S.sanitize_main_config(f"modules:\n  elk:\n    password: {pw}\n")
        check(f"known default {pw} emptied",
              out == "modules:\n  elk:\n    password: ''\n" and changed, out)


def test_any_password_key_under_modules():
    """api_password (Velociraptor's `api` user) and any other *password key."""
    text = ("modules:\n  velociraptor:\n    api_password: '123123'\n"
            "    gui_password: x\n")
    out, changed = S.sanitize_main_config(text)
    check("api_password emptied", _value_of(out, "api_password") == "''", out)
    check("gui_password emptied", _value_of(out, "gui_password") == "''", out)
    check("both reported", changed.count("password") == 2, changed)


def test_allow_weak_passwords_is_forced_off():
    # A dev box turns it on to keep 123123; it must never ship on.
    for on in ("true", "True", "yes"):
        out, changed = S.sanitize_main_config(f"first_login: true\nallow_weak_passwords: {on}  # lab\n")
        check(f"allow_weak_passwords {on} -> false", "allow_weak_passwords: false  # lab" in out, out)
        check(f"allow_weak_passwords {on} reported", "allow_weak_passwords" in changed, changed)
    out, changed = S.sanitize_main_config("allow_weak_passwords: false\n")
    check("allow_weak_passwords false is a no-op", not changed and out == "allow_weak_passwords: false\n", out)


def test_empty_password_is_a_noop():
    for v in ("''", '""', ""):
        text = f"modules:\n  elk:\n    password: {v}\n"
        out, changed = S.sanitize_main_config(text)
        check(f"empty password {v!r} untouched", out == text and not changed, out)


def test_password_outside_modules_is_left_alone():
    """Scoped to the modules: block, so a future non-secret `password_rule:` or
    a key elsewhere is not wiped by a name match."""
    text = "options:\n  password: keep-me\nmodules:\n  elk:\n    password_rule: x\n"
    out, changed = S.sanitize_main_config(text)
    check("non-module password and password_rule untouched",
          out == text and not changed, out)


# ---------------------------------------------------------------------------
# The two regex bugs the docstring records
# ---------------------------------------------------------------------------

def test_quoted_value_containing_hash_is_not_mangled():
    """The `.*?` bug: a non-greedy match stopped at the '#' inside Portainer's
    1234qwer!@#$ and mangled the line into `123123#$'`."""
    for v in ("'1234qwer!@#$'", "p@ss#word"):
        text = f"modules:\n  portainer:\n    password: {v}\n"
        out, _ = S.sanitize_main_config(text)
        check(f"value {v} containing '#' replaced whole",
              out == "modules:\n  portainer:\n    password: ''\n", out)


def test_trailing_comment_is_preserved():
    text = "modules:\n  elk:\n    password: secret  # set at install\n"
    out, _ = S.sanitize_main_config(text)
    check("trailing comment preserved", "# set at install" in out, out)


def test_newlines_are_not_swallowed():
    """The `\\s*` bug: the pattern swallowed newlines and joined lines."""
    text = "modules:\n  elk:\n    password: secret\n    id: tenroot\n"
    out, _ = S.sanitize_main_config(text)
    check("line count preserved", len(out.splitlines()) == len(text.splitlines()), out)
    check("following key intact", "id: tenroot" in out)


def test_domain_is_replaced_with_the_placeholder():
    """A tracked config.yaml must never ship a real address: it becomes the TLS
    CN and the callback baked into every Velociraptor client installer."""
    text = "domain: 192.168.120.11\n"
    out, changed = S.sanitize_main_config(text)
    check("real domain is replaced", S.PLACEHOLDER_DOMAIN in out, out)
    check("original IP is gone", "192.168.120.11" not in out, out)
    check("domain reported as changed", "domain" in changed)


def test_placeholder_domain_is_left_alone():
    text = f"domain: {S.PLACEHOLDER_DOMAIN}\n"
    out, changed = S.sanitize_main_config(text)
    check("placeholder domain untouched", out == text and not changed, out)


def test_github_token_is_emptied():
    text = "options:\n  github_token: 'ghp_realtokenvalue'\n"
    out, changed = S.sanitize_main_config(text)
    check("github_token emptied", "ghp_realtokenvalue" not in out, out)
    check("github_token reported", "github_token" in changed)


def test_data_path_cleared():
    # A drive on the committer's box must not ship: a fresh install would try to
    # move all data to a folder that does not exist there.
    out, changed = S.sanitize_main_config('data_path: "/mnt/intact-data"\n')
    check("data_path cleared", out == 'data_path: ""\n' and "data_path" in changed, out)
    out, changed = S.sanitize_main_config('data_path: ""\n')
    check("empty data_path untouched", "data_path" not in changed, out)


def test_first_login_forced_true():
    text = "first_login: false\n"
    out, changed = S.sanitize_main_config(text)
    check("first_login forced true", "true" in out and "first_login" in changed, out)


def test_comments_and_key_order_survive():
    """Textual edit, never a yaml round-trip."""
    text = (
        "# operator-facing comment\n"
        "first_login: true\n"
        "modules:\n"
        "  # explains the pin below\n"
        "  elk:\n"
        "    enabled: true\n"
        "    password: ''\n"
    )
    out, changed = S.sanitize_main_config(text)
    check("comments + order survive", out == text and not changed, out)


# ---------------------------------------------------------------------------
# Tracked modules/<module>/.env files
# ---------------------------------------------------------------------------

def test_tracked_module_envs_are_already_sanitized():
    """Same invariant as config.yaml: the tracked files ARE the shipped ones,
    so their password values must already be empty."""
    import glob
    import subprocess
    # Tracked ones only: an installed tree also has modules/volweb/.env, which
    # is gitignored and rendered with real secrets on purpose.
    try:
        rels = subprocess.run(["git", "-C", _ROOT, "ls-files", "modules/*/.env"],
                              capture_output=True, text=True, check=True).stdout.split()
        paths = [os.path.join(_ROOT, r) for r in rels]
    except (OSError, subprocess.CalledProcessError):
        paths = sorted(glob.glob(os.path.join(_ROOT, "modules", "*", ".env")))
    check("tracked module .env files found", len(paths) >= 5, paths)
    for path in paths:
        text = open(path, encoding="utf-8").read()
        out, changed = S.sanitize_module_env(text)
        check(f"{os.path.relpath(path, _ROOT)} has no password value",
              out == text and not changed, f"would blank: {changed}")


def test_module_env_password_values_blanked_rest_byte_identical():
    text = ("# header PASSWORD=x stays\n"
            "ELASTIC_VERSION=9.4.2\n"
            "ELASTIC_PASSWORD=s3cret=with=equals\n"
            "VELOX_PASSWORD_2=abc\r\n"
            "TIMESKETCH_PASS=123123\n"
            "KIBANA_PASSWORD=\n"
            "PASSTHROUGH_MODE=on\n"
            "ELASTIC_USER=elastic")
    want = ("# header PASSWORD=x stays\n"
            "ELASTIC_VERSION=9.4.2\n"
            "ELASTIC_PASSWORD=\n"
            "VELOX_PASSWORD_2=\r\n"
            "TIMESKETCH_PASS=\n"
            "KIBANA_PASSWORD=\n"
            "PASSTHROUGH_MODE=on\n"
            "ELASTIC_USER=elastic")
    out, changed = S.sanitize_module_env(text)
    check("module .env: only password values cut", out == want, repr(out))
    check("module .env: keys reported",
          changed == ["ELASTIC_PASSWORD", "VELOX_PASSWORD_2", "TIMESKETCH_PASS"], changed)
    again, changed2 = S.sanitize_module_env(out)
    check("module .env: idempotent", again == out and not changed2)


def test_sanitizer_routing():
    check("modules/elk/.env routed", S.sanitizer_for("modules/elk/.env") is S.sanitize_module_env)
    check("nested .env not routed", S.sanitizer_for("modules/elk/sub/.env") is None)
    check(".env.template not routed", S.sanitizer_for("modules/volweb/.env.template") is None)
    check("config.yaml routed", S.sanitizer_for("config.yaml") is S.sanitize_main_config)


def test_hook_blanks_staged_module_env_and_keeps_working_file():
    """End to end in a throwaway repo: the hook rewrites the INDEX copy of a
    staged modules/<m>/.env and leaves the file on disk alone."""
    import shutil
    import subprocess
    import tempfile
    if not shutil.which("git"):
        check("git available for the hook test", False)
        return
    hook = os.path.join(_ROOT, "scripts", "git-hooks", "sanitize-config-yaml.sh")
    with tempfile.TemporaryDirectory() as repo:
        def git(*a):
            return subprocess.run(["git", "-C", repo, *a], capture_output=True,
                                  text=True, check=True).stdout
        git("init", "-q")
        os.makedirs(os.path.join(repo, "modules", "elk"))
        live = "ELASTIC_VERSION=9\nELASTIC_PASSWORD=LiveBoxPass2026\n"
        with open(os.path.join(repo, "modules", "elk", ".env"), "w") as fh:
            fh.write(live)
        git("add", "modules/elk/.env")
        r = subprocess.run(["bash", hook], cwd=repo, capture_output=True, text=True)
        check("hook exits 0", r.returncode == 0, r.stderr)
        staged = git("show", ":modules/elk/.env")
        check("staged .env password blanked",
              staged == "ELASTIC_VERSION=9\nELASTIC_PASSWORD=\n", repr(staged))
        check("hook output never shows the value", "LiveBoxPass2026" not in r.stderr + r.stdout)
        with open(os.path.join(repo, "modules", "elk", ".env")) as fh:
            check("working .env untouched", fh.read() == live)


if __name__ == "__main__":
    print("test_config_sanitizer")
    for fn in sorted(
        (v for k, v in list(globals().items()) if k.startswith("test_")),
        key=lambda f: f.__name__,
    ):
        fn()
    print()
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s): {', '.join(_FAILURES)}")
        sys.exit(1)
    print("all checks passed")
