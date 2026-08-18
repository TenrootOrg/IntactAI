#!/usr/bin/env python3
"""Tests for scripts/git-hooks/sanitize_config.py.

sanitize_config.py's own docstring has referenced this file since it was
written -- "so it can be unit-tested directly -- see tests/test_config_sanitizer.py"
-- but the file never existed. That is not a cosmetic gap: the same docstring
records two regex bugs that shipped from the earlier heredoc version and says a
unit test "would have caught [them] in seconds".

THE LOAD-BEARING TEST is test_tracked_config_is_already_sanitized. The hook and
config.yaml are two hand-maintained things that must agree about what a shipping
default is, and they silently stopped agreeing once: the working Portainer
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
# Per-module password defaults
# ---------------------------------------------------------------------------

def test_portainer_never_gets_a_password_it_refuses():
    """Portainer refuses anything < 12 chars or equal to the retired default,
    so it must never be handed DEFAULT_PW."""
    text = "modules:\n  portainer:\n    password: an-operators-real-secret\n"
    out, changed = S.sanitize_main_config(text)
    value = out.splitlines()[-1].split(":", 1)[1].strip()
    check("portainer password is replaced", "password" in changed)
    check("portainer replacement is not DEFAULT_PW", value != S.DEFAULT_PW, value)
    check("portainer replacement is >= 12 chars", len(value) >= 12, f"len={len(value)}")
    check(
        "portainer replacement is not the retired default",
        value != S.PORTAINER_RETIRED_PW,
    )


def test_other_modules_get_default_pw():
    text = "modules:\n  elk:\n    password: an-operators-real-secret\n"
    out, _ = S.sanitize_main_config(text)
    value = out.splitlines()[-1].split(":", 1)[1].strip()
    check("non-portainer password -> DEFAULT_PW", value == S.DEFAULT_PW, value)


def test_shipped_defaults_are_left_alone():
    for module, pw in (
        ("elk", S.DEFAULT_PW),
        ("portainer", S.PORTAINER_DEFAULT_PW),
        ("portainer", S.PORTAINER_RETIRED_PW),
    ):
        text = f"modules:\n  {module}:\n    password: {pw}\n"
        out, changed = S.sanitize_main_config(text)
        check(f"shipped default untouched ({module}: {pw[:6]}…)",
              out == text and not changed)


# ---------------------------------------------------------------------------
# The two regex bugs the docstring records
# ---------------------------------------------------------------------------

def test_quoted_value_containing_hash_is_not_mangled():
    """The `.*?` bug: a non-greedy match stopped at the '#' inside Portainer's
    1234qwer!@#$ and mangled the line."""
    text = "modules:\n  portainer:\n    password: '1234qwer!@#$'\n"
    out, changed = S.sanitize_main_config(text)
    check("quoted value containing '#' survives", out == text and not changed, out)


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


def test_github_token_is_emptied():
    text = "options:\n  github_token: 'ghp_realtokenvalue'\n"
    out, changed = S.sanitize_main_config(text)
    check("github_token emptied", "ghp_realtokenvalue" not in out, out)
    check("github_token reported", "github_token" in changed)


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
        "    password: 123123\n"
    )
    out, changed = S.sanitize_main_config(text)
    check("comments + order survive", out == text and not changed, out)


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
