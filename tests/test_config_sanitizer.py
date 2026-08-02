"""Unit tests for the pre-commit config sanitizer.

The sanitizer is the only thing standing between an operator's live GitHub PAT
(and now their sudo + Windows Administrator passwords) and a public commit. It
used to live as a heredoc inside the shell hook, where the only way to test it
was to stage a file and commit — so two regex bugs shipped:

  * `\\s*` in the trailing group matched the newline, so every edit ate the line
    ending and added a blank line.
  * a non-greedy `.*?` value stopped at the `#` inside Portainer's shipped
    `1234qwer!@#$` and treated the rest as a comment, rewriting the line to an
    invalid `123123#$'` — which was committed before anyone noticed.

Both are pinned below. Run:
  python3 tests/test_config_sanitizer.py
"""

import os
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "git-hooks"))

from sanitize_config import (          # noqa: E402
    sanitize_main_config, sanitize_qa_config, SANITIZERS, DEFAULT_PW)


# --- config.yaml ---------------------------------------------------------------


def test_github_token_is_emptied():
    out, changed = sanitize_main_config("  github_token: 'ghp_deadbeef1234'\n")
    assert out == "  github_token: ''\n", out
    assert "github_token" in changed


def test_an_already_empty_token_is_left_alone():
    src = "  github_token: ''\n"
    out, changed = sanitize_main_config(src)
    assert out == src and not changed, "a no-op commit should not touch the index"


def test_module_password_goes_back_to_the_default():
    out, changed = sanitize_main_config("    password: 'hunter2'\n")
    assert out == f"    password: {DEFAULT_PW}\n", out
    assert "password" in changed


def test_portainers_shipped_password_survives_intact():
    """The regression that actually shipped. Portainer refuses passwords under
    12 chars, so rewriting its default to 123123 makes install.sh generate a
    random one instead — a silent behaviour change. And the '#' inside it used
    to be parsed as a comment, producing invalid YAML."""
    src = ("    password: '1234qwer!@#$' # Portainer requires >=12 chars; "
           "shorter values get a randomly-generated one instead\n")
    out, changed = sanitize_main_config(src)
    assert out == src, f"mangled Portainer's default:\n{out}"
    assert not changed


def test_first_login_is_forced_true():
    out, changed = sanitize_main_config("first_login: false\n")
    assert out == "first_login: true\n", out
    assert "first_login" in changed


def test_no_blank_lines_are_introduced():
    """The `\\s*`-ate-the-newline regression: one extra blank line per edit."""
    src = ("first_login: false\n"
           "domain: 10.0.0.1\n"
           "  github_token: 'ghp_x'\n"
           "    password: 'secret'\n")
    out, _ = sanitize_main_config(src)
    assert len(out.splitlines()) == len(src.splitlines()), \
        f"line count changed {len(src.splitlines())} -> {len(out.splitlines())}:\n{out}"
    assert "\n\n" not in out, f"blank line introduced:\n{out}"


def test_trailing_comments_are_preserved():
    out, _ = sanitize_main_config("    password: 'x'   # keep me\n")
    assert out.rstrip().endswith("# keep me"), out


def test_comments_and_unrelated_lines_pass_through():
    src = ("# password: 'not a real setting'\n"
           "schema_version: 2\n"
           "domain: 192.168.1.1\n")
    out, changed = sanitize_main_config(src)
    assert out == src and not changed


# --- qa/qa-config.yaml ---------------------------------------------------------


QA_FILLED = (
    "schema_version: 1\n"
    "platform:\n"
    "  host: '192.168.120.11'\n"
    "  sudo_user: 'tenroot'\n"
    "  sudo_password: '10RootRulez'\n"
    "windows:\n"
    "  host: '192.168.120.128'\n"
    "  username: 'vagrant'\n"
    "  password: 'vagrant'\n"
    "  ssh_port: 22\n"
    "run:\n"
    "  output_dir: '~/qa-runs'\n"
    "  llm_summary: false\n"
)


def test_every_qa_credential_is_blanked():
    out, changed = sanitize_qa_config(QA_FILLED)
    for leaked in ("192.168.120.11", "tenroot", "10RootRulez",
                   "192.168.120.128", "vagrant"):
        assert leaked not in out, f"'{leaked}' survived sanitization:\n{out}"
    assert len(changed) == 6, changed


def test_qa_non_secret_settings_are_untouched():
    """Blanking the whole file would be simpler and wrong — the run knobs are
    shipped defaults a reader is meant to see."""
    out, _ = sanitize_qa_config(QA_FILLED)
    assert "ssh_port: 22" in out
    assert "output_dir: '~/qa-runs'" in out
    assert "llm_summary: false" in out
    assert "schema_version: 1" in out


def test_qa_sanitizing_is_idempotent():
    once, _ = sanitize_qa_config(QA_FILLED)
    twice, changed = sanitize_qa_config(once)
    assert twice == once and not changed, "second pass should be a no-op"


def test_qa_blank_template_is_a_noop():
    """The committed state must survive a round trip unchanged, or every commit
    that touches this file would show a spurious diff."""
    blank = QA_FILLED
    for real in ("'192.168.120.11'", "'tenroot'", "'10RootRulez'",
                 "'192.168.120.128'", "'vagrant'"):
        blank = blank.replace(real, "''")
    out, changed = sanitize_qa_config(blank)
    assert out == blank and not changed, out


def test_qa_keeps_line_count():
    out, _ = sanitize_qa_config(QA_FILLED)
    assert len(out.splitlines()) == len(QA_FILLED.splitlines()), out


def test_qa_password_outside_a_known_section_is_not_blanked():
    """Section-awareness is deliberate: a bare key match would blank unrelated
    settings the moment the file grows a new section."""
    src = "notes:\n  password: 'documented example value'\n"
    out, changed = sanitize_qa_config(src)
    assert out == src and not changed, out


def test_qa_comments_are_preserved():
    src = "windows:\n  password: 'vagrant'   # local admin\n"
    out, _ = sanitize_qa_config(src)
    assert "# local admin" in out
    assert "vagrant" not in out, out


# --- dispatch ------------------------------------------------------------------


def test_both_config_files_are_registered():
    assert "config.yaml" in SANITIZERS
    assert "qa/qa-config.yaml" in SANITIZERS, \
        "the QA config is not sanitized — a sudo password would reach GitHub"


def test_an_unknown_target_fails_closed():
    """Passing content through for an unregistered file would publish it while
    reporting success."""
    import subprocess
    import tempfile
    here = os.path.dirname(os.path.abspath(__file__))
    script = os.path.join(here, "..", "scripts", "git-hooks", "sanitize_config.py")
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as src:
        src.write("password: 'secret'\n")
        src_path = src.name
    dst_path = src_path + ".out"
    try:
        r = subprocess.run([sys.executable, script, "some/other.yaml",
                            src_path, dst_path], capture_output=True, text=True)
        assert r.returncode != 0, "unknown target should be an error, not a pass-through"
    finally:
        for p in (src_path, dst_path):
            if os.path.exists(p):
                os.unlink(p)


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
