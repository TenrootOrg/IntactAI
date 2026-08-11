#!/usr/bin/env python3
"""scripts/git-hooks/sanitize_config.py — the last thing between a live PAT and
a public commit.

This file is referenced by name in sanitize_config.py's own docstring ("so it
can be unit-tested directly -- see tests/test_config_sanitizer.py") and did not
exist. run_tests.sh has always globbed test_*.py, so the loop simply matched
nothing and the sanitizer shipped with no coverage at all.

It is now load-bearing in a second place, which is what prompted writing this:
scripts/ci/packager/package.py runs it to produce the config.yaml template the
backend image is built from, because the real one is excluded from packages for
holding operator secrets. If the sanitizer regresses, a real ghp_ token gets
baked into a shipped image layer -- recoverable, as modules/backend/Dockerfile's
own comment says, with `docker run --entrypoint sh <image> -c 'cat
/app/config.yaml'`.

Both regex bugs named in that docstring are covered below, since they are the
failures this code has actually had.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "scripts", "git-hooks"))

from sanitize_config import (  # noqa: E402
    DEFAULT_PW,
    sanitize_main_config,
    sanitize_qa_config,
)


class MainConfig(unittest.TestCase):
    def test_a_live_github_token_is_blanked(self):
        out, changed = sanitize_main_config(
            "options:\n  github_token: ghp_liveTokenValue123\n")
        self.assertNotIn("ghp_liveTokenValue123", out)
        self.assertIn("github_token: ''", out)
        self.assertIn("github_token", changed)

    def test_an_already_empty_token_is_left_alone(self):
        # Reported as changed only when something actually changed, so the hook
        # does not rewrite the index for a no-op.
        out, changed = sanitize_main_config("options:\n  github_token: ''\n")
        self.assertEqual(changed, [])
        self.assertIn("github_token: ''", out)

    def test_module_passwords_go_back_to_the_shipping_default(self):
        out, changed = sanitize_main_config(
            "modules:\n  elk:\n    password: s3cret-from-this-box\n")
        self.assertNotIn("s3cret-from-this-box", out)
        self.assertIn(DEFAULT_PW, out)
        self.assertIn("password", changed)

    def test_portainers_longer_shipped_default_is_preserved(self):
        # Portainer refuses passwords under 12 chars, so forcing this one to
        # 123123 would silently change shipped behaviour: install.sh would then
        # generate a random password instead of using the documented one.
        out, changed = sanitize_main_config(
            "modules:\n  portainer:\n    password: 1234qwer!@#$\n")
        self.assertIn("1234qwer!@#$", out)
        self.assertEqual(changed, [])

    def test_a_hash_inside_a_quoted_password_is_not_treated_as_a_comment(self):
        # First of the two regex bugs the docstring records: a non-greedy `.*?`
        # stopped at the '#' inside a value and rewrote the line to a mangled
        # `123123#$'`.
        out, _ = sanitize_main_config(
            "modules:\n  x:\n    password: 'abc#def#ghi'\n")
        self.assertIn(DEFAULT_PW, out)
        self.assertNotIn("#def", out)

    def test_no_blank_lines_are_introduced(self):
        # Second recorded bug: `\s*` in the trailing group matched the newline,
        # so every edit added a blank line and the file grew on each commit.
        src = "options:\n  github_token: ghp_x\nmodules:\n  elk:\n    password: p\n"
        out, _ = sanitize_main_config(src)
        self.assertEqual(len(out.splitlines()), len(src.splitlines()))
        self.assertNotIn("\n\n", out)

    def test_comments_and_unrelated_lines_survive(self):
        # A textual edit, deliberately not a yaml round-trip: both tracked files
        # are full of operator-facing comments and the point of tracking them is
        # that a human reads them before installing.
        src = ("# Intact.AI configuration\n"
               "domain: 192.168.120.11   # the appliance address\n"
               "options:\n"
               "  github_token: ghp_x    # a real PAT\n")
        out, _ = sanitize_main_config(src)
        self.assertIn("# Intact.AI configuration", out)
        self.assertIn("domain: 192.168.120.11", out)
        self.assertIn("# the appliance address", out)
        self.assertIn("# a real PAT", out)

    def test_first_login_is_forced_true(self):
        # A fresh checkout must land in setup mode: first_login false with no
        # stored credential fails closed, i.e. nobody can sign in.
        out, changed = sanitize_main_config("first_login: false\n")
        self.assertIn("first_login: true", out)
        self.assertIn("first_login", changed)

    def test_sanitizing_twice_changes_nothing_the_second_time(self):
        src = ("first_login: false\noptions:\n  github_token: ghp_x\n"
               "modules:\n  elk:\n    password: p\n")
        once, _ = sanitize_main_config(src)
        twice, changed = sanitize_main_config(once)
        self.assertEqual(once, twice)
        self.assertEqual(changed, [])


class QaConfig(unittest.TestCase):
    def test_platform_and_windows_secrets_are_blanked(self):
        out, changed = sanitize_qa_config(
            "platform:\n  host: 192.168.120.11\n  sudo_password: hunter2\n"
            "windows:\n  password: Adm1nPass\n")
        self.assertNotIn("hunter2", out)
        self.assertNotIn("Adm1nPass", out)
        self.assertNotIn("192.168.120.11", out)
        self.assertIn("platform.sudo_password", changed)
        self.assertIn("windows.password", changed)

    def test_a_password_under_an_unlisted_section_is_left_alone(self):
        # Section-aware by design: an allowlist, so adding a non-secret knob
        # does not silently get wiped, and a future section's `password:` is
        # not blanked by a bare key-name match.
        out, changed = sanitize_qa_config(
            "future:\n  password: keep-me\n")
        self.assertIn("keep-me", out)
        self.assertEqual(changed, [])

    def test_non_secret_run_settings_survive(self):
        out, _ = sanitize_qa_config(
            "run:\n  output_dir: /var/tmp/qa\n  llm_summary: true\n")
        self.assertIn("/var/tmp/qa", out)
        self.assertIn("llm_summary: true", out)


class AgainstTheRealFile(unittest.TestCase):
    """The property scripts/ci/packager/package.py now depends on."""

    def test_the_live_config_yaml_sanitizes_to_something_secret_free(self):
        repo = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
        path = os.path.join(repo, "config.yaml")
        if not os.path.isfile(path):
            self.skipTest("no config.yaml in this checkout")
        try:
            import yaml
        except ImportError:
            self.skipTest("pyyaml not available")

        with open(path) as fh:
            raw = fh.read()
        clean, _ = sanitize_main_config(raw)

        # Still valid yaml -- install_deps.py parses this copy inside the image
        # build, so a mangled line would break the build rather than the commit.
        doc = yaml.safe_load(clean)
        self.assertIsInstance(doc, dict)

        self.assertFalse((doc.get("options") or {}).get("github_token"),
                         "github_token survived sanitizing")
        allowed = {DEFAULT_PW, "1234qwer!@#$", "", None}
        for name, mod in (doc.get("modules") or {}).items():
            if not isinstance(mod, dict):
                continue
            for key, value in mod.items():
                if "password" in key.lower() and value not in allowed:
                    self.fail(f"modules.{name}.{key} survived sanitizing")


if __name__ == "__main__":
    unittest.main(verbosity=2)
