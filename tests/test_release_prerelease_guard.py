"""Releases for other branches must be GitHub pre-releases (2026-10-06).

Runs the REAL "A build from another branch must be a pre-release" step of
build-release-assets.yml against a throwaway git repo and a stub `gh`: a
commit on main builds either way; a commit off main, or a -devN tag, builds
only when its release is marked pre-release.
"""
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WF = os.path.join(ROOT, ".github/workflows/build-release-assets.yml")


def step_script() -> str:
    lines = open(WF, encoding="utf-8").read().split("\n")
    start = next(i for i, l in enumerate(lines) if "- name: A build from another branch must be a pre-release" in l)
    run = next(i for i in range(start, len(lines)) if lines[i].strip() == "run: |")
    body = []
    for l in lines[run + 1:]:
        if l.strip().startswith("- ") and not l.startswith(" " * 10):
            break
        body.append(l)
    return textwrap.dedent("\n".join(body))


class TheGuard(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        g = lambda *a: subprocess.run(["git", "-C", self.d, *a], check=True, capture_output=True, text=True).stdout.strip()
        g("init", "-q")
        g("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "a")
        self.main = g("rev-parse", "HEAD")
        g("update-ref", "refs/remotes/origin/main", self.main)
        g("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "dev")
        self.dev = g("rev-parse", "HEAD")
        self.bin = os.path.join(self.d, "bin")
        os.makedirs(self.bin)

    def run_step(self, tag, commit, prerelease):
        with open(os.path.join(self.bin, "gh"), "w") as fh:
            fh.write(f"#!/bin/sh\necho {prerelease}\n")
        os.chmod(os.path.join(self.bin, "gh"), 0o755)
        env = dict(os.environ, TAG=tag, COMMIT=commit, GITHUB_REPOSITORY="o/r",
                   PATH=self.bin + os.pathsep + os.environ["PATH"])
        return subprocess.run(["bash", "-c", step_script()], cwd=self.d, env=env,
                              capture_output=True, text=True, timeout=30)

    def test_a_main_release_builds(self):
        self.assertEqual(self.run_step("intact-20261007", self.main, "false").returncode, 0)

    def test_a_branch_release_that_is_a_prerelease_builds(self):
        self.assertEqual(self.run_step("intact-20261006-dev1", self.dev, "true").returncode, 0)

    def test_a_branch_release_that_is_not_a_prerelease_stops(self):
        r = self.run_step("intact-20261006-dev1", self.dev, "false")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Set as a pre-release", r.stdout)

    def test_a_dev_tag_on_main_still_has_to_be_a_prerelease(self):
        self.assertNotEqual(self.run_step("intact-20261006-dev1", self.main, "false").returncode, 0)


if __name__ == "__main__":
    unittest.main()
