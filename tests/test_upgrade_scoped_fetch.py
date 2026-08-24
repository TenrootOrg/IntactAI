"""A box installed before 2026-08-15 cannot verify a partial online upgrade.

Reported live: `/api/upgrade/online` from an intact-20260811 box (and,
independently, the e2e ui-online-full scenario starting from the same tag)
both refused with "Package file verification FAILED" on a perfectly healthy
target release. Root cause: intact-20260811 predates both the scoped
verification fix (fba50cb6, 2026-08-15) and scripts/bootstrap_upgrade.sh
(2026-08-16) -- its own lib/upgrade/package.sh runs before the hop ever
reaches the target release's code, downloads exactly the --only subset the
dashboard asked for, then verifies that subset against the FULL release
manifest and refuses everything it never fetched. Confirmed: the string
INTACT_RELEASE_ONLY_MODULES appears zero times in that tag's package.sh.

_installed_engine_needs_full_fetch() cannot be imported directly -- it lives
in upgrade_routes.py, which pulls in flask and the full services package --
so it is lifted out and executed against a stubbed WORKDIR, exactly as
test_llm_status.py does for llm_sim.py.
"""

import ast
import os
import shutil
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPGRADE_ROUTES = os.path.join(ROOT, "modules/backend/routes/upgrade_routes.py")


def _load():
    with open(UPGRADE_ROUTES, encoding="utf-8") as f:
        src = f.read()
    tree = ast.parse(src)
    ns = {"os": os, "WORKDIR": ""}
    picked = next((n for n in tree.body if isinstance(n, ast.FunctionDef)
                   and n.name == "_installed_engine_needs_full_fetch"), None)
    if picked is None:
        raise AssertionError("_installed_engine_needs_full_fetch not found in upgrade_routes.py")
    exec(compile(ast.Module(body=[picked], type_ignores=[]), UPGRADE_ROUTES, "exec"), ns)
    return ns


NS = _load()
needs_full_fetch = NS["_installed_engine_needs_full_fetch"]


class TestScopedFetchSupport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        NS["WORKDIR"] = self.tmp

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_package_sh(self, body):
        d = os.path.join(self.tmp, "lib", "upgrade")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "package.sh"), "w", encoding="utf-8") as fh:
            fh.write(body)

    def test_no_file_at_all_needs_full_fetch(self):
        # No lib/upgrade/package.sh on disk at all -- older than any engine.
        self.assertTrue(needs_full_fetch())

    def test_pre_fix_engine_needs_full_fetch(self):
        # A real pre-2026-08-15 shape: has upkg_acquire, no scoped branch.
        self._write_package_sh(
            "upkg_acquire() {\n"
            "    upkg_extract \"$@\" || return 1\n"
            "    upkg_verify_file_checksums || return 1\n"
            "}\n"
        )
        self.assertTrue(needs_full_fetch())

    def test_post_fix_engine_does_not_need_full_fetch(self):
        self._write_package_sh(
            "upkg_acquire() {\n"
            "    if [[ -n \"${INTACT_RELEASE_ONLY_MODULES:-}\" ]]; then\n"
            "        upkg_verify_paths_against_manifest \"$list\"\n"
            "    else\n"
            "        upkg_verify_file_checksums\n"
            "    fi\n"
            "}\n"
        )
        self.assertFalse(needs_full_fetch())

    def test_real_intact_20260811_needs_full_fetch(self):
        # Not a stub -- the actual tag's actual file, read via git show, so
        # this fails the moment that release's content is misremembered.
        import subprocess
        try:
            out = subprocess.run(
                ["git", "show", "intact-20260811:lib/upgrade/package.sh"],
                cwd=ROOT, capture_output=True, text=True, timeout=10)
        except Exception:
            self.skipTest("git not available")
        if out.returncode != 0:
            self.skipTest("intact-20260811 tag not available locally")
        self._write_package_sh(out.stdout)
        self.assertTrue(needs_full_fetch())

    def test_real_development_head_does_not_need_full_fetch(self):
        # The live, current file -- proves the check does not false-positive
        # on the box actually running this code today.
        with open(os.path.join(ROOT, "lib/upgrade/package.sh"), encoding="utf-8") as fh:
            self._write_package_sh(fh.read())
        self.assertFalse(needs_full_fetch())


if __name__ == "__main__":
    unittest.main(verbosity=2)
