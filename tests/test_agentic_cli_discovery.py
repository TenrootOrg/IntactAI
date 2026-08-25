"""The panel must not tell an operator the CLI is missing when it is right there.

THE BUG THIS EXISTS FOR. `binary_path()` returned ONE hardcoded path --
/app/data/agentic_cli/bin/codex, where our own installer writes -- and
`is_installed()` checked that path and nothing else. QA had codex installed and
working, ran `codex` in their shell, and the Agentic panel said "codex CLI is
not installed" with an Install CLI button. From where they were standing the
product was simply wrong.

WHERE A NORMAL INSTALL ACTUALLY GOES. Measured on a box with one, because the
layout is not what the name suggests:

    /usr/local/bin/codex
      -> ../lib/node_modules/@openai/codex/bin/codex.js          a NODE shim
    /usr/local/lib/node_modules/@openai/codex/node_modules/
      @openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex
                                                                 the real binary

The thing on PATH is JavaScript and needs a node runtime the backend image does
not ship. The vendored binary underneath is a static-pie ELF that answers
`--version` on its own (verified: codex-cli 0.147.0). So the search has to reach
INTO the npm tree, and the glob has to keep the platform triple variable or an
arm64 appliance finds nothing.

WHAT NO PATH LIST CAN FIX, pinned here so nobody re-opens this ticket looking
for a missing path: the backend runs in a container. A CLI installed on the HOST
is not on the container's filesystem and cannot be exec'd from it. detect() has
to SAY that, which is the difference between an operator fixing it in a minute
and an operator filing this bug again.
"""

import os
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "modules/backend/services/agentic/subscription_cli.py")


def _load(tmp_root):
    """Import the real module with its collaborators stubbed.

    subscription_cli imports the secret store, which drags the backend in. Only
    the discovery half is under test, so the import is satisfied rather than
    served -- the functions below never call it.
    """
    store = types.ModuleType("services.storage.secret_store")
    store.get_secret = lambda *a, **k: None
    store.set_secret = lambda *a, **k: None
    store.delete_secret = lambda *a, **k: None
    for name, mod in (("services", types.ModuleType("services")),
                      ("services.storage", types.ModuleType("services.storage"))):
        sys.modules.setdefault(name, mod)
    sys.modules["services.storage.secret_store"] = store

    os.environ["INTACT_AGENTIC_CLI_ROOT"] = tmp_root
    for stale in [m for m in sys.modules if m.endswith("subscription_cli")]:
        del sys.modules[stale]
    # A real module object, so a test assigning to sub.X rebinds the GLOBAL the
    # module's own functions read. types.SimpleNamespace(**ns) copies, and every
    # override would silently do nothing.
    mod = types.ModuleType("subscription_cli")
    mod.__file__ = SRC
    exec(compile(open(SRC, encoding="utf-8").read(), SRC, "exec"), mod.__dict__)
    return mod


class _NoWhich:
    """shutil, with which() blinded. The module uses shutil for exactly one
    thing in the code under test, and a real which() finds the host's install."""

    def __init__(self, real):
        self._real = real

    def __getattr__(self, name):
        return getattr(self._real, name)

    def which(self, *_a, **_k):
        return None


class _Base(unittest.TestCase):
    P = "codex-subscription"

    def setUp(self):
        import tempfile, shutil
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.sub = _load(os.path.join(self.tmp, "cli"))
        # SANDBOX THE SEARCH. Without this these tests find whatever codex is on
        # the machine running them -- and this repo is developed on a box that
        # has one, so "nothing installed" was true in CI and false locally. A
        # test whose answer depends on the developer's laptop is not a test.
        self.sub._NPM_ROOTS = (os.path.join(self.tmp, "npm"),)
        self.sub._BIN_SEARCH_DIRS = (os.path.join(self.tmp, "usrbin"),)
        self.sub.shutil = _NoWhich(self.sub.shutil)
        # ~ expansions must not escape either.
        os.environ["HOME"] = self.tmp

    def plant(self, relpath):
        """Create an executable file under the sandbox and return its path."""
        p = os.path.join(self.tmp, relpath)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write("#!/bin/sh\necho codex-cli 0.0.0\n")
        os.chmod(p, 0o755)
        return p


class TestItLooksBeyondOurOwnDirectory(_Base):

    def test_the_managed_path_is_still_searched_first(self):
        # It is the copy the upgrade keeps current; a stray newer binary must
        # never silently outrank it.
        cands = self.sub._candidate_paths(self.P)
        self.assertEqual(cands[0], self.sub.install_target_path(self.P))

    def test_it_searches_more_than_one_place(self):
        # The whole bug: one hardcoded path.
        self.assertGreater(len(self.sub._candidate_paths(self.P)), 1)

    def test_a_normal_npm_install_is_found(self):
        # The exact layout measured on a box with a normal install: the thing on
        # PATH is a node shim, and the runnable binary is buried under it.
        want = self.plant("npm/@openai/codex/node_modules/@openai/"
                          "codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex")
        self.assertTrue(self.sub.is_installed(self.P),
                        "a normal npm install still reads as 'not installed'")
        self.assertEqual(self.sub.binary_path(self.P), want)

    def test_the_managed_copy_beats_an_npm_one(self):
        self.plant("npm/@openai/codex/node_modules/@openai/"
                   "codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex")
        mine = self.plant("cli/bin/codex")
        self.assertEqual(self.sub.binary_path(self.P), mine,
                         "the copy upgrades keep current must win")

    def test_a_binary_on_a_plain_bin_dir_is_found(self):
        want = self.plant("usrbin/codex")
        self.assertTrue(self.sub.is_installed(self.P))
        self.assertEqual(self.sub.binary_path(self.P), want)

    def test_the_platform_triple_is_not_hardcoded(self):
        # A literal x86_64 path finds nothing on an arm64 appliance.
        pats = list(self.sub._npm_vendor_globs("codex"))
        vendored = [p for p in pats if "vendor" in p]
        self.assertTrue(vendored, "no vendored-binary pattern at all")
        for p in vendored:
            self.assertIn("vendor/*/", p)
            self.assertNotIn("x86_64", p)

    def test_a_non_root_npm_prefix_is_searched(self):
        # Asserted on the shipped constant, not the sandboxed one: an operator
        # who installed without sudo has it under their home, and dropping that
        # root is the same bug in a new coat.
        with open(SRC, encoding="utf-8") as _fh:
            src = _fh.read()
        self.assertIn(".npm-global", src)
        self.assertIn(".nvm", src)

    def test_it_finds_a_binary_in_our_own_directory(self):
        self.plant("cli/bin/codex")
        self.assertTrue(self.sub.is_installed(self.P))
        self.assertEqual(self.sub.binary_path(self.P),
                         self.sub.install_target_path(self.P))

    def test_nothing_anywhere_reads_as_not_installed(self):
        self.assertFalse(self.sub.is_installed(self.P))

    def test_a_non_executable_file_does_not_count(self):
        p = self.plant("cli/bin/codex")
        os.chmod(p, 0o644)
        self.assertFalse(self.sub.is_installed(self.P),
                         "a file we cannot exec is not an installed CLI")

    def test_the_candidate_list_has_no_duplicates(self):
        cands = self.sub._candidate_paths(self.P)
        self.assertEqual(len(cands), len(set(cands)))


class TestTheInstallerStillChecksItsOwnWork(_Base):
    """run_install_workflow must ask "did I produce the file", not "is there one
    somewhere". Accepting any candidate would let an unrelated copy on PATH
    report a failed download as a successful install -- and the next upgrade
    would then have nothing to update."""

    def test_the_install_target_is_fixed_not_resolved(self):
        self.assertEqual(self.sub.install_target_path(self.P),
                         os.path.join(self.tmp, "cli", "bin", "codex"))

    def test_the_installer_verifies_its_own_target(self):
        with open(SRC, encoding="utf-8") as _fh:
            src = _fh.read()
        seg = src[src.index("Installer exited") - 700:src.index("Installer exited") + 400]
        self.assertIn("_usable(install_target_path(provider))", seg)
        self.assertNotIn("if not is_installed(provider):", seg,
                         "the install check accepts any discovered copy")


class TestItExplainsItselfWhenNothingIsFound(_Base):
    """A bare "not installed" is what made this a bug report instead of a
    two-minute fix. The operator's copy is usually on the HOST, which this
    container cannot see or execute -- no path list changes that, so the message
    has to carry it."""

    def test_the_detail_lists_where_it_looked(self):
        d = self.sub.detect(self.P)
        self.assertFalse(d["installed"])
        self.assertIn("Searched:", d["detail"])
        self.assertIn(self.sub.install_target_path(self.P), d["detail"])

    def test_the_detail_names_the_container_boundary(self):
        d = self.sub.detect(self.P)
        self.assertIn("host", d["detail"].lower())
        self.assertIn("container", d["detail"].lower())

    def test_the_searched_paths_are_returned_for_the_ui(self):
        d = self.sub.detect(self.P)
        self.assertTrue(d.get("searched"))

    def test_a_found_cli_reports_where_it_came_from(self):
        self.plant("cli/bin/codex")
        d = self.sub.detect(self.P)
        self.assertTrue(d["installed"])
        self.assertEqual(d.get("path"), self.sub.install_target_path(self.P))


if __name__ == "__main__":
    unittest.main(verbosity=2)
