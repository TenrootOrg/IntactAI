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
    """A bare "not installed" is what turned this into a bug report.

    The appliance no longer installs codex — the operator does, on the host —
    so the only useful thing this state can say is what to run. Pinned as a
    CONTRACT (host, and the login command), not as a sentence, so the wording
    can be improved without a test failing over it.
    """

    def test_the_detail_says_what_to_do_and_where(self):
        d = self.sub.detect(self.P)
        self.assertFalse(d["installed"])
        self.assertIn("host", d["detail"].lower())
        self.assertIn("codex login", d["detail"])

    def test_the_searched_paths_are_still_returned(self):
        # Not shown in the panel, but it is what a support bundle needs when an
        # operator swears it is installed and the box disagrees.
        d = self.sub.detect(self.P)
        self.assertTrue(d.get("searched"))
        self.assertIn(self.sub.install_target_path(self.P), d["searched"])

    def test_a_found_cli_reports_where_it_came_from(self):
        self.plant("cli/bin/codex")
        d = self.sub.detect(self.P)
        self.assertTrue(d["installed"])
        self.assertEqual(d.get("path"), self.sub.install_target_path(self.P))


class TestTheHostCredential(_Base):
    """The operator's own login is the source of truth, and stays theirs."""

    def _host_auth(self, blob='{"tokens": {"x": 1}}'):
        home = os.path.join(self.tmp, "hostcodex")
        os.makedirs(home, exist_ok=True)
        self.sub._HOST_CODEX_HOME = home
        with open(os.path.join(home, "auth.json"), "w") as fh:
            fh.write(blob)
        return home

    def test_a_host_credential_counts_as_connected(self):
        self.sub._HOST_CODEX_HOME = os.path.join(self.tmp, "nothing")
        self.assertFalse(self.sub.has_credentials(self.P))
        self._host_auth()
        self.assertTrue(self.sub.has_credentials(self.P),
                        "the operator signed in on the host; that is signed in")

    def test_an_absent_host_home_is_not_an_error(self):
        self.sub._HOST_CODEX_HOME = "/definitely/not/here"
        self.assertIsNone(self.sub._read_host_credential(self.P))
        self.assertFalse(self.sub.has_credentials(self.P))

    def test_an_empty_file_is_not_a_credential(self):
        self._host_auth(blob="   \n")
        self.assertFalse(self.sub.has_credentials(self.P))

    def test_a_host_credential_is_never_written_into_our_database(self):
        """THE PRIVACY/DRIFT RULE.

        Writing their token back into our secret store would make has_credentials
        prefer our copy forever — so the appliance quietly forks its own snapshot
        of their identity, and keeps using it after they sign out or sign in as
        somebody else, with nothing on any screen saying why.
        """
        self._host_auth()
        written = []
        self.sub.set_secret = lambda k, v: written.append((k, v))
        home = self.sub._materialize_home(self.P)
        # the CLI rotates the token in place; simulate that
        with open(os.path.join(home, "auth.json"), "w") as fh:
            fh.write('{"tokens": {"x": 2}}')
        self.sub._release_home(self.P, home)
        self.assertEqual(written, [], "a host credential was copied into our DB")

    def test_a_stored_credential_is_still_refreshed(self):
        # Boxes that signed in through the old in-app flow must keep working:
        # their token rotates on use, and dropping the write-back would expire
        # them within hours.
        self.sub.get_secret = lambda *a, **k: '{"tokens": {"x": 1}}'
        written = []
        self.sub.set_secret = lambda k, v: written.append((k, v))
        home = self.sub._materialize_home(self.P)
        with open(os.path.join(home, "auth.json"), "w") as fh:
            fh.write('{"tokens": {"x": 2}}')
        self.sub._release_home(self.P, home)
        self.assertEqual(len(written), 1, "a stored credential stopped refreshing")

    def test_the_stored_credential_wins_over_the_host_one(self):
        # Same reason: an appliance that already had one must not be signed out
        # by an unrelated host login appearing.
        self._host_auth()
        self.sub.get_secret = lambda *a, **k: '{"tokens": {"stored": 1}}'
        home = self.sub._materialize_home(self.P)
        with open(os.path.join(home, "auth.json")) as fh:
            self.assertIn("stored", fh.read())
        self.sub._release_home(self.P, home, persist=False)


class TestTheMountPointsAreNotReadFromTheEnvironment(_Base):
    """The bug that made the whole bridge silently do nothing.

    modules/backend/.env carries INTACT_HOST_CODEX_PKG / INTACT_HOST_CODEX_HOME
    so compose can expand them as the HOST side of two bind mounts. compose also
    passes that same file through `env_file:`, so both variables land in the
    CONTAINER's environment too. Reading them here got the host path --
    /usr/local/lib/node_modules, which does not exist inside this image -- and
    discovery found nothing while the mount sat at /host/node_modules working
    perfectly. Measured on a live appliance: the mount was readable, the binary
    was there, and _NPM_ROOTS came back holding the host path twice.

    The destination is a contract between docker-compose.yaml and this module.
    It is not a setting, and it must not be reachable from the environment.
    """

    COMPOSE = os.path.join(ROOT, "modules/backend/docker-compose.yaml")

    def test_the_mount_points_are_constants(self):
        self.assertEqual(self.sub._HOST_PKG_DIR, "/host/node_modules")
        self.assertEqual(self.sub._HOST_CODEX_HOME, "/host/codex")

    def test_the_host_side_variables_cannot_reach_them(self):
        # Non-vacuous: this is exactly what env_file: does to this process.
        os.environ["INTACT_HOST_CODEX_PKG"] = "/usr/local/lib/node_modules"
        os.environ["INTACT_HOST_CODEX_HOME"] = "/home/someone/.codex"
        self.addCleanup(os.environ.pop, "INTACT_HOST_CODEX_PKG", None)
        self.addCleanup(os.environ.pop, "INTACT_HOST_CODEX_HOME", None)
        fresh = _load(os.path.join(self.tmp, "cli2"))
        self.assertEqual(fresh._HOST_PKG_DIR, "/host/node_modules",
                         "the host path leaked in through env_file again")
        self.assertEqual(fresh._HOST_CODEX_HOME, "/host/codex")

    def test_the_mount_destinations_match_the_compose_file(self):
        with open(self.COMPOSE, encoding="utf-8") as fh:
            compose = fh.read()
        self.assertIn(f":{self.sub._HOST_PKG_DIR}:ro", compose)
        self.assertIn(f":{self.sub._HOST_CODEX_HOME}:ro", compose)

    def test_the_mounts_are_read_only(self):
        with open(self.COMPOSE, encoding="utf-8") as fh:
            compose = fh.read()
        for dest in (self.sub._HOST_PKG_DIR, self.sub._HOST_CODEX_HOME):
            self.assertNotIn(f":{dest}:rw", compose)
            self.assertNotIn(f":{dest}\n", compose)

    def test_nothing_is_mounted_over_the_images_own_bin(self):
        # The obvious implementation mounts /usr/local/bin over itself, and this
        # image keeps its python interpreter there.
        with open(self.COMPOSE, encoding="utf-8") as fh:
            compose = fh.read()
        for dangerous in (":/usr/local/bin", ":/usr/bin", ":/usr/local/lib"):
            self.assertNotIn(dangerous, compose,
                             f"a mount at {dangerous} would shadow the image")

    def test_the_npm_root_is_searched_first(self):
        # A fresh load, not self.sub: setUp sandboxes _NPM_ROOTS, so asserting
        # on it here would only ever measure the sandbox.
        fresh = _load(os.path.join(self.tmp, "cli3"))
        self.assertEqual(fresh._NPM_ROOTS[0], "/host/node_modules",
                         "the operator's own install must be searched first")


class TestThereIsNoInstallOrSignInAnyMore(_Base):
    """The appliance stopped installing software on the host and holding
    somebody's ChatGPT credential. Pinned so neither comes back by accident."""

    ROUTES = os.path.join(ROOT, "modules/backend/routes/agentic_cli_routes.py")

    def test_the_install_and_login_routes_are_gone(self):
        with open(self.ROUTES, encoding="utf-8") as fh:
            src = fh.read()
        code = "\n".join(l.split("#", 1)[0] for l in src.splitlines())
        for gone in ("/api/agentic/cli/install", "/api/agentic/cli/login",
                     "/api/agentic/cli/disconnect",
                     "/api/agentic/cli/import-credential"):
            self.assertNotIn(gone, code, f"{gone} is back")

    def test_status_and_test_survive(self):
        with open(self.ROUTES, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("/api/agentic/cli/status", src)
        self.assertIn("/api/agentic/cli/test", src)

    def test_no_installer_workflow_remains(self):
        with open(SRC, encoding="utf-8") as fh:
            code = "\n".join(l.split("#", 1)[0] for l in fh.read().splitlines())
        for gone in ("def run_install_workflow", "def run_configure_workflow",
                     "def login_start", "def import_credential"):
            self.assertNotIn(gone, code, f"{gone} is back")

    def test_the_old_workflow_names_are_kept_for_orphan_sweeping(self):
        # NOT a leftover: sweep_orphaned_runs matches on these to close rows an
        # upgrading appliance still has from the old flow. Dropping them strands
        # those rows "running" forever.
        with open(SRC, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn('"install":', src)
        self.assertIn('"configure":', src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
