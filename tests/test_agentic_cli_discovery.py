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

    def test_the_newest_copy_wins_regardless_of_install_method(self):
        # Not list order. An npm install made after ours is the one the operator
        # is using, and pretending otherwise is how a box ends up running a
        # binary its operator replaced.
        mine = self.plant("cli/bin/codex")
        os.utime(mine, (1_000_000, 1_000_000))
        theirs = self.plant("npm/@openai/codex/node_modules/@openai/"
                            "codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex")
        os.utime(theirs, (2_000_000, 2_000_000))
        self.assertEqual(self.sub.binary_path(self.P), theirs)
        # ...and the reverse, so this is about mtime and not about which glob ran.
        os.utime(mine, (3_000_000, 3_000_000))
        self.assertEqual(self.sub.binary_path(self.P), mine)

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


class TestTheOfficialInstallerLayout(_Base):
    """`curl -fsSL https://chatgpt.com/codex/install.sh | sh` — the command the
    vendor's own page gives, and a THIRD layout again:

        ~/.local/bin/codex                                       launcher symlink
        ~/.codex/packages/standalone/current      -> releases/<v>-<triple>
        ~/.codex/packages/standalone/releases/<v>-<triple>/bin/codex   the binary

    Two things bit here on a real box, both measured:

      * `current` is an ABSOLUTE symlink into the operator's home. Inside the
        container that path does not exist, so it resolves to nothing while the
        file sits right there under the mount. Everything must go through
        releases/*, never through current.
      * the installer keeps every release it has ever fetched. A lexical sort
        puts 0.99.0 above 0.149.1, so an operator who had just upgraded would
        keep running the old binary with nothing on any screen saying so.
    """

    def _standalone(self, version, *, mtime=None):
        rel = f"hostcodex/packages/standalone/releases/{version}-x86_64-unknown-linux-musl/bin/codex"
        p = self.plant(rel)
        self.sub._HOST_CODEX_HOME = os.path.join(self.tmp, "hostcodex")
        if mtime is not None:
            os.utime(p, (mtime, mtime))
        return p

    def test_the_official_installer_layout_is_found(self):
        want = self._standalone("0.149.1")
        self.assertTrue(self.sub.is_installed(self.P),
                        "the vendor's own install command produces a layout we miss")
        self.assertEqual(self.sub.binary_path(self.P), want)

    def test_it_never_goes_through_the_current_symlink(self):
        pats = " ".join(self.sub._npm_vendor_globs("codex"))
        self.assertIn("packages/standalone/releases/*/bin/codex", pats)
        self.assertNotIn("standalone/current", pats,
                         "current is an absolute host path — dead in a container")

    def test_the_newest_release_wins_not_the_alphabetical_one(self):
        old = self._standalone("0.99.0", mtime=1_000_000)
        new = self._standalone("0.149.1", mtime=2_000_000)
        self.assertGreater(old, new)               # lexically, 0.99 sorts after
        self.assertEqual(self.sub.binary_path(self.P), new,
                         "an upgraded operator would keep running the old binary")

    def test_the_credential_mount_carries_the_binary_too(self):
        # The binary lives inside ~/.codex, which is already mounted for the
        # credential — so this costs no second mount, and that is worth pinning
        # because someone tidying the compose file would not guess it.
        pats = " ".join(self.sub._npm_vendor_globs("codex"))
        self.assertIn(self.sub._HOST_CODEX_HOME + "/packages/standalone", pats)


class TestItReadsWhatTheInstallerSaysIsLive(_Base):
    """Ranking by mtime is a guess. `current` is an answer.

    The standalone installer keeps a `current` symlink beside releases/ naming
    the release it just installed — the one the operator's own `codex` resolves
    to. Its target is an ABSOLUTE host path, useless to follow from inside this
    container, but its basename is exact. When the two disagree, the marker is
    right: anything else has the appliance running a different binary from the
    person supporting it.
    """

    def _release(self, version, *, mtime=None):
        rel = ("hostcodex/packages/standalone/releases/"
               f"{version}-x86_64-unknown-linux-musl/bin/codex")
        p = self.plant(rel)
        self.sub._HOST_CODEX_HOME = os.path.join(self.tmp, "hostcodex")
        if mtime:
            os.utime(p, (mtime, mtime))
        return p

    def _mark(self, version):
        base = os.path.join(self.tmp, "hostcodex/packages/standalone")
        link = os.path.join(base, "current")
        if os.path.islink(link):
            os.unlink(link)
        # ABSOLUTE, exactly as the installer writes it — and pointing at a path
        # that does not exist here, which is the whole difficulty.
        os.symlink(f"/home/someone/.codex/packages/standalone/releases/"
                   f"{version}-x86_64-unknown-linux-musl", link)

    def test_the_marker_decides_which_release_runs(self):
        old = self._release("0.149.1", mtime=2_000_000)     # newer on disk
        new = self._release("0.150.0", mtime=1_000_000)     # older on disk
        self._mark("0.150.0")                                # but marked live
        self.assertEqual(self.sub.binary_path(self.P), new,
                         "mtime overruled the installer's own marker")
        self.assertTrue(os.path.exists(old))

    def test_an_absolute_marker_is_not_followed(self):
        # Following it resolves to nothing in a container. Only the basename is
        # used — that is what makes this work at all.
        self._release("0.150.0")
        self._mark("0.150.0")
        got = self.sub.binary_path(self.P)
        self.assertTrue(got.startswith(self.tmp), got)
        self.assertNotIn("/home/someone", got)

    def test_a_marker_pointing_at_a_missing_release_is_ignored(self):
        real = self._release("0.149.1")
        self._mark("9.9.9")                                  # stale marker
        self.assertEqual(self.sub.binary_path(self.P), real,
                         "a stale marker must not strand the appliance")

    def test_no_marker_falls_back_to_newest(self):
        self._release("0.149.1", mtime=1_000_000)
        new = self._release("0.150.0", mtime=2_000_000)
        self.assertEqual(self.sub.binary_path(self.P), new)


class TestTheContainerLocalGuessesAreGone(_Base):
    """/usr/local/bin, /usr/bin, ~/.local/bin and /opt/bin are the CONTAINER's
    filesystem. The operator's install can never be at any of them, so they could
    only ever match something inside the image — a false positive — while padding
    the diagnostic list with six paths that were never candidates."""

    def test_no_container_local_bin_dirs_are_searched(self):
        fresh = _load(os.path.join(self.tmp, "cli4"))
        self.assertEqual(fresh._BIN_SEARCH_DIRS, ())
        for c in fresh._candidate_paths(self.P):
            self.assertFalse(c in ("/usr/local/bin/codex", "/usr/bin/codex",
                                   "/opt/bin/codex", "/root/.local/bin/codex"), c)

    def test_the_searched_list_is_only_reachable_paths(self):
        fresh = _load(os.path.join(self.tmp, "cli5"))
        allowed = ("/host/", os.path.dirname(fresh.install_target_path(self.P)),
                   os.path.expanduser("~/."))
        for c in fresh._candidate_paths(self.P):
            self.assertTrue(c.startswith(allowed),
                            f"{c} is not somewhere the operator's copy can be")


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
        self.assertEqual(self.sub._HOST_PKG_DIR, "/host/codex-pkg")
        self.assertEqual(self.sub._HOST_CODEX_HOME, "/host/codex")

    def test_the_host_side_variables_cannot_reach_them(self):
        # Non-vacuous: this is exactly what env_file: does to this process.
        os.environ["INTACT_HOST_CODEX_PKG"] = "/usr/local/lib/node_modules"
        os.environ["INTACT_HOST_CODEX_HOME"] = "/home/someone/.codex"
        self.addCleanup(os.environ.pop, "INTACT_HOST_CODEX_PKG", None)
        self.addCleanup(os.environ.pop, "INTACT_HOST_CODEX_HOME", None)
        fresh = _load(os.path.join(self.tmp, "cli2"))
        self.assertEqual(fresh._HOST_PKG_DIR, "/host/codex-pkg",
                         "the host path leaked in through env_file again")
        self.assertEqual(fresh._HOST_CODEX_HOME, "/host/codex")

    def test_an_upgrade_does_not_strand_the_appliance(self):
        """THE VERSION-STABILITY RULE.

        `codex upgrade` writes a new release beside the old one. Any mount whose
        PATH names a version pins the box to whatever was installed the day it
        was configured — and it fails silently, because the old binary is still
        there and still runs. So the two roots that are meant to hit carry no
        version at all, and versions are resolved by glob inside them.
        """
        self.assertEqual(self.sub._HOST_CODEX_HOME, "/host/codex")
        self.assertEqual(self.sub._HOST_NPM_DIR, "/host/node_modules")
        # The rule is "no version in the path", not "must contain a glob":
        # /host/node_modules/@openai/codex/bin/codex carries no version because
        # npm overwrites the package in place, and that is fine.
        import re as _re
        for pat in self.sub._npm_vendor_globs("codex"):
            if pat.startswith(("/host/codex/", "/host/node_modules/")):
                self.assertIsNone(_re.search(r"\d+\.\d+", pat),
                                  f"{pat} pins a version into the search path")

    def test_a_new_release_is_picked_up_with_no_re_stamp(self):
        # Install 0.149.1, then "upgrade" to 0.150.0 the way the standalone
        # installer does — a new sibling under releases/. Nothing re-runs on the
        # host; the appliance must simply follow.
        home = os.path.join(self.tmp, "hostcodex")
        self.sub._HOST_CODEX_HOME = home
        old = self.plant("hostcodex/packages/standalone/releases/"
                         "0.149.1-x86_64-unknown-linux-musl/bin/codex")
        os.utime(old, (1_000_000, 1_000_000))
        self.assertEqual(self.sub.binary_path(self.P), old)
        new = self.plant("hostcodex/packages/standalone/releases/"
                         "0.150.0-x86_64-unknown-linux-musl/bin/codex")
        os.utime(new, (2_000_000, 2_000_000))
        self.assertEqual(self.sub.binary_path(self.P), new,
                         "the box kept running the release the operator replaced")

    def test_the_npm_root_is_searched_without_a_version_in_the_path(self):
        pats = [p for p in self.sub._npm_vendor_globs("codex")
                if p.startswith("/host/node_modules")]
        self.assertTrue(pats, "the npm global root is not searched at all")
        for p in pats:
            self.assertNotIn("0.1", p)

    def test_the_mount_destinations_match_the_compose_file(self):
        with open(self.COMPOSE, encoding="utf-8") as fh:
            compose = fh.read()
        for dest in (self.sub._HOST_PKG_DIR, self.sub._HOST_CODEX_HOME,
                     self.sub._HOST_NPM_DIR):
            self.assertIn(f":{dest}:ro", compose)

    def test_the_mounts_are_read_only(self):
        with open(self.COMPOSE, encoding="utf-8") as fh:
            compose = fh.read()
        for dest in (self.sub._HOST_PKG_DIR, self.sub._HOST_CODEX_HOME,
                     self.sub._HOST_NPM_DIR):
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

    def test_every_mounted_root_is_searched(self):
        fresh = _load(os.path.join(self.tmp, "cli3"))
        pats = " ".join(fresh._npm_vendor_globs("codex"))
        for root in ("/host/codex-pkg", "/host/codex/", "/host/node_modules"):
            self.assertIn(root, pats, f"{root} is not searched")


class TestThePanelTellsThemTheRightCommand(_Base):
    """An install instruction that 404s is worse than none. The first version of
    this panel guessed a raw.githubusercontent URL; the documented one is
    chatgpt.com/codex/install.sh."""

    STORE = os.path.join(ROOT, "modules/nginx/html/js/stores/settings.js")

    def test_the_documented_installer_url_is_offered(self):
        with open(self.STORE, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("https://chatgpt.com/codex/install.sh", src)
        self.assertNotIn("raw.githubusercontent.com/openai/codex", src)

    def test_the_login_command_is_offered(self):
        with open(self.STORE, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("codex login", src)

    def test_the_panel_offers_no_install_button(self):
        panel = os.path.join(ROOT, "modules/nginx/html/partials/settings.html")
        with open(panel, encoding="utf-8") as fh:
            src = fh.read()
        self.assertNotIn("Install CLI", src)
        self.assertNotIn("cliInstall(", src)


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
