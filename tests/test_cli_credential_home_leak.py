"""A leaked credential home wedges every later model call on the box.

THE BUG THIS EXISTS FOR. The subscription CLIs get a private credential home on
tmpfs so the token lives only in RAM. Docker's default /dev/shm is 64MB and each
home runs ~15MB, so about four fit. That was invisible while report narration made
ONE model call at a time.

It stopped being invisible when the report started analysing a case phase by
phase: six CLIs launch in the same second. Measured on a live appliance, three of
the six died instantly with

    failed to initialize in-process app-server client:
    No space left on device (os error 28)

on a box with 43GB free and 15% inode use -- so the message sends you to df, which
tells you nothing is wrong. Three ABANDONED homes were holding 47MB of the 64MB.

WHY THEY LEAK. codex leaves a background app-server child running. PID 1 in the
backend container is `python app.py`, which does not reap orphans, so the child is
re-parented there and keeps its credential dir open. `_release_home`'s
`shutil.rmtree(..., ignore_errors=True)` then fails and says NOTHING, and 15MB of
a 64MB filesystem is gone per run.

Fixed in three places, each pinned below: sweep abandoned homes before allocating
a new one, stop swallowing the removal failure, and (in docker-compose.yaml)
`shm_size: 1gb` plus `init: true` so the orphan is reaped at all.
"""

import os
import sys
import time
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "modules/backend/services/agentic/subscription_cli.py")
COMPOSE = os.path.join(ROOT, "modules/backend/docker-compose.yaml")


def _load():
    store = types.ModuleType("services.storage.secret_store")
    store.get_secret = lambda *a, **k: None
    store.set_secret = lambda *a, **k: None
    store.delete_secret = lambda *a, **k: None
    for name, mod in (("services", types.ModuleType("services")),
                      ("services.storage", types.ModuleType("services.storage"))):
        sys.modules.setdefault(name, mod)
    sys.modules["services.storage.secret_store"] = store
    mod = types.ModuleType("subscription_cli")
    mod.__file__ = SRC
    exec(compile(open(SRC, encoding="utf-8").read(), SRC, "exec"), mod.__dict__)
    return mod


class TheSweeperReclaimsAbandonedHomes(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.sub = _load()
        self.parent = tempfile.mkdtemp(prefix="shm-sim-")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.parent, ignore_errors=True)

    def _home(self, name, age_seconds):
        p = os.path.join(self.parent, name)
        os.makedirs(p, exist_ok=True)
        with open(os.path.join(p, "auth.json"), "w") as f:
            f.write("x")
        old = time.time() - age_seconds
        os.utime(p, (old, old))
        return p

    def test_an_abandoned_home_is_reclaimed(self):
        p = self._home("intact-cli-home-stale", 60 * 60)
        self.sub._sweep_abandoned_homes(self.parent)
        self.assertFalse(os.path.isdir(p), "the 47MB leak was never collected")

    def test_a_home_a_live_call_owns_is_never_touched(self):
        """The trap: a call in ANOTHER THREAD can run for ten minutes. Sweeping
        its home mid-flight would delete the credential out from under it."""
        p = self._home("intact-cli-home-inflight", 60 * 60)
        self.sub._HOME_SOURCE[p] = "store"
        try:
            self.sub._sweep_abandoned_homes(self.parent)
            self.assertTrue(os.path.isdir(p), "swept a home a live call owns")
        finally:
            self.sub._HOME_SOURCE.pop(p, None)

    def test_a_young_home_is_left_alone(self):
        """Untracked but recent = a call that just started."""
        p = self._home("intact-cli-home-young", 5)
        self.sub._sweep_abandoned_homes(self.parent)
        self.assertTrue(os.path.isdir(p))

    def test_unrelated_files_are_never_removed(self):
        """/dev/shm is shared. Only our own prefix is ours to delete."""
        other = os.path.join(self.parent, "someone-elses-thing")
        os.makedirs(other)
        os.utime(other, (0, 0))
        self.sub._sweep_abandoned_homes(self.parent)
        self.assertTrue(os.path.isdir(other))

    def test_no_parent_is_not_an_error(self):
        self.sub._sweep_abandoned_homes(None)


class TheContainerMustHaveRoomForAFanOut(unittest.TestCase):
    """These live in docker-compose.yaml, which ships in the release -- fixing the
    appliance by hand would leave every new install with the same 64MB."""

    def setUp(self):
        import yaml
        with open(COMPOSE, encoding="utf-8") as f:
            self.backend = yaml.safe_load(f)["services"]["backend"]

    def test_shm_is_raised_above_the_64mb_default(self):
        shm = str(self.backend.get("shm_size") or "")
        self.assertTrue(shm, "no shm_size: back to 64MB and ~4 concurrent CLIs")
        self.assertRegex(shm.lower(), r"^\d+(gb?|m b?)?$|^\d+(gb|mb|g|m)$")
        self.assertNotIn("64m", shm.lower())

    def test_pid1_reaps_orphans(self):
        self.assertIs(self.backend.get("init"), True,
                      "without an init, codex's orphaned child stays a zombie "
                      "holding the credential dir open and tmpfs leaks per run")
