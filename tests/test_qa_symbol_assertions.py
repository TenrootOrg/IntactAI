"""The e2e suite's symbol-library checks, driven without a box.

These two assertions are the only thing standing between "an upgrade quietly
deleted volweb_media" and an operator finding out weeks later, on the day they
need memory analysis and have no internet to re-download with. A check that
cries wolf gets muted and a check that never fires is decoration, so both
failure shapes are pinned here rather than trusted.

THE DISTINCTION THAT MATTERS, and the reason these are not one function: a
count we could not READ is not a count that CHANGED. `docker exec` against a
stopped container, a box with no VolWeb installed, and a transient daemon
hiccup all return nothing — and reporting any of them as data loss is exactly
how a tripwire earns its way into the ignored pile.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "qa"))

from lib import appliance                                       # noqa: E402
from lib.runner import PhaseContext                             # noqa: E402


class _TL:
    def event(self, *a, **k):
        pass


def _ctx():
    return PhaseContext(cfg=None, tl=_TL(), run_dir="/tmp", results={},
                        redactor=lambda s: s)


def _only(ctx):
    checks = ctx.take_checks()
    assert len(checks) == 1, f"expected one check, got {len(checks)}"
    return checks[0]


class _Box:
    """Stands in for `docker exec` against the VolWeb worker."""

    def __init__(self, count=None, writable=None):
        self.count, self.writable = count, writable
        self.script = None

    def __call__(self, script, container=None, timeout=60):
        self.script = script
        if "wc -l" in script:
            return "" if self.count is None else str(self.count)
        if self.count is None:
            return ""                      # unreachable box answers nothing
        return {True: "OK", False: "DENIED", None: ""}[self.writable]


class _Patched(unittest.TestCase):

    def box(self, **kw):
        b = _Box(**kw)
        real = appliance._symbols_sh
        appliance._symbols_sh = b
        self.addCleanup(lambda: setattr(appliance, "_symbols_sh", real))
        return b


class TestTheInstallSideCheck(_Patched):
    """After an install the library must exist AND be writable by `app`."""

    def test_a_writable_library_passes_and_reports_the_count(self):
        self.box(count=3, writable=True)
        ctx = _ctx()
        self.assertEqual(appliance.assert_symbols_usable(ctx), 3)
        c = _only(ctx)
        self.assertTrue(c.ok)
        self.assertIn("3 file(s)", c.actual)

    def test_a_root_owned_library_FAILS(self):
        """The bug that shipped for months. The directory is created by a root
        `docker exec` and the chown that handed it to `app` only ran when the
        installer had actually staged a file — which never happens, because the
        shipped pack holds only a .gitkeep. Readable, never writable: runs kept
        starting, kept finishing, and the box learned nothing."""
        self.box(count=3, writable=False)
        ctx = _ctx()
        appliance.assert_symbols_usable(ctx)
        c = _only(ctx)
        self.assertFalse(c.ok, "a library app cannot write to is not usable")
        self.assertIn("NOT writable", c.actual)

    def test_a_populated_but_unwritable_library_still_fails(self):
        """Counting files is not the test. A box can hold every ISF it was
        shipped and still be unable to keep the next one it learns."""
        self.box(count=900, writable=False)
        ctx = _ctx()
        appliance.assert_symbols_usable(ctx)
        self.assertFalse(_only(ctx).ok)

    def test_an_empty_but_writable_library_passes(self):
        """Zero symbols is a legitimate state — a connected box downloads on
        first use. What is not legitimate is being unable to keep them."""
        self.box(count=0, writable=True)
        ctx = _ctx()
        appliance.assert_symbols_usable(ctx)
        self.assertTrue(_only(ctx).ok)

    def test_no_volweb_on_the_box_is_a_skip_not_a_failure(self):
        self.box(count=None)
        ctx = _ctx()
        self.assertIsNone(appliance.assert_symbols_usable(ctx))
        c = _only(ctx)
        self.assertTrue(c.ok)
        self.assertIn("SKIPPED", c.actual)

    def test_it_asks_the_kernel_rather_than_reading_mode_bits(self):
        """Mode bits miss the group, the sticky bit, and whatever a future base
        image changes. Touching a file as `app` cannot be wrong."""
        b = self.box(count=1, writable=True)
        appliance.symbols_writable()
        self.assertIn("su app", b.script)
        self.assertIn("touch", b.script)
        self.assertIn("rm -f", b.script, "the probe must clean up after itself")


class TestTheUpgradeSideCheck(_Patched):

    def survived(self, before, after):
        self.box(count=after)
        ctx = _ctx()
        appliance.assert_symbols_survived(ctx, before, "after")
        return _only(ctx)

    def test_an_unchanged_library_passes(self):
        self.assertTrue(self.survived(3, 3).ok)

    def test_a_grown_library_passes(self):
        """Runs between the two counts legitimately add symbols."""
        self.assertTrue(self.survived(3, 9).ok)

    def test_a_shrunken_library_FAILS_with_both_numbers(self):
        c = self.survived(9, 3)
        self.assertFalse(c.ok)
        self.assertIn("9", str(c.expected))
        self.assertIn("3 file(s)", c.actual)

    def test_losing_everything_fails(self):
        self.assertFalse(self.survived(3, 0).ok)

    def test_a_count_that_could_not_be_READ_is_never_a_count_that_CHANGED(self):
        for before, after in ((None, 3), (3, None), (None, None)):
            c = self.survived(before, after)
            self.assertTrue(c.ok, f"before={before} after={after} must skip")
            self.assertIn("SKIPPED", c.actual)


class TestTheContainerNameIsReadWhenUsedNotWhenImported(unittest.TestCase):
    """`container=SYMBOLS_CONTAINER` as a DEFAULT ARGUMENT is evaluated once at
    import, so a box that renames the worker would be silently ignored — and so
    was the first version of the test above, which patched the module global,
    saw the check pass anyway, and reported a skip path that had never run."""

    def test_pointing_it_elsewhere_takes_effect(self):
        seen = []
        real = appliance._run
        appliance._run = lambda argv, timeout=60: seen.append(argv) or ""
        try:
            appliance.symbol_count()
            self.assertIn(appliance.SYMBOLS_CONTAINER, seen[0])
            appliance.SYMBOLS_CONTAINER = "somewhere_else"
            appliance.symbol_count()
            self.assertIn("somewhere_else", seen[1])
        finally:
            appliance._run = real
            appliance.SYMBOLS_CONTAINER = "intact_volweb_workers"


if __name__ == "__main__":
    unittest.main(verbosity=2)
