"""A fuse must fail with a message, not take the host down.

`json.load` has no ceiling. A run payload larger than free memory does not
raise — it exhausts the machine. That happened on this appliance: the backend
was OOM-killed mid-fuse and the operator had to restart the host.

The fuse already streams member runs one at a time (store.py PASS 2, a
generator written for an earlier OOM), so the exposure is a SINGLE oversized
run, not the case total. Measured here: a 539.9 MB raw_results.json peaks at
1.64 GB RSS — 3.1x — so the guard budgets 4x and refuses when that would not
comfortably fit in MemAvailable.

Refusing names the file and the numbers, lets the other member runs fuse, and
leaves the run stale so it is retried when there is headroom.
"""

import ast
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORE = os.path.join(ROOT, "modules/backend/services/fusion/store.py")

WANTED = ("_available_ram_bytes", "_payload_too_big")


def _load():
    with open(STORE, encoding="utf-8") as fh:
        src = fh.read()
    tree = ast.parse(src)
    picked = {n.name: ast.get_source_segment(src, n) for n in tree.body
              if isinstance(n, ast.FunctionDef) and n.name in WANTED}
    mult = next(n for n in tree.body if isinstance(n, ast.Assign)
                and getattr(n.targets[0], "id", "") == "_PAYLOAD_RAM_MULTIPLIER")
    ns = {}
    exec(compile(ast.Module(body=[mult], type_ignores=[]), STORE, "exec"), ns)
    for name in WANTED:
        exec(compile(picked[name], STORE, "exec"), ns)
    return ns


NS = _load()


class _Base(unittest.TestCase):
    def setUp(self):
        self.logged = []
        self.log = lambda m, lvl="info": self.logged.append((lvl, m))

    def guard(self, size_bytes, avail_bytes):
        NS["os"] = __import__("os")
        real_getsize = os.path.getsize
        os.path.getsize = lambda p: size_bytes
        NS["_available_ram_bytes"] = lambda: avail_bytes
        try:
            return NS["_payload_too_big"]("/data/downloads/run_x/raw_results.json",
                                          log=self.log)
        finally:
            os.path.getsize = real_getsize


class TestItBlocksWhatWouldKillTheBox(_Base):

    def test_a_payload_larger_than_memory_is_refused(self):
        # 5 GB file, 4 GB available — parsing needs ~20 GB
        self.assertTrue(self.guard(5 * 10**9, 4 * 10**9))

    def test_the_refusal_says_what_and_why(self):
        self.guard(5 * 10**9, 4 * 10**9)
        self.assertTrue(self.logged, "a refusal must be logged, never silent")
        lvl, msg = self.logged[-1]
        self.assertEqual(lvl, "error")
        for expected in ("raw_results.json", "GB", "available", "Refuse"):
            self.assertIn(expected, msg)

    def test_the_real_measured_case_is_the_boundary(self):
        """539.9 MB peaked at 1.64 GB. With 6 GB free that must still run —
        blocking it would have blocked every fuse this appliance does."""
        self.assertFalse(self.guard(540 * 10**6, 6 * 10**9))

    def test_the_same_payload_is_refused_when_memory_is_scarce(self):
        """...and the identical file must be refused when the box is loaded."""
        self.assertTrue(self.guard(540 * 10**6, 2 * 10**9))


class TestItStaysOutOfTheWay(_Base):

    def test_a_small_payload_is_never_blocked(self):
        self.assertFalse(self.guard(9 * 10**6, 4 * 10**9))
        self.assertEqual(self.logged, [], "a normal fuse must log nothing")

    def test_it_does_not_block_when_memory_cannot_be_read(self):
        """A container without /proc/meminfo must not have every fuse refused —
        an unreadable gauge is not evidence of a full tank."""
        self.assertFalse(self.guard(5 * 10**9, None))

    def test_a_missing_file_is_not_an_error(self):
        NS["_available_ram_bytes"] = lambda: 4 * 10**9
        self.assertFalse(NS["_payload_too_big"]("/nope/raw_results.json", log=self.log))


class TestTheBudgetReflectsMeasurement(unittest.TestCase):

    def test_the_multiplier_covers_the_observed_expansion(self):
        """539.9 MB -> 1.64 GB RSS is 3.1x; the budget must exceed it."""
        self.assertGreaterEqual(NS["_PAYLOAD_RAM_MULTIPLIER"], 3.1)
