"""Every $store.memory.X the Memory panel binds to must exist in the store.

A typo in an Alpine binding fails silently: the control renders, does nothing,
and looks like a backend problem. The live-page harness (jsdom) would catch it,
but it skips wherever jsdom is not installed — which is most places — so this
offline check covers the one mistake that is both easy to make and invisible.
"""

import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PANEL = os.path.join(ROOT, "modules/nginx/html/partials/memory.html")
STORE = os.path.join(ROOT, "modules/nginx/html/js/memory.js")


def _read(p):
    with open(p, encoding="utf-8") as fh:
        return fh.read()


class TestThePanelOnlyBindsWhatTheStoreHas(unittest.TestCase):

    def setUp(self):
        self.panel = _read(PANEL)
        self.store = _read(STORE)
        # Everything declared inside Alpine.store('memory', { ... }): both
        # `name:` properties and `name()` / `async name()` methods.
        body = self.store[self.store.index("Alpine.store('memory'"):]
        self.declared = set(re.findall(r"^\s{8}(?:async\s+)?([A-Za-z_]\w*)\s*[:(]", body, re.M))

    def test_the_store_was_parsed(self):
        """Guard the guard: a parse that finds nothing would pass every case."""
        self.assertIn("blueprintId", self.declared)
        self.assertIn("startRun", self.declared)
        self.assertGreater(len(self.declared), 20)

    def test_every_binding_resolves(self):
        used = set(re.findall(r"\$store\.memory\.([A-Za-z_]\w*)", self.panel))
        self.assertTrue(used, "no bindings found — the panel or this regex is wrong")
        missing = sorted(used - self.declared)
        self.assertEqual(missing, [], f"panel binds to undeclared store members: {missing}")

    def test_the_new_controls_are_actually_wired(self):
        """Named explicitly so deleting a control fails here rather than
        quietly shrinking the panel."""
        for name in ("keepDump", "dumps", "selectedDump", "startReuse",
                     "loadDumps", "dumpLabel", "adoptId", "adoptRun"):
            self.assertIn(name, self.declared, f"{name} is missing from the store")
            self.assertIn(f"$store.memory.{name}", self.panel, f"{name} is not used by the panel")


class TestTheCacheChainWasBumped(unittest.TestCase):
    """memory.html is loaded by the partial loader and memory.js by index.html,
    each behind a hand-written ?v=. Ship a change without bumping them and the
    browser serves the old file — the change is invisible and looks like a
    backend bug."""

    def test_all_three_layers_agree_they_are_current(self):
        loader = _read(os.path.join(ROOT, "modules/nginx/html/js/bootstrap/partial-loader.js"))
        index = _read(os.path.join(ROOT, "modules/nginx/html/index.html"))
        partial_v = int(re.search(r"partials/\$\{name\}\.html\?v=(\d+)", loader).group(1))
        loader_v = int(re.search(r"partial-loader\.js\?v=(\d+)", index).group(1))
        memory_v = int(re.search(r"js/memory\.js\?v=(\d+)", index).group(1))
        # The values themselves are arbitrary; what matters is that this file
        # is updated with them, so a future change has to look at the chain.
        self.assertGreaterEqual(partial_v, 92)
        self.assertGreaterEqual(loader_v, 76)
        self.assertGreaterEqual(memory_v, 14)


if __name__ == "__main__":
    unittest.main(verbosity=2)
