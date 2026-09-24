"""The case header strip shows facts about the INVESTIGATION, not the graph.

`entities` and `links` were removed from it. They were not wrong, they were
unanswerable: measured on a real case, 416 entities is 374 events + 20
processes + 12 IOCs + 9 accounts + 1 asset, every one of which the operator
already browses by type in Timeline / Identities / Risk. And `links` — 73
account-to-asset edges — had no view anywhere in the product that could show
them, so the number raised a question nothing could answer. An operator asked
exactly that question, which is how this got removed.

This pins the removal rather than the wording: someone re-adding a count to
the strip has to come here and say why, and the check that matters is that a
number in the header is a number the operator can act on.
"""

import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = os.path.join(ROOT, "modules/nginx/html")


def _read(*p):
    with open(os.path.join(HTML, *p), encoding="utf-8") as fh:
        return fh.read()


class TestTheStatStrip(unittest.TestCase):

    def setUp(self):
        s = _read("cases.html")
        m = re.search(r"function statSpans\(c\)\{(.*?)\n\}", s, re.S)
        self.assertIsNotNone(m, "statSpans() is gone or was reshaped")
        self.body = m.group(1)

    def test_it_still_shows_what_an_operator_acts_on(self):
        for field in ("hosts", "findings", "cross_host"):
            self.assertIn(f"c.{field}", self.body,
                          f"{field} disappeared from the header")

    def test_entities_and_links_are_not_in_the_strip(self):
        for field in ("entities", "links"):
            self.assertNotIn(f"c.{field}", self.body,
                             f"{field} is back in the header strip — it is a fact "
                             "about the graph, and nothing in the UI can show it")

    def test_the_reason_is_written_down_where_it_will_be_read(self):
        """Not decoration: without it the next person reads the removal as an
        oversight and puts the counts back."""
        s = _read("cases.html")
        head = s[:s.index("function statSpans")]
        self.assertIn("DELIBERATELY not shown", head)


class TestTheCacheChainWasBumped(unittest.TestCase):
    """Case Analysis is an iframe three hand-versioned layers deep. Bump only
    the inner one and the browser never requests it, because the outer layers
    are cached under URLs that still point at the old inner version — the
    change is invisible and reads as a backend bug. Cost three rounds of
    "still nothing" once."""

    def versions(self):
        return (
            int(re.search(r"partial-loader\.js\?v=(\d+)",
                          _read("index.html")).group(1)),
            int(re.search(r"partials/\$\{name\}\.html\?v=(\d+)",
                          _read("js/bootstrap/partial-loader.js")).group(1)),
            int(re.search(r"cases\.html\?embed=1&view=analysis&v=(\d+)",
                          _read("partials/case-analysis.html")).group(1)),
        )

    def test_all_three_layers_are_current(self):
        loader, partial, frame = self.versions()
        self.assertGreaterEqual(loader, 82)
        self.assertGreaterEqual(partial, 98)
        self.assertGreaterEqual(frame, 83)


if __name__ == "__main__":
    unittest.main(verbosity=2)
