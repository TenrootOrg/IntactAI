"""Inside a selected scope, the "Analyze this scope" cards can only narrow it.

QA: in the scope 2025-09-21 11:09:04 -> 13:23:50 the panel still said "Broad scope"
and offered the very same window (clicking it changed nothing) and a window on
2025-05-27, outside the scope -- a recurring detection active in the scope had
brought its first date along.
"""
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import store  # noqa: E402

SCOPE = {"start": "2025-09-21T11:09:04", "end": "2025-09-21T13:23:50"}
card = lambda s, e, **kw: {"window": {"start": s, "end": e}, **kw}


class CardsInsideScope(unittest.TestCase):
    def test_the_qa_case_leaves_nothing_to_offer(self):
        cards = [card("2025-09-21T11:09:04", "2025-09-21T13:23:50", title="Phase 1"),   # the scope itself
                 card("2025-05-27T11:16:56", "2025-05-27T11:17:10", title="Phase 2")]   # outside it
        self.assertEqual(store._cards_inside_scope(cards, SCOPE), [])

    def test_a_card_inside_is_kept_and_one_over_the_edge_is_clipped(self):
        inside = card("2025-09-21T11:30:00", "2025-09-21T12:00:00", title="in")
        edge = card("2025-05-27T09:00:00", "2025-09-21T11:40:00", title="edge")
        out = store._cards_inside_scope([inside, edge, card("x", "y", rollup=True)], SCOPE)
        self.assertEqual([c["title"] for c in out if not c.get("rollup")], ["in", "edge"])
        self.assertEqual(out[1]["window"], {"start": "2025-09-21T11:09:04", "end": "2025-09-21T11:40:00"})
        self.assertEqual(edge["window"]["start"], "2025-05-27T09:00:00")      # the input is not mutated

    def test_only_the_rollup_left_means_no_panel(self):
        self.assertEqual(store._cards_inside_scope([card("a", "b", rollup=True)], SCOPE), [])

    def test_no_scope_selected_changes_nothing(self):
        cards = [card("2025-05-27T11:16:56", "2025-05-27T11:17:10")]
        self.assertIs(store._cards_inside_scope(cards, None), cards)


if __name__ == "__main__":
    unittest.main()
