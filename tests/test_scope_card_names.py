"""Scope cards: named by WINDOW, and critical detections never only in the rollup.

Found in the audit (jev_test): after a re-fuse reordered the windows, all six
cards carried another phase's name — card 1 (2025-04-21) read "Phase 1 — …",
a name the report gave to 2026-04-07 — because names were matched by number.
And 5 critical rows sat only in the unclickable "further windows" line.
"""
import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import render, schema  # noqa: E402

REPORT = """## Phases at a glance

### Phase 1 — Credential theft and tool staging
- **Window:** `2026-04-07T12:24:58Z` → `2026-04-20T15:17:08Z`
- **Hosts:** A

### Phase 4 — Credential theft and lateral movement
- **Window:** `2025-04-21T21:19:15Z` → `2025-05-04T10:20:18Z`
- **Hosts:** B
"""


def _card(n, start, end):
    return {"n": n, "window": {"start": start, "end": end}}


class Names(unittest.TestCase):
    def test_named_by_overlapping_window_not_by_number(self):
        cards = [_card(1, "2025-04-22T00:00:00Z", "2025-05-03T00:00:00Z"),
                 _card(4, "2026-04-08T00:00:00Z", "2026-04-19T00:00:00Z"),
                 _card(2, "2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z"),
                 {"rollup": True, "window": {"start": "2024-01-01T00:00:00Z", "end": "2026-12-01T00:00:00Z"}}]
        render.name_cards_from_report(cards, REPORT)
        self.assertEqual([c["name"] for c in cards],
                         ["Credential theft and lateral movement", "Credential theft and tool staging",
                          None, None])

    def test_no_report_no_names(self):
        cards = [_card(1, "2025-04-22T00:00:00Z", "2025-05-03T00:00:00Z")]
        render.name_cards_from_report(cards, "")
        self.assertIsNone(cards[0]["name"])

    def test_chat_clusters_are_the_cards_on_screen(self):
        # chat called zoom_targets with its own arguments: its "cluster 3" could be
        # another card, and it never saw the report's names
        from unittest import mock
        from services.fusion import investigate, store
        cards = [{**_card(4, "2025-04-22T00:00:00Z", "2025-05-03T00:00:00Z"), "title": "t4",
                  "host_labels": ["B"], "finding_count": 2, "severity": "high", "mitre": []}]
        with mock.patch.object(store, "get_case", return_value={"report_md": REPORT}), \
             mock.patch.object(store, "scope_cards", return_value=("macro", "", cards, None)), \
             mock.patch.object(render, "zoom_targets") as zt:
            out = investigate._tool("c1", "clusters", {})
        zt.assert_not_called()
        self.assertEqual([(c["n"], c["name"]) for c in out], [(4, "Credential theft and lateral movement")])


class CriticalNotInRollup(unittest.TestCase):
    def test_windows_with_critical_detections_all_stay_cards(self):
        # 8 separate weekly windows, EACH with a critical detection: 6 cards is the
        # normal cap, the other 2 must not vanish into the rollup
        g = schema.FusionGraph(case_id="c")
        g.upsert(schema.Entity(id="asset:H", type="asset", label="H"))
        fs = []
        for w in range(8):
            import datetime as _d
            day = (_d.date(2026, 1, 1) + _d.timedelta(days=10 * w)).isoformat()   # > 7-day window gap
            fs.append(schema.Finding(id=f"c{w}", title=f"SIGMA: critical rule {w} on H", severity="critical",
                                     confidence="m", summary="", asset_ids=["asset:H"], ts=f"{day}T10:00:00Z"))
            for k in range(3):
                fs.append(schema.Finding(id=f"h{w}{k}", title=f"SIGMA: rule {k} on H", severity="high",
                                         confidence="m", summary="", asset_ids=["asset:H"], ts=f"{day}T10:0{k}:00Z"))
        g.findings = fs
        zt = render.zoom_targets(g, n=6)
        cards = [z for z in zt if not z.get("rollup")]
        self.assertEqual(len(cards), 8, [(z.get("title"), z.get("critical_count")) for z in zt])
        self.assertFalse([z for z in zt if z.get("rollup") and z.get("critical_count")])


if __name__ == "__main__":
    unittest.main()
