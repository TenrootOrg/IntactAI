"""The macro report as a MAP of timeframes, and the altitude rule that chooses it.

The operator's ask: a broad case should show a few time windows with what happened
in each, so they can decide where to zoom; clicking a window gives the explicit
report for it; and the choice between the two must be smart, at any scale.

Design constraints this pins down:
  * the windows are OURS (zoom_targets) and the model only narrates them -- letting
    it write the timeframe table made it confabulate dates (scratch_eval S4);
  * one list feeds the cards, the table and the narrative, numbered identically;
  * altitude follows the SHAPE of the activity (distinct phases), not raw span --
    span alone forced a two-year single-cluster case to macro (nothing to map) and
    the operator had to override by hand;
  * zooming into any window yields one cluster -> focused: the loop closes.

    docker exec intact_backend sh -lc \\
      'PYTHONPATH=/app python3 -m pytest /app/tests/test_macro_timeframes.py -q'
"""
import datetime as _dt
import os
import sys
import types
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BACKEND = os.path.join(_ROOT, "modules/backend")
for _p in ("/app", _BACKEND, _ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
for _pkg, _rel in (("services", "services"), ("services.fusion", "services/fusion")):
    if _pkg not in sys.modules:
        _m = types.ModuleType(_pkg); _m.__path__ = [os.path.join(_BACKEND, _rel)]
        sys.modules[_pkg] = _m

from services.fusion import render, schema  # noqa: E402

_T0 = _dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=_dt.timezone.utc)


def _ts(day=0, hour=0):
    return (_T0 + _dt.timedelta(days=day, hours=hour)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _graph(n_hosts, findings):
    g = schema.FusionGraph(case_id="TEST")
    for i in range(n_hosts):
        aid = f"asset:host{i:03d}"
        g.entities[aid] = schema.Entity(id=aid, type="asset", label=f"HOST-{i:03d}")
    return schema.FusionGraph(case_id="TEST", entities=g.entities, findings=findings)


def _find(fid, *, sev="medium", day=0, hour=0, hosts=("host000",), title=None):
    # Titles embed the finding's OWN host, as real detections do ("SIGMA: X on <host>").
    label = "HOST-" + hosts[0][-3:]
    return schema.Finding(id=fid, title=title or f"Finding {fid} on {label}",
                          severity=sev, confidence="medium", summary="s",
                          asset_ids=[f"asset:{h}" for h in hosts], ts=_ts(day, hour))


def _burst(prefix, day, n, sev="medium", hosts=("host000",)):
    return [_find(f"{prefix}{i}", sev=sev, day=day, hour=i, hosts=hosts) for i in range(n)]


class AltitudeFollowsTheShapeOfActivity(unittest.TestCase):

    def test_two_real_phases_are_macro_even_inside_ninety_days(self):
        """Two substantial windows 30 days apart. Span alone (30 < 90) said
        focused; there are two phases to map, so it is macro."""
        g = _graph(3, _burst("a", 0, 4) + _burst("b", 30, 4))
        alt, reason = render._resolve_altitude(g)
        self.assertEqual(alt, "macro", reason)

    def test_one_continuous_cluster_over_a_long_span_is_focused(self):
        """Thirty findings, one every five days for 150 days, three hosts. Nothing to
        map -- it is one phase. Span alone forced this to macro (the case the
        operator overrode by hand); the shape says focused."""
        fs = [_find(f"c{i}", day=i * 5, hosts=(f"host{i % 3:03d}",)) for i in range(30)]
        alt, reason = render._resolve_altitude(_graph(3, fs))
        self.assertEqual(alt, "focused", reason)
        self.assertGreater(render._evidence_span_days(fs), render.MACRO_SPAN_DAYS)

    def test_two_trivial_blips_are_not_a_map(self):
        g = _graph(2, [_find("a", day=0), _find("b", day=10)])
        self.assertEqual(render._resolve_altitude(g)[0], "focused")

    def test_scale_still_forces_macro_with_one_window(self):
        fs = [_find(f"f{i}", day=0, hosts=(f"host{i:03d}",)) for i in range(20)]
        self.assertEqual(render._resolve_altitude(_graph(20, fs))[0], "macro")

    def test_zooming_into_a_window_drops_to_focused(self):
        """The loop: a macro case, narrowed to one of its own zoom windows, must come
        back focused -- or "Analyze this scope" never delivers what it promises."""
        g = _graph(3, _burst("a", 0, 5, sev="high") + _burst("b", 40, 5, sev="high"))
        self.assertEqual(render._resolve_altitude(g)[0], "macro")
        zt = render.zoom_targets(g)
        self.assertEqual(len(zt), 2)
        alt, reason = render._resolve_altitude(g, window=zt[0]["window"])
        self.assertEqual(alt, "focused", reason)


class OneListFeedsCardsTableAndModel(unittest.TestCase):

    def setUp(self):
        self.g = _graph(3, _burst("a", 0, 4, "high") + _burst("b", 20, 4, "high")
                        + _burst("c", 60, 4, "critical", hosts=("host001", "host002")))

    def test_windows_are_numbered_after_ranking(self):
        zt = render.zoom_targets(self.g)
        self.assertEqual([z["n"] for z in zt], [1, 2, 3])
        self.assertEqual(zt[0]["severity"], "critical", "ranked by risk before numbering")

    def test_each_window_carries_the_titles_inside_it(self):
        zt = render.zoom_targets(self.g)
        for z in zt:
            self.assertTrue(z["top_titles"])
            self.assertFalse(any(" on HOST-" in t for t in z["top_titles"]),
                             "host tail must be stripped so one rule is one title")

    def test_macro_payload_carries_the_same_windows(self):
        p = render.distilled(self.g, max_entities=50)
        self.assertEqual(p["scope"]["altitude"], "macro")
        zt = render.zoom_targets(self.g)
        self.assertEqual([t["n"] for t in p["timeframes"]], [z["n"] for z in zt])
        self.assertEqual([t["window"] for t in p["timeframes"]], [z["window"] for z in zt])
        self.assertTrue(all(t["findings"] for t in p["timeframes"]))

    def test_focused_payload_has_no_timeframes(self):
        g = _graph(1, _burst("a", 0, 3))
        p = render.distilled(g, max_entities=50)
        self.assertEqual(p["scope"]["altitude"], "focused")
        self.assertNotIn("timeframes", p)

    def test_table_rows_match_the_cards(self):
        zt = render.zoom_targets(self.g)
        md = render.suspicious_timeframes_md(self.g, zt=zt)
        self.assertEqual(md.count("\n|"), 2 + len(zt))       # header + sep + rows
        for z in zt:
            self.assertIn(f"| {z['n']} |", md)


class TheModelNarratesOurWindowsAndCannotInventOne(unittest.TestCase):
    TABLE = ("## Suspicious Timeframes & Clusters\n\n_note_\n\n"
             "| # | Window (UTC) | Hosts |\n|---|---|---|\n| 1 | a | b |\n| 2 | c | d |\n")

    def test_names_are_parsed_from_the_headings(self):
        md = ("## Timeframes\n### Timeframe 1 — Initial access\nx\n"
              "### Timeframe 2 - Ransomware prep & C2\ny\n### Timeframe 3: Cleanup\nz\n")
        self.assertEqual(render.timeframe_names_from_report(md),
                         {1: "Initial access", 2: "Ransomware prep & C2", 3: "Cleanup"})

    def test_an_invented_window_is_removed_and_reported(self):
        md = ("## Assessment\nok\n\n## Timeframes\n"
              "### Timeframe 1 — Real\n- what happened\n"
              "### Timeframe 9 — Invented\n- confabulated\n- more\n"
              "### Timeframe 2 — Also real\n- fine\n\n## Priority actions\n- x\n")
        out, dropped, inserted = render.merge_timeframes_section(md, self.TABLE, {1, 2})
        self.assertEqual(dropped, [9])
        self.assertNotIn("Invented", out)
        self.assertNotIn("confabulated", out)
        self.assertIn("### Timeframe 1 — Real", out)
        self.assertIn("### Timeframe 2 — Also real", out)
        self.assertIn("## Priority actions", out)

    def test_the_table_lands_under_the_heading_not_at_the_end(self):
        md = "## Assessment\nok\n\n## Timeframes\n### Timeframe 1 — Real\nx\n\n## Priority actions\ny\n"
        out, _, inserted = render.merge_timeframes_section(md, self.TABLE, {1})
        self.assertTrue(inserted)
        self.assertLess(out.index("| 1 | a | b |"), out.index("### Timeframe 1"))
        self.assertGreater(out.index("| 1 | a | b |"), out.index("## Timeframes"))
        self.assertNotIn("## Suspicious Timeframes", out, "the table's own heading is dropped")

    def test_without_the_heading_nothing_is_inserted_but_the_guard_still_runs(self):
        md = "## Assessment\nok\n### Timeframe 7 — ghost\nz\n"
        out, dropped, inserted = render.merge_timeframes_section(md, self.TABLE, {1})
        self.assertFalse(inserted)
        self.assertEqual(dropped, [7])
        self.assertNotIn("ghost", out)


if __name__ == "__main__":
    unittest.main()
