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
import json
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

from services.fusion import render, schema, budget  # noqa: E402

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
        p = render.distilled(self.g, max_entities=50, include_timeframes=True)
        self.assertEqual(p["scope"]["altitude"], "macro")
        zt = render.zoom_targets(self.g)
        self.assertEqual([t["n"] for t in p["timeframes"]], [z["n"] for z in zt])
        self.assertEqual([t["window"] for t in p["timeframes"]], [z["window"] for z in zt])
        self.assertTrue(all(t["findings"] for t in p["timeframes"]))

    def test_focused_payload_has_no_timeframes(self):
        g = _graph(1, _burst("a", 0, 3))
        p = render.distilled(g, max_entities=50, include_timeframes=True)
        self.assertEqual(p["scope"]["altitude"], "focused")
        self.assertNotIn("timeframes", p)

    def test_only_the_report_asks_for_timeframes(self):
        """distilled() serves the report, the advisory, chat and investigate. Only
        the macro REPORT prompt documents `timeframes`; handing the others a key
        their prompts never describe is payload they have no instructions for."""
        p = render.distilled(self.g, max_entities=50)          # advisory/chat default
        self.assertEqual(p["scope"]["altitude"], "macro")
        self.assertNotIn("timeframes", p)
        self.assertIn("timeframes",
                      render.distilled(self.g, max_entities=50, include_timeframes=True))

    def test_timeframes_survive_a_budget_stepdown(self):
        p = render.distilled(self.g, max_entities=50, budget_chars=400,
                             include_timeframes=True)
        self.assertTrue(p.get("timeframes"), "the over-budget rebuild lost them")

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


class ScopesOfferedMustBeWorthOpening(unittest.TestCase):
    """"Analyze this scope" has to lead somewhere. Measured on a narrowed graph, four
    of the six offered cards were a SINGLE finding each -- _substantial() already
    encoded what is worth an analyst's time and simply was not applied here."""

    def _mixed(self):
        # two real phases, plus three trivial one-finding blips far apart
        fs = _burst("a", 0, 5, "high") + _burst("b", 40, 5, "high")
        fs += [_find("t1", day=90), _find("t2", day=140), _find("t3", day=190)]
        return _graph(3, fs)

    def test_trivial_windows_are_not_offered_as_scopes(self):
        zt = render.zoom_targets(self._mixed())
        offered = render.analysable(zt)
        self.assertTrue(offered)
        for z in offered:
            self.assertTrue(render._substantial(z),
                            f"offered a scope of {z['finding_count']} finding(s)")

    def test_the_primitive_still_returns_every_cluster(self):
        """analysable() filters for PRESENTATION. zoom_targets stays the primitive the
        altitude rule counts from -- filtering there made it count its own output."""
        zt = render.zoom_targets(self._mixed())
        self.assertGreater(len(zt), len(render.analysable(zt)))

    def test_nothing_is_lost_by_the_filter(self):
        """A window not offered is still accounted for, or the map lies."""
        g = self._mixed()
        _, allf = render.scope(g)
        zt = render.zoom_targets(g)
        self.assertEqual(sum(z["finding_count"] for z in zt), len(allf))


class TheGlanceTableLetsYouChooseBeforeReading(unittest.TestCase):

    def setUp(self):
        self.g = _graph(3, _burst("a", 0, 5, "critical") + _burst("b", 40, 4, "high"))
        self.zt = render.zoom_targets(self.g)

    def test_a_row_per_phase_plus_the_rollup(self):
        md = render.phases_at_a_glance_md(self.zt, {1: "Credential theft", 2: "C2"})
        self.assertIn("## Phases at a glance", md)
        self.assertIn("| 1 | Credential theft |", md)
        self.assertIn("| 2 | C2 |", md)

    def test_it_falls_back_to_the_detection_name_when_unnamed(self):
        """A deterministic report has no model names; the table must still say what
        each phase holds rather than printing an empty column."""
        md = render.phases_at_a_glance_md(self.zt)
        for line in md.splitlines():
            if line.startswith("| 1 |"):
                self.assertNotIn("|  |", line, line)

    def test_empty_when_there_is_nothing_to_choose_between(self):
        self.assertEqual(render.phases_at_a_glance_md([]), "")


class EveryPhaseCallShouldFillTheModelsWindow(unittest.TestCase):
    """Splitting the case into phases turned ONE whole-case call into N independent
    calls, each with the model's entire context available. Inheriting the whole-case
    `detail` threw that away: measured live, five of six phases at full explicit
    detail were under 11K tokens against a 272K window, yet all six were sent the
    collapsed summary.

    Two traps this pins, both of which produced a wrong fit test first time:
      * `findings_shown` cannot detect the squeeze -- _trim_findings never drops
        anything >= high, so it reads N/N at every budget;
      * render.distilled() step-downs internally, so it does NOT raise or truncate
        to the ceiling -- when it cannot fit it collapses and ships over budget.
    """

    def setUp(self):
        # one phase small enough for explicit, one far too big for a small ceiling
        self.g = _graph(4, _burst("a", 0, 4, "high")
                        + [_find(f"b{i}", sev="high", day=40, hour=i % 24,
                                 hosts=(f"host{i % 4:03d}",)) for i in range(60)])
        self.zt = render.analysable(render.zoom_targets(self.g))

    def _payload(self, z, detail, budget_chars):
        return render.distilled(self.g, window=z["window"], max_entities=200,
                                budget_chars=budget_chars, detail=detail)

    def test_findings_shown_is_not_a_usable_fit_test(self):
        """The trap: it reads full at every budget because high+ is exempt from
        trimming, so a fit test built on it always says 'explicit fits'."""
        z = max(self.zt, key=lambda x: x["finding_count"])
        for bc in (2_000, 2_000_000):
            sc = self._payload(z, "explicit", bc).get("scope") or {}
            self.assertGreaterEqual(sc.get("findings_shown", 0), sc.get("findings", 0))

    def test_a_small_phase_gets_explicit_with_room_to_spare(self):
        z = min(self.zt, key=lambda x: x["finding_count"])
        p = self._payload(z, "explicit", 2_000_000)
        self.assertFalse(budget.over_budget(p, 2_000_000))

    def test_a_generous_ceiling_makes_explicit_strictly_richer(self):
        """If explicit were not bigger there would be nothing to choose between."""
        z = max(self.zt, key=lambda x: x["finding_count"])
        big = 20_000_000
        self.assertGreater(len(json.dumps(self._payload(z, "explicit", big))),
                           len(json.dumps(self._payload(z, "summary", big))))

    def test_distilled_ships_over_budget_rather_than_dropping_severe_findings(self):
        """Documents the real behaviour the fit rule has to live with: a tiny
        ceiling does not truncate, it collapses -- so 'is it over budget' is the
        only honest signal, and being over is survivable."""
        z = max(self.zt, key=lambda x: x["finding_count"])
        p = self._payload(z, "explicit", 1_000)
        sc = p.get("scope") or {}
        self.assertGreaterEqual(sc.get("findings_shown", 0), sc.get("findings", 0))


class SevereActivityOutsideEveryPhaseIsAccountedFor(unittest.TestCase):
    """Measured live: 61 findings across 15 windows fell into the rollup and were
    narrated nowhere -- 40% of the case, including renamed AdFind/procdump drops."""

    def setUp(self):
        # MORE substantial phases than the report shows: the ones past
        # MACRO_TIMEFRAMES are pushed into the rollup and analysed by nobody. That
        # is exactly how 61 findings went unnarrated on the live case -- not because
        # they were trivial, but because they ranked below the cut.
        fs = []
        for i in range(render.MACRO_TIMEFRAMES + 3):
            fs += _burst(f"p{i}", i * 40, 4, "high", hosts=(f"host{i % 3:03d}",))
        fs += [_find("orphan", sev="critical", day=999, hosts=("host002",))]
        self.g = _graph(3, fs)
        self.zt = render.zoom_targets(self.g)

    def test_phases_past_the_cut_are_reported_as_outside(self):
        shown = len(render.analysable(self.zt))
        self.assertEqual(shown, render.MACRO_TIMEFRAMES, "expected the cut to bite")
        out = render.outside_phases(self.g, self.zt)
        self.assertTrue(out, "phases past the cut were narrated by nobody and "
                             "reported by nobody")
        _, allf = render.scope(self.g)
        self.assertLess(len(out), len(allf))

    def test_findings_inside_a_phase_are_not_reported_as_outside(self):
        out = render.outside_phases(self.g, self.zt)
        ids = {f.id for f in out}
        for z in render.analysable(self.zt):
            for f in self.g.findings:
                if f.ts and z["window"]["start"] <= f.ts <= z["window"]["end"]:
                    self.assertNotIn(f.id, ids, f"{f.id} is inside phase {z['n']}")

    def test_the_digest_keeps_only_severe_rows_and_groups_repeats(self):
        out = render.outside_phases(self.g, self.zt)
        rows = render.outside_phases_digest(self.g, out)
        self.assertTrue(rows)
        for r in rows:
            self.assertIn(r["severity"], ("critical", "high"))
            self.assertIn("count", r)
            self.assertIn("hosts", r)
