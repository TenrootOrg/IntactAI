"""The scope-adaptive report ("altitude ladder"): a broad case must render MACRO
(a ranked triage map) and a narrow case FOCUSED (one explicit theory), decided
from the REAL scope — host count, finding volume, and EVIDENCE span (never the
10-year default window). Plus the deterministic pieces the macro path leans on:
the zoom-target clustering, its heat-map, and the hallucinated-hash guard.

Run in-container against the real fusion package (PYTHONPATH=/app) so the actual
shipped selector/clusterer is under test, not a re-implementation that could pass
while the product regressed:

    docker exec intact_backend sh -lc \
      'PYTHONPATH=/app python3 -m pytest \
       /app/tests/test_report_altitude.py -q'   # (or unittest, below)
"""
import datetime as _dt
import os
import sys
import unittest

# The fusion package is `services.fusion` at its app root. That root is /app in the
# backend container (PYTHONPATH=/app) and modules/backend/ in the repo — put both on
# the path so this runs in-container (its true runtime) or from a repo checkout.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in ("/app", os.path.join(_ROOT, "modules/backend"), _ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from services.fusion import render, llm_sim, investigate, schema  # noqa: E402

_T0 = _dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=_dt.timezone.utc)


def _ts(day=0, hour=0):
    return (_T0 + _dt.timedelta(days=day, hours=hour)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _graph(n_hosts, findings):
    """A FusionGraph with n_hosts asset entities + the given findings. Every
    finding's asset_ids point at real asset entities so _host_label resolves."""
    g = schema.FusionGraph(case_id="TEST")
    for i in range(n_hosts):
        aid = f"asset:host{i:03d}"
        g.entities[aid] = schema.Entity(id=aid, type="asset", label=f"HOST-{i:03d}")
    return schema.FusionGraph(case_id="TEST", entities=g.entities, findings=findings)


def _find(fid, *, sev="medium", day=0, hour=0, hosts=("host000",), kind="single",
          mitre=None):
    return schema.Finding(
        id=fid, title=f"Finding {fid}", severity=sev, confidence="medium",
        summary="s", asset_ids=[f"asset:{h}" for h in hosts], ts=_ts(day, hour),
        kind=kind, mitre=list(mitre or []))


class Altitude(unittest.TestCase):
    def test_broad_by_hosts_is_macro(self):
        g = _graph(20, [_find(f"f{i}", day=0, hosts=(f"host{i:03d}",)) for i in range(20)])
        alt, reason = render._resolve_altitude(g)
        self.assertEqual(alt, "macro", reason)

    def test_broad_by_finding_volume_is_macro(self):
        g = _graph(3, [_find(f"f{i}", day=0) for i in range(200)])
        alt, reason = render._resolve_altitude(g)
        self.assertEqual(alt, "macro", reason)

    def test_broad_by_evidence_span_is_macro(self):
        # 3 hosts, 4 findings, but they span 120 days -> macro on span alone.
        g = _graph(3, [_find("a", day=0), _find("b", day=40),
                       _find("c", day=80), _find("d", day=120)])
        alt, reason = render._resolve_altitude(g)
        self.assertEqual(alt, "macro", reason)

    def test_narrow_recent_is_focused(self):
        g = _graph(3, [_find(f"f{i}", day=0, hour=i) for i in range(6)])
        alt, reason = render._resolve_altitude(g)
        self.assertEqual(alt, "focused", reason)

    def test_span_from_evidence_not_window(self):
        # span must come from finding ts, independent of any (10-year) window arg.
        g = _graph(2, [_find("a", day=0), _find("b", day=10)])
        self.assertEqual(render._evidence_span_days(g.findings), 10)
        # a wide window does NOT inflate the span (regression on the 10y default bug)
        wide = {"start": "2016-01-01T00:00:00", "end": "2036-01-01T00:00:00"}
        alt, _ = render._resolve_altitude(g, window=wide)
        self.assertEqual(alt, "focused")  # 2 hosts / 2 findings / 10d span

    def test_empty_graph_is_focused(self):
        self.assertEqual(render._resolve_altitude(_graph(0, []))[0], "focused")


class ZoomTargets(unittest.TestCase):
    def test_gap_splits_into_clusters(self):
        # two bursts 20 days apart -> two clusters (gap > 7d).
        fs = [_find("a1", day=0), _find("a2", day=1),
              _find("b1", day=20), _find("b2", day=21)]
        zt = render.zoom_targets(_graph(2, fs))
        self.assertEqual(len(zt), 2)

    def test_contiguous_activity_is_one_cluster(self):
        fs = [_find("a", day=0), _find("b", day=2), _find("c", day=5)]  # all <7d apart
        zt = render.zoom_targets(_graph(1, fs))
        self.assertEqual(len(zt), 1)
        self.assertEqual(zt[0]["finding_count"], 3)

    def test_ranked_by_risk(self):
        # a later, smaller CRITICAL burst must outrank an earlier low-sev one.
        fs = [_find("lo1", sev="low", day=0), _find("lo2", sev="low", day=1),
              _find("hi", sev="critical", day=30)]
        zt = render.zoom_targets(_graph(2, fs))
        self.assertEqual(zt[0]["severity"], "critical")

    def test_window_bounds_are_real_and_padded(self):
        zt = render.zoom_targets(_graph(1, [_find("a", day=0, hour=0),
                                            _find("b", day=0, hour=4)]))
        w = zt[0]["window"]
        # padded one hour each side -> start before first ts, end after last
        self.assertLess(w["start"], _ts(0, 0))
        self.assertGreater(w["end"], _ts(0, 4))

    def test_findings_without_hosts_yield_no_targets(self):
        f = schema.Finding(id="x", title="t", severity="high", confidence="low",
                           summary="s", asset_ids=[], ts=_ts(0))
        self.assertEqual(render.zoom_targets(_graph(0, [f])), [])


class Heatmap(unittest.TestCase):
    def test_macro_heatmap_has_a_row_per_cluster(self):
        fs = [_find("a", sev="high", day=0), _find("b", day=20)]
        md = render.suspicious_timeframes_md(_graph(2, fs))
        self.assertIn("Suspicious Timeframes", md)
        # header row + separator + 2 data rows
        self.assertEqual(md.count("\n|"), 4)

    def test_empty_when_nothing_to_zoom(self):
        self.assertEqual(render.suspicious_timeframes_md(_graph(0, [])), "")


class SummaryTimeline(unittest.TestCase):
    """The macro/summary timeline collapses + caps recurring detections. The cap
    must NEVER hide a critical: groups are chronological, so a plain head-slice
    dropped late criticals behind earlier high-severity noise."""

    def _graph_with_late_critical(self, n_high):
        # n_high distinct high groups early, then ONE critical last in time
        fs = [_find(f"h{i}", sev="high", day=i) for i in range(n_high)]
        for i, f in enumerate(fs):
            f.title = f"Recurring high detection {i}"      # distinct groups
        crit = _find("crit", sev="critical", day=n_high + 5)
        crit.title = "LATE CRITICAL DETECTION"
        return _graph(1, fs + [crit])

    def test_late_critical_survives_the_cap(self):
        g = self._graph_with_late_critical(render.TIMELINE_MAX_GROUPS + 25)
        md = render.facts_md(g, detail="summary", narrated=True)
        self.assertIn("LATE CRITICAL DETECTION", md)      # never dropped
        self.assertIn("critical group(s) are shown", md)  # and stated

    def test_cap_still_bounds_non_critical(self):
        g = self._graph_with_late_critical(render.TIMELINE_MAX_GROUPS + 25)
        md = render.facts_md(g, detail="summary", narrated=True)
        self.assertIn("non-critical** recurring detection group(s) omitted", md)

    def test_repeats_collapse_with_count(self):
        # same detection on 3 hosts -> ONE row with a count, not three rows
        fs = [_find(f"r{i}", sev="high", day=i, hosts=(f"host{i:03d}",)) for i in range(3)]
        for i, f in enumerate(fs):
            f.title = f"SIGMA: Same Rule on HOST-{i:03d}"   # title embeds the host
        md = render.facts_md(_graph(3, fs), detail="summary", narrated=True)
        self.assertIn("×3", md)


class GroundingGuard(unittest.TestCase):
    def test_flags_hash_absent_from_evidence(self):
        ghost = "a" * 64
        real = "b" * 64
        src = f'{{"sha256":"{real}"}}'
        text = f"The dropper {ghost} was executed; loader {real} followed."
        self.assertEqual(llm_sim._ungrounded_hashes(text, src), [ghost])

    def test_clean_when_all_hashes_grounded(self):
        h = "c" * 64
        self.assertEqual(llm_sim._ungrounded_hashes(f"hash {h}", f"...{h}..."), [])

    def test_no_hashes_is_clean(self):
        self.assertEqual(llm_sim._ungrounded_hashes("no hashes here", "src"), [])


class InvestigateParse(unittest.TestCase):
    def test_bare_tool_call(self):
        self.assertEqual(investigate._parse('{"tool":"evidence","args":{"finding_id":"f1"}}'),
                         {"tool": "evidence", "args": {"finding_id": "f1"}})

    def test_final_answer(self):
        self.assertEqual(investigate._parse('{"final":"done"}'), {"final": "done"})

    def test_json_embedded_in_prose(self):
        obj = investigate._parse('Sure — here you go: {"tool":"list_findings","args":{}} thanks')
        self.assertEqual(obj, {"tool": "list_findings", "args": {}})

    def test_garbage_returns_none(self):
        self.assertIsNone(investigate._parse("not json at all"))
        self.assertIsNone(investigate._parse(""))


if __name__ == "__main__":
    unittest.main(verbosity=2)
