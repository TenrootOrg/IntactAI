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
import json
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


class PayloadBudgetCollapse(unittest.TestCase):
    """The LLM payload budget silently stopped binding at scale: MAX_STEPDOWNS caps the
    halving and >=high findings are exempt from trimming, so a case with thousands of
    high findings shipped far over budget (measured 2.6 MB against a 708 KB budget).
    The last-resort pass collapses repeated detections instead of dropping signal."""

    def _big(self, n_hosts):
        fs = []
        for h in range(n_hosts):
            for k in range(6):
                f = _find(f"f{h}_{k}", sev="high", day=k, hosts=(f"host{h:03d}",))
                f.title = f"SIGMA: Recurring Detection {k} on HOST-{h:03d}"
                fs.append(f)
        return _graph(n_hosts, fs)

    def test_collapse_fires_over_budget_and_preserves_detections(self):
        g = self._big(40)
        big = render.distilled(g, max_entities=50, budget_chars=10**9, detail="summary")
        cut = render.distilled(g, max_entities=50, budget_chars=20000, detail="summary")
        self.assertTrue(cut.get("findings_collapsed"))
        # all 6 DISTINCT detections survive (only the per-host repetition collapses)
        self.assertEqual(len({f["title"] for f in cut["findings"]}), 6)
        self.assertLess(len(json.dumps(cut, default=str)),
                        len(json.dumps(big, default=str)))

    def test_collapse_keeps_severity_and_counts(self):
        cut = render.distilled(self._big(40), max_entities=50, budget_chars=20000,
                               detail="summary")
        self.assertTrue(all(f["severity"] == "high" for f in cut["findings"]))
        self.assertTrue(any(f.get("count", 1) > 1 for f in cut["findings"]))

    def test_does_not_fire_under_budget(self):
        # a small case must be byte-identical to the un-budgeted payload
        g = self._big(2)
        a = render.distilled(g, max_entities=50, budget_chars=10**9, detail="summary")
        b = render.distilled(g, max_entities=50, budget_chars=10**9 - 1, detail="summary")
        self.assertNotIn("findings_collapsed", b)
        self.assertEqual(json.dumps(a, default=str), json.dumps(b, default=str))


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


class ScopeReportsCaseNotPayload(unittest.TestCase):
    """`scope` describes the CASE, not what fitted in the payload.

    Reporting the trimmed count told the model "300 hosts, 40 findings" for a case
    where all 300 hosts had one -- implying most machines were clean. The tool layer
    had the identical defect and made the loop answer "15 hosts" for a 42-host
    incident.
    """

    def _graph(self, n=300):
        g = schema.FusionGraph(case_id="c")
        sevs = (["informational"] * 200 + ["low"] * 60 + ["medium"] * 30 + ["high"] * 10)
        for i in range(n):
            hid = "asset:h%03d" % i
            g.entities[hid] = schema.Entity(id=hid, type="asset", label="WKS-%03d" % i)
            g.findings.append(schema.Finding(
                id="f%03d" % i, title="Finding number %d" % i, severity=sevs[i % len(sevs)],
                confidence="medium", summary="", asset_ids=[hid],
                ts="2026-06-01T00:00:00Z"))
        return g

    def _scope(self, g, max_findings):
        return render._distilled_at(g, window=None, min_severity="informational",
                                    max_entities=60, detail="summary",
                                    max_findings=max_findings)

    def test_scope_findings_is_the_true_total_when_trimmed(self):
        g = self._graph()
        for mf in (150, 40, 15):
            d = self._scope(g, mf)
            self.assertEqual(d["scope"]["findings"], len(g.findings),
                             "max_findings=%s reported a trimmed total" % mf)

    def test_findings_shown_reflects_the_payload(self):
        g = self._graph()
        d = self._scope(g, 40)
        self.assertEqual(d["scope"]["findings_shown"], len(d["findings"]))
        self.assertLess(d["scope"]["findings_shown"], d["scope"]["findings"])

    def test_untrimmed_case_reports_equal_counts(self):
        g = self._graph()
        d = self._scope(g, None)
        self.assertEqual(d["scope"]["findings"], d["scope"]["findings_shown"])

    def test_hosts_and_findings_stay_consistent(self):
        """The bug's signature: truthful host count beside a trimmed finding count."""
        g = self._graph()
        d = self._scope(g, 15)
        self.assertEqual(d["scope"]["hosts"], 300)
        self.assertEqual(d["scope"]["findings"], 300)


class EntityAndIdentityTotals(unittest.TestCase):
    """Trimmed collections must carry their true size.

    Budget stepdowns shrink `identities`, and the model counted the list it received
    as the population -- answering "323 distinct user accounts" for a case with 400,
    citing the truncated name range `corp\\user000-corp\\user322` as evidence.
    """

    def _graph(self, n=400):
        g = schema.FusionGraph(case_id="c")
        g.entities["asset:h"] = schema.Entity(id="asset:h", type="asset", label="H1")
        for i in range(n):
            g.entities["acct:%d" % i] = schema.Entity(
                id="acct:%d" % i, type="account", label="corp\\user%03d" % i,
                severity="medium", anomaly=0.5, first_seen="2026-06-01T00:00:00Z",
                attrs={"_assets": ["asset:h"]})
        g.findings.append(schema.Finding(
            id="f1", title="t", severity="high", confidence="medium", summary="",
            asset_ids=["asset:h"], ts="2026-06-01T00:00:00Z"))
        return g

    def _d(self, g, **kw):
        kw.setdefault("max_entities", 60)
        kw.setdefault("max_findings", None)
        return render._distilled_at(g, window=None, min_severity="informational",
                                    detail="summary", **kw)

    def test_entities_total_survives_the_anomaly_cap(self):
        g = self._graph()
        d = self._d(g)
        self.assertEqual(d["scope"]["entities"], 400)
        self.assertEqual(d["scope"]["entities_shown"], len(d["top_entities"]))
        self.assertLess(d["scope"]["entities_shown"], d["scope"]["entities"])

    def test_identities_total_survives_a_budget_stepdown(self):
        g = self._graph()
        d = self._d(g, max_identities=50)
        self.assertEqual(d["scope"]["identities"], 400)
        self.assertEqual(d["scope"]["identities_shown"], 50)
        self.assertEqual(len(d["identities"]), 50)

    def test_untrimmed_identities_report_equal_counts(self):
        g = self._graph(20)
        d = self._d(g)
        self.assertEqual(d["scope"]["identities"], d["scope"]["identities_shown"])


class RiskTableRespectsScope(unittest.TestCase):
    """The risk row must describe the window being analysed.

    Tally and 'Why' were window-filtered while risk_score and severity were read off
    the fusion-time asset entity, so a host whose findings all fell outside the window
    rendered as "high, 61" beside "0/0/0 - no findings in window" (seen on the real
    Default case: five hosts at 61-62/high with nothing in scope).
    """

    def _graph(self):
        g = schema.FusionGraph(case_id="c")
        for hid, lbl in (("asset:a", "IN-WINDOW"), ("asset:b", "OUT-OF-WINDOW")):
            g.entities[hid] = schema.Entity(id=hid, type="asset", label=lbl,
                                            severity="high", attrs={"modules": ["agentic"]})
        # in-window high finding
        g.findings.append(schema.Finding(
            id="f1", title="Recent high finding on IN-WINDOW", severity="high",
            confidence="medium", summary="", asset_ids=["asset:a"],
            ts="2026-08-15T00:00:00Z"))
        # the other host's only activity predates the window
        g.findings.append(schema.Finding(
            id="f2", title="Old high finding on OUT-OF-WINDOW", severity="high",
            confidence="medium", summary="", asset_ids=["asset:b"],
            ts="2024-01-01T00:00:00Z"))
        return g

    def _rows(self):
        g = self._graph()
        win = {"start": "2026-08-01T00:00:00Z", "end": None}
        return {r["host"]: r for r in render.risk_table(g, window=win)}

    def test_host_with_no_in_window_findings_scores_zero(self):
        r = self._rows()["OUT-OF-WINDOW"]
        self.assertEqual(r["finding_count"], 0)
        self.assertEqual(r["risk_score"], 0)
        self.assertEqual(r["severity"], "informational")

    def test_host_with_in_window_findings_keeps_its_band(self):
        r = self._rows()["IN-WINDOW"]
        self.assertEqual(r["severity"], "high")
        self.assertGreaterEqual(r["risk_score"], 60)
        self.assertLessEqual(r["risk_score"], 79)

    def test_no_row_claims_risk_without_findings(self):
        """The exact contradiction the operator spotted in the UI."""
        for host, r in self._rows().items():
            if r["finding_count"] == 0:
                self.assertEqual(r["risk_score"], 0,
                                 "%s: risk %d with no in-window findings"
                                 % (host, r["risk_score"]))


class LimitationsWindowHonesty(unittest.TestCase):
    """A ~10-year DEFAULT window must not read as a deliberate scope.

    Every live report stated "Only activity between 2016-09-01 and 2026-09-01 was
    considered", presenting the case's non-binding wide default (store.create_case) as a
    real 10-year cutoff. It now states the true evidence span, and calls the window a
    scope limit only when it actually clips the dated findings.
    """

    def _g(self):
        g = schema.FusionGraph(case_id="t")
        g.entities["a"] = schema.Entity(id="a", type="asset", label="H1")
        g.findings = [
            schema.Finding(id="f1", title="x", severity="high", confidence="medium",
                           summary="", asset_ids=["a"], ts="2026-05-03T10:00:00Z"),
            schema.Finding(id="f2", title="y", severity="high", confidence="medium",
                           summary="", asset_ids=["a"], ts="2026-09-01T10:00:00Z")]
        return g

    def test_wide_default_shows_evidence_span_not_a_cutoff(self):
        g = self._g()
        md = render._limitations_md(g, list(g.by_type("asset")), g.findings,
                                    window={"start": "2016-09-01T00:00:00Z",
                                            "end": "2026-09-01T12:00:00Z"})
        self.assertIn("Analysed evidence spans", md)
        self.assertIn("2026-05-03", md)
        self.assertNotIn("2016", md)
        self.assertNotIn("out of scope for this report", md)

    def test_binding_window_is_stated_as_a_scope_limit(self):
        g = self._g()
        md = render._limitations_md(g, list(g.by_type("asset")), g.findings,
                                    window={"start": "2026-08-01T00:00:00Z", "end": None})
        self.assertIn("Time scope was narrowed", md)


class IocHashCarriesFilename(unittest.TestCase):
    """A hash IOC must name the file it came from, so 'block this hash' is actionable.

    Generic: render._ioc_source_label reads the source_name the mapper captured from the
    detection row (or follows the graph link) -- it works for ANY binary, including a
    custom/unknown name, because it never consults a table of known tools.
    """

    def test_source_name_from_attrs(self):
        g = schema.FusionGraph(case_id="c")
        g.entities["a"] = schema.Entity(id="a", type="asset", label="H1")
        i = schema.Entity(id="ioc:hash:abc", type="ioc", label="abc123",
                          attrs={"ioc_kind": "hash", "source_name": "totally_custom.exe"})
        g.entities[i.id] = i
        self.assertEqual(render._ioc_source_label(g, i), "totally_custom.exe")

    def test_path_source_name_is_basenamed(self):
        g = schema.FusionGraph(case_id="c")
        i = schema.Entity(id="ioc:hash:def", type="ioc", label="def",
                          attrs={"ioc_kind": "hash",
                                 "source_name": r"C:\Windows\Temp\x.exe"})
        g.entities[i.id] = i
        self.assertEqual(render._ioc_source_label(g, i), "x.exe")

    def test_non_hash_ioc_returns_none(self):
        g = schema.FusionGraph(case_id="c")
        i = schema.Entity(id="ioc:ip:1", type="ioc", label="1.2.3.4",
                          attrs={"ioc_kind": "ip"})
        g.entities[i.id] = i
        self.assertIsNone(render._ioc_source_label(g, i))


if __name__ == "__main__":
    unittest.main(verbosity=2)
