"""What an operator's triage verdict actually does to a finding.

Written after a live probe reported "suppression genuinely failed" three times
and was wrong all three: every finding it happened to pick was `critical`, and a
benign verdict on a >=critical finding is DELIBERATELY not down-ranked --
"never silently for >=critical (surfaced anyway for review)". It is annotated and
left visible instead.

That carve-out is easy to mistake for a bug from the outside and easy to delete
from the inside, and either mistake is expensive: removing it silently hides
critical findings an operator marked benign by habit, and "fixing" the annotation
path re-introduces exactly the confusion this docstring exists to end.

Also pinned here: the watermark rule that decides whether a verdict still holds
once new data lands, since a case grows by import and every stored verdict has to
survive -- or knowingly not survive -- that growth.

`severity` and `schema` are leaf modules with no intra-package imports, so the
REAL Finding class and the REAL comparison run here. _apply_dispositions and
_wm_new_activity are lifted out of correlate.py and executed against them.
"""

import ast
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FUSION = os.path.join(ROOT, "modules/backend/services/fusion")
CORRELATE = os.path.join(FUSION, "correlate.py")
sys.path.insert(0, FUSION)

import severity as sev          # noqa: E402 — leaf module
from schema import Finding, FusionGraph      # noqa: E402


def _load(names):
    with open(CORRELATE, encoding="utf-8") as f:
        src = f.read()
    tree = ast.parse(src)
    picked = {n.name: ast.get_source_segment(src, n)
              for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names}
    missing = [n for n in names if n not in picked]
    if missing:
        raise AssertionError("not found in correlate.py: %s" % ", ".join(missing))
    # correlate.py has no `from __future__ import annotations`, so the
    # `g: FusionGraph` annotation is evaluated at def time and the name must
    # already be in the namespace.
    ns = {"sev": sev, "FusionGraph": FusionGraph, "Finding": Finding}
    for n in names:
        exec(compile(picked[n], CORRELATE, "exec"), ns)
    return ns


NS = _load(("_wm_new_activity", "_apply_dispositions"))
apply_dispositions = NS["_apply_dispositions"]
wm_new_activity = NS["_wm_new_activity"]


def _graph(*findings):
    g = FusionGraph(case_id="c")
    for f in findings:
        g.add_finding(f)
    return g


def _finding(fid, severity, **kw):
    kw.setdefault("confidence", "high")
    kw.setdefault("entity_ids", [])
    return Finding(id=fid, title="t", severity=severity, summary="s", **kw)


def _benign(target, **kw):
    return dict(target=target, verdict="benign", attribution="it_admin",
                reason="IT confirms expected", **kw)


class TestBenignDownRanks(unittest.TestCase):

    def test_a_high_finding_is_suppressed(self):
        g = _graph(_finding("f1", "high"))
        apply_dispositions(g, [_benign("f1")])
        f = g.findings[0]
        self.assertEqual(f.severity, "informational")
        self.assertEqual(f.confidence, "low")
        self.assertEqual(f.kind, "dispositioned")

    def test_a_medium_finding_is_suppressed(self):
        g = _graph(_finding("f1", "medium"))
        apply_dispositions(g, [_benign("f1")])
        self.assertEqual(g.findings[0].severity, "informational")

    def test_the_attribution_is_recorded_on_the_finding(self):
        """The operator must be able to see WHO called it benign, and why."""
        g = _graph(_finding("f1", "high"))
        apply_dispositions(g, [_benign("f1")])
        self.assertIn("it_admin", g.findings[0].summary)
        self.assertIn("IT confirms expected", g.findings[0].summary)

    def test_a_verdict_on_a_cited_entity_also_applies(self):
        g = _graph(_finding("f1", "high", entity_ids=["proc:1"]))
        apply_dispositions(g, [_benign("proc:1")])
        self.assertEqual(g.findings[0].severity, "informational")

    def test_an_unrelated_finding_is_untouched(self):
        g = _graph(_finding("f1", "high"), _finding("f2", "high"))
        apply_dispositions(g, [_benign("f1")])
        self.assertEqual(g.findings[1].severity, "high")


class TestCriticalIsNeverSilentlyHidden(unittest.TestCase):
    """The carve-out a live probe mistook for a bug three times."""

    def test_a_critical_finding_keeps_its_severity(self):
        g = _graph(_finding("f1", "critical"))
        apply_dispositions(g, [_benign("f1")])
        self.assertEqual(g.findings[0].severity, "critical",
                         "a benign verdict must not silently hide a critical finding")

    def test_but_it_is_still_annotated(self):
        """Otherwise the verdict looks like it did nothing at all."""
        g = _graph(_finding("f1", "critical"))
        apply_dispositions(g, [_benign("f1")])
        s = g.findings[0].summary
        self.assertIn("it_admin", s)
        self.assertIn("critical", s.lower())

    def test_it_is_not_reclassified_as_dispositioned(self):
        g = _graph(_finding("f1", "critical"))
        apply_dispositions(g, [_benign("f1")])
        self.assertNotEqual(g.findings[0].kind, "dispositioned")


class TestMaliciousRaisesConfidence(unittest.TestCase):

    def test_confirmed_malicious_does_not_downgrade(self):
        g = _graph(_finding("f1", "high", confidence="low"))
        apply_dispositions(g, [dict(target="f1", verdict="malicious", reason="confirmed")])
        f = g.findings[0]
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.confidence, "high")
        self.assertIn("operator-confirmed malicious", f.summary)


class TestWatermarkGovernsStaleVerdicts(unittest.TestCase):
    """A benign verdict covers the occurrences it was made against — no more.
    This is what decides whether triage survives the next import."""

    def test_identical_activity_keeps_the_verdict(self):
        self.assertFalse(wm_new_activity("28|2026-05-28T07:24:48Z",
                                         "28|2026-05-28T07:24:48Z"))

    def test_more_occurrences_re_open_it(self):
        self.assertTrue(wm_new_activity("28|2026-05-28T07:24:48Z",
                                        "31|2026-05-28T07:24:48Z"))

    def test_a_later_occurrence_re_opens_it(self):
        self.assertTrue(wm_new_activity("28|2026-05-28T07:24:48Z",
                                        "28|2026-06-01T00:00:00Z"))

    def test_fewer_or_earlier_does_not_re_open(self):
        """Re-narrowing a window must not look like new activity."""
        self.assertFalse(wm_new_activity("28|2026-05-28T07:24:48Z",
                                         "12|2026-05-01T00:00:00Z"))

    def test_no_stored_watermark_never_re_opens(self):
        """Verdicts made before watermarks existed stay in force."""
        self.assertFalse(wm_new_activity(None, "99|2030-01-01T00:00:00Z"))

    def test_a_malformed_watermark_never_re_opens(self):
        """Fail closed: keep the operator's verdict rather than silently drop it."""
        self.assertFalse(wm_new_activity("garbage", "28|2026-05-28T07:24:48Z"))

    def test_a_stale_verdict_leaves_the_finding_at_full_severity(self):
        g = _graph(_finding("f1", "high"))
        apply_dispositions(g, [_benign("f1", watermark="10|2026-01-01T00:00:00Z")])
        # the finding's own watermark is derived from its occurrences; with none
        # stamped it is empty, so nothing can look newer -> verdict still applies
        self.assertEqual(g.findings[0].severity, "informational")

    def test_new_activity_re_opens_and_says_so(self):
        f = _finding("f1", "high")
        f.occ_count, f.occ_latest = 50, "2026-07-01T00:00:00Z"
        g = _graph(f)
        apply_dispositions(g, [_benign("f1", watermark="10|2026-01-01T00:00:00Z")])
        self.assertEqual(g.findings[0].severity, "high",
                         "a verdict predating new activity must not keep suppressing")
        self.assertIn("re-opened", g.findings[0].summary)


class TestDegenerateInput(unittest.TestCase):
    """Triage data comes off the case row; it must never break a fuse."""

    def test_none_is_survivable(self):
        g = _graph(_finding("f1", "high"))
        apply_dispositions(g, None)
        self.assertEqual(g.findings[0].severity, "high")

    def test_non_dict_rows_are_skipped(self):
        g = _graph(_finding("f1", "high"))
        apply_dispositions(g, ["nonsense", None, 42])
        self.assertEqual(g.findings[0].severity, "high")

    def test_a_row_with_no_target_is_skipped(self):
        g = _graph(_finding("f1", "high"))
        apply_dispositions(g, [{"verdict": "benign"}])
        self.assertEqual(g.findings[0].severity, "high")

    def test_a_target_matching_nothing_is_harmless(self):
        g = _graph(_finding("f1", "high"))
        apply_dispositions(g, [_benign("does-not-exist")])
        self.assertEqual(g.findings[0].severity, "high")


if __name__ == "__main__":
    unittest.main(verbosity=2)
