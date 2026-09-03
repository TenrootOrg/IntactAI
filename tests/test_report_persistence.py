"""The report path must never lose a narrative it already paid for, and must
never claim to have saved one it didn't.

Both defects were observed live on the same run: the model returned a complete
19,462-character report, the activity log's last line was "LLM responded", and
nothing was ever written -- because the narrative lived in a local variable
behind two more multi-minute model calls, and because every layer under
_merge_case_details swallowed failure (save_workflow catches everything and
returns False; update_run_status dropped that bool).

Run in-container against the shipped package (PYTHONPATH=/app), or from a repo
checkout:

    docker exec intact_backend sh -lc \
      'PYTHONPATH=/app python3 -m pytest /app/tests/test_report_persistence.py -q'
"""
import datetime as _dt
import os
import sys
import io
import unittest
from unittest import mock

import types

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BACKEND = os.path.join(_ROOT, "modules/backend")
for _p in ("/app", _BACKEND, _ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# services/__init__.py imports the whole backend (grpc, elasticsearch, the
# Velociraptor client), none of which a dev box or CI has. Bind the package to
# its directory WITHOUT executing that __init__ -- the same convention
# test_case_bundle.py uses -- so the module under test imports for real.
if "services" not in sys.modules:
    _svc = types.ModuleType("services")
    _svc.__path__ = [os.path.join(_BACKEND, "services")]
    sys.modules["services"] = _svc

from services.fusion import store, llm_sim  # noqa: E402


def _read_source(rel):
    """Read a repo file for the source-level assertions below."""
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return io.open(os.path.join(root, rel), encoding="utf-8").read()


class _Graph:
    findings = []
    entities = {}
    relationships = []


def _case():
    return {"name": "Case", "audience": "both", "language": "en",
            "min_severity": "informational", "time_window": None,
            "disposition_checklist": [{"q": "already generated"}],
            "fused_run_ids": ["run-1"]}


class NarrativeSurvivesEnrichmentFailure(unittest.TestCase):
    """The checklist runs AFTER the narrative exists. It must not be able to destroy
    it -- that is what once made a finished report invisible: the narrative lived in
    a local variable until a single write at the very end, behind model calls that
    could each run for minutes and raise.

    The advisory used to sit here too and is gone: the report now analyses the case
    phase by phase, which is the same clustering its "incident groups" did, done
    better and actually rendered. These tests therefore assert the guarantee that
    remains -- persist the narrative the moment it exists.
    """

    def _run(self, checklist_side_effect=None, has_checklist=True):
        writes, logs = [], []
        g = _Graph()
        case = _case()
        if not has_checklist:
            case.pop("disposition_checklist", None)
        cl = checklist_side_effect or (lambda *a, **k: [{"q": "x"}])
        with mock.patch.object(store, "get_case", return_value=case), \
             mock.patch.object(store, "load_graph", return_value=g), \
             mock.patch.object(store, "_filter_graph_by_hosts", return_value=g), \
             mock.patch.object(store, "_llm_payload_budget", return_value=(100, 1000)), \
             mock.patch.object(store, "_llm_identity_budget", return_value=10), \
             mock.patch.object(store, "_effective_output_cap", return_value=4096), \
             mock.patch.object(store, "_configured_fusion_model",
                               return_value=("gpt-x", "openrouter", "online")), \
             mock.patch.object(store, "_merge_case_details",
                               side_effect=lambda cid, patch: writes.append(patch)), \
             mock.patch.object(store, "_mutate_list_field",
                               side_effect=lambda *a, **k: None), \
             mock.patch.object(store, "log_case_event",
                               side_effect=lambda cid, a, s="ok", d="", **k: logs.append((a, s))), \
             mock.patch.object(store.llm_sim, "generate_report", return_value="NARRATIVE"), \
             mock.patch.object(store.llm_sim, "generate_disposition_checklist",
                               side_effect=cl):
            out = store.regenerate_report("case-1", use_llm=True)
        return out, writes, logs

    def test_the_narrative_is_persisted_the_moment_it_exists(self):
        out, writes, _ = self._run()
        saved = [w for w in writes if "report_md" in w]
        self.assertEqual(len(saved), 1, f"narrative not persisted; writes={writes}")
        self.assertEqual(saved[0]["report_md"], "NARRATIVE")
        self.assertEqual(saved[0]["report_run_ids"], ["run-1"])
        self.assertFalse(saved[0]["report_dirty"])
        self.assertEqual(out["report_md"], "NARRATIVE")

    def test_a_failing_checklist_does_not_cost_the_narrative(self):
        """The checklist is the remaining enrichment that runs after the report."""
        out, writes, logs = self._run(
            checklist_side_effect=RuntimeError("provider 502"), has_checklist=False)
        saved = [w for w in writes if "report_md" in w]
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0]["report_md"], "NARRATIVE")
        self.assertEqual(out["report_md"], "NARRATIVE")
        self.assertIn(("Checklist", "warning"), logs)

    def test_the_report_is_saved_before_the_checklist_is_asked_for(self):
        """Ordering is the whole point: everything after the save is expendable."""
        order = []
        g = _Graph()
        case = _case(); case.pop("disposition_checklist", None)
        with mock.patch.object(store, "get_case", return_value=case), \
             mock.patch.object(store, "load_graph", return_value=g), \
             mock.patch.object(store, "_filter_graph_by_hosts", return_value=g), \
             mock.patch.object(store, "_llm_payload_budget", return_value=(100, 1000)), \
             mock.patch.object(store, "_llm_identity_budget", return_value=10), \
             mock.patch.object(store, "_effective_output_cap", return_value=4096), \
             mock.patch.object(store, "_configured_fusion_model",
                               return_value=("gpt-x", "openrouter", "online")), \
             mock.patch.object(store, "_merge_case_details",
                               side_effect=lambda cid, p: order.append("SAVE")
                               if "report_md" in p else None), \
             mock.patch.object(store, "_mutate_list_field", side_effect=lambda *a, **k: None), \
             mock.patch.object(store, "log_case_event", side_effect=lambda *a, **k: None), \
             mock.patch.object(store.llm_sim, "generate_report", return_value="NARRATIVE"), \
             mock.patch.object(store.llm_sim, "generate_disposition_checklist",
                               side_effect=lambda *a, **k: order.append("CHECKLIST") or []):
            store.regenerate_report("case-1", use_llm=True)
        self.assertEqual(order[:2], ["SAVE", "CHECKLIST"], order)

    def test_the_advisory_engine_is_gone_entirely(self):
        """Not merely uncalled -- removed. It was a second whole-case model call
        whose output was never wired to a tab, so nothing it produced was ever
        displayed, and it kept resurfacing in the UI as log lines and dead API
        surface long after the operator asked for it to be gone. Keeping a
        dormant `analyze()` around is how it would come back."""
        for name in ("analyze", "_ground", "advisory_shortfall",
                     "_advisory_diagnostic", "ANALYST_SYSTEM_PROMPT"):
            self.assertFalse(hasattr(store.llm_sim, name),
                             f"llm_sim.{name} is back")

    def test_no_advisory_blob_is_written(self):
        """A fuse must not persist details['analysis'] any more -- nothing reads it."""
        src = _read_source("modules/backend/services/fusion/store.py")
        self.assertNotIn('"analysis": analysis', src)

    def test_no_operator_facing_string_says_advisory(self):
        """The operator kept SEEING the word after the feature was removed: it
        survived in the 88% progress line and an 'Advisory saved' event."""
        import re
        for rel in ("modules/backend/services/fusion/store.py",
                    "modules/backend/services/fusion/llm_sim.py",
                    "modules/backend/routes/case_routes.py"):
            for i, line in enumerate(_read_source(rel).splitlines(), 1):
                if line.strip().startswith("#") or "advisory" not in line.lower():
                    continue
                self.assertIsNone(
                    re.search(r"""["'][^"']*advisory[^"']*["']""", line, re.I),
                    f"{rel}:{i} still shows the operator the word: {line.strip()}")


class AFailedWriteIsAnError(unittest.TestCase):
    """"Report saved" must not appear over a write that never happened."""

    def test_merge_raises_when_the_row_write_fails(self):
        ws = mock.Mock()
        ws.get_automation_run.return_value = {"status": "completed"}
        ws.update_run_status.return_value = False          # save_workflow said no
        with mock.patch.object(store, "_ws", return_value=ws):
            with self.assertRaises(RuntimeError):
                store._merge_case_details("case-1", {"report_md": "x"})

    def test_merge_is_silent_when_the_write_lands(self):
        ws = mock.Mock()
        ws.get_automation_run.return_value = {"status": "completed"}
        ws.update_run_status.return_value = True
        with mock.patch.object(store, "_ws", return_value=ws):
            store._merge_case_details("case-1", {"report_md": "x"})   # must not raise

    def test_list_mutation_raises_when_the_write_fails(self):
        ws = mock.Mock()
        ws.mutate_run_details.return_value = False
        with mock.patch.object(store, "_ws", return_value=ws):
            with self.assertRaises(RuntimeError):
                store._mutate_list_field("case-1", "disposition_checklist", lambda cur: cur)


class StuckSpinnerWatchdog(unittest.TestCase):
    """report_generating is cleared by a database write. When that write is the
    thing failing, the flag sticks True forever and the spinner never stops."""

    @staticmethod
    def _ago(seconds):
        t = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(seconds=seconds)
        return t.strftime("%Y-%m-%dT%H:%M:%S")

    def test_not_generating_reads_false(self):
        self.assertFalse(store.report_generation_active({}))
        self.assertFalse(store.report_generation_active({"report_generating": False}))

    def test_a_live_generation_reads_true(self):
        self.assertTrue(store.report_generation_active(
            {"report_generating": True, "report_generating_started_at": self._ago(60)}))

    def test_a_generation_older_than_any_possible_run_reads_false(self):
        self.assertFalse(store.report_generation_active(
            {"report_generating": True,
             "report_generating_started_at": self._ago(store.REPORT_GEN_STALE_SECONDS + 60)}))

    def test_an_unusable_stamp_does_not_cancel_a_live_run(self):
        """Better a spinner that resolves on restart than one killed mid-report."""
        for stamp in (None, "", "not-a-timestamp"):
            self.assertTrue(store.report_generation_active(
                {"report_generating": True, "report_generating_started_at": stamp}), stamp)




class TheReportsMustCarryTheirDocumentContract(unittest.TestCase):
    """Both reports are deliverables, and the PDF renderer keys off their shape:
    an `###` heading followed by a bullet list becomes a bordered card, and the
    literal `- **Severity:** <Level>` is colour-coded (engagement/pdf.py). A prompt
    that stops asking for that shape silently loses the styling."""

    def test_the_focused_report_asks_for_F_N_blocks_the_pdf_can_style(self):
        p = llm_sim.REPORT_SYSTEM_PROMPT_FOCUSED
        self.assertIn("### F-N:", p)
        self.assertIn("- **Severity:** Critical / High / Medium / Low", p)
        self.assertIn("- **Confidence:**", p)
        self.assertIn("*(Responds to: F-N", p)

    def test_the_focused_report_has_the_three_action_horizons(self):
        p = llm_sim.REPORT_SYSTEM_PROMPT_FOCUSED
        for horizon in ("Immediate (next 24 hours)", "Short-term (next week)",
                        "Long-term (next quarter)"):
            self.assertIn(horizon, p)

    def test_the_macro_leads_with_the_executive_layer(self):
        """Priority actions used to sit ABOVE the phases, so the reader was told to
        open Phase 3 before learning what Phase 3 was."""
        p = llm_sim.SYNTHESIS_SYSTEM_PROMPT
        for s in ("## Executive Summary", "## Key Judgements", "## Where to start",
                  "## Recommended Next Steps"):
            self.assertIn(s, p)
        self.assertLess(p.index("## Executive Summary"), p.index("## Where to start"))
        self.assertLess(p.index("## Where to start"), p.index("## Recommended Next Steps"))

    def test_where_to_start_must_rank_every_phase(self):
        p = llm_sim.SYNTHESIS_SYSTEM_PROMPT
        self.assertIn("RANK EVERY PHASE", p)
        self.assertIn("PHASE NUMBERS", p)          # the invented-number guard

    def test_both_reports_state_a_justified_risk_level(self):
        for p in (llm_sim.SYNTHESIS_SYSTEM_PROMPT, llm_sim.REPORT_SYSTEM_PROMPT_FOCUSED):
            self.assertIn("**Risk: CRITICAL|HIGH|MEDIUM|LOW**", p)
            self.assertIn("Reserve CRITICAL", p)

    def test_the_phase_prompt_asks_for_the_card_bullets(self):
        p = llm_sim.PHASE_SYSTEM_PROMPT
        self.assertIn("- **Severity:**", p)
        self.assertIn("- **Confidence:**", p)
        self.assertIn("**Investigate:**", p)


if __name__ == "__main__":
    unittest.main()
