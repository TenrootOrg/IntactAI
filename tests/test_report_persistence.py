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

from services.fusion import store  # noqa: E402


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
    """The advisory and the checklist run AFTER the narrative exists. Neither may
    be able to destroy it -- that is what made a finished report invisible."""

    def _run(self, analyze_side_effect):
        writes, logs = [], []
        g = _Graph()
        with mock.patch.object(store, "get_case", return_value=_case()), \
             mock.patch.object(store, "load_graph", return_value=g), \
             mock.patch.object(store, "_filter_graph_by_hosts", return_value=g), \
             mock.patch.object(store, "_llm_payload_budget", return_value=(100, 1000)), \
             mock.patch.object(store, "_llm_identity_budget", return_value=10), \
             mock.patch.object(store, "_effective_output_cap", return_value=4096), \
             mock.patch.object(store, "_configured_fusion_model",
                               return_value=("gpt-x", "openrouter", "online")), \
             mock.patch.object(store, "_merge_case_details",
                               side_effect=lambda cid, patch: writes.append(patch)), \
             mock.patch.object(store, "log_case_event",
                               side_effect=lambda cid, a, s="ok", d="", **k: logs.append((a, s))), \
             mock.patch.object(store.llm_sim, "generate_report", return_value="NARRATIVE"), \
             mock.patch.object(store.llm_sim, "analyze", side_effect=analyze_side_effect):
            out = store.regenerate_report("case-1", use_llm=True)
        return out, writes, logs

    def test_narrative_is_saved_before_the_advisory_runs(self):
        """A raising advisory must not take the report down with it."""
        out, writes, logs = self._run(RuntimeError("provider 502"))
        saved = [w for w in writes if "report_md" in w]
        self.assertEqual(len(saved), 1, f"narrative not persisted; writes={writes}")
        self.assertEqual(saved[0]["report_md"], "NARRATIVE")
        self.assertEqual(saved[0]["report_run_ids"], ["run-1"])
        self.assertFalse(saved[0]["report_dirty"])
        self.assertEqual(out["report_md"], "NARRATIVE")
        # ...and the operator is told the advisory failed, not left guessing.
        self.assertIn(("Advisory", "warning"), logs)

    def test_a_failed_advisory_does_not_blank_the_stored_one(self):
        _, writes, _ = self._run(RuntimeError("boom"))
        self.assertEqual([w for w in writes if "analysis" in w], [],
                         "a failed advisory pass overwrote the stored advisory")

    def test_happy_path_still_saves_both(self):
        out, writes, logs = self._run(lambda *a, **k: {"incident_groups": [], "hypotheses": []})
        self.assertEqual([w for w in writes if "report_md" in w][0]["report_md"], "NARRATIVE")
        self.assertEqual(len([w for w in writes if "analysis" in w]), 1)
        self.assertEqual(out["report_md"], "NARRATIVE")

    def test_the_advisory_phase_is_logged_at_both_ends(self):
        """It used to run in total silence, so a slow advisory and a hung backend
        looked identical in the activity log."""
        _, _, logs = self._run(lambda *a, **k: {"incident_groups": [], "hypotheses": []})
        actions = [a for a, _ in logs]
        self.assertIn("Advisory · sending request to the LLM", actions)
        self.assertIn("Advisory · complete", actions)


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


if __name__ == "__main__":
    unittest.main()
