"""An offline report never takes the place of an AI report (store._keep_ai_report).

2026-11-22: a report written with the AI, the key removed, Regenerate -- and the
offline report replaced the AI one on screen; the AI report was left only in the
history. Now a run that could not use the AI keeps the AI report, writes nothing
over it, and says why above the report. An offline report still replaces another
offline one, and is still a case's first report.
"""
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BACKEND = os.path.join(_ROOT, "modules/backend")
for _p in (_BACKEND, _ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
# same convention as test_report_persistence.py: the package without its __init__
if "services" not in sys.modules:
    _svc = types.ModuleType("services")
    _svc.__path__ = [os.path.join(_BACKEND, "services")]
    sys.modules["services"] = _svc

from services.fusion import store  # noqa: E402

AI = "# R\n\nwritten by the model\n\n---\n_Narrative by live LLM; fact tables deterministic._\n"
OFFLINE = "# R\n\ntemplate\n\n---\n_Deterministic report — The AI provider rejected the API key. Enter a valid key._\n"


class _Graph:
    findings = []
    entities = {}
    relationships = []


class Rule(unittest.TestCase):
    def test_only_an_offline_result_over_an_ai_report_is_refused(self):
        self.assertIn("rejected the API key", store._keep_ai_report(AI, OFFLINE))
        self.assertIsNone(store._keep_ai_report(AI, AI))            # a new AI report replaces it
        self.assertIsNone(store._keep_ai_report(OFFLINE, OFFLINE))  # offline over offline: as before
        self.assertIsNone(store._keep_ai_report(None, OFFLINE))     # a case's first report
        self.assertIsNone(store._keep_ai_report("", OFFLINE))

    def test_the_timeframe_being_written_is_the_one_compared(self):
        d = {"report_md": OFFLINE, "active_scope": "full",
             "scopes": [{"id": "s2", "report_md": AI}]}
        with mock.patch.object(store, "_active_scope_id", return_value="full"), \
             mock.patch.object(store, "_scopes", return_value=d["scopes"]):
            self.assertEqual(store._scope_report_md(d, "full"), OFFLINE)
            self.assertEqual(store._scope_report_md(d, "s2"), AI)
            self.assertIsNone(store._scope_report_md(d, "gone"))


class Regenerate(unittest.TestCase):
    def _run(self, current, new, kept=None):
        writes, logs = [], []
        g = _Graph()
        case = {"name": "Case", "audience": "both", "language": "en",
                "min_severity": "informational", "time_window": None,
                "disposition_checklist": [{"q": "already generated"}],
                "fused_run_ids": ["run-1"], "report_md": current}
        if kept:
            case["report_ai_kept"] = kept
        with mock.patch.object(store, "get_case", return_value=case), \
             mock.patch.object(store, "load_graph", return_value=g), \
             mock.patch.object(store, "_filter_graph_by_hosts", return_value=g), \
             mock.patch.object(store, "_llm_payload_budget", return_value=(100, 1000)), \
             mock.patch.object(store, "_llm_identity_budget", return_value=10), \
             mock.patch.object(store, "_effective_output_cap", return_value=4096), \
             mock.patch.object(store, "_configured_fusion_model",
                               return_value=("gpt-x", "openrouter", "online")), \
             mock.patch.object(store, "_active_scope_id", return_value="full"), \
             mock.patch.object(store, "_upsert_scope", side_effect=lambda *a, **k: None), \
             mock.patch.object(store._rh, "archive", side_effect=lambda *a, **k: None), \
             mock.patch.object(store, "_merge_case_details",
                               side_effect=lambda cid, patch: writes.append(patch)), \
             mock.patch.object(store, "_mutate_list_field", side_effect=lambda *a, **k: None), \
             mock.patch.object(store, "log_case_event",
                               side_effect=lambda cid, a, s="ok", d="", **k: logs.append((a, s, d))), \
             mock.patch.object(store.llm_sim, "generate_report", return_value=new):
            out = store.regenerate_report("case-1", use_llm=True)
        return out, writes, logs

    def test_an_ai_report_is_kept_when_the_ai_cannot_be_used(self):
        out, writes, logs = self._run(AI, OFFLINE)
        self.assertEqual([w for w in writes if "report_md" in w], [], "nothing written over it")
        note = [w["report_ai_kept"] for w in writes if "report_ai_kept" in w]
        self.assertEqual(len(note), 1)
        self.assertEqual(note[0]["scope"], "full")
        self.assertIn("rejected the API key", note[0]["reason"])
        self.assertTrue(out["kept_ai_report"])
        self.assertEqual(out["report_md"], AI)
        self.assertTrue(any(a == "Report · AI report kept" and s == "warning" for a, s, _ in logs))
        self.assertFalse(any(a == "Report saved" for a, _, _ in logs))

    def test_offline_still_replaces_offline_and_ai_replaces_ai(self):
        for current, new in ((OFFLINE, OFFLINE), (None, OFFLINE), (AI, AI), (OFFLINE, AI)):
            out, writes, _ = self._run(current, new)
            saved = [w for w in writes if "report_md" in w]
            self.assertEqual(len(saved), 1, (current, new))
            self.assertEqual(saved[0]["report_md"], new)
            self.assertNotIn("kept_ai_report", out)

    def test_a_new_report_clears_the_note(self):
        _, writes, _ = self._run(AI, AI, kept={"scope": "full", "reason": "x"})
        saved = [w for w in writes if "report_md" in w][0]
        self.assertIn("report_ai_kept", saved)
        self.assertIsNone(saved["report_ai_kept"])


class RefusionAndPage(unittest.TestCase):
    def test_the_refusion_path_keeps_it_too(self):
        src = io.open(os.path.join(_BACKEND, "services/fusion/store.py"), encoding="utf-8").read()
        fuse = src[src.index("def _fuse_case_locked("):src.index("def regenerate_report_async(")]
        self.assertIn('_keep_ai_report(d.get("report_md"), report)', fuse)
        self.assertIn('report, _report_is_new = d.get("report_md"), False', fuse)
        self.assertIn('_details["report_ai_kept"] = None', fuse)

    def test_the_note_above_the_report(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        src = io.open(os.path.join(_ROOT, "modules/nginx/html/cases.html"), encoding="utf-8").read()
        js = ("const esc=s=>String(s); const window={_md:'# R'};\n"
              + re.search(r"function behindNote\(.*?\n\}", src, re.S).group(0) + """
console.log(JSON.stringify([
  behindNote({active_scope:'full', report_ai_kept:{scope:'full', reason:'The key was rejected.'}}),
  behindNote({active_scope:'s2', report_ai_kept:{scope:'full', reason:'The key was rejected.'}}),
  behindNote({active_scope:'full'})]));""")
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
            t.write(js)
        try:
            import json
            out = json.loads(subprocess.run([node, t.name], capture_output=True, text=True,
                                            check=True).stdout)
        finally:
            os.unlink(t.name)
        self.assertIn("could not use the AI model: The key was rejected.", out[0])
        self.assertIn("Your AI report below was kept", out[0])
        self.assertEqual(out[1], "", "another timeframe's note is not shown here")
        self.assertEqual(out[2], "")


if __name__ == "__main__":
    unittest.main()
