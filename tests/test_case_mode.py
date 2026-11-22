"""A case's mode: IR (the default) or Proactive (services/fusion/case_mode.py).

Asked for 2026-11-22: IR reads everything as possible compromise; Proactive is a
routine check of a healthy environment -- findings below critical score one
level lower, the AI flags only what is worth checking and explains, for each,
why it may be malicious, why it may be a false positive, and what to check.
Old cases and bundles have no mode and are IR.
"""
import io
import json
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
for _p in (os.path.dirname(os.path.abspath(__file__)), _BACKEND):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import case_mode, correlate, decision_model, store  # noqa: E402
from services.fusion.schema import Finding, FusionGraph  # noqa: E402


def _read(*rel):
    with io.open(os.path.join(*rel), encoding="utf-8") as fh:
        return fh.read()


def _f(fid, sev, kind="single"):
    return Finding(id=fid, title=fid, severity=sev, confidence="medium", summary="s", kind=kind)


class Mode(unittest.TestCase):
    def test_old_cases_and_anything_unknown_are_ir(self):
        for d in ({}, None, {"case_mode": None}, {"case_mode": "IRR"}, {"case_mode": 3}, "x"):
            self.assertEqual(case_mode.of(d), "ir", d)
        self.assertEqual(case_mode.of({"case_mode": "Proactive "}), "proactive")
        self.assertEqual(case_mode.clean("PROACTIVE"), "proactive")
        self.assertEqual(case_mode.clean(""), "ir")

    def test_steering_is_the_rule_then_the_operators_own(self):
        self.assertIsNone(case_mode.steering({}))
        self.assertEqual(case_mode.steering({"master_prompt": " backup noise is IT "}), "backup noise is IT")
        s = case_mode.steering({"case_mode": "proactive", "master_prompt": "backup noise is IT"})
        self.assertTrue(s.startswith(case_mode.PROACTIVE_RULE))
        self.assertTrue(s.endswith("backup noise is IT"))
        self.assertEqual(case_mode.steering({"case_mode": "proactive"}), case_mode.PROACTIVE_RULE)

    def test_the_rule_asks_for_both_sides_and_what_to_check(self):
        r = case_mode.PROACTIVE_RULE
        for words in ("why it might be malicious", "false positive", "what to check",
                      "critical is still said plainly", "rational"):
            self.assertIn(words, r)

    def test_the_title(self):
        md = "# Incident Case Report — acme\n\nbody"
        self.assertEqual(case_mode.titled(md, {}), md)
        self.assertEqual(case_mode.titled(md, {"case_mode": "proactive"}),
                         "# Proactive Security Review — acme\n\nbody")
        self.assertEqual(case_mode.titled("no title", {"case_mode": "proactive"}), "no title")


class Scores(unittest.TestCase):
    def test_one_level_lower_never_critical_never_a_judged_row(self):
        g = FusionGraph(case_id="c")
        g.findings = [_f("c", "critical"), _f("h", "high"), _f("m", "medium"), _f("l", "low"),
                      _f("i", "informational"), _f("d", "informational", kind="dispositioned"),
                      _f("dh", "high", kind="dispositioned")]
        self.assertEqual(correlate._proactive_step_down(g), 3)
        got = {f.id: f.severity for f in g.findings}
        self.assertEqual(got, {"c": "critical", "h": "medium", "m": "low", "l": "informational",
                               "i": "informational", "d": "informational", "dh": "high"})
        self.assertIn("[Proactive review: lowered from high]", g.findings[1].summary)
        self.assertNotIn("Proactive", g.findings[0].summary)

    def test_assemble_lowers_only_in_proactive_after_the_floor_before_host_risk(self):
        src = _read(_BACKEND, "services/fusion/correlate.py")
        body = src[src.index("def assemble("):src.index("def _recover_mitre_from_text(")]
        i_floor, i_disp = body.index('"_findings_floor"'), body.index('"_apply_dispositions"')
        i_step, i_score = body.index('"_proactive_step_down"'), body.index('"_score_assets"')
        self.assertTrue(i_floor < i_disp < i_step < i_score)
        self.assertIn('if case_mode == "proactive":', body)

    def test_a_mode_change_asks_for_a_refusion_and_ir_cases_keep_their_signature(self):
        d = {"time_window": {"start": "a", "end": "b"}, "min_severity": "medium"}
        ir = store._settings_sig(d)
        self.assertEqual(ir, store._settings_sig({**d, "case_mode": "ir"}), "no Refusion note on every old case")
        self.assertNotEqual(ir, store._settings_sig({**d, "case_mode": "proactive"}))
        self.assertIn("case_mode", store._REPORT_INPUT_KEYS)
        self.assertIn("case_mode", store.PURGE_KEEPS)


class Saved(unittest.TestCase):
    def _save(self, fields, case=None):
        case = {"name": "qa"} if case is None else case
        with mock.patch.object(store, "get_case", return_value=case), \
             mock.patch.object(store, "_merge_case_details") as merge, \
             mock.patch.object(store, "log_case_event"), \
             mock.patch.object(store, "_report_behind") as behind:
            res = store.update_case_info("c1", fields)
        return res, (merge.call_args.args[1] if merge.called else None), behind

    def test_case_management_saves_it_and_marks_the_report_behind(self):
        res, patch, behind = self._save({"case_mode": "proactive"})
        self.assertEqual(patch, {"case_mode": "proactive"})
        self.assertEqual(res["case_mode"], "proactive")
        behind.assert_called_once()
        _, patch, behind = self._save({"case_mode": "anything"}, {"name": "qa", "case_mode": "proactive"})
        self.assertEqual(patch, {"case_mode": "ir"})
        behind.assert_called_once()
        _, _, behind = self._save({"case_mode": "ir"})            # unchanged: nothing behind
        behind.assert_not_called()
        self.assertEqual(store.case_info({})["case_mode"], "ir")

    def test_configuration_and_creation_take_it_too(self):
        src = _read(_BACKEND, "services/fusion/store.py")
        cfg = src[src.index("def set_analysis_config("):src.index("def _reaches_outside(")]
        self.assertIn('patch["case_mode"] = _mode.clean(cfg["case_mode"])', cfg)
        routes = _read(_BACKEND, "routes/case_routes.py")
        self.assertIn('("case_owner", "case_description", "velo_org", "case_mode")', routes)

    def test_report_and_chat_are_steered_and_the_report_retitled(self):
        src = _read(_BACKEND, "services/fusion/store.py")
        self.assertEqual(src.count("master_prompt=_mode.steering(d)"), 3)      # Refusion, Regenerate, chat
        self.assertNotIn('master_prompt=d.get("master_prompt")', src)
        self.assertEqual(src.count("report = _mode.titled(report, d)"), 2)
        inv = _read(_BACKEND, "services/fusion/investigate.py")
        self.assertIn("system + \"\\n\\n\" + _mode.PROACTIVE_RULE", inv)


class DecisionModel(unittest.TestCase):
    def test_proactive_asks_as_a_review_and_needs_more_certainty(self):
        q = decision_model._proactive_q(decision_model._verdict_question)("q0")
        self.assertTrue(q["instructions"].endswith(case_mode.DECISION_NOTE))
        self.assertEqual(q["criteria"], decision_model.VERDICTS)
        ans = {"choice": "true_positive", "confidence": 0.85,
               "probabilities": {"true_positive": 0.85, "known": 0.1, "false_positive": 0.05}}
        self.assertEqual(decision_model._answer_to_suggestion(ans)["label"], "true_positive")
        self.assertIsNone(decision_model._answer_to_suggestion(ans, decision_model.PROACTIVE_TP_MIN_P)["label"],
                          "0.85 is not enough for a malicious chip in a Proactive case")

    def test_answers_are_kept_per_mode(self):
        cfg = {}
        with mock.patch.object(decision_model, "current_by", return_value="jev/m1"):
            ir = {"decision_by": {"suggestions": "jev/m1"}, "decision_suggestions": {"f": 1}}
            self.assertEqual(decision_model.cached(ir, "suggestions", cfg), {"f": 1})
            self.assertEqual(decision_model.cached({**ir, "case_mode": "proactive"}, "suggestions", cfg), {},
                             "an IR answer is not shown as a Proactive one: re-asked")
            pro = {"case_mode": "proactive", "decision_by": {"suggestions": "jev/m1|proactive"},
                   "decision_suggestions": {"f": 2}}
            self.assertEqual(decision_model.cached(pro, "suggestions", cfg), {"f": 2})
            self.assertEqual(decision_model.shown({"decision_by": {"suggestions": "jev/m0|proactive"},
                                                   "decision_suggestions": {"f": 3}}, "suggestions", cfg),
                             ({"f": 3}, "m0"))
            # the other passes (identities, scopes) are not asked differently: no tag
            self.assertEqual(decision_model._mode_tag({"case_mode": "proactive"}, "identity"), "")


class Page(unittest.TestCase):
    def test_forms_line_and_report_badge(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        src = _read(_ROOT, "modules/nginx/html/cases.html")
        self.assertIn('<select id="cmode"><option value="ir" selected>', src)          # New Case: IR by default
        self.assertIn("case_mode:v('cmode')||'ir'", src)
        self.assertIn("case_mode:v('cdf-mode')||'ir',", src)                            # Case Management
        self.assertIn("case_mode:$('#cf-mode')?.value||'ir',", src)                     # Configuration
        parts = [re.search(r"const CASE_STATUS_LABEL=\{.*?\};", src).group(0),
                 "let _cdEdit=null, _cdDraft={};",
                 re.search(r"function orgName\([^\n]*", src).group(0),
                 re.search(r"function orgLabel\([^\n]*", src).group(0),
                 re.search(r"function _usd\([^\n]*", src).group(0)] + \
                [re.search(r"function %s\(.*?\n\}" % n, src, re.S).group(0)
                 for n in ("orgOptionsHtml", "_aiCostChip", "caseMetaHtml", "caseEditForm", "_reportModeBadge")]
        js = ("const esc=s=>String(s);\nlet _orgOpts=[{id:'root',name:'root'}];\n" + "\n".join(parts) + """
console.log(JSON.stringify([caseMetaHtml({}), caseMetaHtml({case_mode:'proactive'}),
  caseEditForm({case_id:'c1', name:'a'}), caseEditForm({case_id:'c2', name:'b', case_mode:'proactive'}),
  _reportModeBadge('# Proactive Security Review — a\\\\n'), _reportModeBadge('# Incident Case Report — a\\\\n'),
  _reportModeBadge('old')]));""")
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
            t.write(js)
        try:
            out = json.loads(subprocess.run([node, t.name], capture_output=True, text=True, check=True).stdout)
        finally:
            os.unlink(t.name)
        self.assertIn(">IR</span>", out[0])
        self.assertIn(">Proactive</span>", out[1])
        self.assertIn('<option value="ir" selected>IR — incident response</option>', out[2])
        self.assertIn('<option value="proactive" selected>Proactive — routine check</option>', out[3])
        self.assertIn(">Proactive review</span>", out[4])
        self.assertIn(">IR report</span>", out[5])
        self.assertEqual(out[6], "")


if __name__ == "__main__":
    unittest.main()
