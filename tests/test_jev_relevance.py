"""Jev relevance scoring: a stoppable System action that keeps what it scored.

It reads a case's raw collected rows — the only raw material a case has — and
must respect what the operator already said about the case: excluded hosts
are never read, let alone sent. It can run for minutes, so Stop must take
effect between calls, and a stop or a Jev outage must keep the rows already
scored rather than throw them away. The ceiling on rows is a cost bound and is
said in the run log, never silent.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_HERE, os.path.join(_ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services import workflow_service  # noqa: E402
from services.fusion import jev, store  # noqa: E402
from services.fusion.schema import Finding  # noqa: E402

RUNS = {
    "r1": {"details": {"client_name": "HOST1"}},
    "r2": {"details": {"client_name": "EXCLUDED.corp.local"}},
    "r3": {"details": {"client_name": "HOST3",
                       "timeline_events": [{"message": "psexec started"}]}},
}
DATA = {"r1": {"Windows.System.Pslist": [{"Name": f"p{i}", "Blob": "x" * 900} for i in range(5)]},
        "r2": {"Windows.System.Pslist": [{"Name": "secret"}]}}


def _patches(case=None, members=("r1", "r2", "r3")):
    ws = mock.Mock()
    ws.get_automation_run.side_effect = lambda rid: RUNS[rid]
    case = case if case is not None else {"excluded_hosts": ["excluded"]}
    g = types.SimpleNamespace(findings=[Finding(id="f", title="Mimikatz on HOST1", severity="high",
                                                confidence="high", summary="")], entities={})
    return [mock.patch.object(store, "_ws", return_value=ws),
            mock.patch.object(store, "_members_for_case", return_value=list(members)),
            mock.patch.object(store, "_agentic_collected_data",
                              side_effect=lambda rid, det, log=None: DATA.get(rid, {})),
            mock.patch.object(store, "get_case", return_value=case),
            mock.patch.object(store, "view_graph", return_value=g)]


class Rows(unittest.TestCase):
    def test_excluded_hosts_are_never_read_and_rows_are_capped(self):
        with _patches()[0], _patches()[1], _patches()[2]:
            rows = list(jev._case_rows("c1", {"excluded_hosts": ["excluded"]}, None))
        self.assertEqual([(r[0], r[1]) for r in rows],
                         [("r1", "Windows.System.Pslist")] * 5 + [("r3", "timesketch")])
        self.assertNotIn("secret", json.dumps(rows))
        self.assertTrue(rows[0][3].startswith("[HOST1] "))
        self.assertLessEqual(len(rows[0][3]), len("[HOST1] ") + jev.ROW_CHARS)


class Job(unittest.TestCase):
    def run_job(self, answer_for_call, cancel_after=None, members=("r1", "r2", "r3")):
        saved, logs, calls = [], [], []
        cancel = threading.Event()

        def fake_ask(state, questions, **kw):
            calls.append(len(questions))
            if cancel_after is not None and len(calls) >= cancel_after:
                cancel.set()
            return answer_for_call(len(calls), list(questions))
        ps = _patches(members=members) + [
            mock.patch.object(jev, "ask", side_effect=fake_ask),
            mock.patch.object(jev, "pack", lambda items, r, max_tokens: iter(
                [items[i:i + 2] for i in range(0, len(items), 2)])),
            mock.patch.object(store, "_merge_case_details",
                              side_effect=lambda cid, p: saved.append(p["jev_relevance"])),
            mock.patch.object(workflow_service, "add_log_to_run",
                              side_effect=lambda rid, m, lvl="info": logs.append((lvl, m))),
            mock.patch.object(workflow_service, "update_run_status")]
        for p in ps:
            p.start()
        try:
            try:
                res = jev.score_relevance("c1", run_id="R", cancel=cancel)
                err = None
            except RuntimeError as e:
                res, err = None, str(e)
        finally:
            for p in reversed(ps):
                p.stop()
        return res, err, saved, logs, calls

    def test_keeps_only_relevant_rows_best_first(self):
        ps = iter([0.2, 0.9, 0.6, 0.4, 0.95, 0.51])
        res, err, saved, logs, calls = self.run_job(
            lambda n, keys: {k: {"noul": next(ps)} for k in keys})
        self.assertIsNone(err)
        self.assertEqual(calls, [2, 2, 2])
        self.assertEqual([r["p"] for r in saved[-1]["rows"]], [0.95, 0.9, 0.6, 0.51])
        self.assertEqual(saved[-1]["rows_scored"], 6)
        self.assertEqual(res["relevant"], 4)

    def test_stop_takes_effect_between_calls_and_keeps_the_work(self):
        res, err, saved, logs, calls = self.run_job(
            lambda n, keys: {k: {"noul": 0.9} for k in keys}, cancel_after=1)
        self.assertEqual(err, "stopped")
        self.assertEqual(calls, [2])
        self.assertEqual((saved[-1]["rows_scored"], len(saved[-1]["rows"])), (2, 2))

    def test_an_outage_keeps_the_work_and_says_how_far_it_got(self):
        res, err, saved, logs, calls = self.run_job(
            lambda n, keys: None if n == 2 else {k: {"noul": 0.9} for k in keys})
        self.assertIn("after 2 of 6", err)
        self.assertEqual(saved[-1]["rows_scored"], 2)

    def test_the_row_ceiling_is_logged(self):
        with mock.patch.object(jev, "MAX_ROWS", 3):
            res, err, saved, logs, calls = self.run_job(
                lambda n, keys: {k: {"noul": 0.1} for k in keys})
        self.assertEqual(saved[-1]["rows_total"], 3)
        self.assertTrue(any(lvl == "warning" and "first 3" in m for lvl, m in logs))

    def test_no_rows_is_an_error_not_an_empty_success(self):
        res, err, *_ = self.run_job(lambda n, keys: {}, members=())
        self.assertIn("no collected rows", err)


class SystemType(unittest.TestCase):
    def test_runs_under_settings_actions(self):
        self.assertIn("jev_relevance", workflow_service.SYSTEM_TYPES)


class Panel(unittest.TestCase):
    """The real _tlRelHtml from cases.html, run in node."""

    def test_panel_markup(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        with open(os.path.join(_ROOT, "modules/nginx/html/cases.html"), encoding="utf-8") as fh:
            src = fh.read()
        fn = re.search(r"function _tlRelHtml\(d\)\{.*?\n\}", src, re.S)
        self.assertTrue(fn, "_tlRelHtml missing from cases.html")
        js = ("const esc=s=>String(s).replace(/</g,'&lt;');\n" + fn.group(0) + """
console.log(JSON.stringify([
  _tlRelHtml({}),
  _tlRelHtml({scored_at:'2026-09-24T10:00:00', rows_scored:4, rows_total:10,
              rows:[{p:0.93, artifact:'Pslist', text:'<script>'}]}),
]));""")
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
            t.write(js)
        try:
            out = subprocess.run([node, t.name], capture_output=True, text=True, check=True).stdout
        finally:
            os.unlink(t.name)
        empty, panel = json.loads(out)
        self.assertEqual(empty, "")
        self.assertIn("1 most relevant collected rows", panel)
        self.assertIn("stopped at 4 of 10", panel)
        self.assertIn("93%", panel)
        self.assertNotIn("<script>", panel)


if __name__ == "__main__":
    unittest.main()
