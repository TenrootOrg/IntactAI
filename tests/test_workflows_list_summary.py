"""The Workflows tab list is one page of summary rows, filtered in SQL (fleet F28).

It used to run cleanup_orphan_workflows() and load EVERY run of EVERY case with
EVERY log line on each GET, filter by case in Python and return it all -- once a
second per open tab, then JSON.stringify-compared in the browser. At fleet scale
that is megabytes per second and a frozen tab.

Backend: real SQLite in a temp dir; the real route function with a stand-in
`flask` (the backend's dependencies are not installed here). Page: the REAL
js/stores/workflows.js in node with a stub Alpine/DOM, as test_live_logs does.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

os.environ["INTACT_STORAGE_BASE"] = tempfile.mkdtemp(prefix="intact-wflist-")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "modules", "backend"), os.path.join(ROOT, "tests")]

try:
    import flask  # noqa: F401
except ImportError:
    _flask = types.ModuleType("flask")

    class _Blueprint:
        def __init__(self, *a, **k):
            pass

        def route(self, *a, **k):
            return lambda f: f
    _flask.Blueprint = _Blueprint
    _flask.jsonify = lambda *a, **k: a[0] if a else k
    _flask.g = types.SimpleNamespace(case_id=None)
    _flask.request = types.SimpleNamespace(args={})
    _flask.has_request_context = lambda: False
    sys.modules["flask"] = _flask

import _optional_deps  # noqa: F401,E402
from services.storage import get_connection, init_storage, list_workflow_summaries  # noqa: E402

init_storage()
import services.workflow_service as ws  # noqa: E402
import importlib.util  # noqa: E402

# The file alone: routes/__init__ would import every blueprint in the backend.
_spec = importlib.util.spec_from_file_location(
    "dashboard_routes_under_test", os.path.join(ROOT, "modules/backend/routes/dashboard_routes.py"))
dashboard_routes = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dashboard_routes)

WF_JS = os.path.join(ROOT, "modules/nginx/html/js/stores/workflows.js")
APP_JS = os.path.join(ROOT, "modules/nginx/html/js/stores/app.js")


def _run(case_id, atype="velociraptor_collection", details=None, status="completed"):
    rid = ws.create_automation_run(atype, "r", details=details or {}, case_id=case_id)
    ws.update_run_status(rid, status)
    for i in range(3):
        ws.add_log_to_run(rid, f"log {i}")
    return rid


class Summaries(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        get_connection().execute("DELETE FROM workflows")
        get_connection().commit()
        cls.big = _run("caseA", details={"blueprint": "Triage", "client_ids": ["C.%d" % i for i in range(1000)],
                                          "upload_id": "u1", "hunt_id": "H.1"})
        for _ in range(4):
            _run("caseA")
        cls.ts = _run("caseA", atype="timesketch")
        cls.other = _run("caseB")

    def test_case_filter_is_in_sql_and_logs_and_blobs_stay_home(self):
        runs, total = list_workflow_summaries("caseA")
        self.assertEqual(total, 6)
        self.assertNotIn(self.other, [r["run_id"] for r in runs])
        big = next(r for r in runs if r["run_id"] == self.big)
        self.assertNotIn("logs", big)
        self.assertEqual(big["details"], {"blueprint": "Triage", "upload_id": "u1", "hunt_id": "H.1"},
                         "only the keys the list shows -- no client_ids")

    def test_type_filter_and_paging(self):
        runs, total = list_workflow_summaries("caseA", "timesketch")
        self.assertEqual((total, [r["run_id"] for r in runs]), (1, [self.ts]))
        page1, total = list_workflow_summaries("caseA", limit=4)
        page2, _ = list_workflow_summaries("caseA", limit=4, offset=4)
        self.assertEqual((total, len(page1), len(page2)), (6, 4, 2))
        ids = [r["run_id"] for r in page1 + page2]
        self.assertEqual(len(set(ids)), 6)
        created = [r["created_at"] for r in page1 + page2]
        self.assertEqual(created, sorted(created, reverse=True), "newest first")

    def test_the_route_returns_a_page_of_summaries(self):
        flask_mod = sys.modules["flask"]
        with mock.patch.object(flask_mod, "g", types.SimpleNamespace(case_id="caseA")), \
                mock.patch.object(flask_mod, "request", types.SimpleNamespace(args={"limit": "2"})):
            body = dashboard_routes.get_all_automations()
        self.assertEqual((body["total"], len(body["runs"]), body["limit"]), (6, 2, 2))
        for r in body["runs"]:
            self.assertNotIn("logs", r)
            self.assertIn("status", r)
            self.assertIn("error_count", r)

    def test_a_running_hunt_still_reconciles_from_the_summary(self):
        hunt = ws.create_automation_run("velociraptor_hunt", "h", details={"hunt_id": "H.9"},
                                        case_id="caseH")
        ws.update_run_status(hunt, "running")
        import services.velociraptor_service as vs
        flask_mod = sys.modules["flask"]
        with mock.patch.object(vs, "is_hunt_registered", return_value=True), \
                mock.patch.object(flask_mod, "g", types.SimpleNamespace(case_id="caseH")), \
                mock.patch.object(flask_mod, "request", types.SimpleNamespace(args={})):
            body = dashboard_routes.get_all_automations()
        self.assertEqual(body["runs"][0]["status"], "completed")


class OrphanSweepIsThrottled(unittest.TestCase):

    def test_once_a_minute_not_once_a_request(self):
        ws._last_orphan_sweep[0] = 0.0
        with mock.patch.object(ws, "load_workflows", return_value=[]) as load:
            for _ in range(5):
                ws.cleanup_orphan_workflows()
            self.assertEqual(load.call_count, 1)
            ws.cleanup_orphan_workflows(force=True)
            self.assertEqual(load.call_count, 2)


PAGE = r"""
const fs = require('fs');
const handlers = {}, stores = {}, calls = [];
global.window = global;
global.document = { hidden: false, addEventListener: (t, f) => { handlers[t] = f; }, getElementById: () => null,
                    createElement: () => ({}) };
global.Alpine = { store: (n, o) => (o ? (stores[n] = o) : stores[n]) };
global.setInterval = () => 0; global.clearInterval = () => {}; global.setTimeout = () => 0;
let status = 'running';
global.fetch = async (url) => { calls.push(url);
  if (url.startsWith('/api/upgrade/active')) return { ok: true, json: async () => ({}) };
  return { ok: true, status: 200, json: async () => ({ total: 450,
           runs: [{ id: 'r1', status, progress: 5, updated_at: 'u', error_count: 0, logs_never: 1 }] }) }; };
eval(fs.readFileSync(process.env.WF_JS, 'utf8'));
handlers['alpine:init']();
const w = stores.workflows;
(async () => {
  await w.load();
  const first = w.runs;
  await w.load();
  const same = w.runs === first;            // unchanged poll: no reassignment
  status = 'completed';
  await w.load();
  const changed = w.runs !== first && w.runs[0].status === 'completed';
  w.typeFilter = 'timesketch'; w.applyFilter(); await new Promise(r => setImmediate(r));
  w.showMore(); await new Promise(r => setImmediate(r));
  console.log(JSON.stringify({ calls: calls.filter(c => c.startsWith('/api/dashboard')), same, changed,
                               total: w.total, limit: w.limit }));
})();
"""


class Page(unittest.TestCase):

    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_the_store_pages_filters_server_side_and_skips_unchanged_polls(self):
        out = subprocess.run(["node", "-e", PAGE], capture_output=True, text=True,
                             env={**os.environ, "WF_JS": WF_JS})
        self.assertEqual(out.returncode, 0, out.stderr[-2000:])
        got = json.loads(out.stdout.strip().splitlines()[-1])
        self.assertEqual(got["calls"], [
            "/api/dashboard/automations?limit=200",
            "/api/dashboard/automations?limit=200",
            "/api/dashboard/automations?limit=200",
            "/api/dashboard/automations?limit=200&type=timesketch",
            "/api/dashboard/automations?limit=400&type=timesketch",
        ])
        self.assertTrue(got["same"], "an unchanged poll must not re-render the table")
        self.assertTrue(got["changed"])
        self.assertEqual((got["total"], got["limit"]), (450, 400))

    def test_the_list_polls_every_5s_not_every_second(self):
        with open(APP_JS, encoding="utf-8") as fh:
            src = fh.read()
        block = src[src.index("Alpine.store('workflows').load();\n            }"):][:120]
        self.assertIn("}, 5000);", block)


if __name__ == "__main__":
    unittest.main()
