"""A run's log window follows the run with a cursor (fleet F29).

It refetched the WHOLE run every second, JSON.stringify-compared the arrays and
replaced selectedRun, re-rendering an x-for/x-html over a fleet run's 3k-10k
lines -- the tab froze. Now: the first read is the last N lines, each poll asks
GET /api/dashboard/automation/<id>/logs?since=<cursor> for new lines only,
appends them and keeps the last N -- the viewSystemLog() pattern.

Backend: real SQLite in a temp dir and the real route with a stand-in `flask`.
Page: the REAL js/stores/workflows.js in node with a stub Alpine/DOM.
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

os.environ["INTACT_STORAGE_BASE"] = tempfile.mkdtemp(prefix="intact-wflogwin-")
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
from services.storage import get_connection, init_storage  # noqa: E402

init_storage()
import services.workflow_service as ws  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "dashboard_routes_under_test", os.path.join(ROOT, "modules/backend/routes/dashboard_routes.py"))
dashboard_routes = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dashboard_routes)

WF_JS = os.path.join(ROOT, "modules/nginx/html/js/stores/workflows.js")


def _get(run_id, **args):
    flask_mod = sys.modules["flask"]
    with mock.patch.object(flask_mod, "request",
                           types.SimpleNamespace(args={k: str(v) for k, v in args.items()})):
        return dashboard_routes.get_automation_logs(run_id)


class Endpoint(unittest.TestCase):

    def setUp(self):
        self.rid = "velociraptor_collection_1700000000009"
        conn = get_connection()
        conn.execute("DELETE FROM workflows WHERE run_id = ?", (self.rid,))
        conn.execute("DELETE FROM workflow_logs WHERE run_id = ?", (self.rid,))
        # Written by an earlier version: one line embedded in the row.
        conn.execute(
            "INSERT INTO workflows (run_id, automation_type, name, status, progress, logs) "
            "VALUES (?, 'velociraptor_collection', 'the run', 'running', 40, ?)",
            (self.rid, json.dumps([{"timestamp": "t0", "level": "info", "message": "old"}])))
        conn.commit()
        for i in range(4):
            ws.add_log_to_run(self.rid, f"n{i}")

    def test_no_parameters_is_the_whole_log_as_before(self):
        body = _get(self.rid)
        self.assertEqual([l["message"] for l in body["logs"]], ["old", "n0", "n1", "n2", "n3"])
        self.assertEqual((body["status"], body["progress"], body["name"]), ("running", 40, "the run"))

    def test_tail_then_only_new_lines(self):
        tail = _get(self.rid, limit=2)
        self.assertEqual([l["message"] for l in tail["logs"]], ["n2", "n3"])
        self.assertTrue(tail["truncated"])
        self.assertEqual(_get(self.rid, since=tail["cursor"])["logs"], [])
        ws.add_log_to_run(self.rid, "n4")
        nxt = _get(self.rid, since=tail["cursor"])
        self.assertEqual([l["message"] for l in nxt["logs"]], ["n4"])

    def test_bad_numbers_are_refused(self):
        self.assertEqual(_get(self.rid, since="abc")[1], 400)

    def test_unknown_run_is_404(self):
        self.assertEqual(_get("nope_1")[1], 404)


PAGE = r"""
const fs = require('fs');
const handlers = {}, stores = {}, calls = [];
global.window = global;
global.document = { hidden: false, addEventListener: (t, f) => { handlers[t] = f; }, getElementById: () => null,
                    createElement: () => ({}) };
global.Alpine = { store: (n, o) => (o ? (stores[n] = o) : stores[n]) };
const timers = [];
global.setInterval = (f) => { timers.push(f); return timers.length; };
global.clearInterval = (i) => { timers[i - 1] = null; };
global.setTimeout = () => 0;
const script = [];   // queued responses
global.fetch = async (url) => { calls.push(url); const r = script.shift();
  if (r instanceof Error) throw r;
  return { ok: r.ok !== false, status: r.status || 200, json: async () => r.body }; };
const line = m => ({ timestamp: 't', level: 'info', message: m });
eval(fs.readFileSync(process.env.WF_JS, 'utf8'));
handlers['alpine:init']();
const w = stores.workflows;
w.RUN_LOG_KEEP = 3;
const tick = async () => { for (const t of timers) if (t) await t(); };
(async () => {
  const out = {};
  script.push({ body: { status: 'running', progress: 10, cursor: 7, truncated: true, name: 'R',
                        logs: [line('a'), line('b'), line('c')] } });
  await w.viewLogs('run_1');
  out.first = w.selectedRun.logs.map(l => l.message);
  out.truncatedShown = w.selectedRun.truncated;
  script.push({ body: { status: 'running', progress: 20, cursor: 9, logs: [line('d'), line('e')] } });
  await tick();
  out.appended = w.selectedRun.logs.map(l => l.message);
  out.progress = w.selectedRun.progress;
  const before = w.selectedRun;
  script.push({ body: { status: 'running', progress: 20, cursor: 9, logs: [] } });
  await tick();
  out.unchangedKept = w.selectedRun === before;
  script.push({ ok: false, status: 502, body: {} });
  await tick();
  out.reconnecting = w.selectedRun.reconnecting;
  script.push({ body: { status: 'completed', progress: 100, cursor: 9, logs: [] } });
  await tick();
  out.recovered = !w.selectedRun.reconnecting && w.selectedRun.status === 'completed';
  w.closeModal(); await tick();
  out.liveAfterClose = timers.filter(Boolean).length;
  // A bad id: the first read fails -> an error, and no polling at all.
  script.push({ ok: false, status: 404, body: { error: 'Automation run x not found' } });
  await w.viewLogs('x');
  out.fetchError = w.selectedRun.fetchError;
  out.liveAfter404 = timers.filter(Boolean).length;
  // A backend from before log paging (mid-upgrade): no cursor, whole log each poll.
  w.closeModal(); await tick();
  script.push({ body: { status: 'running', progress: 5, logs: [line('x'), line('y')] } });
  await w.viewLogs('old');
  script.push({ body: { status: 'running', progress: 6, logs: [line('x'), line('y')] } });
  await tick();
  out.oldBackend = w.selectedRun.logs.map(l => l.message);
  out.calls = calls;
  console.log(JSON.stringify(out));
})();
"""


class Page(unittest.TestCase):

    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_the_window_reads_a_tail_then_appends_new_lines_only(self):
        out = subprocess.run(["node", "-e", PAGE], capture_output=True, text=True,
                             env={**os.environ, "WF_JS": WF_JS})
        self.assertEqual(out.returncode, 0, out.stderr[-2000:])
        got = json.loads(out.stdout.strip().splitlines()[-1])
        self.assertEqual(got["calls"][:2], ["/api/dashboard/automation/run_1/logs?limit=3",
                                            "/api/dashboard/automation/run_1/logs?since=7&limit=3"])
        self.assertTrue(all("since=9" in c for c in got["calls"][2:5]), got["calls"])
        self.assertEqual(got["first"], ["a", "b", "c"])
        self.assertTrue(got["truncatedShown"])
        self.assertEqual(got["appended"], ["c", "d", "e"], "appended, keeping the last N")
        self.assertEqual(got["progress"], 20)
        self.assertTrue(got["unchangedKept"], "a poll with nothing new must not re-render")
        self.assertTrue(got["reconnecting"])
        self.assertEqual(got["oldBackend"], ["x", "y"], "a cursorless backend's full log replaces, never repeats")
        self.assertTrue(got["recovered"])
        self.assertEqual(got["liveAfterClose"], 0)
        self.assertEqual(got["fetchError"], "Automation run x not found")
        self.assertEqual(got["liveAfter404"], 0)


if __name__ == "__main__":
    unittest.main()
