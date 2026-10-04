"""Settings -> Logs: each container's log, live, in the dashboard's own log viewer.

Backend: docker's timestamps become a cursor that never repeats a line, secrets
are masked as in a support bundle, and only listed containers can be read.
Page: the real workflows.js viewer reads the last lines once, then only new
ones; it does not poll while the browser tab is hidden or after it is closed,
and a running container gets no Stop button.
"""
import json
import os
import shutil
import subprocess
import sys
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_HERE, os.path.join(_ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services import live_logs  # noqa: E402

OUT = ("2026-10-04T07:16:24.1Z first\n"
       "2026-10-04T07:16:24.123456789Z Traceback (most recent call last):\n"
       "not a docker line\n"
       "2026-10-04T07:16:25Z WARNING disk low\n"
       "2026-10-04T07:16:26.5Z admin password: hunter2xyz set\n")


class Parse(unittest.TestCase):
    def test_entries_levels_and_cursor(self):
        logs, cur = live_logs.parse(OUT)
        self.assertEqual([l["level"] for l in logs], ["info", "error", "warning", "info"])
        self.assertEqual(logs[0]["timestamp"], "2026-10-04T07:16:24.100000000Z")   # nine digits
        self.assertEqual(cur, "2026-10-04T07:16:26.500000000Z")
        self.assertNotIn("hunter2xyz", logs[3]["message"])                           # masked like a bundle

    def test_the_cursor_line_is_not_repeated(self):
        # --since is inclusive and docker trims zeros: '24.1Z' must sort before '24.123Z'
        logs, cur = live_logs.parse(OUT, "2026-10-04T07:16:24.100000000Z")
        self.assertEqual(logs[0]["message"], "Traceback (most recent call last):")
        self.assertEqual(live_logs.parse(OUT, cur), ([], cur))                       # nothing new


class Read(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(live_logs, "sources", lambda: [{"id": "intact_backend", "name": "intact_backend",
                                                              "state": "running", "status": "Up"}])
        p.start()
        self.addCleanup(p.stop)

    def test_only_a_listed_container_is_read(self):
        with mock.patch.object(subprocess, "run") as run:
            self.assertIsNone(live_logs.read("../../etc/passwd"))
            self.assertIsNone(live_logs.download("intact_backend; rm -rf /"))
            run.assert_not_called()

    def test_a_poll_asks_docker_only_for_new_lines(self):
        done = mock.Mock(stdout=OUT.encode())
        with mock.patch.object(subprocess, "run", return_value=done) as run:
            first = live_logs.read("intact_backend")
            live_logs.read("intact_backend", first["cursor"])
        self.assertNotIn("--since", run.call_args_list[0][0][0])
        self.assertEqual(run.call_args_list[1][0][0][-3:], ["--since", first["cursor"], "intact_backend"])
        self.assertEqual((first["is_system_log"], first["status"], len(first["logs"])), (True, "running", 4))


VIEWER = r"""
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
let n = 0;
global.fetch = async (url) => { calls.push(url); n++;
  return { ok: true, status: 200, json: async () => ({ status: 'running', cursor: 'c' + n,
           logs: [{ timestamp: 't', level: 'info', message: 'line ' + n }] }) }; };
eval(fs.readFileSync(process.env.WF_JS, 'utf8'));
handlers['alpine:init']();
const w = stores.workflows;
(async () => {
  await w.viewSystemLog('intact_backend');
  const tick = async () => { for (const t of timers) if (t) await t(); };
  await tick();                                   // new lines only
  document.hidden = true; await tick();           // background tab: no request
  document.hidden = false;
  w.closeModal(); await tick();                   // closed: no request
  console.log(JSON.stringify({ calls, open: w.modalOpen, live: timers.filter(Boolean).length }));
})();
"""


class Viewer(unittest.TestCase):
    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_reads_once_then_new_lines_only_and_stops(self):
        js = os.path.join(_ROOT, "modules/nginx/html/js/stores/workflows.js")
        out = subprocess.run(["node", "-e", VIEWER], capture_output=True, text=True,
                             env={**os.environ, "WF_JS": js})
        self.assertEqual(out.returncode, 0, out.stderr[-2000:])
        got = json.loads(out.stdout.strip().splitlines()[-1])
        self.assertEqual(got["calls"], ["/api/system/logs/intact_backend",
                                        "/api/system/logs/intact_backend?since=c1"])
        self.assertEqual((got["open"], got["live"]), (False, 0))

    def test_the_modal_has_no_stop_for_a_container(self):
        with open(os.path.join(_ROOT, "modules/nginx/html/index.html"), encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("x-if=\"!$store.workflows.selectedRun?.is_system_log && ($store.workflows.selectedRun?.status === 'running'", src)
        self.assertIn('x-for="(log, i) in ($store.workflows.selectedRun?.logs || [])" :key="i"', src)


if __name__ == "__main__":
    unittest.main()
