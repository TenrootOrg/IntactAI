"""The run log window's poller state machine (QA F1).

- Two opens of one run at once (double-click, two reattachToActiveRun() after
  the mid-upgrade sign-out) started two pollers; every new line showed twice
  and the extra interval was never cleared.
- After Stop, a poll sent before the stop landed with 'running' and flipped the
  header CANCELLED -> RUNNING -> CANCELLED.
- A finished run was polled once a second for as long as the window was open.
  Re-collect logs into a completed run, so its window keeps following.

Drives the REAL js/stores/workflows.js in node with a stub Alpine/DOM.
"""

import json
import os
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WF_JS = os.path.join(ROOT, "modules/nginx/html/js/stores/workflows.js")

PAGE = r"""
const fs = require('fs');
const handlers = {}, stores = {}, calls = [];
global.window = global;
global.document = { hidden: false, addEventListener: (t, f) => { handlers[t] = f; }, getElementById: () => null,
                    createElement: () => ({}) };
global.Alpine = { store: (n, o) => (o ? (stores[n] = o) : stores[n]) };
global.confirm = () => true;
const timers = [];
global.setInterval = (f) => { timers.push(f); return timers.length; };
global.clearInterval = (i) => { if (i) timers[i - 1] = null; };
global.setTimeout = () => 0;
// Responses by URL kind, so two racing pollers each get a sane answer.
let state = { status: 'running', lines: ['a', 'b'] };
global.fetch = async (url) => {
  calls.push(url);
  await new Promise(r => setImmediate(r));
  if (url.endsWith('/stop')) { state.status = 'cancelled'; return { ok: true, json: async () => ({}) }; }
  if (url.startsWith('/api/dashboard/automations')) return { ok: true, json: async () => ({ runs: [] }) };
  const m = /since=(\d+)/.exec(url), since = m ? +m[1] : 0;
  const all = state.lines.map((x, i) => ({ timestamp: 't', level: 'info', message: x, i }));
  const logs = m ? all.slice(since) : all;
  return { ok: true, json: async () => ({ status: state.status, progress: 0, cursor: all.length, logs }) };
};
eval(fs.readFileSync(process.env.WF_JS, 'utf8'));
handlers['alpine:init']();
const w = stores.workflows;
const live = () => timers.filter(Boolean).length;
const tick = async () => { for (const t of timers.slice()) if (t) await t(); };
(async () => {
  const out = {};
  // 1. Two opens without awaiting.
  await Promise.all([w.viewLogs('r1'), w.viewLogs('r1')]);
  out.liveAfterDouble = live();
  state.lines.push('c');
  await tick(); await tick();
  out.lines = w.selectedRun.logs.map(l => l.message);

  // 2. Stop, then a poll that was sent before it answers 'running'.
  await w.stopWorkflow('r1');                     // sets cancelled on the window
  state.status = 'running';                       // a poll sent before the stop answers late
  await tick();
  out.afterStalePoll = w.selectedRun.status;

  // 3. Terminal: polling stops after a few quiet polls.
  state.status = 'cancelled';
  for (let i = 0; i < 10; i++) await tick();
  out.liveAfterTerminal = live();

  // 4. Re-collect window keeps following a completed run.
  w.closeModal();
  state = { status: 'completed', lines: ['x'] };
  await w.viewLogs('r2', { follow: true });
  for (let i = 0; i < 10; i++) await tick();
  out.liveFollow = live();
  state.lines.push('y');
  await tick();
  out.followLines = w.selectedRun.logs.map(l => l.message);
  w.closeModal();
  out.liveAfterClose = live();
  console.log(JSON.stringify(out));
})();
"""


class Poller(unittest.TestCase):

    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_poller_states(self):
        out = subprocess.run(["node", "-e", PAGE], capture_output=True, text=True,
                             env={**os.environ, "WF_JS": WF_JS})
        self.assertEqual(out.returncode, 0, out.stderr[-2000:])
        got = json.loads(out.stdout.strip().splitlines()[-1])
        self.assertEqual(got["liveAfterDouble"], 1, "two opens must leave one poller")
        self.assertEqual(got["lines"], ["a", "b", "c"], "each line once")
        self.assertEqual(got["afterStalePoll"], "cancelled", "optimistic cancel must not flip back")
        self.assertEqual(got["liveAfterTerminal"], 0, "a finished run stops polling")
        self.assertEqual(got["liveFollow"], 1, "a re-collect window keeps following")
        self.assertEqual(got["followLines"], ["x", "y"])
        self.assertEqual(got["liveAfterClose"], 0)


if __name__ == "__main__":
    unittest.main()
