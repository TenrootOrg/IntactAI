"""The Timesketch client picker is not redrawn every 10 s (fleet F36, picker half).

On the Timesketch tab the 10 s services poll also called
populateTimeSketchClients(), redrawing a ~1,000-row picker under the operator --
scroll position and selection jumped. It loads when the tab opens and on its own
↻ button; the background poll leaves it alone. The Workflows list poll is 5 s.

Runs the REAL 'alpine:initialized' block of js/stores/app.js in node with stubs,
then fires every interval it registered while the Timesketch tab is open.
"""
import json
import os
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "modules/nginx/html/js/stores/app.js")

DRIVER = r"""
const fs = require('fs');
const handlers = {}, calls = [], intervals = [];
const el = () => ({ style: {}, classList: { add(){}, remove(){} }, textContent: '', innerHTML: '', value: '' });
global.window = global;
global.location = { hostname: 'box', hash: '' };
global.addEventListener = () => {};
global.localStorage = { getItem: () => null, setItem(){} };
global.sessionStorage = global.localStorage;
global.CustomEvent = function (t, o) { this.type = t; this.detail = o && o.detail; };
global.dispatchEvent = () => true;
global.document = { hidden: false, addEventListener: (t, f) => { handlers[t] = f; }, getElementById: () => null,
                    querySelectorAll: () => [], querySelector: () => null, createElement: el };
const stores = {
  services: { checkAll: () => calls.push('checkAll'), loadClients: () => calls.push('loadClients') },
  workflows: { load: () => calls.push('workflows.load') },
};
global.Alpine = { store: (n, o) => (o ? (stores[n] = o) : stores[n]) };
global.setInterval = (f, ms) => { intervals.push([f, ms]); return intervals.length; };
global.loadBlueprints = () => new Promise(() => {});
for (const f of ['populateBlueprintDropdown', 'loadTimesketchBlueprintsDropdown', 'initBlueprints'])
  global[f] = () => {};
global.populateTimeSketchClients = () => calls.push('populateTimeSketchClients');
eval(fs.readFileSync(process.env.APP_JS, 'utf8'));
handlers['alpine:init']();
handlers['alpine:initialized']();
stores.app.currentTab = 'modules-timesketch';
calls.length = 0;
for (const [f] of intervals) f();
const wf = intervals.find(([f]) => { const n = calls.length; stores.app.currentTab = 'workflows'; f();
                                     const hit = calls.slice(n).includes('workflows.load');
                                     stores.app.currentTab = 'modules-timesketch'; return hit; });
console.log(JSON.stringify({ calls, workflowsEvery: wf ? wf[1] : null }));
"""


class Picker(unittest.TestCase):
    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_no_background_redraw_of_the_picker(self):
        out = subprocess.run(["node", "-e", DRIVER], capture_output=True, text=True,
                             env={**os.environ, "APP_JS": APP})
        self.assertEqual(out.returncode, 0, out.stderr[-2000:])
        got = json.loads(out.stdout.strip().splitlines()[-1])
        self.assertIn("checkAll", got["calls"], "the services poll itself still runs")
        self.assertNotIn("populateTimeSketchClients", got["calls"])
        self.assertEqual(got["workflowsEvery"], 5000)


if __name__ == "__main__":
    unittest.main()
