"""Leaving an iframe tab and coming back reloads it -- Case Analysis AND Case Management.

"After purge, Case Management still lists the cases until I refresh": both tabs are
iframes that keep whatever they loaded first, and only Case Analysis was reloaded on
re-entry. Runs the REAL switchTab from js/stores/app.js in node with a stub DOM.
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
const reloads = [];
const frames = {};
for (const id of ['analysis-frame', 'cases-frame'])
  frames[id] = { id, src: id, contentWindow: { location: { reload: () => reloads.push(id) } } };
const handlers = {};
const el = () => ({ style: {}, classList: { add(){}, remove(){} }, textContent: '', innerHTML: '', value: '' });
global.window = global;
global.location = { hostname: 'box', hash: '' };
global.localStorage = { getItem: () => null, setItem(){} };
global.sessionStorage = global.localStorage;
global.CustomEvent = function (t, o) { this.type = t; this.detail = o && o.detail; };
global.dispatchEvent = () => true;
global.document = { addEventListener: (t, f) => { handlers[t] = f; }, getElementById: id => frames[id] || null,
                    querySelectorAll: () => [], querySelector: () => null, createElement: el };
const stores = {};
global.Alpine = { store: (n, o) => (o ? (stores[n] = o) : stores[n] || { load(){} }) };
for (const f of ['populateTimeSketchClients', 'loadTimesketchBlueprintsDropdown', 'initBlueprints']) global[f] = () => {};
eval(fs.readFileSync(process.env.APP_JS, 'utf8'));
handlers['alpine:init']();
const app = stores.app;
const seq = [];
for (const t of ['cases', 'dashboard', 'cases', 'case-analysis', 'cases', 'case-analysis']) {
  const n = reloads.length; app.switchTab(t); seq.push([t, reloads.slice(n)]);
}
console.log(JSON.stringify(seq));
"""


class IframeTabsReload(unittest.TestCase):
    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_case_management_and_analysis_reload_on_every_re_entry(self):
        out = subprocess.run(["node", "-e", DRIVER], capture_output=True, text=True,
                             env={**os.environ, "APP_JS": APP})
        self.assertEqual(out.returncode, 0, out.stderr[-2000:])
        seq = json.loads(out.stdout.strip().splitlines()[-1])
        self.assertEqual(seq, [["cases", []],                           # first entry: already loading
                               ["dashboard", []],
                               ["cases", ["cases-frame"]],              # came back: fresh case list
                               ["case-analysis", []],                   # its own first entry
                               ["cases", ["cases-frame"]],
                               ["case-analysis", ["analysis-frame"]]])


if __name__ == "__main__":
    unittest.main()
