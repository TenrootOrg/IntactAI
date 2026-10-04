"""Leaving an iframe tab and coming back refreshes it -- Case Analysis AND Case Management.

"After purge, Case Management still lists the cases until I refresh": both tabs are
iframes that keep whatever they loaded first, and only Case Analysis was reloaded on
re-entry. A reload of the whole frame on every visit was the Case Analysis lag
("very laggy"), so a page that offers refreshOnEntry() refreshes its data in place;
only one that does not is reloaded. Runs the REAL switchTab from js/stores/app.js in node with a stub DOM.
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
// cases-frame has loaded its page: it refreshes in place. analysis-frame has not (yet).
frames['cases-frame'].contentWindow.refreshOnEntry = () => reloads.push('refresh:cases-frame');
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
    def test_case_management_and_analysis_refresh_on_every_re_entry(self):
        out = subprocess.run(["node", "-e", DRIVER], capture_output=True, text=True,
                             env={**os.environ, "APP_JS": APP})
        self.assertEqual(out.returncode, 0, out.stderr[-2000:])
        seq = json.loads(out.stdout.strip().splitlines()[-1])
        self.assertEqual(seq, [["cases", []],                           # first entry: already loading
                               ["dashboard", []],
                               ["cases", ["refresh:cases-frame"]],      # came back: fresh case list, in place
                               ["case-analysis", []],                   # its own first entry
                               ["cases", ["refresh:cases-frame"]],
                               ["case-analysis", ["analysis-frame"]]])   # no hook: reloaded

    def test_the_page_offers_the_hook(self):
        src = open(os.path.join(ROOT, "modules/nginx/html/cases.html"), encoding="utf-8").read()
        hook = src[src.index("window.refreshOnEntry=async function(){"):]
        hook = hook[:hook.index("\n};") + 3]
        self.assertIn("ensureActiveCase()", hook)        # a purged case is left
        self.assertIn("loadCases()", hook)                # the list is fresh
        self.assertIn("return;   // unchanged", hook)     # no redraw when nothing changed


if __name__ == "__main__":
    unittest.main()
