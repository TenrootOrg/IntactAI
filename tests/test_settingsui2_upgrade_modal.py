"""Upgrade-modal regressions (QA group "settingsui2").

F3  A plan (or release list) reply that landed after the operator picked a
    different release overwrote the table with the old release's plan.
G5  The "Package Ready" view and its flags were never reachable; the real
    flow closes the modal and sends the operator to Workflows.

Runs the REAL settings store in node with Alpine, fetch and timers faked.
"""
import json
import os
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGE = os.path.join(ROOT, "modules/nginx/html")

SCRIPT = r"""
const fs = require('fs');
const stores = {}; let init = null;
global.Alpine = { store: (n, o) => (o === undefined ? stores[n] : (stores[n] = o)) };
global.document = { hidden: false, addEventListener: (ev, fn) => { if (ev === 'alpine:init') init = fn; } };
let redirected = 0;
global.window = { dispatchEvent: () => {}, ActiveCase: { gotoSystemWorkflows: () => { redirected++; } } };
global.CustomEvent = function () {};
global.localStorage = { getItem: () => null, setItem: () => {} };
global.console.error = () => {}; global.console.log = () => {};
global.setInterval = () => 1; global.clearInterval = () => {};
global.setTimeout = (fn) => { fn(); return 1; };
eval(fs.readFileSync(process.argv[1], 'utf8'));
if (init) init();
const s = stores.settings, out = {};
const tick = () => new Promise(r => setImmediate(r));
const pending = [];
global.fetch = (url, opt) => new Promise(res => pending.push({ url, body: opt && opt.body, res }));
const reply = (p, body) => p.res({ ok: true, json: async () => body });
(async () => {
  s.prepareModalMode = 'online';
  // F3: pick A, then B; A's reply lands last.
  s.selectedRef = 'A'; const a = s.onSelectedRefChange(); await tick();
  s.selectedRef = 'B'; const b = s.onSelectedRefChange(); await tick();
  reply(pending[1], { success: true, plan: { target: 'B', forced: [], optional: [] } }); await b;
  reply(pending[0], { success: true, plan: { target: 'A', forced: [], optional: [] } }); await a;
  out.plan = s.upgradePlan && s.upgradePlan.target;
  out.computing = s.computingPlan;
  out.planBodies = pending.slice(0, 2).map(p => JSON.parse(p.body).target);

  // F3: two release-list fetches (modal reopened mid-fetch); the first lands last.
  pending.length = 0;
  const r1 = s.fetchUpgradeRefs(); await tick();
  const r2 = s.fetchUpgradeRefs(); await tick();
  reply(pending[1], { success: true, refs: [{ name: 'new' }] }); await r2;
  s.selectedRef = 'new';
  reply(pending[0], { success: true, refs: [{ name: 'old' }] }); await r1;
  out.refs = s.upgradeRefs.map(r => r.name);
  out.refSel = s.selectedRef;
  out.fetching = s.fetchingRefs;

  // G5: Start still closes the modal and redirects to Workflows.
  global.fetch = async () => ({ ok: true, json: async () => ({ success: true, run_id: 'r1' }) });
  s.prepareModalMode = 'prepare'; s.showPreparePackageModal = true;
  await s.startTrackUpgrade();
  out.modal = s.showPreparePackageModal;
  out.redirected = redirected;
  out.loading = s.prepareLoading;
  console.info(JSON.stringify(out));
})().catch(e => { console.info(JSON.stringify({ crash: String(e.stack) })); });
"""

DEAD = ("preparePackageReady", "preparePackageSize", "showingPrepareModules",
        "downloadPreparedPackage", "Package Ready")


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class UpgradeModalStore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        r = subprocess.run(["node", "-e", SCRIPT, os.path.join(PAGE, "js/stores/settings.js")],
                           capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, r.stderr
        cls.got = json.loads(r.stdout.strip().splitlines()[-1])

    def test_no_crash(self):
        self.assertNotIn("crash", self.got)

    def test_f3_stale_plan_dropped(self):
        self.assertEqual(self.got["planBodies"], ["A", "B"])
        self.assertEqual(self.got["plan"], "B")
        self.assertFalse(self.got["computing"])

    def test_f3_stale_refs_dropped(self):
        self.assertEqual(self.got["refs"], ["new"])
        self.assertEqual(self.got["refSel"], "new", "late reply must not clear the pick")
        self.assertFalse(self.got["fetching"])

    def test_g5_start_redirects_to_workflows(self):
        self.assertFalse(self.got["modal"])
        self.assertEqual(self.got["redirected"], 1)
        self.assertFalse(self.got["loading"])


class DeadViewGone(unittest.TestCase):
    def test_g5_no_package_ready_leftovers(self):
        for rel in ("js/stores/settings.js", "partials/settings.html"):
            with open(os.path.join(PAGE, rel), encoding="utf-8") as f:
                src = f.read()
            for name in DEAD:
                self.assertNotIn(name, src, rel)


if __name__ == "__main__":
    unittest.main()
