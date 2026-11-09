"""Settings / services page-store regressions (QA group "settingsui").

F5  Settings pollers kept running after leaving Settings (Actions 1 s tick,
    codex detect every 3 s) and an older Velociraptor reply could land last.
G1  A multi-asset offline import uploaded only the first file: the file list
    was read after closeApplyPackageModal() had emptied it.
G2  Picking "Codex (Subscription)" threw on a deleted _cliStopLogin() call, so
    the detect poll never started.
F12 One failed /api/system/containers fetch marked every module not_installed
    and hid its sidebar entry and Settings tab.
G6  The dashboard status-dot classes had no CSS, so every service light was blank.

Runs the REAL store files in node with Alpine, fetch and timers faked.
"""
import json
import os
import re
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGE = os.path.join(ROOT, "modules/nginx/html")

PRELUDE = r"""
const fs = require('fs');
const stores = {}; let init = null;
global.Alpine = { store: (n, o) => (o === undefined ? stores[n] : (stores[n] = o)) };
global.document = { hidden: false, addEventListener: (ev, fn) => { if (ev === 'alpine:init') init = fn; } };
global.window = { dispatchEvent: () => {}, ActiveCase: { gotoSystemWorkflows: () => {} } };
global.CustomEvent = function () {};
global.localStorage = { getItem: () => null, setItem: () => {} };
global.console.error = () => {}; global.console.log = () => {};
global.setInterval = () => 1; global.clearInterval = () => {};
global.setTimeout = () => 1;
eval(fs.readFileSync(process.argv[1], 'utf8'));
if (init) init();
stores.app = { currentTab: 'settings' };
const calls = [];
const tick = () => new Promise(r => setImmediate(r));
"""

SETTINGS = PRELUDE + r"""
const s = stores.settings, out = {};
(async () => {
  // G2: switching to the subscription provider must not throw and must poll.
  global.fetch = async (url, opt) => { calls.push(url); return { ok: true, json: async () => ({}) }; };
  s.config.agentic.online_llm.provider = 'codex-subscription';
  try { await s.onProviderChange(); out.g2 = 'ok'; } catch (e) { out.g2 = String(e); }
  out.g2Status = calls.some(u => u.startsWith('/api/agentic/cli/status'));
  out.g2Models = calls.includes('/api/maintenance/refresh-codex-models');

  // F5: detect does nothing off Settings or in a hidden browser tab.
  calls.length = 0;
  stores.app.currentTab = 'dashboard'; await s.cliRefresh();
  stores.app.currentTab = 'settings'; document.hidden = true; await s.cliRefresh();
  document.hidden = false;
  out.cliOff = calls.length;
  await s.cliRefresh(); out.cliOn = calls.length;

  // F5: a slow, older Velociraptor reply must not overwrite a newer one.
  const pending = [];
  global.fetch = (url) => new Promise(res => pending.push({ url, res }));
  const first = s.loadVelociraptor(); await tick();
  const second = s.loadVelociraptor(); await tick();
  const reply = (p, body) => p.res({ ok: true, json: async () => body });
  reply(pending[1], { tag: 'new' }); await tick(); await tick();
  reply(pending.find(p => p.url.includes('upgrade-state') && p !== pending[0]), {}); await second;
  reply(pending[0], { tag: 'old' }); await first;
  out.velo = s.velo && s.velo.tag;
  out.veloLoading = s.veloLoading;

  // F5: a second Actions tick while the first is in flight is skipped.
  pending.length = 0;
  const a1 = s.loadActions(); const a2 = s.loadActions(); await a2;
  out.actionsFetches = pending.length;
  pending[0].res({ ok: true, json: async () => ({ actions: [{ id: 1 }] }) }); await a1;
  global.fetch = async () => ({ ok: true, json: async () => ({ actions: [] }) });
  await s.loadActions(); out.actionsAfter = 'ok';

  // G1: every selected asset is uploaded, and package_paths names them all.
  const uploaded = []; let n = 0;
  global.tus = { Upload: function (f, o) { this.start = () => { uploaded.push(f.name);
      this.url = '/api/uploads/id' + (++n); o.onSuccess(); }; } };
  let applyBody = null;
  global.fetch = async (url, opt) => {
    if (url === '/api/upgrade/offline') applyBody = JSON.parse(opt.body);
    return { ok: true, json: async () => ({ success: true, run_id: 'r1' }) };
  };
  const fa = { name: 'a.tar.gz', size: 1 }, fb = { name: 'b.tar.gz', size: 2 };
  s.applyPackage = { _localFile: fa, path: null };
  s.applyPackageFiles = [fa, fb];
  s.applyManifest = { versions: { backend: '2' } };
  s.applySelectedModules = ['backend'];
  await s.applyUploadedPackage();
  for (let i = 0; i < 5; i++) await tick();
  out.uploaded = uploaded;
  out.paths = applyBody && applyBody.package_paths;
  console.info(JSON.stringify(out));
})().catch(e => { console.info(JSON.stringify({ crash: String(e.stack) })); });
"""

SERVICES = PRELUDE + r"""
const sv = stores.services;
window.services = { velociraptor: {}, timesketch: {}, volweb: {} };
(async () => {
  global.fetch = async () => ({ ok: true, json: async () => ({ velociraptor: 'online', timesketch: 'stopped' }) });
  await sv.checkAll();
  global.fetch = async () => { throw new TypeError('Failed to fetch'); };
  await sv.checkAll();
  console.info(JSON.stringify({ statuses: sv.statuses, has: ['velociraptor', 'timesketch', 'volweb'].map(x => sv.has(x)),
                                fresh: (sv.statuses = {}, await sv.checkAll(), sv.statuses) }));
})();
"""


def run(script, rel):
    r = subprocess.run(["node", "-e", script, os.path.join(PAGE, rel)],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout.strip().splitlines()[-1])


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class SettingsStore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.got = run(SETTINGS, "js/stores/settings.js")

    def test_no_crash(self):
        self.assertNotIn("crash", self.got)

    def test_g2_codex_switch_starts_poll(self):
        self.assertEqual(self.got["g2"], "ok")
        self.assertTrue(self.got["g2Status"], "detect poll started")
        self.assertTrue(self.got["g2Models"], "catalog refresh posted")

    def test_f5_cli_detect_only_on_visible_settings(self):
        self.assertEqual(self.got["cliOff"], 0)
        self.assertEqual(self.got["cliOn"], 1)

    def test_f5_stale_velo_reply_dropped(self):
        self.assertEqual(self.got["velo"], "new")
        self.assertFalse(self.got["veloLoading"])

    def test_f5_actions_ticks_do_not_stack(self):
        self.assertEqual(self.got["actionsFetches"], 1)
        self.assertEqual(self.got["actionsAfter"], "ok", "busy flag released")

    def test_g1_all_assets_uploaded(self):
        self.assertEqual(self.got["uploaded"], ["a.tar.gz", "b.tar.gz"])
        self.assertEqual(self.got["paths"], ["/data/uploads/id1", "/data/uploads/id2"])


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class ServicesStore(unittest.TestCase):
    def test_f12_unreachable_keeps_last_statuses(self):
        got = run(SERVICES, "js/stores/services.js")
        self.assertEqual(got["statuses"], {"velociraptor": "online", "timesketch": "stopped",
                                           "volweb": "not_installed"})
        self.assertEqual(got["has"], [True, True, False])
        self.assertEqual(got["fresh"], {"velociraptor": "checking", "timesketch": "checking",
                                        "volweb": "checking"})


class PageSource(unittest.TestCase):
    def read(self, rel):
        with open(os.path.join(PAGE, rel), encoding="utf-8") as f:
            return f.read()

    def test_f5_settings_ticks_gated_on_the_settings_tab(self):
        html = self.read("partials/settings.html")
        for tab in ("actions", "velociraptor"):
            tick = re.search(r"setInterval\(\(\) => \{ if \(settingsTab === '%s'[^}]*\}" % tab, html)
            self.assertIsNotNone(tick, tab)
            self.assertIn("$store.app.currentTab === 'settings'", tick.group(0), tab)
            self.assertIn("!document.hidden", tick.group(0), tab)

    def test_g6_every_status_dot_has_a_colour(self):
        css = self.read("css/styles.css")
        for cls in ("online", "offline", "checking"):
            self.assertRegex(css, r"\.status-%s\s*\{[^}]*background" % cls)


if __name__ == "__main__":
    unittest.main()
