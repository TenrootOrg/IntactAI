"""Cloud scan pages and the Memory panel: failures reach the operator, and the
Workflows reload is real.

- Azure /scan without a run_id used to just re-enable the button (AWS alerted).
- analyze-offline was never checked on either page, so a refused analysis still
  sent the operator to Workflows to watch an `uploaded` row that never moves.
- The AWS offline file input stayed live during an upload: a second pick started
  a second upload.
- memory.js called Alpine.store('workflows').refresh(), which does not exist
  (the store has load()), and carried a poller nothing ever started.

The real x-data methods / store are run in plain node with stubbed fetch, alert
and $store -- jsdom is not installed on most boxes, so the live-page harnesses skip.
"""

import json
import os
import re
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = os.path.join(ROOT, "modules/nginx/html")


def _read(rel):
    with open(os.path.join(HTML, rel), encoding="utf-8") as fh:
        return fh.read()


def _xdata(partial, marker):
    """The x-data object literal of the panel that defines `marker`."""
    src = _read(partial)
    for m in re.finditer(r'x-data="(\{.*?\})"\s*\n\s*x-init=', src, re.S):
        if marker in m.group(1):
            return m.group(1)
    raise AssertionError(f"{marker} not found in {partial}")


DRIVER = r"""
const [objSrc, method, responses] = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const out = { alerts: [], tabs: [], calls: [] };
let i = 0;
global.alert = m => out.alerts.push(String(m));
global.console.error = () => {};
global.cloudTimeFilter = () => ({ filter: {} });
global.FormData = class { append() {} };
global.fetch = async (url) => {
  out.calls.push(url);
  const r = responses[i++] || { status: 200, body: {} };
  return { ok: r.status < 400, status: r.status, statusText: 'x',
           json: async () => { if (typeof r.body === 'string') throw new SyntaxError('Unexpected token <'); return r.body; } };
};
global.$store = { app: { switchTab: t => out.tabs.push(t) } };
const o = eval('(' + objSrc + ')');
o.$store = global.$store;
Object.assign(o, { azureTargetUsers: '', azureTargetIPs: '', azureScopeMode: 'tenant',
                   awsRegions: ['us-east-1'], awsTargetPrincipals: '' });
const ev = { target: { files: [{}], value: 'x' } };
(async () => {
  await o[method](ev);
  out.running = o.azureRunning ?? o.awsRunning;
  process.stdout.write(JSON.stringify(out));
})();
"""


@unittest.skipUnless(shutil.which("node"), "node not installed")
class TestCloudFailuresAreShown(unittest.TestCase):

    def run_method(self, partial, method, responses):
        obj = _xdata(partial, f"async {method}(")
        p = subprocess.run(["node", "-e", DRIVER], input=json.dumps([obj, method, responses]),
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr)
        return json.loads(p.stdout)

    def test_azure_scan_refused_alerts(self):
        out = self.run_method("partials/azure.html", "startAzureScan",
                              [{"status": 500, "body": {"error": "graph down"}}])
        self.assertEqual(out["tabs"], [])
        self.assertTrue(any("graph down" in a for a in out["alerts"]), out)
        self.assertFalse(out["running"])

    def test_azure_scan_html_502_alerts(self):
        out = self.run_method("partials/azure.html", "startAzureScan",
                              [{"status": 502, "body": "<html>"}])
        self.assertEqual(out["tabs"], [])
        self.assertEqual(len(out["alerts"]), 1, out)

    def test_azure_scan_ok_switches(self):
        out = self.run_method("partials/azure.html", "startAzureScan",
                              [{"status": 200, "body": {"run_id": "r1"}}])
        self.assertEqual((out["tabs"], out["alerts"]), (["workflows"], []))

    def test_analyze_offline_refused_stays_and_alerts(self):
        for partial, method in (("partials/azure.html", "uploadAzureLogs"),
                                ("partials/aws.html", "uploadAwsLogs")):
            with self.subTest(partial):
                out = self.run_method(partial, method, [
                    {"status": 200, "body": {"run_id": "r1"}},
                    {"status": 400, "body": {"error": "no files in run"}}])
                self.assertTrue(out["calls"][1].endswith("/analyze-offline"), out)
                self.assertEqual(out["tabs"], [])
                self.assertTrue(any("no files in run" in a for a in out["alerts"]), out)
                self.assertFalse(out["running"])

    def test_analyze_offline_ok_switches(self):
        for partial, method in (("partials/azure.html", "uploadAzureLogs"),
                                ("partials/aws.html", "uploadAwsLogs")):
            with self.subTest(partial):
                out = self.run_method(partial, method, [
                    {"status": 200, "body": {"run_id": "r1"}}, {"status": 200, "body": {}}])
                self.assertEqual((out["tabs"], out["alerts"]), (["workflows"], []))

    def test_aws_offline_input_locked_while_running(self):
        tag = re.search(r'<input type="file" @change="uploadAwsLogs\(\$event\)"[^>]*>',
                        _read("partials/aws.html"), re.S)
        self.assertIsNotNone(tag)
        self.assertIn(':disabled="awsRunning"', tag.group(0))


MEMORY_DRIVER = r"""
const src = require('fs').readFileSync(process.argv[1], 'utf8');
const stores = {}, out = { loads: 0, tabs: [] };
let init, tusOpts;
global.document = { addEventListener: (e, f) => { if (e === 'alpine:init') init = f; } };
global.window = { addEventListener() {} };
global.TabReset = { arm() {} };
global.tus = {};
global.TusUploader = class { constructor(o) { tusOpts = o; } upload() {} };
global.Alpine = { store: (n, v) => (v === undefined ? stores[n] : (stores[n] = v)) };
eval(src);
init();
stores.workflows = { load: () => { out.loads++; } };      // no refresh(), like the real store
stores.app = { switchTab: t => out.tabs.push(t) };
const m = stores.memory;
m.uploadFile = { size: 1 };
m.startUpload();
out.afterStart = out.loads;
tusOpts.onSuccess();
out.afterSuccess = out.loads;
process.stdout.write(JSON.stringify(out));
"""


@unittest.skipUnless(shutil.which("node"), "node not installed")
class TestMemoryWorkflowsReload(unittest.TestCase):

    def test_no_dead_refresh_or_poller(self):
        src = _read("js/memory.js")
        self.assertNotIn(".refresh", src.replace("refreshClients", "").replace("refreshBlueprints", ""))
        for dead in ("_pollTimer", "_startPolling", "_stopPolling", "currentStatus", "currentProgress"):
            self.assertNotIn(dead, src)

    def test_upload_success_really_reloads_workflows(self):
        p = subprocess.run(["node", "-e", MEMORY_DRIVER, os.path.join(HTML, "js/memory.js")],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr)
        out = json.loads(p.stdout)
        self.assertEqual(out["tabs"], ["workflows"])
        self.assertEqual(out["afterSuccess"], out["afterStart"] + 1, out)


if __name__ == "__main__":
    unittest.main()
