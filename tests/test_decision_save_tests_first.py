"""Saving the decision model tests it first, and asks before saving one that fails.

A model OpenRouter does not serve (perplexity/pplx-decider-v1.1-27b, "No endpoints
found") saved without a word, and every fuse after got no suggestions -- while the
answers of the previous model vanished from the case, since answers only show for
the model that gave them. Runs the REAL settings.js store in node, with fetch and
confirm faked.
"""
import json
import os
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORE = os.path.join(ROOT, "modules/nginx/html/js/stores/settings.js")

HARNESS = r"""
const fs = require('fs');
let store = null, init = null;
global.Alpine = { store: (name, obj) => { if (name === 'settings') store = obj; } };
global.document = { addEventListener: (ev, fn) => { if (ev === 'alpine:init') init = fn; } };
global.window = {}; global.localStorage = { getItem: () => null, setItem: () => {} };
eval(fs.readFileSync(process.argv[1], 'utf8'));
if (init) init();
const sc = JSON.parse(process.argv[2]);
const calls = [], asked = [];
global.confirm = (m) => { asked.push(m); return sc.confirm; };
global.fetch = async (url, opt) => {
  calls.push((opt && opt.method || 'GET') + ' ' + url);
  if (url.includes('/decision_model/test'))
    return { ok: true, json: async () => sc.test };
  return { ok: true, json: async () => ({}) };
};
store.showMessage = () => {};
store.config = { agentic: { decision_model: { enabled: sc.enabled, model: 'x/y' }, online_llm: {} } };
store.saveDecisionModel().then(() => {
  console.log(JSON.stringify({ saved: calls.some(c => c.startsWith('PUT /api/config')),
                               tested: calls.some(c => c.includes('/test')), asked }));
});
"""


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class SaveTestsFirst(unittest.TestCase):
    def run_store(self, **sc):
        out = subprocess.run(["node", "-e", HARNESS, STORE, json.dumps(sc)],
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(0, out.returncode, out.stderr)
        return json.loads(out.stdout.strip().splitlines()[-1])

    def test_a_working_model_saves_without_asking(self):
        r = self.run_store(enabled=True, confirm=False, test={"success": True, "p": 0.9})
        self.assertTrue(r["tested"]); self.assertTrue(r["saved"]); self.assertEqual([], r["asked"])

    def test_a_failing_model_asks_with_the_reason_and_cancel_keeps_the_old_settings(self):
        why = "HTTP 404: No endpoints found for perplexity/pplx-decider-v1.1-27b."
        r = self.run_store(enabled=True, confirm=False,
                           test={"success": False, "error": why, "model": "perplexity/pplx-decider-v1.1-27b"})
        self.assertFalse(r["saved"])
        self.assertEqual(1, len(r["asked"]))
        self.assertIn(why, r["asked"][0])

    def test_confirming_saves_anyway(self):
        r = self.run_store(enabled=True, confirm=True, test={"success": False, "error": "unreachable (ConnectionError)"})
        self.assertTrue(r["saved"])

    def test_switched_off_saves_without_testing(self):
        r = self.run_store(enabled=False, confirm=False, test={"success": False, "error": "x"})
        self.assertFalse(r["tested"]); self.assertTrue(r["saved"])


if __name__ == "__main__":
    unittest.main()
