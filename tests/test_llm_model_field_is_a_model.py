"""Test connection on search text says it is not a model, before calling the provider.

"gem" typed into the AI-model picker and tested as is came back "The provider does
not offer the selected model" (2026-10-21) -- the field held the search, not a pick
from the list. Runs the REAL settings.js store in node with fetch faked.
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
const calls = [];
global.fetch = async (url, opt) => {
  calls.push((opt && opt.method || 'GET') + ' ' + url);
  if (url.includes('/models?')) return { ok: true, json: async () => ({ models: sc.catalog }) };
  if (url.includes('/llm/test')) return { ok: true, json: async () => ({ success: true }) };
  return { ok: true, json: async () => ({}) };
};
store.config = { agentic: { llm_mode: 'online', online_llm: { provider: 'openrouter', model: sc.model, api_key: 'k' } } };
store.testLlmConnection().then(() => {
  console.log(JSON.stringify({ result: store.llmTestResult, tested: calls.some(c => c.includes('/llm/test')) }));
});
"""

GEMINI = [{"id": "google/gemini-4-argon"}, {"id": "google/gemini-3.8-flash"},
          {"id": "google/gemini-3.5-flash"}, {"id": "google/gemini-3-pro-image"}]


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class ModelFieldIsAModel(unittest.TestCase):
    def run_store(self, **sc):
        out = subprocess.run(["node", "-e", HARNESS, STORE, json.dumps(sc)],
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(0, out.returncode, out.stderr)
        return json.loads(out.stdout.strip().splitlines()[-1])

    def test_search_text_is_named_with_the_closest_models_and_not_sent(self):
        got = self.run_store(model="gem", catalog=GEMINI)
        self.assertFalse(got["tested"], "no call to the provider with a model that is not one")
        self.assertFalse(got["result"]["success"])
        self.assertIn('"gem" is not a model name', got["result"]["error"])
        self.assertIn("google/gemini-4-argon", got["result"]["error"])

    def test_a_real_model_id_is_tested(self):
        got = self.run_store(model="google/gemini-3.5-flash", catalog=GEMINI)
        self.assertTrue(got["tested"])
        self.assertTrue(got["result"]["success"])

    def test_no_catalog_cannot_judge_so_it_tests(self):
        self.assertTrue(self.run_store(model="my-local-model", catalog=[])["tested"])

    def test_blank_is_the_plan_default_and_is_tested(self):
        self.assertTrue(self.run_store(model="", catalog=GEMINI)["tested"])


if __name__ == "__main__":
    unittest.main()
