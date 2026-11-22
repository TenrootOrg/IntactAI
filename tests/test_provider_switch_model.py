"""Switching the online AI provider never keeps the previous provider's model.

2026-11-22: Ollama Cloud was picked with an OpenRouter model still in the Model
field ("~google/gemini-flash-latest"). Before its key is saved, Ollama Cloud's
model list is empty, and an empty list left the old model in place: every call
then failed with 404 'model "~google/gemini-flash-latest" not found', which was
reported as "check the API key and the internet connection" -- the key was fine.
"""
import json
import os
import shutil
import subprocess
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.dirname(os.path.abspath(__file__)), os.path.join(_ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import llm_sim  # noqa: E402


class Classified(unittest.TestCase):
    def test_ollamas_model_not_found_is_a_model_problem_not_the_key(self):
        e = RuntimeError("NotFoundError: Error code: 404 - {'error': {'message': 'model "
                         "\"~google/gemini-flash-latest\" not found. Try glm-5.3-flash:cloud.', "
                         "'type': 'not_found_error'}}")
        self.assertEqual(llm_sim._classify_llm_error(e), "model_unsupported")
        self.assertIn("Choose a different model", llm_sim.classify_llm_failure(e)["fix"])
        # the others keep their answers
        self.assertEqual(llm_sim._classify_llm_error(RuntimeError("Error code: 401 - invalid api key")),
                         "invalid_key")
        self.assertEqual(llm_sim._classify_llm_error(RuntimeError("x is not a valid model ID")),
                         "model_unsupported")


_HARNESS = r"""
const fs = require('fs');
const src = fs.readFileSync(process.argv[1], 'utf8');
const i = src.indexOf('async onProviderChange() {');
let d = 0, j = src.indexOf('{', i);
for (; j < src.length; j++) { if (src[j] === '{') d++; else if (src[j] === '}' && --d === 0) break; }
const body = src.slice(src.indexOf('{', i) + 1, j);
const run = async (provider, list) => {
  global.fetch = async () => ({ json: async () => ({ models: list }) });
  global.window = { dispatchEvent() {} }; global.CustomEvent = function () {};
  const st = { config: { agentic: { online_llm: { provider, api_key: 'k', model: '~google/gemini-flash-latest' } } },
               _onlineKeyFor: () => 'k', isSubscription: () => false, cliStopPolling() {}, cliStartPolling() {} };
  await (new Function('return async function(){' + body + '}')()).call(st);
  return st.config.agentic.online_llm.model;
};
(async () => {
  console.log(JSON.stringify([
    await run('ollama-cloud', []),                                  // key not saved yet: empty list
    await run('ollama-cloud', [{ id: 'glm-5.3' }, { id: 'gpt-oss:120b' }]),
    await run('openrouter', []),                                    // empty list: its own default
    await run('openrouter', [{ id: 'x/y' }, { id: '~anthropic/claude-sonnet-latest' }]),
  ]));
})();
"""


class SettingsSwitch(unittest.TestCase):
    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_an_empty_list_clears_the_old_model(self):
        js = os.path.join(_ROOT, "modules/nginx/html/js/stores/settings.js")
        r = subprocess.run(["node", "-e", _HARNESS, js], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout),
                         ["", "glm-5.3", "~anthropic/claude-sonnet-latest", "~anthropic/claude-sonnet-latest"])


if __name__ == "__main__":
    unittest.main()
