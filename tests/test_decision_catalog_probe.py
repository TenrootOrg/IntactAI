"""Update catalog tries every decision model, and the picker says which can answer.

OpenRouter lists models this account cannot use (refused by its zero-data-retention
policy) and models with no endpoint at all. The picker offered all 21 alike; one was
saved, and every fuse after got nothing.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BACKEND = os.path.join(_ROOT, "modules/backend")
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)
for _pkg, _rel in (("services", "services"), ("services.fusion", "services/fusion")):
    if _pkg not in sys.modules:
        _m = types.ModuleType(_pkg)
        _m.__path__ = [os.path.join(_BACKEND, _rel)]
        sys.modules[_pkg] = _m
if "requests" not in sys.modules:
    sys.modules["requests"] = types.ModuleType("requests")
    sys.modules["requests"].post = None

from services.fusion import decision_model as dm  # noqa: E402


class _R:
    def __init__(self, status, body):
        self.status_code, self._b, self.text = status, body, json.dumps(body)

    def json(self):
        return self._b


OK = _R(200, {"answers": {"q0": {"type": "noul", "noul": 0.9}}})


class Probe(unittest.TestCase):
    def setUp(self):
        dm.retry_now()

    def probe(self, side_effect, model="v/m"):
        dm._TEXT_STATE.discard(model)
        with mock.patch.object(dm.requests, "post", side_effect=side_effect):
            return dm.probe_model(model, "k")

    def test_kinds(self):
        self.assertEqual("ok", self.probe([OK])["kind"])
        text_only = _R(400, {"error": {"message": "state must be a string or an object with only text, document"}})
        self.assertEqual("ok", self.probe([text_only, OK])["kind"])            # ScaleDown
        policy = _R(404, {"error": {"message": "0 endpoints ... matching your guardrail restrictions and data policy. "
                                               "ZDR violation (account settings)"}})
        p = self.probe([policy])
        self.assertEqual("policy", p["kind"]); self.assertIn("data policy", p["why"])
        gone = _R(404, {"error": {"message": "No endpoints found for perplexity/pplx-decider-v1.1-27b."}})
        self.assertEqual("not_served", self.probe([gone])["kind"])
        self.assertEqual("other", self.probe(OSError("no route"))["kind"])

    def test_a_probe_never_pauses_the_decision_model(self):
        self.probe(OSError("no route"))
        self.assertEqual("", dm.unavailable({"online_llm": {"provider": "openrouter", "api_key": "k"},
                                             "decision_model": {"enabled": True}}))

    def test_results_are_kept_and_shown_on_each_catalog_row(self):
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.object(dm, "PROBES_PATH", os.path.join(d, "p.json")), \
             mock.patch.object(dm, "probe_model", side_effect=lambda m, k: {"ok": m == "jev-latest", "kind": "ok" if m == "jev-latest" else "not_served", "why": ""}):
            counts = dm.probe_catalog("k")
            rows = {m["model"]: m for m in dm.catalog() if m["provider"] == "openrouter"}
        self.assertEqual(len(rows), sum(counts.values()))
        self.assertTrue(rows["jev-latest"]["probe"]["ok"])
        self.assertEqual("not_served", rows["cloudflare/clef"]["probe"]["kind"])


HARNESS = r"""
const fs = require('fs');
let store = null, init = null;
global.Alpine = { store: (n, o) => { if (n === 'settings') store = o; } };
global.document = { addEventListener: (e, f) => { if (e === 'alpine:init') init = f; } };
global.window = {}; global.localStorage = { getItem: () => null, setItem: () => {} };
eval(fs.readFileSync(process.argv[1], 'utf8')); if (init) init();
const rows = [
  { provider: 'openrouter', model: 'a', note: 'A', probe: { ok: true, kind: 'ok', why: '' } },
  { provider: 'openrouter', model: 'b', note: 'B', probe: { ok: false, kind: 'policy', why: 'HTTP 404: data policy' } },
  { provider: 'openrouter', model: 'c', note: 'C', probe: { ok: false, kind: 'not_served', why: 'HTTP 404: No endpoints' } },
  { provider: 'openrouter', model: 'd', note: 'D' } ];
store.decisionCatalog = { models: rows, providers: {} };
const out = {};
for (const m of rows) {
  store.config = { agentic: { decision_model: { provider: 'openrouter', model: m.model } } };
  out[m.model] = [store.decisionProbeMark(m), store.decisionProbeText()];
}
// Picker order: works, data policy, failed, untested -- catalog order inside each group.
store.decisionCatalog = { providers: {}, models: [rows[3], rows[2], rows[1], rows[0],
  { provider: 'openrouter', model: 'e', note: 'E', probe: { ok: true, kind: 'ok', why: '' } },
  { provider: 'openai', model: 'x', note: 'X' }] };
store.config = { agentic: { decision_model: { provider: 'openrouter', model: 'a' } } };
out.order = store.decisionModelsSorted().map(m => m.model);
console.log(JSON.stringify(out));
"""


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class PickerText(unittest.TestCase):
    def test_marks_and_reasons(self):
        store = os.path.join(_ROOT, "modules/nginx/html/js/stores/settings.js")
        r = subprocess.run(["node", "-e", HARNESS, store], capture_output=True, text=True, timeout=30)
        self.assertEqual(0, r.returncode, r.stderr)
        out = json.loads(r.stdout.strip().splitlines()[-1])
        self.assertEqual("✅ ", out["a"][0]); self.assertIn("Answered", out["a"][1])
        self.assertEqual("⚠️ ", out["b"][0]); self.assertIn("openrouter.ai/settings/privacy", out["b"][1])
        self.assertEqual("⛔ ", out["c"][0]); self.assertIn("Not served by OpenRouter", out["c"][1])
        self.assertEqual(["", ""], out["d"])                    # never tested: no mark, no line
        self.assertEqual(["a", "e", "b", "c", "d"], out["order"])   # green, yellow, red, untested


if __name__ == "__main__":
    unittest.main()
