"""Settings -> Agentic and Settings -> Timesketch share ONE OpenRouter key.

QA (2026-11): "enter openrouter api in agentic tab, move to timesketch: you
should enter it again". Each section kept its own copy and neither read the
other's. Now services/openrouter_key.py holds one shared key (in the secrets
table, outside export/import); the models stay per section.

Service logic runs against in-memory stores. The route helpers run with Flask
stubbed when it is missing (only undecorated helpers are called); the real
GET/PUT round-trip runs only where Flask exists. The page side runs the REAL
settings.js store in node with fetch faked.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(_HERE)
for _p in (_HERE, os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Importing services boots SQLite storage: a throwaway DB, never /app/data.
if "INTACT_STORAGE_BASE" not in os.environ:
    os.environ["INTACT_STORAGE_BASE"] = tempfile.mkdtemp(prefix="intact-orkey-")
    import atexit
    atexit.register(shutil.rmtree, os.environ["INTACT_STORAGE_BASE"], True)

import _optional_deps  # noqa: F401,E402

try:
    import flask  # noqa: F401
    HAVE_FLASK = True
except ImportError:
    HAVE_FLASK = False
    _optional_deps.stub("flask")        # route modules import it at the top

from services import openrouter_key as ok  # noqa: E402


def route(name):
    """Load one routes/ module by path: `import routes.x` runs routes/__init__.py,
    which imports every blueprint and their dependencies (werkzeug & co.)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "_route_" + name, os.path.join(ROOT, "modules/backend/routes", name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

TS_CONF_OPENROUTER = """LLM_PROVIDER_CONFIGS = {
    'nl2q': {
        'openrouter': {
            'api_key': '%s',
            'model': 'openai/gpt-4o-mini',
        },
    },
}
"""
TS_CONF_TEMPLATE = """LLM_PROVIDER_CONFIGS = {
    'nl2q': {
        'aistudio': {
            'model': 'gemini-2.5-flash',
            'api_key': '',
        },
    },
}
"""


class Fake:
    """secrets table + frontend_config + timesketch.conf, all in memory/tmp."""

    def __init__(self, agentic=None, conf=None):
        self.secrets = {}
        self.cfg = {"agentic": agentic} if agentic is not None else {}
        self.dir = tempfile.mkdtemp()
        self.conf = os.path.join(self.dir, "timesketch.conf")
        if conf is not None:
            with open(self.conf, "w") as f:
                f.write(conf)

    def __enter__(self):
        s = self.secrets
        self._p = [
            mock.patch.object(ok, "get_secret", lambda k: s.get(k) or None),
            mock.patch.object(ok, "set_secret", lambda k, v: s.__setitem__(k, v) or True),
            mock.patch.object(ok, "delete_secret", lambda k: s.pop(k, None) or True),
            mock.patch.object(ok, "load_frontend_config", lambda: json.loads(json.dumps(self.cfg))),
            mock.patch.object(ok, "save_frontend_config", lambda c: self.cfg.update(json.loads(json.dumps(c)))),
            mock.patch.object(ok, "TIMESKETCH_CONF", self.conf),
        ]
        for p in self._p:
            p.start()
        return self

    def __exit__(self, *a):
        for p in self._p:
            p.stop()
        shutil.rmtree(self.dir, ignore_errors=True)

    def online(self):
        return self.cfg["agentic"]["online_llm"]


def agentic(provider="openrouter", key=""):
    return {"llm_mode": "online", "online_llm": {"provider": provider, "api_key": key, "model": "m"}}


class SharedKeyService(unittest.TestCase):
    def test_agentic_key_is_the_timesketch_key(self):
        with Fake(agentic()) as f:
            self.assertEqual(ok.save("sk-or-agentic-1111"), "sk-or-agentic-1111")
            self.assertEqual(ok.get(), "sk-or-agentic-1111")
            self.assertEqual(f.secrets[ok.SECRET], "sk-or-agentic-1111")

    def test_masked_round_trip_keeps_the_shared_key(self):
        with Fake(agentic()):
            ok.save("sk-or-real-2222")
            self.assertEqual(ok.save(ok.mask("sk-or-real-2222")), "sk-or-real-2222")
            self.assertEqual(ok.save("••••••••"), "sk-or-real-2222")
            self.assertEqual(ok.get(), "sk-or-real-2222")
            self.assertEqual(ok.mask("sk-or-real-2222"), "••••••••2222")

    def test_timesketch_save_rotates_an_agentic_openrouter_key(self):
        with Fake(agentic(key="sk-or-old-0000")) as f:
            ok.save("sk-or-new-3333", from_timesketch=True)
            self.assertEqual(f.online()["api_key"], "sk-or-new-3333")
            self.assertEqual(f.online()["model"], "m", "the model is never shared")

    def test_timesketch_save_never_switches_case_analysis_ai_on(self):
        # Agentic had no key: filling it would start sending case data to the cloud.
        with Fake(agentic(key="")) as f:
            ok.save("sk-or-ts-4444", from_timesketch=True)
            self.assertEqual(f.online()["api_key"], "")
            self.assertEqual(ok.get(), "sk-or-ts-4444")

    def test_timesketch_save_leaves_another_vendors_key_alone(self):
        with Fake(agentic("claude", "sk-ant-5555")) as f:
            ok.save("sk-or-ts-6666", from_timesketch=True)
            self.assertEqual(f.online()["api_key"], "sk-ant-5555")

    def test_emptied_field_removes_the_key(self):
        with Fake(agentic(key="sk-or-x-7777")) as f:
            ok.get()
            self.assertEqual(ok.save("", from_timesketch=True), "")
            self.assertEqual(ok.get(), "")
            self.assertEqual(f.online()["api_key"], "")

    def test_old_box_with_agentic_key_only_is_adopted(self):
        with Fake(agentic(key="sk-or-ag-8888"), conf=TS_CONF_TEMPLATE):
            self.assertEqual(ok.get(), "sk-or-ag-8888")

    def test_old_box_with_timesketch_key_only_is_adopted(self):
        with Fake(agentic("claude", "sk-ant-x"), conf=TS_CONF_OPENROUTER % "sk-or-ts-9999"):
            self.assertEqual(ok.get(), "sk-or-ts-9999")

    def test_both_differ_agentic_wins(self):
        with Fake(agentic(key="sk-or-ag-aaaa"), conf=TS_CONF_OPENROUTER % "sk-or-ts-bbbb"):
            self.assertEqual(ok.get(), "sk-or-ag-aaaa")

    def test_removed_key_is_not_readopted_from_timesketch_conf(self):
        with Fake(agentic(), conf=TS_CONF_OPENROUTER % "sk-or-ts-cccc"):
            self.assertEqual(ok.get(), "sk-or-ts-cccc")
            ok.save("")
            self.assertEqual(ok.get(), "", "conf still holds it until Timesketch is saved")

    def test_a_mask_is_never_adopted_as_a_key(self):
        with Fake(agentic(key="••••••••dddd")):
            self.assertEqual(ok.get(), "")

    def test_no_llm_at_all_is_fine(self):
        with Fake() as f:                       # air-gapped: no config, no conf file
            self.assertEqual(ok.get(), "")
            self.assertNotIn(ok.SECRET, f.secrets)


class RouteHelpers(unittest.TestCase):
    def test_timesketch_defaults_to_openrouter_but_keeps_a_saved_provider(self):
        ts = route("timesketch_llm_routes")
        self.assertEqual(ts.DEFAULT_LLM_MODE, "openrouter")
        self.assertEqual(ts._detect_llm_mode(""), "openrouter")
        self.assertEqual(ts._detect_llm_mode(TS_CONF_TEMPLATE), "openrouter", "the shipped template is not a choice")
        google = TS_CONF_TEMPLATE.replace("'api_key': ''", "'api_key': 'AIzaSaved'")
        self.assertEqual(ts._detect_llm_mode(google), "google")
        ollama = "LLM_PROVIDER_CONFIGS = {\n    'nl2q': {\n        'ollama': {\n            'model': 'x',\n        },\n    },\n}\n"
        self.assertEqual(ts._detect_llm_mode(ollama), "ollama")

    def test_a_masked_key_never_goes_to_another_provider(self):
        cr = route("config_routes")
        with mock.patch.object(ok, "get", return_value="sk-or-shared"):
            self.assertEqual(cr._stored_online_key({"provider": "openrouter"}, {"provider": "claude", "api_key": "sk-ant"}),
                             "sk-or-shared")
        self.assertEqual(cr._stored_online_key({"provider": "claude"}, {"provider": "claude", "api_key": "sk-ant"}), "sk-ant")
        self.assertEqual(cr._stored_online_key({"provider": "claude"}, {"provider": "openrouter", "api_key": "sk-or"}), "")


@unittest.skipUnless(HAVE_FLASK, "needs Flask (the backend image has it)")
class RoundTrip(unittest.TestCase):
    def test_agentic_get_put_and_timesketch_get(self):
        import flask
        cr, ts = route("config_routes"), route("timesketch_llm_routes")
        with Fake(agentic(key=""), conf=TS_CONF_OPENROUTER % "sk-or-ts-eeee") as f:
            app = flask.Flask(__name__)
            app.register_blueprint(cr.config_bp)
            app.register_blueprint(ts.timesketch_llm_bp)
            saved = {}
            with mock.patch.object(cr, "load_frontend_config", lambda: json.loads(json.dumps(f.cfg))), \
                 mock.patch.object(cr, "save_frontend_config", side_effect=lambda c: saved.update(c)), \
                 mock.patch.object(ts, "TIMESKETCH_CONFIG_PATH", f.conf):
                c = app.test_client()
                got = c.get("/api/config").get_json()
                on = got["agentic"]["online_llm"]
                self.assertEqual(on["api_key"], "••••••••eeee", "Timesketch's key shows in Agentic")
                self.assertTrue(on["key_from_shared"])
                self.assertNotIn("sk-or-ts-eeee", json.dumps(got))
                self.assertEqual(c.put("/api/config", json=got).status_code, 200)
                self.assertEqual(saved["agentic"]["online_llm"]["api_key"], "sk-or-ts-eeee")
                self.assertNotIn("key_from_shared", saved["agentic"]["online_llm"])
                tsget = c.get("/api/timesketch/config/llm").get_json()
                self.assertEqual(tsget["openrouter_key"], "••••••••eeee")
                self.assertFalse(tsget["openrouter_key_pending"])
                self.assertNotIn("sk-or-ts-eeee", json.dumps(tsget))


PAGE = os.path.join(ROOT, "modules/nginx/html")
HARNESS = r"""
const fs = require('fs');
let store = null, init = null;
global.Alpine = { store: (name, obj) => { if (name === 'settings') store = obj; } };
global.document = { addEventListener: (ev, fn) => { if (ev === 'alpine:init') init = fn; } };
global.window = { dispatchEvent: () => {} }; global.CustomEvent = function () {};
global.localStorage = { getItem: () => null, setItem: () => {} };
eval(fs.readFileSync(process.argv[1], 'utf8'));
if (init) init();
const posts = [];
global.fetch = async (url, opt) => {
  if (opt && opt.method === 'POST') posts.push({ url, body: JSON.parse(opt.body || '{}') });
  if (url === '/api/config') return { ok: true, json: async () => ({ agentic: { llm_mode: 'online',
      online_llm: { provider: 'claude', api_key: '••••••••ant1', model: 'claude-sonnet-latest' } } }) };
  if (url === '/api/timesketch/config/llm') return { ok: true, json: async () => ({ llm_mode: 'openrouter',
      openrouter_key: '••••••••or99', openrouter_key_pending: true, openrouter_model: 'openai/gpt-4o-mini' }) };
  if (url.includes('/llm/test')) return { ok: true, json: async () => ({ success: true, elapsed_ms: 5 }) };
  return { ok: true, json: async () => ({ models: [] }) };
};
(async () => {
  await store.load();
  const s = store.config, out = {};
  out.pending = s.timesketch.openrouter_key_pending;
  store.shareOpenrouterKey('sk-ant-typed', 'agentic');        // Anthropic's key: not shared
  out.tsAfterAnthropic = s.timesketch.openrouter_key;
  s.agentic.online_llm.api_key = '••••••••ant1';
  s.agentic.online_llm.provider = 'openrouter';
  await store.onProviderChange();
  out.agenticOnOpenrouter = s.agentic.online_llm.api_key;
  store.shareOpenrouterKey('sk-or-new', 'agentic');
  out.tsKey = s.timesketch.openrouter_key;
  store.shareOpenrouterKey('sk-or-newer', 'timesketch');
  out.agKey = s.agentic.online_llm.api_key;
  out.models = [s.agentic.online_llm.model, s.timesketch.openrouter_model];
  s.agentic.online_llm.provider = 'claude';
  s.agentic.online_llm.api_key = '••••••••or99';
  await store.onProviderChange();
  out.backToClaude = s.agentic.online_llm.api_key;
  await store.testTimesketchLlm();
  out.test = posts.find(p => p.url === '/api/config/llm/test').body;
  out.result = store.tsLlmTestResult;
  console.log(JSON.stringify(out));
})();
"""


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class PageStore(unittest.TestCase):
    def test_the_key_follows_between_tabs_and_models_do_not(self):
        r = subprocess.run(["node", "-e", HARNESS, os.path.join(PAGE, "js/stores/settings.js")],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(0, r.returncode, r.stderr)
        got = json.loads(r.stdout.strip().splitlines()[-1])
        self.assertTrue(got["pending"], "load() keeps the pending flag")
        self.assertEqual(got["tsAfterAnthropic"], "••••••••or99")
        self.assertEqual(got["agenticOnOpenrouter"], "••••••••or99", "picking OpenRouter shows the shared key")
        self.assertEqual(got["tsKey"], "sk-or-new")
        self.assertEqual(got["agKey"], "sk-or-newer")
        self.assertEqual(got["models"][1], "openai/gpt-4o-mini")
        self.assertNotEqual(got["models"][0], got["models"][1])
        self.assertEqual(got["backToClaude"], "••••••••ant1", "switching back gives the saved Anthropic key")
        on = got["test"]["agentic"]["online_llm"]
        self.assertEqual((on["provider"], on["model"], on["api_key"]), ("openrouter", "openai/gpt-4o-mini", "sk-or-newer"))
        self.assertTrue(got["result"]["success"])


class PageSource(unittest.TestCase):
    def read(self, rel):
        with open(os.path.join(PAGE, rel)) as f:
            return f.read()

    def test_timesketch_tab_has_test_and_update_catalog(self):
        html = self.read("partials/settings.html")
        start = html.index("<!-- Timesketch Tab -->")
        tab = html[start:html.index("<!-- Velociraptor Tab", start)]
        self.assertIn("$store.settings.testTimesketchLlm()", tab)
        self.assertIn("$store.settings.updateCatalog()", tab)
        self.assertIn("shareOpenrouterKey($event.target.value, 'timesketch')", tab)
        self.assertIn("shareOpenrouterKey($event.target.value, 'agentic')", html)

    def test_timesketch_defaults_to_openrouter_in_the_page(self):
        js = self.read("js/stores/settings.js")
        self.assertIn("llm_mode: tsData.llm_mode || 'openrouter'", js)
        self.assertNotIn("llm_mode: 'google'", js)

    def test_cache_busting_moved(self):
        idx = self.read("index.html")
        self.assertRegex(idx, r"js/stores/settings\.js\?v=\d+")
        loader = self.read("js/bootstrap/partial-loader.js")
        self.assertTrue(re.search(r"partials/\$\{name\}\.html\?v=\d+", loader))


if __name__ == "__main__":
    unittest.main()
