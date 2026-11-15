"""Timesketch's OpenRouter model defaults to Claude Sonnet (latest).

Until a model is chosen, Settings -> Timesketch shows and saves
~anthropic/claude-sonnet-latest (it showed anthropic/claude-3.5-sonnet in the
page and an empty model from the server). A model saved in timesketch.conf
still wins: the GET only fills a field from the conf when it has a value.
Source checks: routes/ needs Flask, which the test run does not install.
"""
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT = "~anthropic/claude-sonnet-latest"


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


class TimesketchDefaultModel(unittest.TestCase):
    def test_the_server_default(self):
        src = _read("modules/backend/routes/timesketch_llm_routes.py")
        self.assertIn(f"DEFAULT_OPENROUTER_MODEL = '{DEFAULT}'", src)
        get = src[src.index("def get_timesketch_llm_config("):]
        self.assertIn("'openrouter_model': DEFAULT_OPENROUTER_MODEL,", get[:900])
        # an empty conf value never replaces the default
        self.assertRegex(get, r"if value:\s*\n\s*config\[ui_key\]")

    def test_the_page_default_and_fallback(self):
        js = _read("modules/nginx/html/js/stores/settings.js")
        self.assertIn(f"openrouter_model: '{DEFAULT}',", js)
        self.assertIn(f"openrouter_model: tsData.openrouter_model || '{DEFAULT}',", js)
        self.assertNotIn("anthropic/claude-3.5-sonnet", js)

    def test_the_browser_loads_the_new_page_code(self):
        m = re.search(r"js/stores/settings\.js\?v=(\d+)", _read("modules/nginx/html/index.html"))
        self.assertGreaterEqual(int(m.group(1)), 66)


if __name__ == "__main__":
    unittest.main()
