"""Jev's own OpenRouter key: masked on read, kept when the masked form is saved.

The Settings page only ever holds the masked string, and Save PUTs the whole
agentic block back. Without the restore, the first Save after entering a key
would overwrite it with bullets — and every Jev call would fail as an auth
error. Needs Flask (the backend image has it; a bare dev box skips).
"""
import os
import sys
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402


class ConfigRoute(unittest.TestCase):
    """Jev's key is masked on read and survives a Save of the masked form.
    Needs Flask (the backend image has it; a bare dev box skips)."""

    def test_mask_and_preserve(self):
        try:
            import flask
            from routes import config_routes as cr
        except ImportError as e:
            self.skipTest(f"no flask here: {e}")
        store = {"agentic": {"online_llm": {"provider": "codex-subscription", "api_key": ""},
                             "jev": {"enabled": True, "api_key": "sk-or-realkey1234"}}}
        saved = {}
        app = flask.Flask(__name__)
        app.register_blueprint(cr.config_bp)
        with mock.patch.object(cr, "load_frontend_config", return_value=store), \
             mock.patch.object(cr, "save_frontend_config", side_effect=lambda c: saved.update(c)):
            c = app.test_client()
            got = c.get("/api/config").get_json()
            self.assertEqual(got["agentic"]["jev"]["api_key"], "••••••••1234")
            self.assertNotIn("sk-or-realkey1234", str(got))
            got["agentic"]["jev"]["enabled"] = False
            self.assertEqual(c.put("/api/config", json=got).status_code, 200)
        self.assertEqual(saved["agentic"]["jev"]["api_key"], "sk-or-realkey1234")
        self.assertFalse(saved["agentic"]["jev"]["enabled"])


if __name__ == "__main__":
    unittest.main()
