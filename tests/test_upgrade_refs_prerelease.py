"""/api/upgrade/refs and development pre-releases (2026-10-06).

The route passes the engine's `prerelease` flag through, labels a dev build
"(pre-release)", and never calls one "latest": latest is the newest STABLE
release. Needs Flask (the backend image has it; a bare dev box skips).
"""
import json
import os
import sys
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402

LISTED = {"installed": "intact-20261005", "releases": [
    {"tag": "intact-20261005", "payload_bytes": 1, "shape": "per-module", "note": "installed", "prerelease": False},
    {"tag": "intact-20261006-dev1", "payload_bytes": 1, "shape": "per-module", "note": "newer", "prerelease": True},
    {"tag": "intact-20261006", "payload_bytes": 1, "shape": "per-module", "note": "newer", "prerelease": False},
    {"tag": "intact-20261007-dev1", "payload_bytes": 1, "shape": "per-module", "note": "newer", "prerelease": True},
]}


class RefsRoute(unittest.TestCase):
    def test_prereleases_are_flagged_and_never_latest(self):
        try:
            import flask
            from routes import upgrade_routes as ur
        except ImportError as e:
            self.skipTest(f"no flask here: {e}")
        app = flask.Flask(__name__)
        app.register_blueprint(ur.upgrade_bp)
        with mock.patch.object(ur, "run_command", return_value={"success": True, "stdout": json.dumps(LISTED)}):
            refs = {r["name"]: r for r in app.test_client().post("/api/upgrade/refs").get_json()["refs"]}
        self.assertTrue(refs["intact-20261006-dev1"]["prerelease"])
        self.assertIn("(pre-release)", refs["intact-20261007-dev1"]["label"])
        self.assertTrue(refs["intact-20261006"]["latest"])                 # not the newer dev build
        self.assertFalse(refs["intact-20261007-dev1"]["latest"])
        self.assertFalse(refs["intact-20261005"]["prerelease"])


if __name__ == "__main__":
    unittest.main()
