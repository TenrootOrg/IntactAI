"""Data stored before the decision model was renamed (2026-10) still reads.

The feature used to be called Jev: its settings lived under agentic.jev and its
case caches under jev_*. A box upgraded in place, an old export and an old case
bundle all still carry those names, so every reader maps them to the new ones —
without ever letting the old name override a newer value, switch the feature off,
or carry a credential past the import guard.
"""
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import store  # noqa: E402
from services.storage import config_store, export_import  # noqa: E402

_SUFFIXES = ("suggestions", "notice", "identity", "scopes", "compromise", "relevance")


def _case(details):
    ws = mock.Mock()
    ws.get_automation_run.return_value = {"automation_type": store.CASE_TYPE, "details": details}
    with mock.patch.object(store, "_ws", return_value=ws):
        return store.get_case("c1")


class CaseCaches(unittest.TestCase):
    def test_old_keys_read_as_new(self):
        d = _case({f"jev_{s}": {"v": s} for s in _SUFFIXES})
        for s in _SUFFIXES:
            self.assertEqual(d.get(f"decision_{s}"), {"v": s}, s)
            self.assertNotIn(f"jev_{s}", d)

    def test_new_key_beats_stale_old_one(self):
        d = _case({"jev_suggestions": {"old": 1}, "decision_suggestions": {"new": 1},
                   "jev_scopes": {"old": 1}, "decision_scopes": {}})
        self.assertEqual(d["decision_suggestions"], {"new": 1})
        self.assertEqual(d["decision_scopes"], {})          # an emptied cache stays empty
        self.assertNotIn("jev_suggestions", d)


class LegacyAgentic(unittest.TestCase):
    def test_migrates(self):
        c = config_store._legacy_agentic({"agentic": {"jev": {"enabled": True, "api_key": "k"}}})
        self.assertEqual(c, {"agentic": {"decision_model": {"enabled": True, "api_key": "k"}}})

    def test_existing_new_block_wins(self):
        c = config_store._legacy_agentic({"agentic": {"jev": {"enabled": False},
                                                      "decision_model": {"enabled": True}}})
        self.assertEqual(c, {"agentic": {"decision_model": {"enabled": True}}})

    def test_noop_without_jev(self):
        for cfg in ({}, {"agentic": {"decision_model": {"enabled": True}}}, {"agentic": "x"}, None):
            before = json.dumps(cfg)
            self.assertEqual(json.dumps(config_store._legacy_agentic(cfg)), before)

    def test_load_frontend_config_returns_new_shape(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute("CREATE TABLE frontend_config (key TEXT, value TEXT, updated_at TEXT)")
        conn.execute("INSERT INTO frontend_config VALUES ('agentic', ?, '')",
                     (json.dumps({"online_llm": {"api_key": "m"},
                                  "jev": {"enabled": True, "api_key": "k"}}),))
        with mock.patch.object(config_store, "get_connection", return_value=conn):
            c = config_store.load_frontend_config()
        self.assertEqual(c["agentic"], {"online_llm": {"api_key": "m"},
                                        "decision_model": {"enabled": True, "api_key": "k"}})
        # read-time only: the stored row is untouched, so a rollback still finds `jev`
        raw = json.loads(conn.execute("SELECT value FROM frontend_config").fetchone()[0])
        self.assertIn("jev", raw)


class OldExportImport(unittest.TestCase):
    def test_old_export_keeps_the_stored_key(self):
        incoming = {"agentic": {"jev": {"enabled": True, "model": "m2", "api_key": "sk-or-attacker"}}}
        stored = {"agentic": {"decision_model": {"enabled": False, "api_key": "sk-or-real"}}}
        with mock.patch.object(export_import, "load_frontend_config", return_value=stored):
            out = export_import._protect_frontend_config_credentials(incoming)
        self.assertNotIn("jev", out["agentic"])
        self.assertEqual(out["agentic"]["decision_model"],
                         {"enabled": True, "model": "m2", "api_key": "sk-or-real"})
        self.assertNotIn("sk-or-attacker", json.dumps(out))
        self.assertIn("jev", incoming["agentic"])              # the caller's dict is untouched


class StalePagePut(unittest.TestCase):
    """A Settings page cached from before the rename PUTs a `jev` block of its own
    defaults. Needs Flask (the backend image has it; a bare dev box skips)."""

    def put(self, body):
        try:
            import flask
            from routes import config_routes as cr
        except ImportError as e:
            self.skipTest(f"no flask here: {e}")
        stored = {"agentic": {"decision_model": {"enabled": True, "api_key": "sk-or-real"}}}
        saved = {}
        app = flask.Flask(__name__)
        app.register_blueprint(cr.config_bp)
        with mock.patch.object(cr, "load_frontend_config", return_value=stored), \
             mock.patch.object(cr, "save_frontend_config", side_effect=lambda c: saved.update(c)):
            self.assertEqual(app.test_client().put("/api/config", json=body).status_code, 200)
        return saved["agentic"]

    def test_lone_jev_block_keeps_stored_setting(self):
        ag = self.put({"agentic": {"jev": {"enabled": False, "api_key": "••••••••real"}}})
        self.assertNotIn("jev", ag)
        self.assertTrue(ag["decision_model"]["enabled"])
        self.assertEqual(ag["decision_model"]["api_key"], "sk-or-real")

    def test_new_block_in_body_wins(self):
        ag = self.put({"agentic": {"jev": {"enabled": True},
                                   "decision_model": {"enabled": False, "api_key": "••••••••real"}}})
        self.assertNotIn("jev", ag)
        self.assertFalse(ag["decision_model"]["enabled"])
        self.assertEqual(ag["decision_model"]["api_key"], "sk-or-real")


class DbDump(unittest.TestCase):
    def test_redacts_both_names(self):
        try:
            from routes import db_routes
        except ImportError as e:
            self.skipTest(f"no flask here: {e}")
        d = tempfile.mkdtemp()
        db = os.path.join(d, "intact.db")
        c = sqlite3.connect(db)
        c.execute("CREATE TABLE secrets (key TEXT, value TEXT)")
        c.execute("CREATE TABLE frontend_config (key TEXT, value TEXT)")
        c.execute("INSERT INTO frontend_config VALUES ('agentic', ?)",
                  (json.dumps({"decision_model": {"api_key": "sk-or-newname0000"},
                               "jev": {"api_key": "sk-or-oldname0000"}}),))
        c.commit()
        c.close()
        tmp = db_routes._make_redacted_backup_copy(db)
        try:
            with open(tmp, "rb") as fh:
                data = fh.read()
            self.assertNotIn(b"sk-or-newname0000", data)
            self.assertNotIn(b"sk-or-oldname0000", data)
        finally:
            os.unlink(tmp)


class RelevanceRunType(unittest.TestCase):
    def test_both_names_are_system_types(self):
        from services import workflow_service
        self.assertIn("decision_relevance", workflow_service.SYSTEM_TYPES)
        self.assertIn("jev_relevance", workflow_service.SYSTEM_TYPES)   # past runs survive a purge


if __name__ == "__main__":
    unittest.main()
