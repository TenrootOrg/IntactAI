"""The data purge deletes the operator's cases and empties the built-in workspaces.

"I used purge and I still see all cases": the purge kept every case and emptied it
by a list of data keys to strip, so everything added after that list (evidence,
report history, verdicts, host status, Jev) survived it. Operator cases now go
through store.delete_case; Default / System keep only their settings.

maintenance_routes needs Flask, so the function's own source runs here against a
real SQLite file, with delete_case removing the row like the real one does.
"""
import json
import os
import re
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_HERE, os.path.join(_ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import store  # noqa: E402

SRC = open(os.path.join(_ROOT, "modules/backend/routes/maintenance_routes.py"), encoding="utf-8").read()
FN = re.search(r"\ndef _purge_runs_and_cases\(.*?(?=\ndef )", SRC, re.S).group(0)

DATA = {"timeline_validations": [{"finding_id": "f1", "status": "true_positive"}], "report_history": [{"id": "0123456789ab"}],
        "case_files": [{"id": "0123456789cd"}], "jev_suggestions": {"f1": {}}, "host_status": {"h": "isolated"},
        "dispositions": [{"x": 1}], "chat_messages": [{"role": "user"}], "activity_log": [{"action": "x"}],
        "report_md": "# old", "scopes": {"a": {}}, "identity_verdicts": [1], "row_seen": {"f1": 1},
        "member_run_ids": ["r1"], "master_prompt": "focus on x", "excluded_hosts": ["h"]}
SETTINGS = {"time_window": {"start": "2016-01-01"}, "min_severity": "high", "masking": {"enabled": True},
            "tlp": "RED", "customer_name": "ACME", "fusion_modules": ["sigma"], "auto_fuse": True}


class Purge(unittest.TestCase):
    def setUp(self):
        fd, self.db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.addCleanup(os.remove, self.db)
        c = sqlite3.connect(self.db)
        c.execute("CREATE TABLE workflows (run_id TEXT PRIMARY KEY, automation_type TEXT, details TEXT)")
        rows = [("case_user1", "case", {"name": "qa test", **DATA, **SETTINGS}),
                ("case_user2", "case", {"name": "jev_test"}),
                ("case_def", "case", {"name": "Default", "is_default": True, **DATA, **SETTINGS}),
                ("case_sys", "case", {"name": "System", "is_system": True, **DATA}),
                ("r1", "velociraptor", {}), ("r2", "timesketch", {}),
                ("up1", "upgrade", {}), ("purge_run", "system_purge", {})]
        c.executemany("INSERT INTO workflows VALUES (?,?,?)", [(a, b, json.dumps(d)) for a, b, d in rows])
        c.commit()
        c.close()
        self.deleted, self.cleaned = [], []

        def delete_case(cid):                      # the real one: its own connection
            k = sqlite3.connect(self.db)
            k.execute("DELETE FROM workflows WHERE run_id = ?", (cid,))
            k.commit()
            k.close()
            self.deleted.append(cid)
            return {"deleted": True}
        for a, v in (("delete_case", delete_case),
                     ("purge_case_files_and_index", lambda cid: self.cleaned.append(cid))):
            p = mock.patch.object(store, a, v)
            p.start()
            self.addCleanup(p.stop)
        self.ns = {"_purge_kb_orphans": lambda: 0}
        exec(FN, self.ns)

    def _run(self, **kw):
        conn = sqlite3.connect(self.db)
        out = self.ns["_purge_runs_and_cases"](conn.cursor(), "purge_run", **kw)
        rows = {r: (t, json.loads(d)) for r, t, d in conn.execute("SELECT * FROM workflows")}
        conn.close()
        return out, rows

    def test_operator_cases_are_deleted_and_builtins_emptied_to_their_settings(self):
        (runs, cases, builtins), rows = self._run()
        self.assertEqual(sorted(self.deleted), ["case_user1", "case_user2"])
        self.assertEqual((cases, builtins), (2, 2))
        self.assertEqual(sorted(rows), ["case_def", "case_sys", "purge_run", "up1"])   # system history kept
        self.assertEqual(runs, 4)                   # 2 cases + 2 investigation runs
        d = rows["case_def"][1]
        for k, v in SETTINGS.items():
            self.assertEqual(d[k], v, k)            # the operator's settings survive
        self.assertTrue(d["is_default"])
        self.assertEqual(d["name"], "Default")
        for k in ("timeline_validations", "report_history", "case_files", "jev_suggestions", "host_status",
                  "dispositions", "activity_log", "scopes", "identity_verdicts", "row_seen",
                  "master_prompt", "excluded_hosts"):
            self.assertNotIn(k, d, k)               # no data about purged evidence
        self.assertEqual((d["report_md"], d["chat_messages"], d["member_run_ids"]), ("", [], []))
        self.assertEqual(sorted(self.cleaned), ["case_def", "case_sys"])   # their files, graph, KB

    def test_the_system_history_section_still_goes_only_when_asked(self):
        _, rows = self._run(include_system=True)
        self.assertEqual(sorted(rows), ["case_def", "case_sys", "purge_run"])

    def test_a_case_that_fails_to_delete_does_not_stop_the_purge(self):
        with mock.patch.object(store, "delete_case", side_effect=RuntimeError("locked")):
            (_, cases, _), rows = self._run()
        self.assertEqual(cases, 0)
        self.assertNotIn("r1", rows)                # the rest of the purge still ran

    def test_store_work_happens_before_this_connection_writes(self):
        # delete_case writes through its own connection; an open write here locks it out.
        self.assertLess(FN.index("store.delete_case(cid)"), FN.index('c.execute(f"DELETE FROM workflows'))
        self.assertIn("_es.delete_workflow_run(rid)", FN)    # or ES copies come back in the run list


if __name__ == "__main__":
    unittest.main()
