"""An online M365 scan where every source failed must end red, not green.

QA A6: the Azure pipeline returned 'completed' / "No data collected" when
collection produced zero records AND errors (bad permissions, missing
license), and the scan route only treated status 'failed' as a failure while
the pipeline reports 'error'. An analyst read the green run as a clean tenant.
AWS was fixed the same way in test_aws_run_fails_honestly.py.
"""

import ast
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.dirname(os.path.abspath(__file__)), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
_optional_deps.stub("markupsafe", "werkzeug", "werkzeug.utils")  # sigma_runner imports werkzeug

from services.azure import pipeline  # noqa: E402

AZURE_ROUTES = os.path.join(ROOT, "modules/backend/routes/azure_routes.py")
BP = {"name": "Quick Triage", "settings": {"sources": ["signin_logs", "audit_logs"]}}


class PipelineOutcome(unittest.TestCase):
    def setUp(self):
        self.log = []
        self._saved = (pipeline.add_log_to_run, pipeline.collect_azure_logs,
                       pipeline.validate_rules_directory)
        pipeline.add_log_to_run = lambda rid, msg, level="info": self.log.append((level, msg))
        pipeline.validate_rules_directory = lambda: (True, "")

    def tearDown(self):
        (pipeline.add_log_to_run, pipeline.collect_azure_logs,
         pipeline.validate_rules_directory) = self._saved

    def _run(self, errors):
        pipeline.collect_azure_logs = lambda **kw: ({}, {"errors": errors, "total_records": 0})
        # run_id "" keeps progress/phase-timing writes off the DB.
        return pipeline.run_azure_pipeline("", {}, BP, {})

    def test_zero_records_with_errors_is_an_error_naming_the_first_cause(self):
        res = self._run(["Sign-in Logs: requires Entra ID P1", "Audit Logs: 403 Forbidden"])
        self.assertEqual(res["status"], "error")
        self.assertIn("requires Entra ID P1", res["error"])
        self.assertEqual(res["phases"]["collection"]["status"], "failed")
        self.assertTrue(any(lv == "error" and "2 source error(s)" in m for lv, m in self.log))

    def test_zero_records_without_errors_is_still_a_completed_run(self):
        res = self._run([])
        self.assertEqual(res["status"], "completed")
        self.assertNotIn("error", res)


class ScanRouteTreatsErrorAsFailed(unittest.TestCase):
    """Flask is not installed here, so check the thread bodies' source."""

    def _body(self, func_name):
        with open(AZURE_ROUTES, encoding="utf-8") as fh:
            src = fh.read()
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.FunctionDef) and node.name == func_name:
                return ast.get_source_segment(src, node)
        raise AssertionError(f"{func_name} not found")

    def test_online_and_offline_threads_both_fail_on_error(self):
        for fn in ("run_scan", "run_analysis"):
            body = self._body(fn)
            self.assertIn("result.get('status') in ('failed', 'error')", body, fn)
            self.assertNotIn("result.get('status') == 'failed'", body, fn)


if __name__ == "__main__":
    unittest.main(verbosity=2)
