"""Stop on a cloud run must stop it, and the result must say 'cancelled'.

QA A2: AWS offline analysis never registered a cancel event and Azure online
registered one but never handed it to the pipeline. Stop relabelled the row
while the analysis ran on, and the persisted result (what /api/<cloud>/status
returns) read 'complete' over partial data.
"""

import os
import re
import sys
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.dirname(os.path.abspath(__file__)), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
_optional_deps.stub("markupsafe", "werkzeug", "werkzeug.utils")  # sigma_runner imports werkzeug

from services import workflow_service  # noqa: E402
from services.aws import boto_client, collectors as aws_collectors, pipeline as aws  # noqa: E402
from services.azure import pipeline as az  # noqa: E402

RECORDS = {"AWS.CloudTrail": [{"eventName": "ConsoleLogin", "eventTime": "2026-11-01T00:00:00Z"}]}
AZ_RECORDS = {"Azure.SignIn": [{"createdDateTime": "2026-11-01T00:00:00Z"}]}
CREDS = {"access_key_id": "AKIAEXAMPLE", "secret_access_key": "s3cret", "region": "us-east-1"}


def _src(rel):
    with open(os.path.join(ROOT, rel)) as f:
        return f.read()


def _func(src, name):
    """Body of a top-level def, up to the next top-level statement."""
    m = re.search(rf"^def {name}\(.*?(?=^\S)", src, re.S | re.M)
    assert m, name
    return m.group(0)


class _Patch(unittest.TestCase):
    def patch(self, obj, attr, value):
        old = getattr(obj, attr)
        setattr(obj, attr, value)
        self.addCleanup(setattr, obj, attr, old)


class AwsStoppedRunSaysCancelled(_Patch):
    def setUp(self):
        self.log = []
        self.patch(aws, "add_log_to_run", lambda rid, m, lv="info": self.log.append((lv, m)))
        self.patch(aws, "_update_run_status", lambda *a, **k: None)
        self.patch(aws, "record_phase_timing", lambda *a, **k: None)
        self.patch(aws, "record_sigma_rule_tally", lambda *a, **k: None)
        self.patch(aws_collectors, "add_log_to_run", lambda *a, **k: None)
        self.patch(aws_collectors, "is_cancelled", lambda _rid: False)

    def test_offline_stop_keeps_records_and_is_cancelled(self):
        self.patch(aws, "is_cancelled", lambda _rid: True)
        res = aws.run_aws_on_existing("", dict(RECORDS), {"blueprint": {"settings": {}}})
        self.assertEqual(res["status"], "cancelled")
        self.assertEqual(len(res["collected_data"]["AWS.CloudTrail"]), 1)
        self.assertTrue(any("Stopped" in m for _, m in self.log))

    def test_offline_not_stopped_still_completes(self):
        self.patch(aws, "is_cancelled", lambda _rid: False)
        self.patch(aws, "load_aws_rules", lambda *a, **k: [])
        res = aws.run_aws_on_existing("", dict(RECORDS), {"blueprint": {"settings": {}}})
        self.assertEqual(res["status"], "complete")

    def test_online_stop_before_any_record_is_not_a_clean_account(self):
        self.patch(aws, "is_cancelled", lambda _rid: True)
        self.patch(boto_client, "preflight", lambda cfg, log=None: {
            "ok": True, "kind": "", "message": "", "account": "1", "arn": "a"})
        self.patch(aws, "collect_aws_logs", lambda **kw: ({}, {"errors": []}))
        bp = {"name": "Quick Triage", "settings": {"sources": ["guardduty_findings"]}}
        res = aws.run_aws_pipeline("", CREDS, bp, {})
        self.assertEqual(res["status"], "cancelled")
        self.assertNotIn("clean", res.get("message", ""))


class AzureStoppedRunSaysCancelled(_Patch):
    BP = {"name": "Quick Triage", "settings": {"sources": ["signin_logs"]}}

    def setUp(self):
        self.log = []
        self.patch(az, "add_log_to_run", lambda rid, m, lv="info": self.log.append((lv, m)))
        self.patch(az, "validate_rules_directory", lambda: (True, ""))
        # is_cancelled says "running": the route's Event alone must stop the run.
        self.patch(workflow_service, "is_cancelled", lambda _rid: False)
        self.patch(az, "_run_post_collection_phases",
                   lambda **kw: kw["result"].__setitem__("collected_data", kw["collected_data"]))

    def _run(self, data, errors=(), stopped=True):
        ev = threading.Event()
        if stopped:
            ev.set()
        self.patch(az, "collect_azure_logs",
                   lambda **kw: (data, {"errors": list(errors), "total_records": 1}))
        return az.run_azure_pipeline("", {}, self.BP, {}, cancel_event=ev)

    def test_online_stop_keeps_records_and_is_cancelled(self):
        res = self._run(dict(AZ_RECORDS))
        self.assertEqual(res["status"], "cancelled")
        self.assertIn("Azure.SignIn", res["collected_data"])

    def test_stop_that_killed_ual_is_cancelled_not_error(self):
        res = self._run({}, errors=["Unified Audit Log: container exited 137"])
        self.assertEqual(res["status"], "cancelled")
        self.assertNotIn("error", res)

    def test_not_stopped_still_completes(self):
        self.assertEqual(self._run(dict(AZ_RECORDS), stopped=False)["status"], "complete")

    def test_offline_stop_is_cancelled(self):
        self.patch(workflow_service, "is_cancelled", lambda _rid: True)
        res = az.run_azure_on_existing("", dict(AZ_RECORDS), {})
        self.assertEqual(res["status"], "cancelled")


class RoutesWireTheEvent(unittest.TestCase):
    """Flask is not installed here, so check the route bodies' source."""

    def test_aws_analyze_offline_registers_and_unregisters(self):
        body = _func(_src("modules/backend/routes/aws_routes.py"), "analyze_offline")
        self.assertIn("register_cancel_event(run_id)", body)
        self.assertIn("unregister_cancel(run_id)", body)
        # the final 'completed' write is skipped once stopped
        self.assertLess(body.index("if is_cancelled(run_id):"), body.index("'completed'"))

    def test_azure_scan_hands_its_event_to_the_pipeline(self):
        body = _func(_src("modules/backend/routes/azure_routes.py"), "start_scan")
        self.assertIn("cancel_event = register_cancel_event(run_id)", body)
        self.assertIn("cancel_event=cancel_event", body)


if __name__ == "__main__":
    unittest.main()
