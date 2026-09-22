"""Evidence a cloud run already collected must outlive whatever stopped it.

THE RULE, from the Windows MEMORY post-mortem: a failed run deleted the 9.2 GB
dump from the host, from staging and from the source, so retrying meant
re-acquiring from the endpoint. Nothing that was collected may be thrown away
because the step AFTER it failed.

The same shape existed in three places across the two cloud providers:

  1. AWS CloudTrail, `_collect_for_region`. Region four raising (expired token,
     no route) propagated out of `collect_cloudtrail` with regions one to three
     still in a local list. Now the failure carries its partial haul
     (boto_client.AwsFatal.partial) and the region loop keeps it.

  2. Both scan routes. `_aws_runs[run_id] = result` and the persist to
     /app/data/*_runs sat BEHIND `if is_cancelled(run_id): return`, so
     stopping a run discarded everything it had pulled — and the Azure run is
     the one whose UAL phase takes 5-10 minutes (azure/pipeline.py says so in
     its own log line).

  3. Azure DFIR-O365RC. Every failure path did
     `shutil.rmtree(output_dir); return {'records': []}` — on timeout, on a
     non-zero exit, on a fatal auth error. The container writes its output
     incrementally, so a UAL pull killed at minute 28 of a 30-minute budget had
     most of the tenant's audit log on disk, and we deleted it unread. This is
     the memory bug, in Azure, exactly.

(1) and (3) are driven for real. (2) is checked on the source, because the
ordering of two statements inside a thread body is the whole bug and a live
Flask + cancel-event harness would test the harness.
"""

import ast
import json
import os
import sys
import tempfile
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
_optional_deps.stub("markupsafe", "werkzeug", "werkzeug.utils")  # sigma_runner imports werkzeug; CI has none

from services.aws import boto_client, cloudtrail_runner, iam_runner  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AWS_ROUTES = os.path.join(ROOT, "modules/backend/routes/aws_routes.py")
AZURE_ROUTES = os.path.join(ROOT, "modules/backend/routes/azure_routes.py")
DFIR = os.path.join(ROOT, "modules/backend/services/azure/dfir_o365rc.py")


class _ClientError(Exception):
    def __init__(self, code):
        super().__init__(f"An error occurred ({code})")
        self.response = {"Error": {"Code": code}}


class _FakeCloudTrail:
    """LookupEvents that answers for some regions and raises for others."""

    def __init__(self, region, raises=None, events_per_pass=2):
        self.region = region
        self.raises = raises
        self.events_per_pass = events_per_pass
        self.calls = 0

    def lookup_events(self, **kwargs):
        self.calls += 1
        if self.raises:
            raise self.raises
        return {"Events": [
            {"EventId": f"{self.region}-{self.calls}-{i}",
             "EventName": "ConsoleLogin",
             "CloudTrailEvent": json.dumps({"eventName": "ConsoleLogin",
                                            "awsRegion": self.region})}
            for i in range(self.events_per_pass)
        ]}


class CloudTrailKeepsTheRegionsItAlreadyRead(unittest.TestCase):
    REGIONS = ["us-east-1", "us-west-2", "eu-central-1", "eu-west-1"]

    def setUp(self):
        self.lines = []
        self.log = lambda msg, lvl="info": self.lines.append((lvl, msg))
        # boto3 itself is not a test dependency (tests/run_tests.sh is stdlib
        # only) and is_available() gates on importing it. The collection loop
        # under test is what matters here.
        self._saved = (cloudtrail_runner._safe_client, cloudtrail_runner.is_available)
        cloudtrail_runner.is_available = lambda cfg=None: {"available": True, "message": "Ready"}

    def tearDown(self):
        cloudtrail_runner._safe_client, cloudtrail_runner.is_available = self._saved

    def _run(self, failure, mode="console_only"):
        clients = {r: _FakeCloudTrail(r, raises=failure if r == "eu-west-1" else None)
                   for r in self.REGIONS}
        cloudtrail_runner._safe_client = lambda svc, cfg, region: clients[region]
        events = cloudtrail_runner.collect_cloudtrail(
            {"access_key_id": "AKIA", "secret_access_key": "x", "region": "us-east-1"},
            mode=mode, regions=self.REGIONS, log_func=self.log,
        )
        return events, clients

    def errors(self):
        return "\n".join(m for lv, m in self.lines if lv == "error")

    def test_the_fourth_region_expiring_keeps_the_first_three(self):
        events, _ = self._run(_ClientError("ExpiredToken"))
        regions_seen = {e.get("awsRegion") for e in events}
        self.assertEqual(len(events), 6, "3 good regions x 2 events per pass")
        self.assertEqual(regions_seen, {"us-east-1", "us-west-2", "eu-central-1"})

    def test_it_says_how_far_it_got_and_why_it_stopped(self):
        self._run(_ClientError("ExpiredToken"))
        err = self.errors()
        self.assertIn("aborting after 3 of 4 region(s)", err)
        self.assertIn("credentials", err.lower())
        self.assertIn("Keeping the 6 event(s)", err)

    def test_no_route_stops_the_sweep_instead_of_trying_every_region(self):
        # Ordered so the FIRST region has no route: without the fatal check
        # this walked all four, each burning the full socket timeout budget.
        clients = {r: _FakeCloudTrail(r, raises=type("EndpointConnectionError", (Exception,), {})())
                   for r in self.REGIONS}
        cloudtrail_runner._safe_client = lambda svc, cfg, region: clients[region]
        events = cloudtrail_runner.collect_cloudtrail(
            {"access_key_id": "AKIA", "secret_access_key": "x"},
            mode="console_only", regions=self.REGIONS, log_func=self.log,
        )
        self.assertEqual(events, [])
        touched = [r for r, c in clients.items() if c.calls]
        self.assertEqual(len(touched), 1, f"tried {touched} despite no route to AWS")
        self.assertIn("no route to AWS", self.errors())

    def test_a_denial_does_not_repeat_itself_once_per_event_name(self):
        # iam_only makes one LookupEvents pass per event name (24 of them).
        # A single denied permission used to log 24 identical warnings and
        # still walk every pass.
        events, clients = self._run(_ClientError("AccessDeniedException"), mode="iam_only")
        self.assertEqual(clients["eu-west-1"].calls, 1)
        self.assertEqual(len(events), 3 * 2 * len(cloudtrail_runner.LIGHT_EVENT_NAMES_IAM))
        self.assertIn("CloudTrail events are INCOMPLETE", self.errors())

    def test_a_denied_region_is_not_reported_as_an_empty_one(self):
        self._run(_ClientError("AccessDeniedException"), mode="console_only")
        self.assertIn("region=eu-west-1", self.errors())
        self.assertIn("INCOMPLETE", self.errors())


class _FakeIAM:
    """Enumerates one user; selected sub-calls are denied."""

    def __init__(self, denied=()):
        self.denied = set(denied)

    def _maybe_deny(self, op):
        if op in self.denied:
            raise _ClientError("AccessDenied")

    def get_paginator(self, name):
        outer = self

        class _P:
            def paginate(self, **kw):
                outer._maybe_deny("list_users")
                return [{"Users": [{"UserName": "svc-deploy", "Arn": "arn:aws:iam::1:user/svc-deploy",
                                    "UserId": "AIDA1", "CreateDate": None}]}]
        return _P()

    def list_attached_user_policies(self, **kw):
        self._maybe_deny("list_attached_user_policies")
        return {"AttachedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                                      "PolicyName": "AdministratorAccess"}]}

    def list_user_policies(self, **kw):
        self._maybe_deny("list_user_policies")
        return {"PolicyNames": []}

    def list_access_keys(self, **kw):
        self._maybe_deny("list_access_keys")
        return {"AccessKeyMetadata": [{"AccessKeyId": "AKIA1", "Status": "Active", "CreateDate": None}]}

    def list_mfa_devices(self, **kw):
        self._maybe_deny("list_mfa_devices")
        return {"MFADevices": [{"SerialNumber": "s"}]}


class HalfReadPrincipalsAreNotReportedAsClean(unittest.TestCase):
    """A denied sub-call made every IAM principal look SAFER than it is."""

    def setUp(self):
        self.lines = []
        self.log = lambda msg, lvl="info": self.lines.append((lvl, msg))
        self._saved = (iam_runner._safe_client, iam_runner.is_available)
        iam_runner.is_available = lambda cfg=None: {"available": True, "message": "Ready"}

    def tearDown(self):
        iam_runner._safe_client, iam_runner.is_available = self._saved

    def _collect(self, denied=()):
        iam_runner._safe_client = lambda svc, cfg: _FakeIAM(denied)
        return iam_runner.collect_iam_principals(
            {"access_key_id": "AKIA", "secret_access_key": "x"}, log_func=self.log)

    def test_a_fully_readable_principal_records_no_gaps(self):
        recs = self._collect()
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["CollectionGaps"], [])
        self.assertTrue(recs[0]["IsAdmin"])
        self.assertTrue(recs[0]["HasMFA"])

    def test_a_denied_policy_read_is_recorded_rather_than_read_as_not_admin(self):
        recs = self._collect(denied=["list_attached_user_policies", "list_mfa_devices"])
        self.assertFalse(recs[0]["IsAdmin"])   # unchanged: we cannot know
        self.assertEqual(len(recs[0]["CollectionGaps"]), 2)
        self.assertTrue(any("attached policies" in g for g in recs[0]["CollectionGaps"]))
        errors = "\n".join(m for lv, m in self.lines if lv == "error")
        self.assertIn("understated, not clean", errors)


class DfirOutputIsReadBeforeItIsDeleted(unittest.TestCase):
    def setUp(self):
        from services.azure import dfir_o365rc
        self.mod = dfir_o365rc

    def test_harvest_reads_every_json_file_the_container_left(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "day1"))
            with open(os.path.join(d, "day1", "a.json"), "w") as f:
                json.dump([{"Operation": "UserLoggedIn"}, {"Operation": "Add member"}], f)
            with open(os.path.join(d, "b.json"), "w") as f:
                json.dump({"Operation": "MailItemsAccessed"}, f)
            with open(os.path.join(d, "truncated.json"), "w") as f:
                f.write('[{"Operation": "cut off"')      # killed mid-write
            recs = self.mod._harvest_output(d)
        self.assertEqual(len(recs), 3, "a half-written file must not lose the finished ones")

    def test_every_delete_of_the_output_dir_reads_it_first(self):
        """`shutil.rmtree(output_dir)` must be preceded by a harvest.

        AST over the whole module, not grep: this is the invariant the memory
        bug broke — the delete ran while the collected files were still unread.
        (The guards that return before the container starts are untouched:
        they never create output.)
        """
        with open(DFIR, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        harvests, deletes = [], []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
            if name == "_harvest_output":
                harvests.append(node.lineno)
            elif name == "rmtree" and node.args and getattr(node.args[0], "id", "") == "output_dir":
                deletes.append(node.lineno)
        self.assertTrue(deletes, "no rmtree(output_dir) found — has the module moved?")
        unread = [d for d in deletes if not any(d - 10 <= h < d for h in harvests)]
        self.assertEqual(unread, [], f"lines {unread} delete collected output without reading it")


class ScanResultsArePersistedBeforeTheCancelCheck(unittest.TestCase):
    """Ordering inside the scan thread — the cancel check must come second."""

    def _thread_body(self, path, func_name):
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == func_name:
                return ast.get_source_segment(src, node)
        raise AssertionError(f"{func_name} not found in {path}")

    def test_aws_stores_and_persists_before_returning_on_cancel(self):
        body = self._thread_body(AWS_ROUTES, "run_scan")
        store = body.index("_aws_runs[run_id] = result")
        persist = body.index('json.dump(result, f, default=str)')
        cancel = body.index("if is_cancelled(run_id):")
        self.assertLess(store, cancel, "a cancelled AWS run discards what it collected")
        self.assertLess(persist, cancel, "a cancelled AWS run is never written to disk")

    def test_azure_stores_and_persists_before_returning_on_cancel(self):
        body = self._thread_body(AZURE_ROUTES, "run_scan")
        store = body.index("_azure_runs[run_id] = result")
        persist = body.index('json.dump(result, f, default=str)')
        cancel = body.index("if is_cancelled(run_id):")
        self.assertLess(store, cancel, "a cancelled Azure run discards a 5-10 minute UAL pull")
        self.assertLess(persist, cancel)

    def test_an_aws_upload_is_on_disk_before_the_analysis_is_requested(self):
        """/analyze-offline used to read _aws_runs only, so a backend restart
        between upload and analysis lost the operator's own files."""
        body = self._thread_body(AWS_ROUTES, "upload_logs")
        self.assertIn("json.dump(upload_record", body)
        analyze = self._thread_body(AWS_ROUTES, "analyze_offline")
        self.assertIn("_load_run(run_id)", analyze)
        self.assertNotIn("run_id not in _aws_runs", analyze)


if __name__ == "__main__":
    unittest.main(verbosity=2)
