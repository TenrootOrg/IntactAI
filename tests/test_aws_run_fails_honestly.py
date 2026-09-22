"""An AWS scan that cannot work must say so in seconds, and name the cause.

WHAT THIS EXISTS FOR. The Windows MEMORY post-mortem produced four rules. Three
of them apply to the AWS path, which is in-process boto3 (no Celery, no poller,
no wait deadline — so nothing here can "time out" the way memory analysis did;
the boto3 socket timeouts ARE the deadline):

  * FAIL FAST, NAME THE CAUSE. Every runner built its own client with the boto3
    defaults (60s connect, 60s read, legacy retries) and caught `Exception` into
    one warning line. A `light` CloudTrail sweep makes 25 LookupEvents passes
    per region, so an appliance with no egress spent HOURS in a run that could
    never succeed and then reported "No data collected" — which is also exactly
    what a clean account reports. An expired access key produced the same
    empty, clean-looking scan.

  * PRESERVE WHAT WAS COLLECTED. `collected_data` lived in a local until the
    pipeline was nearly finished, and `collect_aws_logs` had no guard around
    its per-source loop, so one source raising discarded every source that had
    already succeeded. The operator's only way back was to re-pull the account.

  * NO SILENT DEGRADATION. `bp_settings.get('min_severity')` never matched
    anything: the built-in blueprints carry `min_severity` as a SIBLING of
    `settings` (see get_aws_blueprints), so the fallback always resolved to a
    hardcoded 'low' and a blueprint's declared floor was dead config. The same
    shape as the memory bug's "All plugins (deep dive)" blueprint, which
    expanded its wildcard from an empty table and ran the curated 12.

These drive the REAL pipeline and the REAL collector with a fake boto3 layer;
no network, nothing sleeps. `preflight` is exercised through
`run_aws_pipeline`, not called directly, because the point is that the run
STOPS there.
"""

import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
_optional_deps.stub("markupsafe", "werkzeug", "werkzeug.utils")  # sigma_runner imports werkzeug; CI has none

from services.aws import boto_client, collectors, pipeline  # noqa: E402

CREDS = {"access_key_id": "AKIAEXAMPLE", "secret_access_key": "s3cret", "region": "us-east-1"}


class _ClientError(Exception):
    """Shaped like botocore's ClientError: the code lives in .response."""

    def __init__(self, code, message="denied"):
        super().__init__(f"An error occurred ({code}): {message}")
        self.response = {"Error": {"Code": code, "Message": message}}


class EndpointConnectionError(Exception):
    """Same class NAME botocore raises when there is no route to the endpoint."""


class _Captured:
    """Collects the run log so tests can assert what the operator was told."""

    def __init__(self):
        self.lines = []

    def __call__(self, run_id, msg, level="info"):
        self.lines.append((level, str(msg)))

    def text(self, level=None):
        return "\n".join(m for lv, m in self.lines if level is None or lv == level)


class _PipelineHarness(unittest.TestCase):
    """Runs the real pipeline with its workflow collaborators silenced."""

    def setUp(self):
        self.log = _Captured()
        self._saved = {
            "add_log_to_run": pipeline.add_log_to_run,
            "is_cancelled": pipeline.is_cancelled,
            "_update_run_status": pipeline._update_run_status,
            "record_phase_timing": pipeline.record_phase_timing,
            "record_sigma_rule_tally": pipeline.record_sigma_rule_tally,
            "load_aws_rules": pipeline.load_aws_rules,
            "c_add_log": collectors.add_log_to_run,
            "c_is_cancelled": collectors.is_cancelled,
        }
        pipeline.add_log_to_run = self.log
        pipeline.is_cancelled = lambda _rid: False
        pipeline._update_run_status = lambda *a, **k: None
        pipeline.record_phase_timing = lambda *a, **k: None
        pipeline.record_sigma_rule_tally = lambda *a, **k: None
        pipeline.load_aws_rules = lambda *a, **k: []
        collectors.add_log_to_run = self.log
        collectors.is_cancelled = lambda _rid: False

    def tearDown(self):
        pipeline.add_log_to_run = self._saved["add_log_to_run"]
        pipeline.is_cancelled = self._saved["is_cancelled"]
        pipeline._update_run_status = self._saved["_update_run_status"]
        pipeline.record_phase_timing = self._saved["record_phase_timing"]
        pipeline.record_sigma_rule_tally = self._saved["record_sigma_rule_tally"]
        pipeline.load_aws_rules = self._saved["load_aws_rules"]
        collectors.add_log_to_run = self._saved["c_add_log"]
        collectors.is_cancelled = self._saved["c_is_cancelled"]

    def run_pipeline(self, *, preflight_result, blueprint=None, options=None, collect=None):
        """Drive run_aws_pipeline with a stubbed preflight and collector."""
        bp = blueprint or {"name": "Quick Triage", "settings": {"sources": ["guardduty_findings"]},
                           "min_severity": "low"}
        saved_pre = boto_client.preflight
        saved_collect = pipeline.collect_aws_logs
        boto_client.preflight = lambda cfg, log=None: preflight_result
        if collect is not None:
            pipeline.collect_aws_logs = collect
        try:
            return pipeline.run_aws_pipeline("run1", CREDS, bp, options or {})
        finally:
            boto_client.preflight = saved_pre
            pipeline.collect_aws_logs = saved_collect


class ClassifyNamesTheRealCause(unittest.TestCase):
    def test_expired_key_is_a_credential_problem_not_a_generic_error(self):
        kind, msg = boto_client.classify(_ClientError("ExpiredToken"))
        self.assertEqual(kind, "credentials")
        self.assertIn("credentials", msg.lower())

    def test_access_denied_is_its_own_kind_and_is_not_fatal(self):
        # Denied is per-call: other regions/sources may still be readable, so
        # it must NOT abort the run the way bad credentials do.
        kind, _ = boto_client.classify(_ClientError("AccessDeniedException"))
        self.assertEqual(kind, "denied")
        self.assertNotIn(kind, boto_client.FATAL_KINDS)

    def test_no_endpoint_says_this_box_has_no_route_to_aws(self):
        kind, msg = boto_client.classify(EndpointConnectionError("Could not connect to the endpoint URL"))
        self.assertEqual(kind, "no_route")
        self.assertIn("no route to AWS", msg)
        self.assertIn(kind, boto_client.FATAL_KINDS)

    def test_throttling_is_named_as_incomplete_collection(self):
        kind, msg = boto_client.classify(_ClientError("ThrottlingException"))
        self.assertEqual(kind, "throttled")
        self.assertIn("incomplete", msg.lower())

    def test_an_unknown_exception_still_carries_its_own_text(self):
        kind, msg = boto_client.classify(ValueError("something odd"))
        self.assertEqual(kind, "unknown")
        self.assertIn("something odd", msg)

    def test_the_client_is_built_with_bounded_timeouts(self):
        # The whole no-egress hang came from the library defaults. Assert the
        # numbers exist and are small rather than trusting the call site.
        self.assertLessEqual(boto_client.CONNECT_TIMEOUT, 10)
        self.assertLessEqual(boto_client.READ_TIMEOUT, 30)
        self.assertLessEqual(boto_client.MAX_ATTEMPTS, 3)


class PreflightUsesTheOneCallItCanAfford(unittest.TestCase):
    """preflight() answers reachable / credentials-valid / which-account."""

    def _preflight(self, raiser):
        saved = boto_client.client
        boto_client.client = lambda *a, **k: raiser()
        try:
            return boto_client.preflight(CREDS)
        finally:
            boto_client.client = saved

    def test_no_credentials_is_answered_without_touching_the_network(self):
        def boom():
            raise AssertionError("built a client with no credentials")
        saved = boto_client.client
        boto_client.client = lambda *a, **k: boom()
        try:
            out = boto_client.preflight({})
        finally:
            boto_client.client = saved
        self.assertFalse(out["ok"])
        self.assertEqual(out["kind"], "credentials")

    def test_a_denied_get_caller_identity_does_not_block_the_scan(self):
        # An SCP can deny sts:GetCallerIdentity. Reaching AWS and being
        # recognised is what the check is for; the refusal itself proves both.
        out = self._preflight(lambda: (_ for _ in ()).throw(_ClientError("AccessDenied")))
        self.assertTrue(out["ok"])

    def test_a_rejected_key_stops_the_scan(self):
        out = self._preflight(lambda: (_ for _ in ()).throw(_ClientError("InvalidClientTokenId")))
        self.assertFalse(out["ok"])
        self.assertEqual(out["kind"], "credentials")

    def test_the_account_id_is_carried_back_for_the_run_record(self):
        class _Sts:
            def get_caller_identity(self):
                return {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/dfir"}
        saved = boto_client.client
        boto_client.client = lambda *a, **k: _Sts()
        try:
            out = boto_client.preflight(CREDS)
        finally:
            boto_client.client = saved
        self.assertTrue(out["ok"])
        self.assertEqual(out["account"], "123456789012")


class PreflightStopsTheRunBeforeCollecting(_PipelineHarness):
    def _collector_that_must_not_run(self, *a, **k):
        raise AssertionError("collection started despite a failed preflight")

    def test_air_gapped_box_fails_immediately_and_says_so(self):
        res = self.run_pipeline(
            preflight_result={"ok": False, "kind": "no_route", "account": None, "arn": None,
                              "message": boto_client.classify(EndpointConnectionError("x"))[1]},
            collect=self._collector_that_must_not_run,
        )
        self.assertEqual(res["status"], "error")
        self.assertIn("no route to AWS", res["error"])
        self.assertEqual(res["phases"]["validation"]["status"], "failed")
        self.assertIn("Aborting before collection", self.log.text("error"))

    def test_bad_credentials_do_not_produce_an_empty_clean_looking_run(self):
        res = self.run_pipeline(
            preflight_result={"ok": False, "kind": "credentials", "account": None, "arn": None,
                              "message": boto_client.classify(_ClientError("InvalidClientTokenId"))[1]},
            collect=self._collector_that_must_not_run,
        )
        # The old behaviour: status 'completed', message 'No data collected'.
        self.assertEqual(res["status"], "error")
        self.assertNotEqual(res.get("message"), "No data collected")
        self.assertIn("credentials", res["error"].lower())


class EmptyResultsAreDistinguishable(_PipelineHarness):
    def test_zero_records_with_errors_is_a_failure_naming_the_first_cause(self):
        def collect(**kw):
            return {}, {"errors": ["[AWS] GuardDuty: AWS denied the call (AccessDeniedException)"],
                        "sources_attempted": ["guardduty_findings"],
                        "sources_with_data": [], "sources_failed": ["guardduty_findings"]}

        res = self.run_pipeline(
            preflight_result={"ok": True, "kind": "", "message": "", "account": "1", "arn": "a"},
            collect=collect,
        )
        self.assertEqual(res["status"], "error")
        self.assertIn("AccessDeniedException", res["error"])

    def test_zero_records_with_no_errors_is_reported_as_a_clean_account(self):
        def collect(**kw):
            return {}, {"errors": [], "sources_attempted": ["guardduty_findings"],
                        "sources_with_data": [], "sources_failed": []}

        res = self.run_pipeline(
            preflight_result={"ok": True, "kind": "", "message": "", "account": "1", "arn": "a"},
            collect=collect,
        )
        self.assertEqual(res["status"], "completed")
        self.assertIn("no collection errors", res["message"])
        self.assertIn("this account is clean for this scope", self.log.text())


class PartialCollectionSurvivesAFailure(_PipelineHarness):
    """Three regions collected, the fourth throws. Keep the three."""

    def test_records_and_the_reason_both_reach_the_result(self):
        def collect(**kw):
            return ({"AWS.CloudTrail": [{"eventName": "ConsoleLogin"}] * 30},
                    {"errors": ["[cloudtrail] aborting after 3 of 4 region(s) — "
                                "region=eu-west-1: AWS rejected the credentials (ExpiredToken)"],
                     "sources_attempted": ["cloudtrail_console"],
                     "sources_with_data": ["cloudtrail_console"],
                     "sources_failed": ["cloudtrail_console"]})

        res = self.run_pipeline(
            preflight_result={"ok": True, "kind": "", "message": "", "account": "1", "arn": "a"},
            collect=collect,
        )
        self.assertEqual(len(res["collected_data"]["AWS.CloudTrail"]), 30)
        coll = res["phases"]["collection"]
        self.assertEqual(coll["status"], "partial")
        self.assertEqual(coll["sources_failed"], ["cloudtrail_console"])
        self.assertIn("3 of 4 region(s)", coll["errors"][0])
        self.assertIn("Collection PARTIAL", self.log.text("warning"))

    def test_a_crash_after_collection_still_returns_the_evidence(self):
        # normalize_all_results is swallowed, so break the phase after it.
        def collect(**kw):
            return ({"AWS.IAM": [{"ResourceName": "svc-deploy"}]},
                    {"errors": [], "sources_attempted": ["iam_principals"],
                     "sources_with_data": ["iam_principals"], "sources_failed": []})

        saved = pipeline.run_sigma_rules
        pipeline.run_sigma_rules = lambda **kw: (_ for _ in ()).throw(RuntimeError("detector exploded"))
        try:
            res = self.run_pipeline(
                preflight_result={"ok": True, "kind": "", "message": "", "account": "1", "arn": "a"},
                collect=collect,
            )
        finally:
            pipeline.run_sigma_rules = saved
        self.assertEqual(res["status"], "error")
        self.assertIn("detector exploded", res["error"])
        # The whole point: re-running analysis must be possible without
        # re-collecting the account.
        self.assertEqual(res["collected_data"]["AWS.IAM"], [{"ResourceName": "svc-deploy"}])
        self.assertIn("are kept on this", self.log.text())


class OneSourceCannotTakeDownTheRest(unittest.TestCase):
    """collect_aws_logs had no guard around its per-source loop."""

    def setUp(self):
        self._saved = (collectors.add_log_to_run, collectors.is_cancelled, collectors._stub_collect)
        collectors.add_log_to_run = lambda *a, **k: None
        collectors.is_cancelled = lambda _rid: False

    def tearDown(self):
        collectors.add_log_to_run, collectors.is_cancelled, collectors._stub_collect = self._saved

    def _collect(self, per_source):
        def fake(source, log, **kw):
            out = per_source[source]
            if isinstance(out, Exception):
                raise out
            return out
        collectors._stub_collect = fake
        return collectors.collect_aws_logs(
            run_id="r", aws_config=CREDS,
            sources=["guardduty_findings", "accessanalyzer_findings", "iam_principals"],
            cloudtrail_mode="full",
        )

    def test_a_raising_source_does_not_discard_the_others(self):
        data, status = self._collect({
            "guardduty_findings": [{"FindingId": "gd-1"}],
            "accessanalyzer_findings": RuntimeError("boom"),
            "iam_principals": [{"ResourceName": "root"}],
        })
        self.assertEqual(len(data["AWS.GuardDuty"]), 1)
        self.assertEqual(len(data["AWS.IAM"]), 1)
        self.assertEqual(status["sources_failed"], ["accessanalyzer_findings"])
        self.assertTrue(any("boom" in e for e in status["errors"]))

    def test_a_fatal_runner_error_keeps_the_records_it_had_already_read(self):
        fatal = boto_client.AwsFatal(
            "credentials", "region=eu-west-1: AWS rejected the credentials",
            partial=[{"FindingId": "gd-1"}, {"FindingId": "gd-2"}],
        )
        data, status = self._collect({
            "guardduty_findings": fatal,
            "accessanalyzer_findings": [],
            "iam_principals": [{"ResourceName": "root"}],
        })
        self.assertEqual(len(data["AWS.GuardDuty"]), 2)
        self.assertEqual(status["sources_failed"], ["guardduty_findings"])
        self.assertTrue(any("Keeping 2 record(s)" in e for e in status["errors"]))

    def test_an_unknown_requested_source_is_an_error_not_a_shrug(self):
        collectors._stub_collect = self._saved[2]
        data, status = collectors.collect_aws_logs(
            run_id="r", aws_config={}, sources=["cloudtrail_s3_dataevents"], cloudtrail_mode="full",
        )
        self.assertEqual(data, {})
        self.assertTrue(any("Unknown source" in e for e in status["errors"]), status["errors"])


class NoSilentDegradation(_PipelineHarness):
    def test_a_blueprints_declared_severity_floor_is_actually_used(self):
        # Full Investigation declares informational; nothing used to read it.
        bp = next(b for b in pipeline.get_aws_blueprints() if b["id"] == "aws_full_investigation")
        eff, declared = pipeline._resolve_min_severity({}, bp, bp["settings"])
        self.assertEqual(declared, "informational")
        self.assertEqual(eff, "informational")

    def test_an_explicit_request_still_wins_but_is_recorded_as_a_downgrade(self):
        bp = next(b for b in pipeline.get_aws_blueprints() if b["id"] == "aws_full_investigation")

        def collect(**kw):
            return ({"AWS.IAM": [{"ResourceName": "root", "severity": "high"}]},
                    {"errors": [], "sources_attempted": ["iam_principals"],
                     "sources_with_data": ["iam_principals"], "sources_failed": []})

        res = self.run_pipeline(
            preflight_result={"ok": True, "kind": "", "message": "", "account": "1", "arn": "a"},
            blueprint=bp, options={"min_severity": "high"}, collect=collect,
        )
        self.assertTrue(any("informational+ floor" in d and "high+" in d for d in res["degraded"]),
                        res.get("degraded"))

    def test_a_full_cloudtrail_blueprint_run_in_light_mode_says_what_it_dropped(self):
        bp = next(b for b in pipeline.get_aws_blueprints() if b["id"] == "aws_full_investigation")
        seen = {}

        def collect(**kw):
            seen.update(kw)
            return ({"AWS.CloudTrail": [{"eventName": "ConsoleLogin"}]},
                    {"errors": [], "sources_attempted": ["cloudtrail_console"],
                     "sources_with_data": ["cloudtrail_console"], "sources_failed": []})

        res = self.run_pipeline(
            preflight_result={"ok": True, "kind": "", "message": "", "account": "1", "arn": "a"},
            blueprint=bp, options={"cloudtrail_mode": "light"}, collect=collect,
        )
        self.assertEqual(seen["cloudtrail_mode"], "light")
        self.assertTrue(any("cloudtrail_full source is not collected" in d for d in res["degraded"]),
                        res.get("degraded"))

    def test_the_blueprints_own_cloudtrail_mode_applies_when_none_is_requested(self):
        bp = next(b for b in pipeline.get_aws_blueprints() if b["id"] == "aws_full_investigation")
        seen = {}

        def collect(**kw):
            seen.update(kw)
            return ({"AWS.CloudTrail": [{"eventName": "x"}]},
                    {"errors": [], "sources_attempted": [], "sources_with_data": [], "sources_failed": []})

        res = self.run_pipeline(
            preflight_result={"ok": True, "kind": "", "message": "", "account": "1", "arn": "a"},
            blueprint=bp, options={}, collect=collect,
        )
        self.assertEqual(seen["cloudtrail_mode"], "full")
        # (the SIGMA-rules note is always present here: the harness stubs
        # load_aws_rules to []. Only the CloudTrail downgrade must be absent.)
        self.assertFalse([d for d in res.get("degraded", []) if "cloudtrail" in d.lower()])

    def test_zero_sigma_rules_marks_detection_degraded_instead_of_complete(self):
        def collect(**kw):
            return ({"AWS.CloudTrail": [{"eventName": "ConsoleLogin"}]},
                    {"errors": [], "sources_attempted": ["cloudtrail_console"],
                     "sources_with_data": ["cloudtrail_console"], "sources_failed": []})

        # load_aws_rules is stubbed to [] by the harness — the empty-AWS-subtree
        # case that validate_rules_directory() cannot see because it checks the
        # AZURE path.
        res = self.run_pipeline(
            preflight_result={"ok": True, "kind": "", "message": "", "account": "1", "arn": "a"},
            collect=collect,
        )
        self.assertEqual(res["phases"]["detection"]["status"], "degraded")
        self.assertTrue(any("ZERO rules" in d for d in res["degraded"]), res.get("degraded"))


class DemoDataCanNeverPassAsEvidence(unittest.TestCase):
    def test_fixtures_are_off_unless_explicitly_switched_on(self):
        saved = os.environ.pop(collectors._DEMO_FIXTURES_ENV, None)
        try:
            self.assertFalse(collectors.demo_fixtures_enabled())
            os.environ[collectors._DEMO_FIXTURES_ENV] = "1"
            self.assertTrue(collectors.demo_fixtures_enabled())
        finally:
            os.environ.pop(collectors._DEMO_FIXTURES_ENV, None)
            if saved is not None:
                os.environ[collectors._DEMO_FIXTURES_ENV] = saved

    def test_with_fixtures_off_a_dead_source_reports_zero_not_demo_records(self):
        saved = os.environ.pop(collectors._DEMO_FIXTURES_ENV, None)
        lines = []
        try:
            out = collectors._stub_collect("guardduty_findings", lambda m, l="info": lines.append((l, m)))
        finally:
            if saved is not None:
                os.environ[collectors._DEMO_FIXTURES_ENV] = saved
        self.assertEqual(out, [])
        self.assertTrue(any("demo fixtures are off" in m for _l, m in lines))

    def test_every_fixture_record_is_stamped_synthetic(self):
        os.environ[collectors._DEMO_FIXTURES_ENV] = "1"
        try:
            out = collectors._stub_collect("guardduty_findings", lambda m, l="info": None)
        finally:
            os.environ.pop(collectors._DEMO_FIXTURES_ENV, None)
        self.assertTrue(out, "guardduty fixture is empty — this test proves nothing")
        self.assertTrue(all(r.get(collectors.SYNTHETIC_KEY) for r in out))


class EveryImportedSdkIsDeclared(unittest.TestCase):
    """boto3 was imported by four runners and declared by no requirements file.

    is_available() answers "boto3 not installed: ..." when it is missing, every
    source falls through to the (opt-in, therefore empty) fixture path, and the
    run reports "No data collected" — indistinguishable from a clean account.
    The AWS online mode was supported on paper only, exactly like the Gemini
    provider requirements-agentic.txt was written to stop happening again.
    """

    BACKEND = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "modules/backend")

    def test_boto3_is_imported_by_the_aws_runners(self):
        # Guards the test itself: if the imports move, the check below is moot.
        importers = []
        aws_dir = os.path.join(self.BACKEND, "services/aws")
        for fn in sorted(os.listdir(aws_dir)):
            if not fn.endswith(".py"):
                continue
            with open(os.path.join(aws_dir, fn), encoding="utf-8") as fh:
                if "import boto3" in fh.read():
                    importers.append(fn)
        self.assertTrue(importers, "nothing imports boto3 any more — drop this test")

    def test_boto3_is_declared_in_a_requirements_file(self):
        declared = []
        for fn in sorted(os.listdir(self.BACKEND)):
            if fn.startswith("requirements") and fn.endswith(".txt"):
                with open(os.path.join(self.BACKEND, fn), encoding="utf-8") as fh:
                    for line in fh:
                        line = line.split("#", 1)[0].strip()
                        if line.lower().startswith("boto3"):
                            declared.append(f"{fn}: {line}")
        self.assertTrue(declared, "boto3 is imported but installed by nothing — "
                                  "every live AWS collector silently reports zero records")


if __name__ == "__main__":
    unittest.main(verbosity=2)
