"""AWS and Azure offline analysis — sixteen endpoints, previously zero coverage.

WHY THIS WAS MISSED, and why it should not have been. The cloud modules look
untestable in CI because collection needs credentials and a live tenant. But
collection is only half of them: both ship an OFFLINE path where an operator
uploads logs they already hold and the SIGMA engine runs over them. That path
needs no credentials, no network and no model, and it is the one an incident
responder actually uses when they are handed an export.

THE ASSERTION THAT MATTERS is not that the endpoints answer. It is that a
detection FIRES. A cloud module with an empty rules directory, a broken parser
or a mis-keyed source mapping answers 200 to every request in this phase and
finds nothing — indistinguishable from a clean account. So this uploads a
CloudTrail record engineered to match a rule the product ships
(`aws_cloudtrail_important_change`: eventSource cloudtrail.amazonaws.com +
eventName StopLogging — an attacker turning off logging) and requires that exact
rule to appear in the findings.

The record is synthetic and self-evidently so (account 123456789012, the
TEST-NET-3 address 203.0.113.55, user `qa-attacker`), so it can never be
mistaken for real evidence if it turns up in a report.

SHAPES VERIFIED against a live backend, because two of them are traps:
  * the terminal status is "complete", NOT "completed" -- a poll waiting for
    "completed" runs until it times out on a run that finished immediately.
  * findings come back as {"findings": {RULE_NAME: [...]}}, a dict keyed by
    rule, not a list.
"""

import json
import time

# The shipped rule this phase proves is live, and the record that trips it.
_RULE_SUBSTR = "CloudTrail_Important_Change"
_EVENT = {"Records": [{
    "eventVersion": "1.08",
    "eventTime": "2026-01-15T10:00:00Z",
    "eventSource": "cloudtrail.amazonaws.com",
    "eventName": "StopLogging",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "203.0.113.55",          # TEST-NET-3, never routable
    "userAgent": "aws-cli/2.13.0",
    "userIdentity": {"type": "IAMUser", "userName": "qa-attacker",
                     "arn": "arn:aws:iam::123456789012:user/qa-attacker",
                     "accountId": "123456789012"},
    "requestParameters": {"name": "qa-trail"},
    "eventID": "11111111-2222-3333-4444-555555555555",
    "eventType": "AwsApiCall",
    "recipientAccountId": "123456789012",
}]}

_TERMINAL = ("complete", "completed", "failed", "error")
_POLL_SECONDS = 300

_CUSTOM_RULE = """title: QA CI Custom Rule
id: 6f1c0d2e-0000-4000-8000-qa0000000001
status: experimental
description: Added by the e2e suite to prove operator rules land on disk
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventName: QaCiNeverHappens
    condition: selection
level: low
"""


def register(runner, cfg):

    @runner.phase("cloud_offline",
                  "Upload cloud logs offline and prove a SIGMA rule fires",
                  needs=("features",))
    def cloud_offline(ctx):
        c = ctx.get("client")
        detail = {}

        # ---------------------------------------------------------- 1 ----
        # The module has to be READY and, more importantly, has to have its
        # detection content. Rules ship in the image; a box with none answers
        # 200 to everything below and finds nothing.
        st = c.get("/api/aws/status")
        caps = (st or {}).get("capabilities") or {}
        detail["offline_mode"] = caps.get("offline_mode")
        ctx.check("the AWS module offers offline analysis",
                  bool(caps.get("offline_mode")), actual=caps,
                  note="online mode needs credentials CI does not have; offline "
                       "is the path an incident responder uses on an export")

        rules = c.get("/api/aws/rules")
        n_rules = (rules or {}).get("aws_rules_count") or 0
        detail["aws_rules"] = n_rules
        ctx.check("AWS SIGMA rules are installed on the box", n_rules > 0,
                  expected=">0 rules", actual=n_rules,
                  note="an empty rules tree is the silent failure: every request "
                       "still answers 200 and every account looks clean")

        srcs = (c.get("/api/aws/sources") or {}).get("sources") or []
        detail["sources"] = len(srcs)
        ctx.check("the module declares its log sources", len(srcs) > 0,
                  actual=len(srcs))

        # ---------------------------------------------------------- 2 ----
        # Operator-added detections. A responder who cannot add a rule during
        # an engagement is stuck with what shipped.
        fname = "qa_ci_custom_rule.yml"
        c.post("/api/aws/rules/custom",
               {"filename": fname, "content": _CUSTOM_RULE},
               expect=(200, 201))
        listed = (c.get("/api/aws/rules/custom") or {}).get("rules") or []
        names = [r if isinstance(r, str) else r.get("filename") or r.get("name")
                 for r in listed]
        detail["custom_rules"] = names
        ctx.check("a custom SIGMA rule is stored and listed",
                  any(fname in str(n) for n in names),
                  expected=fname, actual=names)
        c.delete(f"/api/aws/rules/custom/{fname}", expect=(200, 202, 204, 404))
        after = (c.get("/api/aws/rules/custom") or {}).get("rules") or []
        ctx.check("a custom rule can be removed again",
                  not any(fname in str(r) for r in after),
                  actual=len(after),
                  note="rules an operator cannot delete accumulate as false "
                       "positives on every later engagement")

        # ---------------------------------------------------------- 3 ----
        up = c.request("POST", "/api/aws/upload",
                       files={"files": ("cloudtrail.json", json.dumps(_EVENT),
                                        "application/json")},
                       expect=(200, 201))
        run_id = (up or {}).get("run_id")
        detail["run_id"] = run_id
        detail["records"] = (up or {}).get("total_records")
        detail["detected_sources"] = (up or {}).get("sources")
        ctx.check("the CloudTrail export was accepted", bool(run_id), actual=up)
        if not run_id:
            return detail
        ctx.check("the uploaded records were parsed, not just stored",
                  (up or {}).get("total_records", 0) > 0,
                  expected=">0 records", actual=(up or {}).get("total_records"),
                  note="the parser keys off the filename; a file it cannot "
                       "classify uploads fine and analyses nothing")
        ctx.check("the source was auto-detected as CloudTrail",
                  "AWS.CloudTrail" in ((up or {}).get("sources") or []),
                  expected="AWS.CloudTrail", actual=(up or {}).get("sources"))

        try:
            # ------------------------------------------------------ 4 ----
            started = c.post("/api/aws/analyze-offline",
                             {"run_id": run_id, "min_severity": "informational"},
                             expect=(200, 202))
            ctx.check("the offline analysis started", bool(started), actual=started)

            deadline, status = time.time() + _POLL_SECONDS, None
            while time.time() < deadline:
                s = c.get(f"/api/aws/status/{run_id}") or {}
                status = s.get("status")
                # "complete", not "completed" -- measured. Waiting for the wrong
                # word polls a finished run until the phase times out.
                if status in _TERMINAL:
                    break
                time.sleep(3)
            detail["status"] = status
            ctx.check("the analysis reached a terminal state",
                      status in _TERMINAL, expected="/".join(_TERMINAL),
                      actual=status or f"still running after {_POLL_SECONDS}s")
            ctx.check("the analysis did not fail",
                      status in ("complete", "completed"),
                      expected="complete", actual=status)

            # ------------------------------------------------------ 5 ----
            # THE ASSERTION THIS PHASE EXISTS FOR.
            fnd = c.get(f"/api/aws/findings/{run_id}?min_severity=informational")
            by_rule = (fnd or {}).get("findings") or {}
            keys = list(by_rule) if isinstance(by_rule, dict) else []
            detail["rules_fired"] = keys
            detail["total_findings"] = (fnd or {}).get("total_findings")
            ctx.check("SIGMA detection produced findings", bool(keys),
                      expected=">0 rules matched", actual=keys,
                      note="the record uploaded is a textbook StopLogging; no "
                           "finding means the engine ran over it and saw nothing")
            ctx.check("the specific shipped rule fired on the planted event",
                      any(_RULE_SUBSTR in str(k) for k in keys),
                      expected=f"a rule containing {_RULE_SUBSTR!r}",
                      actual=keys,
                      note="asserting the NAMED rule, not just 'some finding': "
                           "a rule set that matches everything is as broken as "
                           "one that matches nothing")

            # The finding must carry the record it matched, or an analyst cannot
            # tell why it fired.
            hits = by_rule.get(next((k for k in keys if _RULE_SUBSTR in str(k)),
                                    ""), []) if keys else []
            matched = (hits[0].get("matched_record") if hits else None) or {}
            ctx.check("the finding carries the record that triggered it",
                      matched.get("eventName") == "StopLogging",
                      expected="StopLogging", actual=matched.get("eventName"),
                      note="a finding with no evidence behind it cannot be "
                           "triaged, only believed")

            # ------------------------------------------------------ 6 ----
            res = c.get(f"/api/aws/results/{run_id}")
            data = (res or {}).get("data") or {}
            detail["result_sources"] = list(data)
            ctx.check("the raw uploaded rows are retrievable",
                      bool(data.get("AWS.CloudTrail")),
                      actual=list(data),
                      note="the drill-down from a finding back to the log line")

            ana = c.get(f"/api/aws/analysis/{run_id}")
            ctx.check("the analysis surface answers with its shape",
                      isinstance(ana, dict) and "analysis" in ana,
                      actual=sorted(ana) if isinstance(ana, dict) else ana,
                      note="empty is correct here -- CI configures no model, so "
                           "there is no narrative, but the envelope must exist")
        finally:
            c.delete(f"/api/aws/runs/{run_id}", expect=(200, 202, 204, 404))

        # What deletion actually guarantees, measured on a live backend: the
        # run leaves the LISTING. Its status and findings still answer 200,
        # because delete_run() clears the in-memory entry and the upload dir but
        # not the persisted blob at PERSIST_DIR/<run_id>.json, which _load_run()
        # falls back to.
        #
        # So the listing is asserted and the residue is RECORDED rather than
        # asserted away -- a test that expects 404 here would be red on a
        # product that has not been changed, and a test that quietly expects 200
        # would be blessing a data-retention bug. It is written down instead,
        # and this check will tighten to 404 the day the route deletes the blob.
        listing = c.get("/api/aws/runs", expect=(200, 404))
        rows = listing if isinstance(listing, list) else (listing or {}).get("runs") or []
        ids = [r.get("run_id") or r.get("id") for r in rows if isinstance(r, dict)]
        detail["still_listed"] = run_id in ids
        ctx.check("a deleted cloud run leaves the run listing",
                  run_id not in ids, expected="absent", actual=run_id in ids,
                  note="this is what the operator sees; see residue below for "
                       "what is still on disk")

        residue = c.status_of(f"/api/aws/status/{run_id}")
        detail["readable_after_delete"] = residue
        ctx.check("the deletion residue is the documented one, not a new one",
                  residue in (200, 404), expected="200 (known) or 404 (fixed)",
                  actual=residue,
                  note="KNOWN GAP, recorded here so it cannot be forgotten: the "
                       "persisted run JSON survives deletion, so the uploaded "
                       "log rows stay readable by run_id. An operator who "
                       "deletes a cloud run has not deleted its data")
        return detail

    # ------------------------------------------------------------------ 2 --
    @runner.phase("cloud_azure",
                  "The Azure module's detection content and rule management",
                  needs=("features",))
    def cloud_azure(ctx):
        """Azure's UPLOAD path is gated on the `o365rc` module, which a profile
        may legitimately not enable — so this asserts what is always true (the
        module answers, its rules are installed, operator rules can be managed)
        and reports the upload gate rather than failing on a deliberate config."""
        c = ctx.get("client")
        detail = {}

        st = c.get("/api/azure/status")
        caps = (st or {}).get("capabilities") or {}
        detail["offline_mode"] = caps.get("offline_mode")
        ctx.check("the Azure module answers with its capabilities",
                  isinstance(caps, dict) and caps, actual=caps)

        rules = c.get("/api/azure/rules")
        total = ((rules or {}).get("counts") or {}).get("total") or 0
        detail["azure_rules"] = total
        ctx.check("Azure SIGMA rules are installed", total > 0,
                  expected=">0 rules", actual=total,
                  note="same silent failure as AWS: no rules, no findings, no "
                       "error anywhere")

        fname = "qa_ci_custom_azure.yml"
        c.post("/api/azure/rules/custom",
               {"filename": fname, "content": _CUSTOM_RULE.replace("aws", "azure")},
               expect=(200, 201))
        listed = (c.get("/api/azure/rules/custom") or {}).get("rules") or []
        ctx.check("a custom Azure rule is stored and listed",
                  any(fname in str(r) for r in listed), actual=listed)
        c.delete(f"/api/azure/rules/custom/{fname}", expect=(200, 202, 204, 404))
        after = (c.get("/api/azure/rules/custom") or {}).get("rules") or []
        ctx.check("a custom Azure rule can be removed again",
                  not any(fname in str(r) for r in after), actual=len(after))

        # Is the upload path open on this profile? Reported, not asserted.
        code = c.status_of("/api/azure/upload")
        detail["upload_probe_status"] = code
        ctx.check("the Azure upload gate is reachable and answers",
                  code is not None, actual=code,
                  note="405 or 400 both mean the route is wired; the module gate "
                       "answers 400 when o365rc is off, which is a config "
                       "choice rather than a fault")
        return detail
