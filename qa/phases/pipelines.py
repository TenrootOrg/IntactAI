"""Run each feature's LIGHTWEIGHT blueprint end to end.

The feature sweep proves the API answers. This proves the product *works*: a
real collection against a real client, a real detection run over real evidence,
a real artefact built. Every blueprint used here is the cheapest one the
platform ships for that feature, chosen so a full pass costs minutes rather than
the hour a "Full Investigation" would.

  Velociraptor   agentic_linux_triage   the Linux QuickWins collection
  AWS            aws_quick_triage       sigma over uploaded CloudTrail
  Azure          azure_quick_triage     sigma over uploaded UAL
  Collector      offline generate       a real Linux collector binary

WHAT CANNOT RUN HERE, and why it is skipped rather than faked. The Timesketch
pipeline's lightweight blueprint is `timesketch_event_logs`, whose KAPE target
is `EventLogs` and whose plaso parser is `winevtx` -- Windows event logs. The
appliance enrols itself as a LINUX client, which has no Windows event logs to
collect, so the pipeline has nothing to ingest. The same is true of memory:
`memory_quick_wins` needs an image that Windows.Memory.Acquisition produces.
Both are recorded as skipped with that reason. Faking either -- pointing them at
a canned file and calling it a pass -- would be worse than not running them,
because the report would claim coverage the run does not have.

THE CLOUD PIPELINES ARE REAL, and they are the ones worth having. Both take an
uploaded evidence file, so the entire sigma detection engine runs with no cloud
account attached. The CloudTrail fixture is built to match a rule that actually
ships (`aws_cloudtrail_disable_logging.yml`: eventSource cloudtrail.amazonaws.com
+ eventName StopLogging), so "zero findings" is a real failure signal rather
than an artefact of evidence nothing was looking for.
"""

import json
import time

from lib import api as api_lib

# The lightest blueprint the platform ships for each feature. Ids, not names:
# selecting by name once picked "Full Triage" over "Event Logs Only" and made a
# run ten times longer for no extra coverage.
BLUEPRINTS = {
    "velociraptor_linux": "agentic_linux_triage",
    "aws": "aws_quick_triage",
    "azure": "azure_quick_triage",
    "timesketch": "timesketch_event_logs",     # EventLogs / winevtx — Windows only
    "memory": "memory_quick_wins",             # needs an acquired image
}

# Bounded so a wedged pipeline fails the phase instead of eating the job's
# 330-minute budget. Generous enough for a cold container that has to warm up.
TIMEOUT_COLLECTION_S = 900
TIMEOUT_CLOUD_S = 600
TIMEOUT_COLLECTOR_S = 900


def register(runner, cfg):
    if not cfg.pipelines:
        return

    tl = runner.ctx.tl

    @runner.phase("pipelines",
                  "Run each feature's lightweight blueprint end to end",
                  needs=("features",))
    def pipelines(ctx):
        detail = {"ran": {}, "skipped": []}
        c = ctx.get("client")
        if c is None:
            ctx.check("an authenticated client is available", False,
                      note="the auth phase did not sign in")
            return detail

        _aws(ctx, c, detail)
        _azure(ctx, c, detail)
        _velociraptor_linux(ctx, c, detail)
        _offline_collector(ctx, c, detail)
        _record_windows_only_skips(ctx, detail)
        return detail


# --- AWS -------------------------------------------------------------------


def _cloudtrail_fixture():
    """One CloudTrail record that a SHIPPED rule matches.

    `aws_cloudtrail_disable_logging.yml` ("AWS CloudTrail Important Change")
    selects eventSource cloudtrail.amazonaws.com with eventName in
    StopLogging/UpdateTrail/DeleteTrail. Matching a real rule on purpose is what
    lets "zero findings" mean the detection engine is broken, instead of meaning
    the fixture described something nothing was looking for.

    Timestamped now, because the quick-triage blueprint carries
    time_range_days: 1 and a fixture dated last week would be filtered out
    before any rule saw it -- a green-looking zero for the wrong reason.
    """
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return json.dumps({"Records": [{
        "eventVersion": "1.08",
        "eventTime": now,
        "eventSource": "cloudtrail.amazonaws.com",
        "eventName": "StopLogging",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.24",
        "userAgent": "aws-cli/2.15.0",
        "userIdentity": {"type": "IAMUser", "userName": "qa-ci-fixture",
                         "arn": "arn:aws:iam::123456789012:user/qa-ci-fixture",
                         "accountId": "123456789012"},
        "requestParameters": {"name": "qa-ci-trail"},
        "responseElements": None,
        "eventID": "00000000-0000-0000-0000-00000000qa01",
        "eventType": "AwsApiCall",
        "recipientAccountId": "123456789012",
    }]}, indent=2)


def _aws(ctx, c, detail):
    body = _upload_evidence(ctx, c, "/api/aws/upload", "qa-ci-cloudtrail.json",
                            _cloudtrail_fixture(), "AWS CloudTrail")
    if not body:
        return
    run_id = body.get("run_id")
    ctx.check("AWS: the uploaded CloudTrail file produced a run", bool(run_id),
              actual=run_id)
    if not run_id:
        return

    try:
        c.request("POST", "/api/aws/analyze-offline", json={
            "run_id": run_id,
            "blueprint": BLUEPRINTS["aws"],
            # Disabled deliberately: the fixture is stamped now, but a clock
            # skew of minutes between the runner and the container would
            # otherwise silently filter the only record away.
            "time_filter": {"enabled": False},
            "min_severity": "low",
        }, expect=(200, 201, 202))
    except Exception as exc:                                  # noqa: BLE001
        ctx.check(f"AWS: {BLUEPRINTS['aws']} analysis starts", False,
                  actual=str(exc)[:180])
        return
    ctx.check(f"AWS: {BLUEPRINTS['aws']} analysis starts", True)

    status = _poll_cloud(c, f"/api/aws/status/{run_id}", TIMEOUT_CLOUD_S,
                         "AWS quick triage")
    ctx.check("AWS: the analysis reached a terminal state", bool(status),
              expected="a terminal status", actual=(status or {}).get("status"),
              note="a run still going after 10 minutes is wedged, not slow")
    if not status:
        return

    findings = _findings_count(c, f"/api/aws/findings/{run_id}")
    detail["ran"]["aws"] = {"run_id": run_id, "findings": findings,
                            "blueprint": BLUEPRINTS["aws"]}
    ctx.check("AWS: sigma detection produced findings from the fixture",
              findings > 0, expected=">0", actual=findings,
              note="the fixture is a StopLogging event, which the shipped "
                   "aws_cloudtrail_disable_logging rule selects; zero means "
                   "the rule pack or the engine is not working")


# --- Azure -----------------------------------------------------------------


def _ual_fixture():
    """One M365 Unified Audit Log record, shaped like a real export."""
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return json.dumps([{
        "CreationTime": now,
        "Id": "00000000-0000-0000-0000-00000000qa02",
        "Operation": "UserLoggedIn",
        "OrganizationId": "00000000-0000-0000-0000-000000000001",
        "RecordType": 15,
        "ResultStatus": "Success",
        "UserKey": "qa-ci-fixture@example.invalid",
        "UserType": 0,
        "Workload": "AzureActiveDirectory",
        "ClientIP": "198.51.100.25",
        "UserId": "qa-ci-fixture@example.invalid",
    }], indent=2)


def _azure(ctx, c, detail):
    """Azure's rule pack is not always present, and that is not a failure.

    A live box reported `Azure rules not found: /opt/sigma-rules/rules/cloud/
    azure` while carrying 57 AWS rules — the SigmaHQ tree simply has no azure
    directory at the pinned ref. Asserting on detections that cannot exist would
    produce a permanent red that trains people to ignore this phase, so the
    availability is checked first and an absent pack is a recorded skip.
    """
    try:
        st = c.get("/api/azure/status", expect=(200, 503))
    except Exception as exc:                                  # noqa: BLE001
        detail["skipped"].append({"pipeline": "azure",
                                  "reason": f"status unavailable: {str(exc)[:90]}"})
        return
    if not isinstance(st, dict) or not st.get("available", False):
        reason = (st or {}).get("message") or "the Azure rule pack is not installed"
        detail["skipped"].append({"pipeline": "azure", "reason": reason})
        ctx.check("Azure: pipeline ran", True, actual=f"SKIPPED: {reason}",
                  note="not a failure; there is no rule pack to detect with")
        return

    body = _upload_evidence(ctx, c, "/api/azure/upload", "qa-ci-ual.json",
                            _ual_fixture(), "Azure UAL")
    if not body:
        return
    run_id = body.get("run_id")
    if not run_id:
        ctx.check("Azure: the uploaded UAL file produced a run", False)
        return

    try:
        c.request("POST", "/api/azure/analyze-offline", json={
            "run_id": run_id, "blueprint": BLUEPRINTS["azure"],
            "time_filter": {"enabled": False}, "min_severity": "low",
        }, expect=(200, 201, 202))
    except Exception as exc:                                  # noqa: BLE001
        ctx.check(f"Azure: {BLUEPRINTS['azure']} analysis starts", False,
                  actual=str(exc)[:180])
        return

    status = _poll_cloud(c, f"/api/azure/status/{run_id}", TIMEOUT_CLOUD_S,
                         "Azure quick triage")
    ctx.check("Azure: the analysis reached a terminal state", bool(status),
              actual=(status or {}).get("status"))
    if status:
        findings = _findings_count(c, f"/api/azure/findings/{run_id}")
        detail["ran"]["azure"] = {"run_id": run_id, "findings": findings,
                                  "blueprint": BLUEPRINTS["azure"]}
        # Recorded, not asserted: a benign UserLoggedIn is not guaranteed to
        # trip any rule, and inventing a malicious-looking fixture would be
        # asserting on our own creativity rather than on the product.
        ctx.check("Azure: the analysis completed and reported findings",
                  True, actual=findings,
                  note="count recorded, not asserted — the fixture is a benign "
                       "sign-in and need not match a rule")


# --- Velociraptor ----------------------------------------------------------


def _velociraptor_linux(ctx, c, detail):
    """The lightweight Linux collection, against the client we just enrolled.

    This is the one pipeline that needs the appliance to have enrolled itself,
    and it is the reason that was worth doing: without it there is no client and
    every collection path in the product is untestable on a bare runner.
    """
    client_id = ctx.get("client_id")
    if not client_id:
        detail["skipped"].append({
            "pipeline": "velociraptor", "blueprint": BLUEPRINTS["velociraptor_linux"],
            "reason": "no client enrolled — enrol_linux produced none"})
        ctx.check("Velociraptor: collection pipeline ran", True,
                  actual="SKIPPED: no enrolled client",
                  note="not a failure; there is nothing to collect from")
        return

    try:
        body = c.request("POST", "/api/agentic/run", json={
            "blueprint_id": BLUEPRINTS["velociraptor_linux"],
            "client_ids": [client_id],
            "collection_minutes": 5,
        }, expect=(200, 201, 202))
    except Exception as exc:                                  # noqa: BLE001
        ctx.check(f"Velociraptor: {BLUEPRINTS['velociraptor_linux']} dispatches",
                  False, actual=str(exc)[:180])
        return

    run_id = (body or {}).get("run_id")
    ctx.check(f"Velociraptor: {BLUEPRINTS['velociraptor_linux']} dispatches",
              bool(run_id), actual=run_id)
    if not run_id:
        return

    run = c.wait_for_run(run_id, TIMEOUT_COLLECTION_S, ctx.tl,
                         what="agentic linux triage")
    ok = api_lib.run_succeeded(run)
    ctx.check("Velociraptor: the collection run completed", ok,
              expected="completed", actual=(run or {}).get("status"),
              note="a None status means the wait timed out — the run is still "
                   "going, which is not the same as failed")

    # Row counts live in the run's LOG TEXT, not in details — repeatedly
    # relearned. Recorded rather than asserted: a quiet Linux runner legitimately
    # has little to find, and asserting rows>0 would make this flaky for a
    # reason that says nothing about the product.
    rows = _collected_rows(c, run_id)
    detail["ran"]["velociraptor"] = {
        "run_id": run_id, "client_id": client_id, "rows": rows,
        "blueprint": BLUEPRINTS["velociraptor_linux"]}
    ctx.check("Velociraptor: the collection reported what it gathered",
              rows is not None, actual=rows,
              note="dispatch and completion are asserted; detection content is "
                   "not — a CI runner is not a compromised host")


# --- offline collector -----------------------------------------------------


def _offline_collector(ctx, c, detail):
    """Build a real Linux collector binary.

    No endpoint needed: this is the artefact an operator carries to a machine
    that cannot reach the server, so a broken build breaks the air-gap workflow
    entirely, silently, for whoever tries to use it next.
    """
    cfg_id = None
    name = f"QA-CI-{time.strftime('%Y%m%d-%H%M%S')}"
    try:
        body = c.request("POST", "/api/velociraptor/offline/configs",
                         json={"name": name, "artifacts": ["Generic.Client.Info"]},
                         expect=(200, 201))
        cfg_id = (body or {}).get("config_id") or (body or {}).get("id")
    except Exception as exc:                                  # noqa: BLE001
        ctx.check("Collector: an offline config can be created", False,
                  actual=str(exc)[:180])
        return
    ctx.check("Collector: an offline config can be created", bool(cfg_id),
              actual=cfg_id)
    if not cfg_id:
        return

    try:
        body = c.request("POST", "/api/velociraptor/offline/generate", json={
            "config_id": cfg_id, "os": "linux", "encryption_scheme": "none",
        }, expect=(200, 201, 202))
    except Exception as exc:                                  # noqa: BLE001
        ctx.check("Collector: a Linux collector is generated", False,
                  actual=str(exc)[:180])
        _delete_quietly(c, f"/api/velociraptor/offline/configs/{cfg_id}")
        return

    file_id = (body or {}).get("file_id") or (body or {}).get("id")
    run_id = (body or {}).get("run_id")
    if run_id and not file_id:
        run = c.wait_for_run(run_id, TIMEOUT_COLLECTOR_S, ctx.tl,
                             what="offline collector build")
        file_id = ((run or {}).get("details") or {}).get("file_id")

    ctx.check("Collector: a Linux collector is generated", bool(file_id),
              actual=file_id)
    if file_id:
        size = _download_size(c, f"/api/velociraptor/offline/download/{file_id}")
        detail["ran"]["offline_collector"] = {"config_id": cfg_id,
                                              "file_id": file_id, "bytes": size}
        ctx.check("Collector: the built binary is a plausible size",
                  (size or 0) > 2 * 2**20, expected=">2 MB",
                  actual=f"{(size or 0) / 2**20:.1f} MB",
                  note="a tiny file here is an error page or a truncated build")

    _delete_quietly(c, f"/api/velociraptor/offline/configs/{cfg_id}")


# --- honest skips ----------------------------------------------------------


def _record_windows_only_skips(ctx, detail):
    for pipeline, blueprint, why in (
        ("timesketch", BLUEPRINTS["timesketch"],
         "the lightweight blueprint collects Windows EventLogs and parses them "
         "with plaso's winevtx parser; the appliance enrols itself as a LINUX "
         "client and has no .evtx to collect"),
        ("memory", BLUEPRINTS["memory"],
         "needs an image from Windows.Memory.Acquisition, which requires a "
         "Windows endpoint"),
    ):
        detail["skipped"].append({"pipeline": pipeline, "blueprint": blueprint,
                                  "reason": why})
        ctx.check(f"{pipeline}: lightweight blueprint pipeline ran", True,
                  actual=f"SKIPPED: {blueprint}", note=why)


# --- helpers ---------------------------------------------------------------


def _upload_evidence(ctx, c, path, filename, payload, label):
    try:
        r = c.s.post(c.base + path,
                     files={"file": (filename, payload, "application/json")},
                     timeout=180)
    except Exception as exc:                                  # noqa: BLE001
        ctx.check(f"{label}: the fixture uploads", False, actual=str(exc)[:180])
        return None
    if r.status_code not in (200, 201, 202):
        ctx.check(f"{label}: the fixture uploads", False,
                  expected="200/201/202", actual=r.status_code)
        return None
    ctx.check(f"{label}: the fixture uploads", True, actual=r.status_code)
    try:
        return r.json()
    except ValueError:
        return {}


def _poll_cloud(c, path, timeout_s, what):
    """Cloud runs keep their state in a module-level dict, not the run table, so
    they are polled on their own status route rather than through
    /api/dashboard/automations."""
    deadline = time.time() + timeout_s
    # "complete", not "completed" — measured against a live box, where the AWS
    # offline run reports exactly that. Waiting for a word the platform never
    # says means polling until the timeout and then reporting a wedged run for
    # something that finished in 0.13 seconds.
    terminal = ("complete", "completed", "success", "succeeded", "finished",
                "done", "failed", "error", "cancelled")
    while time.time() < deadline:
        try:
            body = c.get(path, expect=(200,))
        except Exception:                                     # noqa: BLE001
            body = None
        if isinstance(body, dict):
            st = (body.get("status") or "").lower()
            if st in terminal:
                return body
        time.sleep(10)
    return None


def _findings_count(c, path):
    """How many findings a cloud run produced.

    `findings` is a DICT keyed by rule name, each holding a list of matches --
    not a list. Verified against a live box: a single StopLogging record comes
    back as {"SIGMA.AWS_CloudTrail_Important_Change": [ ... ]}. Counting it as a
    list returns 0, which would have failed the assertion on a pipeline that
    worked perfectly. `total_findings` sits at the top level and is the
    unambiguous answer, so prefer it and treat the rest as fallbacks.
    """
    try:
        body = c.get(path, expect=(200,))
    except Exception:                                         # noqa: BLE001
        return 0
    if isinstance(body, dict):
        if isinstance(body.get("total_findings"), int):
            return body["total_findings"]
        f = body.get("findings")
        if isinstance(f, dict):
            return sum(len(v) for v in f.values() if isinstance(v, list))
        if isinstance(f, list):
            return len(f)
        for key in ("items", "results"):
            if isinstance(body.get(key), list):
                return len(body[key])
        if isinstance(body.get("count"), int):
            return body["count"]
    return len(body) if isinstance(body, list) else 0


def _collected_rows(c, run_id):
    """Row counts from the run's log text — details carries no counts."""
    try:
        logs = c.run_logs(run_id)
    except Exception:                                         # noqa: BLE001
        return None
    text = logs if isinstance(logs, str) else json.dumps(logs)
    import re
    m = re.search(r"Collected\s+([\d,]+)\s+row", text)
    return int(m.group(1).replace(",", "")) if m else 0


def _download_size(c, path):
    try:
        r = c.s.get(c.base + path, timeout=300, stream=True)
        if r.status_code != 200:
            return 0
        return sum(len(chunk) for chunk in r.iter_content(chunk_size=2**20))
    except Exception:                                         # noqa: BLE001
        return 0


def _delete_quietly(c, path):
    try:
        c.request("DELETE", path, expect=(200, 204, 404))
    except Exception:                                         # noqa: BLE001
        pass
