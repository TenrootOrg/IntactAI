#!/usr/bin/env python3
"""Live AWS SIGMA checks — real backend API calls against the live stack.

Covers modules/backend/routes/aws_routes.py: status/blueprint/source/rule
reads, custom-rule CRUD, the offline upload -> analyze -> read-coverage ->
delete pipeline, and (conditionally) the online POST /api/aws/scan path.
REQUIRES_MODULE("aws_sigma") gates every check here as a matter of this
suite's design intent — note that, unlike CVE Scan's `_module_check()` or
Azure's `is_module_enabled('o365rc')` calls, aws_routes.py itself does NOT
actually gate any of its routes on `modules.aws_sigma.enabled` (confirmed:
no `is_module_enabled` import/call anywhere in the file). The routes work
regardless of the flag; we still gate client-side so this file degrades to
a clean SKIP rather than a confusing FAIL on an install where the operator
disabled the module for UI purposes only.

check_aws_upload_analyze is lifted from tests/live_smoke.py's
check_aws_sigma, with two real fixes made after actually RUNNING it against
the live stack (not just reading the plan doc):

  1. POST /api/aws/upload requires a genuine multipart file — confirmed by
     reading aws_routes.py:395 (`if 'files' not in request.files and
     'file' not in request.files: return 400`). live_smoke.py's JSON body
     `{"files": [{"filename":..., "content":...}]}` does NOT work against
     the real route (empirically confirmed: 400 "No files provided" — the
     handler never looks at request.json at all). This check uses
     `requests` directly with a real multipart part instead.
  2. It now calls _lib.synthetic_cloudtrail_event() instead of the inline
     dict live_smoke.py had — same fixture, identical shape, moved to the
     shared module.

DELETE /api/aws/runs/<id> is AWS's own dedicated delete route (unlike most
run types in this backend, which only die via the LiveCase cascade — see
_lib.py's LiveCase docstring). check_aws_upload_analyze exercises it
directly as an independent confirmation the route itself works, so that
particular run is deliberately NOT also attached to a LiveCase (double-
attaching a run that's independently deleted would just make the case's
cleanup a harmless no-op on exit, but it muddies which mechanism actually
did the deleting). Deletion is confirmed via GET /api/aws/runs (the
in-memory run list) rather than a follow-up GET on the run's own read
endpoints — DELETE only clears the in-memory `_aws_runs` entry and the
upload directory, NOT the persisted `/app/data/aws_runs/<run_id>.json`
snapshot, so GET /api/aws/results|status|findings/<run_id> keep serving
that snapshot even after a successful delete (confirmed empirically: a
GET on those endpoints returns 200 with the old data post-delete). That's
a real, minor gap in the route worth knowing about — not a bug in this
test, so we don't assert against it.

check_aws_online_scan only actually calls POST /api/aws/scan when a fresh
read of GET /api/aws/status shows `aws_credentials.configured == false` —
in that state the route runs its documented stub-collector fallback
(fixture data, no real AWS calls; confirmed by GET /api/aws/status's own
`"note": "Collectors are currently stub fixtures..."` and by actually
running a scan in that state: it completes in seconds with fixture
findings). If real credentials ARE configured, this check is skipped
rather than risking a real account-wide scan.

NOT part of run_all.py's sweep, and not meant to run on every change —
invoke it by name, manually, only when asked:

    docker exec intact_backend python3 /app/workdir/tests/live/test_aws_sigma.py
"""
import json
import sys

import requests

from _lib import (
    BASE,
    TIMEOUT,
    REQUIRES_MODULE,
    Skip,
    _delete,
    _get,
    _post,
    poll_run,
    require_module,
    synthetic_cloudtrail_event,
    tagged,
)


CUSTOM_RULE_TEMPLATE = """title: {title}
id: {rule_id}
status: experimental
description: Harmless live-test SIGMA rule — matches an eventName that never occurs in real CloudTrail data.
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventName: '_livetest_never_matches_anything__{rule_id}'
    condition: selection
level: informational
"""


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def _aws_creds_configured():
    s = _get("/api/aws/status")
    if s.status_code != 200:
        # Fail safe: if we can't even read status, don't assume it's safe to
        # fire an online scan.
        return True, s
    return bool((s.json().get("aws_credentials") or {}).get("configured")), s


def check_aws_status_reads():
    creds_configured, s = _aws_creds_configured()
    if s.status_code != 200:
        return False, f"GET /api/aws/status -> {s.status_code}: {s.text[:300]}"
    status = s.json()

    bp = _get("/api/aws/blueprints")
    if bp.status_code != 200:
        return False, f"GET /api/aws/blueprints -> {bp.status_code}: {bp.text[:300]}"
    if not bp.json().get("blueprints"):
        return False, f"no blueprints returned: {bp.text[:300]}"

    src = _get("/api/aws/sources")
    if src.status_code != 200:
        return False, f"GET /api/aws/sources -> {src.status_code}: {src.text[:300]}"

    rules = _get("/api/aws/rules")
    if rules.status_code != 200:
        return False, f"GET /api/aws/rules -> {rules.status_code}: {rules.text[:300]}"

    return True, (
        f"status={status.get('status')} aws_credentials.configured={creds_configured} "
        f"({'stub-collector fallback active' if not creds_configured else 'real credentials present'}) "
        f"blueprints={len(bp.json().get('blueprints', []))} sources={len(src.json().get('sources', []))} "
        f"aws_rules_count={rules.json().get('aws_rules_count')} custom_rules_count={rules.json().get('custom_rules_count')}"
    )


def check_aws_custom_rule_crud():
    rule_id = tagged("aws-rule")
    filename = f"{rule_id}.yml"
    yaml_text = CUSTOM_RULE_TEMPLATE.format(title=rule_id, rule_id=rule_id)

    r = _post("/api/aws/rules/custom", {"filename": filename, "content": yaml_text})
    if r.status_code != 200 or not r.json().get("success"):
        return False, f"POST /api/aws/rules/custom -> {r.status_code}: {r.text[:300]}"
    saved_filename = r.json().get("filename") or filename

    try:
        g = _get("/api/aws/rules/custom")
        if g.status_code != 200:
            return False, f"GET /api/aws/rules/custom -> {g.status_code}: {g.text[:300]}"
        names = [x.get("filename") for x in g.json().get("rules", [])]
        if saved_filename not in names:
            return False, f"created rule {saved_filename!r} not present in list: {names}"
    finally:
        d = _delete(f"/api/aws/rules/custom/{saved_filename}")

    if d.status_code != 200:
        return False, f"DELETE /api/aws/rules/custom/{saved_filename} -> {d.status_code}: {d.text[:300]}"

    g2 = _get("/api/aws/rules/custom")
    names2 = [x.get("filename") for x in g2.json().get("rules", [])] if g2.status_code == 200 else None
    if names2 is not None and saved_filename in names2:
        return False, f"deleted rule {saved_filename!r} still present after DELETE: {names2}"

    return True, f"filename={saved_filename} create -> list -> delete -> list round-trip OK"


def check_aws_upload_analyze():
    event = synthetic_cloudtrail_event()
    content = json.dumps({"Records": [event]}).encode()
    files = {"files": ("cloudtrail_test.json", content, "application/json")}
    up = requests.post(f"{BASE}/api/aws/upload", files=files, timeout=TIMEOUT)
    if up.status_code != 200:
        return False, f"POST /api/aws/upload -> {up.status_code}: {up.text[:300]}"
    run_id = up.json().get("run_id")
    if not run_id:
        return False, f"no run_id from upload: {up.text[:300]}"

    an = _post("/api/aws/analyze-offline", {"run_id": run_id, "min_severity": "informational"})
    if an.status_code != 200:
        return False, f"POST /api/aws/analyze-offline -> {an.status_code}: {an.text[:300]}"

    final, transitions = poll_run(run_id, timeout_seconds=60)
    if final.get("status") != "completed":
        return False, f"run {run_id} ended as '{final.get('status')}' (transitions: {transitions})"

    f = _get(f"/api/aws/findings/{run_id}")
    if f.status_code != 200:
        return False, f"GET /api/aws/findings/{run_id} -> {f.status_code}: {f.text[:300]}"
    findings = f.json()

    res = _get(f"/api/aws/results/{run_id}")
    if res.status_code != 200:
        return False, f"GET /api/aws/results/{run_id} -> {res.status_code}: {res.text[:300]}"

    ana = _get(f"/api/aws/analysis/{run_id}")
    if ana.status_code != 200:
        return False, f"GET /api/aws/analysis/{run_id} -> {ana.status_code}: {ana.text[:300]}"

    dl = _get(f"/api/aws/data/{run_id}/download")
    if dl.status_code != 200 or not dl.content:
        return False, f"GET /api/aws/data/{run_id}/download -> {dl.status_code}, {len(dl.content)} bytes"

    # Independent confirmation of AWS's own dedicated delete route — this run
    # is intentionally never attached to a LiveCase (see module docstring).
    d = _delete(f"/api/aws/runs/{run_id}")
    if d.status_code != 200:
        return False, f"DELETE /api/aws/runs/{run_id} -> {d.status_code}: {d.text[:300]}"

    lst = _get("/api/aws/runs")
    if lst.status_code == 200 and any(x.get("run_id") == run_id for x in lst.json().get("runs", [])):
        return False, f"run {run_id} still present in /api/aws/runs after DELETE"

    return True, (
        f"run_id={run_id} findings_total={findings.get('total_findings')} "
        f"results_records={res.json().get('total_records')} download_bytes={len(dl.content)} "
        f"deleted+confirmed via /api/aws/runs"
    )


def check_aws_online_scan():
    creds_configured, s = _aws_creds_configured()
    if s.status_code != 200:
        return False, f"GET /api/aws/status -> {s.status_code}: {s.text[:300]}"
    if creds_configured:
        raise Skip("real AWS credentials configured - live /scan not exercised by this suite")

    r = _post("/api/aws/scan", {
        "scope_mode": "account_wide",
        "blueprint": "aws_quick_triage",
        "min_severity": "informational",
    })
    if r.status_code != 200:
        return False, f"POST /api/aws/scan -> {r.status_code}: {r.text[:300]}"
    run_id = r.json().get("run_id")
    if not run_id:
        return False, f"no run_id in response: {r.text[:300]}"

    final, transitions = poll_run(run_id, timeout_seconds=90)
    # An online scan with NO credentials must fail, not "complete".
    #
    # It used to complete, because every collector fell back to bundled demo
    # fixtures — attack-shaped records engineered to fire SIGMA. The run was
    # persisted as mode=online with no marker, and its fictional IPs became
    # global ioc:ip nodes in any Case that fused it. This check asserted that
    # behaviour, so it was pinning the bug in place.
    status = final.get("status")
    _delete(f"/api/aws/runs/{run_id}")
    if status != "failed":
        return False, (f"scan without credentials ended as '{status}' — it must fail "
                       f"rather than report invented findings (transitions: {transitions})")
    err = str(final.get("error") or "")
    if "credential" not in err.lower():
        return False, f"failed for the wrong reason: {err[:200]}"
    return True, f"run_id={run_id} correctly failed closed: {err[:80]}"


CHECKS = [
    ("aws_status_reads", REQUIRES_MODULE("aws_sigma"), check_aws_status_reads),
    ("aws_custom_rule_crud", REQUIRES_MODULE("aws_sigma"), check_aws_custom_rule_crud),
    ("aws_upload_analyze", REQUIRES_MODULE("aws_sigma"), check_aws_upload_analyze),
    ("aws_online_scan", REQUIRES_MODULE("aws_sigma"), check_aws_online_scan),
]


def main():
    passed = failed = skipped = 0
    for name, risk, fn in CHECKS:
        print(f"\n--- {name} ---", flush=True)
        try:
            if risk.startswith("REQUIRES_MODULE:"):
                require_module(risk.split(":", 1)[1])
            ok, detail = fn()
        except Skip as e:
            print(f"[SKIP] {name}: {e}", flush=True)
            skipped += 1
            continue
        except Exception as e:
            ok, detail = False, f"unhandled exception: {e}"
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}", flush=True)
        if ok:
            passed += 1
        else:
            failed += 1

    print(f"\n=== {passed} passed, {failed} failed, {skipped} skipped ===", flush=True)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
