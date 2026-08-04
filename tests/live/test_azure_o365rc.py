#!/usr/bin/env python3
"""Live Azure / o365rc checks — real backend API calls against the live stack.

Covers modules/backend/routes/azure_routes.py: status/blueprint/source/rule
reads, custom-rule CRUD, the offline upload -> analyze -> read-coverage ->
delete pipeline, and (conditionally) the online POST /api/azure/scan path.

Module gating here is NOT uniform across the file — verified by reading
azure_routes.py directly rather than trusting the plan doc's "offline path
is always available regardless of tenant" claim at face value:

  - get_azure_status/get_blueprints/get_sources/get_rules_info and the
    custom-rule CRUD routes never call `is_module_enabled` at all — they
    work with o365rc disabled, so azure_status_reads and
    azure_custom_rule_crud are SAFE (ungated) here.
  - POST /api/azure/upload DOES gate on it — the very first line of
    upload_logs() is `if not is_module_enabled('o365rc'): return
    jsonify({...}), 400` (azure_routes.py:380-381). So
    azure_upload_analyze is REQUIRES_MODULE("o365rc"), unlike AWS's
    equivalent upload route, which has no such check at all. The plan
    doc's "always available regardless of tenant" claim is true of
    *tenant credentials* (analyze-offline never touches `_load_cloud_config`
    for creds), but false of the module-enabled flag — those are two
    different gates and only the credentials one is actually absent here.
  - POST /api/azure/scan's background thread re-checks
    `is_module_enabled('o365rc')` a second time (azure_routes.py:266) on
    top of requiring real tenant_id/client_id credentials, so
    azure_online_scan is also REQUIRES_MODULE("o365rc").

check_azure_upload_analyze mirrors check_aws_upload_analyze
(tests/live/test_aws_sigma.py) but for Azure: uses
_lib.synthetic_azure_signin_event() and real multipart (confirmed the same
way as AWS — POST /api/azure/upload requires `request.files`, a JSON body
gets rejected before request.json is ever read). DELETE /api/azure/runs/<id>
is Azure's own dedicated delete route (mirrors AWS's), so this run is
deliberately NOT also attached to a LiveCase — see test_aws_sigma.py's
docstring for the reasoning. Deletion is confirmed via GET /api/azure/runs
(the in-memory list) for the same reason as AWS: DELETE clears the
in-memory `_azure_runs` entry and the upload dir but not the persisted
`/app/data/azure_runs/<run_id>.json` snapshot, so the per-run read
endpoints keep serving it after a successful delete (confirmed
empirically) — a real, minor gap in the route, not a bug in this test.

check_azure_online_scan checks GET /api/azure/status first. Unlike AWS,
Azure has NO stub-collector fallback for the online path — with no real
tenant_id/client_id configured, the background thread fails cleanly with
"Azure credentials not configured" (confirmed empirically) rather than
running against fixture data. That's still safe to exercise for real (it
never reaches any real Azure API), so when status reports no credentials
configured, this check asserts the endpoint reaches exactly that clean
failure — a genuine negative-path regression check — rather than skipping
outright. If real credentials ARE configured, the check is skipped instead
of risking a real tenant-wide scan.

NOT part of run_all.py's sweep, and not meant to run on every change —
invoke it by name, manually, only when asked:

    docker exec intact_backend python3 /app/workdir/tests/live/test_azure_o365rc.py
"""
import json
import sys

import requests

from _lib import (
    BASE,
    TIMEOUT,
    SAFE,
    REQUIRES_MODULE,
    Skip,
    _delete,
    _get,
    _post,
    poll_run,
    require_module,
    synthetic_azure_signin_event,
    tagged,
)


CUSTOM_RULE_TEMPLATE = """title: {title}
id: {rule_id}
status: experimental
description: Harmless live-test SIGMA rule — matches a userPrincipalName that never occurs in real sign-in data.
logsource:
    product: azure
    service: signinlogs
detection:
    selection:
        userPrincipalName: '_livetest_never_matches_anything__{rule_id}'
    condition: selection
level: informational
"""


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def _azure_creds_configured():
    s = _get("/api/azure/status")
    if s.status_code != 200:
        return True, s  # fail safe: don't assume it's safe to fire an online scan
    return bool((s.json().get("azure_credentials") or {}).get("configured")), s


def check_azure_status_reads():
    creds_configured, s = _azure_creds_configured()
    if s.status_code != 200:
        return False, f"GET /api/azure/status -> {s.status_code}: {s.text[:300]}"
    status = s.json()

    bp = _get("/api/azure/blueprints")
    if bp.status_code != 200:
        return False, f"GET /api/azure/blueprints -> {bp.status_code}: {bp.text[:300]}"
    if not bp.json().get("blueprints"):
        return False, f"no blueprints returned: {bp.text[:300]}"

    src = _get("/api/azure/sources")
    if src.status_code != 200:
        return False, f"GET /api/azure/sources -> {src.status_code}: {src.text[:300]}"

    rules = _get("/api/azure/rules")
    if rules.status_code != 200:
        return False, f"GET /api/azure/rules -> {rules.status_code}: {rules.text[:300]}"

    return True, (
        f"status={status.get('status')} azure_credentials.configured={creds_configured} "
        f"({'no stub fallback — /scan will cleanly fail' if not creds_configured else 'real credentials present'}) "
        f"blueprints={len(bp.json().get('blueprints', []))} sources={len(src.json().get('sources', []))} "
        f"rules_available={rules.json().get('available')} custom_rules_count={rules.json().get('custom_rules_count')}"
    )


def check_azure_custom_rule_crud():
    rule_id = tagged("azure-rule")
    filename = f"{rule_id}.yml"
    yaml_text = CUSTOM_RULE_TEMPLATE.format(title=rule_id, rule_id=rule_id)

    r = _post("/api/azure/rules/custom", {"filename": filename, "content": yaml_text})
    if r.status_code != 200 or not r.json().get("success"):
        return False, f"POST /api/azure/rules/custom -> {r.status_code}: {r.text[:300]}"
    saved_filename = r.json().get("filename") or filename

    try:
        g = _get("/api/azure/rules/custom")
        if g.status_code != 200:
            return False, f"GET /api/azure/rules/custom -> {g.status_code}: {g.text[:300]}"
        names = [x.get("filename") for x in g.json().get("rules", [])]
        if saved_filename not in names:
            return False, f"created rule {saved_filename!r} not present in list: {names}"
    finally:
        d = _delete(f"/api/azure/rules/custom/{saved_filename}")

    if d.status_code != 200:
        return False, f"DELETE /api/azure/rules/custom/{saved_filename} -> {d.status_code}: {d.text[:300]}"

    g2 = _get("/api/azure/rules/custom")
    names2 = [x.get("filename") for x in g2.json().get("rules", [])] if g2.status_code == 200 else None
    if names2 is not None and saved_filename in names2:
        return False, f"deleted rule {saved_filename!r} still present after DELETE: {names2}"

    return True, f"filename={saved_filename} create -> list -> delete -> list round-trip OK"


def check_azure_upload_analyze():
    event = synthetic_azure_signin_event()
    content = json.dumps({"value": [event]}).encode()
    files = {"files": ("signin_test.json", content, "application/json")}
    up = requests.post(f"{BASE}/api/azure/upload", files=files, timeout=TIMEOUT)
    if up.status_code != 200:
        return False, f"POST /api/azure/upload -> {up.status_code}: {up.text[:300]}"
    run_id = up.json().get("run_id")
    if not run_id:
        return False, f"no run_id from upload: {up.text[:300]}"

    an = _post("/api/azure/analyze-offline", {"run_id": run_id, "min_severity": "informational"})
    if an.status_code != 200:
        return False, f"POST /api/azure/analyze-offline -> {an.status_code}: {an.text[:300]}"

    final, transitions = poll_run(run_id, timeout_seconds=60)
    if final.get("status") != "completed":
        return False, f"run {run_id} ended as '{final.get('status')}' (transitions: {transitions})"

    f = _get(f"/api/azure/findings/{run_id}")
    if f.status_code != 200:
        return False, f"GET /api/azure/findings/{run_id} -> {f.status_code}: {f.text[:300]}"
    findings = f.json()

    res = _get(f"/api/azure/results/{run_id}")
    if res.status_code != 200:
        return False, f"GET /api/azure/results/{run_id} -> {res.status_code}: {res.text[:300]}"

    ana = _get(f"/api/azure/analysis/{run_id}")
    if ana.status_code != 200:
        return False, f"GET /api/azure/analysis/{run_id} -> {ana.status_code}: {ana.text[:300]}"

    dl = _get(f"/api/azure/data/{run_id}/download")
    if dl.status_code != 200 or not dl.content:
        return False, f"GET /api/azure/data/{run_id}/download -> {dl.status_code}, {len(dl.content)} bytes"

    # Independent confirmation of Azure's own dedicated delete route — this
    # run is intentionally never attached to a LiveCase (see module docstring).
    d = _delete(f"/api/azure/runs/{run_id}")
    if d.status_code != 200:
        return False, f"DELETE /api/azure/runs/{run_id} -> {d.status_code}: {d.text[:300]}"

    lst = _get("/api/azure/runs")
    if lst.status_code == 200 and any(x.get("run_id") == run_id for x in lst.json().get("runs", [])):
        return False, f"run {run_id} still present in /api/azure/runs after DELETE"

    return True, (
        f"run_id={run_id} findings_total={findings.get('total_findings')} "
        f"results_records={res.json().get('total_records')} download_bytes={len(dl.content)} "
        f"deleted+confirmed via /api/azure/runs"
    )


def check_azure_online_scan():
    creds_configured, s = _azure_creds_configured()
    if s.status_code != 200:
        return False, f"GET /api/azure/status -> {s.status_code}: {s.text[:300]}"
    if creds_configured:
        raise Skip("real Azure credentials configured - live /scan not exercised by this suite")

    r = _post("/api/azure/scan", {
        "scope_mode": "tenant_wide",
        "blueprint": "azure_quick_triage",
        "min_severity": "informational",
    })
    if r.status_code != 200:
        return False, f"POST /api/azure/scan -> {r.status_code}: {r.text[:300]}"
    run_id = r.json().get("run_id")
    if not run_id:
        return False, f"no run_id in response: {r.text[:300]}"

    # No stub fallback for Azure (see module docstring): with no tenant
    # credentials configured, the correct/expected outcome is a clean
    # 'failed' with a credentials-not-configured reason, not 'completed'.
    final, transitions = poll_run(run_id, timeout_seconds=60)
    d = _delete(f"/api/azure/runs/{run_id}")
    if final.get("status") != "failed":
        return False, (
            f"expected a clean 'failed' (no credentials configured) outcome; "
            f"got '{final.get('status')}' (transitions: {transitions})"
        )
    err = (final.get("error") or "").lower()
    if "credential" not in err:
        return False, f"run failed, but not for the expected reason (no credentials): {final.get('error')!r}"

    return True, f"run_id={run_id} correctly failed cleanly with no real credentials: {final.get('error')!r} cleanup_status={d.status_code}"


CHECKS = [
    ("azure_status_reads", SAFE, check_azure_status_reads),
    ("azure_custom_rule_crud", SAFE, check_azure_custom_rule_crud),
    ("azure_upload_analyze", REQUIRES_MODULE("o365rc"), check_azure_upload_analyze),
    ("azure_online_scan", REQUIRES_MODULE("o365rc"), check_azure_online_scan),
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
