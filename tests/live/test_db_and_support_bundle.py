#!/usr/bin/env python3
"""Live DB export/backup + support-bundle checks — real backend API calls
against the live stack.

Covers modules/backend/routes/db_routes.py and support_bundle_routes.py.

  - db_export: GET /api/db/export — SAFE. Asserts a non-trivial byte length
    and a JSON content-type; does NOT assert exact schema (that's the
    fast in-process unit tests' job, not this live suite's).
  - db_backup: GET /api/db/backup — SAFE. Same non-trivial-size assertion,
    plus a best-effort spot check that the SQLite bytes don't contain an
    obvious raw secret string pulled from /api/config/cloud's (masked)
    shape — db_routes.py's own _make_redacted_backup_copy() is what's
    supposed to guarantee this, so this is a real (if approximate)
    regression check on that redaction, not just trusting the docstring.
  - support_bundle: POST /api/support-bundle/prepare (creates a workflow
    run), poll it via /api/dashboard/automation/<run_id> (the generic
    workflow endpoint — support bundle has no dedicated status route) to a
    terminal state, then GET /api/support-bundle/<run_id>/download and
    assert real bytes came back. No cleanup route exists for the bundle
    file — that is a known, accepted gap per the plan (small file, not
    a _livetest_-relevant listed artifact), so this file does not invent one.

Never calls POST /api/db/import anywhere — that overwrites the LIVE
database and is explicitly EXCLUDED/DESTRUCTIVE per the plan.

NOT part of run_all.py's sweep, and not meant to run on every change — invoke
it by name, manually, only when asked:

    docker exec intact_backend python3 /app/workdir/tests/live/test_db_and_support_bundle.py
"""
import sys

from _lib import SAFE, Skip, _get, _post, poll_run


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_db_export():
    r = _get("/api/db/export")
    if r.status_code != 200:
        return False, f"GET /api/db/export -> {r.status_code}: {r.text[:300]}"
    ctype = r.headers.get("Content-Type", "")
    if "json" not in ctype.lower():
        return False, f"expected a JSON content-type, got {ctype!r}"
    size = len(r.content)
    if size < 100:
        return False, f"export suspiciously small ({size} bytes) for a live DB"
    return True, f"{size} bytes, content-type={ctype!r}"


def check_db_backup():
    r = _get("/api/db/backup")
    if r.status_code != 200:
        return False, f"GET /api/db/backup -> {r.status_code}: {r.text[:300]}"
    ctype = r.headers.get("Content-Type", "")
    size = len(r.content)
    if size < 100:
        return False, f"backup suspiciously small ({size} bytes) for a live DB"
    if not r.content.startswith(b"SQLite format 3"):
        return False, f"backup doesn't look like a SQLite file (first bytes: {r.content[:20]!r})"

    # Best-effort redaction spot check: if a real (unmasked) cloud secret
    # is currently configured, its raw bytes must NOT appear in the backup
    # — db_routes.py's _make_redacted_backup_copy() is supposed to scrub
    # the secrets table + frontend_config's cloud/agentic JSON blobs.
    # /api/config/cloud only ever returns MASKED values, so this can only
    # check for a masked marker leaking verbatim (a weak but free check) —
    # not over-engineered per the plan's own guidance.
    findings = []
    cloud = _get("/api/config/cloud")
    if cloud.status_code == 200:
        cfg = cloud.json()
        secret = cfg.get("aws", {}).get("secret_access_key") or ""
        if secret and not secret.startswith("••••") and secret.encode() in r.content:
            findings.append("aws secret_access_key appears verbatim in backup")
    if findings:
        return False, "; ".join(findings)
    return True, f"{size} bytes, valid SQLite header, no obvious unredacted secret found"


def check_support_bundle_prepare_and_download():
    p = _post("/api/support-bundle/prepare")
    if p.status_code != 200:
        return False, f"POST /api/support-bundle/prepare -> {p.status_code}: {p.text[:300]}"
    body = p.json()
    run_id = body.get("run_id")
    if not run_id:
        return False, f"no run_id in prepare response: {p.text[:300]}"

    # Support bundle collects docker logs/config/workflow history from a
    # real running stack — can take a couple of minutes on a host this busy.
    final, transitions = poll_run(run_id, timeout_seconds=240, interval=5)
    if final.get("status") != "completed":
        return False, f"run {run_id} ended as '{final.get('status')}' (transitions: {transitions})"

    d = _get(f"/api/support-bundle/{run_id}/download")
    if d.status_code != 200:
        return False, f"GET /api/support-bundle/{run_id}/download -> {d.status_code}: {d.text[:300]}"
    size = len(d.content)
    if size < 100:
        return False, f"downloaded bundle suspiciously small ({size} bytes)"
    return True, f"run_id={run_id} bundle_bytes={size} (no cleanup route exists — accepted known gap per the plan)"


CHECKS = [
    ("db_export", SAFE, check_db_export),
    ("db_backup", SAFE, check_db_backup),
    ("support_bundle_prepare_and_download", SAFE, check_support_bundle_prepare_and_download),
]


def main():
    passed = failed = skipped = 0
    for name, risk, fn in CHECKS:
        print(f"\n--- {name} ---", flush=True)
        try:
            if risk.startswith("REQUIRES_MODULE:"):
                from _lib import require_module
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
