#!/usr/bin/env python3
"""Live upgrade (read-only / planning-only) checks — real backend API calls
against the live stack.

Covers modules/backend/routes/upgrade_routes.py — the highest-consequence
area of this whole suite to get wrong, since the file it lives in also
holds the real apply/prepare/upload machinery that mirrors source over the
running install, loads container images, and rewrites config.yaml. Every
check in THIS file was individually re-verified against the actual handler
source (not just the plan doc) before being added:

  - GET  /api/upgrade/current-versions — reads get_current_versions(); no
    writes.
  - GET  /api/upgrade/quota            — reads a cached GitHub rate-limit
    state; no writes.
  - GET  /api/upgrade/status           — reads get_latest_versions(); no
    writes (the route's own except-clause even downgrades a query failure
    to success=false/200 rather than ever mutating anything).
  - POST /api/upgrade/list-packages    — os.listdir() over the two
    allowlisted package dirs + os.stat() per entry; no writes.
  - POST /api/upgrade/refs             — GitHub API read (list releases/
    branches), 30-min in-process cache; no local writes.
  - POST /api/upgrade/plan             — compute_plan() diffs a target ref
    against locally-installed versions; no writes. Needs a real, currently
    resolvable target — this file fetches /refs first and feeds plan the
    first ref it returns rather than hardcoding a branch name (a
    hardcoded "development" 404s against GitHub on this box: only the
    release tag is currently resolvable here).
  - POST /api/upgrade/package-info     — reads a tarball's manifest.json;
    gated by the same _reject_package_path() allowlist as every other
    package_path-accepting route. Exercised here with an out-of-allowlist
    path (expected 400, not a crash) — no in-allowlist package currently
    exists on this host to try a real read against (see list-packages'
    result), so no positive-path call is made.
  - POST /api/upgrade/peek-manifest    — parses the FIRST few MB of a
    tarball blob the caller posts directly in the request body; pure
    in-memory parsing, no filesystem writes at all. Exercised with
    deliberately-invalid bytes (never a real package) to confirm it fails
    gracefully (200, success:false) rather than 500ing.
  - POST /api/upgrade/preflight        — the route's own docstring states
    it "changes NOTHING... never mirrors source, loads an image, writes
    config.yaml, or touches a container" and the handler
    (services/upgrade/__init__.py:preflight_package) was read line-by-line
    to confirm: it extracts the tarball to a scratch dir under
    /app/data/tmp and DELETES that scratch dir before returning; every
    check it runs (verify_upgrade_package, _reject_downgrades,
    preflight_environment, ensure_backend_runtime_image's precondition
    check) is read-only. Called twice: once with a deliberately-nonexistent
    package_path (confirmed: returns 200 with ok:false, not a crash —
    the negative path), and once for real ONLY if list-packages already
    shows a real package on disk from prior operator activity (this suite
    never uploads one itself) — otherwise that half is a documented Skip.

Never calls, anywhere in this file or this whole suite:
    POST /api/upgrade/offline
    POST /api/upgrade/online
    POST /api/upgrade/prepare
    POST /api/upgrade/upload-run
These are the routes that actually mirror source, load images, and rewrite
config.yaml over the running install — DESTRUCTIVE per the plan, excluded
by construction (not even imported/referenced here).

NOT part of run_all.py's sweep, and not meant to run on every change — invoke
it by name, manually, only when asked:

    docker exec intact_backend python3 /app/workdir/tests/live/test_upgrade_readonly.py
"""
import sys

import requests

from _lib import BASE, SAFE, TIMEOUT, Skip, _get, _post


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_current_versions():
    r = _get("/api/upgrade/current-versions")
    if r.status_code != 200:
        return False, f"GET /api/upgrade/current-versions -> {r.status_code}: {r.text[:300]}"
    body = r.json()
    if not body.get("success"):
        return False, f"success=false: {str(body)[:300]}"
    versions = body.get("versions")
    if not isinstance(versions, dict) or not versions:
        return False, f"expected a non-empty 'versions' dict: {str(body)[:300]}"
    return True, f"{len(versions)} module(s): {versions}"


def check_quota():
    r = _get("/api/upgrade/quota")
    if r.status_code != 200:
        return False, f"GET /api/upgrade/quota -> {r.status_code}: {r.text[:300]}"
    body = r.json()
    # Fail-open by design: success=false just means the rate-limit endpoint
    # was unreachable, which is itself a valid (if less useful) outcome.
    if not body.get("success"):
        return True, f"rate-limit endpoint unreachable (fail-open, not a failure): {str(body)[:200]}"
    for key in ("remaining", "limit", "reset_hm", "authed"):
        if key not in body:
            return False, f"expected {key!r} in response: {str(body)[:300]}"
    return True, f"remaining={body['remaining']}/{body['limit']} authed={body['authed']}"


def check_status():
    r = _get("/api/upgrade/status")
    if r.status_code != 200:
        return False, f"GET /api/upgrade/status -> {r.status_code}: {r.text[:300]}"
    body = r.json()
    if not body.get("success"):
        return True, f"success=false (route's own fail-open path, still 200): {str(body)[:200]}"
    versions = body.get("versions")
    if not isinstance(versions, dict) or not versions:
        return False, f"expected a non-empty 'versions' dict: {str(body)[:300]}"
    return True, f"{len(versions)} module(s) reporting a latest version"


def check_list_packages():
    r = _post("/api/upgrade/list-packages", {})
    if r.status_code != 200:
        return False, f"POST /api/upgrade/list-packages -> {r.status_code}: {r.text[:300]}"
    body = r.json()
    if not body.get("success"):
        return False, f"success=false: {str(body)[:300]}"
    packages = body.get("packages")
    if not isinstance(packages, list):
        return False, f"expected 'packages' to be a list: {str(body)[:300]}"
    return True, f"{len(packages)} package(s) on disk in the allowlisted dirs"


def _fetch_refs():
    """Shared helper — POST /api/upgrade/refs, return (refs_list, error_or_None)."""
    r = _post("/api/upgrade/refs", {})
    if r.status_code != 200:
        return None, f"POST /api/upgrade/refs -> {r.status_code}: {r.text[:300]}"
    body = r.json()
    if not body.get("success"):
        return None, f"success=false: {str(body)[:300]}"
    refs = body.get("refs")
    if not isinstance(refs, list) or not refs:
        return None, f"expected a non-empty 'refs' list: {str(body)[:300]}"
    return refs, None


def check_refs():
    refs, err = _fetch_refs()
    if err:
        return False, err
    kinds = sorted({r.get("kind") for r in refs})
    return True, f"{len(refs)} ref(s): kinds={kinds}, first={refs[0].get('name')!r}"


def check_plan():
    # A hardcoded "development" target 404s against GitHub on this box —
    # only the release tag is currently resolvable here. Feed plan a real,
    # currently-listed ref instead of guessing a branch name.
    refs, err = _fetch_refs()
    if err:
        return False, f"could not resolve a target to plan against: {err}"
    target = refs[0]["name"]

    r = _post("/api/upgrade/plan", {"target": target})
    if r.status_code != 200:
        return False, f"POST /api/upgrade/plan target={target!r} -> {r.status_code}: {r.text[:300]}"
    body = r.json()
    if not body.get("success"):
        return False, f"success=false: {str(body)[:300]}"
    plan = body.get("plan") or {}
    if "forced" not in plan or "optional" not in plan:
        return False, f"expected 'forced'/'optional' rows in plan: {str(plan)[:300]}"
    return True, (
        f"target={target!r} forced={len(plan['forced'])} row(s) "
        f"optional={len(plan['optional'])} row(s)"
    )


def check_package_info_rejects_outside_allowlist():
    r = _post("/api/upgrade/package-info", {"package_path": "/etc/passwd"})
    if r.status_code != 400:
        return False, f"expected 400 for an out-of-allowlist path, got {r.status_code}: {r.text[:300]}"
    body = r.json()
    err = str(body.get("error", "")).lower()
    if "/data/uploads" not in err and "/data/upgrade_packages" not in err:
        return False, f"400 body doesn't explain the allowlist rejection: {str(body)[:300]}"
    return True, f"out-of-allowlist package_path correctly rejected: {body.get('error')!r}"


def check_peek_manifest_graceful_on_garbage():
    # Deliberately not a real tarball — proves the parser fails gracefully
    # (200, success:false) rather than 500ing on malformed input. Pure
    # in-memory parsing; nothing is written to disk by this route.
    # Raw-bytes body, not JSON — bypass _lib's json-only _post wrapper.
    r = requests.post(
        f"{BASE}/api/upgrade/peek-manifest",
        data=b"this-is-not-a-gzip-tarball-livetest",
        headers={"Content-Type": "application/octet-stream"},
        timeout=TIMEOUT,
    )
    if r.status_code not in (200, 400):
        return False, f"unexpected status for garbage input: {r.status_code}: {r.text[:300]}"
    body = r.json()
    if body.get("success"):
        return False, f"expected success=false for garbage bytes, got: {str(body)[:300]}"
    return True, f"garbage bytes handled gracefully (status={r.status_code}): {body.get('error')!r}"


def check_preflight_negative_and_optional_positive():
    # --- Negative path: a nonexistent package_path inside the allowlist,
    # confirmed above (by reading services/upgrade/__init__.py:preflight_package)
    # to return 200 with ok:false rather than crashing. ---
    neg = _post("/api/upgrade/preflight", {
        "package_path": "/data/uploads/_livetest_nonexistent_pkg_do_not_create.tar.gz",
    })
    if neg.status_code != 200:
        return False, f"negative-path preflight -> {neg.status_code}: {neg.text[:300]}"
    neg_body = neg.json()
    if neg_body.get("ok") is not False:
        return False, f"expected ok:false for a nonexistent package, got: {str(neg_body)[:300]}"

    # --- Optional positive path: only if a REAL package already exists on
    # disk from prior operator activity (this suite never uploads one). ---
    packages_resp = _post("/api/upgrade/list-packages", {})
    packages = (packages_resp.json() or {}).get("packages") or [] if packages_resp.status_code == 200 else []
    if not packages:
        raise Skip("no existing upgrade package found to preflight-check")

    real_path = packages[0]["path"]
    pos = _post("/api/upgrade/preflight", {"package_path": real_path})
    if pos.status_code != 200:
        return False, f"positive-path preflight ({real_path}) -> {pos.status_code}: {pos.text[:300]}"
    pos_body = pos.json()
    if "ok" not in pos_body or "checks" not in pos_body:
        return False, f"expected 'ok'/'checks' in positive-path response: {str(pos_body)[:300]}"
    return True, (
        f"negative path correctly ok:false; positive path against real package "
        f"{real_path!r} -> ok={pos_body.get('ok')}, {len(pos_body.get('checks') or [])} check(s) run"
    )


CHECKS = [
    ("upgrade_current_versions", SAFE, check_current_versions),
    ("upgrade_quota", SAFE, check_quota),
    ("upgrade_status", SAFE, check_status),
    ("upgrade_list_packages", SAFE, check_list_packages),
    ("upgrade_refs", SAFE, check_refs),
    ("upgrade_plan", SAFE, check_plan),
    ("upgrade_package_info_rejects_outside_allowlist", SAFE, check_package_info_rejects_outside_allowlist),
    ("upgrade_peek_manifest_graceful_on_garbage", SAFE, check_peek_manifest_graceful_on_garbage),
    ("upgrade_preflight_negative_and_optional_positive", SAFE, check_preflight_negative_and_optional_positive),
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
