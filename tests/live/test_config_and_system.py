#!/usr/bin/env python3
"""Live config + system checks — real backend API calls against the live stack.

Covers modules/backend/routes/config_routes.py, system_routes.py, and
client_routes.py's list endpoint. ALL SAFE, read-only:

  - GET /api/config              — agentic/LLM frontend settings ONLY. This
    does NOT expose modules.*.enabled (confirmed by reading config_routes.py:
    _load_config() reads load_frontend_config(), a completely different,
    DB-backed settings object from config.yaml's modules block) — so no
    check here asserts anything about module state from it.
  - GET /api/config/cloud        — masked secrets expected; asserts any
    non-empty secret-shaped field in the response is actually masked
    (starts with the bullet-mask prefix), never a raw value.
  - GET /api/config/azure/certificate — may legitimately report
    has_certificate: false / available: false when no cert has been
    generated; that is a valid, non-failing outcome on this host, not a bug.
  - GET /api/health, /api/version, /api/system/actions,
    /api/system/containers, /api/test (GET + POST)
  - GET /api/clients — sane list shape only; never assumes a specific
    client exists (the live client population changes over time).

Never calls PUT/POST /api/config or /api/config/cloud anywhere in this file
— those overwrite the LIVE config (which holds real secrets) and are
explicitly EXCLUDED/DESTRUCTIVE per the plan. Only GET is used against those
two routes.

NOT part of run_all.py's sweep, and not meant to run on every change — invoke
it by name, manually, only when asked:

    docker exec intact_backend python3 /app/workdir/tests/live/test_config_and_system.py
"""
import sys

from _lib import SAFE, _get, _post


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_config_frontend():
    r = _get("/api/config")
    if r.status_code != 200:
        return False, f"GET /api/config -> {r.status_code}: {r.text[:300]}"
    body = r.json()
    if "agentic" not in body:
        return False, f"expected 'agentic' key in frontend config: {str(body)[:300]}"
    # If an online_llm api_key happens to be configured, it must be masked
    # (the route masks it — previously it leaked the real key in full).
    key = (body.get("agentic", {}).get("online_llm", {}) or {}).get("api_key", "")
    if key and not key.startswith("••••"):
        return False, f"online_llm.api_key does not look masked: {key!r}"
    return True, f"agentic.llm_mode={body.get('agentic', {}).get('llm_mode')!r}"


def _assert_masked_or_empty(value, field_name, findings):
    if value and not (isinstance(value, str) and value.startswith("••••")):
        findings.append(f"{field_name} looks unmasked: {value!r}")


def check_config_cloud():
    r = _get("/api/config/cloud")
    if r.status_code != 200:
        return False, f"GET /api/config/cloud -> {r.status_code}: {r.text[:300]}"
    body = r.json()
    if "aws" not in body or "azure" not in body:
        return False, f"expected 'aws' and 'azure' keys: {str(body)[:300]}"

    findings = []
    _assert_masked_or_empty(body.get("aws", {}).get("secret_access_key"), "aws.secret_access_key", findings)
    _assert_masked_or_empty(body.get("aws", {}).get("session_token"), "aws.session_token", findings)
    _assert_masked_or_empty(body.get("azure", {}).get("client_secret"), "azure.client_secret", findings)
    if findings:
        return False, "; ".join(findings)
    return True, f"provider={body.get('provider')!r}, all present secret-shaped fields masked (or empty)"


def check_config_azure_certificate():
    r = _get("/api/config/azure/certificate")
    # A 404/empty-shaped 200 (no certificate generated yet) is a valid,
    # non-failing outcome on this host — not a bug.
    if r.status_code == 404:
        return True, "404 — no certificate configured (valid outcome)"
    if r.status_code != 200:
        return False, f"GET /api/config/azure/certificate -> {r.status_code}: {r.text[:300]}"
    body = r.json()
    for key in ("has_certificate", "has_image", "available"):
        if key not in body:
            return False, f"expected {key!r} in response: {str(body)[:300]}"
    return True, f"has_certificate={body.get('has_certificate')} available={body.get('available')}"


def check_health():
    r = _get("/api/health")
    if r.status_code != 200:
        return False, f"GET /api/health -> {r.status_code}: {r.text[:300]}"
    if r.json().get("status") != "healthy":
        return False, f"unexpected health body: {r.text[:300]}"
    return True, "status=healthy"


def check_version():
    r = _get("/api/version")
    if r.status_code != 200:
        return False, f"GET /api/version -> {r.status_code}: {r.text[:300]}"
    version = r.json().get("version")
    if not version:
        return False, f"empty version in response: {r.text[:300]}"
    return True, f"version={version!r}"


def check_system_actions():
    r = _get("/api/system/actions")
    if r.status_code != 200:
        return False, f"GET /api/system/actions -> {r.status_code}: {r.text[:300]}"
    body = r.json()
    if "actions" not in body or not isinstance(body["actions"], list):
        return False, f"'actions' missing or not a list: {str(body)[:300]}"
    return True, f"{len(body['actions'])} action(s) visible"


def check_system_containers():
    r = _get("/api/system/containers")
    if r.status_code != 200:
        return False, f"GET /api/system/containers -> {r.status_code}: {r.text[:300]}"
    body = r.json()
    if not isinstance(body, dict) or not body:
        return False, f"expected a non-empty dict of service -> state: {str(body)[:300]}"
    valid_states = {"online", "stopped", "not_installed"}
    bad = {k: v for k, v in body.items() if v not in valid_states}
    if bad:
        return False, f"unexpected state value(s): {bad}"
    return True, f"{len(body)} service(s): {body}"


def check_test_endpoint():
    g = _get("/api/test")
    if g.status_code != 200 or g.json().get("method") != "GET":
        return False, f"GET /api/test -> {g.status_code}: {g.text[:300]}"
    p = _post("/api/test")
    if p.status_code != 200 or p.json().get("method") != "POST":
        return False, f"POST /api/test -> {p.status_code}: {p.text[:300]}"
    return True, "GET and POST /api/test both echo their method"


def check_clients_list():
    r = _get("/api/clients")
    if r.status_code != 200:
        return False, f"GET /api/clients -> {r.status_code}: {r.text[:300]}"
    body = r.json()
    if "items" not in body or not isinstance(body["items"], list):
        return False, f"'items' missing or not a list: {str(body)[:300]}"
    if "total" not in body:
        return False, f"'total' missing from response: {str(body)[:300]}"
    return True, f"{body.get('total')} client(s) total, {len(body['items'])} returned"


CHECKS = [
    ("config_frontend", SAFE, check_config_frontend),
    ("config_cloud_masked", SAFE, check_config_cloud),
    ("config_azure_certificate", SAFE, check_config_azure_certificate),
    ("health", SAFE, check_health),
    ("version", SAFE, check_version),
    ("system_actions", SAFE, check_system_actions),
    ("system_containers", SAFE, check_system_containers),
    ("test_endpoint_get_post", SAFE, check_test_endpoint),
    ("clients_list", SAFE, check_clients_list),
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
        except Exception as e:
            from _lib import Skip
            if isinstance(e, Skip):
                print(f"[SKIP] {name}: {e}", flush=True)
                skipped += 1
                continue
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
