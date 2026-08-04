"""Shared foundation for tests/live/ — real HTTP calls against the live stack.

Every file in tests/live/ imports from here. This module owns:
  - the HTTP client (thin wrappers around `requests`)
  - Velociraptor client discovery and run polling (lifted from the original
    tests/live_smoke.py so there is exactly one implementation)
  - module-enabled gating, read purely over HTTP (never touches config.yaml
    on disk, which holds live secrets)
  - the risk/skip vocabulary every test file's CHECKS list uses
  - the sacrificial-Case cleanup pattern, which is the only general-purpose
    way to delete most run types (see LiveCase docstring)
  - a generic prefix-based sweep helper for non-run artifacts

Nothing in this package is swept by tests/run_all.py — it hits the REAL
running stack and can take minutes. Run it explicitly:

    docker exec intact_backend python3 /app/workdir/tests/live/run_all.py
"""
import io
import json
import random
import string
import time
import zipfile

import requests

BASE = "http://localhost:5001"
TIMEOUT = 30
ONLINE_THRESHOLD_SECONDS = 600  # matches the dashboard's own "online" cutoff

LIVETEST_PREFIX = "_livetest_"


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------

def _get(path, **kw):
    return requests.get(f"{BASE}{path}", timeout=TIMEOUT, **kw)


def _post(path, payload=None, **kw):
    return requests.post(f"{BASE}{path}", json=payload if payload is not None else {}, timeout=TIMEOUT, **kw)


def _put(path, payload=None, **kw):
    return requests.put(f"{BASE}{path}", json=payload if payload is not None else {}, timeout=TIMEOUT, **kw)


def _delete(path, **kw):
    return requests.delete(f"{BASE}{path}", timeout=TIMEOUT, **kw)


def _post_multipart_json(path, field_name, filename, json_payload, extra_data=None):
    """POST a real multipart file upload whose content is a JSON document.

    Several upload endpoints (confirmed for /api/aws/upload; verify per-route
    before assuming this applies elsewhere — do not assume all upload
    endpoints share this shape) require an actual multipart file (checked
    via Flask's `request.files`), NOT a JSON body — `_post(path, {"files":
    [...]})`'s JSON-embedded-content shape silently fails with a 400 "No
    files provided" because request.files is empty for a JSON request. This
    was discovered the hard way (tests/live_smoke.py's original
    check_aws_sigma sends JSON and does not actually work against the
    current backend) — use this helper instead of _post for any upload
    endpoint until you've confirmed by reading its handler that JSON is
    genuinely accepted.
    """
    content = json.dumps(json_payload).encode()
    files = {field_name: (filename, io.BytesIO(content), "application/json")}
    return requests.post(f"{BASE}{path}", files=files, data=extra_data or {}, timeout=TIMEOUT)


def _post_multipart_bytes(path, field_name, filename, content_bytes, extra_data=None, content_type="application/octet-stream"):
    """POST a real multipart file upload of raw bytes (e.g. a zip)."""
    files = {field_name: (filename, io.BytesIO(content_bytes), content_type)}
    return requests.post(f"{BASE}{path}", files=files, data=extra_data or {}, timeout=TIMEOUT)


# ---------------------------------------------------------------------------
# Naming — every artifact this suite creates is tagged, so it can never
# collide with real user data and is always identifiable for cleanup.
# ---------------------------------------------------------------------------

def tagged(label: str) -> str:
    """LIVETEST_PREFIX + label + a short run-scoped suffix, e.g.
    '_livetest_case_20260727T142301_ab12'. Collision-safe across parallel or
    retried runs."""
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=4))
    ts = time.strftime("%Y%m%dT%H%M%S")
    safe_label = label.replace(" ", "-")
    return f"{LIVETEST_PREFIX}{safe_label}_{ts}_{suffix}"


def is_livetest(name) -> bool:
    return bool(name) and str(name).startswith(LIVETEST_PREFIX)


# ---------------------------------------------------------------------------
# Risk / gating vocabulary — every CHECKS entry is (name, risk, fn)
# ---------------------------------------------------------------------------

SAFE = "SAFE"


def REQUIRES_MODULE(name):
    return f"REQUIRES_MODULE:{name}"


# DESTRUCTIVE is documentation-only — never added to a CHECKS list. Endpoints
# in this bucket (maintenance purge, real upgrade execution, config/db
# overwrite, tool downloads, model refreshes, agentic CLI install/login) are
# simply never called by this suite. See the plan doc for the full list and
# reasoning.
DESTRUCTIVE = "DESTRUCTIVE"


class Skip(Exception):
    """Raise from inside a check fn to record it as SKIP (not FAIL), with a
    human-readable reason as the exception message."""


_config_cache = None

# Same fallback path list as modules/backend/config.py's load_main_config() —
# tried in order, first one that exists wins. /api/config (the "frontend
# config" endpoint) is a DIFFERENT, DB-backed settings object (agentic/LLM
# settings only) and does NOT expose modules.*.enabled — confirmed by
# reading its source (config_routes.py: _load_config() reads
# load_frontend_config(), not config.yaml). /api/system/containers looked
# promising but is incomplete for this purpose (no 'elk'/'plaso' keys — elk
# is only proxied via its 'kibana' container key, plaso has no container at
# all and isn't in its ON_DEMAND_MODULES list) and conflates "enabled" with
# "container currently running", which are different questions for a test
# gate. Reading config.yaml directly is what the backend's own
# is_module_enabled() does, and tests/live/ always runs inside the same
# container as the backend (docker exec intact_backend ...), so this reads
# the exact same file via the exact same access the backend already has —
# no new exposure.
_CONFIG_PATHS = [
    "/app/config.yaml",  # inside the backend container (real invocation path)
    "/app/workdir/config.yaml",  # workdir bind-mount view, if run from there
    "/home/tenroot/intact/config.yaml",  # host-side dev/debug fallback
]


def modules_enabled(force_refresh=False):
    """Return the modules.*.enabled map read from config.yaml, e.g.
    {"elk": True, "volweb": True, ...}. Cached after first read; pass
    force_refresh=True to re-read (e.g. after Part A flips a flag)."""
    global _config_cache
    if _config_cache is None or force_refresh:
        import os
        import yaml

        cfg = None
        for path in _CONFIG_PATHS:
            if os.path.exists(path):
                with open(path) as f:
                    cfg = yaml.safe_load(f)
                break
        if cfg is None:
            raise RuntimeError(f"config.yaml not found at any of {_CONFIG_PATHS}")
        _config_cache = {
            name: bool((mod or {}).get("enabled"))
            for name, mod in (cfg.get("modules") or {}).items()
        }
    return _config_cache


def require_module(name):
    """Raise Skip if `name` isn't enabled per the live /api/config. Call at
    the top of any check that needs a specific module."""
    if not modules_enabled().get(name):
        raise Skip(f"module '{name}' disabled in config.yaml")


# ---------------------------------------------------------------------------
# Velociraptor client discovery + run polling (verbatim logic from the
# original tests/live_smoke.py, so there is exactly one implementation)
# ---------------------------------------------------------------------------

def find_client():
    """Auto-discover a real Velociraptor client. Prefers one that's actually
    online (last_seen_at within ONLINE_THRESHOLD_SECONDS, the same cutoff the
    dashboard itself uses); falls back to the most-recently-seen client
    otherwise so the suite can still run (flagged, not silent).

    Returns (client_dict, warning_or_None). client_dict is None if no client
    has EVER enrolled.
    """
    resp = _get("/api/clients")
    resp.raise_for_status()
    clients = resp.json().get("items", [])
    if not clients:
        return None, "no Velociraptor clients enrolled at all"

    now = time.time()
    with_ts = [c for c in clients if c.get("last_seen_at")]
    online = []
    for c in with_ts:
        age = now - (c["last_seen_at"] / 1_000_000)
        if age < ONLINE_THRESHOLD_SECONDS:
            online.append((age, c))
    if online:
        online.sort(key=lambda x: x[0])
        return online[0][1], None

    if not with_ts:
        return clients[0], "no client has ever checked in (last_seen_at missing) — tests needing a live client will likely fail"

    with_ts.sort(key=lambda c: c["last_seen_at"], reverse=True)
    stale = with_ts[0]
    age_min = (now - stale["last_seen_at"] / 1_000_000) / 60
    return stale, f"no client online in the last {ONLINE_THRESHOLD_SECONDS // 60} min — using most recently seen ({stale.get('hostname')}, last seen {age_min:.0f}m ago)"


def client_is_online(client):
    """Did this client check in recently enough to answer a collection?

    Same cutoff find_client() and the dashboard use, recomputed from the record
    so callers don't have to parse find_client()'s human-readable warning.
    """
    last_seen = (client or {}).get("last_seen_at")
    if not last_seen:
        return False
    return (time.time() - last_seen / 1_000_000) < ONLINE_THRESHOLD_SECONDS


def require_live_client(client):
    """Skip unless a client can actually RESPOND. Returns it if so.

    find_client() deliberately falls back to the most-recently-seen client so
    the suite still exercises read paths when nothing is online. But a check
    that dispatches a real collection, hunt or acquisition needs the endpoint to
    answer — running one against a client that vanished days ago fails with
    "no data returned" or "never observed running", which reads as a broken
    product when the truth is that nobody is home.

    Guarding only on `client is None` was not enough: the record outlives the
    connection. This is what turned an offline lab into three red areas.
    """
    if client is None:
        raise Skip("no Velociraptor client enrolled at all")
    if client_is_online(client):
        return client
    last_seen = client.get("last_seen_at")
    if not last_seen:
        raise Skip(f"client {client.get('hostname')} has never checked in — "
                   f"a live collection cannot complete")
    age_min = (time.time() - last_seen / 1_000_000) / 60
    raise Skip(
        f"no client online in the last {ONLINE_THRESHOLD_SECONDS // 60} min "
        f"(most recent: {client.get('hostname')}, last seen {age_min:.0f}m ago) "
        f"— a live collection cannot complete")


def smallest_agentic_blueprint_for(client_os):
    """Pick the agentic blueprint matching the client's OS with the fewest
    artifacts (fastest real collection). Falls back to the overall smallest
    if none match the OS."""
    resp = _get("/api/blueprints/agentic")
    resp.raise_for_status()
    blueprints = resp.json().get("blueprints", [])
    if not blueprints:
        return None
    os_key = (client_os or "").lower()
    matching = [b for b in blueprints if os_key and os_key in (b.get("id", "") + b.get("name", "")).lower()]
    pool = matching or blueprints
    return min(pool, key=lambda b: len(b.get("artifacts", [])))


def poll_run(run_id, timeout_seconds=180, interval=5):
    """Poll /api/dashboard/automation/<run_id> until completed/failed/cancelled
    or timeout. Returns (final_status_dict, transitions) where transitions is
    the list of (elapsed_seconds, status) pairs observed, so callers can
    verify the run didn't jump straight to 'completed'."""
    start = time.time()
    transitions = []
    last_status = None
    while time.time() - start < timeout_seconds:
        r = _get(f"/api/dashboard/automation/{run_id}")
        if r.status_code == 200:
            d = r.json()
            status = d.get("status")
            if status != last_status:
                transitions.append((round(time.time() - start, 1), status))
                last_status = status
            if status in ("completed", "failed", "cancelled"):
                return d, transitions
        time.sleep(interval)
    return {"status": "timeout"}, transitions


# ---------------------------------------------------------------------------
# Synthetic fixtures — deterministic, no live cloud creds needed
# ---------------------------------------------------------------------------

def synthetic_cloudtrail_event(event_id_suffix=None):
    """A syntactically-real CloudTrail event dict. Feed it to
    _post_multipart_json("/api/aws/upload", "files", "<name>.json",
    {"Records": [event]}) — POST /api/aws/upload requires a genuine
    multipart file (checked via request.files), NOT a JSON body; the
    original tests/live_smoke.py sends JSON for this and does not actually
    work against the current backend (confirmed by reading
    aws_routes.py:upload_logs). Do not repeat that mistake."""
    return {
        "eventVersion": "1.08",
        "eventTime": "2026-07-14T12:00:00Z",
        "eventSource": "cloudtrail.amazonaws.com",
        "eventName": "StopLogging",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.5",
        "userAgent": "aws-cli/2.0",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/malicious-actor",
            "accountId": "123456789012",
            "userName": "malicious-actor",
        },
        "requestParameters": {"name": "management-events"},
        "responseElements": None,
        "eventID": f"livetest-event-{event_id_suffix or int(time.time())}",
        "eventType": "AwsApiCall",
        "recipientAccountId": "123456789012",
    }


def synthetic_azure_signin_event(event_id_suffix=None):
    """A syntactically-real Azure AD sign-in-log-shaped event, for Azure's
    offline upload+analyze path (mirrors the AWS CloudTrail fixture)."""
    return {
        "id": f"livetest-signin-{event_id_suffix or int(time.time())}",
        "createdDateTime": "2026-07-14T12:00:00Z",
        "userPrincipalName": "malicious-actor@example.onmicrosoft.com",
        "userId": "00000000-0000-0000-0000-000000000001",
        "appDisplayName": "Office 365 Exchange Online",
        "ipAddress": "203.0.113.5",
        "clientAppUsed": "Other clients",
        "status": {"errorCode": 0},
        "location": {"city": "Unknown", "state": "Unknown", "countryOrRegion": "RU"},
        "riskLevelAggregated": "high",
        "riskState": "atRisk",
        "conditionalAccessStatus": "notApplied",
    }


def synthetic_csv_zip(filename="Windows.Sys.Programs.csv"):
    """A tiny in-memory zip holding one recognized-name CSV, for CVE's
    upload-CSV path (no live agent/hunt needed)."""
    csv_content = (
        "Name,Version,InstallDate,Publisher\r\n"
        "Example Vulnerable App,1.0.0,2026-01-01,Example Vendor\r\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(filename, csv_content)
    buf.seek(0)
    return buf


# ---------------------------------------------------------------------------
# Cleanup — sacrificial Case (the general-purpose run-cleanup primitive) and
# a generic prefix sweep for everything else.
# ---------------------------------------------------------------------------

class LiveCase:
    """Context manager: creates a Case named tagged('case') on enter, lets
    tests .attach(run_id) any workflow run they produce, and on exit deletes
    the case — which cascade-deletes every attached run (confirmed:
    services/fusion/store.delete_case() calls delete_workflow(run_id) for
    each attached run, then delete_workflow(case_id) for the case row
    itself; see modules/backend/services/fusion/store.py:698-733).

    Cleanup runs in `finally`, so it still happens even if a test raises
    mid-way — everything attached *before* the exception is still deleted.

    Usable standalone (`with LiveCase() as c: ...`) or as one instance
    threaded through a whole file's CHECKS list.
    """

    def __init__(self, name=None):
        self.name = name or tagged("case")
        self.case_id = None
        self.attached = []

    def __enter__(self):
        r = _post("/api/cases", {"name": self.name, "min_severity": "informational"})
        r.raise_for_status()
        body = r.json()
        self.case_id = body.get("case_id") or body.get("id")
        if not self.case_id:
            raise RuntimeError(f"POST /api/cases did not return a case_id: {body}")
        return self

    def attach(self, run_id, fuse=True):
        r = _post(f"/api/cases/{self.case_id}/attach", {"run_ids": [run_id], "fuse": fuse})
        self.attached.append(run_id)
        return r

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.case_id:
            try:
                _delete(f"/api/cases/{self.case_id}")
            except Exception:
                pass
        return False  # never swallow the original exception


def sweep_prefix(list_path, id_field, delete_path_fmt, items_key=None, name_field="name"):
    """List `list_path`, pull the item collection (top-level list, or
    `body[items_key]` when the response wraps it), filter to names starting
    with LIVETEST_PREFIX, DELETE each match via delete_path_fmt.format(id=...).

    `id_field` and `name_field` may each be a single field name or a list of
    candidate field names tried in order (different collections use
    different conventions across this codebase — cases use "case_id",
    blueprints use "id", offline-collector configs use "config_id"/"id",
    custom rules use "filename" for both id and name).

    Returns (checked_count, deleted_ids). Used both by cleanup_sweep.py and
    any test file's own belt-and-braces cleanup for non-run artifacts
    (blueprints, scheduler jobs, offline-collector configs, custom rules)
    that can't ride the LiveCase cascade.
    """
    id_fields = [id_field] if isinstance(id_field, str) else list(id_field)
    name_fields = [name_field] if isinstance(name_field, str) else list(name_field)

    r = _get(list_path)
    if r.status_code != 200:
        return 0, []
    body = r.json()
    items = body.get(items_key) if items_key else body
    if not isinstance(items, list):
        return 0, []
    deleted = []
    for item in items:
        name = next((item.get(f) for f in name_fields if item.get(f)), "")
        if is_livetest(name):
            item_id = next((item.get(f) for f in id_fields if item.get(f) is not None), None)
            if item_id is None:
                continue
            dr = _delete(delete_path_fmt.format(id=item_id))
            if dr.status_code in (200, 204, 404):
                deleted.append(item_id)
    return len(items), deleted
