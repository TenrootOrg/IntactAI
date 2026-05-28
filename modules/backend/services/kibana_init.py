"""Kibana initialization helpers.

The platform creates an `artifact_*` Kibana data view at install time so the
Velociraptor-artifact indices are browsable in Kibana. This must also run
again after an ELK upgrade (the data view can be lost when Kibana's saved
objects are migrated/recreated) — hence a shared, idempotent helper used by
both `scripts/run_maintenance.py` (install-time init) and the ELK upgrader.

Kibana is served over HTTPS (self-signed), so all calls use https + verify=
False on the internal docker network.
"""

import time
from typing import Callable, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

KIBANA_URL = "https://intact_kibana:5601"
DATA_VIEW_TITLE = "artifact_*"
DATA_VIEW_NAME = "Velociraptor Artifacts"


def _wait_for_kibana(logger: Callable, timeout: int = 120) -> bool:
    """Poll Kibana /api/status until it returns 200 or timeout."""
    waited = 0
    while waited < timeout:
        try:
            r = requests.get(f"{KIBANA_URL}/api/status", timeout=8, verify=False)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(5)
        waited += 5
        logger(f"  Kibana: waiting for readiness... ({waited}s)", "info")
    return False


def ensure_kibana_data_view(logger: Optional[Callable] = None, wait: bool = True) -> bool:
    """Create the `artifact_*` data view in Kibana if it's missing. Idempotent.

    Returns True if the data view exists (already or newly created), False on
    any failure (logged, never raises — callers treat it as best-effort init).
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    headers = {"kbn-xsrf": "true", "Content-Type": "application/json"}

    try:
        if wait:
            if not _wait_for_kibana(log):
                log("  Kibana: not ready — skipping data view setup", "warning")
                return False
        else:
            r = requests.get(f"{KIBANA_URL}/api/status", timeout=10, verify=False)
            if r.status_code != 200:
                log("  Kibana: not ready yet", "info")
                return False

        existing = requests.get(f"{KIBANA_URL}/api/data_views", headers=headers, timeout=10, verify=False)
        if existing.status_code != 200:
            log("  Kibana: could not check existing data views", "warning")
            return False

        if any(dv.get("title") == DATA_VIEW_TITLE for dv in existing.json().get("data_view", [])):
            log(f"  Kibana: data view '{DATA_VIEW_NAME}' already exists", "info")
            return True

        payload = {"data_view": {"title": DATA_VIEW_TITLE, "name": DATA_VIEW_NAME, "timeFieldName": "@timestamp"}}
        resp = requests.post(f"{KIBANA_URL}/api/data_views/data_view", json=payload, headers=headers, timeout=10, verify=False)
        if resp.status_code in (200, 201):
            log(f"  Kibana: created '{DATA_VIEW_NAME}' data view", "success")
            return True
        if resp.status_code == 409:
            log("  Kibana: data view already exists", "info")
            return True
        log(f"  Kibana: could not create data view ({resp.status_code})", "warning")
        return False
    except Exception as e:
        log(f"  Kibana: {str(e)[:80]}", "warning")
        return False
