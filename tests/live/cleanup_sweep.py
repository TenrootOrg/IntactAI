#!/usr/bin/env python3
"""Belt-and-braces cleanup: find and delete leftover _livetest_ artifacts
from a prior crashed/killed tests/live/ run.

Every test file cleans up after itself in a try/finally (cases cascade-
delete their attached runs; blueprints/scheduler-jobs/offline-configs/
custom-rules delete themselves directly). This script is the recovery net
for when that didn't happen — a killed process, a host reboot mid-run, a
Ctrl-C. It lists every collection this suite ever creates artifacts in,
filters to names starting with "_livetest_", and deletes matches.

Run manually, or automatically at the start of run_all.py (default on,
--no-sweep to disable):

    docker exec intact_backend python3 /app/workdir/tests/live/cleanup_sweep.py

Only ever touches items whose name/id already starts with "_livetest_" —
by construction this can never match real user-created data (see
_lib.tagged()). Safe to run at any time, including against a totally clean
system (reports zero found, zero deleted).
"""
import sys

import _lib

# (label, list_path, id_field(s), delete_path_format, items_key, name_field(s))
COLLECTIONS = [
    ("cases", "/api/cases", "case_id", "/api/cases/{id}", "cases", "name"),
    ("blueprints (velociraptor)", "/api/blueprints/velociraptor", "id",
     "/api/blueprints/velociraptor/{id}", "blueprints", "name"),
    ("blueprints (agentic)", "/api/blueprints/agentic", "id",
     "/api/blueprints/agentic/{id}", "blueprints", "name"),
    ("blueprints (timesketch)", "/api/blueprints/timesketch", "id",
     "/api/blueprints/timesketch/{id}", "blueprints", "name"),
    ("blueprints (memory)", "/api/blueprints/memory", "id",
     "/api/blueprints/memory/{id}", "blueprints", "name"),
    ("scheduler jobs", "/api/scheduler/jobs", ["id", "job_id"],
     "/api/scheduler/jobs/{id}", "jobs", "name"),
    ("velociraptor offline configs", "/api/velociraptor/offline/configs", ["config_id", "id"],
     "/api/velociraptor/offline/configs/{id}", "configs", ["config_name", "name"]),
    ("aws custom rules", "/api/aws/rules/custom", "filename",
     "/api/aws/rules/custom/{id}", "rules", "filename"),
    ("azure custom rules", "/api/azure/rules/custom", "filename",
     "/api/azure/rules/custom/{id}", "rules", "filename"),
]


def main():
    total_checked = 0
    total_deleted = 0
    print("=== cleanup_sweep: scanning for leftover _livetest_ artifacts ===", flush=True)
    for label, list_path, id_field, delete_fmt, items_key, name_field in COLLECTIONS:
        try:
            checked, deleted = _lib.sweep_prefix(list_path, id_field, delete_fmt, items_key, name_field)
        except Exception as e:
            print(f"  [WARN] {label}: sweep failed ({e})", flush=True)
            continue
        total_checked += checked
        total_deleted += len(deleted)
        if deleted:
            print(f"  {label}: {len(deleted)} deleted (of {checked} checked) -> {deleted}", flush=True)
        else:
            print(f"  {label}: 0 deleted (of {checked} checked)", flush=True)

    print(f"\n=== swept {total_checked} items across {len(COLLECTIONS)} collections, "
          f"deleted {total_deleted} leftover _livetest_ artifact(s) ===", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
