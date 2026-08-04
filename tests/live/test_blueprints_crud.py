#!/usr/bin/env python3
"""Live blueprint CRUD checks — real backend API calls against the live stack.

Covers the full create -> get -> update -> list-contains -> delete ->
get-404 cycle for all 4 blueprint types exposed by
modules/backend/routes/blueprint_routes.py: velociraptor, agentic,
timesketch, and memory (VolWeb). All SAFE (every check cleans up whatever it
creates, in a try/finally, even on failure).

The velociraptor and agentic types share the SAME underlying SQLite table
(the "velociraptor" blueprint store) — agentic's routes literally delegate to
the velociraptor route functions. The only thing that separates them at read
time is /api/blueprints/agentic's list filter: 'agentic' in (name + ' ' +
id).lower() (see blueprint_routes.py list_agentic_blueprints()). This means:
  - A blueprint named/tagged with "agentic" in it shows up in BOTH
    /api/blueprints/agentic and /api/blueprints/velociraptor's list — that's
    expected, not a bug, and the agentic check here asserts exactly that
    rather than assuming strict separation.
  - A blueprint whose name/id does NOT contain "agentic" (e.g. our plain
    "bp-velociraptor" tag) must NOT leak into the agentic list — checked too.

Timesketch and memory blueprints live in their own separate tables
(blueprints_timesketch, blueprints_memory) with no such collision.

NOT part of run_all.py's sweep, and not meant to run on every change — invoke
it by name, manually, only when asked:

    docker exec intact_backend python3 /app/workdir/tests/live/test_blueprints_crud.py
"""
import sys

from _lib import SAFE, _delete, _get, _post, _put, tagged


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_velociraptor_blueprint_crud():
    name = tagged("bp-velociraptor")
    bp_id = None
    try:
        payload = {
            "name": name,
            "description": "live test velociraptor blueprint",
            "artifacts": ["Generic.Client.Info"],
            "settings": {"hunt_expiry": 60, "timeout": 600, "cpu_limit": 50},
        }
        r = _post("/api/blueprints/velociraptor", payload)
        if r.status_code != 201:
            return False, f"POST create -> {r.status_code}: {r.text[:300]}"
        bp_id = r.json().get("blueprint", {}).get("id")
        if not bp_id:
            return False, f"no id in create response: {r.text[:300]}"

        g = _get(f"/api/blueprints/velociraptor/{bp_id}")
        if g.status_code != 200 or g.json().get("name") != name:
            return False, f"GET by id mismatch: {g.status_code} {g.text[:300]}"

        updated = dict(payload)
        updated["description"] = "updated by live test"
        u = _put(f"/api/blueprints/velociraptor/{bp_id}", updated)
        if u.status_code != 200:
            return False, f"PUT update -> {u.status_code}: {u.text[:300]}"

        g2 = _get(f"/api/blueprints/velociraptor/{bp_id}")
        if g2.json().get("description") != "updated by live test":
            return False, f"update didn't persist: {g2.text[:300]}"

        lst = _get("/api/blueprints/velociraptor")
        ids = [b.get("id") for b in lst.json().get("blueprints", [])]
        if bp_id not in ids:
            return False, "created blueprint not found in velociraptor list"

        # This name has no "agentic" substring — must NOT leak into the
        # agentic-filtered view.
        alist = _get("/api/blueprints/agentic")
        aids = [b.get("id") for b in alist.json().get("blueprints", [])]
        if bp_id in aids:
            return False, "velociraptor-named blueprint unexpectedly appeared in agentic list"

        d = _delete(f"/api/blueprints/velociraptor/{bp_id}")
        if d.status_code != 200:
            return False, f"DELETE -> {d.status_code}: {d.text[:300]}"
        deleted_id, bp_id = bp_id, None  # deleted; don't re-delete in finally

        g3 = _get(f"/api/blueprints/velociraptor/{deleted_id}")
        if g3.status_code != 404:
            return False, f"expected 404 after delete, got {g3.status_code}: {g3.text[:300]}"

        return True, f"id={deleted_id} full CRUD cycle OK, correctly absent from agentic list"
    finally:
        if bp_id:
            try:
                _delete(f"/api/blueprints/velociraptor/{bp_id}")
            except Exception:
                pass


def check_agentic_blueprint_crud():
    name = tagged("bp-agentic")  # contains "agentic" -> must surface in both list views
    bp_id = None
    try:
        payload = {
            "name": name,
            "description": "live test agentic blueprint",
            "artifacts": ["Generic.Client.Info"],
            "settings": {"hunt_expiry": 60, "timeout": 600, "cpu_limit": 50},
        }
        r = _post("/api/blueprints/agentic", payload)
        if r.status_code != 201:
            return False, f"POST create -> {r.status_code}: {r.text[:300]}"
        bp_id = r.json().get("blueprint", {}).get("id")
        if not bp_id:
            return False, f"no id in create response: {r.text[:300]}"

        g = _get(f"/api/blueprints/agentic/{bp_id}")
        if g.status_code != 200 or g.json().get("name") != name:
            return False, f"GET by id (agentic) mismatch: {g.status_code} {g.text[:300]}"

        updated = dict(payload)
        updated["description"] = "updated by live test"
        u = _put(f"/api/blueprints/agentic/{bp_id}", updated)
        if u.status_code != 200:
            return False, f"PUT update (agentic) -> {u.status_code}: {u.text[:300]}"

        g2 = _get(f"/api/blueprints/agentic/{bp_id}")
        if g2.json().get("description") != "updated by live test":
            return False, f"update didn't persist: {g2.text[:300]}"

        alist = _get("/api/blueprints/agentic")
        aids = [b.get("id") for b in alist.json().get("blueprints", [])]
        if bp_id not in aids:
            return False, "created blueprint not found in agentic list"

        # Collision case: same underlying table as velociraptor, so it MUST
        # also appear in the velociraptor list — this is documented,
        # expected behavior, not a bug.
        vlist = _get("/api/blueprints/velociraptor")
        vids = [b.get("id") for b in vlist.json().get("blueprints", [])]
        if bp_id not in vids:
            return False, "agentic blueprint unexpectedly missing from velociraptor list (shared-storage collision assumption broke)"

        d = _delete(f"/api/blueprints/agentic/{bp_id}")
        if d.status_code != 200:
            return False, f"DELETE (agentic) -> {d.status_code}: {d.text[:300]}"
        deleted_id, bp_id = bp_id, None

        g3 = _get(f"/api/blueprints/agentic/{deleted_id}")
        if g3.status_code != 404:
            return False, f"expected 404 after delete, got {g3.status_code}: {g3.text[:300]}"

        return True, f"id={deleted_id} full CRUD cycle OK, confirmed present in both agentic and velociraptor list views before delete"
    finally:
        if bp_id:
            try:
                _delete(f"/api/blueprints/agentic/{bp_id}")
            except Exception:
                pass


def check_timesketch_blueprint_crud():
    name = tagged("bp-timesketch")
    bp_id = None
    try:
        payload = {
            "name": name,
            "description": "live test timesketch blueprint",
            "settings": {
                "kape_target": "_KapeTriage",
                "plaso_parser": "win7",
                "plaso_workers": 2,
                "plaso_hasher": "none",
                "plaso_hasher_size": 100,
                "collection_timeout": 100000,
            },
        }
        r = _post("/api/blueprints/timesketch", payload)
        if r.status_code != 201:
            return False, f"POST create -> {r.status_code}: {r.text[:300]}"
        bp_id = r.json().get("blueprint", {}).get("id")
        if not bp_id:
            return False, f"no id in create response: {r.text[:300]}"

        g = _get(f"/api/blueprints/timesketch/{bp_id}")
        if g.status_code != 200 or g.json().get("name") != name:
            return False, f"GET by id mismatch: {g.status_code} {g.text[:300]}"

        updated = dict(payload)
        updated["description"] = "updated by live test"
        u = _put(f"/api/blueprints/timesketch/{bp_id}", updated)
        if u.status_code != 200:
            return False, f"PUT update -> {u.status_code}: {u.text[:300]}"

        g2 = _get(f"/api/blueprints/timesketch/{bp_id}")
        if g2.json().get("description") != "updated by live test":
            return False, f"update didn't persist: {g2.text[:300]}"

        lst = _get("/api/blueprints/timesketch")
        ids = [b.get("id") for b in lst.json().get("blueprints", [])]
        if bp_id not in ids:
            return False, "created blueprint not found in list"

        d = _delete(f"/api/blueprints/timesketch/{bp_id}")
        if d.status_code != 200:
            return False, f"DELETE -> {d.status_code}: {d.text[:300]}"
        deleted_id, bp_id = bp_id, None

        g3 = _get(f"/api/blueprints/timesketch/{deleted_id}")
        if g3.status_code != 404:
            return False, f"expected 404 after delete, got {g3.status_code}: {g3.text[:300]}"

        return True, f"id={deleted_id} full CRUD cycle OK"
    finally:
        if bp_id:
            try:
                _delete(f"/api/blueprints/timesketch/{bp_id}")
            except Exception:
                pass


def check_memory_blueprint_crud():
    name = tagged("bp-memory")
    bp_id = None
    try:
        payload = {
            "name": name,
            "description": "live test memory blueprint",
            "settings": {"plugin_set": "curated_standard", "cpu_limit": 50, "max_bytes": 1073741824},
        }
        r = _post("/api/blueprints/memory", payload)
        if r.status_code != 201:
            return False, f"POST create -> {r.status_code}: {r.text[:300]}"
        bp_id = r.json().get("blueprint", {}).get("id")
        if not bp_id:
            return False, f"no id in create response: {r.text[:300]}"

        g = _get(f"/api/blueprints/memory/{bp_id}")
        if g.status_code != 200 or g.json().get("name") != name:
            return False, f"GET by id mismatch: {g.status_code} {g.text[:300]}"

        updated = dict(payload)
        updated["description"] = "updated by live test"
        u = _put(f"/api/blueprints/memory/{bp_id}", updated)
        if u.status_code != 200:
            return False, f"PUT update -> {u.status_code}: {u.text[:300]}"

        g2 = _get(f"/api/blueprints/memory/{bp_id}")
        if g2.json().get("description") != "updated by live test":
            return False, f"update didn't persist: {g2.text[:300]}"

        lst = _get("/api/blueprints/memory")
        ids = [b.get("id") for b in lst.json().get("blueprints", [])]
        if bp_id not in ids:
            return False, "created blueprint not found in list"

        d = _delete(f"/api/blueprints/memory/{bp_id}")
        if d.status_code != 200:
            return False, f"DELETE -> {d.status_code}: {d.text[:300]}"
        deleted_id, bp_id = bp_id, None

        g3 = _get(f"/api/blueprints/memory/{deleted_id}")
        if g3.status_code != 404:
            return False, f"expected 404 after delete, got {g3.status_code}: {g3.text[:300]}"

        return True, f"id={deleted_id} full CRUD cycle OK"
    finally:
        if bp_id:
            try:
                _delete(f"/api/blueprints/memory/{bp_id}")
            except Exception:
                pass


CHECKS = [
    ("blueprint_crud_velociraptor", SAFE, check_velociraptor_blueprint_crud),
    ("blueprint_crud_agentic", SAFE, check_agentic_blueprint_crud),
    ("blueprint_crud_timesketch", SAFE, check_timesketch_blueprint_crud),
    ("blueprint_crud_memory", SAFE, check_memory_blueprint_crud),
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
