#!/usr/bin/env python3
"""Live Velociraptor offline-collector checks — real backend API calls against
the live stack.

Covers modules/backend/routes/velociraptor_offline_routes.py: config CRUD
(create -> get -> update -> list-contains) -> generate a real collector binary
-> download it and confirm real bytes came back -> delete the config. All
SAFE: no live/enrolled Velociraptor client is needed anywhere in this file —
`generate` builds a standalone binary server-side by repacking the base
Velociraptor client binary already staged in /app/downloads/, it never talks
to an endpoint.

`generate` is asynchronous (POST returns a run_id immediately; the actual
file_id only shows up once the workflow completes — see
`update_run_status(run_id, "completed", ..., details={"file_id": file_id})`
in the route source), so this file polls the run like any other workflow via
`_lib.poll_run`.

The `/api/velociraptor/offline/import` endpoint is deliberately NOT exercised
here: it expects a real Velociraptor offline-collector results ZIP (internal
directory/manifest shape not confirmed by reading the importer source), and
fabricating a synthetic one risks silently testing the wrong thing. Skipped
with a documented `_lib.Skip` instead of guessing at the binary format.

NOT part of run_all.py's sweep, and not meant to run on every change — invoke
it by name, manually, only when asked:

    docker exec intact_backend python3 /app/workdir/tests/live/test_velociraptor_offline.py
"""
import sys

from _lib import SAFE, Skip, _delete, _get, _post, _put, poll_run, tagged


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_offline_config_crud(client):
    name = tagged("offline-cfg")
    config_id = None
    try:
        payload = {
            "config_name": name,
            "description": "live test offline collector config",
            "artifacts": ["Generic.Client.Info"],
            "parameters": {
                "CpuLimit": 50,
                "MaxExecutionTimeInSeconds": 300,
                "MaxIdleTimeInSeconds": 60,
                "EncryptionScheme": "None",
            },
        }
        r = _post("/api/velociraptor/offline/configs", payload)
        if r.status_code != 201:
            return False, f"POST create -> {r.status_code}: {r.text[:300]}"
        body = r.json()
        if not body.get("success"):
            return False, f"create response not success: {body}"
        config_id = body.get("config_id")
        if not config_id:
            return False, f"no config_id in create response: {body}"

        g = _get(f"/api/velociraptor/offline/configs/{config_id}")
        if g.status_code != 200 or g.json().get("config_name") != name:
            return False, f"GET by id mismatch: {g.status_code} {g.text[:300]}"

        updated = dict(payload)
        updated["description"] = "updated by live test"
        u = _put(f"/api/velociraptor/offline/configs/{config_id}", updated)
        if u.status_code != 200:
            return False, f"PUT update -> {u.status_code}: {u.text[:300]}"

        g2 = _get(f"/api/velociraptor/offline/configs/{config_id}")
        if g2.json().get("description") != "updated by live test":
            return False, f"update didn't persist: {g2.text[:300]}"

        lst = _get("/api/velociraptor/offline/configs")
        if lst.status_code != 200:
            return False, f"GET list -> {lst.status_code}: {lst.text[:300]}"
        ids = [c.get("id") or c.get("config_id") for c in lst.json().get("configs", [])]
        if config_id not in ids:
            return False, "created config not found in list"

        return True, f"config_id={config_id} full CRUD-and-list cycle OK"
    finally:
        if config_id:
            _delete(f"/api/velociraptor/offline/configs/{config_id}")


def check_offline_generate_download_delete(client):
    name = tagged("offline-gen")
    config_id = None
    try:
        payload = {
            "config_name": name,
            "description": "live test offline collector generation",
            # Single, cheap, cross-platform artifact — smallest realistic
            # collector build (no large collection set, still a real repack).
            "artifacts": ["Generic.Client.Info"],
            "parameters": {
                "CpuLimit": 50,
                "MaxExecutionTimeInSeconds": 300,
                "MaxIdleTimeInSeconds": 60,
                "EncryptionScheme": "None",
            },
        }
        r = _post("/api/velociraptor/offline/configs", payload)
        if r.status_code != 201:
            return False, f"POST create -> {r.status_code}: {r.text[:300]}"
        config_id = r.json().get("config_id")
        if not config_id:
            return False, f"no config_id in create response: {r.text[:300]}"

        # 'generate' is async: it dispatches a background thread and returns a
        # run_id immediately. file_id only shows up in the run's `details`
        # once the workflow completes.
        gen = _post("/api/velociraptor/offline/generate", {"config_id": config_id, "os": "linux"})
        if gen.status_code != 200:
            return False, f"POST generate -> {gen.status_code}: {gen.text[:300]}"
        gen_body = gen.json()
        if not gen_body.get("success"):
            return False, f"generate response not success: {gen_body}"
        run_id = gen_body.get("run_id")
        if not run_id:
            return False, f"no run_id in generate response: {gen_body}"

        final, transitions = poll_run(run_id, timeout_seconds=180, interval=5)
        if final.get("status") != "completed":
            return False, f"generate run {run_id} ended as '{final.get('status')}' (transitions: {transitions})"

        file_id = (final.get("details") or {}).get("file_id")
        if not file_id:
            return False, f"run completed but no file_id in details: {final}"

        dl = _get(f"/api/velociraptor/offline/download/{file_id}")
        if dl.status_code != 200:
            return False, f"GET download -> {dl.status_code}: {dl.text[:300]}"
        if not dl.content or len(dl.content) < 1024:
            return False, f"download returned suspiciously small body ({len(dl.content)} bytes)"

        return True, (
            f"config_id={config_id} run_id={run_id} file_id={file_id} "
            f"downloaded {len(dl.content)} real bytes"
        )
    finally:
        if config_id:
            _delete(f"/api/velociraptor/offline/configs/{config_id}")


def check_offline_config_delete_confirmed(client):
    """Separate from the CRUD check above: confirms DELETE really deletes
    (follow-up GET returns 404), rather than just trusting the 200 body."""
    name = tagged("offline-del")
    r = _post("/api/velociraptor/offline/configs", {
        "config_name": name,
        "artifacts": ["Generic.Client.Info"],
    })
    if r.status_code != 201:
        return False, f"POST create -> {r.status_code}: {r.text[:300]}"
    config_id = r.json().get("config_id")
    if not config_id:
        return False, f"no config_id in create response: {r.text[:300]}"

    d = _delete(f"/api/velociraptor/offline/configs/{config_id}")
    if d.status_code != 200:
        return False, f"DELETE -> {d.status_code}: {d.text[:300]}"

    g = _get(f"/api/velociraptor/offline/configs/{config_id}")
    if g.status_code != 404:
        return False, f"expected 404 after delete, got {g.status_code}: {g.text[:300]}"

    return True, f"config_id={config_id} deleted and confirmed absent (404 on follow-up GET)"


def check_offline_import_skipped(client):
    raise Skip(
        "no synthetic offline-import fixture — internal ZIP shape not confirmed"
    )


CHECKS = [
    ("velociraptor_offline_config_crud", SAFE, check_offline_config_crud),
    ("velociraptor_offline_generate_download_delete", SAFE, check_offline_generate_download_delete),
    ("velociraptor_offline_config_delete_confirmed", SAFE, check_offline_config_delete_confirmed),
    ("velociraptor_offline_import", SAFE, check_offline_import_skipped),
]


def main():
    from _lib import find_client

    client, warning = find_client()
    if warning:
        print(f"[WARN] {warning}", flush=True)
    if client:
        print(f"[INFO] Using client {client.get('client_id')} ({client.get('hostname')}, {client.get('os')})", flush=True)
    else:
        print("[INFO] No Velociraptor client available — not needed by this file (offline collector generation doesn't touch an endpoint).", flush=True)

    passed = failed = skipped = 0
    for name, risk, fn in CHECKS:
        print(f"\n--- {name} ---", flush=True)
        try:
            if risk.startswith("REQUIRES_MODULE:"):
                from _lib import require_module
                require_module(risk.split(":", 1)[1])
            ok, detail = fn(client)
        except Exception as e:
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
