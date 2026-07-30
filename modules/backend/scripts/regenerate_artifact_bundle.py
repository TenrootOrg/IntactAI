#!/usr/bin/env python3
"""Regenerate the committed Velociraptor artifact bundle.

``modules/velociraptor/bundled_artifacts/`` holds the curated artifact
definitions (Artifact Exchange / DetectRaptor / Sigma / Rapid7 / TenRoot)
that get BAKED into the velociraptor image and loaded on boot via the
``--definitions`` flag (see ``modules/velociraptor/{Dockerfile,
entrypoint.sh}``). The platform no longer imports these over the API at
runtime — they ship inside the image — so this folder is the single source
of truth and must be refreshed whenever you want to pick up upstream
artifact changes (e.g. a new Velociraptor release that updated the Artifact
Exchange, or new TenRoot artifacts).

What it does — it reproduces the *import* the platform used to do at runtime,
then EXPORTS the result back into the repo folder:

  1. Download the latest TenRoot artifact pack from GitHub.
  2. Run the upstream import artifacts against a running Velociraptor:
     Server.Import.ArtifactBundle (the 0.77+ name; falls back to the
     pre-0.77 Server.Import.ArtifactExchange) + DetectRaptor + Extras. These
     pull the newest artifacts from their GitHub sources.
  3. Import the TenRoot pack.
  4. Wait for the async import flows to settle.
  5. Export every non-built-in artifact to
     ``modules/velociraptor/bundled_artifacts/<name>.yaml`` and print the diff.

Run it on a dev/build box that has a RUNNING Velociraptor + internet (it
talks to the server over the gRPC API and the import artifacts fetch from
GitHub). Then commit the updated folder:

    docker exec intact_backend python \
        /app/workdir/modules/backend/scripts/regenerate_artifact_bundle.py
    git add modules/velociraptor/bundled_artifacts && git commit ...
"""

import os
import re
import sys
import time
import json
import urllib.request

sys.path.insert(0, '/app')
from services.velociraptor_service import setup_velociraptor_connection  # noqa: E402
from pyvelociraptor import api_pb2, api_pb2_grpc  # noqa: E402
from services.velociraptor_init_service import (  # noqa: E402
    run_server_artifact, import_tenroot_artifacts, TENROOT_ARTIFACTS_ZIP,
)

TENROOT_ZIP_URL = (
    "https://github.com/TenRootOrg/Velociraptor-Artifacts/archive/refs/heads/main.zip"
)


def log(msg):
    print(f"[REGEN] {msg}", flush=True)


# Some upstream/TenRoot artifacts hardcode live credentials as default
# parameter values (e.g. Custom.Server.Slack.Clients.Online shipped a real
# Slack incoming-webhook URL). Those would (a) trip the gitleaks secret scan
# and (b) commit a working secret to the repo. Scrub the known shapes to a
# harmless placeholder on export — the operator sets the real value at runtime.
_SECRET_SCRUBS = [
    # Slack incoming webhook (with or without a concatenated "Slack" prefix).
    (re.compile(r'(?:Slack)?https://hooks\.slack\.com/services/\S+'),
     'https://hooks.slack.com/services/XXXX/YYYY/ZZZZ'),
]


def scrub_secrets(raw, name):
    cleaned = raw
    for pat, repl in _SECRET_SCRUBS:
        cleaned, n = pat.subn(repl, cleaned)
        if n:
            log(f"  ! scrubbed {n} hardcoded secret(s) from {name}")
    return cleaned


def _bundle_dir():
    """Resolve modules/velociraptor/bundled_artifacts (repo mounted at
    /app/workdir inside the backend container; relative fallback otherwise)."""
    candidates = [
        "/app/workdir/modules/velociraptor/bundled_artifacts",
        os.path.abspath(os.path.join(
            os.path.dirname(__file__), "..", "..", "..",
            "modules", "velociraptor", "bundled_artifacts")),
    ]
    for d in candidates:
        if os.path.isdir(os.path.dirname(d)):
            return d
    return candidates[0]


def run_vql(vql, timeout=180):
    ch = setup_velociraptor_connection()
    stub = api_pb2_grpc.APIStub(ch)
    req = api_pb2.VQLCollectorArgs(max_wait=1, Query=[api_pb2.VQLRequest(Name="q", VQL=vql)])
    rows = []
    for r in stub.Query(req, timeout=timeout):
        if r.Response:
            try:
                rows.extend(json.loads(r.Response))
            except Exception:
                pass
    ch.close()
    return rows


def custom_count():
    rows = run_vql("SELECT count() AS N FROM artifact_definitions() WHERE built_in = false")
    return rows[-1]["N"] if rows else 0


def exchange_import_artifact():
    """0.77 renamed Server.Import.ArtifactExchange -> Server.Import.ArtifactBundle
    (old name aliased). Prefer the new name when the running server defines
    it; fall back to the legacy name on 0.76 and earlier."""
    rows = run_vql("SELECT name FROM artifact_definitions() "
                   "WHERE name = 'Server.Import.ArtifactBundle'")
    if rows:
        return "Server.Import.ArtifactBundle"
    return "Server.Import.ArtifactExchange"


def download_tenroot():
    log(f"Downloading latest TenRoot pack: {TENROOT_ZIP_URL}")
    os.makedirs(os.path.dirname(TENROOT_ARTIFACTS_ZIP), exist_ok=True)
    urllib.request.urlretrieve(TENROOT_ZIP_URL, TENROOT_ARTIFACTS_ZIP)
    log(f"  saved -> {TENROOT_ARTIFACTS_ZIP} "
        f"({os.path.getsize(TENROOT_ARTIFACTS_ZIP) // 1024} KB)")


def wait_until_stable(timeout=1200, settle=3, interval=15, min_wait=90):
    """Poll the custom-artifact count until it stops growing for `settle`
    consecutive checks (after a minimum warm-up so async flows have started)."""
    log("Waiting for async import flows to settle...")
    last = -1
    stable = 0
    waited = 0
    while waited < timeout:
        time.sleep(interval)
        waited += interval
        n = custom_count()
        log(f"  t+{waited}s: {n} custom artifacts")
        if waited >= min_wait and n == last and n > 0:
            stable += 1
            if stable >= settle:
                log(f"  count stable at {n} — imports complete")
                return n
        else:
            stable = 0
        last = n
    log("  timeout reached — exporting whatever is present")
    return custom_count()


def export_bundle():
    out = _bundle_dir()
    os.makedirs(out, exist_ok=True)
    before = {f for f in os.listdir(out) if f.endswith(".yaml")}
    # Clear old YAMLs so upstream deletions are reflected in the bundle.
    for f in before:
        os.remove(os.path.join(out, f))
    rows = run_vql('SELECT name, raw FROM artifact_definitions() '
                   'WHERE built_in = false AND raw != ""')
    after = set()
    for d in rows:
        name, raw = d.get("name"), d.get("raw")
        if not name or not raw:
            continue
        raw = scrub_secrets(raw, name)
        fname = name.replace(".", "__").replace("/", "__") + ".yaml"
        with open(os.path.join(out, fname), "w") as g:
            g.write(raw)
        after.add(fname)
    log(f"Exported {len(after)} artifacts -> {out}")
    added = sorted(after - before)
    removed = sorted(before - after)
    if added:
        log(f"  + {len(added)} new: "
            f"{', '.join(a[:-5] for a in added[:8])}{' ...' if len(added) > 8 else ''}")
    if removed:
        log(f"  - {len(removed)} removed: "
            f"{', '.join(r[:-5] for r in removed[:8])}{' ...' if len(removed) > 8 else ''}")
    if not added and not removed:
        log("  (no change vs the committed bundle)")
    return len(after)


def main():
    log("=== Regenerating Velociraptor artifact bundle ===")
    if not setup_velociraptor_connection():
        log("ERROR: cannot reach Velociraptor — run this on a box with a "
            "running velociraptor server.")
        sys.exit(1)
    log(f"Starting custom-artifact count: {custom_count()}")

    # 1. Fresh TenRoot pack from GitHub.
    try:
        download_tenroot()
    except Exception as e:
        log(f"WARNING: TenRoot download failed ({e}); importing whatever zip is on disk")

    # 2. Trigger upstream import artifacts (async server flows).
    exch = exchange_import_artifact()
    log(f"Exchange import artifact: {exch}")
    for art in (exch, "Server.Import.DetectRaptor", "Server.Import.Extras"):
        log(f"Triggering {art} ...")
        run_server_artifact(art)

    # 3. Import the TenRoot pack (synchronous, per-YAML).
    log("Importing TenRoot pack ...")
    import_tenroot_artifacts()

    # 4. Let the async Server.Import.* flows finish.
    wait_until_stable()

    # 5. Export the resulting definitions back into the repo folder.
    total = export_bundle()
    log(f"=== Done. Bundle now has {total} artifacts. "
        f"Commit modules/velociraptor/bundled_artifacts/ to ship them. ===")


if __name__ == "__main__":
    main()
