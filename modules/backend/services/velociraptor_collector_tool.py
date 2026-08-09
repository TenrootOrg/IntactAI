"""Staging the Velociraptor offline-collector template binary.

Relocated out of services/upgrade/velociraptor.py when the upgrade engine
moved to the host. Its only caller is
services/offline_collector/collector_tool.py, which needs the template present
before an operator can generate a Hunt collector -- that is a runtime product
feature, not an upgrade step, and it would have gone down with the deletion.

The upgrade side of this work now lives in lib/upgrade/velo_refresh.sh, which
registers the tool with the server over VQL rather than gRPC.
"""

import os
import shutil
import subprocess
from typing import Callable, Dict, Optional

from services.proc import WORKDIR, run_command

def _velociraptor_collector_url(clean_version: str) -> str:
    """Build the upstream URL for the velociraptor-collector binary
    matching the operator's pinned velociraptor version. Velociraptor
    publishes this as a per-release asset since at least v0.6 (verified
    on 2026-06-16: 0.1 MB asset at every recent v0.76.x release)."""
    return f"https://github.com/Velocidex/velociraptor/releases/download/v{clean_version}/velociraptor-collector"

def _ensure_velociraptor_collector_tool(
    clean_version: str,
    source: str = "github",
    package_binaries_dir: Optional[str] = None,
    logger: Optional[Callable] = None,
) -> Dict:
    """Make sure /data/tools/velociraptor-collector exists + matches the
    operator's velociraptor pin. Called from install_velociraptor_offline
    and upgrade_velociraptor_offline so the file is present BEFORE the
    operator tries to generate a Hunt collector.

    Sources:
      - source="github" → curl from upstream (online installs/upgrades)
      - source="package" → copy from <package>/binaries/velociraptor-collector
        (offline / air-gap path; the prepare side bundles the file)

    Best-effort: a missing-on-upstream / missing-from-bundle case is
    logged as a warning and the function returns success=False, so the
    caller can decide whether to fail the upgrade or proceed without.
    The current callers proceed — generating a Hunt collector will
    still fail at runtime if the file is missing, but the rest of the
    velociraptor upgrade is unaffected.

    Two distinct steps, BOTH of which must happen for Hunt-collector
    generation to work offline:
      1. STAGE the binary into /app/data/tools/ (download or copy).
      2. REGISTER it in velociraptor's inventory with serve_locally=TRUE
         so the server's `client_repack` uses the local file instead of
         constructing a github download URL.

    Step 2 is the one the 2026-06-16 fix originally MISSED — the binary
    was on disk but unregistered, so velociraptor still reached github
    and failed with "lookup github.com on 127.0.0.11:53: server
    misbehaving". Registration ALWAYS runs (even when the file is
    already staged from a prior run), because a re-install may have
    reset velociraptor's inventory.
    """
    log = logger or (lambda msg, level="info": None)
    # Use /app/data/tools/ — the path that's bind-mounted into velociraptor
    # at /tools and discoverable by configure_inventory's glob.
    tools_dir = "/app/data/tools"
    os.makedirs(tools_dir, exist_ok=True)
    dest = os.path.join(tools_dir, "velociraptor-collector")
    min_size = 50000   # ~80 KB expected; reject anything smaller

    staged = os.path.exists(dest) and os.path.getsize(dest) > min_size

    # ---- Step 1: stage the binary (skip if already valid on disk) ----
    if not staged:
        if source == "package":
            if not package_binaries_dir:
                log("  velociraptor-collector: package_binaries_dir required "
                    "for source='package' — skipping", "warning")
                return {"success": False, "error": "no package_binaries_dir"}
            src = os.path.join(package_binaries_dir, "velociraptor-collector")
            if not os.path.exists(src) or os.path.getsize(src) < min_size:
                log(f"  velociraptor-collector: not bundled in package at "
                    f"{src} — Hunt collector generation will fail without it. "
                    f"Re-prepare from current intact tag to bundle it.",
                    "warning")
                return {"success": False, "error": "not bundled"}
            import shutil
            shutil.copy2(src, dest)
            os.chmod(dest, 0o755)
            log(f"  velociraptor-collector placed from package "
                f"({os.path.getsize(dest)} bytes)", "success")
        else:  # source == "github"
            url = _velociraptor_collector_url(clean_version)
            log(f"  Downloading velociraptor-collector from {url}...", "info")
            cp = run_command(
                f"curl -fL --retry 3 --retry-delay 5 --max-time 300 "
                f"--connect-timeout 30 -o {dest} {url}",
                logger=None, timeout=600,
            )
            if not cp.get('success') or not os.path.exists(dest) or os.path.getsize(dest) < min_size:
                sz = os.path.getsize(dest) if os.path.exists(dest) else 0
                try: os.remove(dest)
                except Exception: pass
                log(f"  velociraptor-collector download failed (size={sz}, "
                    f"err={(cp.get('error') or '')[:120]}) — Hunt collector "
                    f"generation will fail at runtime until this file is "
                    f"manually placed at {dest}.", "warning")
                return {"success": False, "error": "download failed"}
            os.chmod(dest, 0o755)
            log(f"  velociraptor-collector downloaded "
                f"({os.path.getsize(dest)} bytes)", "success")
    else:
        log(f"  velociraptor-collector already staged "
            f"({os.path.getsize(dest)} bytes)", "info")

    # ---- Step 2: register in velociraptor inventory (ALWAYS) ----
    # Staging the file is not enough: without an inventory entry marked
    # serve_locally the endpoint tries to fetch the collector from the
    # internet, which is the one thing an air-gapped deployment cannot do.
    reg = _register_collector_serve_locally(dest, logger=log)
    return {
        "success": True,
        "staged": True,
        "registered": reg.get("success", False),
        "register_error": reg.get("error"),
    }


def _register_collector_serve_locally(dest: str, logger: Optional[Callable] = None) -> Dict:
    """Register the staged collector in Velociraptor's tool inventory.

    Was a gRPC call through pyvelociraptor. The container's own binary speaks
    VQL, so this is the same operation with no client library, no mTLS channel
    built from api.config.yaml, and nothing to keep in step with the server
    version -- which is what let the rest of this work move out to
    lib/upgrade/velo_refresh.sh entirely.

    serve_locally=TRUE is the whole point: without it the endpoint fetches the
    collector from the internet, which an air-gapped deployment cannot do.
    """
    log = logger or (lambda m, l="info": None)
    vql = ("SELECT inventory_add(tool='VelociraptorCollector', serve_locally=TRUE, "
           "file='/tools/%s', accessor='file') AS r FROM scope()" % os.path.basename(dest))
    try:
        r = subprocess.run(
            ["docker", "exec", "intact_velociraptor",
             "/velociraptor/velociraptor", "--config",
             "/velociraptor/server.config.yaml", "query", vql, "--format", "jsonl"],
            capture_output=True, text=True, timeout=120)
    except Exception as e:                      # noqa: BLE001
        log(f"  could not register the collector tool: {e}", "warning")
        return {"success": False, "error": str(e)}
    if r.returncode != 0:
        err = (r.stderr or "").strip()[:200]
        log(f"  collector tool registration failed: {err}", "warning")
        return {"success": False, "error": err}
    log("  velociraptor-collector registered (serve_locally)", "success")
    return {"success": True}
