#!/usr/bin/env python3
"""Velociraptor upgrade functions."""

import os
import shutil
import time
import json
from typing import Dict, Callable, Optional, Tuple

from .base import (
    WORKDIR, HOST_PATH,
    run_command, read_env_file, update_env_file,
    backup_env_file, restore_env_file, cleanup_backup,
    load_docker_image, compare_versions, docker_image_present,
    remove_old_module_image,
)

# ─── Velociraptor config persistence: named volume → host bind-mount ───────────
# server/client/api .config.yaml used to live ONLY in the velociraptor_*_data
# named volume — lost on `down -v`/prune/reinstall, and a regenerated
# server.config.yaml means a NEW CA → every enrolled client breaks. They now
# live host-mounted at data/velociraptor/. These helpers migrate an existing
# (older-release) deployment's configs from the legacy volume into that host
# dir, PRESERVING the CA, before the new bind-mount compose comes up.

_VELO_CONFIGS = ("server.config.yaml", "client.config.yaml", "api.config.yaml")


def _velo_host_dirs():
    """(backend_readable_path, host_path_for_docker_-v) for data/velociraptor."""
    return (os.path.join(WORKDIR, "data", "velociraptor"),
            os.path.join(HOST_PATH, "data", "velociraptor"))


def _besteffort_logger(log: Callable) -> Callable:
    """Wrap a workflow logger so a wrapped command's error-level lines (e.g.
    run_command's 'Command timed out' on a best-effort/optional step) are
    downgraded to warning — they must not pollute the run's error_count
    (which would auto-flip an otherwise-successful upgrade to 'failed') or
    read to the operator as a real failure."""
    def _log(msg, level="info"):
        log(msg, "warning" if level == "error" else level)
    return _log


def _valid_velo_server_config(path) -> bool:
    """True iff `path` is a real server.config.yaml carrying a CA private key —
    so we never enshrine an empty/corrupt file as 'migrated'."""
    try:
        if not (os.path.exists(path) and os.path.getsize(path) > 200):
            return False
        import yaml
        d = yaml.safe_load(open(path)) or {}
        return bool(isinstance(d, dict)
                    and (d.get("CA") or {}).get("private_key")
                    and d.get("Frontend"))
    except Exception:
        return False


def _velo_host_ca_fingerprint():
    """Short SHA-256 of the CA identity in the host server.config.yaml (or
    None). Velociraptor keeps the CA PRIVATE KEY under `CA.private_key` and the
    trusted CA cert under `Client.ca_certificate` — either uniquely identifies
    the CA, so a changed fingerprint means a regenerated CA (clients break)."""
    import hashlib
    backend_dir, _ = _velo_host_dirs()
    try:
        import yaml
        d = yaml.safe_load(open(os.path.join(backend_dir, "server.config.yaml"))) or {}
        ca = ((d.get("CA") or {}).get("private_key")
              or (d.get("Client") or {}).get("ca_certificate") or "")
        return hashlib.sha256(ca.encode()).hexdigest()[:16] if ca else None
    except Exception:
        return None


def _legacy_velo_config_volume():
    """Name of the legacy named volume backing /velociraptor (or matching the
    *_velociraptor_data pattern once the container is gone). None if absent."""
    r = run_command(
        "docker inspect intact_velociraptor "
        "--format '{{range .Mounts}}{{.Name}}::{{.Destination}}{{println}}{{end}}'",
        logger=None)
    if r.get("success"):
        for line in (r.get("stdout") or "").splitlines():
            if line.strip().endswith("::/velociraptor"):
                name = line.split("::")[0].strip()
                if name:
                    return name
    r2 = run_command("docker volume ls --format '{{.Name}}'", logger=None)
    for v in (r2.get("stdout") or "").splitlines():
        v = v.strip()
        if v.endswith("velociraptor_data") and "datastore" not in v and "tmp" not in v:
            return v
    return None


def _migration_copy_image(log: Callable) -> str:
    """Pick a locally-present image (with sh + cp) for the legacy-volume copy.

    Prefer `alpine` when it's already local. On an AIR-GAPPED host alpine isn't
    cached and can't be pulled (`docker run alpine` -> 'Unable to find image ...
    Temporary failure in name resolution'), which used to skip the whole
    migration. Fall back to the velociraptor-server image this very upgrade just
    `docker load`ed — it's ubuntu:22.04-based (has sh + cp) and is guaranteed
    present by the time the migration runs. Last resort stays 'alpine' so an
    online host still auto-pulls it.
    """
    if run_command("docker image inspect alpine", logger=None).get("success"):
        return "alpine"
    r = run_command("docker images --format '{{.Repository}}:{{.Tag}}'", logger=None)
    if r.get("success"):
        for ln in (r.get("stdout") or "").splitlines():
            tag = ln.strip()
            if tag.startswith("velociraptor-server:") and "<none>" not in tag:
                log(f"  alpine unavailable (air-gapped) — using {tag} for the config copy", "info")
                return tag
    return "alpine"


def migrate_velociraptor_config_to_host(logger: Callable = None) -> Dict:
    """One-time migration of the Velociraptor configs from the legacy named
    volume into the host-mounted data/velociraptor/, PRESERVING the CA.

    - Idempotent: no-op once a valid host server.config.yaml exists.
    - Fresh install: no-op (no legacy volume) — entrypoint generates the config.
    - Must run BEFORE the new bind-mount compose comes up (the legacy volume
      survives `compose down --remove-orphans`, so we copy from it directly).
    - On any doubt (copy fails / source invalid) it ABORTS and leaves the old
      named volume intact as a fallback — never half-migrates.
    """
    log = logger or (lambda m, l="info": None)
    backend_dir, host_dir = _velo_host_dirs()
    os.makedirs(backend_dir, exist_ok=True)
    dst = os.path.join(backend_dir, "server.config.yaml")

    if _valid_velo_server_config(dst):
        log("  Velociraptor config already host-mounted (CA present) — migration skipped", "info")
        return {"migrated": False, "reason": "already-present"}

    vol = _legacy_velo_config_volume()
    if not vol:
        log("  No legacy Velociraptor config volume — fresh install; config will be generated", "info")
        return {"migrated": False, "reason": "fresh"}

    log(f"  Migrating Velociraptor config from legacy volume '{vol}' (preserving CA)...", "info")
    staging = os.path.join(backend_dir, ".migrating")
    shutil.rmtree(staging, ignore_errors=True)
    os.makedirs(staging, exist_ok=True)

    files = " ".join(_VELO_CONFIGS)
    copy_image = _migration_copy_image(log)
    cp = run_command(
        f"docker run --rm -v {vol}:/src:ro -v {host_dir}:/dst {copy_image} sh -c "
        f"'mkdir -p /dst/.migrating; for f in {files}; do "
        f"[ -f /src/$f ] && cp /src/$f /dst/.migrating/$f || true; done'",
        logger=None)
    if not cp.get("success"):
        log(f"  Migration copy failed: {cp.get('error')}; legacy volume left untouched", "warning")
        shutil.rmtree(staging, ignore_errors=True)
        return {"migrated": False, "reason": "copy-failed"}

    if not _valid_velo_server_config(os.path.join(staging, "server.config.yaml")):
        log("  Migration aborted: server.config.yaml missing/invalid in the legacy "
            "volume — NOT migrating (old named volume kept as a fallback).", "error")
        shutil.rmtree(staging, ignore_errors=True)
        return {"migrated": False, "reason": "invalid-source"}

    moved = []
    for f in _VELO_CONFIGS:
        s = os.path.join(staging, f)
        if os.path.exists(s):
            os.replace(s, os.path.join(backend_dir, f))
            moved.append(f)
    try:
        os.chmod(dst, 0o600)
    except Exception:
        pass
    shutil.rmtree(staging, ignore_errors=True)
    log(f"  Migrated {len(moved)} Velociraptor config(s) to host (CA preserved): "
        f"{', '.join(moved)}", "success")
    return {"migrated": True, "files": moved, "volume": vol}


def _verify_velo_ca_unchanged(before_fp, logger: Callable = None) -> None:
    """After compose-up, confirm the running server still uses the migrated CA
    (the entrypoint must NOT have regenerated server.config.yaml). A changed
    fingerprint means EVERY enrolled client silently stops reconnecting.

    Escalation (was warning-only): a VERIFIED CA change now RAISES so the
    caller's rollback restores the old server — a failed upgrade is strictly
    better than a fleet that looks fine but never reports again. Operator
    override for a deliberate CA rotation:
        INTACT_ALLOW_VELO_CA_CHANGE=1
    A fingerprint that can't be READ (after_fp None) stays a warning — an
    unverifiable state must not false-positive into a rollback.
    """
    log = logger or (lambda m, l="info": None)
    if not before_fp:
        return  # fresh install — no prior CA to preserve
    time.sleep(3)  # let the entrypoint (re)write derived configs
    after_fp = _velo_host_ca_fingerprint()
    if after_fp and after_fp == before_fp:
        log(f"  ✓ Velociraptor CA preserved across upgrade (fp {before_fp})", "success")
    elif after_fp is None:
        log(f"  ⚠ Could not re-read the Velociraptor CA fingerprint after upgrade — "
            f"CA preservation UNVERIFIED (was {before_fp}). Check client "
            f"reconnection manually.", "warning")
    elif os.environ.get('INTACT_ALLOW_VELO_CA_CHANGE'):
        log(f"  ⚠ Velociraptor CA CHANGED ({before_fp} → {after_fp}) — allowed by "
            f"INTACT_ALLOW_VELO_CA_CHANGE. Enrolled clients need re-enrollment.",
            "warning")
    else:
        log(f"  ✗ Velociraptor CA CHANGED ({before_fp} → {after_fp})! Every enrolled "
            f"client would silently stop reconnecting — failing the upgrade so "
            f"rollback restores the old server. The legacy named volume still "
            f"holds the original config. To rotate the CA deliberately, set "
            f"INTACT_ALLOW_VELO_CA_CHANGE=1 and re-run.", "error")
        raise Exception(
            f"Velociraptor CA changed across upgrade ({before_fp} -> {after_fp}); "
            f"failing to protect the enrolled fleet (set "
            f"INTACT_ALLOW_VELO_CA_CHANGE=1 to permit a deliberate rotation)")


def _existing_artifact_names(logger: Callable = None) -> Optional[set]:
    """Set of artifact names already present in the running Velociraptor
    registry — includes the curated bundle loaded at boot via --definitions
    plus anything Layer-1 init imported. Returns None if the registry can't
    be queried, so callers fall back to importing everything (correctness
    over speed). Lets the snapshot re-imports SKIP artifacts that already
    exist instead of re-importing ~400 of them one-by-one over the API
    (~6.5s each → the ~45-min silent stall seen on offline upgrades)."""
    log = logger or (lambda msg, level="info": None)
    try:
        from services.tools_download_service import setup_velociraptor_connection
        from pyvelociraptor import api_pb2, api_pb2_grpc
        ch = setup_velociraptor_connection()
        if not ch:
            return None
        stub = api_pb2_grpc.APIStub(ch)
        have = set()
        for resp in stub.Query(api_pb2.VQLCollectorArgs(
                max_wait=60, max_row=10000,
                Query=[api_pb2.VQLRequest(VQL='SELECT name FROM artifact_definitions()')]),
                timeout=65):
            if resp.Response:
                for d in json.loads(resp.Response):
                    n = d.get('name')
                    if n:
                        have.add(n)
        return have
    except Exception as e:
        log(f"  Could not list existing artifacts ({type(e).__name__}: {e}); "
            f"will re-import all", "warning")
        return None


def _artifact_name_from_yaml(text: str) -> Optional[str]:
    """Pull the top-level `name:` (artifact identifier) out of an exported
    artifact YAML without a full parse. Column-0 `name:` only, so nested
    source/parameter `name:` keys don't match."""
    import re
    m = re.search(r'^name:\s*["\']?([A-Za-z0-9_.]+)', text, re.MULTILINE)
    return m.group(1) if m else None


def _reimport_artifacts_post_upgrade(velo_data: str, logger: Callable = None,
                                       skip_exchange_imports: bool = False) -> None:
    """Re-register all custom + imported artifacts in the freshly-upgraded
    Velociraptor server's registry.

    Called at the END of a successful upgrade_velociraptor /
    upgrade_velociraptor_offline run, after the new container has passed
    its health check. A Velociraptor binary upgrade leaves the new
    container's artifact registry empty of non-built-in artifacts (the
    data volume persists but the registry is rebuilt on first boot);
    without this re-import, Quick Wins blueprint hunts and Timesketch's
    KapeTriage workflow fail with "artifact not found".

    Re-import has three layers:

    1. `initialize_velociraptor_artifacts()` — the exact same orchestrator
       Maintenance → Refresh Tool Inventory calls. Runs
       `Server.Import.ArtifactExchange` + `Server.Import.DetectRaptor` +
       `Server.Import.Extras` (need internet on the target; gracefully
       degrades to a logged warning when offline). Then re-imports the
       TenRoot zip at `/app/data/tools/Velociraptor-Artifacts-main.zip`
       and `/app/data/custom_artifacts/`.

    2. Pre-upgrade-export catch-all — earlier in the upgrade flow we
       snapshot the OLD registry's custom artifacts to
       `{velo_data}/artifact_definitions/Exported/`. We loop that
       directory here and `import_custom_artifact()` any YAML the
       TenRoot/custom_artifacts paths didn't cover (operator-created
       ad-hoc artifacts that only lived in the registry).

    Failures are SWALLOWED (logged at warning level) — an already-healthy
    upgrade must never be marked failed because of an artifact import
    hiccup.
    """
    log = logger or (lambda msg, level="info": None)
    log("Re-importing custom artifacts into the upgraded Velociraptor...", "info")
    try:
        from services.velociraptor_init_service import (
            initialize_velociraptor_artifacts,
            import_custom_artifact,
        )
    except Exception as e:
        log(
            f"  Could not import velociraptor_init_service "
            f"({type(e).__name__}: {e}); operator should click "
            f"Maintenance → Refresh Tool Inventory.",
            "warning",
        )
        return

    # Layer 1: same orchestrator the Maintenance UI button runs.
    # skip_exchange_imports plumbs through from offline-upgrade callers
    # (where Server.Import.ArtifactExchange / DetectRaptor / Extras need
    # internet at runtime and silently fail on air-gap targets — and
    # the curated bundle is baked into the velociraptor image and loaded
    # on boot via --definitions, so the definitions are already present).
    # Online upgrades
    # pass False (the default) so they still get the live upstream
    # additions Velociraptor's Server.Import.* artifacts would fetch.
    try:
        initialize_velociraptor_artifacts(
            logger_func=log, skip_exchange_imports=skip_exchange_imports
        )
    except Exception as e:
        log(
            f"  initialize_velociraptor_artifacts raised "
            f"({type(e).__name__}: {e}); falling through to "
            f"pre-upgrade-export catch-all.",
            "warning",
        )

    # Layer 2: catch-all from pre-upgrade snapshot.
    exported = os.path.join(velo_data, 'artifact_definitions', 'Exported')
    if not os.path.isdir(exported):
        return
    yamls = sorted(
        f for f in os.listdir(exported) if f.endswith(('.yaml', '.yml'))
    )
    if not yamls:
        return
    # SKIP artifacts already in the registry. The curated bundle is loaded at
    # boot via --definitions and Layer 1 imported the TenRoot/custom set, so
    # most of this snapshot is already present — re-importing all of it
    # one-by-one over the API is ~6.5s each (the ~45-min SILENT stall on
    # offline upgrades). Only the operator's genuinely-custom artifacts remain.
    present = _existing_artifact_names(logger=log)
    total = len(yamls)
    log(f"  Re-importing pre-upgrade snapshot ({total} artifacts; "
        f"skipping any already loaded)...", "info")
    count = skipped = 0
    for i, fn in enumerate(yamls, 1):
        try:
            with open(os.path.join(exported, fn), 'r') as f:
                yaml_content = f.read()
            if present is not None:
                nm = _artifact_name_from_yaml(yaml_content)
                if nm and nm in present:
                    skipped += 1
                    continue
            if import_custom_artifact(yaml_content, logger_func=None):
                count += 1
        except Exception as e:
            log(f"  Re-import {fn} failed ({e}); continuing.", "warning")
        # Progress every 25 so the step is never a silent black box.
        if i % 25 == 0 or i == total:
            log(f"    snapshot progress: {i}/{total} "
                f"(imported {count}, skipped {skipped} already-present)", "info")
    log(f"  Re-imported {count} pre-upgrade-snapshot artifacts "
        f"({skipped} already present, skipped)", "success")


def _restore_bundled_artifact_sources(package_dir: str,
                                       logger: Callable = None) -> None:
    """Copy bundled `artifacts/velociraptor/*` from the offline upgrade
    package into `/app/data/` on the target so the post-upgrade
    `initialize_velociraptor_artifacts()` call has the TenRoot zip and
    custom_artifacts/ available even on a fresh air-gapped host that
    never ran Maintenance with internet.

    Layout the prepare side writes (see prepare_package's velociraptor
    branch):
        <package>/artifacts/velociraptor/Velociraptor-Artifacts-main.zip
        <package>/artifacts/velociraptor/custom_artifacts/*.yaml

    Maps to:
        /app/data/tools/Velociraptor-Artifacts-main.zip
        /app/data/custom_artifacts/*.yaml

    Best-effort: silently no-ops when nothing is bundled (prepare on a
    machine where these files don't exist).
    """
    log = logger or (lambda msg, level="info": None)
    src_dir = os.path.join(package_dir, 'artifacts', 'velociraptor')
    if not os.path.isdir(src_dir):
        return

    src_zip = os.path.join(src_dir, 'Velociraptor-Artifacts-main.zip')
    dst_zip = '/app/data/tools/Velociraptor-Artifacts-main.zip'
    if os.path.isfile(src_zip):
        try:
            os.makedirs(os.path.dirname(dst_zip), exist_ok=True)
            shutil.copy2(src_zip, dst_zip)
            sz_mb = os.path.getsize(dst_zip) / (1024 * 1024)
            log(f"  Restored TenRoot artifacts zip from package "
                f"({sz_mb:.1f} MB) -> {dst_zip}", "info")
        except Exception as e:
            log(f"  TenRoot zip restore failed: {e}", "warning")

    src_custom = os.path.join(src_dir, 'custom_artifacts')
    dst_custom = '/app/data/custom_artifacts'
    if os.path.isdir(src_custom):
        try:
            os.makedirs(dst_custom, exist_ok=True)
            # cp -a preserves perms + handles nested dirs cleanly
            result = run_command(
                f"cp -a {src_custom}/. {dst_custom}/",
                logger=None, timeout=60,
            )
            if result.get('success'):
                n = sum(
                    1 for _, _, files in os.walk(src_custom)
                    for f in files if f.endswith(('.yaml', '.yml'))
                )
                log(f"  Restored {n} custom artifact YAMLs from package "
                    f"-> {dst_custom}/", "info")
            else:
                log(f"  custom_artifacts restore failed: "
                    f"{result.get('error', '')[:120]}", "warning")
        except Exception as e:
            log(f"  custom_artifacts restore raised: {e}", "warning")

    # Legacy Velociraptor binaries (v0.7.x). Prepare staged them at
    # <package>/binaries/legacy/. Drop them into
    # {WORKDIR}/modules/nginx/html/downloads/ so the Downloads page's
    # "Download Legacy EXE / Linux" buttons light up. Without this the
    # buttons stay greyed-out on any host that added velociraptor via
    # Online Upgrade (the initial install.sh seed only runs when
    # velociraptor is enabled at install time).
    legacy_src = os.path.join(package_dir, 'binaries', 'legacy')
    if os.path.isdir(legacy_src):
        legacy_dst = os.path.join(WORKDIR, 'modules', 'nginx', 'html', 'downloads')
        try:
            os.makedirs(legacy_dst, exist_ok=True)
            restored = 0
            for fname in os.listdir(legacy_src):
                src_p = os.path.join(legacy_src, fname)
                if not (os.path.isfile(src_p) and os.path.getsize(src_p) > 1024 * 1024):
                    continue
                dst_p = os.path.join(legacy_dst, fname)
                try:
                    shutil.copy2(src_p, dst_p)
                    if not fname.endswith('.exe'):
                        os.chmod(dst_p, 0o755)
                    restored += 1
                except Exception as e:
                    log(f"  Legacy binary copy failed for {fname}: {e}", "warning")
            if restored:
                log(f"  Restored {restored} legacy Velociraptor binar(y/ies) "
                    f"-> {legacy_dst}/", "info")
        except Exception as e:
            log(f"  Legacy binary restore raised: {e}", "warning")


def _import_bundled_registry_snapshot(package_dir: str,
                                       logger: Callable = None) -> int:
    """Loop the bundled registry-snapshot YAMLs and `import_custom_artifact`
    each into the running Velociraptor's registry.

    The snapshot at `<package>/artifacts/velociraptor/registry_snapshot/`
    was taken from the running Velociraptor on the PREPARE machine via
    SQL `SELECT name, raw FROM artifact_definitions() WHERE built_in =
    FALSE`. That means it already contains every artifact the operator
    had — TenRoot zip imports, custom_artifacts/ imports, AND the
    output of Server.Import.ArtifactExchange / DetectRaptor / Extras
    (which would otherwise need GitHub at apply time).

    Returns the count of successfully-imported artifacts.
    """
    log = logger or (lambda msg, level="info": None)
    snap_dir = os.path.join(package_dir, 'artifacts', 'velociraptor',
                             'registry_snapshot')
    if not os.path.isdir(snap_dir):
        return 0

    try:
        from services.velociraptor_init_service import import_custom_artifact
    except Exception as e:
        log(f"  Could not import import_custom_artifact: {e}", "warning")
        return 0

    yamls = sorted(
        f for f in os.listdir(snap_dir)
        if f.endswith(('.yaml', '.yml'))
    )
    if not yamls:
        return 0

    # SKIP artifacts already in the registry (the --definitions bundle loaded
    # at boot covers most of this snapshot). Avoids re-importing ~400 already-
    # present artifacts one-by-one over the API — the silent multi-minute stall.
    present = _existing_artifact_names(logger=log)
    total = len(yamls)
    log(f"  Importing bundled registry snapshot ({total} artifacts; "
        f"skipping any already loaded)...", "info")
    ok = skipped = 0
    for i, fn in enumerate(yamls, 1):
        try:
            with open(os.path.join(snap_dir, fn), 'r') as f:
                yaml_content = f.read()
            if present is not None:
                nm = _artifact_name_from_yaml(yaml_content)
                if nm and nm in present:
                    skipped += 1
                    continue
            if import_custom_artifact(yaml_content, logger_func=None):
                ok += 1
        except Exception:
            # Per-artifact failures are common with version-skew
            # (newer artifact YAML using fields the new binary
            # doesn't understand). Swallow + continue.
            continue
        # Progress every 25 so the step is never a silent black box.
        if i % 25 == 0 or i == total:
            log(f"    registry-snapshot progress: {i}/{total} "
                f"(imported {ok}, skipped {skipped} already-present)", "info")
    log(f"  Registry snapshot: {ok} imported, {skipped} already present",
        "success" if (ok or skipped) else "warning")
    return ok


def _verify_blueprint_artifacts_loaded(logger: Callable = None) -> Dict:
    """Verify every artifact referenced by the default forensics
    blueprints is actually present in velociraptor's registry after
    import, and log the result. Serves the operator ask "make sure all
    of them was loaded" + "log everything" — if a hunt later fails on a
    missing artifact, the install log already shows exactly which one
    (or confirms all are present so artifacts are ruled out).

    Reads the artifact union from
    modules/backend/config/default_blueprints.yaml at runtime so it
    stays in sync as blueprints change. Best-effort: a velociraptor
    gRPC hiccup logs a warning and returns inconclusive — never fails
    the install/upgrade over a verification step.

    Returns {present: int, missing: [names], total: int, ok: bool}.
    """
    log = logger or (lambda msg, level="info": None)
    import re as _re
    # Blueprint file location: the backend container sees it under /app.
    bp_path = os.path.join(WORKDIR, 'modules', 'backend', 'config', 'default_blueprints.yaml')
    if not os.path.exists(bp_path):
        # Fallback to the in-image copy.
        bp_path = '/app/config/default_blueprints.yaml'
    try:
        with open(bp_path) as f:
            bp_text = f.read()
    except Exception as e:
        log(f"  Artifact verification: could not read blueprints ({e}) — skipping", "warning")
        return {"ok": False, "present": 0, "missing": [], "total": 0}

    # Collect artifact names: list items that look like Velociraptor
    # artifact identifiers (Foo.Bar.Baz with a leading capital).
    wanted = sorted(set(
        m.strip() for m in _re.findall(r'^\s*-\s+([A-Z][A-Za-z0-9]+(?:\.[A-Za-z0-9]+)+)\s*$', bp_text, _re.MULTILINE)
    ))
    if not wanted:
        return {"ok": True, "present": 0, "missing": [], "total": 0}

    try:
        from services.tools_download_service import setup_velociraptor_connection
        from pyvelociraptor import api_pb2, api_pb2_grpc
        import json as _json
        ch = setup_velociraptor_connection()
        if not ch:
            log("  Artifact verification: velociraptor gRPC unreachable — skipping (will retry on Maintenance → Refresh)", "warning")
            return {"ok": False, "present": 0, "missing": [], "total": len(wanted)}
        stub = api_pb2_grpc.APIStub(ch)
        have = set()
        for resp in stub.Query(api_pb2.VQLCollectorArgs(
                max_wait=60, max_row=5000,
                Query=[api_pb2.VQLRequest(VQL='SELECT name FROM artifact_definitions()')]), timeout=65):
            if resp.Response:
                for d in _json.loads(resp.Response):
                    have.add(d.get('name'))
        missing = [a for a in wanted if a not in have]
        if not missing:
            log(f"  ✓ Artifact verification: all {len(wanted)} blueprint artifacts loaded "
                f"— hunts will not fail on missing artifacts", "success")
        else:
            log(f"  ⚠ Artifact verification: {len(wanted)-len(missing)}/{len(wanted)} blueprint "
                f"artifacts loaded; {len(missing)} MISSING — hunts using these will fail:", "warning")
            for m in missing:
                log(f"      ✗ {m}", "warning")
            log(f"  To fix: run Settings → Maintenance → Refresh Tool Inventory (needs internet), "
                f"or re-prepare the package on a host where Velociraptor is running so the full "
                f"artifact registry is snapshotted.", "warning")
        return {"ok": not missing, "present": len(wanted) - len(missing), "missing": missing, "total": len(wanted)}
    except Exception as e:
        log(f"  Artifact verification raised ({type(e).__name__}: {e}) — skipping", "warning")
        return {"ok": False, "present": 0, "missing": [], "total": len(wanted)}


def _verify_and_backfill_blueprint_artifacts(package_dir: str,
                                              logger: Callable = None) -> Dict:
    """Verify all default-blueprint artifacts are loaded; if any are
    missing, backfill them from the bundled zips and re-verify. One
    call covers the whole "make sure all artifacts are there" contract
    for both install + upgrade paths.
    """
    log = logger or (lambda msg, level="info": None)
    res = _verify_blueprint_artifacts_loaded(logger=log)
    missing = res.get("missing") or []
    if not missing:
        return res
    # Backfill the gaps from the bundled zips, then re-verify.
    _backfill_missing_artifacts(package_dir, missing, logger=log)
    return _verify_blueprint_artifacts_loaded(logger=log)


def _backfill_missing_artifacts(package_dir: str, missing_names: list,
                                 logger: Callable = None) -> Dict:
    """Re-import specific artifacts that the bulk import missed.

    The old bulk external-zip import did one gRPC call per
    artifact (320+ for the exchange) with a short timeout; under that
    load a handful time out and fail transiently — 2026-06-16 a fresh
    air-gap install came up with Windows.Detection.Malfind missing
    even though it's in the bundled exchange zip and imports fine in
    isolation. This targeted pass walks the bundled zips, finds the
    YAMLs whose `name:` matches a still-missing blueprint artifact,
    and re-imports each with retries — fast because it only touches
    the few that the bulk pass dropped.

    Returns {recovered: [names], still_missing: [names]}.
    """
    log = logger or (lambda msg, level="info": None)
    if not missing_names:
        return {"recovered": [], "still_missing": []}
    import tempfile, zipfile, re as _re, time as _t
    want = set(missing_names)
    ext_dir = os.path.join(package_dir, 'artifacts', 'velociraptor', 'external')
    if not os.path.isdir(ext_dir):
        return {"recovered": [], "still_missing": list(want)}
    try:
        from services.velociraptor_init_service import import_custom_artifact
    except Exception:
        return {"recovered": [], "still_missing": list(want)}

    log(f"  Backfilling {len(want)} blueprint artifact(s) the bulk import "
        f"missed (transient timeouts): {sorted(want)}", "info")
    recovered = set()
    for zpath in sorted(os.path.join(ext_dir, f) for f in os.listdir(ext_dir) if f.endswith('.zip')):
        if not want - recovered:
            break
        try:
            with tempfile.TemporaryDirectory(prefix='backfill_') as tmp:
                with zipfile.ZipFile(zpath) as zf:
                    zf.extractall(tmp)
                for root, _, files in os.walk(tmp):
                    for fn in files:
                        if not fn.endswith(('.yaml', '.yml')):
                            continue
                        try:
                            content = open(os.path.join(root, fn), 'r', encoding='utf-8', errors='ignore').read()
                        except Exception:
                            continue
                        m = _re.search(r'^\s*name:\s*([A-Za-z0-9._]+)', content, _re.MULTILINE)
                        if not m or m.group(1) not in want or m.group(1) in recovered:
                            continue
                        name = m.group(1)
                        # Retry up to 3× — these are the timeout-prone ones.
                        for attempt in range(3):
                            if import_custom_artifact(content, logger_func=None):
                                recovered.add(name)
                                log(f"    ✓ recovered {name}", "success")
                                break
                            _t.sleep(1)
        except Exception:
            continue
    still = sorted(want - recovered)
    if still:
        log(f"  ⚠ {len(still)} artifact(s) still missing after backfill "
            f"(not in any bundled zip): {still}", "warning")
    return {"recovered": sorted(recovered), "still_missing": still}


# All four binaries the Dockerfile needs to COPY at build time. The
# entrypoint repacks the Mac/Win/Linux clients with the server's config
# on every container boot, so all four MUST be present in the image —
# we can't ship just the linux server. See entrypoint.sh for the
# repack logic.
def _velociraptor_binary_set(clean_version: str) -> Dict[str, str]:
    """Map module-relative dest path → upstream GitHub filename for the
    four binaries required by Dockerfile + entrypoint.sh."""
    return {
        os.path.join('clients', 'linux', 'velociraptor'):
            f"velociraptor-v{clean_version}-linux-amd64",
        os.path.join('clients', 'mac', 'velociraptor_client'):
            f"velociraptor-v{clean_version}-darwin-amd64",
        os.path.join('clients', 'windows', 'velociraptor_client.exe'):
            f"velociraptor-v{clean_version}-windows-amd64.exe",
        os.path.join('clients', 'windows', 'velociraptor_client.msi'):
            f"velociraptor-v{clean_version}-windows-amd64.msi",
    }


# Of the four binaries the Dockerfile expects, only the linux server is
# strictly REQUIRED — without it the container won't start. The
# Mac/Windows CLIENT binaries are convenience artifacts the entrypoint
# tries to repack with the server's config (see entrypoint.sh). When
# they're missing the repack step fails silently and operators just
# don't get a pre-configured client for that platform.
#
# Upstream Velociraptor releases are inconsistent: v0.75.6 ships no
# darwin-amd64; some point releases skip the MSI. We treat those as
# best-effort + drop a zero-byte placeholder so the Dockerfile COPY
# still succeeds.
_REQUIRED_BINARY = os.path.join('clients', 'linux', 'velociraptor')


# Filenames the operator-facing Downloads page expects in
# modules/nginx/html/downloads/. The dashboard's /api/clients/legacy/status
# probes each path; if a file is missing for the configured modern_version
# the corresponding button greys out. install.sh fetches these at first
# install via lib/docker.sh:download_offline_collector_binaries, but the
# upgrade flow didn't refresh them when the pin moves — so a 0.76.5 →
# 0.76.6 bump left the musl binary stale and the "Download Linux (musl)"
# button greyed out (operator hit 2026-06-14). _refresh_offline_collector_downloads
# below closes that gap from both upgrade entry points.
_OFFLINE_COLLECTOR_FILENAMES = (
    "velociraptor-v{v}-windows-amd64.exe",
    "velociraptor-v{v}-windows-amd64.msi",
    "velociraptor-v{v}-linux-amd64",
    "velociraptor-v{v}-linux-amd64-musl",
    "velociraptor-v{v}-darwin-amd64",
)


# ---------------------------------------------------------------------------
# velociraptor-collector — small (~80 KB) template binary that velociraptor's
# server-side `client_repack` VQL function uses as a base when generating
# Hunt offline collectors. Distinct from the per-OS velociraptor binaries
# we already stage:
#   - velociraptor-v{v}-windows-amd64.exe  → operator-facing Downloads page
#   - velociraptor-v{v}-linux-amd64        → server image build context
#   - velociraptor-collector               → server's tools dir, used by
#                                            client_repack at runtime
#
# If this file isn't present in /data/tools/, velociraptor server falls back
# to fetching https://github.com/Velocidex/velociraptor/releases/download/v<track>/velociraptor-collector
# at the moment the operator clicks "Generate Collector" — which fails on
# air-gap targets AND on online targets with transient DNS issues
# (2026-06-16 incident: Hunt: Quick Scan collector generation died with
# "lookup github.com on 127.0.0.11:53: server misbehaving" because the
# file wasn't in /data/tools/ on this fresh-install host).


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
    reg = _register_collector_serve_locally(dest, logger=log)
    return {
        "success": True,
        "staged": True,
        "registered": reg.get("success", False),
        "register_error": reg.get("error"),
    }


def _register_collector_serve_locally(collector_path: str,
                                       logger: Optional[Callable] = None) -> Dict:
    """Register the staged velociraptor-collector in velociraptor's tool
    inventory with serve_locally=TRUE so `client_repack` reads it from
    the server's local filestore instead of fetching from github.

    Mirrors the inventory_add VQL in
    tools_download_service.py:configure_inventory, scoped to the single
    VelociraptorCollector tool. Requires the velociraptor server to be
    up + its gRPC API reachable; on a fresh install/upgrade this runs
    after the readiness wait so the API is live.

    The tool name MUST be "VelociraptorCollector" — that's what the
    inventory entry in data/tools_inventory.yaml uses and what
    velociraptor's Server.Utils.CreateCollector / client_repack looks
    up. The file inside velociraptor is at /tools/velociraptor-collector
    (the bind-mount of /app/data/tools).
    """
    log = logger or (lambda msg, level="info": None)
    try:
        from services.tools_download_service import setup_velociraptor_connection
        from pyvelociraptor import api_pb2, api_pb2_grpc
        import json as _json

        channel = setup_velociraptor_connection()
        if not channel:
            log("  collector inventory registration: velociraptor gRPC "
                "not reachable — Hunt collector may reach github until "
                "Maintenance → Refresh Tool Inventory is run", "warning")
            return {"success": False, "error": "no grpc"}

        stub = api_pb2_grpc.APIStub(channel)
        # Velociraptor sees the tools dir bind-mounted at /tools.
        velo_file_path = "/tools/velociraptor-collector"
        vql = f'''
        SELECT inventory_add(
            tool="VelociraptorCollector",
            serve_locally=TRUE,
            file="{velo_file_path}",
            filename="velociraptor-collector",
            accessor="file"
        ) AS Result FROM scope()
        '''
        request = api_pb2.VQLCollectorArgs(
            max_wait=60, max_row=10,
            Query=[api_pb2.VQLRequest(VQL=vql)],
        )
        file_hash = None
        ok = False
        for response in stub.Query(request, timeout=65):
            if response.Response:
                data = _json.loads(response.Response)
                if data and data[0].get('Result'):
                    ok = True
                    file_hash = data[0]['Result'].get('hash', '')
        if not ok:
            log("  collector inventory registration: inventory_add "
                "returned no result", "warning")
            return {"success": False, "error": "no result"}

        # Copy into the filestore so the served file survives even if the
        # bind-mount path shifts. Same belt-and-braces copy configure_inventory
        # does. Best-effort.
        if file_hash:
            copy_vql = f'''
            SELECT copy(
                filename="{velo_file_path}",
                accessor="file",
                dest="/var./public/{file_hash}",
                permissions="0600"
            ) FROM scope()
            '''
            try:
                copy_req = api_pb2.VQLCollectorArgs(
                    max_wait=30, max_row=1,
                    Query=[api_pb2.VQLRequest(VQL=copy_vql)],
                )
                for _ in stub.Query(copy_req, timeout=35):
                    pass
            except Exception:
                pass

        log("  ✓ velociraptor-collector registered in inventory "
            "(serve_locally=TRUE) — Hunt collector generation will use "
            "the local binary, no github fetch", "success")
        return {"success": True}
    except Exception as e:
        log(f"  collector inventory registration raised "
            f"({type(e).__name__}: {e}) — Hunt collector may reach "
            f"github until Maintenance → Refresh Tool Inventory is run",
            "warning")
        return {"success": False, "error": str(e)}


def _restore_and_configure_tools(package_dir: str,
                                 logger: Optional[Callable] = None) -> Dict:
    """Place package-bundled Velociraptor tools into /data/tools/ and
    register them in velociraptor's inventory with serve_locally=TRUE.

    This is what makes air-gap COLLECTOR GENERATION work for artifacts
    that embed external tools. Artifacts like
    DetectRaptor.Windows.Detection.LolRMM reference a tool
    (DetectRaptorLolRMM = lolrmm.csv) that velociraptor's client_repack
    fetches from the internet at generation time. Without the tool
    served locally, generation dies on an air-gap host with
    `client_repack: Get ".../lolrmm.csv": lookup github.com ...
    connection refused` (2026-06-16 incident: cve_management collector).

    The prepare side bundles every tools_inventory.yaml tool into
    <package>/tools/. Here we:
      1. Copy them into /app/data/tools/ (bind-mounted into
         velociraptor at /tools).
      2. Run configure_inventory() — the same Phase-2 step the
         install.sh / Maintenance→Refresh-Tools path uses — to register
         each tool serve_locally=TRUE so client_repack reads from the
         local filestore instead of the internet.

    Best-effort: a failure logs a warning naming the consequence but
    never fails the velociraptor install/upgrade. Tools the operator
    doesn't use won't matter; the ones they do (cve_management's
    lolrmm) now resolve locally.
    """
    log = logger or (lambda msg, level="info": None)
    import shutil
    pkg_tools = os.path.join(package_dir, 'tools')
    if not os.path.isdir(pkg_tools):
        log("  No bundled tools dir in package — air-gap collector "
            "generation for tool-backed artifacts (cve_management, etc.) "
            "will fetch tools from the internet and fail on air-gap. "
            "Re-prepare with a build that bundles tools.", "warning")
        return {"success": False, "error": "no bundled tools"}

    dest_tools = "/app/data/tools"
    os.makedirs(dest_tools, exist_ok=True)
    placed = 0
    for fn in os.listdir(pkg_tools):
        src = os.path.join(pkg_tools, fn)
        if not os.path.isfile(src):
            continue
        try:
            shutil.copy2(src, os.path.join(dest_tools, fn))
            placed += 1
        except Exception as e:
            log(f"    ✗ tool copy failed for {fn}: {e}", "warning")
    log(f"  Placed {placed} bundled tools into {dest_tools}", "info")

    # Register them serve_locally via the existing inventory configurator.
    try:
        from services.tools_download_service import load_tools_config, configure_inventory
        cfg = load_tools_config()
        if not cfg:
            log("  tools_inventory.yaml not loadable — tools placed but "
                "not registered serve_locally; collector generation may "
                "still reach the internet for them", "warning")
            return {"success": False, "error": "no tools config"}
        # configure_inventory reads from the container-visible tools dir.
        res = configure_inventory("/tools", cfg, logger=log)
        configured = len((res.get("results") or {}).get("configured", []))
        already = len((res.get("results") or {}).get("already_served", []))
        log(f"  ✓ Velociraptor tools registered serve_locally "
            f"({configured} configured, {already} already served) — "
            f"air-gap collector generation will use local tool copies",
            "success")
        return {"success": True, "placed": placed, "configured": configured}
    except Exception as e:
        log(f"  Tool inventory configuration raised "
            f"({type(e).__name__}: {e}) — tools placed but registration "
            f"incomplete; run Maintenance → Refresh Tool Inventory to "
            f"finish", "warning")
        return {"success": False, "error": str(e)}


def _refresh_offline_collector_downloads(clean_version: str,
                                          source: str,
                                          package_binaries_dir: Optional[str] = None,
                                          logger: Optional[Callable] = None) -> Dict:
    """Ensure the operator-visible downloads dir matches the new pin.

    Mirrors what lib/docker.sh:download_offline_collector_binaries does at
    install time, but driven from the upgrade flow so a pin bump (e.g.
    0.76.5 → 0.76.6) refreshes the per-platform binaries that back the
    Downloads page + offline-collector generation. Includes the
    linux-amd64-musl variant, which is what /api/clients/legacy/status's
    `modern_musl` slot checks (and what the Linux (musl) button serves).

    Steps:
      1. Stale-pin cleanup — remove any velociraptor-v*-{platform}{ext}
         files in the downloads dir whose version segment isn't the new
         pin. Same pattern as the install-time loop.
      2. For each of the 5 platforms, place the new file:
           source == "github"  → download from upstream
           source == "package" → copy from <package>/binaries/
      3. Best-effort: a missing platform binary on upstream (e.g.
         v0.75.6 has no darwin-amd64) is logged as a warning, not an
         error. Required-ness is decided by the build path
         (_stage_binaries_for_build), not here.

    Args:
        clean_version: target version string (no leading 'v', e.g. '0.76.6').
        source: 'github' or 'package'.
        package_binaries_dir: required when source == 'package'; the
            dir containing the upstream-named files (same layout as
            prepare's <package>/binaries/).
        logger: standard (msg, level) callable.

    Returns:
        {"success": bool, "refreshed": [<fname>...], "missing": [<fname>...]}
        success is True iff at least one file was placed (operator can
        still serve some platforms even if upstream is missing one).
    """
    log = logger or (lambda msg, level="info": None)
    downloads_dir = os.path.join(WORKDIR, 'modules', 'nginx', 'html', 'downloads')
    os.makedirs(downloads_dir, exist_ok=True)

    log(f"Refreshing offline-collector downloads for v{clean_version}...", "info")

    # Step 1 — purge stale-pin binaries so the dir doesn't accumulate
    # cruft across upgrades. We only touch files matching the
    # velociraptor-v*-{platform} pattern AND only when the version
    # segment isn't either the new modern pin OR the configured legacy
    # pin (versions.velociraptor_legacy in config.yaml). The legacy
    # binaries back the Windows/Linux Legacy buttons and are managed
    # separately by lib/docker.sh:download_legacy_velociraptor_binaries
    # + _restore_bundled_artifact_sources — clobbering them here would
    # grey those buttons out (regression I caught during the 2026-06-14
    # smoke test). Anything else (operator artefacts, non-velociraptor
    # files) is left alone by the prefix filter.
    legacy_version: Optional[str] = None
    try:
        import yaml
        cfg_path = os.path.join(WORKDIR, 'config.yaml')
        if os.path.exists(cfg_path):
            with open(cfg_path) as f:
                cfg = yaml.safe_load(f) or {}
            legacy_version = (cfg.get('versions') or {}).get('velociraptor_legacy')
            if legacy_version is not None:
                legacy_version = str(legacy_version)
    except Exception as e:
        log(f"  Could not read legacy pin from config.yaml ({e}); "
            f"keeping all non-target version files to be safe", "warning")

    keep_tokens = [f"-v{clean_version}-"]
    if legacy_version:
        keep_tokens.append(f"-v{legacy_version}-")

    stale = 0
    platform_suffixes = (
        '-windows-amd64.exe', '-windows-amd64.msi',
        '-linux-amd64', '-linux-amd64-musl', '-darwin-amd64',
    )
    for fname in os.listdir(downloads_dir):
        if not fname.startswith('velociraptor-v'):
            continue
        if not any(fname.endswith(suf) for suf in platform_suffixes):
            continue
        if any(tok in fname for tok in keep_tokens):
            continue
        try:
            os.remove(os.path.join(downloads_dir, fname))
            log(f"  Removed stale binary: {fname}", "info")
            stale += 1
        except Exception as e:
            log(f"  Could not remove stale {fname}: {e}", "warning")
    if stale:
        log(f"  Stale binaries removed: {stale} "
            f"(kept pins: modern=v{clean_version}"
            f"{', legacy=v' + legacy_version if legacy_version else ''})",
            "info")

    # Step 2 — place each platform binary.
    release_tag = (
        resolve_velociraptor_release_tag(clean_version, logger=log)
        if source == "github" else None
    )
    base_url = (
        f"https://github.com/Velocidex/velociraptor/releases/download/{release_tag}"
        if release_tag else None
    )

    refreshed: list = []
    missing: list = []
    for tmpl in _OFFLINE_COLLECTOR_FILENAMES:
        fname = tmpl.format(v=clean_version)
        dest = os.path.join(downloads_dir, fname)

        if os.path.exists(dest) and os.path.getsize(dest) > 1024 * 1024:
            log(f"  Already present: {fname}", "info")
            refreshed.append(fname)
            continue

        ok = False
        if source == "package":
            assert package_binaries_dir, (
                "package_binaries_dir required when source='package'")
            src = os.path.join(package_binaries_dir, fname)
            if os.path.exists(src) and os.path.getsize(src) > 1024 * 1024:
                try:
                    shutil.copy2(src, dest)
                    ok = True
                except Exception as e:
                    log(f"  Copy failed for {fname}: {e}", "warning")
            else:
                log(f"  Not in package: {fname}", "warning")
        else:  # github
            url = f"{base_url}/{fname}"
            log(f"  Downloading: {fname}", "info")
            res = run_command(
                f"curl -fL --retry 3 --retry-delay 5 "
                f"--retry-max-time 900 --connect-timeout 30 -o {dest} {url}",
                logger=log, timeout=1200,
            )
            ok = (
                res.get('success')
                and os.path.exists(dest)
                and os.path.getsize(dest) > 1024 * 1024
            )
            if not ok and os.path.exists(dest):
                # curl -f exits non-zero on 4xx but may have written partial
                # bytes (404 HTML page, etc.). Drop the bad file so the
                # API doesn't report it as available.
                os.remove(dest)

        if ok:
            if not fname.endswith('.msi'):
                try:
                    os.chmod(dest, 0o755)
                except Exception:
                    pass
            log(f"  Placed: {fname} "
                f"({os.path.getsize(dest) // (1024*1024)} MB)", "success")
            refreshed.append(fname)
        else:
            log(f"  Missing: {fname} (button will grey out on Downloads page)",
                "warning")
            missing.append(fname)

    return {
        "success": bool(refreshed),
        "refreshed": refreshed,
        "missing": missing,
    }


def refresh_velociraptor_build_files(src_velo_dir: str, dst_velo_dir: Optional[str] = None,
                                     logger: Optional[Callable] = None) -> bool:
    """Refresh the velociraptor image build inputs from a fresh source tree.

    Copies Dockerfile, entrypoint.sh, .dockerignore and the whole
    bundled_artifacts/ pack from ``src_velo_dir`` into the build context
    (``dst_velo_dir``, default WORKDIR/modules/velociraptor) BEFORE the image is
    baked. This is the fix for "many artifacts missing after upgrade": velociraptor
    is the only module whose image is BUILT locally, and the bake reads the
    on-disk build files — but modules/velociraptor is NOT covered by the intact
    source-mirror, so a box with stale build files re-bakes the OLD, bundle-less
    image and the server then has only its ~438 compiled-in built-ins (no
    --definitions pack). Refreshing from the target release's source guarantees
    the image is baked from the CURRENT Dockerfile + the full ~400-artifact bundle
    on every path that rebuilds (online prepare, offline package, local rebuild).
    No-op (returns False) when src is absent — caller falls back to on-disk files.
    """
    import shutil
    log = logger or (lambda m, l="info": None)
    dst = dst_velo_dir or os.path.join(WORKDIR, 'modules', 'velociraptor')
    if not src_velo_dir or not os.path.isdir(src_velo_dir):
        log(f"  No fresh velociraptor source at {src_velo_dir} — baking from on-disk build files", "warning")
        return False
    copied = []
    try:
        os.makedirs(dst, exist_ok=True)
        for fname in ('Dockerfile', 'entrypoint.sh', '.dockerignore'):
            s = os.path.join(src_velo_dir, fname)
            if os.path.isfile(s):
                shutil.copy2(s, os.path.join(dst, fname))
                copied.append(fname)
        src_bundle = os.path.join(src_velo_dir, 'bundled_artifacts')
        if os.path.isdir(src_bundle):
            dst_bundle = os.path.join(dst, 'bundled_artifacts')
            shutil.rmtree(dst_bundle, ignore_errors=True)
            shutil.copytree(src_bundle, dst_bundle)
            copied.append(f"bundled_artifacts/ ({len(os.listdir(src_bundle))} YAMLs)")
    except Exception as e:
        log(f"  Could not refresh velociraptor build files ({type(e).__name__}: {e})", "warning")
        return False
    log(f"  Refreshed velociraptor build files from source: {', '.join(copied) or '(nothing)'}", "success")
    return True


def _publish_client_binaries_to_tools(module_dir: str, version: str,
                                      logger: Callable = None) -> None:
    """Mirror the staged client binaries into ``data/tools`` under their
    UPSTREAM versioned names, so Velociraptor's inventory can serve them.

    Staging writes GENERIC names under ``modules/velociraptor/clients/``
    (``velociraptor_client.exe``), but ``velociraptor_inventory`` matches
    ``^velociraptor-v.*-windows-amd64.exe$`` inside ``data/tools``. Nothing
    bridged the two, so the agent binaries sat on the box while the inventory
    reported them "File not found" forever — and with no locally-served
    client, Velociraptor reaches upstream to build client packages at hunt
    time, which fails air-gapped. Same failure mode as the image/tar bug.

    Best-effort: never raises. A missing binary just isn't published.
    """
    log = logger or (lambda msg, level="info": None)
    try:
        tools_dir = os.path.join(WORKDIR, 'data', 'tools')
        os.makedirs(tools_dir, exist_ok=True)
        pairs = [
            (os.path.join(module_dir, 'clients', 'linux', 'velociraptor'),
             f'velociraptor-v{version}-linux-amd64'),
            (os.path.join(module_dir, 'clients', 'mac', 'velociraptor_client'),
             f'velociraptor-v{version}-darwin-amd64'),
            (os.path.join(module_dir, 'clients', 'windows', 'velociraptor_client.exe'),
             f'velociraptor-v{version}-windows-amd64.exe'),
            (os.path.join(module_dir, 'clients', 'windows', 'velociraptor_client.msi'),
             f'velociraptor-v{version}-windows-amd64.msi'),
        ]
        published = 0
        for src, name in pairs:
            # Skip the zero-byte placeholders staging inserts for platforms
            # upstream didn't publish.
            if not (os.path.exists(src) and os.path.getsize(src) > 0):
                continue
            shutil.copyfile(src, os.path.join(tools_dir, name))
            published += 1

        # Drop stale per-version copies so the dir doesn't grow ~85 MB an upgrade.
        keep = f'velociraptor-v{version}-'
        for fn in os.listdir(tools_dir):
            if (fn.startswith('velociraptor-v') and not fn.startswith(keep)
                    and any(fn.endswith(s) for s in ('-linux-amd64', '-darwin-amd64',
                                                     '-windows-amd64.exe', '-windows-amd64.msi'))):
                try:
                    os.remove(os.path.join(tools_dir, fn))
                except OSError:
                    pass

        if published:
            log(f"  Published {published} client binaries to data/tools "
                f"(inventory can serve them locally)", "info")
    except Exception as e:
        log(f"  Could not publish client binaries to data/tools: {e}", "warning")


def _stage_binaries_for_build(
    module_dir: str,
    clean_version: str,
    source: str,
    package_binaries_dir: Optional[str] = None,
    logger: Optional[Callable] = None,
) -> Dict:
    """Stage the four Velociraptor binaries into the module's build
    context so `docker compose build` can COPY them without any
    network access at build time.

    Args:
        module_dir: e.g. /app/workdir/modules/velociraptor — the Dockerfile build context.
        clean_version: e.g. "0.75.6" (no `v` prefix).
        source: "github" (curl from upstream) or "package" (copy from `package_binaries_dir`).
        package_binaries_dir: required when source == "package". The dir is
            expected to contain files named per `_velociraptor_binary_set`.
        logger: standard logger callable (msg, level).

    Returns:
        {"success": bool, "staged": [<rel>...], "placeholder": [<rel>...]}

    `success` is True iff the linux server binary was staged. Mac/Win
    misses become zero-byte placeholders + warnings.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    # Probe GitHub for the release tag only when we'll actually fetch
    # from there. Offline-apply paths pass source="package" and copy
    # from the bundled binaries — the probe's result is unused, and
    # logging "tag probe failed" during offline apply was misleading
    # operators into thinking the upgrade was failing when it wasn't
    # (2026-06-15 incident).
    if source == "github":
        release_tag = resolve_velociraptor_release_tag(clean_version, logger=log)
        base_url = f"https://github.com/Velocidex/velociraptor/releases/download/{release_tag}"
    else:
        release_tag = None
        base_url = None

    staged: list = []
    placeholder: list = []
    linux_ok = False
    for rel_dest, upstream_fname in _velociraptor_binary_set(clean_version).items():
        is_required = (rel_dest == _REQUIRED_BINARY)
        dest = os.path.join(module_dir, rel_dest)
        os.makedirs(os.path.dirname(dest), exist_ok=True)

        ok = False
        if source == "package":
            assert package_binaries_dir, "package_binaries_dir is required when source='package'"
            src_path = os.path.join(package_binaries_dir, upstream_fname)
            if os.path.exists(src_path):
                res = run_command(f"cp {src_path} {dest}", logger=log, timeout=60)
                ok = res['success']
            else:
                log(f"  [stage] missing in package: {upstream_fname}", "warning")
        else:  # github
            url = f"{base_url}/{upstream_fname}"
            log(f"  [stage] download {upstream_fname}", "info")
            res = run_command(
                f"curl -fL --retry 5 --retry-delay 5 "
                f"--retry-max-time 600 --connect-timeout 30 -o {dest} {url}",
                logger=log, timeout=1800,
            )
            ok = res['success'] and os.path.exists(dest) and os.path.getsize(dest) > 0
            if not ok and os.path.exists(dest):
                # curl -f exits non-zero on HTTP 4xx but may have written partial bytes
                os.remove(dest)

        if ok:
            if not dest.endswith('.msi'):
                # Explicit mode: `chmod +x` is umask-masked (see velo_bin below).
                run_command(f"chmod 755 {dest}", logger=log)
            staged.append(rel_dest)
            if is_required:
                linux_ok = True
        else:
            if is_required:
                # Fail loud — Dockerfile build will explode anyway, this
                # makes the message actionable.
                log(f"  [stage] REQUIRED binary missing: {upstream_fname}", "error")
                return {
                    "success": False,
                    "staged": staged,
                    "placeholder": placeholder,
                    "error": f"required binary not available upstream: {upstream_fname}",
                }
            # Drop an empty placeholder so the Dockerfile's COPY
            # succeeds. Runtime entrypoint's repack step will silently
            # no-op on the empty file. Operators who need that client
            # can run `velociraptor config repack` later by hand.
            log(f"  [stage] {upstream_fname} unavailable upstream — using empty placeholder", "warning")
            with open(dest, 'wb') as f:
                pass  # zero bytes
            placeholder.append(rel_dest)

    return {
        "success": linux_ok,
        "staged": staged,
        "placeholder": placeholder,
    }


def resolve_velociraptor_release_tag(clean_version: str, logger: Callable = None) -> str:
    """Return the github release tag that actually hosts this version's assets.

    Velocidex's release naming has shifted over time:

    * Older releases (<= 0.7.x and 0.74/0.75/0.76 line) shipped multiple
      patch builds under a single rolling tag like ``v0.76`` —
      ``velociraptor-v0.76.5-linux-amd64`` lived at
      ``releases/download/v0.76/...``.
    * Starting roughly v0.76.6, Velocidex publishes each patch as its
      OWN release, e.g. tag ``v0.76.6`` holds the v0.76.6 assets — the
      old rolling ``v0.76`` release stays frozen at an earlier patch.

    The old code hard-coded ``f"v{major}.{minor}"`` and silently 404'd
    on every new patch release. We now HEAD-probe the full-version tag
    first; only if that 404s do we fall back to the rolling tag.

    Why HEAD not API: cheaper than the GitHub releases endpoint, no
    rate-limit cost, no token needed. One HEAD per upgrade is
    negligible.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    parts = clean_version.split('.')
    full_tag = f"v{clean_version}"                              # v0.76.6
    minor_tag = f"v{parts[0]}.{parts[1]}" if len(parts) >= 2 else full_tag  # v0.76

    binary = f"velociraptor-v{clean_version}-linux-amd64"
    for candidate in (full_tag, minor_tag):
        url = f"https://github.com/Velocidex/velociraptor/releases/download/{candidate}/{binary}"
        try:
            import requests
            r = requests.head(url, allow_redirects=False, timeout=10)
            if r.status_code in (200, 302):
                log(f"  Release tag resolved: {candidate} (probed {r.status_code})", "info")
                return candidate
        except Exception:
            continue
    # Last-resort default. The caller's actual download will surface
    # the 404 with a clear log line.
    log(f"  Release tag probe failed for both {full_tag} and {minor_tag}; "
        f"defaulting to {minor_tag} — the download will fail loudly.", "warning")
    return minor_tag


def get_velociraptor_download_url(version: str, logger: Callable = None) -> Tuple[Optional[str], Optional[str]]:
    """Build Velociraptor binary download URL from version string.

    Velociraptor URL pattern (resolved at call time):
    https://github.com/Velocidex/velociraptor/releases/download/<resolved-tag>/velociraptor-v{version}-linux-amd64

    The resolved-tag is :func:`resolve_velociraptor_release_tag` — tries
    ``v{full_version}`` first, falls back to ``v{major.minor}``.

    Args:
        version: Version string like "0.76.6" or "v0.76.6" (full version required)

    Returns:
        Tuple of (download_url, clean_version) or (None, None) if invalid
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))

    # Normalize version - strip 'v' prefix
    clean_version = version.lstrip('v')
    parts = clean_version.split('.')

    # Require full version (major.minor.patch)
    if len(parts) < 3:
        log(f"  Full version required (e.g., 0.75.6), got: {version}", "warning")
        log(f"  Check https://github.com/Velocidex/velociraptor/releases for available versions", "info")
        return None, None

    release_tag = resolve_velociraptor_release_tag(clean_version, logger=log)
    binary_name = f"velociraptor-v{clean_version}-linux-amd64"
    download_url = f"https://github.com/Velocidex/velociraptor/releases/download/{release_tag}/{binary_name}"

    log(f"  Version: {clean_version}", "info")
    log(f"  Binary: {binary_name}", "info")

    return download_url, clean_version


def regenerate_client_installers(logger: Callable = None,
                                  run_id: Optional[str] = None) -> Dict:
    """Rebuild the pre-configured client installers (MSI / EXE / Linux / Mac).

    The installers in client_installers/ embed the Velociraptor BINARY they
    were repacked from, so a server upgrade leaves every one of them shipping
    the previous agent. Fresh installs already ran this; the two upgrade paths
    did not, so an upgraded server kept handing out the old agent from the
    Downloads page indefinitely — the version gap only shows up later, per
    host, in the client's Agent Version.

    Best-effort on purpose. The upgrade itself has already completed and been
    health-checked by the time this runs; stale installers are a real problem
    but not a reason to roll back a working server. Failures log a warning
    naming the manual command.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    script = os.path.join(WORKDIR, 'scripts', 'generate_clients.sh')

    if not os.path.isfile(script):
        log(f"  generate_clients.sh not found at {script}. Client installers "
            f"still contain the PREVIOUS agent until it is run manually.",
            "warning")
        return {"success": False, "error": "script not found"}

    log("Regenerating client installers (MSI / EXE / Linux / Mac / musl) "
        "against the new version...", "info")
    try:
        cg = run_command(f"bash {script}", logger=log, timeout=600, run_id=run_id)
    except Exception as e:
        log(f"  generate_clients.sh raised: {e}. Client installers still "
            f"contain the PREVIOUS agent; re-run "
            f"`bash scripts/generate_clients.sh` on the host.", "warning")
        return {"success": False, "error": str(e)}

    if cg.get('success'):
        log("  Client installers regenerated; the Downloads page now serves "
            "the new agent.", "success")
        return {"success": True}

    err = (cg.get('error') or '')[:200]
    log(f"  generate_clients.sh returned non-zero: {err}. Client installers "
        f"still contain the PREVIOUS agent; re-run "
        f"`bash scripts/generate_clients.sh` on the host.", "warning")
    return {"success": False, "error": err}


def upgrade_velociraptor(version: str, logger: Callable = None,
                          run_id: Optional[str] = None) -> Dict:
    """Upgrade Velociraptor to specified version with automatic rollback on failure."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    work_dir = os.path.join(WORKDIR, 'modules', 'velociraptor')
    velo_data = os.path.join(work_dir, 'velociraptor')
    env_file = os.path.join(work_dir, '.env')
    container_name = 'intact_velociraptor'

    log("Starting Velociraptor upgrade...", "info")

    # Get current version for rollback
    current_vars = read_env_file(env_file)
    current_version = current_vars.get('VELOCIRAPTOR_VERSION', 'unknown')

    # Reject downgrades. Velociraptor's filestore + datastore schema is
    # forward-compatible only; the docs explicitly warn against rolling
    # the server binary backwards over an existing datastore. Without
    # this guard the upgrade UI happily accepts a lower version (e.g.
    # 0.76.2 -> 0.75.6 selected by mistake in the prepare dialog) and
    # we end up with a half-broken container that fails to start.
    if current_version != 'unknown' and compare_versions(version, current_version) < 0:
        error_msg = (
            f"Velociraptor downgrade not supported: {current_version} -> {version}. "
            f"The server binary cannot be rolled backwards over an existing datastore."
        )
        log(error_msg, "error")
        return {"success": False, "error": error_msg}

    if current_version != 'unknown' and compare_versions(version, current_version) == 0:
        log(f"Velociraptor is already at version {version}", "info")
        return {"success": True, "version": version, "message": "Already at target version"}

    # Export artifacts to disk (before stopping)
    log("Exporting custom artifacts...", "info")
    export_dir = os.path.join(velo_data, 'artifact_definitions', 'Exported')
    os.makedirs(export_dir, exist_ok=True)

    try:
        export_cmd = f"""docker exec {container_name} /velociraptor/velociraptor \
            --config /velociraptor/server.config.yaml query \
            "SELECT name, raw FROM artifact_definitions() WHERE built_in = false AND raw != ''" \
            --format jsonl 2>/dev/null"""
        # This query can return several MB of custom-artifact YAML. It used to
        # "time out" here at ANY timeout value (8s, 20s, 30s all failed
        # identically) — not because Velociraptor was slow, but because
        # run_command()'s poll loop never drained stdout/stderr while
        # waiting, so output past the ~64KB OS pipe buffer deadlocked the
        # child on write(). Fixed at the root in run_command (continuous
        # pipe-draining reader threads) rather than papered over here with a
        # bigger timeout or a retry loop — this single call now succeeds in
        # a few seconds. Still best-effort: a genuine Velociraptor outage
        # skips this optional backup rather than failing the upgrade (custom
        # artifacts live in the datastore volume and are refreshed from
        # source regardless).
        result = run_command(export_cmd, logger=_besteffort_logger(log), timeout=20)
        if result['success'] and result.get('stdout'):
            exported = 0
            for line in result['stdout'].strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        name = data.get('name', '')
                        raw = data.get('raw', '')
                        if name and raw:
                            filename = name.replace('.', '__').replace('/', '__') + '.yaml'
                            with open(os.path.join(export_dir, filename), 'w') as f:
                                f.write(raw)
                            exported += 1
                    except:
                        pass
            log(f"  Exported {exported} custom artifacts", "info")
        elif not result.get('success'):
            log("  Custom-artifact export skipped — Velociraptor's API is busy "
                "mid-upgrade (expected). This is a best-effort convenience "
                "export only: custom artifacts live in the datastore volume, "
                "which survives the upgrade, and are refreshed from source "
                "regardless. Nothing is lost and no action is needed.",
                "info")
    except Exception as e:
        log(f"  Export warning: {str(e)[:50]}", "warning")

    # Create backups
    log(f"Backing up current config (version {current_version})...", "info")
    env_backup = backup_env_file(env_file, logger=log)

    backup_dir = f"/tmp/velo-upgrade-backup-{int(time.time())}"
    os.makedirs(backup_dir, exist_ok=True)

    config_dir = os.path.join(velo_data, 'config')
    if os.path.exists(config_dir):
        run_command(f"cp -a {config_dir} {backup_dir}/config", logger=log)

    artifact_dir = os.path.join(velo_data, 'artifact_definitions')
    if os.path.exists(artifact_dir):
        run_command(f"cp -a {artifact_dir} {backup_dir}/artifact_definitions", logger=log)

    velo_bin = os.path.join(velo_data, 'velociraptor')
    if os.path.exists(velo_bin):
        run_command(f"cp {velo_bin} {backup_dir}/velociraptor.backup", logger=log)

    log(f"  Backup created at {backup_dir}", "info")

    try:
        # Stop container
        log("Stopping Velociraptor container...", "info")
        result = run_command("docker compose down --remove-orphans", cwd=work_dir, logger=log)
        if not result['success']:
            raise Exception(f"Failed to stop Velociraptor: {result['error']}")

        # Query GitHub to find the correct binary URL
        log(f"Finding Velociraptor binary for version {version}...", "info")
        download_url, actual_version = get_velociraptor_download_url(version, logger=log)

        if not download_url:
            raise Exception(f"Could not find Velociraptor release for version {version}. Check https://github.com/Velocidex/velociraptor/releases for available versions.")

        # Update version in .env with the actual version from GitHub
        log(f"Updating version to {actual_version}...", "info")
        update_env_file(env_file, 'VELOCIRAPTOR_VERSION', actual_version, logger=log)
        version_parts = actual_version.split('.')
        if len(version_parts) >= 2:
            velo_tag = f"{version_parts[0]}.{version_parts[1]}"
            update_env_file(env_file, 'VELOCIRAPTOR_TAG', velo_tag, logger=log)

        # Stage all four binaries (linux server + mac/win clients)
        # into the Dockerfile's build context. The Dockerfile is pure
        # COPY now — no network access at build time.
        log(f"Staging Velociraptor {actual_version} binaries for build...", "info")
        stage = _stage_binaries_for_build(
            module_dir=work_dir,
            clean_version=actual_version,
            source="github",
            logger=log,
        )
        if not stage['success']:
            raise Exception(
                f"Failed to stage required binary for build: {stage.get('error','linux server binary not staged')}"
            )
        if stage['placeholder']:
            log(
                f"  Note: {len(stage['placeholder'])} client binary(ies) unavailable upstream — "
                f"placeholder(s) inserted: {', '.join(os.path.basename(p) for p in stage['placeholder'])}",
                "warning",
            )

        # Also keep a copy at the legacy `velo_data/velociraptor` path
        # so the rollback path's backup target still has something to
        # restore from. Cheap belt-and-braces — file already on disk.
        staged_linux = os.path.join(work_dir, 'clients', 'linux', 'velociraptor')
        if os.path.exists(staged_linux):
            run_command(f"cp {staged_linux} {velo_bin}", logger=log)
            # `chmod 755`, NOT `chmod +x`. A symbolic mode with no "who" is
            # masked by the umask, so under a umask carrying execute bits this
            # silently leaves the binary non-executable -- and every VQL call
            # made via `docker exec intact_velociraptor /velociraptor/
            # velociraptor ... query` then fails rc=126 (found, not
            # executable). That takes out memory acquisition and the
            # flow-cancel path, while the Velociraptor SERVER stays healthy
            # because it runs from the image's own copy, so nothing looks
            # wrong. Same bug was fixed in modules/velociraptor/entrypoint.sh;
            # this is the upgrade path that could reintroduce it.
            run_command(f"chmod 755 {velo_bin}", logger=log)

        # Rebuild container — offline-safe now (COPY-only Dockerfile).
        log("Rebuilding container...", "info")
        result = run_command("docker compose build --no-cache", cwd=work_dir, timeout=600, logger=log)
        if not result['success']:
            raise Exception(f"docker compose build failed: {result.get('error','')[:200]}")

        # Restore config/artifact backups (we want to keep these)
        log("Restoring config and artifacts...", "info")
        if os.path.exists(f"{backup_dir}/config"):
            os.makedirs(config_dir, exist_ok=True)
            run_command(f"cp -a {backup_dir}/config/* {config_dir}/", logger=log)

        if os.path.exists(f"{backup_dir}/artifact_definitions"):
            os.makedirs(artifact_dir, exist_ok=True)
            run_command(f"cp -a {backup_dir}/artifact_definitions/* {artifact_dir}/", logger=log)

        # Migrate the configs from the legacy named volume to the host
        # bind-mount BEFORE compose comes up — preserves the CA so enrolled
        # clients keep working. Idempotent; no-op on fresh installs.
        try:
            migrate_velociraptor_config_to_host(logger=log)
        except Exception as _e:
            log(f"  Velociraptor config migration error (continuing): {_e}", "warning")
        _ca_before = _velo_host_ca_fingerprint()

        # Start container
        log("Starting Velociraptor container...", "info")
        result = run_command("docker compose up -d --pull never", cwd=work_dir, logger=log, run_id=run_id)
        if not result['success']:
            raise Exception(f"Failed to start Velociraptor: {result['error']}")
        _verify_velo_ca_unchanged(_ca_before, logger=log)

        # Health check
        # Honest health gate (G5): GUI HTTP probe (pgrep demoted to the
        # 'degraded' tier — a running process with a dead GUI is not healthy),
        # window widened 60s -> 120s, rollback on 'down' instead of the old
        # pending-success on timeout.
        try:
            from services.workflow_service import is_cancelled
            if run_id and is_cancelled(run_id):
                raise Exception("Cancelled during health check wait")
        except ImportError:
            pass
        log("Waiting for Velociraptor to become healthy...", "info")
        from .base import enforce_module_health
        health = enforce_module_health('velociraptor', timeout=120, logger=log)

        # Success - cleanup backups
        time.sleep(15)  # Wait for full startup
        run_command(f"rm -rf {backup_dir}", logger=log)
        cleanup_backup(env_backup, logger=log)
        log(f"Velociraptor upgrade completed: {current_version} -> {actual_version}", "success")

        # Re-import every artifact the previous container had. A
        # Velociraptor binary upgrade leaves the new container's
        # artifact registry empty of non-built-in artifacts (the
        # data volume persists but the registry is rebuilt on first
        # boot). Without this re-import, the Quick Wins blueprint
        # hunt + Timesketch KapeTriage workflow fail with "artifact
        # not found" the first time the operator tries to use them.
        # Uses the same code Maintenance → Refresh Tool Inventory
        # runs, so post-upgrade state matches a freshly-maintained
        # install. Wrapped in try/except: import failure must NEVER
        # fail an already-healthy upgrade.
        _reimport_artifacts_post_upgrade(velo_data, logger=log)

        # Refresh the operator-visible downloads dir so the Dashboard's
        # Velociraptor download buttons (Windows / Linux / Linux musl /
        # Mac) reflect the new pin. Without this, /api/clients/legacy/status
        # still resolves to the OLD musl filename and greys the "Linux
        # (musl)" button after the upgrade. Best-effort — a network blip
        # here must not roll back an already-healthy upgrade.
        try:
            _refresh_offline_collector_downloads(
                clean_version=actual_version, source="github", logger=log,
            )
        except Exception as e:
            log(f"Offline-collector downloads refresh raised: {e}", "warning")

        # Repack the client installers against the NEW binary. Without this an
        # upgraded server keeps serving the old agent from the Downloads page.
        try:
            regenerate_client_installers(logger=log, run_id=run_id)
        except Exception as e:
            log(f"Client installer regeneration raised: {e}", "warning")

        remove_old_module_image('velociraptor', current_version, actual_version, logger=log)
        return {"success": True, "version": actual_version, "health": health["health"], "health_detail": health["detail"]}

    except Exception as e:
        # ROLLBACK: Restore previous version
        error_msg = str(e)
        log(f"Velociraptor upgrade FAILED: {error_msg}", "error")
        log(f"Rolling back to version {current_version}...", "warning")

        # Restore .env backup
        restore_env_file(env_file, env_backup, logger=log)

        # Restore binary backup
        if os.path.exists(f"{backup_dir}/velociraptor.backup"):
            run_command(f"cp {backup_dir}/velociraptor.backup {velo_bin}", logger=log)
            run_command(f"chmod 755 {velo_bin}", logger=log)

        # Restart on the old version. Only REBUILD if the old image is actually
        # gone: a rollback is the worst possible moment to need the network, and
        # `docker compose build` runs apt-get. In the 2026-07-23 air-gapped
        # failure this line burned a second doomed three-minute build before the
        # `up -d` below quietly succeeded on the 0.76.1 image that was there the
        # whole time.
        run_command("docker compose down --remove-orphans", cwd=work_dir, logger=log)
        if docker_image_present(f"velociraptor-server:{current_version}"):
            log(f"  velociraptor-server:{current_version} still present — "
                f"restarting on it without rebuilding.", "info")
        else:
            log(f"  velociraptor-server:{current_version} is gone — rebuilding "
                f"(needs network; will fail air-gapped).", "warning")
            run_command("docker compose build --no-cache", cwd=work_dir, timeout=600, logger=log)
        run_command("docker compose up -d --pull never", cwd=work_dir, logger=log)

        # Cleanup backup dir
        run_command(f"rm -rf {backup_dir}", logger=log)

        log(f"ROLLED BACK Velociraptor to version {current_version}", "warning")
        return {
            "success": False,
            "error": error_msg,
            "rolled_back": True,
            "restored_version": current_version
        }


def upgrade_velociraptor_offline(package_dir: str, version: str, logger: Callable = None,
                                   run_id: Optional[str] = None) -> Dict:
    """Upgrade Velociraptor from offline package with automatic rollback."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    work_dir = os.path.join(WORKDIR, 'modules', 'velociraptor')
    velo_data = os.path.join(work_dir, 'velociraptor')
    env_file = os.path.join(work_dir, '.env')
    container_name = 'intact_velociraptor'
    binaries_dir = os.path.join(package_dir, 'binaries')

    log("Starting Velociraptor offline upgrade...", "info")

    # Get current version for rollback
    current_vars = read_env_file(env_file)
    current_version = current_vars.get('VELOCIRAPTOR_VERSION', 'unknown')

    # Reject downgrades — see notes in upgrade_velociraptor() above.
    if current_version != 'unknown' and compare_versions(version, current_version) < 0:
        error_msg = (
            f"Velociraptor downgrade not supported: {current_version} -> {version}. "
            f"The server binary cannot be rolled backwards over an existing datastore."
        )
        log(error_msg, "error")
        return {"success": False, "error": error_msg}

    if current_version != 'unknown' and compare_versions(version, current_version) == 0:
        log(f"Velociraptor is already at version {version}", "info")
        return {"success": True, "version": version, "message": "Already at target version"}

    # Export artifacts
    log("Exporting custom artifacts...", "info")
    export_dir = os.path.join(velo_data, 'artifact_definitions', 'Exported')
    os.makedirs(export_dir, exist_ok=True)

    try:
        export_cmd = f"""docker exec {container_name} /velociraptor/velociraptor \
            --config /velociraptor/server.config.yaml query \
            "SELECT name, raw FROM artifact_definitions() WHERE built_in = false AND raw != ''" \
            --format jsonl 2>/dev/null"""
        # This query can return several MB of custom-artifact YAML. It used to
        # "time out" here at ANY timeout value (8s, 20s, 30s all failed
        # identically) — not because Velociraptor was slow, but because
        # run_command()'s poll loop never drained stdout/stderr while
        # waiting, so output past the ~64KB OS pipe buffer deadlocked the
        # child on write(). Fixed at the root in run_command (continuous
        # pipe-draining reader threads) rather than papered over here with a
        # bigger timeout or a retry loop — this single call now succeeds in
        # a few seconds. Still best-effort: a genuine Velociraptor outage
        # skips this optional backup rather than failing the upgrade (custom
        # artifacts live in the datastore volume and are refreshed from
        # source regardless).
        result = run_command(export_cmd, logger=_besteffort_logger(log), timeout=20)
        if result['success'] and result.get('stdout'):
            exported = 0
            for line in result['stdout'].strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        name = data.get('name', '')
                        raw = data.get('raw', '')
                        if name and raw:
                            filename = name.replace('.', '__').replace('/', '__') + '.yaml'
                            with open(os.path.join(export_dir, filename), 'w') as f:
                                f.write(raw)
                            exported += 1
                    except:
                        pass
            log(f"  Exported {exported} custom artifacts", "info")
        elif not result.get('success'):
            log("  Custom-artifact export skipped — Velociraptor's API is busy "
                "mid-upgrade (expected). This is a best-effort convenience "
                "export only: custom artifacts live in the datastore volume, "
                "which survives the upgrade, and are refreshed from source "
                "regardless. Nothing is lost and no action is needed.",
                "info")
    except Exception as e:
        log(f"  Export warning: {str(e)[:50]}", "warning")

    # Create backups
    log(f"Backing up current config (version {current_version})...", "info")
    env_backup = backup_env_file(env_file, logger=log)

    backup_dir = f"/tmp/velo-upgrade-backup-{int(time.time())}"
    os.makedirs(backup_dir, exist_ok=True)

    config_dir = os.path.join(velo_data, 'config')
    if os.path.exists(config_dir):
        run_command(f"cp -a {config_dir} {backup_dir}/config", logger=log)

    artifact_dir = os.path.join(velo_data, 'artifact_definitions')
    if os.path.exists(artifact_dir):
        run_command(f"cp -a {artifact_dir} {backup_dir}/artifact_definitions", logger=log)

    velo_bin = os.path.join(velo_data, 'velociraptor')
    if os.path.exists(velo_bin):
        run_command(f"cp {velo_bin} {backup_dir}/velociraptor.backup", logger=log)

    log(f"  Backup created at {backup_dir}", "info")

    try:
        # Stop container
        log("Stopping Velociraptor container...", "info")
        result = run_command("docker compose down --remove-orphans", cwd=work_dir, logger=log, run_id=run_id)
        if not result['success']:
            raise Exception(f"Failed to stop Velociraptor: {result['error']}")

        # Find Velociraptor binary in package (search for matching patterns)
        log("Finding Velociraptor binary in package...", "info")
        clean_ver = version.lstrip('v')
        source_binary = None
        actual_version = clean_ver

        # Try different naming patterns
        patterns = [
            f"velociraptor-v{clean_ver}-linux-amd64",
            f"velociraptor-{clean_ver}-linux-amd64",
        ]

        # Also search for any velociraptor binary matching major.minor version
        if os.path.exists(binaries_dir):
            for fname in os.listdir(binaries_dir):
                if fname.startswith('velociraptor-') and 'linux-amd64' in fname and 'musl' not in fname:
                    # Extract version from filename
                    # velociraptor-v0.75.1-linux-amd64 -> 0.75.1
                    ver_part = fname.replace('velociraptor-v', '').replace('velociraptor-', '').replace('-linux-amd64', '')
                    if ver_part.startswith(clean_ver.rsplit('.', 1)[0]):  # Match major.minor
                        patterns.insert(0, fname)  # Prioritize exact match from package

        for pattern in patterns:
            candidate = os.path.join(binaries_dir, pattern)
            if os.path.exists(candidate):
                source_binary = candidate
                # Extract actual version from filename
                fname = os.path.basename(candidate)
                actual_version = fname.replace('velociraptor-v', '').replace('velociraptor-', '').replace('-linux-amd64', '')
                log(f"  Found binary: {fname}", "info")
                break

        # A binary is only needed to BUILD velociraptor-server:<version> — if
        # that image already exists (a resumed/retried upgrade, or an
        # operator/test tool that already built it directly), staging is
        # pointless and this used to fail loudly anyway. The later
        # docker_image_present() check (~40 lines down) already knows how to
        # skip the load-and-build step correctly; it was just unreachable
        # because this raise fired first. Same class of gap as
        # ELK/IRIS/Plaso/Portainer/VolWeb's offline upgrades, adapted here
        # since Velociraptor's image is locally BUILT rather than pulled, so
        # PRIMARY_IMAGES / preflight_offline_images() don't apply directly.
        if not source_binary:
            target_image_ref = f"velociraptor-server:{clean_ver}"
            if docker_image_present(target_image_ref, run_id=run_id):
                log(f"  No binary in package, but {target_image_ref} is "
                    f"already loaded — skipping binary staging entirely.",
                    "info")
            else:
                raise Exception(f"Velociraptor binary not found in package for version {version}")

        # Update version in .env with actual version from binary
        log(f"Updating version to {actual_version}...", "info")
        update_env_file(env_file, 'VELOCIRAPTOR_VERSION', actual_version, logger=log)
        version_parts = actual_version.split('.')
        if len(version_parts) >= 2:
            velo_tag = f"{version_parts[0]}.{version_parts[1]}"
            update_env_file(env_file, 'VELOCIRAPTOR_TAG', velo_tag, logger=log)

        # Stage all four binaries (linux server + mac/win clients) into
        # the build context from the upgrade package. The Dockerfile is
        # pure COPY, so the build step below is fully offline.
        #
        # Skipped entirely when no binary was found but the target image is
        # already loaded — nothing to stage, and the image-present branch
        # ~30 lines down (docker_image_present) will correctly use it as-is
        # without a build.
        if source_binary:
            log("Staging binaries from upgrade package...", "info")
            stage = _stage_binaries_for_build(
                module_dir=work_dir,
                clean_version=actual_version,
                source="package",
                package_binaries_dir=binaries_dir,
                logger=log,
            )
            if not stage['success']:
                raise Exception(
                    f"Required linux binary missing from upgrade package: "
                    f"{stage.get('error','no linux server binary')}. "
                    f"Re-prepare the upgrade package."
                )
            if stage['placeholder']:
                log(
                    f"  Note: {len(stage['placeholder'])} client binary(ies) absent from package — "
                    f"placeholder(s) inserted: {', '.join(os.path.basename(p) for p in stage['placeholder'])}",
                    "warning",
                )

        # Keep a copy at the legacy velo_data path for backup symmetry
        # with the online flow (same reasoning as upgrade_velociraptor).
        staged_linux = os.path.join(work_dir, 'clients', 'linux', 'velociraptor')
        if os.path.exists(staged_linux):
            run_command(f"cp {staged_linux} {velo_bin}", logger=log)
            run_command(f"chmod 755 {velo_bin}", logger=log)
        _publish_client_binaries_to_tools(work_dir, actual_version, logger=log)
        log("  Binaries staged successfully", "info")

        # Prefer the pre-built image tar bundled in the package — fast,
        # zero-build path. Fall back to a local rebuild (now also
        # offline-safe because every COPY source is in the build
        # context).
        images_dir = os.path.join(package_dir, 'images')
        image_path = os.path.join(images_dir, f"velociraptor-{actual_version}.tar")

        # Any local (fallback) build must use the package's velociraptor build
        # files (Dockerfile / entrypoint.sh / bundled_artifacts), not this box's
        # possibly-stale on-disk copy — otherwise the rebuilt image lacks the
        # artifact bundle. Pre-built image load is already correct (it was baked
        # from the right source during prepare).
        pkg_velo_src = os.path.join(package_dir, 'source', 'intact', 'modules', 'velociraptor')
        image_ref = f"velociraptor-server:{actual_version}"

        # Ask the DAEMON first, not the filesystem. The orchestrator pre-loads
        # every bundled tar and then deletes it to reclaim disk, so by the time
        # we get here the tar is normally gone BECAUSE the image loaded fine.
        # Testing os.path.exists(image_path) first therefore sent every modern
        # package down the "build locally" branch — which runs apt-get and so
        # cannot work air-gapped. That is exactly how the 2026-07-23 air-gapped
        # apply failed: image velociraptor-server:0.77.1 was sitting in the
        # store, and we spent three minutes failing to rebuild it anyway.
        if docker_image_present(image_ref, run_id=run_id):
            log(f"  Image {image_ref} already loaded (tar reclaimed after "
                f"pre-load) — skipping load and build.", "info")
        elif os.path.exists(image_path):
            log("Loading pre-built Velociraptor image...", "info")
            result = load_docker_image(image_path, logger=log, run_id=run_id)
            if not result['success']:
                log(f"  Image load failed, falling back to local build: {result.get('error', '')[:80]}", "warning")
                refresh_velociraptor_build_files(pkg_velo_src, work_dir, logger=log)
                build = run_command("docker compose build --no-cache", cwd=work_dir, timeout=600, logger=log, run_id=run_id)
                if not build['success']:
                    raise Exception(f"docker compose build failed: {build.get('error','')[:200]}")
        else:
            # Legacy packages that predate image baking. Say what this actually
            # costs instead of calling it "offline-safe": the Dockerfile runs
            # apt-get, so this branch REQUIRES network and will fail air-gapped.
            log(f"  {image_ref} is neither loaded nor bundled — falling back to a "
                f"local build. This needs network access (apt-get) and will fail "
                f"in an air-gapped environment.", "warning")
            refresh_velociraptor_build_files(pkg_velo_src, work_dir, logger=log)
            build = run_command("docker compose build --no-cache", cwd=work_dir, timeout=600, logger=log, run_id=run_id)
            if not build['success']:
                raise Exception(f"docker compose build failed: {build.get('error','')[:200]}")

        # Restore config/artifact backups
        log("Restoring config and artifacts...", "info")
        if os.path.exists(f"{backup_dir}/config"):
            os.makedirs(config_dir, exist_ok=True)
            run_command(f"cp -a {backup_dir}/config/* {config_dir}/", logger=log)

        if os.path.exists(f"{backup_dir}/artifact_definitions"):
            os.makedirs(artifact_dir, exist_ok=True)
            run_command(f"cp -a {backup_dir}/artifact_definitions/* {artifact_dir}/", logger=log)

        # Migrate the configs from the legacy named volume to the host
        # bind-mount BEFORE compose comes up — preserves the CA so enrolled
        # clients keep working. Idempotent; no-op on fresh installs.
        try:
            migrate_velociraptor_config_to_host(logger=log)
        except Exception as _e:
            log(f"  Velociraptor config migration error (continuing): {_e}", "warning")
        _ca_before = _velo_host_ca_fingerprint()

        # Start container
        log("Starting Velociraptor container...", "info")
        result = run_command("docker compose up -d --pull never", cwd=work_dir, logger=log, run_id=run_id)
        if not result['success']:
            raise Exception(f"Failed to start Velociraptor: {result['error']}")
        _verify_velo_ca_unchanged(_ca_before, logger=log)

        # Health check
        # Honest health gate (G5): GUI HTTP probe (pgrep demoted to the
        # 'degraded' tier — a running process with a dead GUI is not healthy),
        # window widened 60s -> 120s, rollback on 'down' instead of the old
        # pending-success on timeout.
        try:
            from services.workflow_service import is_cancelled
            if run_id and is_cancelled(run_id):
                raise Exception("Cancelled during health check wait")
        except ImportError:
            pass
        log("Waiting for Velociraptor to become healthy...", "info")
        from .base import enforce_module_health
        health = enforce_module_health('velociraptor', timeout=120, logger=log)

        # Success - cleanup backups
        time.sleep(15)
        run_command(f"rm -rf {backup_dir}", logger=log)
        cleanup_backup(env_backup, logger=log)
        log(f"Velociraptor offline upgrade completed: {current_version} -> {actual_version}", "success")

        # Restore bundled artifact-source files into /app/data/ so the
        # post-upgrade re-import works even on a fresh air-gapped
        # target that never ran Maintenance with internet. See
        # _restore_bundled_artifact_sources for the package layout.
        _restore_bundled_artifact_sources(package_dir, logger=log)

        # Air-gap-complete: re-register every artifact from the
        # prepare-machine's running Velociraptor (snapshot bundled by
        # prepare). Covers Server.Import.ArtifactExchange /
        # DetectRaptor / Extras output that would otherwise need
        # GitHub at apply time on a fresh target.
        try:
            _import_bundled_registry_snapshot(package_dir, logger=log)
        except Exception as e:
            log(f"  Registry-snapshot import raised: {e}", "warning")

        # Direct-download fallback: extract + import the public source
        # zips prepare curl'd. These cover the same three sources as the
        # SQL snapshot above (ArtifactExchange / DetectRaptor / Extras)
        # but run unconditionally — so an upgrade package that was
        # prepared without a running Velociraptor still imports the
        # standard artifact set on the target. Imports are idempotent
        # (import_custom_artifact overwrites by name), so the overlap
        # with the registry snapshot is harmless.
        # Superseded: the curated artifact bundle (ArtifactExchange /
        # DetectRaptor / Sigma / Rapid7 / TenRoot) is now baked into the
        # velociraptor image and loaded on boot via --definitions (see
        # modules/velociraptor/{Dockerfile,entrypoint.sh}). The new image is
        # already running by this point, so the artifacts are present. This
        # replaces the per-artifact gRPC artifact_set() loop that took
        # ~37 min on a fresh air-gap install with a large artifact set.
        log("  Curated artifacts load from the image on boot (--definitions) "
            "— skipping the per-artifact API import.", "info")

        # Same artifact re-import as the online path. See its docstring
        # for the "why" — a Velociraptor binary upgrade leaves the
        # new container's registry empty of non-built-in artifacts,
        # breaking the Quick Wins blueprint hunt + KapeTriage flow
        # for Timesketch. skip_exchange_imports=True because we're in
        # the OFFLINE upgrade path — the curated bundle is baked into the
        # velociraptor image (loaded via --definitions), and
        # the Server.Import.* artifacts would silently 404 on an
        # air-gap target while logging confusing "Some artifacts
        # failed" warnings. The online upgrade path keeps the default
        # (False) so it still benefits from live upstream additions.
        _reimport_artifacts_post_upgrade(velo_data, logger=log,
                                          skip_exchange_imports=True)

        # Verify + backfill all default-blueprint artifacts (see install path).
        try:
            _verify_and_backfill_blueprint_artifacts(package_dir, logger=log)
        except Exception as _ve:
            log(f"  Artifact verify/backfill raised: {_ve}", "warning")

        # Refresh the operator-visible downloads dir from the package's
        # bundled binaries — same gap as the online path, just sourcing
        # the files locally instead of from GitHub. Best-effort: a missing
        # platform binary (older packages prepared before musl was bundled)
        # greys that one button but doesn't fail the upgrade.
        try:
            _refresh_offline_collector_downloads(
                clean_version=actual_version, source="package",
                package_binaries_dir=binaries_dir, logger=log,
            )
        except Exception as e:
            log(f"Offline-collector downloads refresh raised: {e}", "warning")

        # Stage velociraptor-collector for Hunt-collector generation.
        # See _ensure_velociraptor_collector_tool docstring + 2026-06-16
        # incident comment above. Try package first (offline-safe), fall
        # back to upstream if the package was prepared before the
        # bundling step landed (newer packages bundle it).
        try:
            r = _ensure_velociraptor_collector_tool(
                clean_version=actual_version, source="package",
                package_binaries_dir=binaries_dir, logger=log,
            )
            if not r.get("success"):
                _ensure_velociraptor_collector_tool(
                    clean_version=actual_version, source="github", logger=log,
                )
        except Exception as e:
            log(f"velociraptor-collector staging raised: {e}", "warning")

        # Place + register the bundled DEFAULT Velociraptor tools
        # (lolrmm, Autoruns, LastActivityView — the only tools the
        # shipped default blueprints use) serve_locally so air-gap
        # collector generation for tool-backed artifacts (cve_management,
        # etc.) doesn't reach the internet. See _restore_and_configure_tools.
        try:
            _restore_and_configure_tools(package_dir, logger=log)
        except Exception as e:
            log(f"velociraptor tool restore raised: {e}", "warning")

        # Repack the client installers against the NEW binary. Without this an
        # upgraded server keeps serving the old agent from the Downloads page.
        try:
            regenerate_client_installers(logger=log, run_id=run_id)
        except Exception as e:
            log(f"Client installer regeneration raised: {e}", "warning")

        remove_old_module_image('velociraptor', current_version, actual_version, logger=log)
        return {"success": True, "version": actual_version, "health": health["health"], "health_detail": health["detail"]}

    except Exception as e:
        # ROLLBACK: Restore previous version
        error_msg = str(e)
        log(f"Velociraptor offline upgrade FAILED: {error_msg}", "error")
        log(f"Rolling back to version {current_version}...", "warning")

        # Restore .env backup
        restore_env_file(env_file, env_backup, logger=log)

        # Restore binary backup
        if os.path.exists(f"{backup_dir}/velociraptor.backup"):
            run_command(f"cp {backup_dir}/velociraptor.backup {velo_bin}", logger=log)
            run_command(f"chmod 755 {velo_bin}", logger=log)

        # Restart on the old version. Only REBUILD if the old image is actually
        # gone: a rollback is the worst possible moment to need the network, and
        # `docker compose build` runs apt-get. In the 2026-07-23 air-gapped
        # failure this line burned a second doomed three-minute build before the
        # `up -d` below quietly succeeded on the 0.76.1 image that was there the
        # whole time.
        run_command("docker compose down --remove-orphans", cwd=work_dir, logger=log)
        if docker_image_present(f"velociraptor-server:{current_version}"):
            log(f"  velociraptor-server:{current_version} still present — "
                f"restarting on it without rebuilding.", "info")
        else:
            log(f"  velociraptor-server:{current_version} is gone — rebuilding "
                f"(needs network; will fail air-gapped).", "warning")
            run_command("docker compose build --no-cache", cwd=work_dir, timeout=600, logger=log)
        run_command("docker compose up -d --pull never", cwd=work_dir, logger=log)

        run_command(f"rm -rf {backup_dir}", logger=log)

        log(f"ROLLED BACK Velociraptor to version {current_version}", "warning")
        return {
            "success": False,
            "error": error_msg,
            "rolled_back": True,
            "restored_version": current_version
        }


def install_velociraptor_offline(package_dir: str, version: str, logger=None, run_id=None) -> Dict:
    """Fresh-install Velociraptor — picked when intact_velociraptor absent.

    Velociraptor's entrypoint generates its own server config + datastore
    on first boot, so no Python-side cert / config rendering is needed.
    The tracked `.env` carries the VELOX_USER / VELOX_PASSWORD defaults
    from config.yaml that lib/modules.sh:deploy_velociraptor would use.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    from .base import install_module_compose_up
    work_dir = os.path.join(WORKDIR, 'modules', 'velociraptor')
    env_file = os.path.join(work_dir, '.env')
    log(f"Installing Velociraptor (first-time) -> {version or 'tracked default'}...", "info")
    if os.path.exists(env_file) and version:
        update_env_file(env_file, 'VELOCIRAPTOR_VERSION', version, logger=log)
    # CRITICAL: the prefix MUST match what the prepare side actually
    # writes. package.py:prepare_upgrade_package saves the baked
    # velociraptor-server image as `velociraptor-{version}.tar`
    # (filename), NOT `velociraptor-server-{version}.tar`. The previous
    # value here (`'velociraptor-server'`) never matched any file in
    # the package, so the image was never loaded — compose would then
    # see the `build:` directive in modules/velociraptor/
    # docker-compose.yaml, try to build the Dockerfile, attempt to
    # pull `ubuntu:22.04` as the base image, and fail air-gapped with
    # "failed to fetch anonymous token". Air-gap apply tests caught
    # this on 2026-06-09. Aligning the prefix with the prepare-side
    # filename pattern lets the pre-built image load correctly and
    # compose skips the build step entirely.
    compose_result = install_module_compose_up(
        'velociraptor', package_dir, version,
        image_tar_prefixes=['velociraptor-'],
        logger=log, run_id=run_id,
    )
    if not compose_result.get('success'):
        return compose_result

    # Post-install bootstrap. Velociraptor's entrypoint generates its
    # own server.config.yaml / client.config.yaml / api.config.yaml
    # on first boot (~30-60s). The backend's
    # velociraptor_service.load_velociraptor_api_config() later reads
    # api.config.yaml from this container via docker exec — without
    # this wait, the install reports success and the operator's first
    # request to backend → Velociraptor immediately fails because the
    # config files don't exist yet. Polling for client.config.yaml
    # (the same readiness signal lib/modules.sh:deploy_velociraptor
    # uses at line ~683) confirms the entrypoint has finished its
    # config-gen.
    log("Velociraptor container up. Waiting for entrypoint config-gen...", "info")
    import time as _time
    import subprocess as _sub
    config_ready = False
    waited = 0
    # 5 min wall-clock budget. 120 s was too tight on slow disks (same
    # rationale as the Timesketch schema-wait bump on 2026-06-11).
    # Velociraptor's entrypoint does config-gen + key gen + datastore
    # init in series; on a CPU-constrained or disk-slow machine that
    # chain can take >120 s. Most installs land at 5-30 s.
    _CONFIG_WAIT_SECS = 300
    while waited < _CONFIG_WAIT_SECS:
        try:
            probe = _sub.run(
                ["docker", "exec", "intact_velociraptor",
                 "test", "-f", "/velociraptor/client.config.yaml"],
                capture_output=True, text=True, timeout=10,
            )
            if probe.returncode == 0:
                config_ready = True
                log(f"  Velociraptor configuration ready ({waited}s)", "success")
                break
        except _sub.TimeoutExpired:
            pass
        except Exception:
            pass
        # Heartbeat every 30 s.
        if waited and waited % 30 == 0:
            log(f"  …still waiting for config-gen ({waited}s elapsed of "
                f"{_CONFIG_WAIT_SECS}s budget)", "info")
        _time.sleep(5)
        waited += 5

    if not config_ready:
        log(
            f"Velociraptor configuration did not generate within "
            f"{_CONFIG_WAIT_SECS}s. Container IS running but "
            f"api.config.yaml may not be present yet; backend → "
            f"Velociraptor gRPC calls will fail until the entrypoint "
            f"finishes. Wait a minute then retry, or check `docker logs "
            f"intact_velociraptor` for errors. Continuing.",
            "warning",
        )

    # Bundled-artifact restoration — same three paths the upgrade flow
    # runs. Without these a fresh-install Velociraptor comes up with an
    # EMPTY non-built-in artifact registry: no DetectRaptor, no
    # ArtifactExchange, no Extras, no operator custom_artifacts. On an
    # air-gapped target there's no way to fetch them later either, so
    # the install is functionally useless. Each layer is best-effort
    # (existing wrapper pattern) — failures log warnings but don't
    # abort an otherwise-successful install.
    log("Restoring bundled artifacts from package...", "info")
    try:
        _restore_bundled_artifact_sources(package_dir, logger=log)
    except Exception as e:
        log(f"  Bundled artifact source restore raised: {e}", "warning")
    try:
        _import_bundled_registry_snapshot(package_dir, logger=log)
    except Exception as e:
        log(f"  Registry-snapshot import raised: {e}", "warning")
    # Superseded: the curated artifact bundle is baked into the velociraptor
    # image and loaded on boot via --definitions (see modules/velociraptor/
    # {Dockerfile,entrypoint.sh}). On a fresh air-gap install this is what
    # makes Hayabusa / DetectRaptor / KAPE / Sigma artifacts present — and it
    # replaces the per-artifact API import that took ~37 min.
    log("  Curated artifacts load from the image on boot (--definitions) "
        "— skipping the per-artifact API import.", "info")

    # Run the TenRoot artifact importer. Critical for fresh installs:
    # the previous steps register YAMLs that are already standalone
    # artifacts, but the TenRoot custom pack (Windows.Triage.Targets,
    # KAPE blueprints, and ~40 others) is delivered as a ZIP that has
    # to be UNPACKED by a server artifact called
    # Custom.Server.Import.TenRoot.Artifacts running inside Velociraptor.
    # _restore_bundled_artifact_sources above placed the zip at
    # /app/data/tools/Velociraptor-Artifacts-main.zip; we now invoke
    # the same orchestrator the "Maintenance → Refresh Tool Inventory"
    # UI button runs to extract and import every YAML.
    #
    # Without this, KAPE-based TimeSketch automations fail with
    # "Parameter refers to an unknown artifact (Windows.Triage.Targets)"
    # — the symptom the 2026-06-11 fresh-install operator hit. The
    # upgrade path already calls this via _reimport_artifacts_post_upgrade,
    # but install_velociraptor_offline was missing the parallel step.
    log("Importing TenRoot custom artifact pack (KAPE blueprints, etc.)...", "info")
    try:
        from services.velociraptor_init_service import initialize_velociraptor_artifacts
        # skip_exchange_imports=True — the three Server.Import.* artifacts
        # (ArtifactExchange / DetectRaptor / Extras) need internet to
        # download from github at runtime. On air-gapped targets those
        # silently fail and the operator sees "Some artifacts failed".
        # the curated bundle is baked into the velociraptor image and
        # loaded via --definitions, so running
        # the Server.Import.* artifacts is pure noise — skip them and
        # only run the TenRoot zip extraction + local custom artifact
        # imports (both fully air-gap safe).
        initialize_velociraptor_artifacts(logger_func=log, skip_exchange_imports=True)
    except Exception as e:
        log(
            f"  TenRoot import orchestrator raised "
            f"({type(e).__name__}: {e}); operator should click "
            f"Settings → System Maintenance → Refresh Tool Inventory "
            f"to retry. KAPE collections will fail with 'unknown "
            f"artifact (Windows.Triage.Targets)' until this runs "
            f"successfully.",
            "warning",
        )

    # Verify + backfill every default-blueprint artifact (2026-06-16
    # operator ask: "all the artifacts should be there"). Verify finds
    # gaps; backfill re-imports any the bulk pass dropped to transient
    # timeouts. Re-verify logs the final state.
    try:
        _verify_and_backfill_blueprint_artifacts(package_dir, logger=log)
    except Exception as _ve:
        log(f"  Artifact verify/backfill raised: {_ve}", "warning")

    # Generate pre-configured client installers (MSI / EXE / Linux / Mac /
    # musl). lib/modules.sh does this for the install.sh path; the
    # offline-apply path was missing the parallel step, so operators who
    # installed via the UI got a working Velociraptor server but a Downloads
    # page that 404'd on windows-msi. Shares one implementation with the two
    # upgrade paths — this was a third copy of the same block.
    regenerate_client_installers(logger=log, run_id=run_id)

    # Stage velociraptor-collector for Hunt-collector generation. Same
    # call as upgrade_velociraptor_offline — fresh installs from a
    # prepared package were hitting the 2026-06-16 incident where Hunt
    # collector generation died with "lookup github.com on 127.0.0.11:53"
    # because the file wasn't in /data/tools/. Bundled-first, falls
    # back to upstream when the package was prepared before bundling
    # landed.
    binaries_dir_install = os.path.join(package_dir, 'binaries')
    try:
        r = _ensure_velociraptor_collector_tool(
            clean_version=version.lstrip('v'), source="package",
            package_binaries_dir=binaries_dir_install, logger=log,
        )
        if not r.get("success"):
            _ensure_velociraptor_collector_tool(
                clean_version=version.lstrip('v'), source="github", logger=log,
            )
    except Exception as e:
        log(f"velociraptor-collector staging raised: {e}", "warning")

    # Place + register bundled Velociraptor tools serve_locally (same
    # as the upgrade path) so air-gap collector generation for
    # tool-backed artifacts (cve_management's lolrmm, etc.) works.
    try:
        _restore_and_configure_tools(package_dir, logger=log)
    except Exception as e:
        log(f"velociraptor tool restore raised: {e}", "warning")

    return compose_result
