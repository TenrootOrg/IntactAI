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
    load_docker_image, compare_versions,
    remove_old_module_image,
)


def _reimport_artifacts_post_upgrade(velo_data: str, logger: Callable = None) -> None:
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
    try:
        initialize_velociraptor_artifacts(logger_func=log)
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
    count = 0
    for fn in sorted(os.listdir(exported)):
        if not (fn.endswith('.yaml') or fn.endswith('.yml')):
            continue
        try:
            with open(os.path.join(exported, fn), 'r') as f:
                yaml_content = f.read()
            ok = import_custom_artifact(yaml_content, logger_func=log)
            if ok:
                count += 1
        except Exception as e:
            log(f"  Re-import {fn} failed ({e}); continuing.", "warning")
    if count:
        log(f"  Re-imported {count} pre-upgrade-snapshot artifacts", "success")


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

    log(f"  Importing {len(yamls)} artifacts from bundled registry snapshot...", "info")
    ok = 0
    for fn in yamls:
        try:
            with open(os.path.join(snap_dir, fn), 'r') as f:
                yaml_content = f.read()
            if import_custom_artifact(yaml_content, logger_func=None):
                ok += 1
        except Exception:
            # Per-artifact failures are common with version-skew
            # (newer artifact YAML using fields the new binary
            # doesn't understand). Swallow + continue.
            continue
    log(f"  Registry snapshot: {ok}/{len(yamls)} artifacts imported", "success" if ok else "warning")
    return ok


def _import_bundled_external_artifacts(package_dir: str,
                                        logger: Callable = None) -> int:
    """Import the artifact zips that prepare downloaded directly from
    public GitHub URLs (ArtifactExchange, DetectRaptor, Rapid7 Labs).

    Path written by prepare_upgrade_package's velociraptor branch:
        <package>/artifacts/velociraptor/external/*.zip

    Each zip contains many .yaml artifact definitions at various depths
    (the upstream zip layouts aren't uniform — Velocidex's
    artifact_exchange_v2.zip nests under exchange/, DetectRaptor's
    flattens under DetectRaptor/, Rapid7's puts them under Vql/). Walk
    each extracted tree and import every .yaml. Per-artifact failures
    are swallowed for the same reason as registry_snapshot — version
    skew between the prepare-host's Velociraptor and the target's.

    Returns the count of successfully-imported artifacts across all zips.
    """
    import tempfile
    import zipfile

    log = logger or (lambda msg, level="info": None)
    ext_dir = os.path.join(package_dir, 'artifacts', 'velociraptor', 'external')
    if not os.path.isdir(ext_dir):
        return 0

    zips = sorted(
        os.path.join(ext_dir, f) for f in os.listdir(ext_dir)
        if f.endswith('.zip')
    )
    if not zips:
        return 0

    try:
        from services.velociraptor_init_service import import_custom_artifact
    except Exception as e:
        log(f"  Could not import import_custom_artifact: {e}", "warning")
        return 0

    log(f"  Importing artifacts from {len(zips)} external zip(s)...", "info")
    total_ok = 0
    for zpath in zips:
        zname = os.path.basename(zpath)
        try:
            with tempfile.TemporaryDirectory(prefix='extbundle_') as tmp:
                with zipfile.ZipFile(zpath) as zf:
                    zf.extractall(tmp)
                ok = 0
                count = 0
                for root, _, files in os.walk(tmp):
                    for fn in files:
                        if not fn.endswith(('.yaml', '.yml')):
                            continue
                        count += 1
                        try:
                            with open(os.path.join(root, fn), 'r') as f:
                                yaml_content = f.read()
                            if import_custom_artifact(yaml_content, logger_func=None):
                                ok += 1
                        except Exception:
                            continue
                log(f"    {zname}: {ok}/{count} imported", "info" if ok else "warning")
                total_ok += ok
        except zipfile.BadZipFile:
            log(f"    {zname}: not a valid zip — skipping", "warning")
        except Exception as e:
            log(f"    {zname}: {e}", "warning")
    log(f"  External artifact zips: {total_ok} total artifacts imported",
        "success" if total_ok else "warning")
    return total_ok


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
    parts = clean_version.split('.')
    release_tag = f"v{parts[0]}.{parts[1]}" if len(parts) >= 2 else f"v{clean_version}"
    base_url = f"https://github.com/Velocidex/velociraptor/releases/download/{release_tag}"

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
                f"curl -fL --retry 5 --retry-delay 5 --retry-max-time 120 -o {dest} {url}",
                logger=log, timeout=300,
            )
            ok = res['success'] and os.path.exists(dest) and os.path.getsize(dest) > 0
            if not ok and os.path.exists(dest):
                # curl -f exits non-zero on HTTP 4xx but may have written partial bytes
                os.remove(dest)

        if ok:
            if not dest.endswith('.msi'):
                run_command(f"chmod +x {dest}", logger=log)
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


def get_velociraptor_download_url(version: str, logger: Callable = None) -> Tuple[Optional[str], Optional[str]]:
    """Build Velociraptor binary download URL from version string.

    No GitHub API calls - constructs URL directly from version.

    Velociraptor URL pattern:
    https://github.com/Velocidex/velociraptor/releases/download/v{major}.{minor}/velociraptor-v{version}-linux-amd64

    Args:
        version: Version string like "0.75.6" or "v0.75.6" (full version required)

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

    # Build release tag (major.minor)
    release_tag = f"v{parts[0]}.{parts[1]}"

    # Build download URL
    binary_name = f"velociraptor-v{clean_version}-linux-amd64"
    download_url = f"https://github.com/Velocidex/velociraptor/releases/download/{release_tag}/{binary_name}"

    log(f"  Version: {clean_version}", "info")
    log(f"  Release tag: {release_tag}", "info")
    log(f"  Binary: {binary_name}", "info")

    return download_url, clean_version


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
        result = run_command(export_cmd, logger=log, timeout=60)
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
            run_command(f"chmod +x {velo_bin}", logger=log)

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

        # Start container
        log("Starting Velociraptor container...", "info")
        result = run_command("docker compose up -d --pull never", cwd=work_dir, logger=log, run_id=run_id)
        if not result['success']:
            raise Exception(f"Failed to start Velociraptor: {result['error']}")

        # Health check
        log("Waiting for Velociraptor container to be up...", "info")
        healthy = False
        for i in range(30):  # 30 * 2s = 60s max
            try:
                from services.workflow_service import is_cancelled
                if run_id and is_cancelled(run_id):
                    raise Exception("Cancelled during health check wait")
            except ImportError:
                pass
            log(f"  Checking Velociraptor container... ({i*2}s)", "info")
            result = run_command(f"docker exec {container_name} pgrep -f velociraptor", logger=None, timeout=10)
            if result['success']:
                pids = result.get('stdout', '').strip().replace('\n', ', ')
                log(f"  Container healthy - velociraptor running (PIDs: {pids})", "success")
                log("Velociraptor health check: PASSED", "success")
                healthy = True
                break
            else:
                log("  Container not ready yet...", "info")
            time.sleep(2)

        if not healthy:
            check_result = run_command("docker ps -a --filter name=intact_velociraptor --format '{{.Status}}'", logger=None)
            container_status = check_result.get('stdout', '').strip()
            if 'Restarting' in container_status or 'Exited' in container_status:
                raise Exception(f"Velociraptor failed to start - container status: {container_status}")
            log("Velociraptor health check: TIMEOUT (container may still be starting)", "warning")

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

        remove_old_module_image('velociraptor', current_version, actual_version, logger=log)
        return {"success": True, "version": actual_version, "health": "green" if healthy else "pending"}

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
            run_command(f"chmod +x {velo_bin}", logger=log)

        # Rebuild and restart with old version
        run_command("docker compose down --remove-orphans", cwd=work_dir, logger=log)
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
        result = run_command(export_cmd, logger=log, timeout=60)
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

        if not source_binary:
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
            run_command(f"chmod +x {velo_bin}", logger=log)
        log("  Binaries staged successfully", "info")

        # Prefer the pre-built image tar bundled in the package — fast,
        # zero-build path. Fall back to a local rebuild (now also
        # offline-safe because every COPY source is in the build
        # context).
        images_dir = os.path.join(package_dir, 'images')
        image_path = os.path.join(images_dir, f"velociraptor-{actual_version}.tar")

        if os.path.exists(image_path):
            log("Loading pre-built Velociraptor image...", "info")
            result = load_docker_image(image_path, logger=log, run_id=run_id)
            if not result['success']:
                log(f"  Image load failed, falling back to local build: {result.get('error', '')[:80]}", "warning")
                build = run_command("docker compose build --no-cache", cwd=work_dir, timeout=600, logger=log, run_id=run_id)
                if not build['success']:
                    raise Exception(f"docker compose build failed: {build.get('error','')[:200]}")
        else:
            log("No pre-built image in package — building locally (offline-safe).", "info")
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

        # Start container
        log("Starting Velociraptor container...", "info")
        result = run_command("docker compose up -d --pull never", cwd=work_dir, logger=log, run_id=run_id)
        if not result['success']:
            raise Exception(f"Failed to start Velociraptor: {result['error']}")

        # Health check
        log("Waiting for Velociraptor container to be up...", "info")
        healthy = False
        for i in range(30):  # 30 * 2s = 60s max
            try:
                from services.workflow_service import is_cancelled
                if run_id and is_cancelled(run_id):
                    raise Exception("Cancelled during health check wait")
            except ImportError:
                pass
            log(f"  Checking Velociraptor container... ({i*2}s)", "info")
            result = run_command(f"docker exec {container_name} pgrep -f velociraptor", logger=None, timeout=10)
            if result['success']:
                pids = result.get('stdout', '').strip().replace('\n', ', ')
                log(f"  Container healthy - velociraptor running (PIDs: {pids})", "success")
                log("Velociraptor health check: PASSED", "success")
                healthy = True
                break
            else:
                log("  Container not ready yet...", "info")
            time.sleep(2)

        if not healthy:
            check_result = run_command("docker ps -a --filter name=intact_velociraptor --format '{{.Status}}'", logger=None)
            container_status = check_result.get('stdout', '').strip()
            if 'Restarting' in container_status or 'Exited' in container_status:
                raise Exception(f"Velociraptor failed to start - container status: {container_status}")
            log("Velociraptor health check: TIMEOUT (container may still be starting)", "warning")

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
        try:
            _import_bundled_external_artifacts(package_dir, logger=log)
        except Exception as e:
            log(f"  External artifact import raised: {e}", "warning")

        # Same artifact re-import as the online path. See its docstring
        # for the "why" — a Velociraptor binary upgrade leaves the
        # new container's registry empty of non-built-in artifacts,
        # breaking the Quick Wins blueprint hunt + KapeTriage flow
        # for Timesketch. This is a belt-and-suspenders second pass
        # that also triggers Server.Import.* (needs internet — falls
        # back gracefully on air-gap).
        _reimport_artifacts_post_upgrade(velo_data, logger=log)

        remove_old_module_image('velociraptor', current_version, actual_version, logger=log)
        return {"success": True, "version": actual_version, "health": "green" if healthy else "pending"}

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
            run_command(f"chmod +x {velo_bin}", logger=log)

        # Rebuild and restart with old version
        run_command("docker compose down --remove-orphans", cwd=work_dir, logger=log)
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
    try:
        _import_bundled_external_artifacts(package_dir, logger=log)
    except Exception as e:
        log(f"  External artifact import raised: {e}", "warning")

    return compose_result
