#!/usr/bin/env python3
"""Upgrade package preparation service.

Creates offline upgrade packages that can be transferred to air-gapped systems.
"""

import os
import json
import shutil
from datetime import datetime
from typing import Dict, Callable, List, Optional

from .base import run_command, WORKDIR, HOST_PATH


# Docker image mappings for each module
DOCKER_IMAGES = {
    'elk': [
        ('docker.elastic.co/elasticsearch/elasticsearch:{version}', 'elasticsearch-{version}.tar'),
        ('docker.elastic.co/kibana/kibana:{version}', 'kibana-{version}.tar'),
        ('docker.elastic.co/logstash/logstash:{version}', 'logstash-{version}.tar'),
    ],
    'timesketch': [
        ('us-docker.pkg.dev/osdfir-registry/timesketch/timesketch:{version}', 'timesketch-{version}.tar'),
    ],
    'plaso': [
        ('log2timeline/plaso:{version}', 'plaso-{version}.tar'),
    ],
    'iris': [
        # Note: iris-worker uses the same iriswebapp_app image
        # Note: DB image included for air-gap support (data is in volumes, safe to upgrade)
        ('ghcr.io/dfir-iris/iriswebapp_app:{version}', 'iris-app-{version}.tar'),
        ('ghcr.io/dfir-iris/iriswebapp_nginx:{version}', 'iris-nginx-{version}.tar'),
        ('ghcr.io/dfir-iris/iriswebapp_db:{version}', 'iris-db-{version}.tar'),
    ],
    'aws': [
        # Prowler image for AWS posture scans (run on demand, no live container)
        ('toniblyx/prowler:{version}', 'prowler-{version}.tar'),
    ],
    'azure': [
        # DFIR-O365RC image for Azure Unified Audit Log (run on demand). Upstream
        # only ships ':latest', so {version} is normally 'latest'.
        ('anssi/dfir-o365rc:{version}', 'dfir-o365rc-{version}.tar'),
    ],
    'volweb': [
        # VolWeb backend image (memory-forensics analysis stack).
        # The frontend / postgres / redis images are independent — they
        # follow their own pins (volweb_frontend, volweb_postgres,
        # volweb_redis in config.yaml) and bundle separately when those
        # pins change. The backend image is the only one whose version
        # changes routinely across releases.
        ('forensicxlab/volweb-backend:{version}', 'volweb-backend-{version}.tar'),
    ],
}


def _format_size(size_bytes: int) -> str:
    """Format bytes to human-readable size."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def _get_dir_size(path: str) -> int:
    """Get total size of a directory in bytes."""
    total = 0
    for dirpath, dirnames, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if os.path.exists(fp):
                total += os.path.getsize(fp)
    return total


def _compress_with_progress(source_dir: str, source_name: str, output_file: str,
                            logger: Callable, progress_interval: int = 10,
                            run_id: Optional[str] = None) -> Dict:
    """Compress directory to tar.gz with progress updates.

    Args:
        source_dir: Parent directory containing source_name (e.g., /tmp)
        source_name: Name of directory to compress (e.g., intact-upgrade-20260323)
        output_file: Output tar.gz path
        logger: Logging function
        progress_interval: Seconds between progress updates
        run_id: When set, the tar subprocess is terminated immediately if
                the workflow's Stop button is clicked (otherwise tar on
                a ~1 GB package can ignore Stop for 30+ seconds).

    Returns:
        Dict with success status and error if failed
    """
    import subprocess
    import time

    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))

    # Calculate source size for progress estimation
    source_path = os.path.join(source_dir, source_name)
    source_size = _get_dir_size(source_path)
    log(f"  Source size: {_format_size(source_size)}", "info")

    # Start tar in background
    cmd = f"tar -czf {output_file} -C {source_dir} {source_name}"
    process = subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    # Wire Stop button → SIGTERM the tar subprocess. Without this, an
    # operator clicking Stop watches the workflow row flip to
    # "cancelled" but tar keeps writing the archive for tens of
    # seconds to several minutes depending on package size.
    cancel_event = None
    if run_id:
        try:
            from services.workflow_service import (
                get_cancel_event, register_cleanup, terminate_subprocess,
            )
            cancel_event = get_cancel_event(run_id)
            if cancel_event is not None:
                register_cleanup(run_id, lambda p=process: terminate_subprocess(p))
        except Exception:
            cancel_event = None

    last_update = time.time()
    last_size = 0

    # Poll for progress
    while process.poll() is None:
        if cancel_event is not None and cancel_event.is_set():
            log("  Compression cancelled by user", "warning")
            try:
                from services.workflow_service import terminate_subprocess as _ts
                _ts(process)
            except Exception:
                process.terminate()
            try:
                os.remove(output_file)
            except OSError:
                pass
            return {"success": False, "error": "cancelled", "cancelled": True}

        time.sleep(1)

        now = time.time()
        if now - last_update >= progress_interval:
            if os.path.exists(output_file):
                current_size = os.path.getsize(output_file)
                # Estimate progress (compressed is ~30-50% of source for images)
                # Use a rough estimate: output will be ~40% of source
                estimated_final = source_size * 0.4
                if estimated_final > 0:
                    progress = min(99, int((current_size / estimated_final) * 100))
                else:
                    progress = 0

                speed = (current_size - last_size) / progress_interval
                log(f"  Compressing... {_format_size(current_size)} written ({_format_size(speed)}/s)", "info")
                last_size = current_size
            last_update = now

    # Check result
    returncode = process.returncode
    stderr = process.stderr.read().decode() if process.stderr else ""

    if returncode != 0:
        return {"success": False, "error": stderr[:200]}

    return {"success": True}


def _pull_and_save_image(image: str, output_path: str, logger: Callable,
                          run_id: Optional[str] = None) -> bool:
    """Pull a Docker image and save it to a tar file.

    `run_id` makes both subprocesses (docker pull, docker save)
    interruptible — a Stop click during a 20-minute pull terminates
    the docker CLI within a second instead of letting it run to
    completion and only then noticing the cancel flag.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))

    # Pull the image with output shown
    log(f"  Pulling {image}...", "info")
    result = run_command(f"docker pull {image}", timeout=1200, logger=log, run_id=run_id)
    if result.get("cancelled"):
        return False
    if not result['success']:
        log(f"  Failed to pull {image}: {result.get('error', '')[:200]}", "error")
        return False

    # Save the image (increased timeout for large images)
    log(f"  Saving to {os.path.basename(output_path)}...", "info")
    result = run_command(f"docker save -o {output_path} {image}", timeout=1200, logger=None, run_id=run_id)
    if result.get("cancelled"):
        return False
    if not result['success']:
        log(f"  Failed to save {image}: {result.get('error', '')[:200]}", "error")
        return False

    # Check file size - warn if suspiciously small (less than 1MB)
    size = os.path.getsize(output_path)
    if size < 1024 * 1024:  # Less than 1MB
        log(f"  WARNING: Image file is only {_format_size(size)} - may be corrupted!", "warning")
        log(f"  This can happen with docker-in-docker setups. Try running on host.", "warning")
        return False

    log(f"  Done ({_format_size(size)})", "success")
    return True


def prepare_upgrade_package(modules: Dict, run_id: str, logger: Callable = None) -> Dict:
    """Download and package upgrade components.

    Args:
        modules: Dict of module versions, e.g. {"elk": "9.3.1", "velociraptor": "0.75.6"}
        run_id: Workflow run ID for tracking
        logger: Logging function

    Returns:
        Dict with success status, package_path, and metadata
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    package_name = f"intact-upgrade-{timestamp}"
    package_dir = f"/tmp/{package_name}"  # Temp work directory

    # Store final package in persistent location (always use same filename - overwrite previous)
    packages_dir = "/data/upgrade_packages"
    os.makedirs(packages_dir, exist_ok=True)

    # Remove any existing packages (keep only latest)
    for old_file in os.listdir(packages_dir):
        old_path = os.path.join(packages_dir, old_file)
        if os.path.isfile(old_path):
            os.remove(old_path)

    output_file = f"{packages_dir}/intact-upgrade-latest.tar.gz"

    log("=" * 50, "info")
    log("PREPARING UPGRADE PACKAGE", "info")
    log("=" * 50, "info")
    log("", "info")
    log("Selected modules:", "info")
    for module, version in modules.items():
        log(f"  {module.upper()}: {version}", "info")
    log("", "info")

    try:
        # Create directory structure (source dirs created only when Intact.AI selected)
        log("Creating package directory structure...", "info")
        os.makedirs(f"{package_dir}/images", exist_ok=True)
        os.makedirs(f"{package_dir}/binaries", exist_ok=True)

        manifest = {
            "package_version": "1.0",
            "created": datetime.now().isoformat(),
            "created_by": "intact-prepare-package",
            "run_id": run_id,
            "versions": {},
            "contents": {
                "images": [],
                "binaries": [],
                "include_source": False
            }
        }

        total_modules = len(modules)
        completed = 0

        # Process each module
        for module, version in modules.items():
            log("", "info")
            log(f"=== {module.upper()} ({version}) ===", "info")

            if module == 'intact':
                # Download Intact.AI source from the public GitHub repo at the
                # specific ref (tag / branch / SHA) the operator entered in the
                # Prepare Upgrade modal. Previously this copied the running
                # backend container's mounted source — which meant any local
                # untracked edits leaked into the upgrade package and there was
                # no way to ship a known-good upstream release without first
                # checking it out on the running box. Now the operator types a
                # release tag (e.g. `intact-20260604`) and the package gets
                # exactly that snapshot, every time.
                #
                # Uses GitHub's codeload tarball endpoint, which resolves any
                # ref (tag / branch / full SHA) under the same URL shape — no
                # git binary required in the backend container.

                if not version:
                    raise ValueError(
                        "Intact.AI source requires a GitHub ref (release tag, "
                        "branch name, or commit SHA) — type one in the "
                        "'Intact.AI Source Code' version field"
                    )

                import urllib.request
                import urllib.error
                import tarfile

                repo = "TenrootOrg/IntactAI"
                tar_url = (
                    f"https://codeload.github.com/{repo}/tar.gz/{version}"
                )
                tar_path = f"{package_dir}/_intact_source.tar.gz"
                extract_dir = f"{package_dir}/_intact_extracted"

                log(
                    f"Downloading Intact.AI source from "
                    f"github.com/{repo} @ '{version}'...",
                    "info",
                )
                try:
                    urllib.request.urlretrieve(tar_url, tar_path)
                except urllib.error.HTTPError as e:
                    raise RuntimeError(
                        f"GitHub ref '{version}' not found at {repo} "
                        f"(HTTP {e.code}). Make sure the release tag exists "
                        f"at https://github.com/{repo}/releases."
                    ) from e
                except urllib.error.URLError as e:
                    raise RuntimeError(
                        f"Could not reach github.com to download the "
                        f"Intact.AI source: {e}. The Prepare Upgrade flow "
                        f"requires internet on the box running the prepare."
                    ) from e

                size_mb = os.path.getsize(tar_path) / (1024 * 1024)
                log(f"  Downloaded {size_mb:.1f} MB", "info")

                # Extract — GitHub tarballs unpack into a single top-level
                # directory shaped like `IntactAI-<sha-or-tag>/`.
                os.makedirs(extract_dir, exist_ok=True)
                with tarfile.open(tar_path, "r:gz") as tar:
                    tar.extractall(extract_dir)

                tops = [
                    d for d in os.listdir(extract_dir)
                    if os.path.isdir(os.path.join(extract_dir, d))
                ]
                if not tops:
                    raise RuntimeError(
                        f"Downloaded tarball from {tar_url} had no top-level "
                        "directory — corrupt download?"
                    )
                extracted_root = os.path.join(extract_dir, tops[0])

                # Copy the WHOLE repo (matches the GitHub layout — `modules/`,
                # `lib/`, `scripts/`, `install.sh`, `config.yaml`, etc.) to
                # `source/intact/`. The apply step targets the specific
                # directories that need swapping into the running install
                # (backend code, frontend HTML); the rest of the tree is
                # included so operators can inspect / port the release
                # without re-cloning from GitHub. ~30 MB of repo content.
                log("  Copying full repo into package source/intact/ ...", "info")
                shutil.copytree(
                    extracted_root,
                    f"{package_dir}/source/intact",
                    dirs_exist_ok=True,
                    # `.git/` should not be there in a tarball but if it is,
                    # don't ship it. Also drop any accidentally-present
                    # operator state.
                    ignore=shutil.ignore_patterns(
                        '__pycache__', '*.pyc', '.env*', '*.db*',
                        '.git', 'data', 'backups',
                    ),
                )
                log("  Full repo copied", "success")

                # Mirror the historical `source/backend` and `source/frontend`
                # entry points so the apply side (services/upgrade/intact.py +
                # __init__.py) keeps working unchanged for the offline
                # upgrade flow that ships backend + frontend HTML into the
                # running install. The apply side prefers the new
                # `source/intact/` paths when present (see intact.py edit)
                # but falls back to these for older packages.
                backend_src_in_repo = os.path.join(extracted_root, 'modules', 'backend')
                frontend_src_in_repo = os.path.join(extracted_root, 'modules', 'nginx', 'html')

                if os.path.isdir(backend_src_in_repo):
                    shutil.copytree(
                        backend_src_in_repo,
                        f"{package_dir}/source/backend",
                        dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '.env*', '*.db*'),
                    )
                if os.path.isdir(frontend_src_in_repo):
                    shutil.copytree(
                        frontend_src_in_repo,
                        f"{package_dir}/source/frontend",
                        dirs_exist_ok=True,
                    )

                # Tear down the temp tarball + extraction so they don't end up
                # inside the final .tar.gz output.
                try:
                    os.remove(tar_path)
                    shutil.rmtree(extract_dir)
                except Exception:
                    pass

                manifest["versions"]["intact"] = version
                manifest["contents"]["include_source"] = True
                manifest["contents"]["source_origin"] = (
                    f"github.com/{repo}@{version}"
                )

            elif module == 'velociraptor':
                # Velociraptor packaging — internet REQUIRED here on the
                # prepare side. The Dockerfile is pure COPY; all four
                # binaries (linux server + mac/win clients) must be in
                # the build context before `docker compose build`. We
                # download them upstream, stage them into the module
                # build context AND drop a copy into the package's
                # binaries/ dir so the offline upgrade can re-stage on
                # the target without network. If the build succeeds we
                # also bake the image into images/<version>.tar so the
                # target can `docker load` directly.
                log("Downloading Velociraptor binaries (4 — linux server + mac/win clients)...", "info")

                clean_version = version.lstrip('v')
                parts = clean_version.split('.')

                if len(parts) < 3:
                    log(f"  Full version required (e.g., 0.75.6), got: {version}", "error")
                    continue

                release_tag = f"v{parts[0]}.{parts[1]}"
                base_url = f"https://github.com/Velocidex/velociraptor/releases/download/{release_tag}"
                velo_tag = f"{parts[0]}.{parts[1]}"

                # The four upstream filenames the Dockerfile needs.
                # Keep them aligned with `_velociraptor_binary_set` in
                # services/upgrade/velociraptor.py.
                upstream_binaries = [
                    f"velociraptor-v{clean_version}-linux-amd64",
                    f"velociraptor-v{clean_version}-darwin-amd64",
                    f"velociraptor-v{clean_version}-windows-amd64.exe",
                    f"velociraptor-v{clean_version}-windows-amd64.msi",
                ]

                # Module build context dirs (mirror the COPY paths in
                # modules/velociraptor/Dockerfile).
                velo_dir = "/app/workdir/modules/velociraptor"
                staging_map = {
                    upstream_binaries[0]: os.path.join(velo_dir, 'clients', 'linux',   'velociraptor'),
                    upstream_binaries[1]: os.path.join(velo_dir, 'clients', 'mac',     'velociraptor_client'),
                    upstream_binaries[2]: os.path.join(velo_dir, 'clients', 'windows', 'velociraptor_client.exe'),
                    upstream_binaries[3]: os.path.join(velo_dir, 'clients', 'windows', 'velociraptor_client.msi'),
                }

                log(f"  Version: {clean_version}", "info")
                log(f"  Release tag: {release_tag}", "info")

                # Only the linux server binary is REQUIRED. Mac/Windows
                # clients are convenience artifacts the entrypoint
                # tries to repack with server config; if upstream
                # doesn't publish them for this point release (e.g.
                # v0.75.6 has no darwin-amd64), we stage zero-byte
                # placeholders so the Dockerfile COPY still succeeds
                # and the runtime repack silently no-ops on them.
                required_binary = upstream_binaries[0]  # the linux-amd64 one
                required_ok = False
                missing_optional: list = []

                # The local install staged these same four binaries under
                # modules/nginx/html/downloads/ at install time (see
                # lib/docker.sh:download_offline_collector_binaries). On a
                # box that's been installed and is now preparing an offline
                # upgrade package, the binary is already on disk — using
                # the local copy makes prepare work air-gapped AND
                # immunizes it against the upstream curl flakes the user
                # has been hitting (e.g. v0.76.5-linux-amd64 1-min hang).
                local_downloads = f"{WORKDIR}/modules/nginx/html/downloads"

                for fname in upstream_binaries:
                    pkg_path = f"{package_dir}/binaries/{fname}"
                    staged_dest = staging_map[fname]
                    os.makedirs(os.path.dirname(staged_dest), exist_ok=True)
                    local_src = os.path.join(local_downloads, fname)

                    # Local-first: same binary, no network round-trip.
                    if os.path.exists(local_src) and os.path.getsize(local_src) > 0:
                        log(f"  Using local: {fname} ({_format_size(os.path.getsize(local_src))})", "info")
                        cp = run_command(f"cp {local_src} {pkg_path}", logger=None, run_id=run_id)
                        if cp.get("cancelled"):
                            return {"success": False, "error": "cancelled", "cancelled": True}
                        ok = cp['success'] and os.path.exists(pkg_path) and os.path.getsize(pkg_path) > 0
                    else:
                        url = f"{base_url}/{fname}"
                        log(f"  Downloading: {fname}", "info")
                        dl = run_command(
                            f"curl -L -f --retry 5 --retry-delay 5 --retry-max-time 120 "
                            f"-o {pkg_path} {url}",
                            timeout=300, logger=None, run_id=run_id,
                        )
                        if dl.get("cancelled"):
                            return {"success": False, "error": "cancelled", "cancelled": True}
                        ok = dl['success'] and os.path.exists(pkg_path) and os.path.getsize(pkg_path) > 0
                    if not ok:
                        if os.path.exists(pkg_path):
                            os.remove(pkg_path)
                        if fname == required_binary:
                            log(f"  Failed to download REQUIRED {fname}: {dl.get('error','')[:120]}", "error")
                            break
                        log(f"  {fname} unavailable upstream — using empty placeholder", "warning")
                        # zero-byte file in both the package and the
                        # build-context staging dir, so the Dockerfile
                        # COPY succeeds offline too.
                        open(pkg_path, 'wb').close()
                        open(staged_dest, 'wb').close()
                        missing_optional.append(fname)
                        continue

                    if not fname.endswith('.msi'):
                        os.chmod(pkg_path, 0o755)
                    log(f"  Done ({_format_size(os.path.getsize(pkg_path))})", "success")
                    manifest["contents"]["binaries"].append(fname)

                    run_command(f"cp {pkg_path} {staged_dest}", logger=None)
                    if not fname.endswith('.msi'):
                        run_command(f"chmod +x {staged_dest}", logger=None)
                    if fname == required_binary:
                        required_ok = True

                if not required_ok:
                    log("  Required linux server binary unavailable — skipping image bake.", "error")
                    log("  Target machines will fail offline upgrade until the package is re-prepared.", "warning")
                    continue
                if missing_optional:
                    log(f"  Note: placeholder(s) used for {len(missing_optional)} client binary(ies): {', '.join(missing_optional)}",
                        "warning")

                manifest["versions"]["velociraptor"] = clean_version

                # Build the image with the now-staged binaries. The
                # Dockerfile is COPY-only, so this is fast (~1s) and
                # has zero network dependencies. If it still fails,
                # something is structurally wrong (e.g., base image
                # missing in local Docker), not a network issue.
                log("Baking Velociraptor image for the target (offline-safe build)...", "info")
                host_velo_dir = velo_dir.replace(WORKDIR, HOST_PATH, 1)
                compose_file = f"{host_velo_dir}/docker-compose.yaml"
                image_tag = f"velociraptor-server:{clean_version}"
                build_result = run_command(
                    f"VELOCIRAPTOR_VERSION={clean_version} VELOCIRAPTOR_TAG={velo_tag} "
                    f"docker compose -f {compose_file} --project-directory {host_velo_dir} build "
                    f"--build-arg VELOCIRAPTOR_VERSION={clean_version} --build-arg VELOCIRAPTOR_TAG={velo_tag}",
                    timeout=600, logger=None, run_id=run_id,
                )
                if build_result.get("cancelled"):
                    return {"success": False, "error": "cancelled", "cancelled": True}
                if build_result['success']:
                    output_path = f"{package_dir}/images/velociraptor-{clean_version}.tar"
                    save_result = run_command(
                        f"docker save -o {output_path} {image_tag}",
                        timeout=300, logger=None, run_id=run_id,
                    )
                    if save_result.get("cancelled"):
                        return {"success": False, "error": "cancelled", "cancelled": True}
                    if save_result['success']:
                        img_size = os.path.getsize(output_path)
                        log(f"  Image exported ({_format_size(img_size)})", "success")
                        manifest["contents"]["images"].append(f"velociraptor-{clean_version}.tar")
                    else:
                        log(f"  Failed to export image: {save_result.get('error', '')[:120]}", "warning")
                        log("  Target will rebuild locally from the staged binaries (still offline-safe).", "info")
                else:
                    log(f"  Failed to build image: {build_result.get('error', '')[:160]}", "warning")
                    log("  Target will rebuild locally from the staged binaries (still offline-safe).", "info")

            elif module in DOCKER_IMAGES:
                # Pull and save Docker images
                for image_template, output_template in DOCKER_IMAGES[module]:
                    image = image_template.format(version=version)
                    output_name = output_template.format(version=version)
                    output_path = f"{package_dir}/images/{output_name}"

                    if _pull_and_save_image(image, output_path, log, run_id=run_id):
                        manifest["contents"]["images"].append(output_name)
                    # Honor cancel between images (fast-exit on Stop).
                    try:
                        from services.workflow_service import is_cancelled
                        if is_cancelled(run_id):
                            return {"success": False, "error": "cancelled", "cancelled": True}
                    except Exception:
                        pass

                manifest["versions"][module] = version

                # Timesketch-specific: bundle alembic migrations into the package
                # so the offline upgrade doesn't need internet access. The
                # installed Timesketch wheel doesn't ship migrations/; fetching
                # from GitHub at upgrade time defeats the offline guarantee.
                if module == 'timesketch':
                    log("Bundling Timesketch alembic migrations...", "info")
                    mig_url = f"https://github.com/google/timesketch/archive/refs/tags/{version}.tar.gz"
                    src_tarball = f"{package_dir}/_ts_src_{version}.tar.gz"
                    dl = run_command(f"curl -fLsS -o {src_tarball} {mig_url}", timeout=180, logger=None, run_id=run_id)
                    if dl.get("cancelled"):
                        return {"success": False, "error": "cancelled", "cancelled": True}
                    if not dl['success'] or not os.path.exists(src_tarball) or os.path.getsize(src_tarball) < 1024:
                        log(f"  Failed to download Timesketch source for migrations from {mig_url}", "warning")
                        log("  Offline upgrade may fall back to GitHub for migrations at apply time", "warning")
                    else:
                        ts_mig_dir = f"{package_dir}/migrations/timesketch"
                        os.makedirs(ts_mig_dir, exist_ok=True)
                        # --strip-components=3 drops `timesketch-<ver>/timesketch/migrations/`
                        # so extracted contents land as `versions/`, `env.py`,
                        # `alembic.ini` etc. directly under ts_mig_dir — the
                        # layout tsctl's `-d` flag expects.
                        extract = run_command(
                            f"tar -xzf {src_tarball} -C {ts_mig_dir} --wildcards "
                            f"--strip-components=3 '*/timesketch/migrations/*'",
                            timeout=60, logger=None
                        )
                        try:
                            os.remove(src_tarball)
                        except Exception:
                            pass
                        if extract['success'] and os.path.isdir(f"{ts_mig_dir}/versions"):
                            mig_count = len([f for f in os.listdir(f"{ts_mig_dir}/versions") if f.endswith('.py')])
                            log(f"  Migrations bundled ({mig_count} revision files)", "success")
                            manifest["contents"].setdefault("migrations", []).append("timesketch")
                        else:
                            log(f"  Failed to extract migrations from source tarball", "warning")
            else:
                log(f"  Unknown module: {module}", "warning")

            completed += 1

        # Check if any modules were actually packaged
        has_content = (manifest["contents"]["images"] or
                      manifest["contents"]["binaries"] or
                      manifest["contents"].get("include_source", False))
        if not has_content:
            raise Exception("No modules were packaged successfully. Check your internet connection and try again.")

        # Write manifest
        log("", "info")
        log("=== Creating Manifest ===", "info")
        with open(f"{package_dir}/manifest.json", 'w') as f:
            json.dump(manifest, f, indent=2)
        log("  Created manifest.json", "success")

        # Create tar.gz archive
        log("", "info")
        log("=== Creating Package Archive ===", "info")
        log("  Compressing package (this may take a few minutes)...", "info")

        result = _compress_with_progress(
            source_dir="/tmp",
            source_name=package_name,
            output_file=output_file,
            logger=log,
            progress_interval=10,
            run_id=run_id,
        )

        if result.get("cancelled"):
            return {"success": False, "error": "cancelled", "cancelled": True}
        if not result['success']:
            raise Exception(f"Failed to create archive: {result.get('error', '')[:200]}")

        package_size = os.path.getsize(output_file)
        log(f"  Package created: {_format_size(package_size)}", "success")

        # Summary (cleanup happens in finally block)
        log("", "info")
        log("=" * 50, "info")
        log("PACKAGE READY", "success")
        log("=" * 50, "info")
        log(f"  Size: {_format_size(package_size)}", "info")
        log(f"  Modules: {', '.join(modules.keys())}", "info")
        log("", "info")
        log("Click 'Download Package' to save the file.", "info")

        return {
            "success": True,
            "package_path": output_file,
            "package_name": f"{package_name}.tar.gz",
            "package_size": package_size,
            "manifest": manifest
        }

    except Exception as e:
        log(f"Package preparation failed: {str(e)}", "error")

        # Remove failed output file
        if os.path.exists(output_file):
            os.remove(output_file)

        return {
            "success": False,
            "error": str(e)
        }

    finally:
        # Always cleanup temp directory and pulled images
        if os.path.exists(package_dir):
            try:
                shutil.rmtree(package_dir)
            except Exception:
                pass

        # Always cleanup pulled Docker images
        for module, version in modules.items():
            if module in DOCKER_IMAGES:
                for image_template, _ in DOCKER_IMAGES[module]:
                    image = image_template.format(version=version)
                    run_command(f"docker rmi {image} 2>/dev/null || true", logger=None, timeout=60)
