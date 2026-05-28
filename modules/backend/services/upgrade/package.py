#!/usr/bin/env python3
"""Upgrade package preparation service.

Creates offline upgrade packages that can be transferred to air-gapped systems.
"""

import os
import json
import shutil
from datetime import datetime
from typing import Dict, Callable, List

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
                            logger: Callable, progress_interval: int = 10) -> Dict:
    """Compress directory to tar.gz with progress updates.

    Args:
        source_dir: Parent directory containing source_name (e.g., /tmp)
        source_name: Name of directory to compress (e.g., intact-upgrade-20260323)
        output_file: Output tar.gz path
        logger: Logging function
        progress_interval: Seconds between progress updates

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

    last_update = time.time()
    last_size = 0

    # Poll for progress
    while process.poll() is None:
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


def _pull_and_save_image(image: str, output_path: str, logger: Callable) -> bool:
    """Pull a Docker image and save it to a tar file."""
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))

    # Pull the image with output shown
    log(f"  Pulling {image}...", "info")
    result = run_command(f"docker pull {image}", timeout=1200, logger=log)
    if not result['success']:
        log(f"  Failed to pull {image}: {result.get('error', '')[:200]}", "error")
        return False

    # Save the image (increased timeout for large images)
    log(f"  Saving to {os.path.basename(output_path)}...", "info")
    result = run_command(f"docker save -o {output_path} {image}", timeout=1200, logger=None)
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
                # Copy source files from local machine
                # TODO: Future - pull from GitHub like other modules (currently private repo)
                # Should work like: download specific version/tag from repo
                log("Copying Intact.AI source files...", "info")

                backend_src = os.path.join(WORKDIR, 'modules', 'backend')
                frontend_src = os.path.join(WORKDIR, 'modules', 'nginx', 'html')

                if os.path.isdir(backend_src):
                    log("  Copying backend source...", "info")
                    shutil.copytree(
                        backend_src,
                        f"{package_dir}/source/backend",
                        dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '.env*', '*.db*')
                    )
                    log("  Backend source copied", "success")
                else:
                    log(f"  Backend source not found at {backend_src}", "warning")

                if os.path.isdir(frontend_src):
                    log("  Copying frontend source...", "info")
                    shutil.copytree(
                        frontend_src,
                        f"{package_dir}/source/frontend",
                        dirs_exist_ok=True
                    )
                    log("  Frontend source copied", "success")
                else:
                    log(f"  Frontend source not found at {frontend_src}", "warning")

                manifest["versions"]["intact"] = version
                manifest["contents"]["include_source"] = True

            elif module == 'velociraptor':
                # Download Velociraptor binary and build image for air-gap support
                log("Downloading Velociraptor binary...", "info")

                # Parse version
                clean_version = version.lstrip('v')
                parts = clean_version.split('.')

                if len(parts) < 3:
                    log(f"  Full version required (e.g., 0.75.6), got: {version}", "error")
                    continue

                release_tag = f"v{parts[0]}.{parts[1]}"
                binary_name = f"velociraptor-v{clean_version}-linux-amd64"
                url = f"https://github.com/Velocidex/velociraptor/releases/download/{release_tag}/{binary_name}"

                log(f"  Version: {clean_version}", "info")
                log(f"  Release tag: {release_tag}", "info")
                log(f"  URL: {url}", "info")

                binary_path = f"{package_dir}/binaries/{binary_name}"
                result = run_command(
                    f"curl -L -f -o {binary_path} {url}",
                    timeout=300,
                    logger=None
                )

                if result['success']:
                    os.chmod(binary_path, 0o755)
                    size = os.path.getsize(binary_path)
                    log(f"  Downloaded ({_format_size(size)})", "success")
                    manifest["versions"]["velociraptor"] = clean_version
                    manifest["contents"]["binaries"].append(binary_name)

                    # Build and export image for air-gap support
                    log("Building Velociraptor image for air-gap...", "info")
                    velo_dir = "/app/workdir/modules/velociraptor"
                    velo_bin_dest = os.path.join(velo_dir, "velociraptor", "velociraptor")

                    # Copy binary to velociraptor directory for build
                    run_command(f"cp {binary_path} {velo_bin_dest}", logger=None)
                    run_command(f"chmod +x {velo_bin_dest}", logger=None)

                    # Build image with specific tag
                    # Use host paths for docker compose (container paths don't work for build context)
                    host_velo_dir = velo_dir.replace(WORKDIR, HOST_PATH, 1)
                    compose_file = f"{host_velo_dir}/docker-compose.yaml"

                    image_tag = f"velociraptor-server:{clean_version}"
                    velo_tag = f"{parts[0]}.{parts[1]}"
                    build_result = run_command(
                        f"VELOCIRAPTOR_VERSION={clean_version} VELOCIRAPTOR_TAG={velo_tag} "
                        f"docker compose -f {compose_file} --project-directory {host_velo_dir} build "
                        f"--build-arg VELOCIRAPTOR_VERSION={clean_version} --build-arg VELOCIRAPTOR_TAG={velo_tag}",
                        timeout=600, logger=None
                    )

                    if build_result['success']:
                        # Export the built image
                        output_path = f"{package_dir}/images/velociraptor-{clean_version}.tar"
                        save_result = run_command(f"docker save -o {output_path} {image_tag}", timeout=300, logger=None)
                        if save_result['success']:
                            img_size = os.path.getsize(output_path)
                            log(f"  Image exported ({_format_size(img_size)})", "success")
                            manifest["contents"]["images"].append(f"velociraptor-{clean_version}.tar")
                        else:
                            log(f"  Failed to export image: {save_result.get('error', '')[:100]}", "warning")
                    else:
                        log(f"  Failed to build image: {build_result.get('error', '')[:100]}", "warning")
                        log("  Binary included but image not built - offline upgrade will require network", "warning")
                else:
                    log(f"  Failed to download: {result.get('error', '')[:100]}", "error")

            elif module in DOCKER_IMAGES:
                # Pull and save Docker images
                for image_template, output_template in DOCKER_IMAGES[module]:
                    image = image_template.format(version=version)
                    output_name = output_template.format(version=version)
                    output_path = f"{package_dir}/images/{output_name}"

                    if _pull_and_save_image(image, output_path, log):
                        manifest["contents"]["images"].append(output_name)

                manifest["versions"][module] = version

                # Timesketch-specific: bundle alembic migrations into the package
                # so the offline upgrade doesn't need internet access. The
                # installed Timesketch wheel doesn't ship migrations/; fetching
                # from GitHub at upgrade time defeats the offline guarantee.
                if module == 'timesketch':
                    log("Bundling Timesketch alembic migrations...", "info")
                    mig_url = f"https://github.com/google/timesketch/archive/refs/tags/{version}.tar.gz"
                    src_tarball = f"{package_dir}/_ts_src_{version}.tar.gz"
                    dl = run_command(f"curl -fLsS -o {src_tarball} {mig_url}", timeout=180, logger=None)
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
            progress_interval=10
        )

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
