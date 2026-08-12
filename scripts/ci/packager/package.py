#!/usr/bin/env python3
"""Release package builder -- pulls/saves images, mirrors source, writes the
manifest, compresses.

Moved from modules/backend/services/upgrade/package.py when the upgrade
engine moved off the backend to host-side bash (see docs/UPGRADE.md). This is
NOT dead code carried along for nostalgia: it is the only thing that builds a
release, and scripts/ci/build_release_package.py depends on it directly. What
changed in the move is the coupling, not the logic -- see proc.py,
backend_mode.py, resolver.py and velociraptor_release.py's docstrings for what
each replaces and why.

Still creates the SAME package shape upgrade.sh consumes: one asset per
module, sharing a top-level `intact-upgrade-<tag>/` directory, each carrying a
`manifests/<module>.json` sidecar for the CI index job to merge.
"""

import os
import json
import shutil
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Dict, Callable, List, Optional, Tuple

from .proc import run_command, WORKDIR, HOST_PATH


# How many images to pull+save at once within a module.
#
# Three, not more, because the two halves of the work scale differently.
# `docker pull` is network-bound and overlaps almost perfectly -- that is where
# the win is, and on a module like timesketch (five images) it is most of the
# wall clock. `docker save` is disk-bound; running many at once mostly queues
# on I/O while raising the peak free-space demand, since every in-flight save
# holds a reservation. Three keeps a pull running behind every save without
# turning the disk into the bottleneck.
#
# CI parallelises ACROSS modules already (one runner per module), so this only
# shortens the slowest module -- which is exactly what sets the release's
# critical path.
_IMAGE_WORKERS = 3

# One aggregate progress line this often while images are in flight. Same
# cadence and same reasoning as the asset downloader: with several workers
# running, each logging its own percentage produces noise nobody reads, so a
# single reporter says what is happening overall.
_IMAGE_PROGRESS_SECONDS = 30


# Primary images per module — the deliverables the operator's
# `versions:` pin in config.yaml directly drives. `{version}` is
# substituted with `modules[<module>]` at prepare time.
# PRIMARY_IMAGES, TRANSITIVE_IMAGES, module_image_repos, image_owner_prefixes
# and images_by_module were relocated to services/image_map.py when the
# upgrade engine moved to the host (app.py's boot-time image reclaim needed
# them and the package they lived in was going away). They are NOT
# upgrade-specific -- image_map.py is a permanent shared module, not deleted
# code -- so importing it here is not the coupling PR7 broke. This IS the one
# deliberate backend import in this file, and it is safe only because the
# packager always runs inside the intact-backend image (see
# build-release-assets.yml's `docker run intact-backend:ci-packager`), never
# on the bare `resolve` runner -- order.py exists precisely so the bare-runner
# path never needs to reach this far.
from services.image_map import (
    PRIMARY_IMAGES, TRANSITIVE_IMAGES,
    module_image_repos, image_owner_prefixes, images_by_module,
)



TRANSITIVE_ENV_KEYS = {
    'timesketch': {
        'opensearch': 'OPENSEARCH_VERSION',
        'postgres':   'POSTGRES_VERSION',
        'redis':      'REDIS_VERSION',
        'nginx':      'NGINX_VERSION',
    },
    'iris': {
        # iris's compose uses `image: rabbitmq:${RABBITMQ_VERSION:?...}`
        # — the apply side must write RABBITMQ_VERSION into
        # modules/iris/.env before compose up. Old comment claiming
        # iris's rabbitmq was a literal tag was incorrect (likely
        # written when iris first shipped with a hardcoded tag, before
        # the env-var conversion).
        'rabbitmq': 'RABBITMQ_VERSION',
    },
    'volweb': {
        'postgres': 'VOLWEB_POSTGRES_VERSION',
        'redis':    'VOLWEB_REDIS_VERSION',
    },
    # tusd is the backend backbone's upload sidecar. It rides the same
    # `<module>_<sidecar>` convention (versions.backend_tusd -> TUSD_VERSION),
    # but the intact backbone is upgraded outside the generic per-module loop,
    # so recreate_tusd() in intact.py is what stamps + recreates it.
    'backend': {
        'tusd': 'TUSD_VERSION',
    },
}


def _read_config_yaml_versions() -> Dict[str, str]:
    """Return the `versions:` block from config.yaml as a flat dict.
    Fail-soft (empty dict) on any read/parse error so a malformed
    config.yaml surfaces in get_transitive_tag's KeyError rather than
    a yaml.YAMLError that's harder to attribute. Caller is expected
    to validate the keys it cares about.
    """
    config_path = os.path.join(WORKDIR, 'config.yaml')
    if not os.path.exists(config_path):
        return {}
    try:
        import yaml  # local — yaml isn't used elsewhere in this module
        with open(config_path, 'r') as f:
            cfg = yaml.safe_load(f) or {}
        v = cfg.get('versions') or {}
        return {str(k): str(val).strip() for k, val in v.items()
                if val is not None}
    except Exception:
        return {}


def get_transitive_tag(module: str, dep: str,
                        primary_version: Optional[str] = None,
                        logger: Optional[Callable] = None,
                        target_versions: Optional[Dict[str, str]] = None) -> str:
    """Resolve <module>.<dep> from a `versions:` map. By default reads the
    operator's local `config.yaml`, but the caller can pass
    `target_versions` to override — this is what the prepare flow does
    so the BUNDLED transitive pins come from the TARGET release's
    `config.yaml` rather than whatever the build host happens to have
    pinned locally.

    No upstream scrape, no cache layer, no fallback table.

    `primary_version` is kept in the signature for source-compat with
    callers that used to need it for the live scrape, but is ignored —
    the pin from the chosen `versions:` map is authoritative regardless
    of which primary version is being installed/upgraded.

    Raises `KeyError` when the `versions.<module>_<dep>` entry is
    missing. The error message is operator-facing; it tells them what
    key to add.
    """
    log = logger or (lambda msg, lvl='info': None)
    key = f"{module}_{dep}"
    if target_versions is not None:
        versions = target_versions
        source = "target config.yaml"
    else:
        versions = _read_config_yaml_versions()
        source = "config.yaml"
    value = versions.get(key)
    if not value:
        raise KeyError(
            f"versions.{key} is missing from config.yaml. The 2026-06-14 "
            f"refactor moved transitive sidecar pins from an upstream "
            f"scrape into config.yaml. Add a line under `versions:` like:\n"
            f"  {key}: '<tag>'\n"
            f"For reference, current shipped values are documented in the "
            f"config.yaml comment block above the `<module>_<dep>` entries."
        )
    log(f"  [transitive] {module}.{dep} = {value} ({source})", "info")
    return value


def get_docker_images_for(module: str, version: str,
                           logger: Optional[Callable] = None,
                           target_versions: Optional[Dict[str, str]] = None) -> list:
    """Return the list of `(image, tar_filename)` to bundle for one
    primary module + version. Same shape the old `DOCKER_IMAGES[module]`
    list returned (already with placeholders expanded), so callers can
    iterate uniformly.

    Tag resolution per image:
      - Primary image: `versions.<module>` pin from config.yaml
      - Transitive image: `versions.<module>_<dep>` pin from config.yaml
        (e.g. `timesketch_postgres`, `iris_rabbitmq`). See
        get_transitive_tag for the resolver.

    `logger` (when provided) emits one info-level line per resolved
    transitive tag so the prepare log shows which config.yaml entry
    fed each image.
    """
    out = []
    for image_pat, tar_pat in PRIMARY_IMAGES.get(module, []):
        out.append((
            image_pat.format(version=version),
            tar_pat.format(version=version),
        ))
    for dep_key, image_pat, tar_pat in TRANSITIVE_IMAGES.get(module, []):
        tag = get_transitive_tag(module, dep_key, primary_version=version,
                                  logger=logger,
                                  target_versions=target_versions)
        out.append((
            image_pat.format(tag=tag),
            tar_pat.format(tag=tag),
        ))
    return out


def get_transitive_versions_for(module: str,
                                  primary_version: Optional[str] = None,
                                  logger: Optional[Callable] = None,
                                  target_versions: Optional[Dict[str, str]] = None,
                                  ) -> Dict[str, str]:
    """Return the resolved transitive tags for `module` keyed by env-var
    name (e.g. {'POSTGRES_VERSION': '15', 'OPENSEARCH_VERSION': '2.19.5'}).
    Empty dict for modules with no transitive deps. The manifest carries
    this so the offline apply can stamp per-module `.env` files BEFORE
    `docker compose up`.

    `primary_version` enables the upstream-scrape fallback in
    get_transitive_tag — without it, only the operator override +
    hardcoded defaults are consulted.

    `logger` (when provided) is forwarded to get_transitive_tag so each
    dep's resolution chain is visible in the workflow log.
    """
    env_map = TRANSITIVE_ENV_KEYS.get(module, {})
    if not env_map:
        return {}
    out = {}
    for dep_key, env_key in env_map.items():
        try:
            out[env_key] = get_transitive_tag(
                module, dep_key, primary_version=primary_version,
                logger=logger, target_versions=target_versions,
            )
        except KeyError:
            continue
    return out


# Backwards-compat shim: anything that historically did
# `DOCKER_IMAGES[<module>]` still works (returns the templated list).
# The two in-tree callers in this file have been updated to call
# get_docker_images_for() directly with the version arg; this stays
# only for any future callers / external tooling that import the dict.
class _DockerImagesCompat:
    def __contains__(self, module: str) -> bool:
        return module in PRIMARY_IMAGES or module in TRANSITIVE_IMAGES

    def __getitem__(self, module: str):
        # Return the un-expanded templates so old `.format(version=...)`
        # callers keep working. Transitive entries are returned with the
        # resolved tag pre-baked (since they have no `{version}` slot).
        items = list(PRIMARY_IMAGES.get(module, []))
        for dep_key, image_pat, tar_pat in TRANSITIVE_IMAGES.get(module, []):
            try:
                tag = get_transitive_tag(module, dep_key)
            except KeyError:
                continue
            items.append((image_pat.format(tag=tag), tar_pat.format(tag=tag)))
        return items


DOCKER_IMAGES = _DockerImagesCompat()


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

    # Build a file list with manifest.json FIRST so it lives in the
    # first ~10KB of the gzipped tar. This lets:
    #   * the operator's browser peek the manifest from the first ~5MB
    #     of the local file before any upload (see /api/upgrade/peek-manifest),
    #   * get_package_info()'s slow-path fallback to find the manifest
    #     in the first decompressed block instead of scanning the
    #     entire archive.
    # Falls back to the legacy directory-mode tar command if the
    # manifest doesn't exist (older callers / partial packages).
    manifest_rel = os.path.join(source_name, 'manifest.json')
    manifest_abs = os.path.join(source_path, 'manifest.json')
    list_file = output_file + '.filelist'
    use_files_from = False
    try:
        if os.path.isfile(manifest_abs):
            entries = [manifest_rel]
            for root, _, files in os.walk(source_path):
                for f in files:
                    rel = os.path.relpath(os.path.join(root, f), source_dir)
                    if rel != manifest_rel:
                        entries.append(rel)
            with open(list_file, 'w') as f:
                f.write('\n'.join(entries) + '\n')
            use_files_from = True
    except Exception as _e:
        # Anything weird → fall through to the legacy directory-mode tar.
        # The output is still a correct tarball, just with manifest in
        # whatever filesystem-order tar picks.
        use_files_from = False

    if use_files_from:
        cmd = f"tar -czf {output_file} -C {source_dir} -T {list_file}"
    else:
        cmd = f"tar -czf {output_file} -C {source_dir} {source_name}"
    process = subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    # The backend's copy of this wired a Stop button to SIGTERM the tar
    # subprocess via workflow_service's cancel event -- meaningless here,
    # since a CI job has no such button. A cancelled Actions run kills the
    # whole container, which achieves the same end more bluntly. `run_id`
    # stays a parameter (threaded through to run_command below, which
    # ignores it) so this function's signature matches its origin.
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

    # Best-effort cleanup of the file list (only created when use_files_from
    # branch ran). Failures here are harmless cruft.
    try:
        if use_files_from and os.path.isfile(list_file):
            os.remove(list_file)
    except Exception:
        pass

    if returncode != 0:
        return {"success": False, "error": stderr[:200]}

    # Post-write integrity check. `tar -czf` returning 0 is not enough —
    # we've seen tar produce structurally-corrupt gzip streams under
    # disk pressure / concurrent writes that pass tar's own exit code
    # but fail the operator's apply step with a raw zlib error at
    # extract time. `gzip -t` reads the whole file and validates every
    # deflate block, so a corrupt archive fails here instead of on a
    # different machine 5 minutes later. Cost: one full re-read of the
    # archive (~10-30 sec on a 4 GB file) — small price for the
    # operator confidence.
    log("  Verifying archive integrity (gzip -t)...", "info")
    verify = subprocess.run(
        ["gzip", "-t", output_file],
        capture_output=True, text=True,
    )
    if verify.returncode != 0:
        try:
            os.remove(output_file)
        except OSError:
            pass
        err = (verify.stderr or "").strip() or "gzip integrity check failed"
        return {
            "success": False,
            "error": (
                "Output tar.gz failed gzip integrity check: "
                f"{err[:200]}. Likely cause: disk pressure or concurrent "
                "writes during compression. Free up /data and re-run prepare."
            ),
        }
    log("  Archive integrity OK", "success")

    return {"success": True}


class _DiskBudget:
    """Free-space accounting shared by concurrent `docker save`s.

    Run serially, reading `disk_usage().free` immediately before each save is
    sound. Run three at once and all three read the SAME free space, all three
    conclude they fit, and the volume can still run out with every tar
    truncated — `docker save` exits 0 on a short write, so nothing notices
    until the apply side hits "unexpected EOF" on a customer's box weeks later.

    Reserving up front makes the check mean what it says: a save only starts if
    its space is still unclaimed by the saves already running.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._reserved = 0

    def reserve(self, path: str, nbytes: int) -> Tuple[bool, Optional[int]]:
        """(granted, unreserved_free). `unreserved_free` is None when free
        space could not be read at all, in which case the caller proceeds
        unchecked — exactly as it did before this class existed."""
        with self._lock:
            try:
                free = shutil.disk_usage(path).free
            except (FileNotFoundError, OSError):
                return True, None
            available = free - self._reserved
            if available < nbytes:
                return False, available
            self._reserved += nbytes
            return True, available

    def release(self, nbytes: int) -> None:
        with self._lock:
            self._reserved = max(0, self._reserved - nbytes)


def _pull_and_save_image(image: str, output_path: str, logger: Callable,
                          run_id: Optional[str] = None,
                          budget: Optional['_DiskBudget'] = None,
                          quiet: bool = False) -> bool:
    """Pull a Docker image and save it to a tar file.

    `run_id` makes both subprocesses (docker pull, docker save)
    interruptible — a Stop click during a 20-minute pull terminates
    the docker CLI within a second instead of letting it run to
    completion and only then noticing the cancel flag.

    `budget` serialises the pre-save free-space check across concurrent callers
    (see :class:`_DiskBudget`). A private one is used when none is passed, which
    reserves nothing anyone else can see and so behaves exactly as the serial
    path always did.

    `quiet` suppresses `docker pull`'s layer-progress stream. With several
    images in flight those streams interleave into something unreadable, so the
    caller reports aggregate progress instead; failures still carry the full
    error text either way.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    budget = budget or _DiskBudget()
    tar_name = os.path.basename(output_path)

    # Pull the image with output shown
    log(f"  Pulling {image}...", "info")
    result = run_command(f"docker pull {image}", timeout=1800,
                         logger=None if quiet else log, run_id=run_id)
    if result.get("cancelled"):
        return False
    if not result['success']:
        log(f"  Failed to pull {image}: {result.get('error', '')[:200]}", "error")
        return False

    # Disk-space check before docker save. The pulled image lives in
    # /var/lib/docker — `docker save` streams it to a tar in the
    # package_dir, which is on the same volume as the output_path
    # we're writing to. If the volume runs out of space mid-save,
    # the tar is truncated silently (`docker save` exits 0 with a
    # partial file) and the apply side then fails with a confusing
    # "unexpected EOF" much later.
    #
    # Use `docker inspect --format='{{.Size}}'` to get the image's
    # uncompressed size — that's roughly what the tar will be. Add
    # a 1.2× margin since tar bookkeeping + uncompressed-vs-saved
    # discrepancies push it slightly over.
    size_check = run_command(
        f"docker inspect --format='{{{{.Size}}}}' {image}",
        timeout=30, logger=None, run_id=run_id,
    )
    required = 0
    if size_check.get("success"):
        try:
            image_bytes = int((size_check.get('stdout', '0') or '0').strip().strip("'"))
            required = int(image_bytes * 1.2)
        except (ValueError, TypeError):
            # docker inspect output unexpected — skip the check, fall
            # through to docker save (the silent-truncation risk is
            # still better than blocking the build on a parse error).
            required = 0

    if required:
        granted, available = budget.reserve(os.path.dirname(output_path), required)
        if not granted:
            log(
                f"  Not enough disk for {tar_name}: need ≥{_format_size(required)} "
                f"(image × 1.2), {_format_size(available or 0)} unreserved. "
                f"Free disk and re-run prepare.",
                "error",
            )
            return False

    # Save the image (increased timeout for large images)
    log(f"  Saving to {tar_name}...", "info")
    try:
        result = run_command(f"docker save -o {output_path} {image}",
                             timeout=1200, logger=None, run_id=run_id)
    finally:
        # The tar now occupies real space, so the reservation has done its job
        # either way — on success the bytes are accounted for by the filesystem,
        # on failure they were never taken. Holding it would starve later saves.
        if required:
            budget.release(required)

    if result.get("cancelled"):
        return False
    if not result['success']:
        log(f"  Failed to save {image}: {result.get('error', '')[:200]}", "error")
        return False

    # Check file size - warn if suspiciously small (less than 1MB)
    size = os.path.getsize(output_path)
    if size < 1024 * 1024:  # Less than 1MB
        log(f"  WARNING: {tar_name} is only {_format_size(size)} - may be corrupted!", "warning")
        log(f"  This can happen with docker-in-docker setups. Try running on host.", "warning")
        return False

    log(f"  Done: {tar_name} ({_format_size(size)})", "success")
    return True


def _pull_and_save_images(images: List[Tuple[str, str]], images_dir: str,
                          logger: Callable,
                          run_id: Optional[str] = None) -> Tuple[List[str], bool]:
    """Pull+save every (image, tar_name) concurrently. -> (saved_names, cancelled)

    Serially this is the slowest part of building a module's asset, and it is
    slow for a reason that parallelises well: most of the time is spent waiting
    on a registry, not on the CPU. Timesketch pulls five images, iris and volweb
    four each, and elk three large ones — so a module's build is mostly N round
    trips taken one at a time.

    Returned names preserve the DECLARED order, not completion order, so the
    manifest's `contents.images` list does not shuffle from run to run based on
    which registry answered first.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))

    # Same story as _compress_with_progress above: no cancel machinery in CI.
    def _cancelled() -> bool:
        return False

    if len(images) < 2:
        saved = [name for image, name in images
                 if _pull_and_save_image(image, os.path.join(images_dir, name),
                                         log, run_id=run_id)]
        return saved, _cancelled()

    budget = _DiskBudget()
    workers = min(_IMAGE_WORKERS, len(images))
    done: Dict[str, bool] = {}
    in_flight: Dict[str, str] = {}       # tar name -> image ref
    state_lock = threading.Lock()
    stop_reporting = threading.Event()

    log(f"  Pulling {len(images)} images, {workers} at a time "
        f"(progress every {_IMAGE_PROGRESS_SECONDS}s)...", "info")

    def _one(entry: Tuple[str, str]) -> bool:
        image, name = entry
        with state_lock:
            in_flight[name] = image
        ok = False
        try:
            # quiet: N interleaved layer-progress streams are unreadable, so the
            # reporter below speaks for all of them.
            ok = _pull_and_save_image(image, os.path.join(images_dir, name),
                                      log, run_id=run_id, budget=budget,
                                      quiet=True)
        except Exception as exc:
            # One image raising must not take the other workers' results with
            # it. Count it as failed and let the bundled-vs-declared gate below
            # decide what that means for the module.
            log(f"  Failed to bundle {image}: {type(exc).__name__}: {exc}", "error")
        finally:
            with state_lock:
                in_flight.pop(name, None)
                done[name] = ok
        return ok

    def _report() -> None:
        while not stop_reporting.wait(_IMAGE_PROGRESS_SECONDS):
            with state_lock:
                n_done = len(done)
                pending = sorted(in_flight)
            try:
                written = sum(
                    os.path.getsize(os.path.join(images_dir, f))
                    for f in os.listdir(images_dir)
                    if os.path.isfile(os.path.join(images_dir, f))
                )
            except OSError:
                written = 0
            still = (", ".join(pending[:3]) + ("…" if len(pending) > 3 else "")
                     if pending else "finishing")
            log(f"  … {n_done}/{len(images)} images saved, "
                f"{_format_size(written)} on disk — working on {still}", "info")

    reporter = threading.Thread(target=_report, daemon=True)
    reporter.start()
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(_one, images))
    finally:
        stop_reporting.set()
        reporter.join(timeout=2)

    saved = [name for _image, name in images if done.get(name)]
    return saved, _cancelled()


def _intact_first(modules: Dict):
    """Order (module, version) pairs so 'intact' is processed FIRST.

    The intact step extracts the release into source/intact/, which later modules
    read from — notably velociraptor, whose image bake refreshes its build files
    (Dockerfile / bundled_artifacts) from source/intact/modules/velociraptor. If a
    modules dict is ordered velociraptor-before-intact (e.g. a prepare with
    selected_modules=[velociraptor]), velociraptor would bake from stale on-disk
    files and ship a bundle-less image. Stable sort: other modules keep order."""
    return sorted(modules.items(), key=lambda kv: kv[0] != 'intact')


def _prepare_backend_images(package_dir: str, target_version: str, manifest: Dict,
                            source_root: str = None, source_commit: str = None,
                            logger: Callable = None, run_id: str = None) -> Dict:
    """Wave F: bake + bundle the backend runtime image + tusd sidecar.

    Reads the `nginx` / `backend_tusd` pins from ``config.yaml`` at
    ``source_root`` — the ORIGINAL checkout the release was built from, e.g.
    the caller's ``extracted_root``/``source_dir`` — not from
    ``package_dir/source/intact/config.yaml``. That path never has a
    config.yaml to read any more: it is excluded from what ships (see the
    full-repo copytree's ignore_patterns) because it may hold whatever
    machine built the package's live operator secrets. Neither pin comes
    from the manifest either — `nginx` and `backend_tusd` are not
    RELEASE_MODULES entries, so `manifest["versions"]` never carries them;
    config.yaml is the only place they exist.

    The docker build context is packed CLI-side (verified on the live box),
    so the container-local package path works — no host-path mapping needed.

    * tusd image: best-effort (closes the Wave B offline gap — a bundled
      backend_tusd bump then loads without a pull). A miss is a warning, not fatal.
    * backend image: baked ONLY when the target is Full-mode (its backend compose
      no longer bind-mounts code). A Full-mode package without its image would
      brick the apply, so a build/save failure FAILS the whole prepare.

    Returns {"success": bool, ["error"], ["cancelled"]}.
    """
    log = logger or (lambda m, l="info": None)
    src_root = os.path.join(package_dir, 'source', 'intact')
    if not os.path.isdir(src_root):
        return {"success": True}                 # narrow-layout / pre-Wave-F package
    os.makedirs(os.path.join(package_dir, 'images'), exist_ok=True)

    _cfg_root = source_root or src_root
    try:
        import yaml as _yaml
        with open(os.path.join(_cfg_root, 'config.yaml')) as _cf:
            _versions = (_yaml.safe_load(_cf) or {}).get('versions') or {}
    except Exception as _e:
        log(f"  (backend-image prep: could not read config.yaml at {_cfg_root}: {_e})", "warning")
        _versions = {}
    tusd_tag = _versions.get('backend_tusd')
    # The baked image MUST carry the identity the TARGET will look for at
    # convergence, or the shipped image is invisible and the box rebuilds from
    # source. backend_target_tag() on the target resolves
    #   config.yaml versions.backend  ->  VERSION  ->  'development'
    # so an absent/placeholder versions.backend there lands on the release tag
    # from VERSION. Baking off `versions.backend` alone disagreed with that:
    # a 20260721 package shipped intact-backend:development while the box
    # looked for intact-backend:intact-20260721, and rebuilt (observed
    # 2026-07-22). Prefer the release identity from the manifest — it is the
    # same value the target's VERSION carries — and keep the old sources as
    # fallbacks.
    _release_tag = ((manifest.get('versions') or {}).get('intact') or '').strip()
    be_tag = _release_tag or _versions.get('backend') or target_version

    # tusd sidecar image — best-effort
    if tusd_tag:
        _out = f"{package_dir}/images/tusd-{tusd_tag}.tar"
        if _pull_and_save_image(f"tusproject/tusd:{tusd_tag}", _out, log, run_id=run_id):
            manifest["contents"]["images"].append(f"tusd-{tusd_tag}.tar")

    # Main reverse-proxy nginx — the appliance's ONLY ingress (modules/nginx/,
    # the intact_nginx container, `image: nginx:${NGINX_VERSION}`).
    #
    # Nothing bundled this until now, and the gap was invisible on a connected
    # box: `docker compose up -d` just pulled it, one line after the installer
    # logged "images already loaded from the package — not pulling". On an
    # air-gapped box [8/8] Nginx simply fails and the platform has no front
    # door. The same hole exists on the upgrade side, where intact.py stamps
    # NGINX_VERSION and runs `compose up -d nginx`; both are fixed by the image
    # being in the package, with no change needed there.
    #
    # FATAL rather than best-effort like tusd above: tusd is a sidecar and a
    # package without it is merely degraded, while a package without nginx is
    # undeployable. Same reasoning as the backend image below.
    #
    # NAME: intact-nginx-<tag>.tar, NOT nginx-<tag>.tar. `nginx-` is already
    # timesketch's prefix in TRANSITIVE_IMAGES (its own nginx:1.25.5-alpine-slim),
    # and image_owner_prefixes() is a flat prefix map -- reusing it would
    # attribute the platform's ingress to timesketch and let the unselected-module
    # prune delete it on any apply that deselects timesketch. The tar filename is
    # module-qualified; the image ref inside is plain `nginx:<tag>`, which is what
    # compose resolves. The two differ on purpose.
    nginx_tag = _versions.get('nginx')
    if not nginx_tag:
        return {"success": False,
                "error": ("versions.nginx is missing from the target release's "
                          "config.yaml, so the main reverse-proxy image cannot be "
                          "bundled. modules/nginx/docker-compose.yaml pins "
                          "nginx:${NGINX_VERSION}; a package without it cannot "
                          "bring up the platform's only ingress offline.")}
    _nginx_image = f"nginx:{nginx_tag}"
    _out = f"{package_dir}/images/intact-nginx-{nginx_tag}.tar"
    # INSPECT BEFORE PULL. _pull_and_save_image always runs `docker pull`, and
    # this function is shared with the on-box Prepare Package flow -- an
    # appliance preparing a package is, by definition, already running this
    # exact nginx image, and may well have no registry access at all. Pulling
    # unconditionally would turn a fatal error into the normal case there.
    _have = run_command(f"docker image inspect {_nginx_image}",
                        timeout=30, logger=None, run_id=run_id)
    if _have.get("success"):
        log(f"  {_nginx_image} already present — saving without pulling", "info")
        _save = run_command(f"docker save -o {_out} {_nginx_image}",
                            timeout=600, logger=None, run_id=run_id)
        if _save.get("cancelled"):
            return {"success": False, "cancelled": True, "error": "cancelled"}
        _ok = _save.get("success") and os.path.exists(_out)
    else:
        _ok = _pull_and_save_image(_nginx_image, _out, log, run_id=run_id)
    if not _ok:
        return {"success": False,
                "error": (f"could not bundle {_nginx_image} — refusing to ship a "
                          f"package whose [8/8] Nginx step would need the internet. "
                          f"Pull it on this host first, or correct versions.nginx.")}
    manifest["contents"]["images"].append(f"intact-nginx-{nginx_tag}.tar")
    log(f"  Main nginx image bundled ({_format_size(os.path.getsize(_out))})", "success")

    # backend runtime image — Full-mode releases MUST ship their baked image.
    # A Full-mode package without it forces the target to rebuild the backend
    # from source at convergence (slow, and it stranded boxes at ~95%). So decide
    # the mode from the TARGET's own compose, and if we can't decide — the compose
    # is missing/unreadable — FAIL LOUD instead of silently defaulting to "legacy"
    # and shipping an image-less package.
    from .backend_mode import backend_full_mode
    target_compose = os.path.join(src_root, 'modules', 'backend', 'docker-compose.yaml')
    if not os.path.isfile(target_compose):
        return {"success": False,
                "error": (f"target backend docker-compose.yaml not found at "
                          f"{target_compose} — cannot determine backend deploy mode. "
                          f"Refusing to ship a package that may be missing the backend "
                          f"image. Re-prepare from a complete release tree.")}
    if not backend_full_mode(target_compose):
        log("  Backend is legacy source-mounted mode — no backend image bake "
            "needed (restart path)", "info")
        return {"success": True}

    image = f"intact-backend:{be_tag}"
    dockerfile = os.path.join(src_root, 'modules', 'backend', 'Dockerfile')
    # CI pre-tags this exact image as `intact-backend:ci-packager` before this
    # runs -- same Dockerfile, same checkout, same commit, since this whole
    # packaging process is invoked FROM inside that image. Rebuilding it here
    # would be an identical build of the identical inputs; `docker image
    # inspect` catches that and skips straight to save.
    # Provenance, so "already present" can be more than a hope. CI's pre-tagged
    # image predates this label and has none -- absent stays "reuse", exactly as
    # before. A label that DISAGREES is the local case: a dev box accumulates
    # intact-backend:<tag> images across builds, and the reuse below happily
    # shipped one baked from an older commit. That image carries /app/host-engine,
    # which ensure_host_engine() writes over lib/ and scripts/ at every backend
    # start -- so a stale bake does not merely ship old code, it silently REVERTS
    # the engine fixes on the box hours after the upgrade reported success.
    # Taken as an ARGUMENT, not from the manifest: manifest_extra -- which is
    # where source_commit ends up -- is merged into the manifest at the very
    # end of prepare_upgrade_package, long after this runs. Reading it here got
    # an empty string and silently stamped no label at all, which is the one
    # outcome that looks exactly like success.
    _commit = source_commit or ""
    inspect = run_command(f"docker image inspect {image}",
                          timeout=30, logger=None, run_id=run_id)
    _stale = False
    if inspect.get("success") and _commit:
        _lbl = run_command(
            f"docker image inspect -f "
            f"'{{{{index .Config.Labels \"org.intact.commit\"}}}}' {image}",
            timeout=30, logger=None, run_id=run_id)
        _was = (_lbl.get("output") or "").strip()
        if _was and _was not in ("<no value>", "null") and _was != _commit:
            log(f"  Backend image {image} was baked from {_was[:12]}, this "
                f"release is {_commit[:12]} — rebaking", "warning")
            run_command(f"docker rmi -f {image}", timeout=120,
                        logger=None, run_id=run_id)
            _stale = True
    if inspect.get("success") and not _stale:
        log(f"  Backend image {image} already present — reusing (built earlier "
            f"in this run from the same commit)", "info")
    else:
        log(f"Baking backend runtime image {image} (Full-mode release)...", "info")
        if not os.path.isfile(dockerfile):
            return {"success": False,
                    "error": (f"Full-mode release but no backend Dockerfile at {dockerfile} "
                              f"— cannot bake the required backend image. Re-prepare from a "
                              f"complete release tree.")}

        # The Dockerfile does `COPY config.yaml /app/config.yaml`, twice, and
        # src_root no longer has one: excluding it from what ships is what
        # stops a package built on a live box from carrying that box's PAT and
        # module passwords. So the build context needs a config.yaml that is
        # NOT the operator's.
        #
        # Not source_root's copy: on a live appliance that is exactly the file
        # full of real secrets, and baking it into an image layer is the leak
        # the Dockerfile's own comment describes as recoverable with a plain
        # `docker run --entrypoint sh <image> -c 'cat /app/config.yaml'`.
        #
        # So sanitize it with the repo's OWN sanitizer -- the same one the
        # pre-commit hook runs to decide what "shipping defaults" means -- and
        # delete it again afterwards so the package still ships no config.yaml.
        # install_deps.py only reads it to pick module dependencies, and the
        # sanitized template has every module enabled, so the image gets the
        # same superset it does in CI.
        #
        # CI never hit this because it pre-tags intact-backend:ci-packager and
        # the `docker image inspect` above skips the build entirely. The bug
        # was therefore invisible until a build ran where that image was absent.
        _tmpl = os.path.join(src_root, 'config.yaml')
        _tmpl_created = False
        if not os.path.isfile(_tmpl):
            _live = os.path.join(source_root, 'config.yaml') if source_root else None
            _san = os.path.join(src_root, 'scripts', 'git-hooks', 'sanitize_config.py')
            if not (_live and os.path.isfile(_live)):
                return {"success": False,
                        "error": ("cannot bake the backend image: the Dockerfile copies "
                                  "config.yaml and neither the package tree nor source_root "
                                  "has one to sanitize into a template.")}
            if not os.path.isfile(_san):
                return {"success": False,
                        "error": (f"cannot bake the backend image: no sanitizer at {_san}, "
                                  f"and the operator's config.yaml must never be baked in "
                                  f"unsanitized.")}
            _r = run_command(f"python3 {_san} config.yaml {_live} {_tmpl}",
                             timeout=60, logger=None, run_id=run_id)
            if not _r.get("success") or not os.path.isfile(_tmpl):
                return {"success": False,
                        "error": (f"could not produce a sanitized config.yaml template for "
                                  f"the backend image build: {_r.get('error', '')[:200]}")}
            # The sanitizer only blanks credentials -- it leaves the build
            # host's own enabled/disabled choices alone. install_deps.py reads
            # this file to decide which module dependencies to install, so
            # without this the baked image would carry whatever subset the
            # build machine happened to have switched on, and the Dockerfile's
            # promise that "the template ships every module enabled: true, so
            # this installs a superset -- which also makes the image
            # reproducible instead of varying by build host" would quietly stop
            # being true. A release built on a box with elk off would ship a
            # backend image with no elk dependencies.
            #
            # A yaml round-trip loses the file's comments, which is normally
            # the reason not to do this (see sanitize_config.py's docstring) --
            # here it does not matter: this copy exists only as a docker build
            # context and is deleted a few lines below.
            try:
                import yaml as _yaml
                with open(_tmpl) as _fh:
                    _doc = _yaml.safe_load(_fh) or {}
                for _mod in (_doc.get('modules') or {}).values():
                    if isinstance(_mod, dict):
                        _mod['enabled'] = True
                with open(_tmpl, 'w') as _fh:
                    _yaml.safe_dump(_doc, _fh, default_flow_style=False,
                                    sort_keys=False)
            except Exception as _e:
                return {"success": False,
                        "error": (f"could not normalise the config.yaml template "
                                  f"for the backend image build: {_e}")}

            _tmpl_created = True
            log("  Sanitized config.yaml template staged for the image build "
                "(all modules enabled; removed again before packaging)", "info")

        try:
            _lblarg = f" --label org.intact.commit={_commit}" if _commit else ""
            build = run_command(
                f"docker build -f {dockerfile} -t {image}{_lblarg} {src_root}",
                timeout=1800, logger=None, run_id=run_id)
        finally:
            # Unconditionally, including on a failed build: a template left
            # behind would ship inside source/intact/ and quietly undo the
            # exclusion this whole dance exists to preserve.
            if _tmpl_created:
                try:
                    os.remove(_tmpl)
                except OSError:
                    pass
        if build.get("cancelled"):
            return {"success": False, "cancelled": True, "error": "cancelled"}
        if not build.get("success"):
            return {"success": False,
                    "error": (f"backend runtime image build failed — a Full-mode release "
                              f"CANNOT ship without its image: {build.get('error', '')[:200]}")}
    _out = f"{package_dir}/images/intact-backend-{be_tag}.tar"
    save = run_command(f"docker save -o {_out} {image}",
                       timeout=600, logger=None, run_id=run_id)
    if save.get("cancelled"):
        return {"success": False, "cancelled": True, "error": "cancelled"}
    if not save.get("success"):
        return {"success": False,
                "error": f"backend image save failed: {save.get('error', '')[:200]}"}
    manifest["contents"]["images"].append(f"intact-backend-{be_tag}.tar")
    log(f"  Backend image exported ({_format_size(os.path.getsize(_out))})", "success")
    return {"success": True}


def _config_at_ref_from_checkout(source_dir, ref, log):
    """`config.yaml` as of <ref>, read out of a local git checkout. None when
    that is not possible, so the caller falls through to the network.

    WHY THIS COMES FIRST. In CI the network fetch is not just redundant, it is
    strictly worse. The build job checks out the target commit
    (`ref: needs.resolve.outputs.commit`, fetch-depth 0) and mounts that
    workspace into this container -- so the release's own config.yaml is
    already on disk, and asking GitHub for it again re-derives a file we have
    while adding a way to fail. It failed exactly that way on
    intact-20260812: a 404 for a tag GitHub could not resolve at that moment,
    45 minutes into the run, which stamped pins_source=local-fallback and made
    the index job refuse a release whose pins were, in fact, correct.

    `git show <ref>:config.yaml` rather than reading the working tree, because
    those are different claims. The worktree can have been edited since
    checkout; `git show` is the file AS OF that commit, which is precisely what
    "the target release's own config.yaml" means. That distinction is not
    theoretical here -- scripts/dev/build_local_release_assets.sh stages a copy
    of a possibly-dirty working tree and passes --commit for it.

    Not a "fallback": when this succeeds the pins are target-release by
    definition, and the caller labels them so. pins_source=local-fallback stays
    reserved for the case it was written for -- an appliance packaging a
    release it is not itself running, where the local file really is a
    different release's.
    """
    # Imported here, not at module scope: this file already defers heavier
    # imports to their use sites (see _compress_with_progress), and this path
    # is skipped entirely outside a git checkout.
    import subprocess
    import yaml

    if not source_dir or not ref:
        return None
    git_dir = os.path.join(source_dir, '.git')
    if not os.path.exists(git_dir):
        return None
    try:
        out = subprocess.run(
            ['git', '-C', source_dir, 'show', f'{ref}:config.yaml'],
            capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0 or not (out.stdout or '').strip():
        return None
    try:
        cfg = yaml.safe_load(out.stdout)
    except yaml.YAMLError:
        return None
    if not isinstance(cfg, dict) or not cfg.get('versions'):
        return None
    log(f"Read the target release's config.yaml from the checkout at "
        f"{ref[:12]} (no network needed).", "info")
    return cfg


def prepare_upgrade_package(modules: Dict, run_id: str, logger: Callable = None,
                            compress: bool = True,
                            work_dir: Optional[str] = None,
                            manifest_extra: Optional[Dict] = None,
                            manifest_sidecar_name: Optional[str] = None,
                            source_dir: Optional[str] = None,
                            source_commit: Optional[str] = None,
                            packages_dir: Optional[str] = None) -> Dict:
    """Download and package upgrade components.

    Args:
        modules: Dict of module versions, e.g. {"elk": "9.3.1", "velociraptor": "0.75.6"}
        run_id: Free-form label for the run, threaded through to run_command's
                  log lines. No cancellation semantics here (see
                  _compress_with_progress) -- the backend this was moved out of
                  used it to key a Stop button's cancel event; the CI packager
                  has no such button, and build_release_package.py passes
                  ci_release_<tag>.
        logger: Logging function
        compress: When True (default and the only mode the CI packager uses),
                  compress the built directory to a tar.gz via the atomic-swap
                  pattern (write to `<output>.new`, gzip -t it, os.replace()
                  over the previous good archive), then clean up the work dir.
                  compress=False is unused today; it is kept because a future
                  caller building several module packages in one process may
                  want the built directory without the tar.gz round-trip.
        work_dir: Where to build the package contents. Defaults to
                  /tmp/<package_name>/. CI passes a fixed --work-dir per
                  scripts/ci/build_release_package.py's own docstring: every
                  module asset must extract to the SAME top-level directory
                  name for the per-module merge to work.
        source_dir: Package the Intact.AI source from THIS directory instead of
                  downloading it from GitHub. For CI, where the checkout is
                  already on disk at the pinned commit — see the long note at
                  the `intact` branch below for why that is a correctness fix
                  and not just a saved download. A box leaves this None.
        source_commit: The commit `source_dir` sits at, recorded in the
                  manifest as the source's origin. Only meaningful with
                  source_dir.
        packages_dir: Where the finished .tar.gz lands. Defaults to
                  /data/upgrade_packages — the persistent location an operator
                  later downloads it from, which is why the atomic swap keeps
                  the previous archive intact. CI points this straight at its
                  output mount instead, so the asset is written ONCE rather
                  than written there and copied out: at ~2.5 GB for elk, the
                  second copy is not free.

    Returns:
        Dict with success status. Shape depends on `compress`:
        - compress=True:  {success, package_path, package_name, package_size, manifest}
        - compress=False: {success, package_dir, manifest}
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    package_name = f"intact-upgrade-{timestamp}"
    package_dir = work_dir if work_dir else f"/tmp/{package_name}"

    # Compression-only state — skipped when compress=False (online flow
    # doesn't produce a tar.gz at all).
    _packages_dir_overridden = bool(packages_dir)
    packages_dir = packages_dir or "/data/upgrade_packages"
    output_file = f"{packages_dir}/intact-upgrade-latest.tar.gz"
    output_file_tmp = f"{output_file}.new"
    if compress:
        # Store final package in persistent location with an atomic-swap
        # workflow:
        #   1. write the new archive to `<output_file>.new`
        #   2. validate it (gzip -t inside _compress_with_progress)
        #   3. os.replace() the validated `.new` over `<output_file>`
        # The previous good package stays on disk untouched throughout
        # the whole prepare run — if anything fails, the operator's
        # last working archive is still there to fall back to.
        os.makedirs(packages_dir, exist_ok=True)
        if os.path.exists(output_file_tmp):
            try:
                os.remove(output_file_tmp)
            except OSError:
                pass

    log("=" * 50, "info")
    log("PREPARING UPGRADE PACKAGE", "info")
    log("=" * 50, "info")
    log("", "info")
    log("Selected modules:", "info")
    for module, version in modules.items():
        log(f"  {module.upper()}: {version}", "info")
    log("", "info")

    # Resolve the TARGET release's `versions:` block once. This is what
    # we'll feed to get_docker_images_for / get_transitive_versions_for
    # below — bundling the pins the release was cut with, not whatever
    # the build host has locally (which is divergent the moment the
    # operator has installed a different baseline). Falls back silently
    # to the operator's local config.yaml on any fetch failure so a
    # transient GitHub blip doesn't break the prepare flow.
    target_versions: Optional[Dict[str, str]] = None
    # The release tag, however this build was invoked.
    #
    # This read `modules.get('intact')` alone, which is the tag ONLY on a build
    # that carries the intact module. A per-module build narrows the set to one
    # entry (release_module_set: `selected = {only}`), so on `--module elk` the
    # dict is {'elk': '9.4.4'} and this was None -- the whole resolve below was
    # skipped by `if target_ref`, target_versions stayed None, and the manifest
    # was stamped pins_source=local-fallback. Every per-module asset except
    # intact, every run, deterministically; the index job then refused the
    # release.
    #
    # It was invisible from the logs. Nothing was fetched, so no fetch error was
    # printed, and the only surviving signal was the index job quoting a message
    # about GitHub being unreachable -- for a network call that never happened.
    # That is also why the legacy workflow was unaffected: it builds every module
    # in one pass (only=None), so `intact` is present and this resolved.
    target_ref = modules.get('intact') or (manifest_extra or {}).get('release_tag')
    if target_ref:
        try:
            cfg = _config_at_ref_from_checkout(source_dir, source_commit or target_ref, log)
            if cfg is None:
                from .resolver import fetch_upstream_config
                cfg = fetch_upstream_config(target_ref)
            v = (cfg.get('versions') or {})
            target_versions = {str(k): str(val).strip() for k, val in v.items()
                               if val is not None}
            log(f"Using `versions:` block from target release "
                f"{target_ref} ({len(target_versions)} entries) as the "
                f"source of truth for transitive sidecar pins.", "info")
        except Exception as e:
            # LOUD on purpose: a silently-stale fallback can bundle mismatched
            # sidecar pins. The banner + manifest marker (pins_source below)
            # make the degraded provenance visible in the run log AND in
            # package info, instead of one easily-missed line.
            log("=" * 50, "warning")
            log(f"WARNING: could not fetch target release config.yaml for "
                f"{target_ref}: {e}", "warning")
            log("Falling back to the OPERATOR'S LOCAL config.yaml for "
                "transitive sidecar pins. If local pins are out of date, this "
                "package may bundle MISMATCHED sidecar versions. Re-run the "
                "prepare when GitHub is reachable to get release-true pins.",
                "warning")
            log("=" * 50, "warning")
            target_versions = None

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
                "include_source": False,
                # Provenance of the transitive sidecar pins bundled below:
                # 'target-release' = fetched from the target ref's config.yaml
                # (correct); 'local-fallback' = GitHub fetch failed and the
                # operator's local pins were used — possibly stale/mismatched.
                "pins_source": ("target-release" if target_versions is not None
                                 else "local-fallback"),
            }
        }

        total_modules = len(modules)
        completed = 0

        # Process each module. ALWAYS process 'intact' FIRST so its source is
        # extracted into source/intact/ before any module that reads from it —
        # notably velociraptor, whose image bake refreshes its build files
        # (Dockerfile / bundled_artifacts) from source/intact/modules/velociraptor.
        # Without this, a modules dict ordered velociraptor-before-intact (e.g. a
        # prepare with selected_modules=[velociraptor]) bakes from stale on-disk
        # build files and ships a bundle-less image. Stable sort keeps the order
        # of the remaining modules.
        ordered_modules = _intact_first(modules)
        for module, version in ordered_modules:
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

                # WHERE THE SOURCE COMES FROM. On a box, nowhere but GitHub:
                # the appliance has no checkout and no git, so Prepare downloads
                # the ref the operator typed. In CI the source is already on
                # disk, checked out at the commit `resolve` pinned — and going
                # back to GitHub for it there is not merely redundant, it
                # reopens the hole the pin exists to close. Every other asset is
                # built from THE SHA; a codeload fetch is by REF, so a tag
                # re-cut mid-run would ship different source than the rest of
                # the release was built from, and `source_origin` would record
                # the ref rather than the commit, leaving nothing to catch it.
                #
                # Copying the checkout was rejected once before, for a good
                # reason: it was the RUNNING box's mounted source, so untracked
                # local edits leaked into the package. A CI checkout has no such
                # edits by construction — it is a fresh clone at one SHA — which
                # is why this is opt-in via source_dir rather than a default.
                if source_dir:
                    if not os.path.isdir(source_dir):
                        raise RuntimeError(
                            f"source_dir {source_dir!r} is not a directory — "
                            f"cannot package the Intact.AI source from it")
                    extracted_root = source_dir
                    resolved_ref = source_commit or version
                    tar_path = extract_dir = None
                    log(f"  Using the checkout at {source_dir} "
                        f"(commit {(source_commit or '?')[:12]}) — no download", "info")
                else:
                    import urllib.request
                    import urllib.error
                    import json as _json
                    import tarfile

                    repo = "TenrootOrg/IntactAI"

                    # If the operator typed a BRANCH name (`development`,
                    # `main`, a feature branch), resolve its current HEAD
                    # SHA via the GitHub branches API FIRST. Two reasons:
                    #
                    # 1. Codeload caches tarballs by ref. For branches —
                    #    which move — the cache can serve a stale or
                    #    truncated tarball captured before the latest
                    #    commit. We've hit this exact issue (memory note:
                    #    "push any commit to bust the per-SHA cache").
                    #    Downloading by resolved SHA bypasses the
                    #    branch-ref cache entirely.
                    #
                    # 2. The package becomes reproducible — the manifest
                    #    records the exact commit SHA shipped, so an
                    #    operator can correlate the apply log against
                    #    git history later.
                    #
                    # If `version` is already a release tag or commit SHA
                    # (the branches API 404s for those), skip the
                    # resolution and fall through to the existing
                    # codeload-by-ref path.
                    # `resolved_ref` is what we pass to codeload (SHA when
                    # we can resolve the branch — bypasses the codeload
                    # stale-cache bug for moving refs). The manifest +
                    # VERSION-file stamp still uses the operator's input
                    # verbatim (`development`, `intact-20260604`, etc.) —
                    # operators don't want to see SHAs in the UI; they want
                    # "the latest development" to read as exactly that.
                    resolved_ref = version
                    branch_api_url = (
                        f"https://api.github.com/repos/{repo}/branches/{version}"
                    )
                    try:
                        # Authenticate when a token is configured (env or
                        # config.yaml options.github_token) — this api.github.com
                        # call counts against the 60/hr anonymous per-IP cap.
                        _gh_headers = {"Accept": "application/vnd.github+json"}
                        try:
                            from .resolver import _github_token
                            _tok = _github_token()
                            if _tok:
                                _gh_headers["Authorization"] = f"token {_tok}"
                        except Exception:
                            pass
                        req = urllib.request.Request(
                            branch_api_url,
                            headers=_gh_headers,
                        )
                        with urllib.request.urlopen(req, timeout=30) as resp:
                            branch_data = _json.load(resp)
                        head_sha = (branch_data.get('commit') or {}).get('sha')
                        if head_sha:
                            resolved_ref = head_sha
                            log(
                                f"  Branch '{version}' resolved to HEAD "
                                f"{head_sha[:7]} for download (manifest "
                                f"keeps '{version}')",
                                "info",
                            )
                    except urllib.error.HTTPError as e:
                        if e.code == 404:
                            # Not a branch — could be a tag or SHA. Use
                            # the operator's input verbatim. The codeload
                            # call below will surface a clearer error if
                            # the ref doesn't exist at all.
                            pass
                        else:
                            log(
                                f"  Branch resolution returned HTTP {e.code} "
                                f"(continuing with raw ref): {e.reason}",
                                "warning",
                            )
                    except urllib.error.URLError as e:
                        # GitHub API unreachable — try codeload directly.
                        # If GitHub is fully down, codeload will fail with
                        # a clearer error below.
                        log(
                            f"  Branch resolution skipped (network: {e}). "
                            "Will try codeload with the ref as-is.",
                            "warning",
                        )

                    tar_url = (
                        f"https://codeload.github.com/{repo}/tar.gz/{resolved_ref}"
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
                            f"GitHub ref '{resolved_ref}' not found at {repo} "
                            f"(HTTP {e.code}). Make sure the release tag exists "
                            f"at https://github.com/{repo}/releases — or if you "
                            f"meant a branch, check it isn't deleted."
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
                        # Per-box state and key material. The note below has always
                        # claimed this list defends against a source_dir wired to a
                        # live install; until 2026-08-12 it did not actually name any
                        # of it, and scripts/dev/build_local_release_assets.sh stages
                        # exactly that (an rsync of the working tree). A locally built
                        # package therefore carried the build box's rendered
                        # timesketch_legacy.conf -- a real SECRET_KEY and a real
                        # postgres password -- inside source/intact/. Only .gitkeep is
                        # tracked under any of these, so nothing real is lost.
                        'secrets', 'certificates', 'ssl', 'client_installers',
                        '*.pem', '*.key', '*.crt', '*.p12', '*.pfx',
                        # Rendered from the tracked .template at install time, unique
                        # per box. The templates stay.
                        'timesketch.conf', 'timesketch_legacy.conf',
                        # Key material and per-box secrets. Today `source_dir`
                        # is only ever a pristine CI checkout or a codeload
                        # tarball, so none of this exists to copy -- see the
                        # note at the top of this function about why packaging
                        # a RUNNING box's tree was rejected. This list is
                        # defence in depth for the day someone wires
                        # source_dir to a live install anyway: certs and
                        # secrets are generated per-install (nginx cert, IRIS
                        # root CA, Velociraptor CA, module passwords), so
                        # shipping them inside a release would hand every
                        # customer the same private keys.
                        #
                        # Both directory names AND extensions: a Portainer
                        # admin password is an extensionless file, so
                        # extension globs alone would miss it. The only
                        # tracked content in these dirs is .gitkeep, and the
                        # apply side copies source/intact/ OVER an existing
                        # install -- an absent empty dir means "leave the live
                        # one alone", which is exactly right.
                        'ssl', 'certificates', 'secrets',
                        '*.key', '*.pem', '*.crt', '*.pfx', '*.p12',
                        # config.yaml is TRACKED (the pre-commit hook sanitizes
                        # the STAGED copy back to shipping defaults, but never
                        # touches the working file) and qa-config.yaml the same
                        # way -- so whatever machine runs this packager may have
                        # either one sitting on disk holding real operator
                        # credentials (GitHub PAT, module passwords) or QA
                        # target creds. `platform_config_path()` in
                        # build_release_package.py deliberately prefers that
                        # live file over the tracked one for reading version
                        # pins; that preference must never extend to what gets
                        # SHIPPED. A release does not need a pre-filled
                        # config.yaml at all -- a fresh install seeds its own
                        # via lib/config.sh:check_config().
                        'config.yaml', 'qa-config.yaml',
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

                # Record the operator's input verbatim in the manifest.
                # `resolved_ref` (the SHA we actually downloaded) is
                # captured separately in source_origin so the package
                # is still traceable to a specific commit when needed,
                # but the user-facing version string stays simple.
                manifest["versions"]["intact"] = version
                manifest["contents"]["include_source"] = True
                manifest["contents"]["source_origin"] = (
                    f"checkout@{resolved_ref}" if source_dir
                    else f"github.com/{repo}@{resolved_ref}"
                )

                # Belt-and-suspenders: stamp the VERSION file inside the
                # packaged source tree with the operator's input. The
                # release-time GitHub Action keeps VERSION up-to-date
                # on `development` so on release tags this is usually
                # a no-op overwrite. But it also covers cases the
                # workflow can't (branches, commit SHAs, release tags
                # from before the Action existed). When the apply
                # step's `cp -a source/intact/* WORKDIR/` runs, this
                # VERSION lands at the install root where
                # get_current_versions reads it — operators see
                # "development" or "intact-20260604" in the Settings
                # page, matching what they typed in the modal.
                # There used to be a second stamp here, into
                # source/intact/config.yaml's versions.backend — removed along
                # with config.yaml from what ships (see the full-repo
                # copytree's ignore_patterns). backend_target_tag() on the
                # target reads config.yaml versions.backend before VERSION,
                # but that is the TARGET BOX's OWN config.yaml, stamped live
                # by _intact_stamp() during apply — not a value carried inside
                # the package. A shipped config.yaml would only ever have been
                # read by nothing (grep confirms no apply-side code path reads
                # source/intact/config.yaml), so this was already a no-op by
                # the time it started silently no-op'ing on a missing file.
                try:
                    intact_source_root = f"{package_dir}/source/intact"
                    if os.path.isdir(intact_source_root):
                        version_file = f"{intact_source_root}/VERSION"
                        with open(version_file, "w") as vf:
                            vf.write(version.strip() + "\n")
                        log(f"  Stamped source/intact/VERSION -> {version}", "info")
                except Exception as e:
                    log(f"  Could not stamp VERSION file: {e}", "warning")

                # Wave F: bake + bundle the backend runtime image (Full-mode
                # releases only) + the tusd sidecar image. A Full-mode package
                # without its image is a brick-kit — a build failure FAILS prepare.
                # MUST run before the teardown below: it reads config.yaml from
                # extracted_root, which the teardown deletes in the
                # download-from-GitHub branch (source_dir is None then).
                _bimg = _prepare_backend_images(package_dir, version, manifest,
                                                source_root=extracted_root,
                                                source_commit=source_commit,
                                                logger=log, run_id=run_id)
                if not _bimg.get("success"):
                    if _bimg.get("cancelled"):
                        return {"success": False, "error": "cancelled", "cancelled": True}
                    return {"success": False, "error": _bimg["error"]}

                # Tear down the temp tarball + extraction so they don't end up
                # inside the final .tar.gz output. Nothing to tear down when the
                # source came from a checkout we do not own — deleting THAT
                # would take the caller's working tree with it. Deliberately
                # AFTER _prepare_backend_images above, which still needs
                # extracted_root to read config.yaml's nginx/backend_tusd pins.
                if tar_path or extract_dir:
                    try:
                        os.remove(tar_path)
                        shutil.rmtree(extract_dir)
                    except Exception:
                        pass

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

                # See resolve_velociraptor_release_tag in velociraptor.py
                # for why we can't just compute v{major}.{minor} here —
                # Velocidex's tagging changed at v0.76.6 (each patch has
                # its own release now).
                from .velociraptor_release import resolve_velociraptor_release_tag
                release_tag = resolve_velociraptor_release_tag(clean_version, logger=log)
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
                # modules/velociraptor/Dockerfile). Derive from WORKDIR (not a
                # literal /app/workdir) so the host-path translation below
                # (velo_dir.replace(WORKDIR, HOST_PATH)) works when WORKDIR is
                # overridden via INTACT_PATH — e.g. the CI packager, where the
                # repo is the mounted checkout, not the image's /app/workdir.
                # Identical to the old literal on a normal box (WORKDIR=/app/workdir).
                velo_dir = os.path.join(WORKDIR, "modules", "velociraptor")

                # Refresh the build files (Dockerfile / entrypoint.sh /
                # bundled_artifacts) from the TARGET release's source before
                # baking, so the image is built from the current Dockerfile +
                # full artifact bundle — not whatever stale copy is on this box.
                # The 'intact' module (processed earlier) extracted the release
                # into source/intact/. Without this, a box with old
                # modules/velociraptor re-bakes the old bundle-less image and the
                # server is missing ~400 artifacts (e.g. Windows.Hayabusa.Rules).
                from .velociraptor_release import refresh_velociraptor_build_files
                refresh_velociraptor_build_files(
                    os.path.join(package_dir, 'source', 'intact', 'modules', 'velociraptor'),
                    velo_dir, logger=log)

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
                            f"curl -L -f --retry 5 --retry-delay 5 "
                            f"--retry-max-time 600 --connect-timeout 30 "
                            f"-o {pkg_path} {url}",
                            timeout=1800, logger=None, run_id=run_id,
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
                        run_command(f"chmod 755 {staged_dest}", logger=None)
                    if fname == required_binary:
                        required_ok = True

                if not required_ok:
                    log("  Required linux server binary unavailable — skipping image bake.", "error")
                    log("  Target machines will fail offline upgrade until the package is re-prepared.", "warning")
                    continue
                if missing_optional:
                    log(f"  Note: placeholder(s) used for {len(missing_optional)} client binary(ies): {', '.join(missing_optional)}",
                        "warning")

                # linux-amd64-musl: NOT consumed by the Dockerfile (so it
                # has no staging_map entry), but the apply-side velociraptor
                # offline upgrade copies it into modules/nginx/html/downloads/
                # so the Dashboard's "Download Linux (musl)" button stays
                # lit on the new pin. Best-effort: an older patch with no
                # musl asset upstream just means that button greys out on
                # target — doesn't fail prepare.
                musl_fname = f"velociraptor-v{clean_version}-linux-amd64-musl"
                musl_pkg_path = f"{package_dir}/binaries/{musl_fname}"
                musl_local = os.path.join(local_downloads, musl_fname)
                musl_ok = False
                if os.path.exists(musl_local) and os.path.getsize(musl_local) > 0:
                    log(f"  Using local: {musl_fname} "
                        f"({_format_size(os.path.getsize(musl_local))})", "info")
                    cp = run_command(
                        f"cp {musl_local} {musl_pkg_path}",
                        logger=None, run_id=run_id,
                    )
                    if cp.get("cancelled"):
                        return {"success": False, "error": "cancelled", "cancelled": True}
                    musl_ok = (
                        cp['success']
                        and os.path.exists(musl_pkg_path)
                        and os.path.getsize(musl_pkg_path) > 0
                    )
                else:
                    musl_url = f"{base_url}/{musl_fname}"
                    log(f"  Downloading: {musl_fname}", "info")
                    dl = run_command(
                        f"curl -L -f --retry 5 --retry-delay 5 "
                        f"--retry-max-time 600 --connect-timeout 30 "
                        f"-o {musl_pkg_path} {musl_url}",
                        timeout=1800, logger=None, run_id=run_id,
                    )
                    if dl.get("cancelled"):
                        return {"success": False, "error": "cancelled", "cancelled": True}
                    musl_ok = (
                        dl['success']
                        and os.path.exists(musl_pkg_path)
                        and os.path.getsize(musl_pkg_path) > 0
                    )
                if musl_ok:
                    os.chmod(musl_pkg_path, 0o755)
                    log(f"  Done ({_format_size(os.path.getsize(musl_pkg_path))})",
                        "success")
                    manifest["contents"]["binaries"].append(musl_fname)
                else:
                    if os.path.exists(musl_pkg_path):
                        os.remove(musl_pkg_path)
                    log(f"  {musl_fname} unavailable — Linux (musl) download "
                        f"button will grey out on target after apply", "warning")

                # velociraptor-collector — small (~80 KB) standalone
                # collector binary that velociraptor's server-side
                # client_repack uses as the base for Hunt-collector
                # generation. Without it bundled, air-gap targets fail
                # collector generation with "lookup github.com on
                # 127.0.0.11:53: server misbehaving" (2026-06-16
                # incident). Apply side stages it from
                # binaries/velociraptor-collector into /data/tools/
                # via _ensure_velociraptor_collector_tool.
                collector_fname = "velociraptor-collector"
                collector_pkg_path = f"{package_dir}/binaries/{collector_fname}"
                collector_url = f"{base_url}/{collector_fname}"
                log(f"  Downloading: {collector_fname} (for Hunt-collector generation)", "info")
                dl = run_command(
                    f"curl -L -f --retry 5 --retry-delay 5 "
                    f"--retry-max-time 300 --connect-timeout 30 "
                    f"-o {collector_pkg_path} {collector_url}",
                    timeout=600, logger=None, run_id=run_id,
                )
                if dl.get("cancelled"):
                    return {"success": False, "error": "cancelled", "cancelled": True}
                collector_ok = (
                    dl['success']
                    and os.path.exists(collector_pkg_path)
                    and os.path.getsize(collector_pkg_path) > 50000
                )
                if collector_ok:
                    os.chmod(collector_pkg_path, 0o755)
                    log(f"  Done ({_format_size(os.path.getsize(collector_pkg_path))})",
                        "success")
                    manifest["contents"]["binaries"].append(collector_fname)
                else:
                    if os.path.exists(collector_pkg_path):
                        os.remove(collector_pkg_path)
                    log(f"  {collector_fname} unavailable from upstream — "
                        f"apply will fall back to fetching at runtime (requires "
                        f"internet on apply host) or Hunt-collector generation "
                        f"will fail until file manually placed.", "warning")

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

                # Probe `docker compose` first. The user's prepare run
                # surfaced `unknown shorthand flag: 'f' in -f / See
                # 'docker --help'.` — the error came from `docker`
                # itself (not `docker compose`) because the compose
                # plugin isn't installed in the backend container.
                # Without the plugin, `docker` parses `compose` as a
                # positional and `-f` as a global flag it doesn't
                # recognize. Skip the bake cleanly instead of spewing
                # that misleading error; the apply step rebuilds the
                # image locally from the staged binaries anyway.
                compose_probe = run_command(
                    "docker compose version",
                    timeout=10, logger=None, run_id=run_id,
                )
                if not compose_probe.get("success"):
                    log("  `docker compose` plugin not available in this container — "
                        "skipping image bake.", "info")
                    log("  Target will rebuild locally from the staged binaries (still offline-safe).", "info")
                    continue

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

                # Bundle Velociraptor artifact-source files so the apply
                # side can re-import them post-upgrade even on an
                # air-gapped target. The post-upgrade re-import in
                # services/upgrade/velociraptor.py uses
                # initialize_velociraptor_artifacts() — that function
                # reads two host paths:
                #   /app/data/tools/Velociraptor-Artifacts-main.zip
                #   /app/data/custom_artifacts/
                # Both are bind-mounted on /app/data so they survive
                # backend restarts on the SAME machine; but when the
                # upgrade package is transported to a fresh target,
                # those paths may be empty there. Snapshotting them
                # into the package makes the artifact restoration
                # fully offline-safe.
                log("Bundling Velociraptor artifact sources...", "info")
                velo_artifacts_dir = os.path.join(package_dir, 'artifacts', 'velociraptor')
                os.makedirs(velo_artifacts_dir, exist_ok=True)

                src_zip = '/app/data/tools/Velociraptor-Artifacts-main.zip'
                dst_zip = os.path.join(velo_artifacts_dir, 'Velociraptor-Artifacts-main.zip')
                if os.path.isfile(src_zip):
                    try:
                        shutil.copy2(src_zip, dst_zip)
                        sz_mb = os.path.getsize(dst_zip) / (1024 * 1024)
                        log(f"  Bundled TenRoot artifacts zip from local cache ({sz_mb:.1f} MB)", "success")
                        manifest["contents"].setdefault("velociraptor_artifacts", {})["zip"] = True
                    except Exception as e:
                        log(f"  Could not bundle TenRoot zip: {e}", "warning")
                else:
                    # Fetch-from-upstream fallback: when the operator added
                    # velociraptor via Online Upgrade (not at initial
                    # install), the install.sh tools_download step that
                    # seeds this zip never ran. Without this fallback the
                    # apply log shows "TenRoot artifacts zip absent" and
                    # the custom triage/IR artifacts (Windows.Triage.*,
                    # etc.) never get imported on the target.
                    log(f"  TenRoot artifacts zip absent at {src_zip} — fetching from upstream...", "info")
                    tenroot_url = "https://github.com/TenRootOrg/Velociraptor-Artifacts/archive/refs/heads/main.zip"
                    dl = run_command(
                        f"curl -fL --retry 3 --retry-max-time 600 --connect-timeout 30 "
                        f"--max-time 900 -o {dst_zip} {tenroot_url}",
                        timeout=950, logger=None, run_id=run_id,
                    )
                    if dl.get("cancelled"):
                        return {"success": False, "error": "cancelled", "cancelled": True}
                    if dl.get("success") and os.path.isfile(dst_zip) and os.path.getsize(dst_zip) > 1024:
                        sz_mb = os.path.getsize(dst_zip) / (1024 * 1024)
                        log(f"  Fetched TenRoot artifacts zip from upstream ({sz_mb:.1f} MB)", "success")
                        manifest["contents"].setdefault("velociraptor_artifacts", {})["zip"] = True
                        # Seed the local cache so subsequent prepares hit the fast path.
                        try:
                            os.makedirs(os.path.dirname(src_zip), exist_ok=True)
                            shutil.copy2(dst_zip, src_zip)
                        except Exception:
                            pass
                    else:
                        err = (dl.get("error") or "")[:120]
                        log(f"  Upstream fetch failed ({err}) — apply will skip TenRoot pack", "warning")
                        if os.path.isfile(dst_zip):
                            try:
                                os.remove(dst_zip)
                            except Exception:
                                pass

                # Legacy Velociraptor binaries (v0.7.x — for Win 7 /
                # Server 2008 R2 hosts where the modern Go-1.22 build
                # crashes with 0xc0000005). lib/docker.sh:
                # download_legacy_velociraptor_binaries seeds these at
                # install time when velociraptor is enabled — but on a
                # fresh backend+cve-only install the legacy zip never
                # ran, so when the operator adds velociraptor via
                # Online Upgrade the Downloads page shows greyed-out
                # "Download Legacy EXE / Linux" buttons.
                #
                # Bundle them here so the apply side can drop them into
                # modules/nginx/html/downloads/ on the target. Same
                # local-first-then-upstream pattern as the modern
                # binaries above. Pin lives in config.yaml's
                # versions.velociraptor_legacy (default '0.7.1').
                legacy_pin = None
                try:
                    cfg_path = os.path.join(WORKDIR, 'config.yaml')
                    if os.path.isfile(cfg_path):
                        import yaml as _yaml
                        with open(cfg_path) as _f:
                            _cfg = _yaml.safe_load(_f) or {}
                        legacy_pin = (((_cfg.get('versions') or {})
                                        .get('velociraptor_legacy')) or None)
                        if legacy_pin:
                            legacy_pin = str(legacy_pin).strip().lstrip('v')
                except Exception as _ce:
                    log(f"  Could not read versions.velociraptor_legacy: {_ce}", "warning")

                if legacy_pin:
                    legacy_filenames = [
                        f"velociraptor-v{legacy_pin}-windows-amd64.exe",
                        f"velociraptor-v{legacy_pin}-linux-amd64-musl",
                    ]
                    legacy_pkg_dir = os.path.join(package_dir, 'binaries', 'legacy')
                    os.makedirs(legacy_pkg_dir, exist_ok=True)
                    legacy_url_base = (f"https://github.com/Velocidex/velociraptor/"
                                       f"releases/download/v{legacy_pin}")
                    legacy_local_dir = os.path.join(WORKDIR, 'modules', 'nginx',
                                                    'html', 'downloads')
                    legacy_bundled = []
                    log(f"Bundling Velociraptor LEGACY v{legacy_pin} binaries...", "info")
                    for fname in legacy_filenames:
                        dst = os.path.join(legacy_pkg_dir, fname)
                        local_src = os.path.join(legacy_local_dir, fname)
                        if os.path.isfile(local_src) and os.path.getsize(local_src) > 1024 * 1024:
                            cp = run_command(f"cp {local_src} {dst}",
                                             logger=None, run_id=run_id)
                            if cp.get("cancelled"):
                                return {"success": False, "error": "cancelled", "cancelled": True}
                            if cp.get("success") and os.path.isfile(dst):
                                sz = os.path.getsize(dst) / (1024 * 1024)
                                log(f"  {fname}: bundled from local cache ({sz:.1f} MB)", "success")
                                legacy_bundled.append(fname)
                                continue
                        log(f"  {fname}: fetching from upstream...", "info")
                        dl = run_command(
                            f"curl -fL --retry 3 --retry-max-time 600 "
                            f"--connect-timeout 30 --max-time 900 "
                            f"-o {dst} {legacy_url_base}/{fname}",
                            timeout=950, logger=None, run_id=run_id,
                        )
                        if dl.get("cancelled"):
                            return {"success": False, "error": "cancelled", "cancelled": True}
                        if (dl.get("success") and os.path.isfile(dst)
                                and os.path.getsize(dst) > 1024 * 1024):
                            sz = os.path.getsize(dst) / (1024 * 1024)
                            log(f"  {fname}: fetched from upstream ({sz:.1f} MB)", "success")
                            legacy_bundled.append(fname)
                            # Seed local cache so the prepare host's
                            # legacy download buttons start working too.
                            try:
                                os.makedirs(legacy_local_dir, exist_ok=True)
                                shutil.copy2(dst, os.path.join(legacy_local_dir, fname))
                            except Exception:
                                pass
                        else:
                            err = (dl.get("error") or "")[:120]
                            log(f"  {fname}: upstream fetch failed ({err}) — "
                                f"legacy {fname.split('-')[3] if '-' in fname else 'OS'} "
                                f"download will be unavailable on the target", "warning")
                            if os.path.isfile(dst):
                                try:
                                    os.remove(dst)
                                except Exception:
                                    pass
                    if legacy_bundled:
                        manifest["contents"].setdefault("velociraptor_legacy", {})
                        manifest["contents"]["velociraptor_legacy"]["version"] = legacy_pin
                        manifest["contents"]["velociraptor_legacy"]["binaries"] = legacy_bundled
                else:
                    log("Legacy Velociraptor: versions.velociraptor_legacy not set — skipping", "info")

                src_custom = '/app/data/custom_artifacts'
                if os.path.isdir(src_custom) and os.listdir(src_custom):
                    dst_custom = os.path.join(velo_artifacts_dir, 'custom_artifacts')
                    try:
                        os.makedirs(dst_custom, exist_ok=True)
                        cp = run_command(
                            f"cp -a {src_custom}/. {dst_custom}/",
                            logger=None, timeout=60, run_id=run_id,
                        )
                        if cp.get('success'):
                            n_yaml = sum(
                                1 for _, _, files in os.walk(dst_custom)
                                for f in files if f.endswith(('.yaml', '.yml'))
                            )
                            log(f"  Bundled {n_yaml} custom artifact YAMLs from {src_custom}/", "success")
                            manifest["contents"].setdefault("velociraptor_artifacts", {})["custom_dir"] = True
                            manifest["contents"]["velociraptor_artifacts"]["custom_count"] = n_yaml
                        else:
                            log(f"  custom_artifacts copy failed: {cp.get('error', '')[:120]}", "warning")
                    except Exception as e:
                        log(f"  Could not bundle custom_artifacts: {e}", "warning")
                else:
                    log(f"  No custom artifacts at {src_custom}/ — apply will skip", "info")

                # Snapshot the running Velociraptor's full non-built-in
                # artifact registry. This is the ROBUST air-gap layer:
                # the operator's running Velociraptor already has
                # everything they imported via Server.Import.ArtifactExchange
                # (Velocidex's exchange repo on github), Server.Import.
                # DetectRaptor (mgreen27's repo), and Server.Import.Extras
                # — plus the TenRoot zip artifacts and custom_artifacts/
                # entries. By exporting them ALL via SQL at prepare time
                # and bundling the YAMLs, the apply side on a fresh
                # air-gapped target can re-register every one of those
                # artifacts without ever reaching github. Same SQL the
                # pre-upgrade-export step uses, but run at prepare time
                # against the prepare-machine's Velociraptor.
                log("Snapshotting Velociraptor artifact registry...", "info")
                snapshot_dir = os.path.join(velo_artifacts_dir, 'registry_snapshot')
                os.makedirs(snapshot_dir, exist_ok=True)
                try:
                    # Velociraptor's `query` defaults to a JSON array output
                    # (one big `[ {...}, {...} ]` blob). The `raw` field is
                    # the original artifact YAML text. We parse the array
                    # and write each artifact's `raw` to its own .yaml
                    # for the apply side's per-file `import_custom_artifact`.
                    #
                    # IMPORTANT: NO `run_id=` here. The cancellation-aware
                    # branch of `run_command` uses Popen + PIPE without
                    # draining stdout during its 1-second poll loop. The
                    # subprocess writes ~2 MB to stdout (one big JSON
                    # array of 359+ artifacts) and blocks on a full
                    # 64 KB pipe buffer — `process.poll()` returns None
                    # forever, the helper hits its timeout, and we lose
                    # the snapshot. The legacy `subprocess.run(
                    # capture_output=True)` path handles the large
                    # output correctly; we accept that Stop can't kill
                    # this specific query (it returns in ~2 s anyway).
                    # Pre-check whether velociraptor is actually running here.
                    # `docker exec` into an absent container fails with "No such
                    # container", and run_command logs that at WARNING — which
                    # looks alarming on a build host (CI / backend-only deploy)
                    # that legitimately has no velo. `docker ps` succeeds with
                    # empty output when the container is absent, so probing this
                    # way emits no scary warning; we then reuse the graceful
                    # "not running" branch below.
                    _velo_ps = run_command(
                        "docker ps -q -f name=intact_velociraptor",
                        logger=None, timeout=15)
                    if not (_velo_ps.get('stdout') or '').strip():
                        snap = {"success": False,
                                "error": "No such container: intact_velociraptor"}
                    else:
                        snap = run_command(
                            "docker exec intact_velociraptor /velociraptor/velociraptor "
                            "--config /velociraptor/server.config.yaml query "
                            "'SELECT name, raw FROM artifact_definitions() "
                            "WHERE built_in = FALSE AND raw != \"\"'",
                            logger=None, timeout=180,
                        )
                    if snap.get('success'):
                        import json as _json
                        # Velociraptor's `query` doesn't emit a single
                        # JSON array — it emits ONE array per result
                        # batch, concatenated. For 359+ artifacts the
                        # output looks like
                        #     [ {row1}, {row2} ][ {row3}, {row4} ]...
                        # which `json.loads` rejects ("Extra data"
                        # after the first array). Use raw_decode in a
                        # streaming loop to consume every concatenated
                        # value robustly — handles `[` / `]` literals
                        # inside string fields without regex hacks.
                        raw_out = snap.get('stdout') or ''
                        decoder = _json.JSONDecoder()
                        rows = []
                        idx = 0
                        while idx < len(raw_out):
                            while idx < len(raw_out) and raw_out[idx].isspace():
                                idx += 1
                            if idx >= len(raw_out):
                                break
                            try:
                                obj, end = decoder.raw_decode(raw_out, idx)
                            except _json.JSONDecodeError:
                                break
                            if isinstance(obj, list):
                                rows.extend(obj)
                            elif isinstance(obj, dict):
                                rows.append(obj)
                            idx = end
                        snap_count = 0
                        for row in rows:
                            if not isinstance(row, dict):
                                continue
                            name = (row.get('name') or '').strip()
                            raw = row.get('raw') or ''
                            if not name or not raw:
                                continue
                            # Sanitize artifact name for filename
                            safe = name.replace('/', '_').replace('\\', '_')
                            try:
                                with open(os.path.join(snapshot_dir, f"{safe}.yaml"), 'w') as f:
                                    f.write(raw)
                                snap_count += 1
                            except Exception:
                                continue
                        if snap_count:
                            log(f"  Snapshotted {snap_count} live artifacts from running Velociraptor "
                                f"(includes ArtifactExchange + DetectRaptor + Extras + custom + ad-hoc)",
                                "success")
                            manifest["contents"]["velociraptor_artifacts"]["registry_snapshot_count"] = snap_count
                        else:
                            log("  Registry snapshot returned 0 artifacts — running Velociraptor "
                                "may have empty non-built-in registry", "warning")
                    else:
                        # Soft fail — the direct-download step below
                        # covers the standard sources (ArtifactExchange,
                        # DetectRaptor, Extras) without needing a running
                        # Velociraptor. Operator only loses bespoke
                        # artifacts they imported manually that aren't
                        # in those public sources.
                        #
                        # Special-case the "container absent" failure —
                        # that's the EXPECTED state when prepare runs
                        # on a build host that doesn't have velociraptor
                        # installed (clean VM, backend-only deployment).
                        # Logging it at WARNING made operators panic
                        # mid-run on otherwise-clean prepare flows.
                        # Other failure causes (real SQL errors, docker
                        # transients) still get WARNING.
                        snap_err = snap.get('error', '') or ''
                        if 'No such container' in snap_err:
                            log("  Velociraptor isn't running on this build host "
                                "— skipping the live artifact-registry snapshot. "
                                "This is NOT critical: the full curated artifact "
                                "set is baked into the velociraptor image (loaded "
                                "on boot via --definitions), and the direct "
                                "downloads below cover the standard sources "
                                "(ArtifactExchange, DetectRaptor, Sigma, Triage). "
                                "The snapshot would only add bespoke artifacts an "
                                "operator hand-imported on a LIVE server — none "
                                "exist on a build host.", "info")
                        else:
                            log(f"  Registry snapshot SQL failed (continuing — direct "
                                f"downloads below will cover the standard sources): "
                                f"{snap_err[:120]}", "warning")
                except Exception as e:
                    log(f"  Registry snapshot raised: {e}", "warning")

                # External artifact zips are no longer bundled here. The
                # curated artifact set (Artifact Exchange / DetectRaptor /
                # Sigma / Rapid7 / Triage / Registry+SQLite Hunter / TenRoot)
                # is now baked into the velociraptor image as plain YAMLs
                # (modules/velociraptor/bundled_artifacts/, loaded on boot via
                # --definitions — see modules/velociraptor/{Dockerfile,
                # entrypoint.sh}). It therefore ships INSIDE the velociraptor
                # image tar this package already carries, and the target loads
                # it in one pass at startup instead of importing each artifact
                # over the API (the old ~37-min step). Nothing to download or
                # bundle separately. Refresh that folder with
                # scripts/regenerate_artifact_bundle.py when upstream changes.

                # ── Bundle Velociraptor TOOLS for air-gap ──────────────
                # Some artifacts reference external tools that
                # velociraptor's client_repack fetches from the
                # internet at COLLECTOR-GENERATION time. On an air-gap
                # target that fetch fails — 2026-06-16 incident:
                # cve_management collector died with
                # `client_repack: Get ".../lolrmm.csv": lookup
                # github.com ... connection refused`. The artifacts
                # themselves were present (bundled zips); the TOOL the
                # artifact embeds was not. Bundle the DEFAULT tool tier
                # (enabled:true in data/tools_inventory.yaml — the only
                # tools the shipped default blueprints actually use:
                # lolrmm.csv, Autoruns, LastActivityView) into the package
                # so the apply side can place them in /data/tools/ +
                # register them serve_locally. Optional tools (Hayabusa,
                # YARA, EZ tools, etc.) are NOT used by any default
                # blueprint and are only bundled when an operator flips
                # options.download_tools. Reuses the same downloader the
                # install.sh / Maintenance→Refresh-Tools path uses.
                log("Bundling DEFAULT Velociraptor tools (lolrmm, Autoruns, "
                    "LastActivityView) for air-gap collector generation...", "info")
                try:
                    # Deliberate backend import #2 (see services.image_map
                    # above): tools_download_service needs grpc/pyvelociraptor,
                    # which only the packager container's baked /app has. Best-
                    # effort by the try/except below, same as before the move.
                    from services.tools_download_service import (
                        load_tools_config, download_tools_from_config,
                    )
                    tcfg = load_tools_config()
                    if tcfg:
                        pkg_tools_dir = os.path.join(package_dir, 'tools')
                        os.makedirs(pkg_tools_dir, exist_ok=True)
                        # Bundle ONLY the default tool tier (enabled:true) — the
                        # set the shipped default blueprints need. Optional tools
                        # (enabled:false, gated by options.download_tools) are
                        # never packaged; air-gap targets that want them flip the
                        # flag + run Maintenance with internet. include_optional
                        # is pinned False here regardless of the build host's flag.
                        tdl = download_tools_from_config(
                            pkg_tools_dir, tcfg, logger=log, run_id=run_id,
                            include_optional=False,
                        )
                        if tdl.get('cancelled'):
                            return {"success": False, "error": "cancelled", "cancelled": True}
                        n_tools = len(tdl.get('downloaded', [])) + len(tdl.get('already_exists', []))
                        n_failed = len(tdl.get('failed', []))
                        if n_tools:
                            manifest["contents"]["velociraptor_tools"] = n_tools
                            log(f"  ✓ Bundled {n_tools} Velociraptor tools "
                                f"into package ({n_failed} failed)",
                                "success")
                        else:
                            log(f"  No Velociraptor tools bundled "
                                f"({n_failed} failed) — air-gap collector "
                                f"generation for tool-backed artifacts "
                                f"(cve_management, etc.) will fail until "
                                f"tools are available.", "warning")
                    else:
                        log("  tools_inventory.yaml not loadable — skipping "
                            "tool bundling", "warning")
                except Exception as _te:
                    log(f"  Velociraptor tool bundling raised "
                        f"({type(_te).__name__}: {_te}); air-gap collector "
                        f"generation may fail for tool-backed artifacts",
                        "warning")

            elif module in PRIMARY_IMAGES or module in TRANSITIVE_IMAGES:
                # Resolve the full image list for this module + record the
                # transitive tags in the manifest so the apply side (which
                # never reads config.yaml — it gets the package from a
                # potentially-disconnected host) knows which `.env` values
                # to stamp before `docker compose up`. The `log` callable
                # is threaded into get_docker_images_for and
                # get_transitive_versions_for so each dep's resolution
                # chain (operator override / upstream scrape / fallback)
                # is recorded in the workflow log — added 2026-06-14 after
                # an operator hit a silent stale-default that bundled
                # the wrong opensearch version.
                if module in TRANSITIVE_IMAGES:
                    src_label = ("target release config.yaml"
                                 if target_versions is not None
                                 else "operator's local config.yaml")
                    log(f"  Resolving transitive deps for {module}@{version} "
                        f"(reading from {src_label}):",
                        "info")
                images_for_module = get_docker_images_for(
                    module, version, logger=log,
                    target_versions=target_versions,
                )
                tv_env = get_transitive_versions_for(
                    module, primary_version=version, logger=log,
                    target_versions=target_versions,
                )
                if tv_env:
                    manifest["contents"].setdefault(
                        "transitive_versions", {})[module] = tv_env
                    log(f"  Transitive pins bundled for {module}: " +
                        ', '.join(f'{k}={v}' for k, v in tv_env.items()),
                        "success")

                # Pull and save Docker images, several at a time — see
                # _pull_and_save_images. Cancel is honoured inside each docker
                # subprocess and re-checked once the pool drains.
                declared = len(images_for_module)
                saved_names, was_cancelled = _pull_and_save_images(
                    images_for_module, f"{package_dir}/images", log, run_id=run_id)
                if was_cancelled:
                    return {"success": False, "error": "cancelled", "cancelled": True}
                manifest["contents"]["images"].extend(saved_names)
                bundled_for_module = len(saved_names)

                # Bundling-completeness gate. Three outcomes:
                #
                # (a) bundled == declared → normal: every image landed,
                #     register the module's version + let apply run.
                # (b) 0 < bundled < declared → partial: at least one
                #     image bundled but not all. Surface the warning
                #     and register the version (operator opted in by
                #     selecting the module; let apply try its best
                #     with what we shipped).
                # (c) bundled == 0 → total failure for this module
                #     (typo'd version, registry 404, network glitch).
                #     Skip the manifest entry so the apply phase
                #     doesn't run for this module — no contradictory
                #     "succeeded:N" report and no .env bumped to a
                #     non-existent version. Operator fixes the typo
                #     and re-runs without touching the rest of the
                #     stack.
                if bundled_for_module == 0 and declared > 0:
                    log(
                        f"  MODULE_FAILED_PREPARE: {module} bundled 0/{declared} images — "
                        f"skipping {module} (apply phase will not run for this module). "
                        f"Likely a typo'd version or registry 404; verify the version exists upstream.",
                        "error",
                    )
                    # Do NOT add to manifest.versions; apply skips it.
                    continue
                if bundled_for_module < declared:
                    log(
                        f"  WARNING: {module} bundled {bundled_for_module}/{declared} images — "
                        "the target may fail to start a container at apply time.",
                        "warning",
                    )

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
                        # Mode-aware message — online apply has internet
                        # and can re-fetch on the fly, offline apply on
                        # an air-gap target genuinely needs the bundled
                        # migrations. Don't shout WARNING during online
                        # mode (it scared operators on otherwise-clean
                        # runs 2026-06-15); only WARN when the missing
                        # migrations actually matter (offline tar).
                        if compress:
                            log(
                                "  Timesketch migrations not bundled; the apply "
                                "on the air-gap target will need GitHub access "
                                "for migrations. Re-run prepare if the target "
                                "has no internet.",
                                "warning",
                            )
                        else:
                            log(
                                "  Timesketch migrations not bundled "
                                "(online mode — apply will fetch from GitHub "
                                "directly).",
                                "info",
                            )
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

                    # Timesketch-specific: bundle DFIQ data (scenarios/facets/
                    # questions YAMLs) so an air-gapped install/upgrade doesn't
                    # need to `git clone google/dfiq` at apply time -- mirrors
                    # the migrations bundling immediately above. Pinned via
                    # versions.dfiq (a commit SHA, not a branch) for the same
                    # reproducibility reason every other versions.* entry is
                    # pinned: an unpinned "main" would let bundled content
                    # silently drift between CI builds under an unchanged tag.
                    # Consumer: lib/modules/timesketch.sh's deploy_timesketch
                    # (moves the equivalent live-clone data into
                    # modules/timesketch/config/dfiq/); staged from the
                    # package by lib/package.sh before deploy_timesketch runs,
                    # so its own `[[ -f ... ]]` presence check short-circuits
                    # and the clone is never attempted.
                    log("Bundling Timesketch DFIQ data...", "info")
                    dfiq_versions = target_versions if target_versions is not None else _read_config_yaml_versions()
                    dfiq_ref = dfiq_versions.get('dfiq') or 'main'
                    dfiq_url = f"https://github.com/google/dfiq/archive/{dfiq_ref}.tar.gz"
                    dfiq_src_tarball = f"{package_dir}/_dfiq_src_{dfiq_ref}.tar.gz"
                    dfiq_dl = run_command(f"curl -fLsS -o {dfiq_src_tarball} {dfiq_url}", timeout=180, logger=None, run_id=run_id)
                    if dfiq_dl.get("cancelled"):
                        return {"success": False, "error": "cancelled", "cancelled": True}
                    if not dfiq_dl['success'] or not os.path.exists(dfiq_src_tarball) or os.path.getsize(dfiq_src_tarball) < 1024:
                        # Same mode-aware messaging as the migrations block:
                        # online apply can still fetch DFIQ live, only an
                        # offline/air-gapped apply actually needs the bundle.
                        if compress:
                            log(
                                "  DFIQ data not bundled; the apply on the "
                                "air-gap target will need GitHub access for "
                                "DFIQ. Re-run prepare if the target has no "
                                "internet.",
                                "warning",
                            )
                        else:
                            log(
                                "  DFIQ data not bundled "
                                "(online mode — apply will fetch from GitHub "
                                "directly).",
                                "info",
                            )
                    else:
                        dfiq_dir = f"{package_dir}/dfiq"
                        os.makedirs(dfiq_dir, exist_ok=True)
                        # --strip-components=3 drops `dfiq-<ref>/dfiq/data/` so
                        # extracted contents land as `scenarios/`, `facets/`,
                        # `questions/` directly under dfiq_dir -- the layout
                        # deploy_timesketch's own clone-handling already
                        # produces (mv "${_tmp}/repo/dfiq/data"/* ...).
                        dfiq_extract = run_command(
                            f"tar -xzf {dfiq_src_tarball} -C {dfiq_dir} --wildcards "
                            f"--strip-components=3 '*/dfiq/data/*'",
                            timeout=60, logger=None
                        )
                        try:
                            os.remove(dfiq_src_tarball)
                        except Exception:
                            pass
                        dfiq_yaml_count = sum(
                            1 for _r, _d, fs in os.walk(dfiq_dir) for f in fs if f.endswith('.yaml')
                        ) if os.path.isdir(dfiq_dir) else 0
                        if dfiq_extract['success'] and dfiq_yaml_count > 0:
                            dfiq_tar_path = f"{dfiq_dir}/dfiq-data.tar"
                            import tarfile as _dfiqtf
                            with _dfiqtf.open(dfiq_tar_path, 'w') as tar:
                                for entry in os.listdir(dfiq_dir):
                                    if entry == 'dfiq-data.tar':
                                        continue
                                    tar.add(os.path.join(dfiq_dir, entry), arcname=entry)
                            # Remove the loose extracted tree now that it's
                            # tarred -- only dfiq-data.tar should ship.
                            for entry in os.listdir(dfiq_dir):
                                if entry == 'dfiq-data.tar':
                                    continue
                                entry_path = os.path.join(dfiq_dir, entry)
                                if os.path.isdir(entry_path):
                                    shutil.rmtree(entry_path)
                                else:
                                    os.remove(entry_path)
                            log(f"  DFIQ data bundled ({dfiq_yaml_count} YAML files, ref {dfiq_ref})", "success")
                            manifest["contents"]["dfiq"] = {
                                "ref": dfiq_ref,
                                "yaml_files": dfiq_yaml_count,
                                "file": "dfiq/dfiq-data.tar",
                            }
                        else:
                            log(f"  Failed to extract DFIQ data from source tarball", "warning")

                # VolWeb-specific: bundle the three curated YARA rule
                # repos so apply (install or upgrade) can seed VolWeb's
                # yararulesets table without needing internet at apply
                # time. Mirrors how velociraptor artifacts are bundled
                # above. Sources match what
                # `lib/modules.sh:seed_yara_rulesets` and
                # `routes/maintenance_routes.py:_YARA_RULESETS` use, so
                # bundled vs online refresh produce equivalent corpora.
                #
                # The three repos download as ~10-25 MB zips each;
                # adds ~50 MB to the bundle. Worth the size — air-gap
                # targets need these to do useful memory forensics.
                if module == 'volweb':
                    log("Bundling VolWeb YARA rule sources...", "info")
                    yara_dir = os.path.join(package_dir, 'yara_rulesets')
                    os.makedirs(yara_dir, exist_ok=True)
                    yara_sources = [
                        (
                            "Neo23x0 signature-base",
                            "signature-base.zip",
                            "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip",
                            "Florian Roth's curated YARA rules (~749 active)",
                        ),
                        (
                            "Elastic protections",
                            "protections-artifacts.zip",
                            "https://github.com/elastic/protections-artifacts/archive/refs/heads/main.zip",
                            "Elastic security YARA detection rules (~695 active)",
                        ),
                        # YARA-Forge was dropped: it publishes rules ONLY
                        # as release assets (its repo has zero .yar files)
                        # AND ships them as one giant concatenated .yar
                        # that the whole-file bundle importer can't split
                        # or keep imports for — it seeded a single useless
                        # rule. The two curated repos above ship .yar
                        # files in-tree and import natively.
                    ]
                    yara_bundled = []
                    for name, fname, url, desc in yara_sources:
                        dst = os.path.join(yara_dir, fname)
                        try:
                            cp = run_command(
                                f"curl -fL --retry 3 --retry-delay 5 "
                                f"--max-time 600 --connect-timeout 30 "
                                f"-o {dst} {url}",
                                logger=None, timeout=900, run_id=run_id,
                            )
                            # GitHub serves master/main branch zips —
                            # one of them 404s depending on the repo's
                            # default branch name. Retry the other.
                            if not (cp.get('success') and os.path.isfile(dst) and os.path.getsize(dst) > 1024):
                                alt_url = url.replace('/master.zip', '/main.zip') if 'master.zip' in url else url.replace('/main.zip', '/master.zip')
                                if alt_url != url:
                                    log(f"  ✗ {name}: primary branch zip not found; trying {alt_url.rsplit('/', 1)[-1]}...", "info")
                                    cp = run_command(
                                        f"curl -fL --retry 3 --retry-delay 5 "
                                        f"--max-time 600 --connect-timeout 30 "
                                        f"-o {dst} {alt_url}",
                                        logger=None, timeout=900, run_id=run_id,
                                    )
                            if not (cp.get('success') and os.path.isfile(dst) and os.path.getsize(dst) > 1024):
                                log(f"  ✗ {name}: download failed; apply will skip this ruleset", "warning")
                                try: os.remove(dst)
                                except Exception: pass
                                continue
                            size_mb = os.path.getsize(dst) / (1024 * 1024)
                            log(f"  ✓ {name} → {fname} ({size_mb:.1f} MB)", "success")
                            yara_bundled.append({
                                "name": name,
                                "filename": fname,
                                "description": desc,
                                "source_url": url,
                            })
                        except Exception as e:
                            log(f"  ✗ {name}: {e}", "warning")
                    if yara_bundled:
                        manifest["contents"]["yara_rulesets"] = yara_bundled
                        log(f"  VolWeb YARA rule sources bundled "
                            f"({len(yara_bundled)}/{len(yara_sources)})",
                            "success")
                    else:
                        log("  WARNING: no YARA rule sources bundled — "
                            "VolWeb will start with an empty YARA corpus on "
                            "the air-gap target. Operator can run "
                            "Maintenance → Refresh YARA Rulesets later if "
                            "the target gets internet.", "warning")
            elif module == 'aws_sigma':
                # aws_sigma ships no docker image — the versioned artifact is the
                # SIGMA AWS CloudTrail rule pack (cloned from SigmaHQ into
                # /opt/sigma-rules). Bundle it as images/aws_sigma-<version>.tar so an
                # air-gapped target installs the detection rules on apply
                # (services/upgrade/aws.py:upgrade_aws_offline, and
                # lib/docker.sh:install_bundled_rule_packs on the install path).
                # Mirrors the cve_scan pattern (a no-image module that ships a
                # data artifact).
                #
                # Named aws_sigma-<v>.tar, not the historical cloudtrail-<v>.tar:
                # the module id was renamed and the old filename made the artifact
                # look like it belonged to a module that no longer exists. Both
                # readers accept either spelling, so a package built before the
                # rename still applies — see aws.py and install_bundled_rule_packs.
                # image_owner_prefixes() likewise still maps BOTH prefixes, or an
                # older package's pack becomes unattributable and is never pruned
                # or disk-budgeted.
                import tarfile as _cttf
                aws_rules = "/opt/sigma-rules/rules/cloud/aws"
                if os.path.isdir(aws_rules):
                    images_dir = f"{package_dir}/images"
                    os.makedirs(images_dir, exist_ok=True)
                    out_tar = f"{images_dir}/aws_sigma-{version}.tar"
                    with _cttf.open(out_tar, 'w') as tar:
                        tar.add(aws_rules, arcname='.')
                    n_rules = sum(1 for _r, _d, fs in os.walk(aws_rules)
                                  for f in fs if f.endswith(('.yml', '.yaml')))
                    size_mb = os.path.getsize(out_tar) / (1024 * 1024)
                    manifest["contents"].setdefault("rule_packs", []).append({
                        "module": "aws_sigma",
                        "file": f"images/aws_sigma-{version}.tar",
                        "rules": n_rules, "size_mb": round(size_mb, 2),
                    })
                    # Register aws_sigma as a versioned module so the apply
                    # orchestrator actually installs it. The per-module apply loop
                    # is version-gated (`version = manifest['versions'].get(module)`
                    # then `if not version: continue`), so a rule-pack that only
                    # lives under contents.rule_packs is silently skipped — the
                    # bundled tar never reaches upgrade_cloudtrail_offline. Pinning
                    # the version here routes aws_sigma through the same dispatch as
                    # every other module (offline_upgrade_functions['aws_sigma']).
                    manifest["versions"]["aws_sigma"] = version
                    log(f"  Bundled SIGMA AWS rule pack: {n_rules} rules "
                        f"({size_mb:.1f} MB)", "success")
                else:
                    log(f"  WARNING: no SIGMA AWS rules at {aws_rules} — aws_sigma was "
                        "selected but this build host has no rule pack to bundle. Run the "
                        "installer's download_sigma_rules first, otherwise the air-gap "
                        "target starts with no AWS detection rules.", "warning")

            else:
                # This build host's code doesn't have packaging logic for
                # '{module}' — normal when it's a module a NEWER release added
                # or renamed and this (older) code predates it. Not an error:
                # on a connected target the module reads its data live (e.g.
                # aws_sigma reads /opt/sigma-rules), and the versioned artifact
                # is (re)built by the target's own code in the release package.
                # Info, not warning, so it doesn't read as a failure.
                log(f"  Module '{module}' isn't packaged by this build host "
                    f"(newer/renamed module this code predates) — skipping its "
                    f"artifact here; it installs from the release package.", "info")

            completed += 1

        # Check if any modules were actually packaged
        has_content = (manifest["contents"]["images"] or
                      manifest["contents"]["binaries"] or
                      manifest["contents"].get("include_source", False) or
                      manifest["contents"].get("rule_packs"))
        if not has_content:
            raise Exception("No modules were packaged successfully. Check your internet connection and try again.")

        # Per-file sha256 integrity map. `gzip -t` at apply time only proves
        # the OUTER archive isn't corrupt — a truncated/corrupt image tar
        # INSIDE a gzip-valid archive used to surface mid-apply, after the
        # module was already down. verify_upgrade_package re-hashes each file
        # against this map before any module runs (and skips the check for
        # older packages whose manifest has no sha256 block — back-compat).
        log("", "info")
        log("=== Hashing package contents (sha256) ===", "info")
        import hashlib as _hashlib
        _sha_map = {}
        for _root, _dirs, _files in os.walk(package_dir):
            for _fn in _files:
                _abs = os.path.join(_root, _fn)
                _rel = os.path.relpath(_abs, package_dir)
                if _rel == 'manifest.json':
                    continue  # the manifest can't contain its own hash
                if _rel.startswith('manifests/'):
                    # Per-module manifest sidecars are copies of this same
                    # manifest, so they cannot contain their own hash either.
                    # Both are covered by the ASSET-level sha256 published
                    # alongside the tarball and verified before extraction.
                    continue
                _h = _hashlib.sha256()
                with open(_abs, 'rb') as _fh:
                    for _chunk in iter(lambda: _fh.read(4 * 1024 * 1024), b''):
                        _h.update(_chunk)
                _sha_map[_rel] = _h.hexdigest()
        manifest["contents"]["sha256"] = _sha_map
        log(f"  Hashed {len(_sha_map)} file(s)", "success")

        # Per-image byte sizes, keyed by the same filenames already recorded
        # in contents.images. Without this, required_free_gb_for_manifest()
        # (the apply-side disk preflight) falls back to using the COMPRESSED
        # package size as a stand-in for the UNCOMPRESSED image bytes it
        # actually needs to budget for. That systematically UNDER-estimates:
        # the images are what dominate the package, and they expand on the
        # way out. Measured 2026-07-22 on the lean package — images total
        # 5.02 GiB uncompressed against a 2.32 GiB tarball, so the fallback
        # was reasoning about less than half the real footprint and only
        # avoided a bad call because APPLY_MIN_FREE_GB floored it at 10.
        # Recording the real sizes makes the estimate honest rather than
        # accidentally-in-range.
        images_dir = os.path.join(package_dir, 'images')
        image_sizes = {}
        for fn in manifest["contents"].get("images") or []:
            fpath = os.path.join(images_dir, fn)
            if os.path.exists(fpath):
                image_sizes[fn] = os.path.getsize(fpath)
        manifest["contents"]["image_sizes"] = image_sizes

        # Caller-supplied provenance, merged in BEFORE the write so it lands
        # inside the tarball rather than only in the sidecar. The sidecar can be
        # regenerated or replaced independently of the package it describes; a
        # field that only lives there cannot be trusted by the apply side, which
        # reads the manifest out of the archive it is about to install.
        if manifest_extra:
            manifest.setdefault("contents", {}).update(manifest_extra)

        # Write manifest
        log("", "info")
        log("=== Creating Manifest ===", "info")
        with open(f"{package_dir}/manifest.json", 'w') as f:
            json.dump(manifest, f, indent=2)
        log("  Created manifest.json", "success")

        # PER-MODULE ASSET SIDECAR — written LAST, so it carries the COMPLETE
        # manifest including the sha256 map.
        #
        # N module assets all extract into one directory (they share a
        # top-level dir name), so their root manifest.json files overwrite each
        # other -- last extractor wins, silently. Each asset therefore also
        # carries manifests/<module>.json, and the apply-side assembler merges
        # those into the root manifest. Writing this BEFORE the hash walk was
        # the obvious-looking mistake: the sidecar then held a manifest with no
        # sha map at all, so the assembled package had nothing to verify and
        # said so only by silently checking zero files.
        if manifest_sidecar_name:
            _side_abs = os.path.join(package_dir, manifest_sidecar_name)
            os.makedirs(os.path.dirname(_side_abs), exist_ok=True)
            with open(_side_abs, 'w') as _sf:
                json.dump(manifest, _sf, indent=2)
            log(f"  Created {manifest_sidecar_name} (per-module asset manifest)",
                "success")

        # Online-upgrade short-circuit: no tar.gz needed — return the
        # built package_dir directly. Caller (run_online_upgrade_workflow)
        # owns the dir from here and cleans up after the apply finishes.
        if not compress:
            log("", "info")
            log("=" * 50, "info")
            log("PACKAGE DIRECTORY READY (compress=False, caller owns cleanup)", "success")
            log("=" * 50, "info")
            log(f"  Modules: {', '.join(modules.keys())}", "info")
            log(f"  Built at: {package_dir}", "info")
            return {
                "success": True,
                "package_dir": package_dir,
                "manifest": manifest,
            }

        # Create tar.gz archive
        log("", "info")
        log("=== Creating Package Archive ===", "info")
        log("  Compressing package (this may take a few minutes)...", "info")

        # Disk-space preflight — refuse to start compression if the
        # output volume doesn't have enough room.
        try:
            source_size_check = _get_dir_size(package_dir)
            free_bytes = shutil.disk_usage(packages_dir).free
            required = int(source_size_check * 1.2)
            if free_bytes < required:
                msg = (
                    f"Not enough free space in {packages_dir} — "
                    f"need ≥{_format_size(required)} "
                    f"(source × 1.2), have {_format_size(free_bytes)}. "
                    "Free disk and re-run prepare."
                )
                log(msg, "error")
                raise Exception(msg)
        except FileNotFoundError:
            pass

        # Derive source_dir / source_name from the actual built path so
        # a caller-overridden work_dir composes correctly through tar.
        result = _compress_with_progress(
            source_dir=os.path.dirname(package_dir),
            source_name=os.path.basename(package_dir),
            output_file=output_file_tmp,
            logger=log,
            progress_interval=10,
            run_id=run_id,
        )

        if result.get("cancelled"):
            # Cancellation already removes output_file_tmp inside the
            # compressor's cancel branch; previous good package is
            # untouched.
            return {"success": False, "error": "cancelled", "cancelled": True}
        if not result['success']:
            # `_compress_with_progress` already deleted the corrupt
            # tmp file (on tar failure or gzip-t failure). The
            # previous `output_file` — if any — is still in place.
            raise Exception(f"Failed to create archive: {result.get('error', '')[:200]}")

        # Atomic swap: rename the validated `.new` over the canonical
        # filename. os.replace is atomic on POSIX so a concurrent
        # apply-upgrade reader always sees either the old file or the
        # new file, never a partial. After this point the previous
        # package is gone — but only after we KNOW the new one is good.
        os.replace(output_file_tmp, output_file)
        log("  Swapped new archive into place (atomic)", "success")

        # Sidecar manifest — placed NEXT to the tarball, not inside it,
        # so get_package_info() can return in O(1) without having to
        # decompress the entire (multi-GB) tarball just to read the
        # manifest. Tarball is still self-describing; this is purely
        # a read-performance optimization.
        try:
            sidecar = output_file + '.manifest.json'
            with open(sidecar, 'w') as out:
                json.dump(manifest, out)
            log(f"  Wrote sidecar manifest -> {os.path.basename(sidecar)}", "info")
        except Exception as e:
            log(f"  Sidecar manifest write failed: {e}", "warning")

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
        # UI guidance, and only true when the archive landed in the operator's
        # persistent packages dir with a button pointing at it. A CI build sends
        # it somewhere else and nobody is going to click anything.
        if not _packages_dir_overridden:
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

        # Remove ONLY the in-progress `.new` file — leave the
        # previously-good `output_file` (if any) intact so the
        # operator's apply-upgrade flow still has a working archive.
        if os.path.exists(output_file_tmp):
            try:
                os.remove(output_file_tmp)
            except OSError:
                pass

        return {
            "success": False,
            "error": str(e)
        }

    finally:
        # Offline-prepare cleanup ONLY. Online-upgrade caller owns the
        # package_dir and consumes it via the apply step — cleanup
        # happens in the orchestration's own finally block instead.
        if compress:
            if os.path.exists(package_dir):
                try:
                    shutil.rmtree(package_dir)
                except Exception:
                    pass

            for module, version in modules.items():
                if module in PRIMARY_IMAGES or module in TRANSITIVE_IMAGES:
                    for image, _ in get_docker_images_for(module, version,
                                                            target_versions=target_versions):
                        run_command(f"docker rmi {image} 2>/dev/null || true", logger=None, timeout=60)
