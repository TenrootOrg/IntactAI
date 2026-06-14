#!/usr/bin/env python3
"""Upgrade package preparation service.

Creates offline upgrade packages that can be transferred to air-gapped systems.
"""

import os
import json
import shutil
import time
from datetime import datetime
from typing import Dict, Callable, List, Optional

from .base import run_command, WORKDIR, HOST_PATH


# Primary images per module — the deliverables the operator's
# `versions:` pin in config.yaml directly drives. `{version}` is
# substituted with `modules[<module>]` at prepare time.
PRIMARY_IMAGES = {
    'elk': [
        ('docker.elastic.co/elasticsearch/elasticsearch:{version}',
         'elasticsearch-{version}.tar'),
        ('docker.elastic.co/kibana/kibana:{version}',
         'kibana-{version}.tar'),
        ('docker.elastic.co/logstash/logstash:{version}',
         'logstash-{version}.tar'),
    ],
    'timesketch': [
        ('us-docker.pkg.dev/osdfir-registry/timesketch/timesketch:{version}',
         'timesketch-{version}.tar'),
    ],
    'plaso': [
        ('log2timeline/plaso:{version}', 'plaso-{version}.tar'),
    ],
    'iris': [
        # iris-worker reuses the same iriswebapp_app image. The DB image
        # is included for air-gap support; data lives in a volume so the
        # upgrade is non-destructive.
        ('ghcr.io/dfir-iris/iriswebapp_app:{version}',
         'iris-app-{version}.tar'),
        ('ghcr.io/dfir-iris/iriswebapp_nginx:{version}',
         'iris-nginx-{version}.tar'),
        ('ghcr.io/dfir-iris/iriswebapp_db:{version}',
         'iris-db-{version}.tar'),
    ],
    'prowler': [
        ('toniblyx/prowler:{version}', 'prowler-{version}.tar'),
    ],
    'o365rc': [
        # Upstream only ships ':latest', so {version} is normally 'latest'.
        ('anssi/dfir-o365rc:{version}', 'dfir-o365rc-{version}.tar'),
    ],
    'volweb': [
        # forensicxlab releases backend + frontend in lockstep so a single
        # `versions.volweb` pin drives both.
        ('forensicxlab/volweb-backend:{version}',
         'volweb-backend-{version}.tar'),
        ('forensicxlab/volweb-frontend:{version}',
         'volweb-frontend-{version}.tar'),
    ],
}


# Transitive infrastructure images per module — postgres / opensearch /
# redis / rabbitmq / nginx etc. that the primary module's compose pulls
# at runtime. Each entry is:
#   (dep_key, image_pattern, tar_pattern)
#
# `dep_key` is looked up at prepare time in config.yaml's
# `transitive_versions.<module>.<dep_key>` block (see _read_transitive_pin
# below); the resolved tag fills `{tag}` in both patterns. Fallbacks in
# TRANSITIVE_DEFAULTS keep the historical behaviour when the operator's
# config.yaml has no `transitive_versions:` block.
#
# Air-gap correctness: at apply time, the resolved tag also lands in the
# bundled manifest.json under `contents.transitive_versions`, and the
# offline-apply step writes it to per-module `.env` files BEFORE
# `docker compose up`. That way the compose's `${VAR:-default}`
# resolves to the tag of an image actually present in the loaded
# bundle, not the static default the compose file shipped with.
TRANSITIVE_IMAGES = {
    'timesketch': [
        ('postgres',   'postgres:{tag}',                       'postgres-{tag}.tar'),
        ('opensearch', 'opensearchproject/opensearch:{tag}',   'opensearch-{tag}.tar'),
        ('redis',      'redis:{tag}',                          'redis-{tag}.tar'),
        ('nginx',      'nginx:{tag}',                          'nginx-{tag}.tar'),
    ],
    'iris': [
        # Infrastructure dep — IRIS compose pulls rabbitmq from Docker
        # Hub at compose-up time. Bundling lets the apply step load it
        # offline.
        ('rabbitmq', 'rabbitmq:{tag}', 'rabbitmq-{tag}.tar'),
    ],
    'volweb': [
        # Distinct tar names from timesketch's postgres/redis so both
        # bundles can coexist on disk without name collisions.
        ('postgres', 'postgres:{tag}', 'volweb-postgres-{tag}.tar'),
        ('redis',    'redis:{tag}',    'volweb-redis-{tag}.tar'),
    ],
}


# Fallback tags when config.yaml has no `transitive_versions.<module>.<dep>`
# entry. Mirrors today's hardcoded values, so the refactor is a no-op
# for any operator who hasn't added the block.
TRANSITIVE_DEFAULTS = {
    'timesketch': {
        # Timesketch >=20260611 requires OpenSearch >=2.19.5 (compat-floor
        # break that bit us when upstream bumped past 2.11.0 — see the
        # transitive_resolver module's history).
        'opensearch': '2.19.5',
        'postgres':   '15',
        'redis':      '7-alpine',
        'nginx':      'alpine',
    },
    'iris': {
        'rabbitmq': '3-management-alpine',
    },
    'volweb': {
        'postgres': '15',
        'redis':    '7',
    },
}


# Maps each transitive `(module, dep_key)` to the env var name the
# module's compose file consumes. Used by the apply side to write the
# right `.env` line before `docker compose up`, and by the prepare side
# to record bundled tags in the manifest. Keys live in
# modules/<module>/docker-compose.yaml as `${VAR:-default}` references.
TRANSITIVE_ENV_KEYS = {
    'timesketch': {
        'opensearch': 'OPENSEARCH_VERSION',
        'postgres':   'POSTGRES_VERSION',
        'redis':      'REDIS_VERSION',
        'nginx':      'NGINX_VERSION',
    },
    'volweb': {
        'postgres': 'VOLWEB_POSTGRES_VERSION',
        'redis':    'VOLWEB_REDIS_VERSION',
    },
    # iris's rabbitmq is referenced literally in
    # modules/iris/docker-compose.yaml — no env var. The apply side
    # treats a missing env-key as "no .env write needed; the image
    # already gets loaded and compose's literal `rabbitmq:3-management-
    # alpine` reference matches".
    'iris': {},
}


def _read_transitive_pin(module: str, dep: str) -> Optional[str]:
    """Return config.yaml's `transitive_versions.<module>.<dep>` value, or
    None when the block / module / key is absent. Fail-soft on any
    parse error so a malformed config.yaml never blocks a prepare.

    This is the OPERATOR OVERRIDE layer — when an entry exists here, it
    wins over upstream scrape + hardcoded defaults. Leave empty (or
    omit the block entirely) to track upstream automatically.
    """
    config_path = os.path.join(WORKDIR, 'config.yaml')
    if not os.path.exists(config_path):
        return None
    try:
        import yaml  # local — yaml isn't used elsewhere in this module
        with open(config_path, 'r') as f:
            cfg = yaml.safe_load(f) or {}
        block = ((cfg.get('transitive_versions') or {}).get(module) or {})
        val = block.get(dep)
        return str(val).strip() if val is not None else None
    except Exception:
        return None


# Disk cache for upstream-scraped transitive versions. Keyed by
# (module, primary_version) — both are immutable on the upstream side
# (the version is a release tag), so the cached result is valid as long
# as upstream doesn't force-push the tag (which they shouldn't). 24h
# TTL guards against rare cases where they do.
_UPSTREAM_CACHE_DIR = '/app/data/cache/transitive_resolver'
_UPSTREAM_CACHE_TTL_SEC = 24 * 60 * 60

# In-process LRU layer over the disk cache: prepare iterates the
# transitive image list per module + version, calling
# `_resolve_from_upstream` once per dep — without the in-memory layer
# we'd hit disk N times per module per prepare. Lives for the
# lifetime of the prepare process.
_UPSTREAM_MEM_CACHE: Dict[str, Dict[str, str]] = {}

# Floating tags upstream sometimes ships in their compose
# (e.g. k1nd0ne/VolWeb's `redis:latest`). Don't propagate those — they
# defeat reproducibility. When upstream uses one of these, fall through
# to the next layer (config.yaml override → TRANSITIVE_DEFAULTS).
_FLOATING_TAGS = frozenset({
    'latest', 'master', 'main', 'develop', 'dev', 'edge', 'stable',
    'rolling',
})


def _resolve_from_upstream(module: str,
                            primary_version: str,
                            logger: Optional[Callable] = None) -> Dict[str, str]:
    """Fetch `transitive_resolver.resolve_for(module, primary_version)`
    via a layered cache. Returns dict of `{dep_key: tag}` for whatever
    upstream's compose / config.env declares at the pinned tag, or `{}`
    on any failure.

    Layers, fastest first:
      1. _UPSTREAM_MEM_CACHE (process-lifetime dict)
      2. _UPSTREAM_CACHE_DIR (disk JSON, 24h TTL — survives backend
         restarts; works across multiple prepares in the same day)
      3. resolve_for() (live network call to upstream)

    Each layer also strips floating tags before storing.

    The optional `logger` makes every step of the chain visible in the
    workflow log (which cache layer hit, what URL is being scraped, what
    came back, why an attempt failed). Critical for diagnosing "why did
    prepare bundle opensearch X" questions — without these breadcrumbs
    a wrong version looks identical in the log to a right one.
    """
    log = logger or (lambda msg, lvl='info': None)
    cache_key = f"{module}@{primary_version}"
    if cache_key in _UPSTREAM_MEM_CACHE:
        cached = _UPSTREAM_MEM_CACHE[cache_key]
        log(f"  [transitive] {module}@{primary_version}: in-memory cache hit "
            f"({len(cached)} deps)", "info")
        return cached

    cache_path = os.path.join(
        _UPSTREAM_CACHE_DIR,
        f"{module}-{primary_version.replace('/', '_')}.json",
    )
    now = time.time()
    if os.path.isfile(cache_path):
        try:
            age = now - os.path.getmtime(cache_path)
            if age < _UPSTREAM_CACHE_TTL_SEC:
                with open(cache_path, 'r') as f:
                    cached = json.load(f) or {}
                _UPSTREAM_MEM_CACHE[cache_key] = cached
                age_h = int(age // 3600)
                age_m = int((age % 3600) // 60)
                log(f"  [transitive] {module}@{primary_version}: disk cache "
                    f"hit (age {age_h}h{age_m}m, {len(cached)} deps)",
                    "info")
                return cached
        except Exception as e:
            log(f"  [transitive] {module}@{primary_version}: disk cache "
                f"unreadable ({type(e).__name__}: {e}) — re-fetching",
                "warning")

    # Cache miss. Hit upstream.
    log(f"  [transitive] {module}@{primary_version}: cache miss → scraping "
        f"upstream config…", "info")
    try:
        from .transitive_resolver import resolve_for
        raw = resolve_for(module, primary_version) or {}
        if raw:
            log(f"  [transitive] {module}@{primary_version}: scrape returned "
                f"{', '.join(f'{k}={v}' for k, v in raw.items())}",
                "info")
        else:
            log(f"  [transitive] {module}@{primary_version}: scrape returned "
                f"NO data (upstream URL may have moved, repo archived, or "
                f"network unreachable). Callers will surface this loudly — "
                f"see get_transitive_tag.",
                "warning")
    except Exception as e:
        log(f"  [transitive] {module}@{primary_version}: scrape raised "
            f"{type(e).__name__}: {e}. Falling through to empty result.",
            "warning")
        raw = {}

    # Strip floating tags so they never feed back through the pipeline.
    cleaned = {
        k: v for k, v in raw.items()
        if str(v).strip().lower() not in _FLOATING_TAGS
    }
    dropped = set(raw) - set(cleaned)
    if dropped:
        log(f"  [transitive] {module}@{primary_version}: dropped floating "
            f"tag(s) {sorted(dropped)} (won't trust 'latest'/'master'/etc. "
            f"for pinned bundle)", "warning")

    # Persist (best-effort).
    try:
        os.makedirs(_UPSTREAM_CACHE_DIR, exist_ok=True)
        tmp = cache_path + '.new'
        with open(tmp, 'w') as f:
            json.dump(cleaned, f)
        os.replace(tmp, cache_path)
    except Exception as e:
        log(f"  [transitive] {module}@{primary_version}: disk cache write "
            f"failed ({type(e).__name__}: {e}); in-memory cache only",
            "warning")

    _UPSTREAM_MEM_CACHE[cache_key] = cleaned
    return cleaned


def get_transitive_tag(module: str, dep: str,
                        primary_version: Optional[str] = None,
                        logger: Optional[Callable] = None) -> str:
    """Resolve the tag for one transitive container of `module`.

    Resolution order (first hit wins):
      1. config.yaml's `transitive_versions.<module>.<dep>` — operator
         override. Sparse only; almost never set. Loud log when used.
      2. Upstream scrape via `_resolve_from_upstream` — hits the module's
         own published compose / config.env at the pinned tag. This is
         the REQUIRED path: prepare + online-upgrade always run with
         internet by design, so the scrape MUST succeed.

    Raises `RuntimeError` when neither the operator override nor the
    upstream scrape produces a value. This replaces a previous silent
    fallback to `TRANSITIVE_DEFAULTS[module][dep]` that bit an operator
    on 2026-06-14 — a stale default bundled the wrong opensearch
    version and the prepare reported success. Hard-failing instead
    makes the underlying problem (no internet, upstream URL moved, etc.)
    impossible to miss.

    `TRANSITIVE_DEFAULTS` survives in this module ONLY as a documented
    record of the last-known-good upstream pins per module. It is NOT
    consulted by this resolver. If you ever need an air-gap fallback,
    add it as an explicit `transitive_versions.<module>.<dep>` override
    in config.yaml before running prepare.

    Raises `KeyError` when the (module, dep) pair itself is unknown
    (misnamed at the call site).
    """
    log = logger or (lambda msg, lvl='info': None)

    pinned = _read_transitive_pin(module, dep)
    if pinned:
        log(f"  [transitive] {module}.{dep} = {pinned} "
            f"(operator override from config.yaml.transitive_versions)",
            "info")
        return pinned

    if primary_version:
        upstream = _resolve_from_upstream(module, primary_version, logger=log)
        if upstream and dep in upstream:
            tag = upstream[dep]
            log(f"  [transitive] {module}.{dep} = {tag} (upstream scrape)",
                "success")
            return tag

    # Both override and scrape failed. Raise a hard error so prepare
    # aborts cleanly with an actionable message instead of silently
    # bundling a stale default.
    last_known = TRANSITIVE_DEFAULTS.get(module, {}).get(dep, '<unknown>')
    msg = (
        f"Cannot resolve transitive dep {module}.{dep}: "
        f"no operator override in config.yaml.transitive_versions, "
        f"and upstream scrape returned nothing for primary_version="
        f"{primary_version!r}. Prepare requires internet to scrape each "
        f"module's own config.env / docker-compose at the pinned tag. "
        f"Either (a) restore internet access to api.github.com + "
        f"raw.githubusercontent.com and re-run, or (b) set "
        f"`transitive_versions.{module}.{dep}: '<tag>'` in config.yaml "
        f"as a manual override (last-known-good value: {last_known!r})."
    )
    log(msg, "error")
    raise RuntimeError(msg)


def get_docker_images_for(module: str, version: str,
                           logger: Optional[Callable] = None) -> list:
    """Return the list of `(image, tar_filename)` to bundle for one
    primary module + version. Same shape the old `DOCKER_IMAGES[module]`
    list returned (already with placeholders expanded), so callers can
    iterate uniformly.

    Tag resolution per image (layered, first hit wins):
      - Primary image: `versions.<module>` pin from config.yaml
      - Transitive image: config.yaml's
        `transitive_versions.<module>.<dep>` override → upstream scrape
        for `(module, version)` at the pinned tag → TRANSITIVE_DEFAULTS

    `logger` (when provided) lights up the transitive resolution chain
    so the prepare log shows which source produced each tag. Without it
    the resolution is silent (legacy behaviour preserved for callers
    that don't have a logger).
    """
    out = []
    for image_pat, tar_pat in PRIMARY_IMAGES.get(module, []):
        out.append((
            image_pat.format(version=version),
            tar_pat.format(version=version),
        ))
    for dep_key, image_pat, tar_pat in TRANSITIVE_IMAGES.get(module, []):
        tag = get_transitive_tag(module, dep_key, primary_version=version,
                                  logger=logger)
        out.append((
            image_pat.format(tag=tag),
            tar_pat.format(tag=tag),
        ))
    return out


def get_transitive_versions_for(module: str,
                                  primary_version: Optional[str] = None,
                                  logger: Optional[Callable] = None,
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
                logger=logger,
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
    result = run_command(f"docker pull {image}", timeout=1800, logger=log, run_id=run_id)
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
    if size_check.get("success"):
        try:
            image_bytes = int((size_check.get('stdout', '0') or '0').strip().strip("'"))
            required = int(image_bytes * 1.2)
            try:
                free_bytes = shutil.disk_usage(os.path.dirname(output_path)).free
            except (FileNotFoundError, OSError):
                free_bytes = None
            if free_bytes is not None and free_bytes < required:
                log(
                    f"  Not enough disk for {os.path.basename(output_path)}: "
                    f"need ≥{_format_size(required)} (image × 1.2), "
                    f"have {_format_size(free_bytes)}. Free disk and re-run prepare.",
                    "error",
                )
                return False
        except (ValueError, TypeError):
            # docker inspect output unexpected — skip the check, fall
            # through to docker save (the silent-truncation risk is
            # still better than blocking the build on a parse error).
            pass

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


def prepare_upgrade_package(modules: Dict, run_id: str, logger: Callable = None,
                            compress: bool = True,
                            work_dir: Optional[str] = None) -> Dict:
    """Download and package upgrade components.

    Args:
        modules: Dict of module versions, e.g. {"elk": "9.3.1", "velociraptor": "0.75.6"}
        run_id: Workflow run ID for tracking
        logger: Logging function
        compress: When True (default, offline flow), compress the built
                  directory to a tar.gz at /data/upgrade_packages/ via
                  the atomic-swap pattern, then clean up the work dir.
                  When False (online-upgrade flow), skip compression +
                  cleanup; the caller takes ownership of the
                  package_dir and is responsible for removing it when
                  the apply step is done.
        work_dir: Where to build the package contents. Defaults to
                  /tmp/<package_name>/. Online flow passes
                  /app/data/tmp/<...>/ so the dir survives the backend
                  restart that intact upgrades trigger between Phase 1
                  and Phase 2.

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
    packages_dir = "/data/upgrade_packages"
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
                    req = urllib.request.Request(
                        branch_api_url,
                        headers={"Accept": "application/vnd.github+json"},
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

                # Record the operator's input verbatim in the manifest.
                # `resolved_ref` (the SHA we actually downloaded) is
                # captured separately in source_origin so the package
                # is still traceable to a specific commit when needed,
                # but the user-facing version string stays simple.
                manifest["versions"]["intact"] = version
                manifest["contents"]["include_source"] = True
                manifest["contents"]["source_origin"] = (
                    f"github.com/{repo}@{resolved_ref}"
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
                try:
                    intact_source_root = f"{package_dir}/source/intact"
                    if os.path.isdir(intact_source_root):
                        version_file = f"{intact_source_root}/VERSION"
                        with open(version_file, "w") as vf:
                            vf.write(version.strip() + "\n")
                        log(f"  Stamped source/intact/VERSION -> {version}", "info")
                except Exception as e:
                    log(f"  Could not stamp VERSION file: {e}", "warning")

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
                from .velociraptor import resolve_velociraptor_release_tag
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
                        log(f"  Registry snapshot SQL failed (continuing — direct "
                            f"downloads below will cover the standard sources): "
                            f"{snap.get('error', '')[:120]}", "warning")
                except Exception as e:
                    log(f"  Registry snapshot raised: {e}", "warning")

                # Direct downloads — pull artifact source zips straight
                # from their public GitHub URLs. Runs UNCONDITIONALLY
                # (works whether velociraptor is up or down) so the
                # package always contains the standard artifact set even
                # when the SQL snapshot above couldn't run.
                #
                # The three URLs are what Velociraptor 0.76.x itself
                # uses for Server.Import.ArtifactExchange /
                # Server.Import.DetectRaptor / Server.Import.Extras (verified
                # by querying the live Velociraptor's Server.Import.*
                # artifact YAMLs on 2026-06-10). They may need to be
                # updated when bumping to a future Velociraptor major
                # version that points elsewhere. The SQL snapshot above,
                # when velociraptor IS running, captures whatever URLs
                # the running version actually expects — so the two
                # paths complement each other.
                external_dir = os.path.join(velo_artifacts_dir, 'external')
                os.makedirs(external_dir, exist_ok=True)
                # Full list — every URL Server.Import.ArtifactExchange /
                # DetectRaptor / Extras would download at runtime. The
                # Extras artifact in particular downloads from SIX URLs
                # (not the two the original list had); missing the
                # Triage zip means Windows.Triage.Targets is absent on
                # the apply target, which kape_service.py:76 hard-fails
                # on with "Parameter refers to an unknown artifact". The
                # 2026-06-11 fresh-install operator hit exactly this.
                # See `Server.Import.Extras` artifact YAML for the
                # authoritative list (parameters.Details.default).
                external_sources = [
                    (
                        "Artifact Exchange (Velocidex)",
                        "artifact_exchange_v2.zip",
                        "https://github.com/Velocidex/velociraptor-docs/raw/gh-pages/exchange/artifact_exchange_v2.zip",
                    ),
                    (
                        "DetectRaptor (mgreen27)",
                        "detectraptor_latest.zip",
                        # GitHub /latest/download/<asset> redirects to
                        # whatever asset name the latest release uses.
                        # Verified 2026-06-10: latest tag = DetectRaptor,
                        # asset name DetectRaptorVQL.zip (~750 KB).
                        # Works without an API token at the anonymous
                        # rate-limit (60/h is plenty for prepare).
                        "https://github.com/mgreen27/DetectRaptor/releases/latest/download/DetectRaptorVQL.zip",
                    ),
                    (
                        "Rapid7 Labs VQL",
                        "rapid7labs_vql.zip",
                        "https://github.com/rapid7/Rapid7-Labs/raw/main/Vql/release/Rapid7LabsVQL.zip",
                    ),
                    (
                        "Velociraptor Sigma",
                        "velociraptor_sigma.zip",
                        "https://sigma.velocidex.com/Velociraptor.Sigma.Artifacts.zip",
                    ),
                    (
                        "Registry Hunter (Velocidex)",
                        "windows_registry_hunter.zip",
                        "https://registry-hunter.velocidex.com/Windows.Registry.Hunter.zip",
                    ),
                    (
                        "SQLite Hunter (Velocidex)",
                        "sqlite_hunter.zip",
                        "https://sqlitehunter.velocidex.com/SQLiteHunter.zip",
                    ),
                    (
                        "Triage Artifacts (Velocidex) — Windows.Triage.Targets, Windows.KapeFiles.Targets",
                        "velociraptor_triage.zip",
                        "https://triage.velocidex.com/artifacts/Velociraptor_Triage_v0.1.zip",
                    ),
                ]
                log("Downloading external artifact sources (public GitHub URLs)...",
                    "info")
                dl_count = 0
                for label, fname, url in external_sources:
                    dst = os.path.join(external_dir, fname)
                    try:
                        cp = run_command(
                            f"curl -fL --retry 3 --retry-delay 5 "
                            f"--max-time 600 --connect-timeout 30 "
                            f"-o {dst} {url}",
                            logger=None, timeout=900, run_id=run_id,
                        )
                        if not (cp.get('success') and os.path.isfile(dst)):
                            log(f"  ✗ {label}: curl failed "
                                f"({(cp.get('error') or '')[:100]})", "warning")
                            continue
                        # Verify it's a real zip by reading the magic
                        # bytes: every ZIP starts with PK\x03\x04. This
                        # cleanly rejects GitHub's HTML error pages while
                        # accepting legitimate small zips like Rapid7's
                        # ~12 KB Rapid7LabsVQL.zip — which a size-based
                        # threshold ("> 50 KB") would false-positive on.
                        try:
                            with open(dst, 'rb') as f:
                                head = f.read(4)
                        except Exception as e:
                            log(f"  ✗ {label}: could not read downloaded "
                                f"file: {e}", "warning")
                            try: os.remove(dst)
                            except Exception: pass
                            continue
                        if not head.startswith(b'PK\x03\x04'):
                            sz_kb = os.path.getsize(dst) / 1024
                            log(f"  ✗ {label}: download isn't a real zip "
                                f"(magic={head!r}, {sz_kb:.0f} KB) — most "
                                f"likely an HTML error page, dropping",
                                "warning")
                            try: os.remove(dst)
                            except Exception: pass
                            continue
                        sz_mb = os.path.getsize(dst) / (1024 * 1024)
                        log(f"  ✓ {label} → {fname} ({sz_mb:.2f} MB)",
                            "success")
                        dl_count += 1
                    except Exception as e:
                        log(f"  ✗ {label}: {e}", "warning")
                if dl_count > 0:
                    manifest["contents"].setdefault("velociraptor_artifacts", {})[
                        "external_zips"] = dl_count
                if dl_count == 0:
                    log("  No external artifact sources downloaded — package "
                        "will rely on registry_snapshot + custom_artifacts + "
                        "TenRoot zip alone. Verify the upstream URLs haven't "
                        "moved if this is an internet-connected prepare host.",
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
                    log(f"  Resolving transitive deps for {module}@{version} "
                        f"(operator override → upstream scrape → fallback):",
                        "info")
                images_for_module = get_docker_images_for(
                    module, version, logger=log,
                )
                tv_env = get_transitive_versions_for(
                    module, primary_version=version, logger=log,
                )
                if tv_env:
                    manifest["contents"].setdefault(
                        "transitive_versions", {})[module] = tv_env
                    log(f"  Transitive pins bundled for {module}: " +
                        ', '.join(f'{k}={v}' for k, v in tv_env.items()),
                        "success")

                # Pull and save Docker images
                declared = len(images_for_module)
                bundled_for_module = 0
                for image, output_name in images_for_module:
                    output_path = f"{package_dir}/images/{output_name}"

                    if _pull_and_save_image(image, output_path, log, run_id=run_id):
                        manifest["contents"]["images"].append(output_name)
                        bundled_for_module += 1
                    # Honor cancel between images (fast-exit on Stop).
                    try:
                        from services.workflow_service import is_cancelled
                        if is_cancelled(run_id):
                            return {"success": False, "error": "cancelled", "cancelled": True}
                    except Exception:
                        pass

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

        # Online-upgrade short-circuit: no tar.gz needed — return the
        # built package_dir directly. Caller (run_online_upgrade_workflow)
        # owns the dir from here and cleans up after the apply finishes.
        if not compress:
            log("", "info")
            log("=" * 50, "info")
            log("PACKAGE DIRECTORY READY (online-upgrade, no compression)", "success")
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
                    for image, _ in get_docker_images_for(module, version):
                        run_command(f"docker rmi {image} 2>/dev/null || true", logger=None, timeout=60)
