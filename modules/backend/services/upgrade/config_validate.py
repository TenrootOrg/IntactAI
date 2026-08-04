#!/usr/bin/env python3
"""Up-front config.yaml validation for the upgrade path.

Runs BEFORE any upgrade mutation so a malformed / incomplete config.yaml
fails fast with a clear operator message, instead of surfacing mid-upgrade
as a KeyError (e.g. get_transitive_tag in package.py) after containers are
already down. Read-only: uses yaml.safe_load for reading, never rewrites.
"""
import os
from typing import Callable, List, Tuple

from .base import WORKDIR
from .package import TRANSITIVE_ENV_KEYS


REQUIRED_TOP_LEVEL = ('domain', 'modules', 'versions', 'project_name')

# module id -> its primary `versions.<key>` pin. ONLY modules that actually
# carry a primary pin in the shipped config.yaml are listed; o365rc and
# some modules intentionally have none (their image tag lives in .env / is
# ':latest'), so requiring one there would be a false positive. Both the
# legacy 'cloudtrail' key and its post-migration 'aws_sigma' name are
# accepted during the rename transition release.
PRIMARY_PIN_KEY = {
    'elk': 'elk',
    'iris': 'iris',
    'plaso': 'plaso',
    'portainer': 'portainer',
    'timesketch': 'timesketch',
    'velociraptor': 'velociraptor',
    'volweb': 'volweb',
    'cloudtrail': 'cloudtrail',
    'aws_sigma': 'aws_sigma',
}

_ENABLED_TRUE = ('true', 'enable', 'enabled', 'yes', 'on')
_ENABLED_FALSE = ('false', 'disable', 'disabled', 'no', 'off')

# Advisory host-layer Docker floor (warn-only in preflight_environment). Keep in
# sync with lib/common.sh (INTACT_MIN/REC_DOCKER_VERSION) + docs/SUPPORTED_PLATFORMS.md.
MIN_DOCKER_VERSION = "20.10"   # hard floor: compose v2 plugin era
REC_DOCKER_VERSION = "24.0"    # recommended


def _docker_version_ge(have: str, floor: str) -> bool:
    """True when Docker Server.Version string `have` (e.g. '27.3.1', '24.0.7-ce')
    is >= dotted `floor`. Lenient: unparseable input returns True so a parsing
    quirk never produces a spurious warning."""
    try:
        h = [int(x) for x in have.split('-', 1)[0].split('.')[:3]]
        f = [int(x) for x in floor.split('.')[:3]]
        return h >= f
    except (ValueError, AttributeError):
        return True


def _is_enabled(block) -> bool:
    """True when a module block's `enabled` is truthy (bool True or one of
    the accepted 'enable'/'yes'/... strings — o365rc ships `enabled: enable`)."""
    if not isinstance(block, dict):
        return False
    v = block.get('enabled')
    if v is True:
        return True
    return isinstance(v, str) and v.strip().lower() in _ENABLED_TRUE


def validate_config(config_path: str = None, logger: Callable = None,
                    require_pins: bool = True) -> Tuple[bool, List[str]]:
    """Structural pre-flight validation of config.yaml. Never raises.

    Returns (ok, errors). Checks:
      - config.yaml parses as a YAML mapping
      - required top-level keys present (domain, modules, versions, project_name)
      - enabled flags are bool / known strings; version values are non-empty scalars
      - when `require_pins` (default): each ENABLED module has its primary pin
        (when it has one) AND every sidecar pin (reusing package.TRANSITIVE_ENV_KEYS)
        — this pre-empts the operator-facing get_transitive_tag KeyError.

    `require_pins=False` skips the pin-completeness checks. Use it where the
    config read hasn't yet had the release's version pins merged in (e.g. the
    offline-apply entry, whose sidecars come from the bundled manifest, not
    config.yaml) so a pin the merge/manifest supplies can't cause a false
    positive that blocks a valid upgrade.
    """
    log = logger or (lambda m, l="info": None)
    path = config_path or os.path.join(WORKDIR, 'config.yaml')
    errors: List[str] = []

    if not os.path.isfile(path):
        return False, [f"config.yaml not found at {path}"]
    try:
        import yaml
        with open(path) as f:
            cfg = yaml.safe_load(f) or {}
    except Exception as e:
        return False, [f"config.yaml is not valid YAML: {e}"]
    if not isinstance(cfg, dict):
        return False, ["config.yaml top level is not a mapping"]

    for k in REQUIRED_TOP_LEVEL:
        if k not in cfg:
            errors.append(f"missing required top-level key '{k}'")

    modules = cfg.get('modules') or {}
    versions = cfg.get('versions') or {}
    if not isinstance(modules, dict):
        errors.append("'modules' is not a mapping")
        modules = {}
    if not isinstance(versions, dict):
        errors.append("'versions' is not a mapping")
        versions = {}

    def _pin_ok(key) -> bool:
        val = versions.get(key)
        return val is not None and str(val).strip() != ""

    for mod, block in modules.items():
        # type sanity on the enabled flag (independent of enabled/disabled)
        if isinstance(block, dict) and 'enabled' in block:
            en = block.get('enabled')
            if not (en is True or en is False or
                    (isinstance(en, str)
                     and en.strip().lower() in _ENABLED_TRUE + _ENABLED_FALSE)):
                errors.append(f"modules.{mod}.enabled is not boolean/'enable': {en!r}")

        if not _is_enabled(block) or not require_pins:
            continue

        # primary pin — only for modules that actually have one
        pk = PRIMARY_PIN_KEY.get(mod)
        if pk and not _pin_ok(pk):
            errors.append(f"module '{mod}' is enabled but versions.{pk} is missing/empty")

        # sidecar pins — authoritative source is package.TRANSITIVE_ENV_KEYS
        for dep in TRANSITIVE_ENV_KEYS.get(mod, {}):
            skey = f"{mod}_{dep}"
            if not _pin_ok(skey):
                errors.append(
                    f"module '{mod}' is enabled but sidecar versions.{skey} is "
                    f"missing (would crash get_transitive_tag mid-upgrade)")

    # version values must be non-empty scalars
    for k, v in versions.items():
        if v is None or isinstance(v, (dict, list)):
            errors.append(
                f"versions.{k} must be a non-empty scalar, got {type(v).__name__}")

    ok = len(errors) == 0
    if ok:
        log("  [config-validate] config.yaml passed pre-upgrade validation", "info")
    else:
        log(f"  [config-validate] config.yaml has {len(errors)} problem(s)", "warning")
    return ok, errors


# ---------------------------------------------------------------------------
# Environment + disk preflight — fail fast with actionable messages instead of
# cryptic mid-upgrade failures (docker missing, compose v1-only host, disk
# filling up under a multi-GB pull/extract).
# ---------------------------------------------------------------------------

# Free-space floors (GiB). Prepare pulls + saves multi-GB images; apply
# extracts a package ~3x its size (see verify_upgrade_package's own check).
# These are conservative entry-gates, not exact accounting — the per-image
# and extraction checks downstream stay authoritative.
PREPARE_MIN_FREE_GB = 25
APPLY_MIN_FREE_GB = 10



def required_free_gb_for_manifest(manifest: dict, package_bytes: int = 0,
                                  floor_gb: int = APPLY_MIN_FREE_GB,
                                  selected_modules=None) -> float:
    """Disk an apply of THIS package actually needs, in GiB.

    The fixed floor is a guess that is wrong in both directions: too strict for a
    small module-only package, too loose for a multi-GB one carrying a dozen
    images. The manifest already lists every bundled image and the package size
    is known, so size the requirement from the real numbers instead:

      package (already on disk) + extracted tree + loaded images + headroom

    Extraction roughly restores the compressed payload, and `docker load` writes
    the image layers a second time into /var/lib/docker, so the images are
    counted twice — once extracted under images/, once in the image store. The
    floor still applies as a lower bound so a tiny package cannot claim an
    implausibly small requirement.

    `selected_modules` narrows the image budget to what the operator actually
    chose. None (the default) budgets the whole package, which is the right
    answer before the selection is known.
    """
    images = ((manifest or {}).get('contents') or {}).get('image_sizes') or {}
    if not isinstance(images, dict):
        images = {}

    # Budget only what will actually be loaded. A package ships every module,
    # but an operator applying two of them pays for two -- charging them for
    # all ten turned a 22 GiB job into a 37 GiB one and refused the upgrade on
    # a box that had ample room for the work it was asked to do.
    #
    # Unattributable images (no owner in the packaging tables) are always
    # counted: they are a packaging bug, and under-budgeting is the failure
    # mode that ends in ENOSPC halfway through `docker load`.
    if selected_modules is not None:
        try:
            from .package import images_by_module
            owned = images_by_module(list(images))
            keep = set()
            for module, names in owned.items():
                if module is None or module in set(selected_modules):
                    keep.update(names)
            images = {k: v for k, v in images.items() if k in keep}
        except Exception:
            pass          # attribution failed -> budget the whole package

    img_bytes = sum(int(v or 0) for v in images.values())
    if not img_bytes:
        # Older manifests record only image NAMES, not sizes. Fall back to the
        # package size, which is dominated by those same images.
        img_bytes = int(package_bytes or 0)
    need = int(package_bytes or 0) + img_bytes * 2
    need_gb = need / (1024 ** 3)
    return max(float(floor_gb), round(need_gb * 1.15, 1))   # 15% headroom


def required_free_gb_after_extraction(images_dir: str,
                                      floor_gb: int = APPLY_MIN_FREE_GB) -> float:
    """Disk still needed once the package is ALREADY EXTRACTED, in GiB.

    required_free_gb_for_manifest() sizes the WHOLE job from a clean start:
    package + extracted tree + loaded images. That is the right answer for the
    check that runs BEFORE anything is downloaded or unpacked.

    It is the wrong answer for the check that runs after extraction, which is
    where it was being used. By then the tarball and the extracted tree are
    both on disk and have already been subtracted from `free` -- so charging
    for them again compares a from-scratch total against post-extraction free
    space and double-counts every byte already spent. On a 5.8 GB / 10-module
    package that demanded 37.7 GiB from a box with 23.1 GiB free and ample room
    for the work actually remaining (2026-08-02, upgrading 20260726).

    What is genuinely still to come is the docker image store growing as
    `docker load` runs. And load_all_bundled_images(cleanup_after_load=True)
    deletes each tar the moment its layers are in the store, so the extracted
    copy and the store copy never coexist for the whole set -- only for the one
    tar in flight. Worst case a store copy runs ~1.5x its tar (layers land
    decompressed where the tar held them compressed), which makes the run's net
    growth about half the staged bytes, plus one tar's transient peak:

        need = staged_bytes * 0.5 + largest_single_tar

    Measured from the tars ACTUALLY on disk rather than from the manifest, so
    it automatically reflects the unselected-module prune and any tar a
    previous attempt already loaded and reclaimed. The floor still applies:
    module upgrades do more than load images (pg_dump backups, compose churn,
    rollback snapshots) and that work needs room the image maths cannot see.
    """
    import os as _os
    try:
        sizes = [_os.path.getsize(_os.path.join(images_dir, f))
                 for f in _os.listdir(images_dir) if f.endswith('.tar')]
    except OSError:
        return float(floor_gb)        # unreadable -> fall back to the floor
    if not sizes:
        return float(floor_gb)        # nothing left to load
    need = sum(sizes) * 0.5 + max(sizes)
    return max(float(floor_gb), round(need / (1024 ** 3) * 1.15, 1))


def preflight_environment(logger: Callable = None,
                          min_free_gb: int = APPLY_MIN_FREE_GB) -> Tuple[bool, List[str]]:
    """Pre-upgrade environment check. Never raises. Returns (ok, errors).

    Verifies, with operator-actionable messages:
      - the docker CLI is reachable (daemon responding),
      - docker compose v2 exists (the upgrade code emits `docker compose ...`
        exclusively — a compose-v1-only host fails cryptically without this),
      - the workdir (INTACT_PATH mount) is present and writable,
      - the data staging volume has at least `min_free_gb` GiB free.
    """
    import shutil as _shutil
    import subprocess as _sp
    log = logger or (lambda m, l="info": None)
    errors: List[str] = []
    _sized_from_manifest = min_free_gb != APPLY_MIN_FREE_GB

    def _run(cmd):
        try:
            r = _sp.run(cmd, capture_output=True, text=True, timeout=30)
            return r.returncode == 0, (r.stdout or r.stderr or '').strip()
        except FileNotFoundError:
            return False, f"{cmd[0]}: not found"
        except Exception as e:
            return False, str(e)

    ok_docker, out = _run(["docker", "version", "--format", "{{.Server.Version}}"])
    if not ok_docker:
        errors.append(
            f"docker daemon is not reachable ({out[:120]}). The upgrade drives "
            f"everything through the docker socket — check the /var/run/docker.sock "
            f"mount and permissions.")
    else:
        # Advisory host-layer floor (warn-only, never blocks — the compose-v2
        # check below is the functional gate). Keep in sync with lib/common.sh
        # INTACT_MIN/REC_DOCKER_VERSION and docs/SUPPORTED_PLATFORMS.md.
        if not _docker_version_ge(out, MIN_DOCKER_VERSION):
            log(f"  [preflight] Docker {out} is below the supported floor "
                f"({MIN_DOCKER_VERSION}+) — upgrade Docker; see "
                f"docs/SUPPORTED_PLATFORMS.md", "warning")
        elif not _docker_version_ge(out, REC_DOCKER_VERSION):
            log(f"  [preflight] Docker {out} works but {REC_DOCKER_VERSION}+ is "
                f"recommended (docs/SUPPORTED_PLATFORMS.md)", "warning")
        ok_compose, cout = _run(["docker", "compose", "version", "--short"])
        if not ok_compose:
            errors.append(
                f"`docker compose` (v2 plugin) is not available ({cout[:120]}). "
                f"IntactAI requires Docker Compose v2 — the legacy `docker-compose` "
                f"v1 binary is not supported. Install the compose plugin.")

    workdir = WORKDIR
    if not os.path.isdir(workdir):
        errors.append(f"workdir {workdir} does not exist — is the INTACT_PATH "
                      f"volume mounted?")
    elif not os.access(workdir, os.W_OK):
        errors.append(f"workdir {workdir} is not writable — upgrade must edit "
                      f"config.yaml and module .env files there.")

    # Staging lives on the /app/data bind mount (falls back to workdir when
    # absent, e.g. running outside the container in dev).
    staging = '/app/data' if os.path.isdir('/app/data') else workdir
    try:
        free_gb = _shutil.disk_usage(staging).free / (1024 ** 3)
        if free_gb < min_free_gb:
            errors.append(
                f"only {free_gb:.1f} GiB free on {staging} — at least "
                f"{min_free_gb} GiB is required for upgrade staging. Free disk "
                f"space (old packages/images) and retry."
                + (f" (This package needs ~{min_free_gb} GiB: sized from its own "
                   f"manifest, not a fixed floor.)" if _sized_from_manifest else ""))
    except Exception as e:
        log(f"  [preflight] disk check skipped ({e})", "warning")

    ok = len(errors) == 0
    if ok:
        log("  [preflight] environment checks passed (docker, compose v2, "
            "workdir, disk)", "info")
    return ok, errors
