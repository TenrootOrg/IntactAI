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
# cve_scan intentionally have none (their image tag lives in .env / is
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
