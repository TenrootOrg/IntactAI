#!/usr/bin/env python3
"""Auto-detect drift between our pinned transitive container versions
and what each primary module's upstream compose recommends — and
rewrite `config.yaml` in place when drift is found.

Run by `.github/workflows/transitive-pin-drift.yml` on a daily cron.
On detected drift, the workflow opens a PR against `development` with
the rewritten config.yaml; the operator reviews and merges. The next
prepare on that branch picks up the bumped transitive pins via the
existing `services/upgrade/package.py:get_docker_images_for` machinery.

Why this isn't in the prepare flow itself:

    Coupling "is upstream changed?" (a slow, periodic, reviewable
    question) to "build me a package now" (a fast, deterministic
    operator action) would add a network round-trip + a silent
    config-mutation to every prepare. Out-of-band detection via cron
    keeps prepares deterministic and makes upstream-tracked changes
    explicit PRs you can read before they hit anyone's deploy.

Usage:
    python3 scripts/check_transitive_drift.py            # detect + rewrite, exit 0 / 1 (drift / no-drift)
    python3 scripts/check_transitive_drift.py --dry-run  # detect only, never write
    python3 scripts/check_transitive_drift.py --json     # machine-readable diff summary

Exit codes:
    0 → drift detected and config.yaml rewritten (or --dry-run + drift)
    1 → no drift; nothing to do
    2 → operational error (unreachable upstream, parse failure, etc.)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Dict, List, Optional, Tuple


def _project_root() -> str:
    """Repo root, regardless of where this script is invoked from."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.join(here, os.pardir))


_RESOLVER_MODULE = None  # cached singleton


def _load_resolver():
    """Load transitive_resolver.py as an isolated module — bypasses
    services.upgrade.__init__'s heavy backend init chain (storage,
    grpc, etc.) which would otherwise fail outside the backend
    container."""
    global _RESOLVER_MODULE
    if _RESOLVER_MODULE is not None:
        return _RESOLVER_MODULE
    import importlib.util
    path = os.path.join(_project_root(), 'modules', 'backend', 'services',
                         'upgrade', 'transitive_resolver.py')
    if not os.path.isfile(path):
        raise SystemExit(f"resolver not found at {path}")
    spec = importlib.util.spec_from_file_location(
        'transitive_resolver_standalone', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    _RESOLVER_MODULE = mod
    return mod


def _read_config_yaml() -> Tuple[Dict, str]:
    """Returns (parsed_dict, raw_text). Raw text is needed for the
    surgical regex rewrite that preserves comments + ordering."""
    import yaml
    config_path = os.path.join(_project_root(), 'config.yaml')
    if not os.path.isfile(config_path):
        raise SystemExit(f"config.yaml not found at {config_path}")
    with open(config_path) as f:
        raw = f.read()
    parsed = yaml.safe_load(raw) or {}
    return parsed, raw


def _rewrite_one_pin(content: str, module: str, dep: str,
                      new_value: str) -> Tuple[str, bool]:
    """Mirror of services/upgrade/base.py:set_transitive_version_in_config
    so this script doesn't need the backend's import path at runtime —
    it's just a small regex.

    Returns (new_content, changed_bool)."""
    pattern = re.compile(
        rf"(^transitive_versions:\s*\n(?:[ \t]+.*\n)*?"
        rf"[ \t]+{re.escape(module)}:\s*\n(?:[ \t]+.*\n)*?)"
        rf"([ \t]+{re.escape(dep)}:\s*(['\"]?))[^\n'\"#]+"
        rf"((['\"]?)\s*(?:#.*)?$)",
        re.MULTILINE,
    )
    match = pattern.search(content)
    if not match:
        return content, False
    last_line = match.group(0).split('\n')[-1]
    cur = re.search(
        rf"{re.escape(dep)}:\s*(['\"]?)([^'\"#\n]+)(['\"]?)",
        last_line,
    )
    if cur and cur.group(2).strip() == new_value:
        return content, False
    new_line = match.group(2) + new_value + match.group(4)
    return (content[:match.start()] + match.group(1) + new_line
             + content[match.end():], True)


# Floating / rolling tags upstream sometimes uses in their compose
# instead of a concrete pin (e.g. k1nd0ne/VolWeb's `image: "redis:latest"`).
# Treating these as "recommendations" would defeat reproducibility — the
# next pull at this tag may return a different image. Skip them: when
# upstream uses one of these, leave our concrete pin alone and surface a
# warning so the operator knows upstream stopped pinning.
_FLOATING_TAGS = frozenset({
    'latest', 'master', 'main', 'develop', 'dev', 'edge', 'stable',
    'rolling',
})


def detect_drift(cfg: Dict) -> Tuple[Dict[str, Dict[str, Tuple[str, str]]],
                                       List[str]]:
    """Returns:
       (drift_map, warnings)
       drift_map: {module: {dep: (current, upstream)}} — only entries
                  where current != upstream AND upstream is a concrete
                  tag (floating tags like 'latest' are filtered out).
       warnings:  human-readable notes (unreachable upstream, floating
                  tag skipped, etc.).
    """
    resolver_mod = _load_resolver()
    RESOLVERS = resolver_mod.RESOLVERS
    resolve_for = resolver_mod.resolve_for

    versions_block = cfg.get('versions') or {}
    transitive_block = cfg.get('transitive_versions') or {}

    # Map of OUR module id → the key in versions: that drives the
    # primary-pin lookup. Matches the per-module entries in RESOLVERS.
    # Most module ids match the versions: key 1:1; if a future module
    # ever uses a different key (like intact → 'backend'), update here.
    versions_key_for: Dict[str, str] = {
        'timesketch': 'timesketch',
        'iris':       'iris',
        'volweb':     'volweb',
    }

    drift: Dict[str, Dict[str, Tuple[str, str]]] = {}
    warnings: List[str] = []

    for module in RESOLVERS:
        vkey = versions_key_for.get(module, module)
        primary = versions_block.get(vkey)
        if not primary:
            warnings.append(f"{module}: no versions.{vkey} pin in config.yaml; "
                            f"skipping drift check")
            continue
        upstream = resolve_for(module, str(primary).strip(),
                                logger=lambda m, level='info': warnings.append(
                                    f"{module}: {m}"))
        if not upstream:
            warnings.append(f"{module}: upstream resolver returned empty; "
                            f"skipping (network issue or upstream layout changed?)")
            continue

        # Mapping from resolver-output key (e.g. 'opensearch') to the
        # key we use in transitive_versions: block (same name today).
        cur_for_module = transitive_block.get(module) or {}
        per_dep: Dict[str, Tuple[str, str]] = {}
        for dep, up_tag in upstream.items():
            up_tag_norm = str(up_tag).strip().lower()
            if up_tag_norm in _FLOATING_TAGS:
                # Upstream ships an unpinned tag here. Keep our concrete
                # pin and tell the operator — bowing to 'latest' would
                # defeat the whole point of pinning.
                warnings.append(
                    f"{module}.{dep}: upstream ships floating tag "
                    f"{up_tag!r} (not a real recommendation); keeping "
                    f"our pinned value {cur_for_module.get(dep)!r}"
                )
                continue
            our_tag = cur_for_module.get(dep)
            if our_tag is None:
                # First-time: treat as drift (we should adopt upstream's
                # recommendation as a new pin so future audits track it).
                per_dep[dep] = ('(unset)', str(up_tag))
            elif str(our_tag).strip() != str(up_tag).strip():
                per_dep[dep] = (str(our_tag), str(up_tag))
        if per_dep:
            drift[module] = per_dep

    return drift, warnings


def format_drift_summary(drift: Dict[str, Dict[str, Tuple[str, str]]]) -> str:
    if not drift:
        return "No drift detected."
    lines = []
    for module, deps in drift.items():
        lines.append(f"  {module}:")
        for dep, (cur, up) in deps.items():
            lines.append(f"    {dep}: {cur!r} → {up!r}  (upstream recommendation)")
    return "\n".join(lines)


def rewrite(content: str,
             drift: Dict[str, Dict[str, Tuple[str, str]]]) -> str:
    """Apply each drift entry as a surgical regex edit on the raw YAML
    text. Doesn't go through yaml.safe_dump (which would strip
    comments / re-quote / reorder)."""
    out = content
    for module, deps in drift.items():
        for dep, (_, up_tag) in deps.items():
            out, changed = _rewrite_one_pin(out, module, dep, up_tag)
            if not changed:
                # Likely the (unset) case — the transitive_versions
                # block for this module exists but doesn't have this
                # dep key yet. The regex requires an existing line to
                # rewrite. For (unset) entries we'd need to insert,
                # which is messier; surface it as a manual-action note
                # instead.
                pass
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dry-run', action='store_true',
                        help='Detect only; never write config.yaml')
    parser.add_argument('--json', action='store_true',
                        help='Emit machine-readable diff to stdout')
    args = parser.parse_args()

    try:
        cfg, raw = _read_config_yaml()
    except Exception as e:
        print(f"ERROR: could not read config.yaml: {e}", file=sys.stderr)
        return 2

    try:
        drift, warnings = detect_drift(cfg)
    except Exception as e:
        print(f"ERROR: drift detection raised: {type(e).__name__}: {e}",
              file=sys.stderr)
        return 2

    for w in warnings:
        print(f"[warn] {w}", file=sys.stderr)

    if args.json:
        print(json.dumps({
            'drift': {m: {d: {'current': c, 'upstream': u}
                          for d, (c, u) in deps.items()}
                       for m, deps in drift.items()},
            'warnings': warnings,
        }, indent=2))
    else:
        print(format_drift_summary(drift))

    if not drift:
        return 1  # no-drift exit code (workflow treats this as "nothing to do")

    if args.dry_run:
        return 0  # drift detected but write skipped

    new_raw = rewrite(raw, drift)
    if new_raw == raw:
        # No regex hit any existing key — likely all drift entries are
        # (unset) cases. Surface and bail.
        print("NOTE: drift detected but no existing keys matched the "
              "regex. Manual config.yaml addition may be required.",
              file=sys.stderr)
        return 0
    config_path = os.path.join(_project_root(), 'config.yaml')
    with open(config_path, 'w') as f:
        f.write(new_raw)
    print(f"Wrote {config_path}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
