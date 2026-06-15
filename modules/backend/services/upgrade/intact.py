#!/usr/bin/env python3
"""Intact.AI Platform upgrade functions - combines backend and frontend."""

import os
import re
from typing import Dict, Callable, Optional

from .base import WORKDIR, run_command


def merge_versions_from_new_config(
    new_config_path: str,
    operator_config_path: str,
    logger: Callable = None,
) -> Dict:
    """Merge ONLY the `versions:` block from the new release's config.yaml
    into the operator's existing config.yaml.

    Behaviour:
      - Lines under `versions:` that exist in BOTH files: value updated
        to match the new release.
      - Lines that exist in the new release but NOT in the operator's
        local file: appended at the end of the operator's versions:
        block.
      - Lines in the operator's file but NOT in the new release: left
        alone (operator may have added per-host pins).
      - Everything outside `versions:` (domain, modules.*.password,
        modules.*.id, comments, etc.) is preserved verbatim — never
        touched.

    Why text-level merge instead of yaml.safe_load + yaml.dump:
      preserves the operator's comments, blank lines, and overall
      structure. yaml.dump would normalize the file and lose context.

    Args:
        new_config_path:      path to the freshly-extracted release config.yaml
                              (e.g. <package>/source/intact/config.yaml).
        operator_config_path: path to the operator's local config.yaml
                              (typically /app/workdir/config.yaml).
        logger:               standard (msg, level) callable.

    Returns:
        {"success": bool,
         "updated": {key: (old_value, new_value), ...},
         "added":   {key: value, ...},
         "skipped": [...]}      # keys in operator's file that weren't in
                                # the new release (preserved).
    """
    log = logger or (lambda msg, level="info": None)

    if not os.path.isfile(new_config_path):
        log(f"  [config-merge] new release config.yaml missing at "
            f"{new_config_path}; skipping merge", "warning")
        return {"success": False, "updated": {}, "added": {}, "skipped": []}
    if not os.path.isfile(operator_config_path):
        log(f"  [config-merge] operator config.yaml missing at "
            f"{operator_config_path}; nothing to merge into", "warning")
        return {"success": False, "updated": {}, "added": {}, "skipped": []}

    # Extract `<key>: <value>` lines from the new release's versions:
    # block — parse-by-text so we don't depend on PyYAML being present
    # (it is, but the same code is used by lib/* shell helpers via the
    # CLI bridge).
    def _extract_versions_block(path):
        """Return dict of {key: value_str} for entries under `versions:`."""
        try:
            with open(path, 'r') as f:
                lines = f.read().splitlines()
        except Exception:
            return {}
        in_block = False
        out = {}
        for raw in lines:
            line = raw.rstrip()
            if not in_block:
                if re.match(r'^versions\s*:\s*$', line):
                    in_block = True
                continue
            # Inside versions: block. End-of-block = de-indented non-blank,
            # non-comment line (i.e. a new top-level key).
            stripped_lead = line[:len(line) - len(line.lstrip())]
            if line.strip() == "" or line.lstrip().startswith("#"):
                continue
            if len(stripped_lead) == 0:
                # de-indented → versions: block is over.
                break
            # Parse `  key: value` (handle quoted values + inline comments)
            m = re.match(r'^\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+?)\s*(?:#.*)?$',
                         line)
            if m:
                key = m.group(1)
                val = m.group(2).strip()
                # Strip surrounding quotes for the comparison key
                if (val.startswith("'") and val.endswith("'")) or \
                   (val.startswith('"') and val.endswith('"')):
                    val = val[1:-1]
                out[key] = val
        return out

    new_versions = _extract_versions_block(new_config_path)
    op_versions  = _extract_versions_block(operator_config_path)

    if not new_versions:
        log(f"  [config-merge] new release has no versions: block — nothing "
            f"to merge", "warning")
        return {"success": False, "updated": {}, "added": {}, "skipped": []}

    updated = {}
    added = {}
    for key, new_val in new_versions.items():
        if key in op_versions:
            if op_versions[key] != new_val:
                updated[key] = (op_versions[key], new_val)
        else:
            added[key] = new_val

    skipped = [k for k in op_versions if k not in new_versions]

    if not updated and not added:
        log(f"  [config-merge] operator config.yaml versions already match "
            f"the new release (no changes needed)", "info")
        return {"success": True, "updated": {}, "added": {},
                "skipped": skipped}

    # Apply the merge to the operator's file, text-level so comments/
    # blank lines / structure are preserved.
    try:
        with open(operator_config_path, 'r') as f:
            lines = f.read().splitlines()
    except Exception as e:
        log(f"  [config-merge] read failed for {operator_config_path}: {e}",
            "error")
        return {"success": False, "updated": {}, "added": {}, "skipped": []}

    out_lines = []
    in_block = False
    block_end_idx = None
    for i, raw in enumerate(lines):
        line = raw.rstrip()
        if not in_block:
            out_lines.append(raw)
            if re.match(r'^versions\s*:\s*$', line):
                in_block = True
            continue

        # Inside the versions: block.
        # Detect end-of-block by a de-indented non-blank non-comment line.
        stripped_lead = line[:len(line) - len(line.lstrip())]
        if line.strip() != "" and not line.lstrip().startswith("#") \
                and len(stripped_lead) == 0:
            # End of versions: block reached. Inject any `added` keys
            # BEFORE this line so they live inside the block.
            block_end_idx = len(out_lines)
            for k, v in added.items():
                quoted = _format_value(v)
                out_lines.append(f"  {k}: {quoted}")
            if added:
                # blank line separating new entries from the next top-level
                out_lines.append("")
            out_lines.append(raw)
            in_block = False
            continue

        # Try to match `<key>: <value>` and update if needed.
        m = re.match(r'^(\s+)([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+?)(\s*(?:#.*)?)\s*$',
                     line)
        if m and m.group(2) in updated:
            indent = m.group(1)
            key = m.group(2)
            trailing_comment = m.group(4) or ""
            _, new_val = updated[key]
            new_quoted = _format_value(new_val)
            out_lines.append(f"{indent}{key}: {new_quoted}{trailing_comment}")
        else:
            out_lines.append(raw)

    # Edge case: versions: block was the LAST block in the file (no
    # following de-indented line triggered the injection above).
    if in_block and added:
        for k, v in added.items():
            quoted = _format_value(v)
            out_lines.append(f"  {k}: {quoted}")

    try:
        with open(operator_config_path, 'w') as f:
            f.write('\n'.join(out_lines) + '\n')
    except Exception as e:
        log(f"  [config-merge] write failed for {operator_config_path}: {e}",
            "error")
        return {"success": False, "updated": updated, "added": added,
                "skipped": skipped}

    if updated:
        for key, (old_val, new_val) in updated.items():
            log(f"  [config-merge] updated versions.{key}: {old_val} -> "
                f"{new_val}", "info")
    if added:
        for key, val in added.items():
            log(f"  [config-merge] added versions.{key} = {val}", "info")
    if skipped:
        log(f"  [config-merge] preserved {len(skipped)} operator-local "
            f"versions key(s): {', '.join(skipped[:6])}"
            f"{'...' if len(skipped) > 6 else ''}", "info")

    return {"success": True, "updated": updated, "added": added,
            "skipped": skipped}


def _format_value(v: str) -> str:
    """Quote a versions: value to match the existing config.yaml style.

    Style rules (matching the shipped config.yaml):
      - Semver-like (`9.3.3`, `2.39.1`, `14.1`) → bare. Two-or-more dots,
        digits + dots only. YAML parses these as strings.
      - Pure-numeric date-stamps (`20260611`) → SINGLE QUOTED. Without
        quoting YAML would coerce to int 20260611 and downstream str
        operations would silently break.
      - Anything with letters or hyphens (`v2.4.27`, `13.0-alpine`,
        `latest`) → single-quoted for safety.
      - Already-quoted strings → pass through.
    """
    s = str(v)
    if s == "":
        return "''"
    if (s.startswith("'") and s.endswith("'")) or \
       (s.startswith('"') and s.endswith('"')):
        return s
    # Semver-style (TWO or more dots, digits + dots only) → bare.
    if re.match(r'^[0-9]+(\.[0-9]+){2,}$', s):
        return s
    # Single-dot decimals like `14.1`, `2.39` → bare (legitimate version).
    if re.match(r'^[0-9]+\.[0-9]+$', s):
        return s
    # Everything else (date-stamps, semver-with-suffix, v-prefixed,
    # alpine-suffixed, floating) gets single-quoted.
    return f"'{s}'"


def upgrade_intact(version: str = None, logger: Callable = None) -> Dict:
    """Upgrade Intact.AI Platform (backend + frontend) by pulling latest code.

    NOTE: This runs INSIDE the backend container. The upgrade orchestrator
    handles nginx restart and backend restart scheduling. This function
    just updates the code files.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    repo_dir = WORKDIR

    log("Starting Intact.AI Platform upgrade...", "info")

    # Git pull latest code
    log("Pulling latest code from repository...", "info")
    result = run_command("git pull origin main", cwd=repo_dir, logger=log)
    if not result['success']:
        result = run_command("git pull origin development", cwd=repo_dir, logger=log)
        if not result['success']:
            log("Warning: Could not pull latest code", "warning")

    # Fix file permissions (files pulled by root need correct ownership for future upgrades)
    log("Fixing file permissions...", "info")
    run_command("chown -R 1000:1000 /app/workdir/modules/backend/", logger=None)
    run_command("chown -R 1000:1000 /app/workdir/modules/nginx/html/", logger=None)

    # NOTE: Nginx and backend restarts are handled by the upgrade orchestrator
    # to support two-phase upgrades

    log("Intact.AI Platform code updated", "success")

    return {"success": True, "message": "Code updated"}


def upgrade_intact_offline(package_dir: str, version: str = None, logger: Callable = None,
                            run_id: Optional[str] = None) -> Dict:
    """Upgrade Intact.AI Platform from offline package source files.

    NOTE: This runs INSIDE the backend container. The upgrade orchestrator
    handles nginx restart and backend restart scheduling. This function
    just updates the code files.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    backend_dir = os.path.join(WORKDIR, 'modules', 'backend')
    nginx_html = os.path.join(WORKDIR, 'modules', 'nginx', 'html')

    # Layout resolution: packages built after the "GitHub release" Prepare
    # change ship the WHOLE repo at `source/intact/` (mirroring the GitHub
    # tree). Older packages ship just the two narrow paths at
    # `source/backend` and `source/frontend`. Prefer the new layout; fall
    # back so operators with an old package on disk still upgrade cleanly.
    intact_root = os.path.join(package_dir, 'source', 'intact')
    if os.path.isdir(intact_root):
        backend_source = os.path.join(intact_root, 'modules', 'backend')
        frontend_source = os.path.join(intact_root, 'modules', 'nginx', 'html')
    else:
        backend_source = os.path.join(package_dir, 'source', 'backend')
        frontend_source = os.path.join(package_dir, 'source', 'frontend')

    log("Starting Intact.AI Platform offline upgrade...", "info")

    # Check if directories exist AND have files (empty dirs are created even when Intact.AI not selected)
    has_backend = os.path.exists(backend_source) and os.listdir(backend_source)
    has_frontend = os.path.exists(frontend_source) and os.listdir(frontend_source)

    if not has_backend and not has_frontend:
        log("Intact.AI source not included in package, skipping...", "warning")
        return {"success": True, "skipped": True}

    # Merge the new release's versions: block into the operator's local
    # config.yaml. Without this, an operator on test-1 (config.yaml has
    # timesketch_opensearch: 2.11.0) who upgrades to test-2 would still
    # see 2.11.0 in their local config — and the upgrade workflow would
    # bundle the wrong opensearch image. Merge is text-level so
    # operator-local fields (domain, passwords, modules.*.enabled)
    # outside the versions: block are preserved verbatim.
    new_config_path = os.path.join(intact_root, 'config.yaml') \
        if os.path.isdir(intact_root) else None
    operator_config_path = os.path.join(WORKDIR, 'config.yaml')
    if new_config_path and os.path.isfile(new_config_path):
        log("Merging versions: block from new release config.yaml...", "info")
        try:
            merge_versions_from_new_config(
                new_config_path, operator_config_path, logger=log,
            )
        except Exception as e:
            log(f"  config.yaml merge raised "
                f"({type(e).__name__}: {e}); proceeding with existing "
                f"config.yaml — pins may be stale", "warning")

    # Copy backend source files
    if has_backend:
        log("Copying backend source files...", "info")
        run_command(f"cp -a {backend_source}/* {backend_dir}/", logger=log, run_id=run_id)

    # Copy frontend files
    if has_frontend:
        log("Copying frontend files...", "info")
        run_command(f"cp -a {frontend_source}/* {nginx_html}/", logger=log, run_id=run_id)

    # Stamp VERSION at the install root so the sidebar + Settings page
    # reflect the new release. Only present in the new `source/intact/`
    # layout — legacy packages that ship just source/backend + source/frontend
    # have no VERSION file to copy (and were built before the sidebar
    # version display existed, so reporting "unknown" until the next
    # upgrade is the right behaviour).
    version_source = os.path.join(intact_root, 'VERSION') if os.path.isdir(intact_root) else None
    if version_source and os.path.exists(version_source):
        version_dest = os.path.join(WORKDIR, 'VERSION')
        log("Copying VERSION file...", "info")
        run_command(f"cp -a {version_source} {version_dest}", logger=log, run_id=run_id)

    # Fix file permissions (files copied by root need correct ownership for future upgrades)
    log("Fixing file permissions...", "info")
    run_command("chown -R 1000:1000 /app/workdir/modules/backend/", logger=None)
    run_command("chown -R 1000:1000 /app/workdir/modules/nginx/html/", logger=None)

    # NOTE: Nginx and backend restarts are handled by the upgrade orchestrator
    # to support two-phase upgrades

    log("Intact.AI Platform files updated", "success")

    return {"success": True, "message": "Files updated"}
