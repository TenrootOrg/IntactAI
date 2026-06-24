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
                "skipped": skipped, "backup_path": None}

    # Capture the operator's pre-merge structure for the safety assert:
    # everything OUTSIDE the versions: block must be byte-identical
    # after the merge. If it isn't, abort and leave the file untouched
    # — protects the operator's domain, passwords, modules.*.enabled,
    # and any custom top-level keys from being clobbered by a parser
    # bug.
    try:
        with open(operator_config_path, 'r') as f:
            pre_text = f.read()
    except Exception as e:
        log(f"  [config-merge] pre-read failed for {operator_config_path}: {e}",
            "error")
        return {"success": False, "updated": {}, "added": {}, "skipped": [],
                "backup_path": None}

    # Take a sibling backup so the orchestrator can roll back on
    # upgrade failure. Backup path returned to caller; caller is
    # responsible for delete-on-success / restore-on-failure.
    backup_path = operator_config_path + ".pre-upgrade-backup"
    try:
        if not os.path.exists(backup_path):
            # First merge attempt of this upgrade — capture pristine state.
            with open(backup_path, 'w') as f:
                f.write(pre_text)
            log(f"  [config-merge] backed up operator config.yaml -> "
                f"{backup_path} (will be restored if upgrade fails)",
                "info")
        else:
            log(f"  [config-merge] backup already exists at {backup_path} "
                f"(prior upgrade attempt). Not overwriting — that file "
                f"holds the last known-good config; current operator "
                f"file is the WIP one being re-merged.", "info")
    except Exception as e:
        log(f"  [config-merge] backup write failed ({type(e).__name__}: "
            f"{e}); refusing to merge without a rollback path",
            "error")
        return {"success": False, "updated": {}, "added": {}, "skipped": [],
                "backup_path": None}

    lines = pre_text.splitlines()

    # Plan insertion points for ADDED keys (new in the release, not in
    # operator's file). Group siblings: a new `iris_<x>` lands right
    # below the last existing `iris_*` (or `iris:`) line, not appended
    # at the bottom of the versions: block. Same for new primary pins
    # — they land near other primary pins, not interleaved with sidecar
    # entries. Falls back to end-of-block when no sibling anchor exists.
    def _key_prefix(k):
        """For `iris_rabbitmq` → 'iris'. For `iris` (primary) → 'iris'.
        Used to group sibling keys for insertion-point grouping.
        """
        return k.split('_', 1)[0]

    def _is_primary(k):
        """Primary pins have no underscore (or are the legacy
        `velociraptor_legacy` exception which is conceptually primary
        even though it has an underscore).
        """
        return '_' not in k or k == 'velociraptor_legacy'

    # Build map from existing-key → its line index in the source file
    existing_key_lines = {}
    in_block_scan = False
    for idx, raw in enumerate(lines):
        line = raw.rstrip()
        if not in_block_scan:
            if re.match(r'^versions\s*:\s*$', line):
                in_block_scan = True
            continue
        stripped_lead = line[:len(line) - len(line.lstrip())]
        if line.strip() != "" and not line.lstrip().startswith("#") \
                and len(stripped_lead) == 0:
            break
        m = re.match(r'^\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*.+', line)
        if m:
            existing_key_lines[m.group(1)] = idx

    # For each added key, pick its "insertion anchor" (the line index
    # AFTER which it should be inserted). Anchor priority:
    #   1. Last existing line whose key shares the `<prefix>_` family
    #      with the new key (sidecar grouping).
    #   2. Last existing line for the primary (so `iris_rabbitmq` lands
    #      below `iris:` if no `iris_*` exists yet).
    #   3. Last existing PRIMARY line if the new key is also primary.
    #   4. None (fall through to end-of-block append).
    insertion_groups = {}  # anchor_line_idx → list of (key, value) to insert
    end_of_block_appends = []  # keys with no anchor at all
    for k, v in added.items():
        anchor_idx = None
        prefix = _key_prefix(k)
        if _is_primary(k):
            # Anchor: last primary key in the existing file
            primary_lines = [(idx, key) for key, idx in existing_key_lines.items()
                              if _is_primary(key)]
            if primary_lines:
                anchor_idx = max(idx for idx, _ in primary_lines)
        else:
            # Sidecar — anchor: last `<prefix>_<x>` line, else `<prefix>:` line
            family_lines = [idx for key, idx in existing_key_lines.items()
                             if key.startswith(f"{prefix}_") or key == prefix]
            if family_lines:
                anchor_idx = max(family_lines)
        if anchor_idx is not None:
            insertion_groups.setdefault(anchor_idx, []).append((k, v))
        else:
            end_of_block_appends.append((k, v))

    out_lines = []
    in_block = False
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
            # End of versions: block reached. Inject any anchorless
            # `added` keys (modules with no existing sibling) BEFORE
            # this line so they live inside the block.
            if end_of_block_appends:
                for k, v in end_of_block_appends:
                    out_lines.append(f"  {k}: {_format_value(v)}")
                out_lines.append("")  # blank line before next top-level
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

        # If this line is an anchor for sibling-grouped insertions,
        # emit the new keys IMMEDIATELY AFTER it so a new
        # `iris_<sidecar>` lands right under the last `iris_*` line
        # (or `iris:` itself) — preserving config.yaml's logical grouping.
        if i in insertion_groups:
            # Use the same indent as the line we just emitted (typically
            # two spaces matching the rest of the block).
            indent_match = re.match(r'^(\s+)', line)
            indent_str = indent_match.group(1) if indent_match else "  "
            for k, v in insertion_groups[i]:
                out_lines.append(f"{indent_str}{k}: {_format_value(v)}")

    # Edge case: versions: block was the LAST block in the file (no
    # following de-indented line triggered the end-of-block injection
    # above). Append the anchorless adds at the tail.
    if in_block and end_of_block_appends:
        for k, v in end_of_block_appends:
            out_lines.append(f"  {k}: {_format_value(v)}")

    new_text = '\n'.join(out_lines) + '\n'

    # ── SAFETY ASSERT ──
    # The merge MUST only touch the versions: block. Anything outside
    # it (domain, modules.*.password, modules.*.id, project_name,
    # comments, options:, etc.) must be byte-identical to the pre-merge
    # text. If the diff touches anything else, abort: don't write,
    # restore from the backup we just took. Protects operator
    # credentials + per-host config from a parser bug.
    def _strip_versions_block(text):
        """Return everything in `text` outside the versions: block."""
        out = []
        in_block = False
        for raw in text.splitlines():
            line = raw.rstrip()
            if not in_block:
                if re.match(r'^versions\s*:\s*$', line):
                    in_block = True
                    out.append(line)  # keep the heading line itself
                    continue
                out.append(line)
                continue
            stripped_lead = line[:len(line) - len(line.lstrip())]
            if line.strip() != "" and not line.lstrip().startswith("#") \
                    and len(stripped_lead) == 0:
                in_block = False
                out.append(line)
        return "\n".join(out)

    pre_outside = _strip_versions_block(pre_text)
    new_outside = _strip_versions_block(new_text)
    if pre_outside != new_outside:
        log(f"  [config-merge] SAFETY ASSERT FAILED: merge changed lines "
            f"outside the versions: block. Refusing to write — operator "
            f"config left untouched. Backup at {backup_path} (also "
            f"unchanged from pre-merge state).", "error")
        # Diagnostic: show the first diverging line
        import difflib
        diff_lines = list(difflib.unified_diff(
            pre_outside.splitlines(), new_outside.splitlines(),
            fromfile='pre-merge (outside versions:)',
            tofile='post-merge (outside versions:)', lineterm=''))[:20]
        for d in diff_lines:
            log(f"    {d}", "error")
        return {"success": False, "updated": {}, "added": {},
                "skipped": [], "backup_path": backup_path,
                "error": "safety assert failed"}

    try:
        with open(operator_config_path, 'w') as f:
            f.write(new_text)
    except Exception as e:
        log(f"  [config-merge] write failed for {operator_config_path}: {e}",
            "error")
        return {"success": False, "updated": updated, "added": added,
                "skipped": skipped, "backup_path": backup_path}

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
            "skipped": skipped, "backup_path": backup_path}


def revert_module_versions_from_backup(module_name: str,
                                        operator_config_path: str,
                                        logger: Callable = None) -> Dict:
    """Revert ONLY the failing module's versions: keys from the backup.

    Called by the orchestrator's per-module error handler. If timesketch
    upgrade fails, this reverts `timesketch`, `timesketch_postgres`,
    `timesketch_opensearch`, `timesketch_redis`, `timesketch_nginx`
    back to their pre-merge values. iris/volweb/etc. keep their new
    pins — they're independent.

    Scoping rule: a versions: key belongs to module M iff the key is
    exactly `M` (primary pin) OR starts with `M_` (sidecar pin). This
    matches the flat-naming convention adopted by the 2026-06-14
    refactor (timesketch_opensearch, iris_rabbitmq, volweb_postgres,
    etc.).

    Backup is preserved on disk after revert — subsequent failures of
    OTHER modules can still revert their own pins. Cleanup happens
    once the whole workflow finishes (cleanup_config_yaml_backup).

    Returns: {"success": bool, "reverted": {key: (was, restored), ...}}
    """
    log = logger or (lambda msg, level="info": None)
    backup_path = operator_config_path + ".pre-upgrade-backup"
    if not os.path.isfile(backup_path):
        log(f"  [config-rollback {module_name}] no backup at {backup_path} — "
            f"nothing to revert (the merge probably didn't run on this "
            f"upgrade)", "info")
        return {"success": False, "reverted": {}}

    try:
        with open(backup_path) as f:
            backup_text = f.read()
        with open(operator_config_path) as f:
            current_text = f.read()
    except Exception as e:
        log(f"  [config-rollback {module_name}] read failed: {e}", "error")
        return {"success": False, "reverted": {}}

    # Extract versions: blocks from both files using the same parser the
    # merge uses (text-level, comment-preserving).
    backup_versions = _extract_versions_text(backup_text)
    current_versions = _extract_versions_text(current_text)

    # Which keys belong to this module?
    def _is_module_key(k):
        return k == module_name or k.startswith(f"{module_name}_")

    reverted = {}
    new_versions = dict(current_versions)
    for key, backup_val in backup_versions.items():
        if not _is_module_key(key):
            continue
        cur_val = current_versions.get(key)
        if cur_val != backup_val:
            new_versions[key] = backup_val
            reverted[key] = (cur_val, backup_val)
    # Keys the operator's current file has but the backup doesn't (new
    # additions from the merge) and that belong to this module: drop.
    for key in list(current_versions.keys()):
        if not _is_module_key(key):
            continue
        if key not in backup_versions:
            del new_versions[key]
            reverted[key] = (current_versions[key], None)  # None = removed

    if not reverted:
        log(f"  [config-rollback {module_name}] no pins to revert "
            f"(versions already match backup)", "info")
        return {"success": True, "reverted": {}}

    # Rewrite the operator's config.yaml with the reverted versions:
    # block. Use the merge's text-level writer so comments/structure
    # are preserved.
    new_text = _rewrite_versions_block(current_text, new_versions)

    # Safety assert: only versions: block changed.
    def _strip_versions(text):
        out = []
        in_block = False
        for raw in text.splitlines():
            line = raw.rstrip()
            if not in_block:
                if re.match(r'^versions\s*:\s*$', line):
                    in_block = True
                    out.append(line)
                    continue
                out.append(line)
                continue
            stripped_lead = line[:len(line) - len(line.lstrip())]
            if line.strip() != "" and not line.lstrip().startswith("#") \
                    and len(stripped_lead) == 0:
                in_block = False
                out.append(line)
        return "\n".join(out)
    if _strip_versions(current_text) != _strip_versions(new_text):
        log(f"  [config-rollback {module_name}] SAFETY ASSERT failed — "
            f"revert touched lines outside versions: block; aborting",
            "error")
        return {"success": False, "reverted": {}}

    try:
        with open(operator_config_path, 'w') as f:
            f.write(new_text)
    except Exception as e:
        log(f"  [config-rollback {module_name}] write failed: {e}", "error")
        return {"success": False, "reverted": {}}

    for key, (cur, restored) in reverted.items():
        if restored is None:
            log(f"  [config-rollback {module_name}] removed versions.{key} "
                f"(was added by merge; now reverted; was: {cur})", "warning")
        else:
            log(f"  [config-rollback {module_name}] reverted versions.{key}: "
                f"{cur} -> {restored}", "warning")
    return {"success": True, "reverted": reverted}


def _extract_versions_text(text: str) -> Dict[str, str]:
    """Parse `<key>: <value>` lines from a config.yaml's versions: block.
    Same logic the merge helper uses, exposed for the rollback path.
    """
    in_block = False
    out = {}
    for raw in text.splitlines():
        line = raw.rstrip()
        if not in_block:
            if re.match(r'^versions\s*:\s*$', line):
                in_block = True
            continue
        stripped_lead = line[:len(line) - len(line.lstrip())]
        if line.strip() == "" or line.lstrip().startswith("#"):
            continue
        if len(stripped_lead) == 0:
            break
        m = re.match(r'^\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+?)\s*(?:#.*)?$', line)
        if m:
            val = m.group(2).strip()
            if (val.startswith("'") and val.endswith("'")) or \
               (val.startswith('"') and val.endswith('"')):
                val = val[1:-1]
            out[m.group(1)] = val
    return out


def _rewrite_versions_block(text: str, desired_versions: Dict[str, str]) -> str:
    """Re-emit `text` with the versions: block's `<key>: <value>` lines
    replaced to match `desired_versions`. Keys not in the original block
    get appended at the end of the block. Keys removed from
    `desired_versions` are dropped from the output. Everything outside
    the versions: block is preserved verbatim.
    """
    lines = text.splitlines()
    out_lines = []
    in_block = False
    seen = set()
    for raw in lines:
        line = raw.rstrip()
        if not in_block:
            out_lines.append(raw)
            if re.match(r'^versions\s*:\s*$', line):
                in_block = True
            continue

        stripped_lead = line[:len(line) - len(line.lstrip())]
        if line.strip() != "" and not line.lstrip().startswith("#") \
                and len(stripped_lead) == 0:
            # End of versions: block — inject any keys we still owe
            for k, v in desired_versions.items():
                if k not in seen:
                    out_lines.append(f"  {k}: {_format_value(v)}")
                    seen.add(k)
            out_lines.append(raw)
            in_block = False
            continue

        m = re.match(r'^(\s+)([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+?)(\s*(?:#.*)?)\s*$',
                     line)
        if m:
            indent = m.group(1)
            key = m.group(2)
            trailing_comment = m.group(4) or ""
            if key in desired_versions:
                new_val = desired_versions[key]
                out_lines.append(f"{indent}{key}: {_format_value(new_val)}{trailing_comment}")
                seen.add(key)
            # If key isn't in desired_versions → drop the line (revert removed it)
        else:
            out_lines.append(raw)

    # If versions: was the last block, inject any still-owed keys
    if in_block:
        for k, v in desired_versions.items():
            if k not in seen:
                out_lines.append(f"  {k}: {_format_value(v)}")
    return "\n".join(out_lines) + "\n"


def cleanup_config_yaml_backup(operator_config_path: str,
                                logger: Callable = None) -> None:
    """Delete the pre-merge backup after a successful upgrade.
    Caller commits to the new versions: block; the next upgrade
    will take a fresh backup.
    """
    log = logger or (lambda msg, level="info": None)
    backup_path = operator_config_path + ".pre-upgrade-backup"
    if os.path.isfile(backup_path):
        try:
            os.remove(backup_path)
            log(f"  [config-cleanup] removed {backup_path} (upgrade "
                f"succeeded; new versions: block is committed)", "info")
        except Exception as e:
            log(f"  [config-cleanup] couldn't remove backup "
                f"({type(e).__name__}: {e}); harmless leftover",
                "warning")


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

    # A non-release branch (e.g. `development`) carries no stamped VERSION file
    # (the stamp action only commits it on a published release), so after the
    # pull WORKDIR/VERSION may be missing/empty → the sidebar shows "unknown".
    # Fall back to the target version when one was provided.
    version_dest = os.path.join(WORKDIR, 'VERSION')
    try:
        _have = os.path.exists(version_dest) and bool(open(version_dest).read().strip())
    except Exception:
        _have = False
    if not _have and version and version != 'from_package':
        log(f"No stamped VERSION file — writing target version '{version}'...", "info")
        try:
            with open(version_dest, 'w') as _vf:
                _vf.write(str(version).strip() + "\n")
        except Exception as e:
            log(f"  Could not stamp VERSION ({e})", "warning")

    # NOTE: Nginx and backend restarts are handled by the upgrade orchestrator
    # to support two-phase upgrades

    log("Intact.AI Platform code updated", "success")

    return {"success": True, "message": "Code updated"}


def stamp_intact_version(package_dir, version=None, logger=None, run_id=None):
    """Write WORKDIR/VERSION for the just-applied intact release so the sidebar
    + Settings show a real version instead of "unknown". Precedence:
      1. a release-stamped source/intact/VERSION in the package — copy verbatim
         (the GitHub release action commits it)
      2. manifest.json -> versions.intact
      3. the passed `version` (ignored when it's the 'from_package' sentinel)

    Shared by upgrade_intact_offline (Phase 1, pre-restart) AND the Phase-2
    resume finalizer (post-restart, NEW code) so the stamp is governed by
    whichever code is newest. Idempotent — being called in both phases is
    harmless. Returns the stamped string, or None if nothing could be resolved.
    """
    log = logger or (lambda m, l="info": None)
    version_dest = os.path.join(WORKDIR, 'VERSION')
    intact_root = os.path.join(package_dir, 'source', 'intact') if package_dir else None
    version_source = os.path.join(intact_root, 'VERSION') \
        if (intact_root and os.path.isdir(intact_root)) else None

    if version_source and os.path.exists(version_source):
        log("Stamping VERSION from release-built package source...", "info")
        run_command(f"cp -a {version_source} {version_dest}", logger=log, run_id=run_id)
        try:
            return open(version_dest).read().strip()
        except Exception:
            return None

    # No release-stamped file (dev-built package). Resolve from the manifest,
    # then the passed version; skip the 'from_package' sentinel.
    stamp = version if (version and version != 'from_package') else None
    if not stamp and package_dir:
        try:
            import json as _json
            with open(os.path.join(package_dir, 'manifest.json')) as _mf:
                stamp = ((_json.load(_mf).get('versions') or {}).get('intact'))
        except Exception:
            stamp = None
    if stamp and stamp != 'from_package':
        log(f"Stamping VERSION = {stamp} (no release-stamped file in source)...", "info")
        try:
            with open(version_dest, 'w') as _vf:
                _vf.write(str(stamp).strip() + "\n")
            return stamp
        except Exception as e:
            log(f"  Could not stamp VERSION ({e}); sidebar may show 'unknown'", "warning")
            return None
    log("  No VERSION in package source and no manifest version — sidebar shows "
        "'unknown' until a release-built upgrade", "warning")
    return None


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

    # Stamp WORKDIR/VERSION so the sidebar + Settings reflect the new release.
    # Shared with the Phase-2 resume finalizer (services/upgrade.__init__) so
    # whichever code is NEWEST governs the stamp — see stamp_intact_version.
    stamp_intact_version(package_dir, version, logger=log, run_id=run_id)

    # Fix file permissions (files copied by root need correct ownership for future upgrades)
    log("Fixing file permissions...", "info")
    run_command("chown -R 1000:1000 /app/workdir/modules/backend/", logger=None)
    run_command("chown -R 1000:1000 /app/workdir/modules/nginx/html/", logger=None)

    # NOTE: Nginx and backend restarts are handled by the upgrade orchestrator
    # to support two-phase upgrades

    log("Intact.AI Platform files updated", "success")

    return {"success": True, "message": "Files updated"}
