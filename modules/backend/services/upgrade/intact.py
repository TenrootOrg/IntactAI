#!/usr/bin/env python3
"""Intact.AI Platform upgrade functions - combines backend and frontend."""

import os
import re
import shutil
from typing import Dict, Callable, Optional

from .base import (
    WORKDIR, run_command, update_env_file, load_docker_image,
    refresh_module_compose_file,
)


def _mirror_tree(src: str, dst: str, protect=(), logger=None) -> Dict:
    """Mirror src -> dst so dst becomes an EXACT copy of the new release's tree:
    overwrite every file from src AND delete files dst still has that src no
    longer ships. The delete half is the whole point — a plain ``cp -a src/*``
    only ever adds/overwrites, so a module retired upstream (e.g. the old
    services/agentic/chat.py, the pre-package analyzers.py/reports.py monoliths,
    engagement_routes.py, downloaded skill packs) would linger forever and could
    shadow its replacement. Mirroring removes them.

    Operator + runtime data is spared: top-level relpaths in ``protect`` (e.g.
    '.env', 'downloads') are never copied, never deleted, never descended into,
    and any __pycache__ is ignored (regenerated on import). Pure-Python so it
    works in the backend container without an rsync dependency.

    Returns {"copied": int, "deleted": [relpath, ...]}.
    """
    log = logger or (lambda m, l="info": None)
    protect = set(protect)

    def _spared(rel: str) -> bool:
        parts = rel.split('/')
        if '__pycache__' in parts:
            return True
        for p in protect:
            if rel == p or rel.startswith(p + '/'):
                return True
        return False

    def _rel(root_rel: str, name: str) -> str:
        return name if not root_rel else f"{root_rel}/{name}"

    # 1) DELETE: bottom-up so a stale dir empties out before we rmdir it.
    deleted = []
    for root, dirs, files in os.walk(dst, topdown=False):
        rr = os.path.relpath(root, dst)
        rr = '' if rr == '.' else rr
        for name in files:
            rel = _rel(rr, name)
            if _spared(rel):
                continue
            if not os.path.exists(os.path.join(src, rel)):
                try:
                    os.remove(os.path.join(root, name))
                    deleted.append(rel)
                except OSError:
                    pass
        for name in dirs:
            rel = _rel(rr, name)
            if _spared(rel):
                continue
            d = os.path.join(root, name)
            if not os.path.exists(os.path.join(src, rel)) and not os.listdir(d):
                try:
                    os.rmdir(d)
                    deleted.append(rel + '/')
                except OSError:
                    pass

    # 2) COPY: overwrite dst with everything src ships (minus spared paths).
    copied = 0
    for root, dirs, files in os.walk(src, topdown=True):
        rr = os.path.relpath(root, src)
        rr = '' if rr == '.' else rr
        dirs[:] = [d for d in dirs if not _spared(_rel(rr, d))]
        dst_root = dst if not rr else os.path.join(dst, rr)
        os.makedirs(dst_root, exist_ok=True)
        for name in files:
            rel = _rel(rr, name)
            if _spared(rel):
                continue
            shutil.copy2(os.path.join(root, name), os.path.join(dst_root, name))
            copied += 1

    log(f"  mirror {os.path.basename(dst.rstrip('/'))}: {copied} file(s) copied, "
        f"{len(deleted)} stale entr{'y' if len(deleted) == 1 else 'ies'} removed",
        "info")
    if deleted:
        preview = ", ".join(deleted[:12])
        more = f" (+{len(deleted) - 12} more)" if len(deleted) > 12 else ""
        log(f"    removed: {preview}{more}", "info")
    return {"copied": copied, "deleted": deleted}


# ---------------------------------------------------------------------------
# Anti-brick: source snapshot + importability gate.
#
# _mirror_tree replaces the LIVE backend source in place. Before these
# helpers, a release with a syntax error meant the backend crash-looped on
# import after the restart — whole platform down, manual recovery only,
# because no copy of the old tree existed and nothing verified the new tree
# before restarting into it.
# ---------------------------------------------------------------------------

ROLLBACK_ROOT = "/app/data/tmp"          # host bind mount — survives restarts
ROLLBACK_PREFIX = "intact-rollback-"


def snapshot_intact_tree(run_id, backend_dir, nginx_html, logger=None):
    """Snapshot the CURRENT install to ROLLBACK_ROOT/intact-rollback-<run_id>/
    ({backend/, frontend/}) so a bad release can be rolled back. Keeps exactly
    one snapshot (deletes previous intact-rollback-*). Excludes backend/.env
    (the mirror never touches it either) and frontend/downloads/ (large,
    regenerated); __pycache__ is skipped by _mirror_tree itself. Source-only
    tree is tens of MB — deps live in the image, not the tree.

    Returns the snapshot path, or None on failure (caller proceeds LOUDLY
    unprotected — a full disk shouldn't block upgrades, but must be visible).
    """
    log = logger or (lambda m, l="info": None)
    try:
        import glob as _glob
        tag = (run_id or 'manual').replace('/', '_')
        snap = os.path.join(ROLLBACK_ROOT, f"{ROLLBACK_PREFIX}{tag}")
        for old in _glob.glob(os.path.join(ROLLBACK_ROOT, f"{ROLLBACK_PREFIX}*")):
            if old != snap:
                shutil.rmtree(old, ignore_errors=True)
        shutil.rmtree(snap, ignore_errors=True)
        os.makedirs(os.path.join(snap, 'backend'), exist_ok=True)
        os.makedirs(os.path.join(snap, 'frontend'), exist_ok=True)
        _mirror_tree(backend_dir, os.path.join(snap, 'backend'),
                     protect=('.env',), logger=None)
        _mirror_tree(nginx_html, os.path.join(snap, 'frontend'),
                     protect=('downloads',), logger=None)
        log(f"  Rollback snapshot of the current install saved to {snap}", "info")
        return snap
    except Exception as e:
        log(f"  ⚠ NO ROLLBACK SNAPSHOT ({type(e).__name__}: {e}) — proceeding "
            f"UNPROTECTED: a broken release cannot be auto-rolled-back", "warning")
        return None


def restore_intact_tree(snapshot_dir, backend_dir, nginx_html, logger=None) -> bool:
    """Exact restore of the pre-upgrade install from a snapshot_intact_tree
    snapshot — including DELETING files the bad release added (mirror
    semantics both ways). Spares the same operator paths (.env, downloads/).
    """
    log = logger or (lambda m, l="info": None)
    try:
        _mirror_tree(os.path.join(snapshot_dir, 'backend'), backend_dir,
                     protect=('.env',), logger=log)
        _mirror_tree(os.path.join(snapshot_dir, 'frontend'), nginx_html,
                     protect=('downloads',), logger=log)
        run_command(f"chown -R 1000:1000 {backend_dir}/", logger=None)
        run_command(f"chown -R 1000:1000 {nginx_html}/", logger=None)
        log("  Previous install restored from rollback snapshot", "success")
        return True
    except Exception as e:
        log(f"  RESTORE FAILED ({type(e).__name__}: {e}) — snapshot kept at "
            f"{snapshot_dir} for manual recovery", "error")
        return False


def cleanup_rollback_snapshots(logger=None):
    """Remove all intact-rollback-* snapshots. Called when an upgrade finishes
    on code that has proven it boots (Phase 2 runs ON the new code, so reaching
    its finalizer is the proof). Failed upgrades keep their snapshot for manual
    recovery; the 168h sweep in base.sweep_stale_upgrade_staging reaps leftovers.
    """
    log = logger or (lambda m, l="info": None)
    import glob as _glob
    for snap in _glob.glob(os.path.join(ROLLBACK_ROOT, f"{ROLLBACK_PREFIX}*")):
        shutil.rmtree(snap, ignore_errors=True)
        log(f"  Removed rollback snapshot {os.path.basename(snap)} (upgrade "
            f"finished on the new code)", "info")


def verify_backend_compiles(backend_dir, old_requirements=None, logger=None,
                            swap_ready: bool = False) -> Dict:
    """Importability gate for a just-mirrored backend tree, run BEFORE the
    restart so a broken release can never take the platform down.

    1. `python3 -m compileall` over every shipped .py — catches the
       SyntaxError/IndentationError class (the container-can-never-boot bug).
       ALWAYS a hard gate — the image is baked from this same source, so broken
       source means a broken image too.
    2. requirements diff: a dependency the NEW tree requires that is not
       installed in the CURRENT image would crash at import time despite
       compiling — hard-fail the gate for those too (importing app.py live to
       probe would run Flask/DB side effects, so this diff is the safe proxy).
       SOFTENED when ``swap_ready`` (Wave F Full-mode): the container is about to
       be recreated from a NEW image that HAS the deps, so a missing package is
       expected, not a brick — log it and pass. Legacy restart path (swap_ready
       False) keeps the hard block: restarting the old image WOULD crash.

    Returns {"success": bool, "error": str}.
    """
    log = logger or (lambda m, l="info": None)
    # -f forces recompilation: without it, compileall trusts a .pyc whose
    # recorded source mtime+size still match — a same-second overwrite (or a
    # pathological mirror timing) could slip a broken file past the gate.
    r = run_command(
        f"python3 -m compileall -q -f -x '(__pycache__|downloads)' {backend_dir}",
        logger=None, timeout=300)
    if not r.get('success'):
        detail = ((r.get('stdout') or '') + '\n' + (r.get('stderr') or '')).strip()
        return {"success": False,
                "error": f"new backend fails to compile:\n{detail[-1500:]}"}

    # New deps the running image doesn't have -> import-time crash post-restart.
    try:
        def _req_names(path):
            names = set()
            if path and os.path.isfile(path):
                for line in open(path):
                    line = line.strip()
                    if not line or line.startswith(('#', '-')):
                        continue
                    name = re.split(r'[<>=!~\[; ]', line, 1)[0].strip().lower()
                    if name:
                        names.add(name)
            return names
        new_req = _req_names(os.path.join(backend_dir, 'requirements.txt'))
        old_req = _req_names(old_requirements)
        added = new_req - old_req
        if added:
            import importlib.metadata as _md
            missing = []
            for name in sorted(added):
                try:
                    _md.distribution(name)
                except _md.PackageNotFoundError:
                    missing.append(name)
            if missing:
                if swap_ready:
                    log(f"  New deps {', '.join(missing)} not in the current image "
                        f"— provided by the incoming backend image (Full-mode swap)",
                        "info")
                else:
                    return {"success": False,
                            "error": (f"new backend requires package(s) not installed "
                                      f"in the current image: {', '.join(missing)} — "
                                      f"restarting would crash at import. This release "
                                      f"needs a new backend IMAGE, not just source.")}
    except Exception as e:
        log(f"  requirements-diff check skipped ({e})", "warning")

    return {"success": True, "error": ""}


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


def recreate_tusd(logger: Callable = None) -> bool:
    """Apply the pinned tusd tag to the intact_tusd sidecar.

    tusd lives in the backend (intact-backbone) compose but is upgraded OUTSIDE
    the generic per-module transitive loop (the loop is keyed on 'intact', which
    has no modules/intact/.env). The restart handoff does `docker restart
    intact_tusd`, which keeps the OLD image — so a versions.backend_tusd bump
    would never take effect. This stamps TUSD_VERSION from config.yaml into the
    backend .env and `docker compose up -d tusd`, which recreates the container
    ONLY when the tag actually changed (idempotent no-op otherwise).

    Non-fatal by design: tusd is an upload sidecar, so a recreate hiccup must
    never roll back the whole intact upgrade — it logs a warning and returns
    False. Safe to call on every intact upgrade (online + offline).
    """
    log = logger or (lambda m, l="info": None)
    backend_dir = os.path.join(WORKDIR, 'modules', 'backend')
    try:
        tag = None
        cfg_path = os.path.join(WORKDIR, 'config.yaml')
        if os.path.isfile(cfg_path):
            import yaml
            with open(cfg_path) as f:
                cfg = yaml.safe_load(f) or {}
            tag = (cfg.get('versions') or {}).get('backend_tusd')
        if tag:
            update_env_file(os.path.join(backend_dir, '.env'), 'TUSD_VERSION',
                            str(tag), logger=log)
        r = run_command("docker compose up -d tusd", cwd=backend_dir,
                        logger=None, timeout=120)
        if not r.get('success'):
            log(f"tusd recreate returned nonzero (sidecar — continuing): "
                f"{(r.get('stderr') or r.get('stdout') or '')[:200]}", "warning")
            return False
        log(f"tusd sidecar recreated at {tag or 'pinned default'}", "success")
        return True
    except Exception as e:
        log(f"tusd recreate skipped ({type(e).__name__}: {e})", "warning")
        return False


def upgrade_intact(version: str = None, logger: Callable = None) -> Dict:
    """Upgrade Intact.AI Platform (backend + frontend) by pulling latest code.

    NOTE: This runs INSIDE the backend container. The upgrade orchestrator
    handles nginx restart and backend restart scheduling. This function
    just updates the code files.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    repo_dir = WORKDIR

    log("Starting Intact.AI Platform upgrade...", "info")

    # Anti-brick snapshot (legacy online path — kept for old-release resume
    # compatibility): capture the current trees before git mutates them.
    _backend_dir = os.path.join(WORKDIR, 'modules', 'backend')
    _nginx_html = os.path.join(WORKDIR, 'modules', 'nginx', 'html')
    snapshot = snapshot_intact_tree('online', _backend_dir, _nginx_html, logger=log)

    # Git pull latest code
    log("Pulling latest code from repository...", "info")
    result = run_command("git pull origin main", cwd=repo_dir, logger=log)
    if not result['success']:
        result = run_command("git pull origin development", cwd=repo_dir, logger=log)
        if not result['success']:
            log("Warning: Could not pull latest code", "warning")

    # Importability gate — same anti-brick contract as the offline path.
    gate = verify_backend_compiles(
        _backend_dir,
        old_requirements=(os.path.join(snapshot, 'backend', 'requirements.txt')
                          if snapshot else None),
        logger=log)
    if not gate["success"]:
        log("NEW BACKEND FAILED THE COMPILE GATE — restoring the previous "
            "install; the backend will NOT restart into broken code.", "error")
        if snapshot and restore_intact_tree(snapshot, _backend_dir, _nginx_html, logger=log):
            return {"success": False, "rolled_back": True,
                    "error": f"new backend failed the compile gate; previous "
                             f"version restored: {gate['error']}"}
        return {"success": False, "rolled_back": False,
                "error": f"new backend failed the compile gate AND no snapshot "
                         f"restore was possible: {gate['error']}"}

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

    # Apply any tusd pin bump (versions.backend_tusd) — recreate, since the
    # restart handoff only `docker restart`s tusd (keeps the old image).
    recreate_tusd(logger=log)

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


# ---------------------------------------------------------------------------
# Wave F — Full image-per-release backend (image swap + container recreate)
# ---------------------------------------------------------------------------
# The backend historically ran its code from HOST BIND-MOUNTS (./services etc.),
# so upgrades mirrored source + `docker restart` and never touched the image —
# which meant a release adding a pip dep was hard-blocked and base/pip CVEs never
# patched. Wave F makes the image the unit of release: when the target release's
# compose no longer bind-mounts the code (the "flip" — Full mode), the image
# carries engine+code and the upgrade SWAPS the image and RECREATES the
# container. Legacy source-mounted releases keep the byte-identical restart path.
#
# MASTER SWITCH: the target release's own backend docker-compose.yaml. If it
# still bind-mounts `./services:/app/services`, it's a legacy (restart) release;
# if that mount is gone, it's a Full (recreate) release. Single source of truth,
# derivable from the compose file alone — no extra config key, no drift.

_BACKEND_CODE_MOUNT_SENTINEL = re.compile(r'\./services:/app/services')


def backend_full_mode(compose_path: str) -> bool:
    """True when the backend compose runs code from the IMAGE (the Full,
    post-flip model — no ./services code bind-mount). False = legacy
    source-mounted (restart path). Missing/unreadable file → False (safe:
    default to the proven restart path)."""
    try:
        with open(compose_path) as f:
            return not _BACKEND_CODE_MOUNT_SENTINEL.search(f.read())
    except OSError:
        return False


def backend_target_tag() -> str:
    """Image tag the target release wants = versions.backend (the release id),
    read from the (post-merge) operator config.yaml. Falls back to '1.0.0' — the
    compose default and the literal install-day tag — so an absent/garbled key
    can never point at a bogus image."""
    try:
        import yaml
        with open(os.path.join(WORKDIR, 'config.yaml')) as f:
            cfg = yaml.safe_load(f) or {}
        tag = (cfg.get('versions') or {}).get('backend')
        tag = str(tag).strip() if tag not in (None, '') else ''
        return tag or '1.0.0'
    except Exception:
        return '1.0.0'


def running_backend_image() -> Optional[str]:
    """The image ref the LIVE intact_backend container was created from
    (ground truth for the old tag / swap detection). None if not resolvable."""
    r = run_command("docker inspect -f '{{.Config.Image}}' intact_backend",
                    logger=None, timeout=15)
    out = (r.get('stdout') or '').strip() if r.get('success') else ''
    return out or None


def ensure_backend_runtime_image(package_dir: str, target_tag: str,
                                 run_id: Optional[str] = None,
                                 logger: Callable = None) -> Dict:
    """Make `intact-backend:<target_tag>` present locally BEFORE any recreate.

    Order (idempotent — safe on crash-resume): already-present → refresh from the
    bundled tar if one ships (loads a moved dev tag's new bits) → load the bundled
    tar → FAIL. Runs in Phase 1 before the snapshot/mirror, so a FAIL leaves the
    platform fully up and untouched.

    Returns {"available": bool, "error": str}.
    """
    log = logger or (lambda m, l="info": None)
    image = f"intact-backend:{target_tag}"
    tar = (os.path.join(package_dir, 'images', f'intact-backend-{target_tag}.tar')
           if package_dir else None)

    present = run_command(f"docker image inspect {image}",
                          logger=None, timeout=30).get('success')
    if present:
        # Full mode always ships a freshly-baked image; refresh from the tar so a
        # moved tag (dev 'development') picks up new bits. Offline already loaded
        # it via load_all_bundled_images — this is a cheap no-op there.
        if tar and os.path.isfile(tar):
            load_docker_image(tar, logger=log, run_id=run_id)
        return {"available": True, "error": ""}

    if tar and os.path.isfile(tar):
        log(f"  Loading bundled backend image {os.path.basename(tar)}...", "info")
        res = load_docker_image(tar, logger=log, run_id=run_id)
        if res.get('success') and run_command(
                f"docker image inspect {image}", logger=None, timeout=30).get('success'):
            return {"available": True, "error": ""}

    return {"available": False,
            "error": (f"backend runtime image {image} is neither present nor "
                      f"bundled in the package — this Full-mode release cannot be "
                      f"applied. Re-prepare the package with a Wave-F-capable "
                      f"release (the prepare step bakes + bundles the image).")}


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

    # ── Wave F: Full-mode image-swap detection (BEFORE snapshot/mirror) ──────
    # Decide from the TARGET release's own backend compose whether this is a
    # Full-mode release (image carries the code → swap + recreate) or a legacy
    # source-mounted release (mirror + restart). Runs before anything is touched
    # so a missing image FAILS the module with the platform still fully up.
    needs_swap = False
    target_tag = backend_target_tag()          # = versions.backend (post-merge)
    old_image = running_backend_image()
    if has_backend:
        target_compose = os.path.join(backend_source, 'docker-compose.yaml')
        if backend_full_mode(target_compose):
            needs_swap = True
            log(f"Full-mode release detected — backend runs from image "
                f"intact-backend:{target_tag} (swap + recreate)", "info")
            _ens = ensure_backend_runtime_image(package_dir, target_tag,
                                                run_id=run_id, logger=log)
            if not _ens["available"]:
                log(f"BACKEND RUNTIME IMAGE UNAVAILABLE — aborting the intact "
                    f"upgrade with the platform untouched. {_ens['error']}", "error")
                return {"success": False, "rolled_back": False,
                        "needs_swap": True, "error": _ens["error"]}

    # Anti-brick snapshot: capture the CURRENT install before the mirror
    # replaces it in place, so a broken release can be rolled back instead of
    # crash-looping the platform. Lives on the /app/data bind mount (survives
    # restarts); deleted at Phase-2 success, swept after 168h otherwise.
    snapshot = snapshot_intact_tree(run_id, backend_dir, nginx_html, logger=log)

    # Mirror backend + frontend so the install becomes an EXACT copy of the new
    # release (overwrite everything AND delete files the release retired) — a
    # plain `cp -a src/*` only ever adds, leaving stale modules to shadow their
    # replacements. Operator/runtime data under these trees is spared:
    #   backend  -> .env (operator-rotated secrets; also backed up/restored)
    #   frontend -> downloads/ (Velociraptor client binaries, large; regenerated)
    # __pycache__ is always ignored. config.yaml lives at WORKDIR root (outside
    # both trees) and is version-merged separately, so it is never touched here.
    # Safety: the mirror DELETES install files the source lacks, so a partial or
    # corrupt package could wipe a healthy install. Only mirror when the source
    # carries a sentinel proving it's a real release tree; otherwise fall back to
    # the old additive `cp -a` (never deletes) and warn.
    if has_backend:
        if os.path.exists(os.path.join(backend_source, 'app.py')):
            log("Mirroring backend source files (overwrite + prune retired)...", "info")
            _mirror_tree(backend_source, backend_dir, protect=('.env',), logger=log)
        else:
            log("  backend source missing app.py — incomplete package; using "
                "additive copy (no prune) to avoid wiping the install", "warning")
            run_command(f"cp -a {backend_source}/* {backend_dir}/", logger=log, run_id=run_id)

    # Copy frontend files
    if has_frontend:
        if os.path.exists(os.path.join(frontend_source, 'index.html')):
            log("Mirroring frontend files (overwrite + prune retired)...", "info")
            _mirror_tree(frontend_source, nginx_html, protect=('downloads',), logger=log)
        else:
            log("  frontend source missing index.html — incomplete package; using "
                "additive copy (no prune) to avoid wiping the install", "warning")
            run_command(f"cp -a {frontend_source}/* {nginx_html}/", logger=log, run_id=run_id)

    # Refresh the velociraptor IMAGE BUILD FILES (Dockerfile, entrypoint.sh,
    # bundled_artifacts/) from the new release source. Velociraptor is the only
    # module whose image is built locally; its bake reads these on-disk files,
    # and they are NOT part of the backend/frontend mirror above — so without
    # this an upgraded box keeps stale build files and re-bakes the old,
    # bundle-less image (server then missing ~400 artifacts). Only with the
    # full-repo layout (source/intact/); harmless no-op otherwise.
    if os.path.isdir(intact_root):
        try:
            from .velociraptor import refresh_velociraptor_build_files
            refresh_velociraptor_build_files(
                os.path.join(intact_root, 'modules', 'velociraptor'),
                os.path.join(WORKDIR, 'modules', 'velociraptor'),
                logger=log)
        except Exception as e:
            log(f"  Could not refresh velociraptor build files: {e}", "warning")

        # Refresh every sidecar module's docker-compose.yaml from the new
        # release source. These modules each version-upgrade independently
        # (their own upgrade_<module>() only bumps .env pins and reuses
        # whatever compose file is already on disk) — nothing else ever
        # refreshes the compose file itself, so a box installed before a
        # structural compose change (a mount, a healthcheck, a capability)
        # would otherwise run it FOREVER, through any number of upgrades.
        # File-only refresh: never touches config/, secrets/, or data under
        # the module dir. Takes effect the next time that module's compose
        # comes up (its own version bump, or an operator restart) — this
        # step alone does not recreate any container.
        for _sidecar in ('velociraptor', 'iris', 'timesketch', 'elk',
                          'portainer', 'volweb', 'nginx'):
            try:
                refresh_module_compose_file(_sidecar, intact_root, logger=log)
            except Exception as e:
                log(f"  Could not refresh {_sidecar} compose file: {e}", "warning")

    # Importability gate — BEFORE stamping VERSION and before the orchestrator
    # can schedule the restart. The orchestrator only saves awaiting_restart +
    # restarts inside its success branch, so returning success:False here
    # guarantees the platform keeps running the OLD code.
    if has_backend:
        log("Verifying the new backend compiles (anti-brick gate)...", "info")
        old_reqs = (os.path.join(snapshot, 'backend', 'requirements.txt')
                    if snapshot else None)
        gate = verify_backend_compiles(backend_dir, old_requirements=old_reqs,
                                       logger=log, swap_ready=needs_swap)
        if not gate["success"]:
            log("NEW BACKEND FAILED THE COMPILE GATE — restoring the previous "
                "install; the backend will NOT restart into broken code.", "error")
            if snapshot and restore_intact_tree(snapshot, backend_dir, nginx_html, logger=log):
                return {"success": False, "rolled_back": True,
                        "error": f"new backend failed the compile gate; previous "
                                 f"version restored: {gate['error']}"}
            return {"success": False, "rolled_back": False,
                    "error": f"new backend failed the compile gate AND no snapshot "
                             f"restore was possible — DO NOT RESTART the backend "
                             f"manually until fixed: {gate['error']}"}
        log("  ✓ New backend compiles; no missing image dependencies", "success")

    # Stamp WORKDIR/VERSION so the sidebar + Settings reflect the new release.
    # AFTER the gate on purpose: a failed gate must not leave the UI claiming
    # the new version while old code runs. Shared with the Phase-2 resume
    # finalizer (services/upgrade.__init__) — see stamp_intact_version.
    stamp_intact_version(package_dir, version, logger=log, run_id=run_id)

    # Fix file permissions (files copied by root need correct ownership for future upgrades)
    log("Fixing file permissions...", "info")
    run_command("chown -R 1000:1000 /app/workdir/modules/backend/", logger=None)
    run_command("chown -R 1000:1000 /app/workdir/modules/nginx/html/", logger=None)

    # Apply any tusd pin bump (versions.backend_tusd) — recreate, since the
    # restart handoff only `docker restart`s tusd (keeps the old image).
    recreate_tusd(logger=log)

    # NOTE: Nginx and backend restarts are handled by the upgrade orchestrator
    # to support two-phase upgrades

    log("Intact.AI Platform files updated", "success")

    # Wave F: hand the swap decision + rollback coordinates to the orchestrator,
    # which dispatches recreate-vs-restart in the Phase-1 success branch.
    return {"success": True, "message": "Files updated",
            "needs_swap": needs_swap,
            "target_tag": target_tag,
            "old_image": old_image,
            "snapshot": snapshot}
