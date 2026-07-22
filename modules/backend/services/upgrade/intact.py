#!/usr/bin/env python3
"""Intact.AI Platform upgrade functions - combines backend and frontend."""

import os
import re
import shutil
from typing import Dict, Callable, Optional

from .base import WORKDIR, run_command, load_docker_image


# ─────────────────────────────────────────────────────────────────────────────
# Full-mode backend machinery (ported verbatim from intact-20260721).
#
# This release runs the backend from the baked image intact-backend:<release>,
# never from host code bind-mounts. Phase 1 therefore LOADS the image shipped in
# the package and RECREATES the container onto it before Phase 2 runs, so the
# NEW release's code drives the rest of its own upgrade. See WAVE_F_PLAN.md.
# ─────────────────────────────────────────────────────────────────────────────

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
    read from the (post-merge) operator config.yaml. The backend image is
    always named after the actual release — never a static placeholder like
    the old '1.0.0' — so an absent/garbled config key falls back to the
    release's own VERSION file (the same source of truth every other release
    identifier comes from), and only as a last resort to 'development'."""
    try:
        import yaml
        with open(os.path.join(WORKDIR, 'config.yaml')) as f:
            cfg = yaml.safe_load(f) or {}
        tag = (cfg.get('versions') or {}).get('backend')
        tag = str(tag).strip() if tag not in (None, '') else ''
        if tag:
            return tag
    except Exception:
        pass
    try:
        with open(os.path.join(WORKDIR, 'VERSION')) as f:
            v = f.read().strip()
        if v:
            return v
    except Exception:
        pass
    return 'development'


def running_backend_image() -> Optional[str]:
    """The image ref the LIVE intact_backend container was created from
    (ground truth for the old tag / swap detection). None if not resolvable."""
    r = run_command("docker inspect -f '{{.Config.Image}}' intact_backend",
                    logger=None, timeout=15)
    out = (r.get('stdout') or '').strip() if r.get('success') else ''
    return out or None


_BACKEND_FINGERPRINT_SKIP_DIRS = {'__pycache__', 'downloads', 'report_downloads',
                                  'upgrade_packages', 'upload_data'}
_BACKEND_FINGERPRINT_SKIP_FILES = {'.env'}


def backend_source_fingerprint(backend_dir: Optional[str] = None) -> str:
    """SHA-256 over every file's actual bytes under modules/backend/ (sorted
    by relative path), skipping .env/runtime-only dirs. Deliberately NOT a
    comparison of built Docker image IDs — those are sensitive to file mtimes
    in the build context (routine git checkouts/chown touch mtimes with zero
    content change) and are not guaranteed reproducible across separate
    `docker build` invocations even for byte-identical source. This is a pure
    content hash: the only thing that can move it is an actual code change."""
    import hashlib
    root = backend_dir or os.path.join(WORKDIR, 'modules', 'backend')
    h = hashlib.sha256()
    try:
        paths = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in sorted(dirnames) if d not in _BACKEND_FINGERPRINT_SKIP_DIRS]
            for fn in sorted(filenames):
                if fn in _BACKEND_FINGERPRINT_SKIP_FILES:
                    continue
                paths.append(os.path.join(dirpath, fn))
        for p in sorted(paths):
            rel = os.path.relpath(p, root).encode('utf-8', 'replace')
            h.update(rel)
            try:
                with open(p, 'rb') as f:
                    h.update(f.read())
            except OSError:
                pass
    except Exception:
        return ''
    return h.hexdigest()


_BACKEND_FINGERPRINT_FILE = '/app/data/backend-source.applied.sha256'


def record_backend_source_fingerprint(logger: Callable = None) -> None:
    """Save the CURRENT live tree's fingerprint as 'what's actually running'
    — called right after a successful swap so the next boot's drift check has
    a baseline to compare against."""
    log = logger or (lambda m, l="info": None)
    try:
        fp = backend_source_fingerprint()
        if fp:
            with open(_BACKEND_FINGERPRINT_FILE, 'w') as f:
                f.write(fp + '\n')
    except Exception as e:
        log(f"  (could not record backend source fingerprint: {e})", "warning")


def read_recorded_backend_source_fingerprint() -> Optional[str]:
    try:
        with open(_BACKEND_FINGERPRINT_FILE) as f:
            v = f.read().strip()
        return v or None
    except OSError:
        return None


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

    # ── Full-mode image-swap detection (BEFORE anything is mutated) ──────────
    # This release runs the backend from a baked image, so Phase 1 loads the
    # image the package ships and hands off to a RECREATE — the new code then
    # drives Phase 2. Deciding (and failing) here, before the snapshot and the
    # source copy, means a package missing its backend image aborts with the
    # platform completely untouched.
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
        else:
            log("Target release is legacy source-mounted (no backend image) — "
                "using the restart path.", "info")

    # Anti-brick snapshot: capture the CURRENT install before the copy replaces
    # it, so a broken release can be rolled back by the recreate helper instead
    # of crash-looping the platform. Lives on the /app/data bind mount.
    snapshot = snapshot_intact_tree(run_id, backend_dir, nginx_html, logger=log)

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

    return {"success": True, "message": "Files updated",
            "needs_swap": needs_swap, "target_tag": target_tag,
            "old_image": old_image, "snapshot": snapshot}
