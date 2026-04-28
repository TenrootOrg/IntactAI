#!/usr/bin/env python3
"""
Skills download service — refreshes the on-disk DFIR skill files from the
upstream Anthropic Cybersecurity Skills repository.

Triggered from the Maintenance UI ("Refresh skills") and from the broader
system maintenance run. Reads `services/agentic/skills/MANIFEST.txt` for the
list of skills to refresh, fetches each upstream SKILL.md via HTTPS, writes
to a temp file, and atomically renames into place. After success, the
in-memory skill index is reset so the next analyzer call re-scans disk.

Designed to be safe under concurrent analyzer use:
- never partial-writes a file (download to <name>.md.tmp, then rename)
- never deletes existing files on download failure (skips that one)
- only resets the index after at least one file changed
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import tempfile
import time
from typing import Callable, Dict, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

# Hardcoded upstream — same source documented in skills/NOTICE.
UPSTREAM_REPO = "mukul975/Anthropic-Cybersecurity-Skills"
UPSTREAM_REF = "main"
UPSTREAM_RAW_BASE = (
    f"https://raw.githubusercontent.com/{UPSTREAM_REPO}/{UPSTREAM_REF}/skills"
)

DEFAULT_REQUEST_TIMEOUT = 20  # seconds per HTTP request
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_BACKOFF = 5  # seconds, then 2x, 3x


def _skills_dir() -> str:
    """Resolve the skills directory relative to this file (services/.../agentic/skills)."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "agentic", "skills")


def _manifest_path() -> str:
    return os.path.join(_skills_dir(), "MANIFEST.txt")


def _read_manifest() -> List[Tuple[str, str]]:
    """Return a list of (category, name) tuples from MANIFEST.txt.
    Skips blank lines + comments. Raises FileNotFoundError if absent.
    """
    path = _manifest_path()
    entries: List[Tuple[str, str]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "/" not in line:
                logger.warning("[Skills] MANIFEST: ignoring malformed line %r", line)
                continue
            category, name = line.split("/", 1)
            category = category.strip()
            name = name.strip()
            if not category or not name:
                continue
            entries.append((category, name))
    return entries


def _http_get_with_retry(url: str, attempts: int = DEFAULT_MAX_ATTEMPTS,
                         backoff: int = DEFAULT_BACKOFF,
                         timeout: int = DEFAULT_REQUEST_TIMEOUT) -> Optional[bytes]:
    """GET `url` with exponential backoff. Returns body bytes on success
    (HTTP 200 with non-empty body), else None.
    """
    for attempt in range(1, attempts + 1):
        try:
            r = requests.get(url, timeout=timeout)
            if r.status_code == 200 and r.content:
                return r.content
            logger.warning(
                "[Skills] %s -> HTTP %s (attempt %d/%d)",
                url, r.status_code, attempt, attempts
            )
        except requests.RequestException as e:
            logger.warning(
                "[Skills] %s failed (attempt %d/%d): %s",
                url, attempt, attempts, e
            )
        if attempt < attempts:
            time.sleep(backoff * attempt)
    return None


def _atomic_write(target: str, body: bytes) -> bool:
    """Write `body` to a tempfile next to `target` and rename atomically.
    Returns True if something actually changed (i.e., new content differs
    from existing); False if the file was already up-to-date or the write
    failed.
    """
    target_dir = os.path.dirname(target)
    os.makedirs(target_dir, exist_ok=True)

    # If the file already exists and content matches, no-op.
    if os.path.exists(target):
        with open(target, "rb") as f:
            existing = f.read()
        if hashlib.sha256(existing).digest() == hashlib.sha256(body).digest():
            return False

    fd, tmp_path = tempfile.mkstemp(prefix=".dl-", suffix=".tmp", dir=target_dir)
    try:
        with os.fdopen(fd, "wb") as tmp:
            tmp.write(body)
        os.replace(tmp_path, target)  # atomic on POSIX
        return True
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def refresh_skills(
    logger_fn: Optional[Callable[[str, str], None]] = None,
) -> Dict:
    """Refresh on-disk skills from upstream. Reads MANIFEST.txt, fetches each
    listed skill's SKILL.md, atomic-writes to disk, and finally resets the
    in-memory index so next analyzer call sees the new content.

    Returns a result dict with counts:
        {
            "success": bool,
            "updated": [<category/name>...],   # files that changed on disk
            "unchanged": [<category/name>...], # files already up-to-date
            "failed": [<category/name>...],    # fetched failed after retries
            "total": int,
        }

    Designed to be safe under concurrent analyzer use — atomic per-file
    writes, no partial files visible, no destructive cleanup on partial
    failure.
    """
    log = logger_fn or (lambda msg, level="info": None)

    try:
        entries = _read_manifest()
    except FileNotFoundError:
        log("[Skills] MANIFEST.txt not found; nothing to refresh.", "warning")
        return {
            "success": False, "error": "manifest_missing",
            "updated": [], "unchanged": [], "failed": [], "total": 0,
        }

    skills_dir = _skills_dir()
    log(f"[Skills] Refreshing {len(entries)} skills from {UPSTREAM_REPO}@{UPSTREAM_REF}", "info")

    updated: List[str] = []
    unchanged: List[str] = []
    failed: List[str] = []

    for i, (category, name) in enumerate(entries, 1):
        rel = f"{category}/{name}"
        url = f"{UPSTREAM_RAW_BASE}/{name}/SKILL.md"
        target = os.path.join(skills_dir, category, f"{name}.md")

        body = _http_get_with_retry(url)
        if body is None:
            log(f"  [{i}/{len(entries)}] FAIL  {rel}", "warning")
            failed.append(rel)
            continue

        try:
            changed = _atomic_write(target, body)
        except Exception as e:  # noqa: BLE001
            log(f"  [{i}/{len(entries)}] WRITE_FAIL  {rel}: {e}", "warning")
            failed.append(rel)
            continue

        if changed:
            updated.append(rel)
            log(f"  [{i}/{len(entries)}] updated  {rel}", "success")
        else:
            unchanged.append(rel)
            # Don't spam logs with every unchanged file — only on a sampling.
            if i % 20 == 0 or i == len(entries):
                log(f"  [{i}/{len(entries)}] unchanged  {rel}", "info")

    summary_msg = (
        f"[Skills] Refresh summary: {len(updated)} updated, "
        f"{len(unchanged)} unchanged, {len(failed)} failed of {len(entries)}"
    )
    log(summary_msg, "success" if not failed else "warning")

    # Drop the in-memory cache so the next analyzer call re-scans disk.
    if updated:
        try:
            from services.agentic.skills import (
                reset_skill_index_for_reload, load_skill_index_at_boot,
            )
            reset_skill_index_for_reload()
            load_skill_index_at_boot()
            log("[Skills] In-memory skill index reloaded.", "info")
        except Exception as e:  # noqa: BLE001
            log(f"[Skills] Index reload failed (will re-load on next backend restart): {e}", "warning")

    return {
        "success": not failed or len(updated) + len(unchanged) > 0,
        "updated": updated,
        "unchanged": unchanged,
        "failed": failed,
        "total": len(entries),
    }
