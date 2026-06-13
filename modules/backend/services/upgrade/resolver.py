#!/usr/bin/env python3
"""
Track-based upgrade resolver.

Backs the new "pick one Intact release, derive everything else" UX. The
flow:

  1. UI's Fetch button hits :func:`list_github_refs` → release tags +
     a synthetic `development` branch entry. Cached 30 minutes.
  2. UI's Compute Plan button hits :func:`compute_plan(target)` which:
       a) reads the LOCAL config.yaml (single source of truth for
          "what's installed locally") + per-module .env files for
          actually-running versions,
       b) :func:`resolve_upgrade_chain` produces the ordered list of
          intermediate refs the customer must walk through (we've
          QA'd N→N+1, not 1→3),
       c) for each ref in the chain, :func:`fetch_upstream_config`
          pulls THAT release's config.yaml,
       d) the FINAL target's config.yaml drives the displayed module
          table — operator wants to see the end state.

All GitHub I/O is gated behind explicit operator actions (no page-load
chatter, no background polling) and cached for 30 minutes; see
:func:`_cache_get`/:func:`_cache_put`.
"""

import os
import re
import time
import yaml
from typing import Dict, List, Optional, Tuple

import requests

from .base import (
    WORKDIR,
    get_current_versions,
    get_latest_versions,
)


# ─── GitHub configuration ─────────────────────────────────────────────────

GITHUB_REPO = 'TenrootOrg/IntactAI'
GITHUB_API = f'https://api.github.com/repos/{GITHUB_REPO}'
GITHUB_RAW = f'https://github.com/{GITHUB_REPO}/raw'

# Synthetic dropdown entry for the rolling development branch. Distinct
# from release tags — chains targeted at this never walk intermediates
# (development is a moving target; "stepping through" is meaningless).
DEV_BRANCH = 'development'

# Pinned for legibility — bumping these is a backend code change, not an
# operator concern.
GH_TIMEOUT = 30
CACHE_TTL_SECONDS = 30 * 60


# ─── Cache (in-process, no Redis dep) ─────────────────────────────────────

_cache: Dict[str, Tuple[float, object]] = {}


def _cache_get(key: str):
    """Return cached value or None if missing/stale."""
    entry = _cache.get(key)
    if not entry:
        return None
    stamped_at, value = entry
    if (time.time() - stamped_at) > CACHE_TTL_SECONDS:
        _cache.pop(key, None)
        return None
    return value


def _cache_put(key: str, value):
    _cache[key] = (time.time(), value)


def _gh_call_log(path: str, action: str):
    """Audit line — see how chatty we are with the GitHub API.

    Every external call emits one line so it's grep-able if the cache
    isn't working or someone adds an unintended hit (e.g. via a startup
    task).
    """
    print(f"[GH-CALL] {path} user-action={action}", flush=True)


# ─── Public API ───────────────────────────────────────────────────────────

def list_github_refs(user_action: str = 'fetch') -> List[Dict]:
    """Return the dropdown list for the Fetch button.

    Format::

        [
            {'kind': 'tag',    'name': 'v1.4.2', 'label': 'release v1.4.2 (latest)'},
            {'kind': 'tag',    'name': 'v1.4.1', 'label': 'release v1.4.1'},
            ...
            {'kind': 'branch', 'name': 'development', 'label': 'development branch (rolling)'},
        ]

    Synthetic `development` entry always appended last. Cached for
    CACHE_TTL_SECONDS — clicks within that window return cached without
    a GitHub round-trip. The `user_action` is only used in the audit log.
    """
    cached = _cache_get('refs')
    if cached is not None:
        return cached

    _gh_call_log(f'/repos/{GITHUB_REPO}/releases', user_action)
    headers = {'Accept': 'application/vnd.github.v3+json'}
    token = os.environ.get('GITHUB_TOKEN')
    if token:
        headers['Authorization'] = f'token {token}'
    try:
        resp = requests.get(
            f'{GITHUB_API}/releases',
            headers=headers, timeout=GH_TIMEOUT,
        )
    except requests.RequestException as e:
        raise ResolverError(f'GitHub unreachable: {e}')
    if resp.status_code == 403:
        raise ResolverError(
            'GitHub rate-limit reached. Wait until the limit resets '
            '(usually within an hour) or set GITHUB_TOKEN.'
        )
    if resp.status_code != 200:
        raise ResolverError(
            f'GitHub /releases returned {resp.status_code}: {resp.text[:200]}'
        )

    releases = resp.json() or []
    # GitHub returns newest first by default. Mark the first non-draft,
    # non-prerelease entry as (latest); everything else gets a plain
    # label. Drafts/prereleases never show — operators shouldn't be
    # nudged onto unreleased builds.
    items: List[Dict] = []
    latest_marked = False
    for rel in releases:
        if rel.get('draft') or rel.get('prerelease'):
            continue
        tag = rel.get('tag_name') or ''
        if not tag:
            continue
        if not latest_marked:
            label = f'release {tag} (latest)'
            latest_marked = True
        else:
            label = f'release {tag}'
        items.append({'kind': 'tag', 'name': tag, 'label': label})

    items.append({
        'kind': 'branch',
        'name': DEV_BRANCH,
        'label': 'development branch (rolling)',
    })

    _cache_put('refs', items)
    return items


def fetch_upstream_config(ref: str, user_action: str = 'plan') -> Dict:
    """Pull `<ref>/config.yaml` from GitHub raw and return the parsed dict.

    Cached for CACHE_TTL_SECONDS keyed by ref. A Compute Plan click
    followed by a Confirm click within the window uses one fetch, not
    two.
    """
    cache_key = f'config:{ref}'
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    url = f'{GITHUB_RAW}/{ref}/config.yaml'
    _gh_call_log(url, user_action)
    try:
        resp = requests.get(url, timeout=GH_TIMEOUT)
    except requests.RequestException as e:
        raise ResolverError(f'GitHub raw fetch failed for {ref}: {e}')
    if resp.status_code != 200:
        raise ResolverError(
            f'GitHub raw returned {resp.status_code} for {ref}: '
            f'{resp.text[:200]}'
        )

    try:
        cfg = yaml.safe_load(resp.text) or {}
    except yaml.YAMLError as e:
        raise ResolverError(f'Upstream config.yaml @ {ref} parse error: {e}')

    if not isinstance(cfg, dict):
        raise ResolverError(
            f'Upstream config.yaml @ {ref} did not parse as a mapping'
        )

    _cache_put(cache_key, cfg)
    return cfg


def resolve_upgrade_chain(current_ref: Optional[str],
                          target_ref: str,
                          user_action: str = 'plan') -> List[str]:
    """Return the ordered list of refs to walk through.

    * Target == ``development``: chain is ``[development]`` only. The
      rolling branch has no intermediate stepping concept — we apply
      whatever HEAD is.
    * Target is a release tag, current_ref is a release tag: walk the
      sorted release list and return all tags strictly between
      ``current_ref`` (exclusive) and ``target_ref`` (inclusive). If
      ``current_ref`` is None or 'unknown' (intact never recorded a
      release version on this host), return ``[target_ref]`` only —
      a single-step apply (safer than guessing how far back we need
      to walk).
    * Target == current_ref: empty chain (no-op).

    Refs returned are GitHub ref names (e.g. 'v1.4.2'), suitable for
    feeding back into :func:`fetch_upstream_config`.
    """
    if target_ref == DEV_BRANCH:
        return [DEV_BRANCH]

    if not current_ref or current_ref in ('unknown', 'Not installed'):
        return [target_ref]

    if current_ref == target_ref:
        return []

    refs = list_github_refs(user_action=user_action)
    # Tag entries only (drop development synthetic), in newest-first
    # order as returned by the GitHub API.
    tags = [r['name'] for r in refs if r['kind'] == 'tag']

    # Hard reality check: an upgrade-time .env or VERSION file can hold
    # whatever the operator's pinned, but for the CHAIN walk we need
    # current_ref to actually exist as a release. If it doesn't (e.g.
    # operator on a custom dev build), short-circuit to a single-step
    # jump — same as the "unknown current" case above.
    if current_ref not in tags:
        return [target_ref]
    if target_ref not in tags:
        raise ResolverError(
            f'Target ref {target_ref!r} not present in GitHub releases '
            f'list. Hit Fetch again to refresh.'
        )

    # tags are newest-first; chain should be oldest-newer-newest from
    # current (exclusive) to target (inclusive).
    cur_idx = tags.index(current_ref)
    tgt_idx = tags.index(target_ref)

    if tgt_idx >= cur_idx:
        # Target is OLDER than (or equal to) current — operator picked a
        # downgrade. Per the plan, no special downgrade logic: we honor
        # operator intent and emit a one-step chain.
        return [target_ref]

    # cur_idx > tgt_idx → target is newer. Slice between them and
    # reverse so we step oldest-to-newest.
    step_tags = tags[tgt_idx:cur_idx]
    step_tags.reverse()
    return step_tags


def compute_plan(target_ref: str,
                 user_action: str = 'plan') -> Dict:
    """Build the work plan for the UI to render.

    Returns::

        {
            'current_intact_version': '...',
            'target': target_ref,
            'chain': [ref1, ref2, ...],
            'forced':   [{'module', 'current', 'target', 'action'}, ...],
            'optional': [{'module', 'current', 'target', 'action'}, ...],
        }

    ``forced`` lists modules already installed locally (operator MUST
    upgrade them — no checkbox). ``optional`` lists modules present in
    upstream's final-target config.yaml but absent locally (operator
    may opt in via a checkbox). ``action`` is one of ``'upgrade'``,
    ``'install'``, ``'noop'``.
    """
    current = get_current_versions()
    intact_current = current.get('intact', {}).get('current', 'unknown')

    chain = resolve_upgrade_chain(intact_current, target_ref,
                                  user_action=user_action)

    # The final target's config drives what the operator sees in the
    # module table. Intermediate steps' configs are pulled at apply
    # time, not here, to keep Compute Plan cheap.
    upstream_cfg = fetch_upstream_config(target_ref, user_action=user_action)
    upstream_versions = upstream_cfg.get('versions') or {}
    upstream_modules = upstream_cfg.get('modules') or {}

    # Same key map as base.get_latest_versions(). intact in code →
    # backend key in config.yaml.
    KEY_MAP = {
        'elk':          'elk',
        'timesketch':   'timesketch',
        'plaso':        'plaso',
        'iris':         'iris',
        'velociraptor': 'velociraptor',
        'prowler':      'prowler',
        'o365rc':       'o365rc',
        'intact':       'backend',
        'volweb':       'volweb',
    }

    forced: List[Dict] = []
    optional: List[Dict] = []

    for module_id, cfg_key in KEY_MAP.items():
        cur_state = current.get(module_id, {}).get('current', 'Not installed')
        if module_id == 'intact':
            # The 'intact' (backend) module's "target version" isn't a
            # docker-image tag — it's the GitHub ref the operator
            # picked. config.yaml's versions.backend exists for legacy
            # reasons but is a fallback constant (1.0.0), not the
            # shipped tag. Showing 'intact-20260609 → 1.0.0' would
            # misleadingly suggest the operator is being asked to
            # downgrade to a year-old release. The right answer:
            # target == the picked ref (or 'development' for the
            # rolling branch).
            upstream_ver = target_ref
        else:
            upstream_ver = upstream_versions.get(cfg_key)
            if upstream_ver is None:
                # Module no longer in upstream (e.g. removed in a future
                # release). Don't surface as install-able; leave running.
                continue
            upstream_ver = str(upstream_ver)

        if cur_state == 'Not installed':
            # New-to-this-host. Show as optional (default unchecked).
            optional.append({
                'module': module_id,
                'current': cur_state,
                'target': upstream_ver,
                'action': 'install',
            })
            continue

        # Module is installed. action depends on version delta.
        if cur_state == upstream_ver:
            action = 'noop'
        else:
            action = 'upgrade'
        forced.append({
            'module': module_id,
            'current': cur_state,
            'target': upstream_ver,
            'action': action,
        })

    return {
        'current_intact_version': intact_current,
        'target': target_ref,
        'chain': chain,
        'forced': forced,
        'optional': optional,
    }


# ─── Errors ───────────────────────────────────────────────────────────────

class ResolverError(Exception):
    """Resolver-layer failure. Routes catch and return HTTP 502."""
    pass
