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
from typing import Callable, Dict, List, Optional, Tuple

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

def get_github_rate_limit() -> Optional[Dict]:
    """Fetch current GitHub REST API quota state.

    The ``api.github.com/rate_limit`` endpoint is explicitly excluded
    from the rate-limit counter itself (per GitHub's docs:
    "Accessing this endpoint does not count against your REST API
    rate limit"), so we can poll it as often as needed without
    burning quota.

    Returns ``None`` on any failure (network, JSON parse, missing key)
    so callers can fail-open — checking the rate limit must never
    block a workflow just because the operator's network can't reach
    github's status endpoint (could be an offline mirror).
    """
    import time as _time
    headers = {'Accept': 'application/vnd.github.v3+json'}
    token = os.environ.get('GITHUB_TOKEN')
    if token:
        headers['Authorization'] = f'token {token}'
    try:
        resp = requests.get(
            'https://api.github.com/rate_limit',
            headers=headers, timeout=10,
        )
    except requests.RequestException:
        return None
    if resp.status_code != 200:
        return None
    try:
        core = resp.json().get('resources', {}).get('core', {})
    except Exception:
        return None
    remaining = core.get('remaining')
    limit = core.get('limit')
    used = core.get('used')
    reset = core.get('reset')
    if remaining is None or reset is None:
        return None
    reset_in = max(0, int(reset) - int(_time.time()))
    # Format reset time as local HH:MM for the operator-facing message.
    try:
        reset_hm = _time.strftime('%H:%M', _time.localtime(int(reset)))
    except Exception:
        reset_hm = 'unknown'
    return {
        'remaining': int(remaining),
        'limit': int(limit) if limit is not None else None,
        'used': int(used) if used is not None else None,
        'reset_epoch': int(reset),
        'reset_in_seconds': reset_in,
        'reset_hm': reset_hm,
        'authed': bool(token),
    }


class ResolverQuotaError(Exception):
    """GitHub rate limit too low to start the requested workflow.

    Separate from :class:`ResolverError` so route handlers can map it
    to HTTP 429 (Too Many Requests) instead of the generic 502.
    """
    pass


def check_quota_or_raise(needed: int, action_name: str,
                          log: Optional[Callable] = None) -> None:
    """Pre-flight: refuse to start an action if quota is insufficient.

    Fail-open semantics — if `get_github_rate_limit()` returns None
    (endpoint unreachable, network blip), we PROCEED without
    blocking. The advisory check is to give the operator a clear
    "you'll hit the limit, wait N minutes" message BEFORE the
    workflow runs, not to be a hard gate that misbehaves when the
    operator's network is weird.

    Args:
        needed: upper-bound rate-limit-counted calls this action makes.
        action_name: human-readable label for the error / log message.
        log: optional logger function for the success-case info line.

    Raises:
        ResolverQuotaError when quota < needed.
    """
    # Always print to backend stdout (visible in docker logs) so the
    # [GH-QUOTA] audit trail is grep-able regardless of whether the
    # caller passed a logger. If a workflow logger is supplied, also
    # forward into the workflow log so the operator sees it in the
    # Workflows tab.
    def _emit(msg: str, level: str = 'info') -> None:
        print(msg, flush=True)
        if log is not None:
            try:
                log(msg, level)
            except Exception:
                pass

    state = get_github_rate_limit()
    if state is None:
        _emit(f"[GH-QUOTA] {action_name}: rate-limit endpoint unreachable; "
              "proceeding without pre-flight check", "warning")
        return
    remaining = state['remaining']
    limit = state['limit'] or 60
    reset_hm = state['reset_hm']
    reset_min = max(0, state['reset_in_seconds'] // 60)
    if remaining < needed:
        _emit(f"[GH-QUOTA] {action_name}: REFUSED — needs {needed}, have {remaining}/{limit} "
              f"(resets {reset_hm}, in {reset_min}m)", "error")
        # Multi-line actionable instructions in the error message so
        # the UI's "showMessage(d.error)" surfaces a path the operator
        # can actually follow, not just "set GITHUB_TOKEN" with no
        # context. Two options shown — wait OR raise the cap — with
        # exact commands for the raise-the-cap path.
        if state['authed']:
            fix_block = (
                " (Token IS authed against /5000 cap; "
                "you're rate-limited by an unusually high call volume — "
                "wait until reset.)"
            )
        else:
            fix_block = (
                "\n\nTo raise the cap from 60 → 5000/hr:\n"
                "  1) Get a token: github.com/settings/tokens "
                "→ Generate new token (classic). Leave all scopes UNCHECKED "
                "(public-repo reads only, smaller blast radius if it leaks).\n"
                "  2) On the IntactAI host:\n"
                "       echo 'GITHUB_TOKEN=ghp_YOUR_TOKEN' | sudo tee -a "
                "/home/tenroot/intact/modules/backend/.env\n"
                "       docker restart intact_backend\n"
                "  3) Confirm — open this modal again; the [GH-QUOTA] log "
                "should now show have N/5000 instead of N/60.\n"
                "Otherwise, wait until reset."
            )
        raise ResolverQuotaError(
            f"GitHub rate limit too low for {action_name}: "
            f"need {needed}, have {remaining}. "
            f"Quota resets at {reset_hm} (in {reset_min} minutes).{fix_block}"
        )
    _emit(f"[GH-QUOTA] {action_name}: needs {needed} calls, "
          f"have {remaining}/{limit} remaining (resets {reset_hm})", "info")


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


def list_upstream_modules(target_ref: str,
                          user_action: str = 'prepare-list') -> List[Dict]:
    """Return the flat module list for a given target ref.

    Used by Prepare Package — the build-server's local state is
    irrelevant when bundling for an unknown air-gap target, so this
    helper returns every module in the upstream ``versions:`` block
    without any noop/forced/optional classification.

    The intact module isn't in upstream's versions block as a
    docker-image-style pin (the upstream key is ``backend`` and the
    real "version" of intact is the picked ref itself), so we surface
    it separately with the ref as its target.

    Returns::

        [
            {'module': 'intact',      'target': 'intact-20260612'},
            {'module': 'elk',         'target': '9.3.3'},
            {'module': 'timesketch',  'target': '20260611'},
            ...
        ]

    Reuses :func:`fetch_upstream_config` (30-min cache), so this is a
    no-cost call on repeat clicks within the cache window.
    """
    upstream_cfg = fetch_upstream_config(target_ref, user_action=user_action)
    upstream_versions = upstream_cfg.get('versions') or {}

    # Same key map as compute_plan(). intact's "version" is the ref.
    KEY_MAP = [
        ('intact',       'backend'),
        ('elk',          'elk'),
        ('timesketch',   'timesketch'),
        ('plaso',        'plaso'),
        ('iris',         'iris'),
        ('velociraptor', 'velociraptor'),
        ('cloudtrail',      'cloudtrail'),
        ('o365rc',       'o365rc'),
        ('volweb',       'volweb'),
    ]

    out: List[Dict] = []
    for module_id, cfg_key in KEY_MAP:
        if module_id == 'intact':
            out.append({'module': 'intact', 'target': target_ref})
            continue
        v = upstream_versions.get(cfg_key)
        if v is None:
            # Module not in upstream — skip silently. Future-proof: a
            # release that drops a module shouldn't show it as
            # bundleable.
            continue
        out.append({'module': module_id, 'target': str(v)})

    # CVE Scan is versionless (no image / no pin) but IS bundleable: ticking
    # it in Prepare Package ships the prebuilt CVE database (cves.db) so an
    # air-gapped target gets CVE matching without reaching the upstream
    # feeds. Surfaced with target 'latest' since the corpus is always the
    # newest feeds at build time.
    out.append({'module': 'cve_scan', 'target': 'latest'})
    return out


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
        'cloudtrail':      'cloudtrail',
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
        # SPECIAL CASE — intact: the platform code itself never gets a
        # 'noop' even when the ref/version string matches. Rolling refs
        # like 'development' map the SAME name to DIFFERENT commits over
        # time, and bumping a pinned numeric version isn't the only way
        # new module-integration logic ships (a bugfix re-push to the
        # same ref must still re-copy files + restart). Always running
        # the intact step also unblocks the "Bug: nothing to upgrade →
        # button greyed" footgun the operator hit 2026-06-14: even when
        # every module is at-target, the operator can still click Start
        # to refresh intact and pick up new commits on the rolling ref.
        if module_id == 'intact':
            action = 'upgrade'
        elif cur_state == upstream_ver:
            action = 'noop'
        else:
            action = 'upgrade'
        forced.append({
            'module': module_id,
            'current': cur_state,
            'target': upstream_ver,
            'action': action,
        })

    # CVE Scan is versionless (no docker image, no version pin) — the corpus
    # is always the latest upstream NVD feeds, so it can't go through the
    # version-diff loop above. Surface it as a standalone OPTIONAL row:
    # ticking it ensures modules.cve_scan is enabled and (re)downloads +
    # reindexes the local CVE database. Default unchecked so a routine
    # online upgrade never silently kicks off a large feed re-download.
    try:
        from config import is_module_enabled as _mod_enabled
        cve_on = bool(_mod_enabled('cve_scan'))
    except Exception:
        cve_on = False
    optional.append({
        'module': 'cve_scan',
        'current': 'Installed' if cve_on else 'Not installed',
        'target': 'latest',
        'action': 'upgrade' if cve_on else 'install',
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
