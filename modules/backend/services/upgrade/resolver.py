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

# DOWNLOAD-ONLY upgrades: the package is always the CI-built artifact attached
# to a GitHub Release; nothing is ever built on the operator's box. `development`
# is a rolling branch with no Release — and therefore no package — so it cannot
# be an upgrade target. Flip this to True to offer it again (only meaningful if
# an on-box build path is reinstated).
OFFER_DEV_BRANCH = False

# Pinned for legibility — bumping these is a backend code change, not an
# operator concern.
GH_TIMEOUT = 30
CACHE_TTL_SECONDS = 30 * 60


def _release_package_bytes(rel: dict, tag: str):
    """Total size in bytes of the installable payload attached to ``rel``, or
    ``None`` when that release carries nothing a box could apply.

    THREE SHAPES COUNT, and getting this wrong makes releases disappear from
    the picker entirely — the caller `continue`s on ``None`` and upgrades are
    download-only, so a release nothing recognises is simply not offered.

      1. per-module assets — ``intact-<tag>-<module>.tar.gz[.part-NN]``, the
         current shape. Their total is what a box would pay to take the whole
         release; it fetches only the modules it needs, so this over-states
         rather than under-states, which is the safe direction for a size hint.
      2. the compatibility bundle — ``intact-upgrade-<tag>.tar.gz[.part-NN]``,
         still published and still what an older box downloads.
      3. nothing else. ``.sha256`` / ``.manifest.json`` / ``.meta.json`` /
         ``.index.json`` sidecars are metadata, not payload.

    Deliberately does NOT require the index: a release carrying module assets
    is installable by any box new enough to read them, and one carrying only
    the bundle is installable by every box. Both must remain visible.
    """
    bundle = f'intact-upgrade-{tag}.tar.gz'
    # `<tag>-<module>.tar.gz`. The tag ALREADY begins with "intact-", so the
    # asset name is intact-20260804-elk.tar.gz -- not intact-intact-20260804-elk.
    #
    # This read `f'intact-{tag}-'` and so looked for the doubled prefix. The
    # builder had that same bug and was fixed; this copy was missed, and the
    # consequence is silent and total: _release_package_bytes returns None for
    # every per-module release, the caller treats None as "nothing installable
    # here" and skips it, and the release simply DOES NOT APPEAR in the upgrade
    # picker. Observed on intact-20260804, where the dialog offered only
    # intact-20260726 -- the one older release still carrying a legacy bundle,
    # which matched the other pattern.
    #
    # Both spellings are accepted: a release cut while the builder still doubled
    # the prefix is just as installable, and there is no reason to make it
    # invisible now.
    module_prefixes = (f'{tag}-', f'intact-{tag}-')
    sidecars = ('.sha256', '.manifest.json', '.meta.json', '.index.json')
    total = 0
    found = False
    for a in (rel.get('assets') or []):
        name = a.get('name') or ''
        if name.endswith(sidecars):
            continue
        is_bundle = name == bundle or name.startswith(bundle + '.part-')
        is_module = (name.startswith(module_prefixes)
                     and ('.tar.gz' in name))
        if is_bundle or is_module:
            total += a.get('size') or 0
            found = True
    return total if found else None


# ─── Cache (in-process, no Redis dep) ─────────────────────────────────────

_cache: Dict[str, Tuple[float, object]] = {}

# Sentinel distinguishing "cached: confirmed no manifest asset" from "not yet
# cached" (which _cache_get already represents as plain None).
_MISSING = object()



def _github_token():
    """GitHub API token: GITHUB_TOKEN env (set into the backend .env at install
    from config.yaml options.github_token) first, falling back to a fresh read
    of config.yaml itself — so an operator can add the token to config.yaml and
    it takes effect WITHOUT editing .env or restarting the backend. Raises the
    anonymous 60 req/hr per-IP cap to 5,000 req/hr. Needs a READ-ONLY-PUBLIC
    token (classic PAT with no scopes, or fine-grained public-repos read-only)
    — see the github_token comment in config.yaml.
    """
    token = os.environ.get('GITHUB_TOKEN')
    if token:
        return token
    try:
        from config import load_main_config
        cfg = load_main_config() or {}
        token = (cfg.get('options') or {}).get('github_token')
        return token if isinstance(token, str) and token.strip() else None
    except Exception:
        return None

def _cache_get(key: str):
    """Return cached value or None if missing/stale."""
    entry = _cache.get(key)
    if not entry:
        return None
    stamped_at, value = entry
    if (time.time() - stamped_at) > CACHE_TTL_SECONDS:
        # Return None, but do NOT evict. _cache_get_stale() serves this entry
        # as a last-resort fallback when a live fetch fails, and popping here
        # destroyed it at precisely the moment it became useful: the cache
        # expires, the next fetch fails, and the fallback finds nothing.
        # The keyspace is a handful of fixed keys, so retaining costs nothing.
        return None
    return value


def _cache_put(key: str, value):
    _cache[key] = (time.time(), value)


def _cache_get_stale(key: str):
    """The cached value REGARDLESS of age, or (None, 0).

    A last resort for when a live fetch fails. A release list from an hour ago
    is very nearly as useful as one from a minute ago -- releases are cut
    weekly at most -- and it is enormously more useful than the empty dropdown
    the operator sees today when GitHub is unreachable or the anonymous
    60/hr quota is spent. The caller marks the answer stale so the UI can say
    so rather than pretending it is current.
    """
    entry = _cache.get(key)
    if not entry:
        return None, 0
    stamped_at, value = entry
    return value, int(time.time() - stamped_at)


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
    token = _github_token()
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
        # ONE sentence. This lands in a transient toast, and the previous
        # version put ~200 words there -- three numbered steps, two URLs and a
        # config snippet -- which is unreadable in a popup that disappears and
        # cannot be copied from. The instinct was right (give the operator a
        # path, not just "set GITHUB_TOKEN") but a toast is the wrong place for
        # it: the full walkthrough lives in the modal's quota banner, which is
        # persistent, on-screen while they act, and next to the thing it fixes.
        if state['authed']:
            fix_block = (" The token is already authenticated against the "
                         "5000/hr cap, so this is unusual call volume — wait "
                         "for the reset.")
        else:
            fix_block = (" Set options.github_token in config.yaml to raise the "
                         "cap to 5000/hr (no restart needed), or wait for the "
                         "reset.")
        raise ResolverQuotaError(
            f"GitHub rate limit reached — {action_name} needs {needed} calls, "
            f"{remaining} left. Resets at {reset_hm}, in {reset_min} min."
            f"{fix_block}"
        )
    _emit(f"[GH-QUOTA] {action_name}: needs {needed} calls, "
          f"have {remaining}/{limit} remaining (resets {reset_hm})", "info")


def _github_latest_tag(user_action: str = 'fetch') -> Optional[str]:
    """The tag GitHub itself considers the latest release, or None.

    NOT the same as "newest published". GitHub honours the maintainer's
    "Set as the latest release" choice, so a release cut for testing and
    deliberately not promoted is newer yet still not latest. Deriving the
    badge from list position instead advertised exactly such a release to
    every operator as the one to upgrade to.

    Soft-fails to None (no badge) rather than raising: a missing label is
    cosmetic, and this must never break the dropdown.
    """
    _gh_call_log(f'/repos/{GITHUB_REPO}/releases/latest', user_action)
    headers = {'Accept': 'application/vnd.github.v3+json'}
    token = _github_token()
    if token:
        headers['Authorization'] = f'token {token}'
    try:
        resp = requests.get(f'{GITHUB_API}/releases/latest',
                            headers=headers, timeout=GH_TIMEOUT)
    except requests.RequestException:
        return None
    if resp.status_code != 200:      # 404 = repo has no non-prerelease release
        return None
    try:
        return (resp.json() or {}).get('tag_name') or None
    except ValueError:
        return None


def list_github_refs(user_action: str = 'fetch', force: bool = False) -> List[Dict]:
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
    # force=True is the operator explicitly asking GitHub again (the modal's
    # refresh button, and opening the modal at all). The 30-minute TTL exists
    # to stop page-load chatter burning rate-limit, but it also meant a release
    # whose CI package finished AFTER the last fetch stayed invisible until the
    # TTL expired -- and the refresh button, hitting the same cache, could not
    # break out of it. Still writes the fresh result back, so nothing else
    # re-fetches needlessly.
    if not force:
        cached = _cache_get('refs')
        if cached is not None:
            return cached

    _gh_call_log(f'/repos/{GITHUB_REPO}/releases', user_action)
    headers = {'Accept': 'application/vnd.github.v3+json'}
    token = _github_token()
    if token:
        headers['Authorization'] = f'token {token}'
    # Retry the transient shapes before giving up. A single dropped TCP
    # connection or a GitHub 5xx currently empties the operator's dropdown and
    # costs them a manual retry -- which spends MORE quota than the retry would
    # have. Deliberately does NOT retry 403 (rate limit) or 404: those are
    # answers, not accidents, and hammering them makes the situation worse.
    resp = None
    last_exc = None
    for attempt in range(3):
        try:
            resp = requests.get(
                f'{GITHUB_API}/releases',
                headers=headers, timeout=GH_TIMEOUT,
            )
            if resp.status_code < 500:
                break
            last_exc = ResolverError(
                f'GitHub /releases returned {resp.status_code}')
        except requests.RequestException as e:
            last_exc = ResolverError(f'GitHub unreachable: {e}')
            resp = None
        if attempt < 2:
            time.sleep(1.5 * (attempt + 1))
    if resp is None:
        raise last_exc or ResolverError('GitHub unreachable')
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
    latest_tag = _github_latest_tag(user_action)
    items: List[Dict] = []
    for rel in releases:
        # Drafts stay hidden -- nobody can install one. Prereleases DO show,
        # labelled: hiding them left no way to publish a test release that is
        # installable on purpose without also advertising it as current.
        if rel.get('draft'):
            continue
        tag = rel.get('tag_name') or ''
        if not tag:
            continue
        # DOWNLOAD-ONLY: upgrades consume the CI-built package exclusively —
        # nothing is ever built on the operator's box. A release without a
        # package asset therefore isn't a usable target, so it never shows.
        # The /releases payload carries `assets` inline, so this costs no
        # extra GitHub call.
        pkg_bytes = _release_package_bytes(rel, tag)
        if pkg_bytes is None:
            continue
        if rel.get('prerelease'):
            label = f'release {tag} (pre-release)'
        elif latest_tag and tag == latest_tag:
            label = f'release {tag} (latest)'
        else:
            label = f'release {tag}'
        items.append({'kind': 'tag', 'name': tag, 'label': label,
                      'prerelease': bool(rel.get('prerelease')),
                      'latest': bool(latest_tag and tag == latest_tag),
                      'package_mb': round(pkg_bytes / 1024 / 1024)})

    if OFFER_DEV_BRANCH:
        items.append({
            'kind': 'branch',
            'name': DEV_BRANCH,
            'label': 'development branch (rolling)',
        })

    # Cache only a list that actually has releases in it.
    #
    # `items` can come back with nothing but the synthetic development entry --
    # when CI has not finished attaching package assets yet, every release is
    # filtered out by the `pkg_bytes is None` test above. Caching that pinned an
    # empty dropdown for the full 30-minute TTL, so every non-forced call
    # returned nothing and the operator's instinct (open it again) could not
    # clear it. An empty answer is exactly the one worth re-asking.
    if any(i.get('kind') == 'tag' for i in items):
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


def fetch_release_manifest(ref: str, user_action: str = 'plan') -> Optional[Dict]:
    """What release ``ref`` can actually deliver, as ``{'versions': {...}}``.

    Two shapes answer this, and they are tried in that order:

    1. ``intact-release-<ref>.index.json`` — the per-module release index. This
       is the authority for anything built after the move to per-module assets:
       it names every module the release ships and the version each one
       carries, which is exactly the picker's question. It is also the ONLY
       answer for such a release, because there is no longer a single bundle to
       hang a sidecar off.
    2. ``intact-upgrade-<ref>.tar.gz.manifest.json`` — the bundle sidecar. Every
       release up to and including the last full-package one has this and no
       index, so the fallback is not politeness, it is how older releases stay
       visible in the picker.

    Both are normalised to the manifest shape (``versions``) that
    :func:`_upstream_module_rows` consumes, so callers cannot tell which
    answered.

    ``config.yaml``'s ``modules:`` block (what :func:`fetch_upstream_config`
    reads) lists every module the CODEBASE supports, regardless of what a
    given release's CI build chose to bundle (see ``RELEASE_MODULES`` in
    ``scripts/ci/build_release_package.py`` — a release can deliberately ship
    lean, e.g. skipping elk/iris/volweb/portainer). Deriving the picker from
    config.yaml offers a checkbox for a module the download can never
    deliver — ticking it is a silent no-op at apply time, since the module
    simply isn't in the tarball's own manifest. This reads the SAME manifest
    the apply engine matches against, so the picker can never promise more
    than the package actually contains.

    Returns ``None`` when the release carries neither (shouldn't happen for any
    ref ``list_github_refs`` offers, since that already filters to releases
    with a payload asset — one of the two ships alongside it). Cached like
    :func:`fetch_upstream_config`.
    """
    cache_key = f'manifest:{ref}'
    cached = _cache_get(cache_key)
    if cached is not None:
        return None if cached is _MISSING else cached

    headers = {'Accept': 'application/vnd.github.v3+json'}
    token = _github_token()
    if token:
        headers['Authorization'] = f'token {token}'
    _gh_call_log(f'/repos/{GITHUB_REPO}/releases/tags/{ref}', user_action)
    try:
        resp = requests.get(f'{GITHUB_API}/releases/tags/{ref}',
                            headers=headers, timeout=GH_TIMEOUT)
    except requests.RequestException as e:
        raise ResolverError(f'GitHub unreachable fetching release {ref}: {e}')
    if resp.status_code != 200:
        raise ResolverError(
            f'GitHub /releases/tags/{ref} returned {resp.status_code}: '
            f'{resp.text[:200]}'
        )
    rel = resp.json() or {}
    by_name = {(a.get('name') or ''): a.get('browser_download_url')
               for a in (rel.get('assets') or [])}
    index_name = f'intact-release-{ref}.index.json'
    manifest_name = f'intact-upgrade-{ref}.tar.gz.manifest.json'

    kind, asset_url = None, None
    for _kind, _name in (('index', index_name), ('manifest', manifest_name)):
        if by_name.get(_name):
            kind, asset_url = _kind, by_name[_name]
            break
    if not asset_url:
        _cache_put(cache_key, _MISSING)
        return None

    try:
        mresp = requests.get(asset_url, timeout=GH_TIMEOUT)
    except requests.RequestException as e:
        raise ResolverError(f'Manifest download failed for {ref}: {e}')
    if mresp.status_code != 200:
        raise ResolverError(
            f'Manifest download for {ref} returned {mresp.status_code}'
        )
    try:
        payload = mresp.json()
    except ValueError as e:
        raise ResolverError(f'Manifest for {ref} did not parse as JSON: {e}')

    if kind == 'index':
        # Normalise the index into the manifest shape. A module whose entry
        # carries no version is still listed — it exists in the release, and
        # 'latest' is what the config.yaml path would have shown anyway. What
        # must NOT happen is dropping it, which would hide a downloadable
        # module from the picker.
        assets = payload.get('assets') or {}
        manifest = {
            'versions': {m: (e.get('version') or 'latest')
                         for m, e in assets.items()},
            'release_tag': payload.get('release_tag'),
            'source_commit': payload.get('source_commit'),
        }
    else:
        manifest = payload

    _cache_put(cache_key, manifest)
    return manifest


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


# Modules that appear in config.yaml but are NOT upgraded/bundled through this
# system — infrastructure managed by install.sh, with no upgrade handler
# (not in PRIMARY_IMAGES, not in offline_upgrade_functions). Explicit, documented
# skip so the picker never offers a non-upgradeable row.
_NON_UPGRADEABLE = set()

# Preferred display order for the module picker. Any module NOT listed here —
# e.g. a brand-new module added to config.yaml — is appended after these
# (alphabetically), so new modules appear automatically with no code change.
_MODULE_DISPLAY_ORDER = ['elk', 'timesketch', 'plaso', 'iris', 'velociraptor',
                         'aws_sigma', 'o365rc', 'volweb', 'portainer']


def _upstream_module_rows(upstream_cfg: dict, target_ref: str,
                          package_manifest: Optional[dict] = None) -> List[Dict]:
    """Generic module list for the upgrade/prepare picker.

    Prefers ``package_manifest`` (see :func:`fetch_release_manifest`) — the
    actual ``versions:`` block baked into the release's downloadable
    package — over ``upstream_cfg``'s ``config.yaml`` ``modules:`` block.
    config.yaml lists every module the CODEBASE supports regardless of
    packaging scope (a release can deliberately ship lean, e.g. skipping
    elk/iris/volweb/portainer — see ``RELEASE_MODULES`` in
    ``scripts/ci/build_release_package.py``); reading it here would offer a
    checkbox for a module the download can never deliver, a silent no-op at
    apply time since the module isn't in the tarball. Falls back to
    ``upstream_cfg`` only when no manifest was fetched (e.g. the caller
    tolerated a fetch failure) — better a possibly-stale list than none.

    - ``intact`` is implicit (its config key is ``backend`` and its real
      "version" is the picked ref), so it is prepended explicitly, target = ref.
    - ``cve_scan`` is versionless (its CVE DB is rolling data baked
      best-effort — see ``upgrade_cve_offline``, which degrades gracefully
      with a warning when no DB was bundled) so it never appears in a
      manifest's ``versions`` dict even on releases that include it. Always
      surfaced with target ``'latest'`` — safe unlike the other modules
      since ticking it never silently does nothing.
    - ``_NON_UPGRADEABLE`` infra modules are skipped.

    Returns ``[{'module': str, 'target': str}, ...]`` with intact first, then the
    preferred order, then any new modules alphabetically.
    """
    if package_manifest is not None:
        pkg_versions = dict(package_manifest.get('versions') or {})
        pkg_versions.pop('intact', None)
        names = [m for m in pkg_versions if m not in _NON_UPGRADEABLE]
        ordered = [m for m in _MODULE_DISPLAY_ORDER if m in names]
        ordered += sorted(m for m in names if m not in _MODULE_DISPLAY_ORDER)
        rows: List[Dict] = [{'module': 'intact', 'target': target_ref}]
        for name in ordered:
            rows.append({'module': name, 'target': str(pkg_versions[name])})
        return rows

    mods = upstream_cfg.get('modules') or {}
    versions = upstream_cfg.get('versions') or {}
    names = [m for m in mods if m not in _NON_UPGRADEABLE]
    ordered = [m for m in _MODULE_DISPLAY_ORDER if m in names]
    ordered += sorted(m for m in names if m not in _MODULE_DISPLAY_ORDER)
    rows: List[Dict] = [{'module': 'intact', 'target': target_ref}]
    for name in ordered:
        v = versions.get(name)
        rows.append({'module': name, 'target': str(v) if v is not None else 'latest'})
    return rows


def list_upstream_modules(target_ref: str,
                          user_action: str = 'prepare-list') -> List[Dict]:
    """Return the flat module list for a given target ref.

    Used by Prepare Package — the build-server's local state is
    irrelevant when bundling for an unknown air-gap target, so this
    helper returns every module the release's ACTUAL package contains,
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

    Reuses :func:`fetch_upstream_config` + :func:`fetch_release_manifest`
    (both 30-min cached), so this is a no-cost call on repeat clicks within
    the cache window.
    """
    upstream_cfg = fetch_upstream_config(target_ref, user_action=user_action)
    package_manifest = fetch_release_manifest(target_ref, user_action=user_action)
    # Manifest-scoped — see _upstream_module_rows. Only what the download for
    # THIS release actually contains shows up as a row.
    return _upstream_module_rows(upstream_cfg, target_ref,
                                 package_manifest=package_manifest)


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
    package_manifest = fetch_release_manifest(target_ref, user_action=user_action)

    forced: List[Dict] = []
    optional: List[Dict] = []

    # Manifest-scoped module set (see _upstream_module_rows): only modules
    # THIS release's package actually bundles show up, so ticking a box can
    # never silently do nothing at apply time. intact's target is the
    # picked ref; classification (forced/optional/noop) is unchanged.
    for row in _upstream_module_rows(upstream_cfg, target_ref,
                                     package_manifest=package_manifest):
        module_id = row['module']
        upstream_ver = row['target']
        cur_state = current.get(module_id, {}).get('current', 'Not installed')


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
        # SPECIAL CASE — intact: the platform code itself never gets a 'noop'
        # even when the ref/version string matches. Rolling refs like
        # 'development' map the SAME name to DIFFERENT commits over time, and a
        # bugfix re-push to the same ref must still re-copy files + restart. Also
        # unblocks the "nothing to upgrade → button greyed" footgun: the operator
        # can always click Start to refresh intact on the rolling ref.
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
