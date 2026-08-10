"""Fetch a release's config.yaml from GitHub raw. Trimmed from
services/upgrade/resolver.py's operator-facing UX resolver, which does 30-minute
caching and a config.yaml-fallback token lookup for a long-lived backend
process. Neither applies to the packager: a GitHub Actions job runs once and
exits, so there is nothing for a cache to save a second call from, and there is
no operator config.yaml in a CI checkout (config.yaml is untracked -- see
`intact-config-yaml-is-untracked`) to fall back to.

What is NOT trimmed: `_github_token` still reads GITHUB_TOKEN first, because
that is the credential `resolve`'s own workflow step exports (raises the
anonymous 60 req/hr per-IP cap to 5,000/hr for a matrix of module builds that
each may need it).
"""

import os

import requests
import yaml

GITHUB_REPO = 'TenrootOrg/IntactAI'
GITHUB_RAW = f'https://github.com/{GITHUB_REPO}/raw'
GH_TIMEOUT = 30


class ResolverError(Exception):
    """Upstream config.yaml could not be fetched or parsed."""


def _github_token():
    token = os.environ.get('GITHUB_TOKEN')
    return token if token and token.strip() else None


def fetch_upstream_config(ref: str) -> dict:
    """Pull `<ref>/config.yaml` from GitHub raw and return the parsed dict."""
    url = f'{GITHUB_RAW}/{ref}/config.yaml'
    headers = {}
    token = _github_token()
    if token:
        headers['Authorization'] = f'Bearer {token}'
    try:
        resp = requests.get(url, timeout=GH_TIMEOUT, headers=headers)
    except requests.RequestException as e:
        raise ResolverError(f'GitHub raw fetch failed for {ref}: {e}') from e
    if resp.status_code != 200:
        raise ResolverError(
            f'GitHub raw returned {resp.status_code} for {ref}: {resp.text[:200]}')
    try:
        cfg = yaml.safe_load(resp.text) or {}
    except yaml.YAMLError as e:
        raise ResolverError(f'Upstream config.yaml @ {ref} parse error: {e}') from e
    if not isinstance(cfg, dict):
        raise ResolverError(f'Upstream config.yaml @ {ref} did not parse as a mapping')
    return cfg
