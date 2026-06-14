#!/usr/bin/env python3
"""Resolve transitive container versions from each primary module's
upstream source of truth.

Why: today's flow hardcodes transitive container pins (opensearch, postgres,
redis, rabbitmq, nginx) in three places that must hand-sync — package.py's
DOCKER_IMAGES dict, every module's compose default, every module's .env.
When upstream bumps a compat floor (e.g. Timesketch 20260611 requiring
OpenSearch >=2.19.5 instead of 2.11), we find out by production breaking.

This module reads upstream's OWN compose / env file at the tag the
operator is targeting and returns the transitive versions THAT release
uses. Lets the caller diff against our local pins, surface drift in the
upgrade plan, or auto-bump.

Each module has a different layout, so RESOLVERS describes per-module
how to fetch + parse. Adding a new module = adding a new RESOLVERS entry.

Validated 2026-06-14 against:
  - google/timesketch @ 20260611  → opensearch 2.19.5, postgres 13.0-alpine,
                                     redis 7.2.11-alpine, nginx 1.25.5-alpine-slim
  - dfir-iris/iris-web @ v2.4.27  → rabbitmq 3-management-alpine
  - k1nd0ne/VolWeb     @ v3.16.0  → postgres 14.1, redis latest
"""

from __future__ import annotations

import os
import re
import sys
from typing import Dict, List, Optional

# Optional dependency — only used when running standalone CLI. Backend
# already has `requests` available; this lazy-import avoids forcing it
# when the module is parsed at startup.


# Per-module resolver entries. Each describes how to locate + parse
# the upstream source of truth at a given primary-version tag.
#
# Fields:
#   tag_prefix         Prefix to add to the operator's pinned version
#                      when forming the URL. Empty for tags like
#                      "20260611"; "v" for tags like "v3.16.0".
#   env_url            (optional) Fetch this file and extract NAME=VALUE.
#                      Used for Timesketch which stores defaults in a
#                      separate config.env, not in the compose.
#   env_mapping        (used with env_url) NAME_IN_ENV → key the
#                      resolver returns. Filters out irrelevant vars
#                      (e.g. NUM_WSGI_WORKERS, TIMESKETCH_LOGS_PATH).
#   compose_urls       (optional) Fetch each, parse `image:` lines.
#                      Multiple URLs for modules that split deps
#                      across composes (e.g. IRIS's rabbitmq lives
#                      in docker-compose.base.yml, not main).
#   images_of_interest (used with compose_urls) Image-basename → key
#                      the resolver returns. Filters out images we
#                      don't bundle (e.g. otel collector, jaeger).
RESOLVERS: Dict[str, Dict] = {
    'timesketch': {
        'tag_prefix': '',
        'env_url': ('https://raw.githubusercontent.com/google/timesketch/'
                    '{tag}/docker/release/config.env'),
        'env_mapping': {
            'OPENSEARCH_VERSION': 'opensearch',
            'POSTGRES_VERSION': 'postgres',
            'REDIS_VERSION': 'redis',
            'NGINX_VERSION': 'nginx',
        },
    },
    'iris': {
        # IRIS's main compose has db/app/nginx referenced as iris-version-
        # coupled images (driven by versions.iris in our config.yaml).
        # The only transitive infrastructure dep is rabbitmq, which lives
        # in docker-compose.base.yml with a literal `rabbitmq:3-management-
        # alpine` tag.
        'tag_prefix': '',
        'compose_urls': [
            ('https://raw.githubusercontent.com/dfir-iris/iris-web/'
             '{tag}/docker-compose.base.yml'),
        ],
        'images_of_interest': {
            'rabbitmq': 'rabbitmq',
        },
    },
    'volweb': {
        # VolWeb's tag scheme uses a 'v' prefix on the GitHub side
        # (v3.16.0) even though our config.yaml stores the bare version.
        'tag_prefix': 'v',
        'compose_urls': [
            ('https://raw.githubusercontent.com/k1nd0ne/VolWeb/'
             '{tag}/docker-compose.yaml'),
        ],
        'images_of_interest': {
            'postgres': 'postgres',
            'redis': 'redis',
        },
    },
    # No transitive container deps to resolve for:
    #   - velociraptor (single binary, no compose deps to track)
    #   - plaso        (single image, on-demand, no live containers)
    #   - prowler      (single image, on-demand)
    #   - o365rc       (single image, on-demand)
    #   - elk          (elasticsearch/kibana/logstash are the primary
    #                   images; no transitive infra deps in compose)
}


# Match `image:`, optionally quoted, with optional whitespace and any
# leading registry path. Capture the basename (last path segment before
# `:`) and the tag. Examples this matches:
#   image: postgres:14.1
#   image: "redis:latest"
#   image: opensearchproject/opensearch:2.19.5
#   image: us-docker.pkg.dev/foo/bar/timesketch:20260611
#   image: ${OPENSEARCH_VERSION}                    ← NOT matched (no ':tag')
#
# We DON'T want to match lines using ${VAR} refs without inline defaults
# because we don't know the tag without the env file.
_IMAGE_LINE = re.compile(
    r"""^\s*image:\s*["']?            # `image:` keyword + optional quote
        (?:[\w./-]+/)?                # optional registry/path prefix
        (?P<name>[\w.-]+)             # image basename (last segment)
        :                             # required colon (no `:` → skip)
        (?P<tag>[\w.-]+)              # tag — letters/digits/dots/hyphens
        ["']?\s*$                     # optional close quote
    """,
    re.VERBOSE | re.MULTILINE,
)


# `${VAR:-default}` extractor for compose patterns like
#   image: ${DB_IMAGE_NAME:-ghcr.io/...}:${DB_IMAGE_TAG:-v2.4.27}
# In that form we want the inline default tag.
_INLINE_DEFAULT_TAG = re.compile(
    r"""^\s*image:\s*["']?
        (?:[$][{][\w]+(?::-)?[\w./-]+[}])?     # ${REGISTRY:-...}
        (?:[\w./-]+/)?                          # or literal path
        (?P<name>[\w.-]+)                       # basename
        :
        (?:[$][{][\w]+:-(?P<dtag>[\w.-]+)[}])   # ${TAG_VAR:-defaultTag}
        ["']?\s*$
    """,
    re.VERBOSE | re.MULTILINE,
)


def parse_compose_for_images(yaml_text: str,
                              names: Dict[str, str]) -> Dict[str, str]:
    """Walk a compose-file's `image:` lines, return {key: tag} for
    every image whose basename is in `names` (basename → output_key).

    Handles two patterns:
      - Literal: `image: postgres:14.1`              → postgres = 14.1
      - With inline default: `image: foo:${T:-v2.4.27}` → if foo is wanted,
        returns foo = v2.4.27
    Skips:
      - `${VAR}` refs without inline defaults (we don't know the value)
      - Images whose basename isn't in `names`
    """
    found: Dict[str, str] = {}
    for m in _IMAGE_LINE.finditer(yaml_text):
        basename = m.group('name')
        if basename in names:
            found[names[basename]] = m.group('tag')
    for m in _INLINE_DEFAULT_TAG.finditer(yaml_text):
        basename = m.group('name')
        dtag = m.group('dtag')
        if basename in names and names[basename] not in found:
            found[names[basename]] = dtag
    return found


def parse_env_for_versions(env_text: str,
                            mapping: Dict[str, str]) -> Dict[str, str]:
    """Walk `NAME=VALUE` env-file lines, return {output_key: VALUE}
    for every NAME in `mapping` (NAME → output_key).

    Ignores comments (#…), blank lines, and quoted values (best-effort
    strip of trailing comments after `#`).
    """
    out: Dict[str, str] = {}
    for raw in env_text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        name, _, val = line.partition('=')
        name = name.strip()
        if name not in mapping:
            continue
        # Strip trailing inline comment + quotes.
        val = val.split('#', 1)[0].strip().strip('"').strip("'")
        if val:
            out[mapping[name]] = val
    return out


def _http_get_text(url: str, timeout: int = 15) -> Optional[str]:
    """Fetch a URL as text. Returns None on any failure (fail-open).
    Imports `requests` lazily so this module is cheap to import."""
    try:
        import requests
    except Exception:
        # Standard-library fallback so the CLI works without the backend
        # venv (e.g. when an operator runs `python3 -m
        # services.upgrade.transitive_resolver` from outside the
        # container).
        import urllib.request
        try:
            req = urllib.request.Request(
                url, headers={'User-Agent': 'intact-ai-transitive-resolver'},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status != 200:
                    return None
                return resp.read().decode('utf-8', errors='replace')
        except Exception:
            return None
    try:
        r = requests.get(url, timeout=timeout, headers={
            'User-Agent': 'intact-ai-transitive-resolver',
            'Accept': 'text/plain, */*',
        })
        if r.status_code != 200:
            return None
        return r.text
    except Exception:
        return None


def resolve_for(module: str, version: str,
                 logger=None) -> Dict[str, str]:
    """Return the transitive container versions that `module` @ `version`
    declares upstream. Empty dict if the module has no resolver entry
    or if upstream fetch fails (fail-open — caller falls back to
    local hardcoded defaults).

    Args:
        module: primary module name (e.g. 'timesketch'); must be a key
                in RESOLVERS, otherwise returns {}.
        version: the operator's pinned version (e.g. '20260611' or
                 '3.16.0'); `tag_prefix` is applied automatically.
        logger: optional callable(msg, level='info'); silent if None.
    """
    log = logger or (lambda msg, level='info': None)
    entry = RESOLVERS.get(module)
    if not entry:
        return {}

    tag = f"{entry.get('tag_prefix', '')}{version}"
    result: Dict[str, str] = {}

    # Env-file path (e.g. Timesketch's config.env)
    env_url_tpl = entry.get('env_url')
    if env_url_tpl:
        url = env_url_tpl.format(tag=tag)
        text = _http_get_text(url)
        if text is None:
            log(f"  transitive_resolver: env_url unreachable for "
                f"{module}@{tag} ({url})", "warning")
        else:
            extracted = parse_env_for_versions(text, entry['env_mapping'])
            result.update(extracted)

    # Compose paths (e.g. IRIS, VolWeb)
    for url_tpl in entry.get('compose_urls') or []:
        url = url_tpl.format(tag=tag)
        text = _http_get_text(url)
        if text is None:
            log(f"  transitive_resolver: compose unreachable for "
                f"{module}@{tag} ({url})", "warning")
            continue
        extracted = parse_compose_for_images(
            text, entry['images_of_interest'],
        )
        # Don't let one compose overwrite another's entry (later
        # composes don't shadow earlier ones for the same key — first
        # win matters when, e.g., a dev compose ships a stale tag).
        for k, v in extracted.items():
            result.setdefault(k, v)

    return result


# ---------------------------------------------------------------------------
# CLI entry point so operators can sanity-check a module/version without
# touching the backend. Usage:
#   python3 -m services.upgrade.transitive_resolver timesketch 20260611
# ---------------------------------------------------------------------------
def _cli() -> int:
    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
        print(
            "Usage: python3 -m services.upgrade.transitive_resolver "
            "<module> [version]\n"
            "       (with no args, runs the validation suite against "
            "all configured modules)\n"
            f"       Modules: {', '.join(sorted(RESOLVERS.keys()))}",
            file=sys.stderr,
        )
        # Validation suite — confirms every RESOLVERS entry's upstream
        # source is reachable + parser returns at least one value.
        # Tags below are the ones shipped in repo HEAD today; bump
        # alongside config.yaml pins.
        suite = [
            ('timesketch', '20260611', {'opensearch', 'postgres', 'redis',
                                         'nginx'}),
            ('iris',       'v2.4.27',  {'rabbitmq'}),
            ('volweb',     '3.16.0',   {'postgres', 'redis'}),
        ]
        ok = True
        print("\nRunning validation suite...\n", file=sys.stderr)
        for mod, ver, expected_keys in suite:
            res = resolve_for(mod, ver, logger=lambda m, level='info': print(
                f"  {m}", file=sys.stderr))
            got_keys = set(res.keys())
            missing = expected_keys - got_keys
            status = "OK " if not missing else "MISS"
            print(f"  [{status}] {mod}@{ver}  →  {res}", file=sys.stderr)
            if missing:
                print(f"         missing keys: {missing}", file=sys.stderr)
                ok = False
        return 0 if ok else 1

    module = sys.argv[1]
    if len(sys.argv) >= 3:
        version = sys.argv[2]
    else:
        # Default to what config.yaml says.
        # Try to read from /home/tenroot/intact/config.yaml (host path)
        # then /app/workdir/config.yaml (container path).
        cfg_paths = [
            os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))))),
                'config.yaml'),
            '/home/tenroot/intact/config.yaml',
            '/app/workdir/config.yaml',
        ]
        version = None
        for p in cfg_paths:
            if os.path.exists(p):
                try:
                    import yaml
                    with open(p) as f:
                        cfg = yaml.safe_load(f) or {}
                    version = str(((cfg.get('versions') or {})
                                   .get(module) or '')).strip()
                    if version:
                        break
                except Exception:
                    continue
        if not version:
            print(f"No version given and config.yaml lookup failed for "
                  f"'{module}'", file=sys.stderr)
            return 2

    res = resolve_for(module, version,
                       logger=lambda m, level='info': print(m,
                                                              file=sys.stderr))
    if not res:
        print(f"(empty result for {module}@{version})", file=sys.stderr)
        return 1
    for k, v in sorted(res.items()):
        print(f"{k}={v}")
    return 0


if __name__ == '__main__':
    sys.exit(_cli())
