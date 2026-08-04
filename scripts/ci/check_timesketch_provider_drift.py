#!/usr/bin/env python3
"""Warn when upstream Timesketch moves the contract our LLM providers rely on.

We add two LLM providers to Timesketch, which ships as a vendor image we do
not build. Doing that means writing into the container's site-packages and
appending imports to a file UPSTREAM owns
(``timesketch/lib/llms/providers/__init__.py``), against an interface upstream
also owns. A Timesketch version bump can change any of it.

The failure is not gentle. ``LLMManager.register_provider()`` raises
``ValueError`` on a duplicate provider name, and that exception propagates out
of ``timesketch.wsgi`` — so if upstream ever ships its own ``openrouter``, the
naive outcome is not a missing feature, it is four containers in a crash loop.
``apply.sh`` defends against that at runtime; this script is the part that
tells a human BEFORE the release goes out.

What it compares is upstream against upstream — the Timesketch version this
release pins, versus the version a human last verified our providers against.
Not our files against theirs. The baseline is only re-stamped by a person who
has actually tested the providers on the new version, which is what stops this
from going quiet on its own.

    python3 scripts/ci/check_timesketch_provider_drift.py            # check the pinned version
    python3 scripts/ci/check_timesketch_provider_drift.py --json     # machine-readable
    python3 scripts/ci/check_timesketch_provider_drift.py --github   # ::warning:: + step summary
    python3 scripts/ci/check_timesketch_provider_drift.py --version 20260630 --stamp

Exit codes (the workflow maps ALL of them to success — this never fails a
release build; see the `resolve` job in
.github/workflows/build-release-assets.yml):

    0   verified, no drift
    10  drift detected
    20  could not verify (network, missing tag, unreadable baseline)

Stdlib only, and the network is touched only by ``fetch_upstream_files``, so
everything else runs offline.
"""

import argparse
import difflib
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def _default_config():
    """config.yaml is the operator's own file and is not tracked in git (GitHub
    PAT, dashboard login, module passwords), so a CI checkout — where this runs —
    has config.yaml tracked, carrying the `versions:` pin this reads."""
    for name in ('config.yaml',):
        candidate = os.path.join(REPO_ROOT, name)
        if os.path.isfile(candidate):
            return candidate
    return os.path.join(REPO_ROOT, 'config.yaml')


DEFAULT_CONFIG = _default_config()
DEFAULT_BASELINE = os.path.join(REPO_ROOT, 'scripts', 'ci',
                                'timesketch_provider_baseline.json')

# Same URL modules/backend/services/upgrade/package.py already fetches to
# bundle Timesketch's alembic migrations, so this is not a new network
# destination for the release build. Deliberately NOT api.github.com: that is
# 60 requests/hour per runner IP for anonymous callers and it does 403 in
# practice. codeload has no such limit.
TARBALL_URL = "https://github.com/google/timesketch/archive/refs/tags/{version}.tar.gz"
FETCH_TIMEOUT = 120

# ---------------------------------------------------------------------------
# What we watch, and why. Two tiers.
#
#   contract        our providers are written against this; a change means
#                   "go test the providers on the new version"
#   must_not_exist  upstream shipping a provider under one of OUR names is a
#                   name collision — apply.sh will then decline to install
#                   ours, and the operator gets upstream's behaviour instead
#   advisory        early-warning signal; a change here is worth a look but
#                   rarely breaks anything on its own
# ---------------------------------------------------------------------------
_P = "timesketch/lib/llms/providers"

WATCHED = {
    f"{_P}/__init__.py": (
        "contract",
        "apply.sh appends our import block to this file"),
    f"{_P}/interface.py": (
        "contract",
        "LLMProvider.__init__, the DEFAULT_* constants and generate()'s signature"),
    f"{_P}/manager.py": (
        "contract",
        "register_provider() and its duplicate-name ValueError"),
    f"{_P}/contrib/__init__.py": (
        "contract",
        "empty upstream; content here means upstream took over contrib wiring"),
    f"{_P}/contrib/openrouter.py": (
        "must_not_exist",
        "name collision with our openrouter provider"),
    f"{_P}/contrib/litellm_proxy.py": (
        "must_not_exist",
        "name collision with our litellm_proxy provider"),
    f"{_P}/contrib/azureai.py": (
        "advisory",
        "the reference contrib provider ours are modelled on"),
    "timesketch/api/v1/resources/settings.py": (
        "advisory",
        "decides whether a provider surfaces to the UI as available"),
}

EXIT_OK = 0
EXIT_DRIFT = 10
EXIT_UNVERIFIED = 20


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------

def read_pinned_version(config_path):
    """Pull versions.timesketch out of config.yaml.

    Regex rather than pyyaml so this runs anywhere with a bare interpreter —
    including the offline test container, which has no yaml guarantee. The
    pattern is scoped to the versions: block so it cannot pick up the
    modules.timesketch.enabled key or a commented-out neighbour.
    """
    with open(config_path, 'r', encoding='utf-8') as handle:
        content = handle.read()

    block = re.search(r'^versions:\s*$(.*?)(?=^\S)', content,
                      re.MULTILINE | re.DOTALL)
    scope = block.group(1) if block else content
    match = re.search(r"^\s+timesketch:\s*'?\"?([A-Za-z0-9._-]+)'?\"?\s*(?:#.*)?$",
                      scope, re.MULTILINE)
    if not match:
        raise ValueError(
            f"could not find versions.timesketch in {config_path}")
    return match.group(1)


def load_baseline(path):
    with open(path, 'r', encoding='utf-8') as handle:
        return json.load(handle)


# ---------------------------------------------------------------------------
# Fetch (the only part that touches the network)
# ---------------------------------------------------------------------------

def _safe_members(tar):
    """Yield members that are plain files at a sane path.

    An absolute or ``..`` path in a tarball is the classic path-traversal
    trick. Nothing here is extracted to disk, but reading is filtered anyway —
    the repo already carries this habit in services/archive_guard.py.
    """
    for member in tar.getmembers():
        if not member.isfile():
            continue
        name = member.name
        if name.startswith('/') or '..' in name.split('/'):
            continue
        yield member


def read_tarball(path_or_fileobj, watched=None):
    """Return {watched_path: content_bytes} for the files present."""
    watched = WATCHED if watched is None else watched
    found = {}
    opener = (tarfile.open(fileobj=path_or_fileobj, mode='r:gz')
              if hasattr(path_or_fileobj, 'read')
              else tarfile.open(path_or_fileobj, mode='r:gz'))
    with opener as tar:
        for member in _safe_members(tar):
            # Archive members are prefixed with 'timesketch-<tag>/'; match on
            # the suffix so the prefix never has to be guessed.
            for wanted in watched:
                if member.name.endswith('/' + wanted):
                    handle = tar.extractfile(member)
                    if handle is not None:
                        found[wanted] = handle.read()
                    break
    return found


def fetch_upstream_files(version, watched=None, timeout=FETCH_TIMEOUT):
    """Download the tag tarball and return {watched_path: content_bytes}.

    Raises RuntimeError with an operator-readable reason on any failure —
    callers turn that into "could not verify", never into a hard failure.
    """
    url = TARBALL_URL.format(version=version)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            payload = response.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise RuntimeError(
                f"no upstream Timesketch tag '{version}' ({url} -> 404). "
                f"Is versions.timesketch a real upstream release tag?") from exc
        raise RuntimeError(f"HTTP {exc.code} fetching {url}") from exc
    except Exception as exc:  # network, DNS, TLS, timeout
        raise RuntimeError(f"{type(exc).__name__} fetching {url}: {exc}") from exc

    try:
        return read_tarball(io.BytesIO(payload), watched=watched)
    except tarfile.TarError as exc:
        raise RuntimeError(f"unreadable tarball at {url}: {exc}") from exc


# ---------------------------------------------------------------------------
# Compare (pure — no I/O, no network)
# ---------------------------------------------------------------------------

def sha256(data):
    return hashlib.sha256(data).hexdigest()


def compare(baseline, upstream_digests, watched=None):
    """Diff a baseline against upstream digests.

    baseline          the parsed baseline JSON
    upstream_digests  {watched_path: sha256-hex}, absent key == file not present

    Returns {"drift": bool, "findings": [...]} where each finding has
    path / tier / kind / detail. Deliberately pure so the whole verdict is
    testable without a network.
    """
    watched = WATCHED if watched is None else watched
    recorded = baseline.get('files', {})
    findings = []

    for path, (tier, why) in sorted(watched.items()):
        expected = recorded.get(path, {})
        present_now = path in upstream_digests

        if tier == 'must_not_exist':
            if present_now:
                findings.append({
                    'path': path, 'tier': tier, 'kind': 'appeared',
                    'detail': f"upstream now ships this file — {why}. apply.sh "
                              f"will decline to install ours, so the provider "
                              f"an operator selects is upstream's, not ours."})
            continue

        if not present_now:
            findings.append({
                'path': path, 'tier': tier, 'kind': 'removed',
                'detail': f"upstream no longer ships this file — {why}"})
            continue

        expected_sha = expected.get('sha256')
        if not expected_sha:
            findings.append({
                'path': path, 'tier': tier, 'kind': 'unbaselined',
                'detail': f"no baseline digest recorded for this file — {why}"})
            continue

        if expected_sha != upstream_digests[path]:
            findings.append({
                'path': path, 'tier': tier, 'kind': 'changed',
                'detail': f"changed upstream — {why}"})

    return {'drift': bool(findings), 'findings': findings}


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

_REMEDIATION = """\
What to do
  1. Read the diff above and decide whether it affects our providers
     (modules/timesketch/llm_providers/).
  2. Bring the stack up on the new Timesketch version and confirm both
     providers still register:
       docker exec intact_timesketch_web python3 -c \\
         "from timesketch.lib.llms.providers import manager; \\
          print(sorted(n for n,_ in manager.LLMManager.get_providers()))"
  3. Fix modules/timesketch/llm_providers/ if needed, then re-stamp:
       python3 scripts/ci/check_timesketch_provider_drift.py --version {version} --stamp
     and commit scripts/ci/timesketch_provider_baseline.json.

This warning does not block the release. It means the package that was just
built is worth testing before you hand it to a customer.\
"""


def _unified_diff(old_text, new_text, path, max_lines=80):
    diff = list(difflib.unified_diff(
        old_text.splitlines(), new_text.splitlines(),
        fromfile=f"baseline/{path}", tofile=f"upstream/{path}", lineterm=''))
    if len(diff) > max_lines:
        diff = diff[:max_lines] + [f"... ({len(diff) - max_lines} more diff lines)"]
    return "\n".join(diff)


def render_report(result, baseline, version, sources=None, baseline_sources=None):
    """Human-readable verdict. Returns (text, list_of_annotation_lines).

    `sources` / `baseline_sources` are {path: text} for the pinned and the
    last-verified upstream versions. When both are available the report shows
    the actual upstream-to-upstream diff; when they are not (offline, tag
    gone) it still reports the drift, just without the detail.
    """
    lines = []
    annotations = []
    was = baseline.get('verified_upstream_version', '?')

    if not result['drift']:
        lines.append(
            f"Timesketch LLM-provider contract: no upstream drift "
            f"(pinned {version}, baseline verified against {was}).")
        return "\n".join(lines), annotations

    lines.append("Timesketch LLM-provider contract: UPSTREAM DRIFT DETECTED")
    lines.append("")
    lines.append(f"  release pins Timesketch : {version}")
    lines.append(f"  baseline verified against: {was} "
                 f"(on {baseline.get('verified_on', '?')} "
                 f"by {baseline.get('verified_by', '?')})")
    lines.append("")
    lines.append("Our two contrib LLM providers (openrouter, litellm_proxy) are")
    lines.append("written against these upstream files and are installed into the")
    lines.append("vendor container at start-up. Something they depend on moved:")
    lines.append("")

    for finding in result['findings']:
        lines.append(f"  [{finding['tier']}/{finding['kind']}] {finding['path']}")
        lines.append(f"      {finding['detail']}")
        annotations.append(
            f"::warning file={finding['path']}::Timesketch {finding['kind']}: "
            f"{finding['path']} ({finding['tier']}) — {finding['detail']}")

    if sources and baseline_sources:
        for finding in result['findings']:
            path = finding['path']
            if finding['kind'] != 'changed':
                continue
            old = baseline_sources.get(path)
            new = sources.get(path)
            if old is None or new is None:
                continue
            lines.append("")
            lines.append(f"--- {was} -> {version}: {path} ---")
            lines.append(_unified_diff(old, new, path))
    elif result['drift']:
        lines.append("")
        lines.append(f"(diff against {was} unavailable — could not fetch that "
                     f"upstream tag; the findings above still stand)")

    lines.append("")
    lines.append(_REMEDIATION.format(version=version))
    return "\n".join(lines), annotations


def emit_github(text, annotations):
    for annotation in annotations:
        print(annotation)
    summary_path = os.environ.get('GITHUB_STEP_SUMMARY')
    if not summary_path:
        return
    try:
        with open(summary_path, 'a', encoding='utf-8') as handle:
            handle.write("## Timesketch LLM-provider drift\n\n")
            handle.write("```\n")
            handle.write(text)
            handle.write("\n```\n")
    except OSError as exc:
        print(f"(could not write the step summary: {exc})")


# ---------------------------------------------------------------------------
# Stamp
# ---------------------------------------------------------------------------

def stamp(baseline_path, version, sources, digests, verified_by):
    import datetime
    existing = {}
    if os.path.isfile(baseline_path):
        try:
            existing = load_baseline(baseline_path)
        except (OSError, ValueError):
            existing = {}

    files = {}
    for path, (tier, why) in sorted(WATCHED.items()):
        entry = {'tier': tier, 'why': why}
        if tier == 'must_not_exist':
            entry['present_upstream'] = path in digests
        elif path in digests:
            entry['sha256'] = digests[path]
        else:
            entry['sha256'] = None
            entry['note'] = 'not present in this upstream tag'
        files[path] = entry

    baseline = {
        '_comment': (
            'Upstream Timesketch files our contrib LLM providers depend on, as '
            'last VERIFIED BY A HUMAN. Regenerate only after actually testing '
            'the providers on the new version: '
            'python3 scripts/ci/check_timesketch_provider_drift.py '
            '--version <tag> --stamp'),
        'verified_upstream_version': version,
        'verified_on': datetime.date.today().isoformat(),
        'verified_by': verified_by or existing.get('verified_by', 'unknown'),
        'known_upstream_provider_names': sorted(
            _provider_names(sources.get(f"{_P}/__init__.py", ''))
            or existing.get('known_upstream_provider_names', [])),
        'files': files,
    }
    with open(baseline_path, 'w', encoding='utf-8') as handle:
        json.dump(baseline, handle, indent=2, sort_keys=False)
        handle.write("\n")
    return baseline


def _provider_names(providers_init_text):
    """Best-effort list of the provider modules upstream imports.

    Used only to record what existed at stamp time, so a future collision has
    something to be compared against. Module name, not the class's NAME
    attribute — reading that would mean importing upstream code.
    """
    return sorted(set(re.findall(
        r'^from\s+timesketch\.lib\.llms\.providers(?:\.contrib)?\s+import\s+(\w+)',
        providers_init_text, re.MULTILINE)))


# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Warn when upstream Timesketch moves the LLM-provider contract.")
    parser.add_argument('--version', help="upstream tag (default: versions.timesketch)")
    parser.add_argument('--config', default=DEFAULT_CONFIG)
    parser.add_argument('--baseline', default=DEFAULT_BASELINE)
    parser.add_argument('--tarball', help="use a local tarball instead of fetching")
    parser.add_argument('--stamp', action='store_true',
                        help="record the fetched version as the verified baseline")
    parser.add_argument('--verified-by', default=None)
    parser.add_argument('--json', action='store_true', dest='as_json')
    parser.add_argument('--github', action='store_true',
                        help="emit ::warning:: annotations and a step summary")
    args = parser.parse_args(argv)

    def bail(reason):
        payload = {'status': 'unverified', 'reason': reason}
        if args.as_json:
            print(json.dumps(payload, indent=2))
        else:
            print(f"Timesketch LLM-provider contract: COULD NOT VERIFY — {reason}")
        if args.github:
            print(f"::warning::Timesketch LLM-provider drift check could not "
                  f"run: {reason}")
            emit_github(
                f"Timesketch LLM-provider contract: COULD NOT VERIFY\n\n"
                f"  {reason}\n\nThe release is unaffected; the check simply did "
                f"not get an answer.", [])
        return EXIT_UNVERIFIED

    try:
        version = args.version or read_pinned_version(args.config)
    except (OSError, ValueError) as exc:
        return bail(str(exc))

    try:
        if args.tarball:
            sources_raw = read_tarball(args.tarball)
        else:
            sources_raw = fetch_upstream_files(version)
    except (RuntimeError, OSError, tarfile.TarError) as exc:
        return bail(str(exc))

    digests = {path: sha256(blob) for path, blob in sources_raw.items()}
    sources = {path: blob.decode('utf-8', 'replace')
               for path, blob in sources_raw.items()}

    if args.stamp:
        baseline = stamp(args.baseline, version, sources, digests, args.verified_by)
        message = (f"Baseline stamped: Timesketch {version}, "
                   f"{len(baseline['files'])} files -> {args.baseline}")
        print(json.dumps(baseline, indent=2) if args.as_json else message)
        return EXIT_OK

    try:
        baseline = load_baseline(args.baseline)
    except (OSError, ValueError) as exc:
        return bail(f"unreadable baseline {args.baseline}: {exc}")

    result = compare(baseline, digests)

    # Only when something actually moved, and only to enrich the report: pull
    # the last-verified tag too so the operator sees the real
    # upstream-to-upstream diff rather than just "the hash changed". Best
    # effort by design — a second network call must not turn a successful
    # drift report into "could not verify".
    baseline_sources = None
    baseline_version = baseline.get('verified_upstream_version')
    if result['drift'] and baseline_version and baseline_version != version:
        try:
            baseline_sources = {
                path: blob.decode('utf-8', 'replace')
                for path, blob in fetch_upstream_files(baseline_version).items()}
        except (RuntimeError, OSError, tarfile.TarError):
            baseline_sources = None

    text, annotations = render_report(result, baseline, version,
                                      sources=sources,
                                      baseline_sources=baseline_sources)

    if args.as_json:
        print(json.dumps({
            'status': 'drift' if result['drift'] else 'ok',
            'pinned_version': version,
            'baseline_version': baseline.get('verified_upstream_version'),
            'drift': result['drift'],
            'findings': result['findings'],
        }, indent=2))
    else:
        print(text)

    if args.github:
        emit_github(text, annotations)

    return EXIT_DRIFT if result['drift'] else EXIT_OK


if __name__ == '__main__':
    sys.exit(main())
