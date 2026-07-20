"""Download a pre-built release upgrade package from a GitHub Release.

Phase 2 of the CI-built-package effort. Instead of building the upgrade
package ON the customer box (where an older on-box backend can be
module-blind — the factor-5 / "Unknown module" class, where prepare drops a
module a newer release added or renamed), the ONLINE upgrade downloads the
version-pinned package that CI built with the TARGET release's OWN code and
attached to the GitHub Release.

Because a GitHub release asset is capped at 2 GiB, CI splits the tarball into
``<pkg>.tar.gz.part-00``, ``.part-01``, … plus a whole-file
``<pkg>.tar.gz.sha256`` (see .github/workflows/build-release-package.yml).
This module finds those assets, downloads them (resumable, authenticated for
the private repo), concatenates the parts back into a single ``.tar.gz``,
verifies the sha256, and returns the path — which the normal offline-apply
engine (``run_offline_upgrade_workflow(package_path=…)``) then consumes
exactly as if the operator had uploaded it.

Fails soft: ``find_release_package`` / ``download_release_package`` return
``None`` when the target release has no package asset (a pre-CI release, or
the rolling ``development`` branch that has no Release), so the caller falls
back to building on-box and every existing scenario keeps working.
"""
import hashlib
import os
import time
from typing import Callable, List, Optional, Tuple

import requests

from services.upgrade.resolver import GITHUB_API, _github_token

_STREAM_CHUNK = 1024 * 1024          # 1 MiB network/disk streaming chunk
_HASH_CHUNK = 4 * 1024 * 1024        # 4 MiB sha256 read chunk
_CONNECT_TIMEOUT = 30
_READ_TIMEOUT = 300
_RETRIES = 4


class PackageDownloadCancelled(Exception):
    """Raised when the operator hits Stop during the download/reassembly."""


def _cancel_event(run_id: Optional[str]):
    """The workflow's cancel event, so a multi-GB download aborts promptly
    on Stop (same hook tools_download_service.download_file uses)."""
    if not run_id:
        return None
    try:
        from services.workflow_service import get_cancel_event
        return get_cancel_event(run_id)
    except Exception:
        return None


def _headers(octet: bool = False) -> dict:
    """GitHub headers with auth (the repo is private, so asset downloads need
    the token too — not just the api.github.com metadata calls)."""
    h = {
        'User-Agent': 'IntactAI-Upgrade/1.0',
        'Accept': 'application/octet-stream' if octet else 'application/vnd.github+json',
    }
    tok = _github_token()
    if tok:
        h['Authorization'] = f'token {tok}'
    return h


def _get_release(tag: str, log: Callable) -> Optional[dict]:
    url = f'{GITHUB_API}/releases/tags/{tag}'
    r = requests.get(url, headers=_headers(), timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT))
    if r.status_code == 404:
        log(f"  No GitHub release tagged '{tag}' — nothing to download.", "info")
        return None
    r.raise_for_status()
    return r.json()


def find_release_package(tag: str, logger: Callable = None) -> Optional[dict]:
    """Locate the upgrade-package assets on release ``tag``.

    Returns a dict ``{'base', 'parts': [(name,url,size)…], 'whole':
    (name,url,size)|None, 'sha': (name,url)|None}`` or ``None`` when the
    release doesn't exist or carries no upgrade-package asset (caller then
    builds on-box). Asset ``url`` is the api.github.com asset URL, which
    serves the bytes when fetched with ``Accept: application/octet-stream``
    (works for private repos, unlike the browser_download_url which needs a
    session)."""
    log = logger or (lambda m, l="info": None)
    rel = _get_release(tag, log)
    if not rel:
        return None
    base = f"intact-upgrade-{tag}.tar.gz"
    assets = {a['name']: a for a in (rel.get('assets') or [])}
    parts: List[Tuple[str, str, int]] = sorted(
        [(n, a['url'], a.get('size') or 0) for n, a in assets.items()
         if n.startswith(base + '.part-')],
        key=lambda t: t[0],
    )
    whole = None
    if base in assets:
        a = assets[base]
        whole = (base, a['url'], a.get('size') or 0)
    sha = None
    if (base + '.sha256') in assets:
        a = assets[base + '.sha256']
        sha = (base + '.sha256', a['url'])
    if not parts and not whole:
        log(f"  Release '{tag}' has no upgrade-package asset "
            f"(expected {base}[.part-*]) — will build on-box instead.", "info")
        return None
    return {'base': base, 'parts': parts, 'whole': whole, 'sha': sha}


def _download_asset(url: str, dest: str, size: int, run_id: Optional[str],
                    log: Callable, on_progress: Optional[Callable] = None) -> None:
    """Stream one release asset to ``dest`` with auth, resuming a partial file
    via ``Range`` and retrying transient failures. ``size`` (0 = unknown, e.g.
    the tiny .sha256) enables an exact-length check."""
    cancel = _cancel_event(run_id)
    attempt = 0
    while True:
        attempt += 1
        have = os.path.getsize(dest) if os.path.exists(dest) else 0
        if size and have == size:
            return                                   # already complete
        if size and have > size:                     # corrupt/over-long — restart
            os.remove(dest)
            have = 0
        headers = _headers(octet=True)
        mode = 'wb'
        if have:
            headers['Range'] = f'bytes={have}-'
            mode = 'ab'
        try:
            r = requests.get(url, headers=headers, stream=True, allow_redirects=True,
                             timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT))
            # Asked to resume but the server ignored Range (200 not 206):
            # start clean so we don't append onto existing bytes.
            if have and r.status_code == 200:
                r.close()
                if os.path.exists(dest):
                    os.remove(dest)
                have, mode = 0, 'wb'
                r = requests.get(url, headers=_headers(octet=True), stream=True,
                                 allow_redirects=True,
                                 timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT))
            r.raise_for_status()
            downloaded = have
            # Log a progress line every ~5% of the part (min 50 MB) so the
            # operator can see it moving — a 1.9 GB part is otherwise silent
            # for minutes and looks stuck.
            report_every = max((size // 20) if size else 0, 50 * 1024 * 1024)
            next_report = downloaded + report_every
            with open(dest, mode) as f:
                for chunk in r.iter_content(_STREAM_CHUNK):
                    if cancel is not None and cancel.is_set():
                        raise PackageDownloadCancelled()
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if on_progress is not None:
                            on_progress(downloaded)
                        if downloaded >= next_report:
                            if size:
                                log(f"      … {downloaded // 1048576}/{size // 1048576} MB "
                                    f"({downloaded * 100 // size}%)", "info")
                            else:
                                log(f"      … {downloaded // 1048576} MB", "info")
                            next_report = downloaded + report_every
            got = os.path.getsize(dest)
            if size and got != size:
                raise IOError(f"length mismatch: got {got}, expected {size}")
            return
        except PackageDownloadCancelled:
            raise
        except Exception as e:
            if attempt >= _RETRIES:
                raise
            backoff = min(30, 2 ** attempt)
            resume_at = os.path.getsize(dest) if os.path.exists(dest) else 0
            log(f"    download hiccup ({type(e).__name__}: {e}) — retry "
                f"{attempt}/{_RETRIES} in {backoff}s (resume @ {resume_at} bytes)",
                "warning")
            time.sleep(backoff)


def _verify_sha256(path: str, expected: str, run_id: Optional[str],
                   log: Callable) -> None:
    cancel = _cancel_event(run_id)
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for buf in iter(lambda: f.read(_HASH_CHUNK), b''):
            if cancel is not None and cancel.is_set():
                raise PackageDownloadCancelled()
            h.update(buf)
    got = h.hexdigest().lower()
    if got != expected.lower():
        try:
            os.remove(path)
        except OSError:
            pass
        raise IOError(f"package sha256 mismatch: got {got[:12]}…, "
                      f"expected {expected[:12]}…")
    log("  Package sha256 verified.", "success")


def download_release_package(tag: str, dest_dir: str, run_id: str = None,
                             logger: Callable = None,
                             progress_cb: Optional[Callable] = None) -> Optional[str]:
    """Download + reassemble + verify the CI package for release ``tag``.

    Returns the path to a single ``.tar.gz`` under ``dest_dir`` (ready for
    ``run_offline_upgrade_workflow(package_path=…)``), or ``None`` when the
    release has no package asset (caller falls back to building on-box).
    Raises ``PackageDownloadCancelled`` on Stop, or ``IOError`` on a sha
    mismatch."""
    log = logger or (lambda m, l="info": print(f"[{l}] {m}"))
    info = find_release_package(tag, logger=log)
    if not info:
        return None
    os.makedirs(dest_dir, exist_ok=True)
    final_path = os.path.join(dest_dir, info['base'])

    # Whole-file sha sidecar (tiny) first, so we can verify after reassembly.
    expected_sha = None
    if info['sha']:
        sha_path = os.path.join(dest_dir, info['sha'][0])
        _download_asset(info['sha'][1], sha_path, 0, run_id, log)
        try:
            expected_sha = open(sha_path).read().split()[0].strip()
        except Exception:
            expected_sha = None
        finally:
            try:
                os.remove(sha_path)
            except OSError:
                pass

    if info['whole']:
        name, url, size = info['whole']
        log(f"Downloading pre-built release package {name} "
            f"({size / 1024 / 1024:.0f} MB, built in CI from {tag}'s own code)…",
            "info")
        _download_asset(url, final_path, size, run_id, log)
    else:
        parts = info['parts']
        total = sum(p[2] for p in parts)
        log(f"Downloading pre-built release package for {tag}: {len(parts)} "
            f"parts, {total / 1024 / 1024 / 1024:.1f} GB (built in CI from the "
            f"target release's own code — no on-box build needed)…", "info")
        part_paths: List[str] = []
        done_bytes = 0  # bytes fully downloaded in PRIOR parts
        for i, (name, url, size) in enumerate(parts):
            pth = os.path.join(dest_dir, name)
            log(f"  part {i + 1}/{len(parts)}: {name} "
                f"({size / 1024 / 1024:.0f} MB)", "info")
            # Feed an overall fraction (download phase = 0..0.9 of the bar) so
            # the workflow progress bar advances smoothly, not just per-part.
            cb = None
            if progress_cb and total:
                cb = lambda d, _base=done_bytes: progress_cb(
                    min(0.9, (_base + d) / total))
            _download_asset(url, pth, size, run_id, log, on_progress=cb)
            done_bytes += size
            part_paths.append(pth)
        # Concatenate, deleting each part as soon as it's appended so peak
        # disk is ~ the assembled file + one part, not 2× the package.
        cancel = _cancel_event(run_id)
        log("  Reassembling parts into a single package…", "info")
        with open(final_path, 'wb') as out:
            for pth in part_paths:
                with open(pth, 'rb') as pf:
                    while True:
                        if cancel is not None and cancel.is_set():
                            raise PackageDownloadCancelled()
                        buf = pf.read(_STREAM_CHUNK)
                        if not buf:
                            break
                        out.write(buf)
                try:
                    os.remove(pth)
                except OSError:
                    pass

    if expected_sha:
        log("  Verifying package sha256…", "info")
        _verify_sha256(final_path, expected_sha, run_id, log)
    else:
        log("  No .sha256 sidecar on the release — skipping whole-file check "
            "(the apply step still verifies every file against the in-package "
            "manifest).", "warning")
    return final_path
