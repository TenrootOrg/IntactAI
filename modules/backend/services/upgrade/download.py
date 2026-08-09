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
import shutil
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Optional, Tuple

import requests

from services.upgrade.resolver import GITHUB_API, _github_token

_STREAM_CHUNK = 1024 * 1024          # 1 MiB network/disk streaming chunk
_HASH_CHUNK = 4 * 1024 * 1024        # 4 MiB sha256 read chunk
_CONNECT_TIMEOUT = 30
_READ_TIMEOUT = 300
# 4 sounds generous until the asset is a ~1.9 GB part on a slow link: every
# retry resumes by on-disk size rather than restarting, so each one is cheap,
# and a multi-hour transfer will see more than 4 ordinary TCP blips along the
# way. scripts/prepare_package.sh hit this exact class of bug with the same
# GitHub-CDN mechanism and widened 3 -> 20 for the same reason; matched here.
_RETRIES = 20
# Small, non-resumable calls (release metadata, the tiny .sha256 sidecar) --
# a short, fixed retry count is enough since there's nothing to resume and
# the payload is tiny; the risk is a single dropped connection, not a slow
# transfer.
_META_RETRIES = 3

# Parts download concurrently. A single connection to GitHub's release CDN is
# per-connection limited, not link limited: measured off one box, one stream
# got 8-12 MB/s while four in parallel got 20.8 MB/s on the same link. The
# parts are independent assets, so overlapping them is free speed.
#
# Deliberately parallel ACROSS parts rather than splitting each part into byte
# ranges: _download_asset resumes a partial file by its on-disk size, which
# only holds while one writer appends sequentially. Range-splitting a single
# file would leave holes that size alone cannot describe, so a Stop/retry
# would have to restart the part. Whole packages already exceed the 2 GiB
# asset cap by several parts -- and now that releases ship every module they
# will have more, not fewer -- so this scales on its own.
_PART_WORKERS = 4

# Concurrent ASSET downloads. A release now ships one asset per module, so a
# full fetch is ~9 separate downloads rather than one -- and GitHub throttles a
# single connection well below what the link can carry, which made the
# sequential version spend most of its wall-clock waiting instead of
# transferring. Four rather than "all of them": past that the per-connection
# share falls off faster than the concurrency wins it back, and each extra
# stream is another multi-GB write competing for the same disk.
_ASSET_WORKERS = 4

# One status line for the whole download, rewritten on this interval, instead
# of every part logging its own progress. With parts running concurrently the
# per-part lines interleave, and at ~5% each a 4-part package emits ~80 of
# them — the operator ends up scrolling a transcript of progress instead of
# reading a status. See _PROGRESS_MARKER.
_PROGRESS_SECONDS = 30
_PROGRESS_MARKER = "Download: "

# Floor for a single asset's own progress lines, used only when there is no
# central reporter (the whole-file, non-split package path). Module-level so
# tests can lower it -- inline, a small fixture could never trigger it and a
# test asserting the lines are suppressed would pass vacuously.
_PART_LOG_FLOOR = 50 * 1024 * 1024


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
    # Every download in this module starts with this one call — unlike the
    # asset transfers below, it was never retried at all, so a single dropped
    # connection here aborted the whole online-upgrade attempt before a byte
    # of the package had been fetched. Same retry shape as resolver.py's
    # list_github_refs: retry connection errors/5xx, not 403/404 (answers,
    # not accidents).
    r = None
    last_exc = None
    for attempt in range(_META_RETRIES):
        try:
            r = requests.get(url, headers=_headers(),
                             timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT))
            if r.status_code < 500:
                break
            last_exc = None
        except requests.RequestException as e:
            last_exc = e
            r = None
        if attempt < _META_RETRIES - 1:
            log(f"  release lookup hiccup — retry {attempt + 1}/{_META_RETRIES}", "warning")
            time.sleep(1.5 * (attempt + 1))
    if r is None:
        raise last_exc or IOError(f"could not reach GitHub for release '{tag}'")
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
                    log: Callable, on_progress: Optional[Callable] = None,
                    label: str = "", log_progress: bool = True) -> None:
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
            report_every = max((size // 20) if size else 0, _PART_LOG_FLOOR)
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
                        if log_progress and downloaded >= next_report:
                            if size:
                                log(f"      …{label} {downloaded // 1048576}/"
                                    f"{size // 1048576} MB "
                                    f"({downloaded * 100 // size}%)", "info")
                            else:
                                log(f"      …{label} {downloaded // 1048576} MB", "info")
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
            log(f"    download hiccup{label} ({type(e).__name__}: {e}) — retry "
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
        part_paths: List[str] = [os.path.join(dest_dir, n) for n, _u, _s in parts]
        workers = max(1, min(_PART_WORKERS, len(parts)))
        log(f"  Fetching {len(parts)} parts, {workers} at a time "
            f"(one stream is per-connection limited, not link limited). "
            f"Progress logged every {_PROGRESS_SECONDS}s.", "info")

        # Overall fraction (download phase = 0..0.9 of the bar). Each worker
        # reports ITS OWN cumulative byte count, so the bar needs the sum
        # across parts, not the last value seen — hence the shared dict.
        # Ordering between workers is arbitrary, so the lock is what keeps the
        # sum from being computed mid-update and jumping backwards.
        seen = {i: 0 for i in range(len(parts))}
        seen_lock = threading.Lock()

        def _mk_cb(idx):
            def _cb(done):
                with seen_lock:
                    seen[idx] = done
                    agg = sum(seen.values())
                if progress_cb and total:
                    progress_cb(min(0.9, agg / total))
            return _cb

        def _status_line() -> str:
            """One line covering every part, e.g.

              Download: [part 1/4] 1805/1900 MB (95%), [part 2/4] 1900/1900 MB
              (Completed), [part 3/4] 1425/1900 MB (75%), [part 4/4] queued
            """
            with seen_lock:
                done_now = dict(seen)
            bits = []
            for i, (_n, _u, size) in enumerate(parts):
                d = done_now.get(i, 0)
                mb, tot_mb = d // 1048576, size // 1048576
                if size and d >= size:
                    bits.append(f"[part {i + 1}/{len(parts)}] {tot_mb}/{tot_mb} MB (Completed)")
                elif d:
                    pct = (d * 100 // size) if size else 0
                    bits.append(f"[part {i + 1}/{len(parts)}] {mb}/{tot_mb} MB ({pct}%)")
                else:
                    bits.append(f"[part {i + 1}/{len(parts)}] queued")
            agg = sum(done_now.values())
            overall = (agg * 100 // total) if total else 0
            return (f"{_PROGRESS_MARKER}{overall}% of "
                    f"{total / 1024 / 1024 / 1024:.1f} GB — " + ", ".join(bits))

        def _emit_status():
            """Append a new progress line each interval.

            This used to upsert a SINGLE line in place, keyed by
            _PROGRESS_MARKER. In a terminal that reads well; in the workflow
            log viewer it does not, because the history is the information:
            whether throughput is holding, when a part stalled, and how long
            the download has really been running. An in-place line answers none
            of those -- a transfer frozen for ten minutes looks identical to a
            healthy one, since the only thing that changes is a number you
            never saw before.

            One line per interval is cheap: a 5.7 GB package at typical speeds
            is a few dozen lines, each timestamped by the viewer.
            """
            log(_status_line(), "info")

        stop_reporter = threading.Event()

        def _reporter():
            _emit_status()                       # place the line immediately
            while not stop_reporter.wait(_PROGRESS_SECONDS):
                _emit_status()

        reporter = threading.Thread(target=_reporter, name="pkg-progress",
                                    daemon=True)
        reporter.start()

        try:
            with ThreadPoolExecutor(max_workers=workers,
                                    thread_name_prefix="pkg-part") as ex:
                futures = {
                    ex.submit(_download_asset, url, part_paths[i], size, run_id,
                              log, _mk_cb(i), f" [part {i + 1}/{len(parts)}]",
                              False): i
                    for i, (name, url, size) in enumerate(parts)
                }
                # Surface the first failure (Stop, or a hard error after
                # retries). In-flight parts are left to finish rather than
                # killed mid-write: each is resumable by on-disk size, so a
                # completed or partial file is a head start for the retry,
                # never corruption. A Stop propagates to the others anyway —
                # they share the run's cancel event and check it every chunk.
                first_error = None
                for fut in as_completed(futures):
                    try:
                        fut.result()
                    except BaseException as e:   # noqa: BLE001 — re-raised below
                        if first_error is None:
                            first_error = e
                if first_error is not None:
                    raise first_error
        finally:
            # Stop before the final emit, so the reporter can't race it and
            # leave a stale mid-download line as the last word.
            stop_reporter.set()
            reporter.join(timeout=5)
        _emit_status()
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


# ===========================================================================
# Per-module release assets
# ===========================================================================
#
# A release publishes one asset per module plus an index describing them. The
# box downloads only the modules it is actually installing or upgrading, then
# assembles them into one package_dir (see base.assemble_release_package).
#
# find_release_index returning None is the whole transition strategy: releases
# built before this existed have no index, the caller falls back to
# download_release_package, and the legacy single-bundle path is untouched.

def find_release_index(tag: str, logger: Callable = None) -> Optional[dict]:
    """The per-module asset index for release ``tag``, or None if it has none.

    Shape:
        {"release_tag": …, "source_commit": …,
         "assets": {"<module>": {"asset": name, "version": …,
                                 "sha256": …, "size": n,
                                 "parts": [name, …]}}}
    """
    log = logger or (lambda m, l="info": None)
    rel = _get_release(tag, log)
    if not rel:
        return None
    assets = {a['name']: a for a in (rel.get('assets') or [])}
    # `<tag>.index.json`. The older spelling glued a literal `intact-release-`
    # onto a tag that already starts with `intact-`, producing
    # `intact-release-intact-20260804.index.json` -- which reads like a module
    # asset for a module named "release". Both are accepted so a release cut
    # under the old name stays readable.
    name = next((n for n in (f"{tag}.index.json",
                             f"intact-release-{tag}.index.json")
                 if n in assets), None)
    if not name:
        log(f"  Release '{tag}' has no per-module index ({tag}.index.json) — "
            f"using the single-package path.", "info")
        return None
    # A transient blip here used to fall straight through to the legacy
    # single-package path — misleading on a modern release that has no such
    # asset, and it throws away the per-module scoping for no real reason.
    # Retry the small JSON fetch first; only fall back once it has genuinely
    # failed _META_RETRIES times.
    index = None
    last_exc = None
    for attempt in range(_META_RETRIES):
        try:
            r = requests.get(assets[name]['url'], headers=_headers(octet=True),
                             timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT))
            r.raise_for_status()
            index = r.json()
            break
        except Exception as e:
            last_exc = e
            if attempt < _META_RETRIES - 1:
                log(f"  release index fetch hiccup — retry {attempt + 1}/{_META_RETRIES}", "warning")
                time.sleep(1.5 * (attempt + 1))
    if index is None:
        log(f"  Could not read the release index ({type(last_exc).__name__}: {last_exc}) — "
            f"falling back to the single package.", "warning")
        return None

    # Attach the live asset URLs; the index records names, not URLs, so it
    # stays valid if the repo is renamed or mirrored.
    for module, entry in (index.get('assets') or {}).items():
        entry['urls'] = []
        for n in ([entry['asset']] if entry.get('asset') in assets
                  else (entry.get('parts') or [])):
            if n in assets:
                entry['urls'].append((n, assets[n]['url'],
                                      assets[n].get('size') or 0))
    return index


def download_release_assets(tag: str, modules, dest_dir: str,
                            run_id: str = None, logger: Callable = None,
                            progress_cb: Optional[Callable] = None):
    """Download the assets for ``modules`` from release ``tag``.

    Returns ``(asset_paths, index)``. Raises IOError if any requested module has
    no asset, or if one fails its checksum.

    A MISSING ASSET IS FATAL, deliberately. The apply loop is driven by the
    assembled manifest's ``versions``, so a module whose asset quietly failed to
    download simply would not appear there — and the run would report success
    having never touched it. That is the same silent-staleness failure the delta
    scheme had, arriving through a different door, so it is refused here and
    again in the assembler.
    """
    log = logger or (lambda m, l="info": print(f"[{l}] {m}"))
    index = find_release_index(tag, logger=log)
    if not index:
        return None, None

    available = index.get('assets') or {}
    wanted = [m for m in modules if m in available]
    missing = sorted(set(modules) - set(available))
    if missing:
        raise IOError(
            f"release {tag} has no asset for: {', '.join(missing)}. "
            f"Applying without them would leave those modules untouched while "
            f"reporting success.")

    os.makedirs(dest_dir, exist_ok=True)

    total_bytes = sum((available[m].get('size') or 0) for m in wanted)
    log(f"Downloading {len(wanted)} asset(s) from {tag} "
        f"({total_bytes / (1024 ** 3):.2f} GB): {', '.join(sorted(wanted))}",
        "info")

    # PARALLEL ACROSS ASSETS. GitHub throttles a single connection well below
    # what the link can carry, so nine sequential downloads spend most of their
    # time waiting rather than transferring. Bounded at _ASSET_WORKERS because
    # past that the per-connection share drops faster than the concurrency buys
    # back, and every extra stream is another multi-GB write competing for the
    # same disk.
    #
    # Progress is reported by a single reporter thread rather than by each
    # worker: nine workers logging their own percentages interleave into
    # something unreadable, and the operator only wants one question answered --
    # how much of the whole download is left.
    done_bytes = {m: 0 for m in wanted}
    done_lock = threading.Lock()
    finished = set()
    results: Dict[str, str] = {}
    errors: Dict[str, BaseException] = {}

    def _progress_for(module):
        def _cb(n):
            with done_lock:
                done_bytes[module] = n
        return _cb

    def _fetch(module):
        entry = available[module]
        urls = entry.get('urls') or []
        if not urls:
            raise IOError(f"release {tag} lists {module} in its index but the "
                          f"asset itself is not attached to the release")
        final = os.path.join(dest_dir, entry['asset'])

        if len(urls) == 1 and urls[0][0] == entry['asset']:
            name, url, size = urls[0]
            _download_asset(url, final, size, run_id, log,
                            _progress_for(module), label=f"{module} ",
                            log_progress=False)
        else:
            # Split asset: fetch its parts, then concatenate, removing each as
            # it is appended so peak disk stays at assembled + one part.
            part_paths = []
            for name, url, size in urls:
                pp = os.path.join(dest_dir, name)
                _download_asset(url, pp, size, run_id, log, None,
                                label=f"{module} ", log_progress=False)
                part_paths.append(pp)
            with open(final, 'wb') as out:
                for pp in part_paths:
                    with open(pp, 'rb') as chunk:
                        shutil.copyfileobj(chunk, out, 8 * 1024 * 1024)
                    os.remove(pp)

        want = entry.get('sha256')
        if want:
            _verify_sha256(final, want, run_id, log)
        else:
            log(f"  {module}: no sha256 in the index — integrity unverified",
                "warning")
        return final

    stop_reporting = threading.Event()

    def _report():
        # One line every _PROGRESS_SECONDS, naming what is still in flight so a
        # stall is attributable to a module rather than to "the download".
        while not stop_reporting.wait(_PROGRESS_SECONDS):
            with done_lock:
                got = sum(done_bytes.values())
                pending = sorted(set(wanted) - finished)
            pct = (got * 100 // total_bytes) if total_bytes else 0
            log(f"  … {got / (1024 ** 3):.2f}/{total_bytes / (1024 ** 3):.2f} GB "
                f"({pct}%) — {len(finished)}/{len(wanted)} done"
                + (f", fetching {', '.join(pending[:3])}"
                   f"{'…' if len(pending) > 3 else ''}" if pending else ""),
                "info")

    reporter = threading.Thread(target=_report, daemon=True)
    reporter.start()
    try:
        workers = max(1, min(_ASSET_WORKERS, len(wanted)))
        with ThreadPoolExecutor(max_workers=workers,
                                thread_name_prefix='asset-dl') as ex:
            futures = {ex.submit(_fetch, m): m for m in sorted(wanted)}
            for fut in as_completed(futures):
                module = futures[fut]
                try:
                    results[module] = fut.result()
                except BaseException as e:          # noqa: BLE001 - re-raised
                    errors[module] = e
                with done_lock:
                    finished.add(module)
                if module in results:
                    log(f"  ✓ {module} ({os.path.getsize(results[module]) / (1024 ** 2):.0f} MB) "
                        f"[{len(finished)}/{len(wanted)}]", "success")
    finally:
        stop_reporting.set()

    if errors:
        # Cancellation wins over any other failure: it is what the operator
        # asked for, not something that went wrong.
        for e in errors.values():
            if isinstance(e, PackageDownloadCancelled):
                raise e
        first = sorted(errors)[0]
        raise IOError(f"could not download the {first} asset: {errors[first]}")

    paths = [results[m] for m in sorted(results)]
    log(f"  {len(paths)} asset(s) ready", "success")
    return paths, index
