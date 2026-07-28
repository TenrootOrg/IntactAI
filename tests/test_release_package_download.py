"""Parallel multi-part download of a CI release package.

A single connection to GitHub's release CDN is per-connection limited, not link
limited -- measured off one box, one stream got 8-12 MB/s while four in parallel
got 20.8 MB/s on the same link. The package is already split into <2 GiB parts
(the release-asset cap), so the parts now download concurrently.

What has to stay true when they do:

  * the reassembled file is the parts concatenated IN ORDER -- workers finish
    in arbitrary order, and a package assembled out of order is a corrupt
    tarball that only fails much later, during apply;
  * the progress fraction is the SUM across workers and never goes backwards
    (each worker reports its own cumulative count, so using the last value seen
    would make the bar jump around);
  * a Stop still aborts, and the error surfaces rather than being swallowed by
    the thread pool;
  * the whole-file sha256 is still verified after reassembly.

HTTP is faked; _download_asset, the reassembly and the hashing are the real
code. The fake deliberately holds each response open briefly so genuinely
sequential downloads cannot pass the concurrency assertion.

Run: docker exec intact_backend python /app/workdir/tests/test_release_package_download.py
"""

import hashlib
import os
import shutil
import sys
import tempfile
import threading
import time

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.upgrade import download as D  # noqa: E402

TAG = "intact-20260728"
BASE = f"intact-upgrade-{TAG}.tar.gz"
PART_SIZE = 256 * 1024          # small but > 1 chunk, so iter_content loops
N_PARTS = 4


def _part_bytes(i):
    """Distinct, order-sensitive content per part."""
    return bytes([(i * 37 + j) % 256 for j in range(PART_SIZE)])


WHOLE = b"".join(_part_bytes(i) for i in range(N_PARTS))
WHOLE_SHA = hashlib.sha256(WHOLE).hexdigest()


class _Resp:
    def __init__(self, data, status=206):
        self._data, self.status_code = data, status
        self.url = "https://release-assets.githubusercontent.com/fake"

    def raise_for_status(self):
        if self.status_code >= 400:
            raise IOError(f"HTTP {self.status_code}")

    def iter_content(self, n):
        for i in range(0, len(self._data), n):
            yield self._data[i:i + n]

    def json(self):
        import json
        return json.loads(self._data)

    def close(self):
        pass


class _Fake:
    """Serves the fake release + assets, and records download concurrency."""

    def __init__(self, hold=0.05):
        self.live = 0
        self.max_live = 0
        self.lock = threading.Lock()
        self.hold = hold

    def get(self, url, headers=None, stream=False, allow_redirects=True, timeout=None):
        headers = headers or {}
        if url.endswith(f"/releases/tags/{TAG}"):
            import json
            assets = [{"name": f"{BASE}.part-{i:02d}", "url": f"asset://part/{i}",
                       "size": PART_SIZE} for i in range(N_PARTS)]
            assets.append({"name": f"{BASE}.sha256", "url": "asset://sha", "size": 64})
            return _Resp(json.dumps({"assets": assets}).encode(), 200)

        if url == "asset://sha":
            return _Resp(f"{WHOLE_SHA}  {BASE}\n".encode(), 200)

        idx = int(url.rsplit("/", 1)[1])
        data = _part_bytes(idx)
        start = 0
        if headers.get("Range"):
            start = int(headers["Range"].split("=")[1].split("-")[0])
            data = data[start:]

        with self.lock:
            self.live += 1
            self.max_live = max(self.max_live, self.live)
        # Hold the slot open so sequential downloads can never look concurrent.
        time.sleep(self.hold)
        with self.lock:
            self.live -= 1
        return _Resp(data, 206 if start else 200)


def _run(fake, run_id=None, progress=None):
    orig = D.requests.get
    D.requests.get = fake.get
    tmp = tempfile.mkdtemp(prefix="pkgdl_")
    try:
        return D.download_release_package(TAG, tmp, run_id=run_id,
                                          logger=lambda m, l="info": None,
                                          progress_cb=progress), tmp
    finally:
        D.requests.get = orig


def test_parts_download_concurrently():
    fake = _Fake()
    path, tmp = _run(fake)
    try:
        assert fake.max_live > 1, (
            f"parts downloaded one at a time (max concurrent = {fake.max_live}) "
            f"-- the thread pool is not being used")
        assert fake.max_live <= D._PART_WORKERS, (
            f"{fake.max_live} concurrent downloads exceeds _PART_WORKERS="
            f"{D._PART_WORKERS}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_reassembled_file_is_parts_in_order():
    """Workers finish in arbitrary order; the file must still be part-00,
    part-01, ... A misordered tarball only fails later, during apply."""
    fake = _Fake()
    path, tmp = _run(fake)
    try:
        assert path and os.path.exists(path)
        got = open(path, "rb").read()
        assert got == WHOLE, "reassembled package does not match the parts in order"
        assert hashlib.sha256(got).hexdigest() == WHOLE_SHA
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_part_files_are_cleaned_up():
    fake = _Fake()
    path, tmp = _run(fake)
    try:
        leftovers = [f for f in os.listdir(tmp) if ".part-" in f]
        assert not leftovers, f"part files left on disk: {leftovers}"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_progress_is_aggregated_and_monotonic():
    """Each worker reports its OWN cumulative bytes. Using the last value seen
    would make the bar lurch backwards whenever a different worker reported."""
    seen = []
    fake = _Fake()
    path, tmp = _run(fake, progress=seen.append)
    try:
        assert seen, "no progress reported at all"
        assert seen == sorted(seen), (
            f"progress went backwards: {[round(x, 3) for x in seen[:12]]} -- "
            f"workers' counts are being read individually, not summed")
        assert max(seen) <= 0.9 + 1e-9, f"download phase exceeded 0.9: {max(seen)}"
        assert max(seen) > 0.8, (
            f"progress topped out at {max(seen):.2f}; the full download should "
            f"reach ~0.9")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_sha256_mismatch_is_fatal():
    """A corrupted package must not reach the apply step."""
    fake = _Fake()
    real_get = fake.get

    def corrupting_get(url, **kw):
        r = real_get(url, **kw)
        if url.startswith("asset://part/0") and not url.endswith("sha"):
            return _Resp(b"\x00" * PART_SIZE, r.status_code)
        return r

    fake.get = corrupting_get
    try:
        path, tmp = _run(fake)
        shutil.rmtree(tmp, ignore_errors=True)
        raise AssertionError("a corrupt package passed sha256 verification")
    except IOError as e:
        assert "sha256" in str(e).lower(), f"unexpected IOError: {e}"


def test_stop_aborts_the_download():
    """Stop must surface out of the pool, not be swallowed by a worker."""
    class _Cancelled(threading.Event):
        pass

    ev = threading.Event()
    ev.set()
    orig = D._cancel_event
    D._cancel_event = lambda run_id: ev if run_id else None
    fake = _Fake(hold=0.01)
    try:
        path, tmp = _run(fake, run_id="run_stop")
        shutil.rmtree(tmp, ignore_errors=True)
        raise AssertionError("Stop did not abort the download")
    except D.PackageDownloadCancelled:
        pass
    finally:
        D._cancel_event = orig


def test_progress_is_one_status_line_not_per_part_spam():
    """A 4-part package logging every ~5% per part emits ~80 interleaved lines.
    The central reporter replaces them with a single status line."""
    lines = []
    fake = _Fake()
    orig_get, orig_floor = D.requests.get, D._PART_LOG_FLOOR
    D.requests.get = fake.get
    # Without this the assertion is VACUOUS: report_every floors at 50 MB, so a
    # 256 KB fixture part could never emit a per-part line even with logging
    # fully enabled, and the test would pass no matter what the pool passes.
    D._PART_LOG_FLOOR = 32 * 1024
    tmp = tempfile.mkdtemp(prefix="pkgdl_")
    try:
        D.download_release_package(TAG, tmp, run_id=None,
                                   logger=lambda m, l="info": lines.append(m),
                                   progress_cb=None)
        status = [m for m in lines if m.startswith(D._PROGRESS_MARKER)]
        assert status, "no aggregated status line was emitted"
        per_part = [m for m in lines if m.lstrip().startswith("…")]
        assert not per_part, (
            f"per-part progress lines leaked into the log: {per_part[:3]} -- the "
            f"pool must pass log_progress=False")
    finally:
        D.requests.get, D._PART_LOG_FLOOR = orig_get, orig_floor
        shutil.rmtree(tmp, ignore_errors=True)


def test_status_line_shape_and_final_state():
    """Format: [part n/N] X/Y MB (pct%) | (Completed) | queued."""
    lines = []
    fake = _Fake()
    orig = D.requests.get
    D.requests.get = fake.get
    tmp = tempfile.mkdtemp(prefix="pkgdl_")
    try:
        D.download_release_package(TAG, tmp, run_id=None,
                                   logger=lambda m, l="info": lines.append(m),
                                   progress_cb=None)
        final = [m for m in lines if m.startswith(D._PROGRESS_MARKER)][-1]
        for i in range(N_PARTS):
            assert f"[part {i + 1}/{N_PARTS}]" in final, (
                f"part {i + 1} missing from the status line: {final}")
        assert final.count("(Completed)") == N_PARTS, (
            f"final line should show every part Completed: {final}")
        assert "100%" in final, f"final line should read 100%: {final}"
    finally:
        D.requests.get = orig
        shutil.rmtree(tmp, ignore_errors=True)


def test_per_part_lines_still_work_without_a_central_reporter():
    """The single-asset path (whole, unsplit package) keeps its own progress
    lines -- there is no reporter there. Lower the floor so a small fixture
    can trigger them; inline it could not, and this would pass vacuously."""
    lines = []
    fake = _Fake()
    orig_get, orig_floor = D.requests.get, D._PART_LOG_FLOOR
    D.requests.get = fake.get
    D._PART_LOG_FLOOR = 32 * 1024          # well under PART_SIZE
    tmp = tempfile.mkdtemp(prefix="pkgdl_")
    try:
        D._download_asset("asset://part/0", os.path.join(tmp, "one.bin"),
                          PART_SIZE, None, lambda m, l="info": lines.append(m),
                          None, " [part 1/1]", True)
        assert any(m.lstrip().startswith("…") for m in lines), (
            "a standalone asset download logged no progress at all")
        lines.clear()
        D._download_asset("asset://part/1", os.path.join(tmp, "two.bin"),
                          PART_SIZE, None, lambda m, l="info": lines.append(m),
                          None, " [part 1/1]", False)
        assert not any(m.lstrip().startswith("…") for m in lines), (
            "log_progress=False did not suppress the per-asset lines")
    finally:
        D.requests.get, D._PART_LOG_FLOOR = orig_get, orig_floor
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as e:
                failures += 1
                print(f"FAIL {name}: {e}")
            except Exception as e:      # noqa: BLE001
                # Not just tidiness: a misordered reassembly is caught by the
                # sha256 check, which raises IOError rather than asserting.
                # Catching AssertionError alone turned that real detection into
                # a traceback with no verdict line.
                failures += 1
                print(f"FAIL {name}: unexpected {type(e).__name__}: {e}")
    print("OK" if not failures else f"{failures} FAILED")
    sys.exit(1 if failures else 0)
