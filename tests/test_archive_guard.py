"""Archive admission: reject the pathological, admit real evidence.

Four upload paths extracted operator-supplied ZIPs with nothing bounding what
came out — KAPE triage used a bare `extractall`, the Azure ingest read each
member fully into RAM with `src.read()`, and the memory uploader streamed a
member with no ceiling. The upload cap limits COMPRESSED bytes; expansion was
unbounded, so a small archive could fill the volume or exhaust backend memory
and take the platform down mid-incident.

The hard part is that this is forensic tooling and real evidence is enormous —
KAPE triage runs to tens of GB, a memory image is the size of the host's RAM. A
cap tuned to feel safe rejects the day job, and a tool that rejects real
evidence gets switched off. So the tests that matter most here are the ones
asserting that LEGITIMATE archives still pass; the rejections are the easy half.

Everything is built in a temp dir; no fixtures, no network, no live stack.

Run: docker exec intact_backend python3 /app/workdir/tests/test_archive_guard.py
"""

import io
import os
import sys
import tempfile
import zipfile

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services import archive_guard as G  # noqa: E402


def _zip(path, members):
    """members: [(name, bytes)]"""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members:
            z.writestr(name, data)
    return path


def _tmp(name="a.zip"):
    return os.path.join(tempfile.mkdtemp(prefix="arcguard_"), name)


# --- real evidence must still get through -----------------------------------


def test_a_normal_forensic_archive_is_accepted():
    """The most important test here, and the one that set the threshold.

    Sized deliberately ABOVE RATIO_CHECK_ABOVE_BYTES so it actually exercises
    the ratio branch rather than skipping it. Content is varied the way real
    event records are — identical repeated lines compress far better than
    anything a host actually produces, and an earlier version of this fixture
    measured 273x, which is what proved a 200x ceiling would reject evidence.
    """
    import random
    rnd = random.Random(1234)
    users = ["jsmith", "administrator", "svc_backup", "mgarcia", "root"]
    lines = []
    for i in range(420_000):
        lines.append(
            b'{"EventID":%d,"Computer":"WS%02d","User":"%s","Time":"2026-07-2%dT%02d:%02d:%02dZ"}\n'
            % (rnd.choice([4624, 4625, 4688, 4672]), rnd.randint(1, 40),
               rnd.choice(users).encode(), rnd.randint(0, 9),
               rnd.randint(0, 23), rnd.randint(0, 59), rnd.randint(0, 59)))
    body = b"".join(lines)
    p = _zip(_tmp(), [(f"logs/evt_{i}.json", body[i::4]) for i in range(4)])
    stats = G.inspect_zip(p)
    assert stats["total_uncompressed"] > G.RATIO_CHECK_ABOVE_BYTES, (
        f"fixture is only {stats['total_uncompressed']} bytes — below the ratio "
        f"gate, so this test would pass without exercising anything")
    assert stats["ratio"] < G.MAX_RATIO, (
        f"ordinary log data hit the bomb threshold at {stats['ratio']:.0f}x — "
        f"the limit is too tight for real evidence")


def test_an_incompressible_image_is_accepted():
    """A memory image or an encrypted container barely compresses at all."""
    p = _zip(_tmp(), [("PhysicalMemory.raw", os.urandom(2 * 1024 * 1024))])
    stats = G.inspect_zip(p)
    assert stats["ratio"] < 2, stats["ratio"]


def test_an_empty_archive_is_not_treated_as_a_bomb():
    """Zero compressed bytes must not divide into a huge ratio."""
    p = _zip(_tmp(), [])
    stats = G.inspect_zip(p)
    assert stats["members"] == 0 and stats["ratio"] == 0


def test_a_tiny_highly_compressible_archive_is_accepted():
    """A few KB of zeros expands enormously by ratio but threatens nothing.
    The guard ignores ratio below a floor of compressed data for this reason."""
    p = _zip(_tmp(), [("pad.txt", b"\0" * 400_000)])
    G.inspect_zip(p)          # must not raise


# --- the pathological cases -------------------------------------------------


def test_a_compression_bomb_is_rejected():
    """A real bomb: 50 MB of zeros, which deflate crushes to a few KB."""
    # 640 MB of zeros -> a few hundred KB. A real bomb is worse still; this is
    # already ~1000x, twice the ceiling.
    p = _zip(_tmp(), [(f"bomb_{i}", b"\0" * (64 * 1024 * 1024)) for i in range(10)])
    compressed = os.path.getsize(p)
    try:
        G.inspect_zip(p)
    except G.ArchiveRejected as e:
        assert "bomb" in str(e).lower() or "expands" in str(e).lower(), e
        return
    raise AssertionError(
        f"a {compressed // 1024} KB archive expanding to 640 MB was accepted")


def test_too_many_members_is_rejected():
    p = _zip(_tmp(), [("f%d" % i, b"x") for i in range(50)])
    try:
        G.inspect_zip(p, max_members=10)
    except G.ArchiveRejected as e:
        assert "entries" in str(e), e
        return
    raise AssertionError("member count limit not enforced")


def test_an_oversized_member_is_rejected():
    p = _zip(_tmp(), [("big.raw", os.urandom(1024 * 1024))])
    try:
        G.inspect_zip(p, max_member_bytes=1024)
    except G.ArchiveRejected as e:
        assert "big.raw" in str(e), "the error must name the offending entry"
        return
    raise AssertionError("per-member limit not enforced")


def test_a_corrupt_archive_is_rejected_not_crashed():
    p = _tmp("corrupt.zip")
    with open(p, "wb") as fh:
        fh.write(b"PK\x03\x04 this is not a zip")
    try:
        G.inspect_zip(p)
    except G.ArchiveRejected as e:
        assert "ZIP" in str(e), e
        return
    raise AssertionError("a corrupt archive was accepted")


# --- free space -------------------------------------------------------------


def test_insufficient_free_space_is_refused_before_writing():
    """The check that actually adapts to the machine."""
    d = tempfile.mkdtemp(prefix="arcguard_space_")
    free = os.statvfs(d).f_bavail * os.statvfs(d).f_frsize
    try:
        G.require_free_space(d, free * 4)
    except G.ArchiveRejected as e:
        assert "space" in str(e).lower(), e
        return
    raise AssertionError("free-space reservation not enforced")


def test_free_space_check_targets_the_destination_not_root():
    """Extraction targets are bind-mounted volumes; '/' says nothing about them."""
    import inspect
    src = inspect.getsource(G.require_free_space)
    assert "disk_usage(dest_dir)" in src, \
        "free space must be measured at the destination"


def test_an_unreadable_destination_does_not_block_the_upload():
    """Can't tell != must refuse. Don't invent a reason to reject real work."""
    assert G.require_free_space("/proc/nonexistent/nope", 10) is None


# --- the declared size is not trustworthy -----------------------------------


def test_copy_bounded_stops_a_member_that_overruns_its_declared_size():
    """`file_size` in the central directory is what the archive CLAIMS. A
    caller that sized its free-space check from it was told a number an
    attacker picked."""
    src = io.BytesIO(b"A" * 10_000)
    dst = io.BytesIO()
    try:
        G.copy_bounded(src, dst, 1_000, chunk=256, what="'evil.raw'")
    except G.ArchiveRejected as e:
        assert "evil.raw" in str(e), e
        assert dst.tell() <= 1_000 + 256, "wrote far past the limit before stopping"
        return
    raise AssertionError("an overrunning member was copied in full")


def test_copy_bounded_passes_an_honest_member_through_intact():
    payload = os.urandom(50_000)
    dst = io.BytesIO()
    n = G.copy_bounded(io.BytesIO(payload), dst, len(payload), chunk=4096)
    assert n == len(payload)
    assert dst.getvalue() == payload, "honest content must survive byte-for-byte"


# --- the call sites are actually wired --------------------------------------


def test_every_upload_path_calls_the_guard():
    """A guard nothing calls is decoration. Pins the three wirings."""
    import inspect
    from services import kape_upload_service as K
    from services.memory import upload_extract as M
    import routes.azure_routes as A

    assert "guard_zip" in inspect.getsource(K), "KAPE extraction is unguarded"
    assert "guard_zip" in inspect.getsource(A), "Azure ZIP ingest is unguarded"
    msrc = inspect.getsource(M)
    assert "require_free_space" in msrc and "copy_bounded" in msrc, \
        "memory upload extraction is unguarded"


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1; print(f"FAIL {fn.__name__}"); traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
