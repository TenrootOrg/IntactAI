#!/usr/bin/env python3
"""One admission policy for operator-supplied ZIP archives.

Four upload paths extracted archives with no bound on what came out: KAPE
triage (`ZipFile.extractall`), Azure log bundles (`src.read()` — the whole
member into RAM), memory-image uploads, and the CVE pack (since removed). The
upload cap limits COMPRESSED bytes; expansion is unbounded, so a small archive
could fill the volume or exhaust memory and take the whole platform down with
it — a DFIR platform failing mid-incident.

The limits here are deliberately generous, because this is forensic tooling and
real evidence is enormous: KAPE triage archives run to tens of GB and a memory
image is the size of the host's RAM. A cap tuned to feel safe would reject the
day job, and a tool that rejects real evidence gets switched off.

So the load-bearing check is not an absolute size — it is FREE SPACE at the
destination. That adapts to the machine instead of guessing, and it is the
condition actually worth preventing: running out of disk halfway through an
extraction, which leaves a corrupt tree and no clear error. The absolute caps
sit far above plausible evidence and exist to catch the pathological case (a
zip bomb, a malformed header) before it starts.

Compression ratio is the one cheap tell that separates a bomb from big
evidence. Real forensic content — event logs, JSON, MFT — compresses roughly
10-20x. A crafted bomb runs to thousands. The threshold sits an order of
magnitude above the honest case.

Everything is read from the ZIP CENTRAL DIRECTORY, so nothing is written to
disk before the archive is judged. Note that `file_size` there is
attacker-controlled metadata: it is what the archive CLAIMS. That is enough to
reject an obvious bomb up front, and callers that stream (see the memory
uploader) still bound the real write. This is admission control, not a
guarantee about bytes on disk.
"""

import os
import shutil
import zipfile

# An archive is REJECTED above these. Set high on purpose — see the module
# docstring: these catch the pathological case, they are not a size policy.
MAX_MEMBERS = 500_000              # KAPE triage of a busy host: ~100k files
MAX_MEMBER_BYTES = 512 * 1024**3   # one member: a full memory image and then some
MAX_TOTAL_BYTES = 2 * 1024**4      # 2 TiB uncompressed across the archive

# Ratio is a secondary heuristic and the one most likely to reject real
# evidence, so it is set loose on purpose. Measured, not assumed:
#   varied JSON event records (realistic)      10.3x
#   the SAME line repeated (a lazy test fixture) 273x
# The second number is why this is 500 and not 20 — repetitive-but-genuine
# content exists, and a ceiling near the typical case would reject it. Actual
# bombs run 10^4-10^6x, so 500 still catches them with orders of magnitude to
# spare. See tests/test_archive_guard.py, which builds both shapes.
MAX_RATIO = 500

# ...and it is only consulted once the EXPANSION is big enough to matter.
# Gating on compressed size instead was wrong and let a 50 KB archive that
# expands to 50 MB through, because the archive was too small to be judged.
# What threatens the host is the output, so that is what decides whether the
# question is worth asking. Below this, no ratio can hurt anything.
RATIO_CHECK_ABOVE_BYTES = 32 * 1024**2

# Extraction needs room for the output plus working space. 1.15 mirrors the
# headroom the upgrade path already reserves for package staging.
FREE_SPACE_HEADROOM = 1.15


class ArchiveRejected(Exception):
    """The archive failed admission. The message is operator-facing: it says
    which limit, what the archive claimed, and what the limit is, so the
    operator can act instead of guessing."""


def inspect_zip(path, *, max_members=MAX_MEMBERS, max_member_bytes=MAX_MEMBER_BYTES,
                max_total_bytes=MAX_TOTAL_BYTES, max_ratio=MAX_RATIO):
    """Read the central directory and return stats, or raise ArchiveRejected.

    Returns ``{members, total_uncompressed, total_compressed, ratio,
    largest_member}``. Nothing is extracted.
    """
    try:
        with zipfile.ZipFile(path, "r") as zf:
            infos = zf.infolist()
    except zipfile.BadZipFile as e:
        raise ArchiveRejected(f"Not a readable ZIP archive: {e}") from e

    members = len(infos)
    if members > max_members:
        raise ArchiveRejected(
            f"Archive declares {members:,} entries; the limit is {max_members:,}.")

    total_unc = 0
    total_cmp = 0
    largest = 0
    for i in infos:
        size = int(getattr(i, "file_size", 0) or 0)
        total_unc += size
        total_cmp += int(getattr(i, "compress_size", 0) or 0)
        if size > largest:
            largest = size
        if size > max_member_bytes:
            raise ArchiveRejected(
                f"Entry {i.filename!r} declares {_gb(size)} uncompressed; the "
                f"per-entry limit is {_gb(max_member_bytes)}.")

    if total_unc > max_total_bytes:
        raise ArchiveRejected(
            f"Archive declares {_gb(total_unc)} uncompressed; the limit is "
            f"{_gb(max_total_bytes)}.")

    # Ratio is only asked once the OUTPUT is big enough to threaten the host.
    # A few hundred KB of zeros expands enormously by ratio and endangers
    # nothing; conversely a small archive can hide a large expansion, which is
    # why the gate is on uncompressed size rather than compressed.
    ratio = (total_unc / total_cmp) if total_cmp else 0
    if total_unc >= RATIO_CHECK_ABOVE_BYTES and ratio > max_ratio:
        raise ArchiveRejected(
            f"Archive expands {ratio:.0f}x ({_gb(total_cmp)} to {_gb(total_unc)}), "
            f"beyond the {max_ratio}x limit — this looks like a compression bomb. "
            f"If it is genuine evidence, extract it outside the platform and "
            f"upload the contents.")

    return {
        "members": members,
        "total_uncompressed": total_unc,
        "total_compressed": total_cmp,
        "ratio": ratio,
        "largest_member": largest,
    }


def require_free_space(dest_dir, needed_bytes, headroom=FREE_SPACE_HEADROOM):
    """Raise unless dest_dir can hold needed_bytes (plus headroom).

    Checks the DESTINATION, not '/', because the extraction targets are
    bind-mounted volumes that are usually a different filesystem — asking the
    root filesystem tells you nothing about where the bytes actually land.
    """
    try:
        os.makedirs(dest_dir, exist_ok=True)
        free = shutil.disk_usage(dest_dir).free
    except OSError as e:
        # Can't tell — don't invent a reason to block a legitimate upload.
        return None
    required = int(needed_bytes * headroom)
    if free < required:
        raise ArchiveRejected(
            f"Not enough space in {dest_dir}: extraction needs about "
            f"{_gb(required)} and {_gb(free)} is free. Free up space or extract "
            f"to a larger volume.")
    return free


def guard_zip(path, dest_dir, *, log=None, **limits):
    """inspect_zip + require_free_space. Returns the stats dict.

    The single call an extraction site should make before it writes anything.
    """
    stats = inspect_zip(path, **limits)
    require_free_space(dest_dir, stats["total_uncompressed"])
    if log:
        log(f"archive: {stats['members']:,} entries, {_gb(stats['total_uncompressed'])} "
            f"uncompressed ({stats['ratio']:.1f}x) — accepted")
    return stats


def copy_bounded(src, dst, limit_bytes, *, chunk=4 * 1024 * 1024, what="entry"):
    """Stream src->dst, refusing to write more than limit_bytes.

    The central directory's `file_size` is what the archive CLAIMS, so a
    caller that sized its free-space check from it has been told a number an
    attacker chose. This bounds what actually lands on disk: a member that
    keeps producing bytes past its declared size is stopped mid-write rather
    than filling the volume.

    Returns the byte count written; raises ArchiveRejected on overrun.
    """
    written = 0
    while True:
        buf = src.read(chunk)
        if not buf:
            return written
        written += len(buf)
        if written > limit_bytes:
            raise ArchiveRejected(
                f"{what} produced more than the {_gb(limit_bytes)} it declared — "
                f"stopping. The archive's own size metadata is not trustworthy.")
        dst.write(buf)


def _gb(n):
    """Human size. Archives here span KB to TB, so pick a sensible unit."""
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
