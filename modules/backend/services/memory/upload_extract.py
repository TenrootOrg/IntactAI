"""Extract a memory dump from an operator-supplied file.

Two input shapes covered:

  1. **Raw memory image** — ``.raw``, ``.bin``, ``.dmp``, ``.mem`` or any
     extensionless file whose first 4 bytes don't match a known
     archive format. Used as-is.

  2. **Velociraptor offline export ZIP** — produced by either:
       * ``Windows.Memory.Acquisition`` flow → "Prepare Collection" /
         "Prepare Download" in the Velociraptor GUI. The ZIP contains
         a ``results/.../Windows.Memory.Acquisition/`` tree plus the
         actual page-file under ``uploads/file/auto/.../PhysicalMemory``.
       * Offline collector (``Velociraptor.exe collector`` with the
         Memory.Acquisition artifact). Same internal layout but with
         a slightly different prefix.

The extractor walks the ZIP looking for any member whose name ends in
``PhysicalMemory`` or has a ``.raw`` / ``.bin`` extension AND whose
uncompressed size is ≥ 200 MB (excludes the small metadata JSONs).
Largest match wins — there is only ever one physical-memory file per
flow but the heuristic guards against picking a stray ``.raw`` log.

The recovered file is streamed to disk under ``staging_dir``; we never
buffer the dump in memory (a 16 GB dump on a 4 GB backend container
would OOM-kill the worker).
"""

from __future__ import annotations

import os
import shutil
import zipfile
from typing import Callable, Optional


# Magic-byte sniff used to reject zlib/gzip/snappy/zstd dumps that
# Velociraptor wrote at-rest. The pipeline downstream assumes the
# .raw is uncompressed page-file content.
_ZLIB_MAGIC = b"\x78"           # zlib header byte 0 (any compression level)
_GZIP_MAGIC = b"\x1f\x8b"
_SNAPPY_MAGIC = b"\xff\x06\x00\x00sNaPpY"
_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

# Memory dumps are big. Anything smaller than this in a ZIP is metadata
# we explicitly do NOT want to confuse for the page-file. 200 MB
# threshold: a memdump on a 1-GB-RAM host would still clear it, and no
# Velociraptor metadata file approaches this size.
_MIN_DUMP_SIZE = 200 * 1024 * 1024


class UploadExtractError(Exception):
    """Raised when the upload can't be turned into a usable raw dump."""


def _sniff_raw(path: str) -> None:
    """Read the first 8 bytes and reject if they look compressed.

    Raises ``UploadExtractError`` on rejection so the caller can flip
    the workflow to ``status='failed'`` with a clear message.
    """
    with open(path, "rb") as f:
        head = f.read(8)
    if head.startswith(_GZIP_MAGIC):
        raise UploadExtractError(
            "file is gzip-compressed (.gz). Decompress before uploading."
        )
    if head.startswith(_SNAPPY_MAGIC):
        raise UploadExtractError(
            "file is snappy-compressed. Re-export from Velociraptor with "
            "Compression='None' or decompress before uploading."
        )
    if head.startswith(_ZSTD_MAGIC):
        raise UploadExtractError(
            "file is zstd-compressed. Decompress before uploading."
        )
    # zlib check is heuristic — the marker byte is too common to be a
    # hard reject on its own. Only flag if the next two bytes match the
    # zlib well-formed header set (CM=8, CINFO valid, FCHECK passes).
    if len(head) >= 2 and head[0] == 0x78 and head[1] in (0x01, 0x5e, 0x9c, 0xda):
        raise UploadExtractError(
            "file looks like zlib-wrapped (Velociraptor at-rest format). "
            "Re-export via Prepare Download — Velociraptor's UI un-wraps it."
        )


def extract_memory_from_upload(
    upload_path: str,
    *,
    staging_dir: str,
    logger: Optional[Callable[[str, str], None]] = None,
) -> str:
    """Turn ``upload_path`` into a path to a usable raw memory image.

    For a raw upload this is the input path (sanity-checked). For a
    ZIP it's the path to the extracted raw under ``staging_dir``.

    Args:
        upload_path: the file the operator uploaded.
        staging_dir: writable directory where extracted dumps land.
            The caller is responsible for cleanup.
        logger: optional ``logger(message, level)`` for progress lines.

    Returns:
        Absolute path to a raw memory image ready for VolWeb upload.

    Raises:
        UploadExtractError: file is missing, corrupt, compressed, or
            doesn't contain a recognisable memory dump.
    """
    def log(msg: str, level: str = "info") -> None:
        if logger:
            logger(msg, level)

    if not os.path.isfile(upload_path):
        raise UploadExtractError(f"upload missing: {upload_path}")

    size = os.path.getsize(upload_path)
    if size < 16 * 1024 * 1024:
        # Anything under 16 MB cannot be a memory image — every modern
        # Windows host has more RAM than that. Fail loudly here rather
        # than letting Vol3 spend 30+ seconds rejecting it.
        raise UploadExtractError(
            f"file too small to be a memory dump: {size} bytes "
            f"(min ~16 MB)"
        )

    # ZIP path ----------------------------------------------------------
    if zipfile.is_zipfile(upload_path):
        log(f"upload: ZIP detected ({size // 1024 // 1024} MB). Searching for memory image…")
        os.makedirs(staging_dir, exist_ok=True)
        best: tuple[str, int] | None = None   # (name, size_bytes)
        with zipfile.ZipFile(upload_path, "r") as z:
            for info in z.infolist():
                if info.is_dir():
                    continue
                name_lower = info.filename.lower()
                ext = os.path.splitext(name_lower)[1]
                is_candidate = (
                    name_lower.endswith("/physicalmemory")
                    or name_lower.endswith("physicalmemory")
                    or ext in (".raw", ".bin", ".mem", ".dmp")
                )
                if not is_candidate:
                    continue
                if info.file_size < _MIN_DUMP_SIZE:
                    continue
                if best is None or info.file_size > best[1]:
                    best = (info.filename, info.file_size)

            if not best:
                raise UploadExtractError(
                    "ZIP doesn't contain a recognisable memory image. "
                    "Expected: a file ≥ 200 MB ending in PhysicalMemory, "
                    ".raw, .bin, .mem, or .dmp"
                )

            zip_member, raw_size = best
            out_name = os.path.basename(zip_member) or "PhysicalMemory.raw"
            if not out_name.endswith((".raw", ".bin", ".mem", ".dmp")):
                out_name = out_name + ".raw"
            out_path = os.path.join(staging_dir, out_name)

            # Only ONE member is extracted here, so the archive-wide caps do
            # not apply — what matters is whether the staging volume can hold
            # this image, and whether the member stops where it said it would.
            # `raw_size` comes from the ZIP central directory, i.e. it is what
            # the archive CLAIMS; copy_bounded stops a member that keeps
            # producing bytes past that instead of filling the volume.
            from services.archive_guard import (ArchiveRejected, copy_bounded,
                                                require_free_space)
            try:
                require_free_space(staging_dir, raw_size)
            except ArchiveRejected as e:
                raise UploadExtractError(str(e)) from e

            log(
                f"upload: extracting {zip_member!r} ({raw_size // 1024 // 1024} MB) → {out_path}",
            )
            try:
                with z.open(zip_member, "r") as src, open(out_path, "wb") as dst:
                    copy_bounded(src, dst, raw_size, what=f"{zip_member!r}")
            except ArchiveRejected as e:
                try:
                    os.remove(out_path)
                except OSError:
                    pass
                raise UploadExtractError(str(e)) from e

        _sniff_raw(out_path)
        log("upload: extraction complete — image looks uncompressed", "success")
        return out_path

    # Raw path ----------------------------------------------------------
    log(f"upload: raw memory image detected ({size // 1024 // 1024} MB)")
    _sniff_raw(upload_path)
    return upload_path


__all__ = ["extract_memory_from_upload", "UploadExtractError"]
