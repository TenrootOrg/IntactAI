"""One folder for every memory image the appliance keeps.

Images used to land wherever their route put them: a browser upload under
``_uploads/<upload-id>/`` (a new id every time, so the same MemoryDump_Lab6.raw
was stored twice, 1.5 GB each), a Velociraptor acquisition at the top of the
dumps volume. Now every image is ADOPTED into ``raw_memory/`` on the same
volume (so it stays VolWeb's staging file — a rename, not a copy), named with
the date it arrived, and recorded in ``index.json`` with where it came from.

An image identical to one already kept is not stored again: the new copy is
dropped and the kept one is used. Files are hashed only when two have the same
size — a memory image's size is almost unique, so normally nothing is hashed.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import shutil
import threading

DUMPS_DIR = "/data/memory_dumps"
RAW_DIR_NAME = "raw_memory"
_INDEX = "index.json"
_MIN_BYTES = 1024 * 1024
_lock = threading.RLock()


def raw_dir(dumps_dir: str = DUMPS_DIR) -> str:
    return os.path.join(dumps_dir, RAW_DIR_NAME)


def _index_path(dumps_dir):
    return os.path.join(raw_dir(dumps_dir), _INDEX)


def _load(dumps_dir) -> dict:
    try:
        with open(_index_path(dumps_dir), encoding="utf-8") as fh:
            d = json.load(fh)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(dumps_dir, idx) -> None:
    tmp = _index_path(dumps_dir) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(idx, fh, indent=1, sort_keys=True)
    os.replace(tmp, _index_path(dumps_dir))


def _sha256(path, chunk=8 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(chunk), b""):
            h.update(b)
    return h.hexdigest()


def _sample(path, chunk=8 * 1024 * 1024) -> str:
    """Hash of three 8 MB slices (start, middle, end). Memory images are exactly
    the machine's RAM size, so two hosts with the same RAM always match on size;
    their contents differ within the first megabytes. The full hash is only
    read when the samples agree."""
    size = os.path.getsize(path)
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for off in (0, max(0, size // 2 - chunk // 2), max(0, size - chunk)):
            fh.seek(off)
            h.update(fh.read(chunk))
    return h.hexdigest()


def _safe(name) -> str:
    name = os.path.basename(str(name or "memory.raw")).replace("\x00", "")
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._") or "memory.raw"


def _stamp(when) -> str:
    if isinstance(when, (int, float)):
        when = _dt.datetime.fromtimestamp(when, _dt.timezone.utc)
    elif isinstance(when, str) and when:
        try:
            when = _dt.datetime.fromisoformat(when.replace("Z", "+00:00"))
        except ValueError:
            when = None
    when = when or _dt.datetime.now(_dt.timezone.utc)
    return when.strftime("%Y-%m-%d_%H%M%S")


def in_store(path, dumps_dir: str = DUMPS_DIR) -> bool:
    try:
        return os.path.realpath(path).startswith(os.path.realpath(raw_dir(dumps_dir)) + os.sep)
    except OSError:
        return False


def _prune_empty_upload_dir(path, dumps_dir) -> None:
    """A browser upload came in its own _uploads/<id>/ — remove it once empty."""
    parent = os.path.dirname(path)
    if os.path.basename(os.path.dirname(parent)) == "_uploads":
        try:
            os.rmdir(parent)
        except OSError:
            pass


def adopt(path, *, source, original_name=None, when=None, origin=None,
          dumps_dir: str = DUMPS_DIR, log=None) -> tuple[str, bool]:
    """Move an image into raw_memory/. Returns (path to use, was_duplicate).

    `source`: "upload" / "velociraptor" / "migrated". `origin`: what is known of
    the machine and run ({client_name, client_id, run_id, case_id}). A duplicate
    of a kept image is DELETED and the kept path returned — the caller must then
    treat the image as someone else's (never delete it after the run)."""
    log = log or (lambda m, level="info": None)
    if in_store(path, dumps_dir):
        return path, False
    try:
        on_volume = os.path.realpath(path).startswith(os.path.realpath(dumps_dir) + os.sep)
    except OSError:
        on_volume = False
    if not on_volume:
        # Not on the dumps volume: moving it in would be a multi-GB copy across
        # filesystems. Uploads and acquisitions always land on the volume.
        return path, False
    os.makedirs(raw_dir(dumps_dir), exist_ok=True)
    size = os.path.getsize(path)
    with _lock:
        idx = _load(dumps_dir)
        new_hash = None
        for name, rec in list(idx.items()):
            kept = os.path.join(raw_dir(dumps_dir), name)
            if rec.get("size") != size or not os.path.isfile(kept):
                continue
            if _sample(path) != (rec.get("sample") or _sample(kept)):
                continue                       # same RAM size, different machine
            new_hash = new_hash or _sha256(path)
            if not rec.get("sha256"):
                rec["sha256"] = _sha256(kept)
            if rec["sha256"] == new_hash:
                os.remove(path)
                _prune_empty_upload_dir(path, dumps_dir)
                rec["shared"] = True           # more than one run relies on it now
                rec.setdefault("also_arrived", []).append(
                    {"source": source, "at": _stamp(when), "original_name": original_name or os.path.basename(path)})
                _save(dumps_dir, idx)
                log(f"memory: this image is identical to the kept {name} — using it, not storing a second copy", "info")
                return kept, True
        name = f"{_stamp(when)}__{_safe(original_name or os.path.basename(path))}"
        base, n = name, 1
        while os.path.exists(os.path.join(raw_dir(dumps_dir), name)):
            n += 1
            stem, ext = os.path.splitext(base)
            name = f"{stem}_{n}{ext}"
        dest = os.path.join(raw_dir(dumps_dir), name)
        try:
            os.rename(path, dest)            # same volume: instant
        except OSError:
            shutil.move(path, dest)
        _prune_empty_upload_dir(path, dumps_dir)
        idx[name] = {"size": size, "source": source, "added_at": _stamp(when), "sample": _sample(dest),
                     "original_name": original_name or os.path.basename(path),
                     "origin": {k: v for k, v in (origin or {}).items() if v}}
        if new_hash:
            idx[name]["sha256"] = new_hash
        _save(dumps_dir, idx)
    log(f"memory: image stored as {dest}", "info")
    return dest, False


def is_shared(path, dumps_dir: str = DUMPS_DIR) -> bool:
    """More than one run arrived with this exact image: no single run's cleanup
    may delete it (it is removed from Memory → Kept images, or by a purge)."""
    if not path or not in_store(path, dumps_dir):
        return False
    return bool((_load(dumps_dir).get(os.path.basename(path)) or {}).get("shared"))


def forget(path, dumps_dir: str = DUMPS_DIR) -> None:
    """Drop an image's index entry after its file was deleted elsewhere."""
    if not in_store(path, dumps_dir):
        return
    with _lock:
        idx = _load(dumps_dir)
        if idx.pop(os.path.basename(path), None) is not None:
            _save(dumps_dir, idx)


def listing(dumps_dir: str = DUMPS_DIR) -> list:
    """Every kept image, newest first, with what is known of it."""
    out = []
    d = raw_dir(dumps_dir)
    if not os.path.isdir(d):
        return out
    idx = _load(dumps_dir)
    for name in os.listdir(d):
        p = os.path.join(d, name)
        if name.startswith(".") or name in (_INDEX, _INDEX + ".tmp", "removed.log") or not os.path.isfile(p):
            continue
        try:
            st = os.stat(p)
        except OSError:
            continue
        if st.st_size < _MIN_BYTES:
            continue
        rec = idx.get(name) or {}
        out.append({"path": p, "name": name, "size_bytes": st.st_size, "mtime": st.st_mtime,
                    "added_at": rec.get("added_at"), "source": rec.get("source"),
                    "original_name": rec.get("original_name") or name,
                    "origin": rec.get("origin") or None,
                    "also_arrived": len(rec.get("also_arrived") or [])})
    out.sort(key=lambda e: (e.get("added_at") or "", e["mtime"]), reverse=True)
    return out


def remove(name, dumps_dir: str = DUMPS_DIR, by=None) -> dict:
    """Delete one kept image by its name in raw_memory/, recorded in removed.log."""
    if not name or os.path.basename(name) != name or name in (_INDEX, _INDEX + ".tmp", "removed.log"):
        return {"error": "not a kept image"}
    p = os.path.join(raw_dir(dumps_dir), name)
    if not os.path.isfile(p):
        return {"error": "no such image"}
    size = os.path.getsize(p)
    with _lock:
        os.remove(p)
        idx = _load(dumps_dir)
        rec = idx.pop(name, None) or {}
        _save(dumps_dir, idx)
        # Removing evidence leaves a trace: MemoryDump_Lab6.raw vanished on the
        # first day of this folder and nothing said by whom or when.
        with open(os.path.join(raw_dir(dumps_dir), "removed.log"), "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
                                 "name": name, "size": size, "by": by or "unknown",
                                 "origin": rec.get("origin") or {}}) + "\n")
    return {"removed": name, "freed_bytes": size}


def migrate(origins=None, in_use=(), dumps_dir: str = DUMPS_DIR, log=None) -> list:
    """Move every image outside raw_memory/ into it (uploads, acquisitions),
    dated by the run that produced it or the file's own time, duplicates dropped.
    Skips files a running run is reading (`in_use`). Returns [(old, new, dup)]."""
    log = log or (lambda m, level="info": None)
    origins = origins or {}
    moved = []
    if not os.path.isdir(dumps_dir):
        return moved
    # ONCE. It ran on every list load, and a list load can land while an upload
    # is still arriving in _uploads/<id>/ or Velociraptor is still writing an
    # acquisition at the top of the volume — neither is a run with a path yet,
    # so `in_use` cannot protect them, and moving a half-written file breaks
    # it. New images are adopted by the pipeline; this is for the old ones.
    marker = os.path.join(raw_dir(dumps_dir), ".migrated")
    if os.path.exists(marker):
        return moved
    busy = {os.path.realpath(p) for p in in_use if p}
    import time as _time
    recent = _time.time() - 600               # and never a file touched in the last 10 minutes
    for root, dirs, files in os.walk(dumps_dir):
        rel = os.path.relpath(root, dumps_dir)
        if rel == RAW_DIR_NAME or rel.startswith(RAW_DIR_NAME + os.sep):
            dirs[:] = []
            continue
        if rel.count(os.sep) > 1:               # ours are top level or _uploads/<id>/
            dirs[:] = []
            continue
        for fn in files:
            p = os.path.join(root, fn)
            try:
                if os.path.getsize(p) < _MIN_BYTES or os.path.realpath(p) in busy \
                        or os.path.getmtime(p) > recent:
                    continue
            except OSError:
                continue
            o = origins.get(p) or {}
            new, dup = adopt(p, source="migrated", original_name=fn,
                             when=o.get("created_at") or os.path.getmtime(p),
                             origin=o, dumps_dir=dumps_dir, log=log)
            moved.append((p, new, dup))
    os.makedirs(raw_dir(dumps_dir), exist_ok=True)
    with open(marker, "w") as fh:
        fh.write(_stamp(None) + "\n")
    return moved
