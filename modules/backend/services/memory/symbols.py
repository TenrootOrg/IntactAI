"""Volatility symbol tables (ISF): which ones an image needs, and adding one by hand.

Volatility reads a Windows image only with the symbol table of that EXACT
kernel build, fetched from Microsoft on first use. An air-gapped appliance
cannot fetch, so a kernel it has never seen yields no plugin output at all
(docs/MEMORY_SYMBOLS_AIRGAP.md). The fix is manual and small: find out which
file the image needs, download it on any connected machine, carry it over,
upload it here. This module does the two ends:

  required(image)  reads the kernel's debug record (RSDS) straight out of the
                   image — the same record Volatility looks up — and says which
                   .pdb it needs, whether the library has it, and its
                   Microsoft download link.
  add(path, name)  takes what the analyst brought: Microsoft's .pdb (converted
                   to ISF here, with the Volatility already inside VolWeb), a
                   ready .json.xz / .json ISF, or a .zip symbol pack — and puts
                   it where VolWeb's Volatility looks (media/symbols).
"""
from __future__ import annotations

import mmap
import os
import re
import shlex
import shutil
import struct
import subprocess
import uuid

from .volweb_client import _VOLWEB_WORKER_CONTAINER, _config_value

DUMPS_DIR = "/data/memory_dumps"
# On the dumps volume, which VolWeb mounts as media/staging: a file put here by
# the backend is readable by VolWeb's worker without an HTTP hop.
INCOMING = ".symbols_incoming"
SYMBOLS_DIR = "/home/app/web/media/symbols"
STAGING_IN_VOLWEB = "/home/app/web/media/staging"
# The kernel (every plugin needs it) and tcpip (the network plugins).
WANTED = ("ntkrnlmp.pdb", "ntoskrnl.pdb", "ntkrnlpa.pdb", "ntkrpamp.pdb", "tcpip.pdb")
MSDL = "https://msdl.microsoft.com/download/symbols"


def _worker() -> str:
    return _config_value("worker_container", default=None) or _VOLWEB_WORKER_CONTAINER


def _exec(script: str, timeout: int = 300) -> subprocess.CompletedProcess:
    """Run a shell script inside VolWeb's worker as root (then hand files to app)."""
    return subprocess.run(["docker", "exec", _worker(), "sh", "-c", script],
                          capture_output=True, text=True, timeout=timeout)


def _guid(raw16: bytes) -> str:
    d1, d2, d3 = struct.unpack("<IHH", raw16[:8])
    return f"{d1:08X}{d2:04X}{d3:04X}{raw16[8:].hex().upper()}"


_FOUND_CACHE: dict = {}      # (path, size, mtime) -> records; an image never changes


def _records(image_path: str, max_hits: int = 20000) -> dict:
    """Kernel/tcpip RSDS records in the image. Stops once a kernel and tcpip
    are both found: reading all of a 5 GB image took 20–30 s per Check and the
    button looked stuck (2026-09-28); the records normally sit early."""
    st = os.stat(image_path)
    key = (image_path, st.st_size, st.st_mtime)
    if key in _FOUND_CACHE:
        return _FOUND_CACHE[key]
    found = {}
    with open(image_path, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        pos, hits = 0, 0
        while hits < max_hits:
            if any(b == "tcpip.pdb" for b, _g, _a in found) and \
                    any(b != "tcpip.pdb" for b, _g, _a in found):
                break
            i = mm.find(b"RSDS", pos)
            if i < 0:
                break
            hits += 1
            pos = i + 4
            rec = mm[i + 4:i + 24 + 64]
            if len(rec) < 24:
                break
            name = rec[20:].split(b"\x00", 1)[0].decode("ascii", "ignore").lower()
            base = name.replace("\\", "/").rsplit("/", 1)[-1]
            if base not in WANTED:
                continue
            guid, age = _guid(rec[:16]), struct.unpack("<I", rec[16:20])[0]
            if 0 < age < 1000:
                found[(base, guid, age)] = True
    _FOUND_CACHE[key] = found
    return found


def required(image_path: str) -> list:
    """The symbol tables this image needs, read from its RSDS debug records.
    [{pdb, guid, age, have, file, url}], kernel first."""
    found = _records(image_path)
    have = set(library_ids())
    out = []
    for base, guid, age in found:
        out.append({"pdb": base, "guid": guid, "age": age,
                    "file": f"windows/{base}/{guid}-{age}.json.xz",
                    "have": f"{base}/{guid}-{age}" in have,
                    # Microsoft's symbol server: GUID then age in HEX, no separator
                    "url": f"{MSDL}/{base}/{guid}{age:X}/{base}"})
    # Memory holds debug records of more than one kernel variant (ntoskrnl.pdb
    # copies beside the running ntkrnlmp.pdb). Only ONE kernel table is needed:
    # once the library has one, the others are noise — shown as "missing,
    # needed for any plugin output" they sent the analyst after files that do
    # nothing (DESKTOP-3LRFS8Q, 2026-09-28, whose 9 plugins ran fine).
    kernels = [r for r in out if r["pdb"] != "tcpip.pdb"]
    if any(r["have"] for r in kernels):
        out = [r for r in out if r["pdb"] == "tcpip.pdb" or r["have"]]
    else:
        for r in kernels:
            r["alternative"] = len(kernels) > 1      # "one of these" — ntkrnlmp first
    out.sort(key=lambda r: (r["pdb"] == "tcpip.pdb", r["pdb"] != "ntkrnlmp.pdb", r["pdb"], r["guid"]))
    return out


def library() -> list:
    """Symbol files VolWeb's Volatility can use: [{file, size, mtime}]."""
    r = _exec(f"find {shlex.quote(SYMBOLS_DIR)} -type f -printf '%P\\t%s\\t%T@\\n' 2>/dev/null", 60)
    out = []
    for line in (r.stdout or "").splitlines():
        parts = line.split("\t")
        if len(parts) == 3:
            out.append({"file": parts[0], "size": int(parts[1]), "mtime": float(parts[2])})
    out.sort(key=lambda e: -e["mtime"])
    return out


def library_ids() -> list:
    """'ntkrnlmp.pdb/GUID-age' for every ISF in the library."""
    ids = []
    for e in library():
        m = re.match(r"windows/([^/]+)/([0-9A-Fa-f]{32,33}-\d+)\.json(\.xz)?$", e["file"])
        if m:
            ids.append(f"{m.group(1).lower()}/{m.group(2).upper()}")
    return ids


# Inside the worker: convert/name/place one incoming file. Reads the ISF's own
# metadata for its name — never trusts the uploaded file name.
_PLACE = r'''
import json, lzma, os, shutil, subprocess, sys
src, kind, symbols = sys.argv[1], sys.argv[2], sys.argv[3]
def die(msg):
    print(json.dumps({"error": msg})); sys.exit(0)
tmp = src + ".isf.json.xz"
if kind == "pdb":
    r = subprocess.run([sys.executable, "-m", "volatility3.framework.symbols.windows.pdbconv",
                        "-f", src, "-o", tmp], capture_output=True, text=True)
    if r.returncode != 0 or not os.path.isfile(tmp):
        die("could not convert the .pdb: " + (r.stderr or r.stdout)[-300:])
elif kind == "json":
    with open(src, "rb") as i, lzma.open(tmp, "wb") as o:
        o.write(i.read())
else:
    tmp = src
try:
    meta = json.load(lzma.open(tmp))["metadata"]["windows"]["pdb"]
    db, guid, age = meta["database"].lower(), meta["GUID"].upper(), int(meta["age"])
except Exception as e:
    die("not a Windows symbol table (no metadata.windows.pdb): %s" % e)
dest_dir = os.path.join(symbols, "windows", db)
os.makedirs(dest_dir, exist_ok=True)
dest = os.path.join(dest_dir, "%s-%d.json.xz" % (guid, age))
existed = os.path.exists(dest)
if not existed:
    shutil.move(tmp, dest)            # staging and symbols are different volumes
elif tmp != src:
    os.remove(tmp)
print(json.dumps({"file": "windows/%s/%s-%d.json.xz" % (db, guid, age),
                  "pdb": db, "guid": guid, "age": age, "already_had": existed}))
'''


def add(local_path: str, filename: str, dumps_dir: str = DUMPS_DIR) -> dict:
    """Add one uploaded symbol file to VolWeb's library. `local_path` is the
    upload as saved by the route (anywhere); it is removed afterwards."""
    fname = os.path.basename(filename or "").lower()
    if fname.endswith(".pdb"):
        kind = "pdb"
    elif fname.endswith(".json.xz"):
        kind = "xz"
    elif fname.endswith(".json"):
        kind = "json"
    elif fname.endswith(".zip"):
        kind = "zip"
    else:
        return {"error": "Upload a .pdb from Microsoft, a .json.xz / .json symbol table, or a .zip symbol pack."}
    incoming = os.path.join(dumps_dir, INCOMING)
    os.makedirs(incoming, exist_ok=True)
    tag = uuid.uuid4().hex[:12]
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", fname) or "symbol"
    staged = os.path.join(incoming, f"{tag}_{safe}")
    shutil.move(local_path, staged)
    in_worker = f"{STAGING_IN_VOLWEB}/{INCOMING}/{tag}_{safe}"
    try:
        if kind == "zip":
            # A symbol pack is read in place by Volatility: it goes in whole.
            dest = f"{SYMBOLS_DIR}/{tag}_{safe}"
            r = _exec(f"cp {shlex.quote(in_worker)} {shlex.quote(dest)} && chown app:app {shlex.quote(dest)}", 300)
            if r.returncode != 0:
                return {"error": "could not store the pack: " + (r.stderr or "")[-200:]}
            return {"file": f"{tag}_{safe}", "pack": True}
        sp = ("SP=$(ls -d /home/app/.local/lib/python3*/site-packages 2>/dev/null | head -1); "
              f"PYTHONPATH=\"$SP\" python3 -c {shlex.quote(_PLACE)} "
              f"{shlex.quote(in_worker)} {kind} {shlex.quote(SYMBOLS_DIR)}; "
              f"chown -R app:app {shlex.quote(SYMBOLS_DIR)}")
        r = _exec(sp, 600)
        import json
        last = [ln for ln in (r.stdout or "").splitlines() if ln.startswith("{")]
        if not last:
            return {"error": "the conversion gave no answer: " + (r.stderr or r.stdout or "")[-300:]}
        return json.loads(last[-1])
    except subprocess.TimeoutExpired:
        return {"error": "the conversion took too long (over 10 minutes)"}
    finally:
        try:
            os.remove(staged)
        except OSError:
            pass
