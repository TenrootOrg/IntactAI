"""Volatility symbol tables (ISF), added by hand — for air-gapped boxes.

Volatility reads a Windows image only with the symbol table of that EXACT
build, fetched from Microsoft on first use; an air-gapped appliance cannot
fetch it (docs/MEMORY_SYMBOLS_AIRGAP.md). add() takes what the analyst
brought — Volatility's whole windows.zip pack, a Microsoft .pdb (converted
here with the Volatility inside VolWeb) or a ready .json.xz / .json table —
and puts it where VolWeb's Volatility looks (media/symbols).
"""
from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import uuid

from .volweb_client import _VOLWEB_WORKER_CONTAINER, _config_value

DUMPS_DIR = "/data/memory_dumps"
# On the dumps volume, which VolWeb mounts as media/staging: a file put here by
# the backend is readable by VolWeb's worker without an HTTP hop.
INCOMING = ".symbols_incoming"
SYMBOLS_DIR = "/home/app/web/media/symbols"
STAGING_IN_VOLWEB = "/home/app/web/media/staging"


def _worker() -> str:
    return _config_value("worker_container", default=None) or _VOLWEB_WORKER_CONTAINER


def _exec(script: str, timeout: int = 300) -> subprocess.CompletedProcess:
    """Run a shell script inside VolWeb's worker as root (then hand files to app)."""
    return subprocess.run(["docker", "exec", _worker(), "sh", "-c", script],
                          capture_output=True, text=True, timeout=timeout)


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
