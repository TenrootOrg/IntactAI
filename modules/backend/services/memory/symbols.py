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
import threading
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


# Build Volatility's symbol index in the background in both workers right after
# the library changed, so the next memory analysis does not pay for it: vol3
# indexes every table before any plugin runs, ~14 minutes for windows.zip
# (2026-10-05). Same snippet as lib/modules/volweb.sh:_VOLWEB_PREWARM_PY.
# A pack REPLACED under the same name keeps its index rows: Volatility re-reads
# a known location only after 3 days (SQLITE_CACHE_PERIOD), so a corrected
# table went on being looked up under its old name (2026-10-06, air-gap proof:
# tcpip tables first indexed as "unknown.pdb"). Rows of a zip newer than when
# they were indexed are dropped first, so update() reads them again now.
_PREWARM = '''import os, sqlite3, datetime as dt, volatility3.symbols as s
s.__path__.append(os.path.abspath("media/symbols"))
from volatility3.framework import constants
from volatility3.framework.automagic import symbol_cache as c
idx = os.path.join(constants.CACHE_PATH, constants.IDENTIFIERS_FILENAME)
try:
    con = sqlite3.connect(idx)
    for f in os.listdir("media/symbols"):
        if f.endswith(".zip"):
            p = os.path.abspath(os.path.join("media/symbols", f))
            mt = dt.datetime.fromtimestamp(os.path.getmtime(p), dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            con.execute("DELETE FROM cache WHERE location LIKE ? AND cached < ?", ("jar:file:" + p + "!%", mt))
    con.commit()
    con.close()
except sqlite3.Error:
    pass
c.SqliteCache(idx).update()'''
_INDEX_WORKERS = ("intact_volweb_workers", "intact_volweb_workers_yarascan")


def prewarm_index(say=None) -> None:
    """Start the index build in each worker and return at once. Best-effort."""
    log_to = '"${XDG_CACHE_HOME:-$HOME/.cache}"'
    script = (f"mkdir -p {log_to} && cd /home/app/web && "
              f"nice -n 10 python3 -c {shlex.quote(_PREWARM)} > {log_to}/symbol-index.log 2>&1")
    started = 0
    for c in _INDEX_WORKERS:
        try:
            r = subprocess.run(["docker", "exec", "-d", "-u", "app", c, "sh", "-c", script],
                               capture_output=True, text=True, timeout=30)
            started += r.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
    if started and say:
        say("Indexing the symbol library in the background — the next memory "
            "analysis will not have to wait for it.")


# What the library holds, for the Symbol tables page (2026-10-05: "mention the
# version or date of the table on this machine"). A pack's DATE is the newest
# table inside it -- the zip's own record, not when it reached this box (the
# Volatility pack is 2019 whichever day it was installed). Read-only.
_LIBRARY = r'''
import json, os, sys, zipfile, datetime as dt
lib = sys.argv[1]
iso = lambda t: dt.datetime.fromtimestamp(t, dt.timezone.utc).isoformat(timespec="seconds")
packs, kernels = [], []
for root, _dirs, files in os.walk(lib):
    for f in files:
        p = os.path.join(root, f)
        try:
            st = os.stat(p)
        except OSError:
            continue
        if f.endswith(".zip") and root == lib:
            meta = {}
            try:
                with zipfile.ZipFile(p) as z:
                    infos = [i for i in z.infolist() if i.filename.startswith("windows/")
                             and i.filename.endswith((".json.xz", ".json"))]
                    if "intact-kernel-pack.json" in z.namelist():
                        meta = json.loads(z.read("intact-kernel-pack.json"))
                newest = max((i.date_time for i in infos), default=None)
            except (zipfile.BadZipFile, OSError, ValueError):
                infos, newest = [], None
            pack = {"name": f, "size": st.st_size, "added": iso(st.st_mtime), "tables": len(infos),
                    "dated": dt.date(*newest[:3]).isoformat() if newest else None}
            # Our kernel pack says which Windows each table is for. Its date is
            # then the newest WINDOWS build it covers -- the zip entries carry
            # only the day CI converted them, which says nothing about coverage.
            rows = list((meta.get("tables") or {}).values())
            if rows:
                top = max(rows, key=lambda r: r.get("released") or "")
                vers = sorted({w for r in rows for w in r.get("windows") or []},
                              key=lambda w: (w.startswith("11-"), w))
                label = lambda w: "Windows 11 " + w[3:] if w.startswith("11-") else "Windows 10 " + w
                pack.update(dated=top.get("released"), built=meta.get("built"),
                            newest_build=(top.get("version") or "").split(" ")[0],
                            covers=[label(vers[0]), label(vers[-1])] if vers else None)
            packs.append(pack)
        elif f.endswith((".json.xz", ".json", ".json.gz")) and "/windows/" in p:
            kernels.append((st.st_mtime, os.path.relpath(p, lib)))
kernels.sort()
print(json.dumps({"packs": packs, "kernels": len(kernels),
                  "newest_kernel": ({"file": kernels[-1][1], "added": iso(kernels[-1][0])} if kernels else None)}))
'''
_INDEX_STATE = ('c="${XDG_CACHE_HOME:-$HOME/.cache}/volatility3/identifier.cache"; '
                'if pgrep -f "[S]qliteCache" >/dev/null 2>&1; then echo building; '
                'elif [ -f "$c" ]; then echo "ready $(stat -c %Y "$c")"; else echo missing; fi')


def library() -> dict:
    """Packs (with their own date), per-kernel tables and the index state of each
    worker. {"error": ...} when VolWeb cannot be reached."""
    import json
    try:
        r = _exec(f"python3 -c {shlex.quote(_LIBRARY)} {shlex.quote(SYMBOLS_DIR)}", 60)
        out = json.loads([ln for ln in (r.stdout or "").splitlines() if ln.startswith("{")][-1])
    except (IndexError, ValueError, subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return {"error": "VolWeb's symbol library could not be read — is VolWeb running?"}
    import datetime as _dt
    out["index"] = {}
    for c in _INDEX_WORKERS:
        try:
            st = subprocess.run(["docker", "exec", "-u", "app", c, "sh", "-c", _INDEX_STATE],
                                capture_output=True, text=True, timeout=30).stdout.split()
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            st = []
        state = st[0] if st else "unknown"
        out["index"][c] = {"state": state, "built": (_dt.datetime.fromtimestamp(int(st[1]), _dt.timezone.utc)
                                                     .isoformat(timespec="seconds") if len(st) > 1 else None)}
    return out


# One install at a time. Two uploads of the same pack seconds apart (seen in the
# live test) each checked the library before the other had stored anything, and
# both went in.
_ADD_LOCK = threading.Lock()


def _sha256(path: str) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(4 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def add(local_path: str, filename: str, dumps_dir: str = DUMPS_DIR, log=None) -> dict:
    """Add one uploaded symbol file to VolWeb's library. `local_path` is the
    upload as saved by the route (anywhere); it is removed afterwards.
    `log(message)` narrates the steps into the upload's run (Settings → Actions)."""
    say = log or (lambda msg: None)
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
    if kind == "zip":
        # Volatility reads every pack in the library on every run: a corrupt or
        # unrelated zip there would break symbol loading for all memory runs.
        import zipfile
        try:
            with zipfile.ZipFile(local_path) as z:
                tables = [n for n in z.namelist()
                          if n.startswith("windows/") and n.endswith((".json.xz", ".json"))]
                ok = bool(tables)
                if ok:
                    say(f"Symbol pack: {len(tables):,} Windows symbol table(s) — verifying every file's checksum…")
                bad = z.testzip() if ok else None
        except (zipfile.BadZipFile, OSError) as e:
            return {"error": f"not a readable .zip ({e})"}
        if not ok:
            return {"error": "this .zip holds no Windows symbol tables (windows/…json.xz) — "
                             "not a Volatility symbol pack"}
        if bad:
            return {"error": f"the .zip is damaged ({bad} fails its checksum) — download it again"}
    incoming = os.path.join(dumps_dir, INCOMING)
    os.makedirs(incoming, exist_ok=True)
    tag = uuid.uuid4().hex[:12]
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", fname) or "symbol"
    staged = os.path.join(incoming, f"{tag}_{safe}")
    shutil.move(local_path, staged)
    in_worker = f"{STAGING_IN_VOLWEB}/{INCOMING}/{tag}_{safe}"
    _ADD_LOCK.acquire()
    try:
        if kind == "zip":
            # THE SAME PACK IS NOT STORED TWICE. Volatility reads every pack in the
            # library on every run, and with no feedback during the upload the
            # 840 MB windows.zip was sent twice and kept twice. Compared by
            # content, so a renamed copy is recognised too.
            say("Pack verified — checking whether the library already has it…")
            mine = _sha256(staged)
            r = _exec(f"cd {shlex.quote(SYMBOLS_DIR)} 2>/dev/null && sha256sum *.zip 2>/dev/null", 900)
            for line in (r.stdout or "").splitlines():
                digest, _, name = line.partition("  ")
                if digest.strip() == mine and name.strip():
                    return {"file": name.strip(), "pack": True, "already_had": True}
            # A symbol pack is read in place by Volatility: it goes in whole,
            # UNDER ITS OWN NAME, so a newer windows.zip replaces the older one
            # instead of piling up beside it (each upload used to get a random
            # prefix and every edition stayed). Copied beside it and renamed, so
            # a running analysis never reads half a pack; older prefixed copies
            # of the same pack (<12-hex>_windows.zip) are removed.
            say("Storing the pack in VolWeb's symbol library…")
            dest = f"{SYMBOLS_DIR}/{safe}"
            tmp = f"{SYMBOLS_DIR}/.{safe}.incoming"
            old = f"{SYMBOLS_DIR}/" + "[0-9a-f]" * 12 + f"_{safe}"
            r = _exec(f"cp {shlex.quote(in_worker)} {shlex.quote(tmp)} && chown app:app {shlex.quote(tmp)}"
                      f" && R=$([ -e {shlex.quote(dest)} ] && echo 1); mv -f {shlex.quote(tmp)} {shlex.quote(dest)}"
                      f" && for o in {old}; do [ -f \"$o\" ] && rm -f \"$o\" && R=1; done; echo \"replaced=$R\"", 300)
            if r.returncode != 0:
                _exec(f"rm -f {shlex.quote(tmp)}", 30)
                return {"error": "could not store the pack: " + (r.stderr or "")[-200:]}
            replaced = "replaced=1" in (r.stdout or "")
            if replaced:
                say("An older copy of this pack was replaced — only the newest is kept.")
            prewarm_index(say)
            return {"file": safe, "pack": True, "replaced": replaced}
        say({"pdb": "Converting the .pdb to a symbol table with the Volatility inside VolWeb…",
             "json": "Compressing the table and reading its own metadata…",
             "xz": "Reading the table's own metadata…"}[kind])
        sp = ("SP=$(ls -d /home/app/.local/lib/python3*/site-packages 2>/dev/null | head -1); "
              f"PYTHONPATH=\"$SP\" python3 -c {shlex.quote(_PLACE)} "
              f"{shlex.quote(in_worker)} {kind} {shlex.quote(SYMBOLS_DIR)}; "
              f"chown -R app:app {shlex.quote(SYMBOLS_DIR)}")
        r = _exec(sp, 600)
        import json
        last = [ln for ln in (r.stdout or "").splitlines() if ln.startswith("{")]
        if not last:
            return {"error": "the conversion gave no answer: " + (r.stderr or r.stdout or "")[-300:]}
        res = json.loads(last[-1])
        if not res.get("error") and not res.get("already_had"):
            prewarm_index(say)
        return res
    except subprocess.TimeoutExpired:
        return {"error": "the conversion took too long (over 10 minutes)"}
    finally:
        _ADD_LOCK.release()
        try:
            os.remove(staged)
        except OSError:
            pass
