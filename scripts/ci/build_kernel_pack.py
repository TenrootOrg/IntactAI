#!/usr/bin/env python3
"""Build intact-windows-kernels.zip: Volatility 3 symbol tables (ISF) for recent
Windows kernels, so an AIR-GAPPED appliance can analyse a memory image of them.

Why this exists (2026-10-05): the only ready-made pack, Volatility's windows.zip,
stops in 2019. A Windows 11 24H2 image (DESKTOP-2175T02) needed
ntkrnlmp.pdb/953A8DE880B0818C32DA2DEC1D79C2D9-1, which is not in it; a connected
box downloads that from Microsoft on first use, an air-gapped one cannot. This
does ahead of time, for every recent kernel build, exactly what VolWeb does for
one image: the same Microsoft symbol server, the same Volatility converter.

  1. Winbindex lists every Windows build of a file, with the timestamp and
     virtual size Microsoft's symbol server addresses it by.
  2. The PE's CodeView record names its PDB (name, GUID, age) -- read with HTTP
     range requests, not a whole-kernel download.
  3. The PDB comes from msdl.microsoft.com and `volatility3 ... pdbconv` turns it
     into windows/<pdb>/<GUID>-<age>.json.xz, the layout VolWeb reads in a pack.

A cache directory keeps every converted table, so a release only converts the
Windows updates published since the last one. Exits non-zero only when nothing
at all could be built; individual failures are reported and skipped.

    python3 scripts/ci/build_kernel_pack.py --out dist/ --cache ~/.cache/kpack --since 2024-10-01
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import gzip
import json
import lzma
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

WINBINDEX = "https://winbindex.m417z.com/data/by_filename_compressed/{}.json.gz"
MSDL = "https://msdl.microsoft.com/download/symbols"
AMD64 = 34404
# The binaries whose PDBs Volatility's Windows plugins need: the kernel (every
# plugin) and tcpip (NetScan / NetStat).
FILES = ("ntoskrnl.exe", "tcpip.sys")
# EVERY build of every Windows version Microsoft still supports, LTSC and Server
# lines included -- not "the last N months". Measured on the image that started
# this: Windows 11 IoT Enterprise LTSC 24H2 runs 10.0.26100.1742, the September
# 2024 base build, a year older than a 12-month window reaches. LTSC/IoT boxes sit
# on their base build for years. Winbindex keys (Server 2016/2019/2022/2025 share
# 1607/1809/21H2/11-24H2). ~690 kernels + ~370 tcpip, ~530 MB.
SUPPORTED = ("1507", "1607", "1809", "21H2", "22H2",
             "11-22H2", "11-23H2", "11-24H2", "11-25H2", "11-26H1")
UA = {"User-Agent": "Microsoft-Symbol-Server/10.0.0.0"}


def _get(url: str, rng: tuple[int, int] | None = None, timeout: int = 120) -> bytes:
    hdr = dict(UA)
    if rng:
        hdr["Range"] = f"bytes={rng[0]}-{rng[1]}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=hdr), timeout=timeout) as r:
        body = r.read()
        # A server that ignores Range answers 200 with the whole file: slice it,
        # or every offset below reads the wrong bytes.
        if rng and getattr(r, "status", 206) == 200:
            body = body[rng[0]:rng[1] + 1]
        return body


def builds(name: str, since: str, data: dict | None = None, versions=SUPPORTED) -> list[dict]:
    """x64 builds of `name` in one of `versions` (None: any), shipped in an update
    released on/after `since`."""
    if data is None:
        data = json.load(gzip.GzipFile(fileobj=__import__("io").BytesIO(_get(WINBINDEX.format(name)))))
    out = []
    for v in data.values():
        fi = v.get("fileInfo") or {}
        if fi.get("machineType") != AMD64 or "timestamp" not in fi or "virtualSize" not in fi:
            continue
        rel = [(kb.get("updateInfo") or {}).get("releaseDate") or ""
               for kbs in (v.get("windowsVersions") or {}).values() for kb in kbs.values()
               if isinstance(kb, dict)]
        latest = max(rel or [""])
        if versions and not set(versions) & set(v.get("windowsVersions") or {}):
            continue
        if latest >= since:
            out.append({"file": name, "timestamp": fi["timestamp"], "virtualSize": fi["virtualSize"],
                        "version": fi.get("version", ""), "released": latest,
                        "windows": sorted((v.get("windowsVersions") or {}).keys())})
    return out


def codeview(b: dict) -> tuple[str, str, int]:
    """(pdb name, GUID, age) from the PE's CodeView debug record."""
    url = f"{MSDL}/{b['file']}/{b['timestamp']:08X}{b['virtualSize']:X}/{b['file']}"
    head = _get(url, (0, 4095))
    pe = struct.unpack_from("<I", head, 0x3C)[0]
    nsec = struct.unpack_from("<H", head, pe + 6)[0]
    opt = pe + 24
    if struct.unpack_from("<H", head, opt)[0] != 0x20B:
        raise ValueError("not a PE32+ image")
    dbg_rva, dbg_size = struct.unpack_from("<II", head, opt + 112 + 6 * 8)
    secs = opt + struct.unpack_from("<H", head, pe + 20)[0]

    def raw(rva):
        for i in range(nsec):
            va, vsz, rsz, rptr = (struct.unpack_from("<I", head, secs + i * 40 + o)[0] for o in (12, 8, 16, 20))
            if va <= rva < va + max(vsz, rsz):
                return rva - va + rptr
        raise ValueError("debug directory outside every section")

    off = raw(dbg_rva)
    dd = _get(url, (off, off + dbg_size - 1))
    for i in range(0, len(dd), 28):
        typ, size, _rva, ptr = struct.unpack_from("<I", dd, i + 12)[0], *struct.unpack_from("<III", dd, i + 16)
        if typ == 2:                                   # IMAGE_DEBUG_TYPE_CODEVIEW
            cv = _get(url, (ptr, ptr + size - 1))
            if cv[:4] != b"RSDS":
                raise ValueError("CodeView record is not RSDS")
            d1, d2, d3 = struct.unpack_from("<IHH", cv, 4)
            guid = f"{d1:08X}{d2:04X}{d3:04X}" + cv[12:20].hex().upper()
            age = struct.unpack_from("<I", cv, 20)[0]
            name = cv[24:].split(b"\0", 1)[0].decode()
            return name, guid, age
    raise ValueError("no CodeView debug record")


def convert(pdb: str, guid: str, age: int, cache: str) -> str:
    """windows/<pdb>/<GUID>-<age>.json.xz in the cache, converting when missing."""
    rel = f"windows/{pdb}/{guid}-{age}.json.xz"
    dest = os.path.join(cache, rel)
    if os.path.exists(dest):
        return rel
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        local = os.path.join(tmp, pdb)
        with open(local, "wb") as fh:
            fh.write(_get(f"{MSDL}/{pdb}/{guid}{age:X}/{pdb}", timeout=600))
        out = os.path.join(tmp, "out.json.xz")
        r = subprocess.run([sys.executable, "-m", "volatility3.framework.symbols.windows.pdbconv",
                            "-f", local, "-o", out], capture_output=True, text=True, timeout=1800)
        if r.returncode != 0 or not os.path.exists(out):
            raise RuntimeError((r.stderr or r.stdout or "pdbconv failed")[-300:])
        meta = json.load(lzma.open(out))["metadata"]["windows"]["pdb"]
        if meta["GUID"].upper() != guid or int(meta["age"]) != age:
            raise RuntimeError(f"converted table says {meta['GUID']}-{meta['age']}")
        shutil.move(out, dest + ".tmp")
        os.replace(dest + ".tmp", dest)
    return rel


def build(out_dir: str, cache: str, since: str, jobs: int, data: dict | None = None,
          skip_zip: str | None = None, log=print) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(cache, exist_ok=True)
    todo = [b for name in FILES for b in builds(name, since, (data or {}).get(name))]
    # Tables Volatility's own windows.zip already carries are not shipped twice.
    have = set()
    if skip_zip:
        have = {n for n in zipfile.ZipFile(skip_zip).namelist() if n.endswith((".json.xz", ".json"))}
    log(f"kernel pack: {len(todo)} x64 build(s) of {', '.join(FILES)} in supported Windows "
        f"versions, released since {since}" + (f"; skipping {len(have)} table(s) in {skip_zip}" if have else ""))
    tables, failed = {}, []

    def one(b):
        pdb, guid, age = codeview(b)
        rel = f"windows/{pdb}/{guid}-{age}.json.xz"
        if rel in have:
            return b, None
        return b, convert(pdb, guid, age, cache)

    with cf.ThreadPoolExecutor(max_workers=jobs) as ex:
        for f in cf.as_completed([ex.submit(one, b) for b in todo]):
            try:
                b, rel = f.result()
                if rel:
                    tables.setdefault(rel, {"version": b["version"], "released": b["released"],
                                            "windows": b["windows"]})
            except Exception as e:                       # noqa: BLE001 -- one bad build, not the pack
                failed.append(str(e)[:200])
    if not tables:
        raise SystemExit(f"kernel pack: nothing built ({len(failed)} failure(s); first: {failed[:1]})")
    pack = os.path.join(out_dir, "intact-windows-kernels.zip")
    with zipfile.ZipFile(pack + ".tmp", "w", zipfile.ZIP_STORED) as z:   # .xz is already compressed
        for rel in sorted(tables):
            z.write(os.path.join(cache, rel), rel)
        z.writestr("intact-kernel-pack.json", json.dumps(
            {"built": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "since": since,
             "tables": tables, "failed": len(failed)}, indent=1, sort_keys=True))
    os.replace(pack + ".tmp", pack)
    log(f"kernel pack: {len(tables)} table(s) -> {pack} "
        f"({os.path.getsize(pack) / 1048576:.0f} MB); {len(failed)} build(s) skipped")
    for e in failed[:10]:
        log(f"  skipped: {e}")
    return {"pack": pack, "tables": len(tables), "failed": failed}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--cache", required=True)
    ap.add_argument("--since", default="2000-01-01",
                    help="only builds released on/after this date (default: every build of a supported version)")
    ap.add_argument("--skip-zip", help="a symbol pack whose tables need not be built again (windows.zip)")
    ap.add_argument("--jobs", type=int, default=max(2, (os.cpu_count() or 2)))
    a = ap.parse_args(argv)
    build(a.out, os.path.expanduser(a.cache), a.since, a.jobs, skip_zip=a.skip_zip)
    return 0


if __name__ == "__main__":
    sys.exit(main())
