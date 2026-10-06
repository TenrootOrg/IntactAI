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

Each release starts from the previous release's pack (--seed-zip), so it only
converts the Windows updates published since; only the first one is a cold build. Exits non-zero only when nothing
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
import time
import urllib.error
import urllib.request
import zipfile

WINBINDEX = "https://winbindex.m417z.com/data/by_filename_compressed/{}.json.gz"
MSDL = "https://msdl.microsoft.com/download/symbols"
AMD64 = 34404
# The binaries whose PDBs Volatility's Windows plugins need: the kernel (every
# plugin) and tcpip (NetScan / NetStat).
FILES = ("ntoskrnl.exe", "tcpip.sys")
# EVERY x64 build of EVERY Windows 10/11 version Winbindex knows -- not "still
# supported", not "the last N months". Organisations run old Windows for years
# and new Windows the week it ships; an air-gapped box cannot fill a gap later.
# Measured on the image that started this: Windows 11 IoT Enterprise LTSC 24H2
# runs 10.0.26100.1742, the September 2024 base build. None (no filter) also
# means a Windows version Microsoft ships tomorrow is in the next build with no
# change here. Server 2016/2019/2025 share their kernels with Windows 10
# 1607/1809 and Windows 11 24H2 and are covered; Server 2022 (build 20348) is
# NOT in Winbindex and needs another source. ~920 kernels + ~550 tcpip, ~700 MB.
VERSIONS = None
UA = {"User-Agent": "Microsoft-Symbol-Server/10.0.0.0"}


def _get(url: str, rng: tuple[int, int] | None = None, timeout: int | None = None) -> bytes:
    hdr = dict(UA)
    if rng:
        hdr["Range"] = f"bytes={rng[0]}-{rng[1]}"
    # A few KB of a PE header answers in a second or never; a whole PDB can take minutes.
    timeout = timeout or (30 if rng else 120)
    # Retried: on 2026-10-06 the cold plan lost 62 of 1,682 builds to
    # "urlopen error timed out" with 16 lookups in flight -- each then cost the
    # assembling job a retry and the plan two minutes. A 404 is final: the
    # symbol server does not have that build (11 that day).
    for attempt in range(3):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=hdr), timeout=timeout) as r:
                body = r.read()
                # A server that ignores Range answers 200 with the whole file: slice it,
                # or every offset below reads the wrong bytes.
                if rng and getattr(r, "status", 206) == 200:
                    body = body[rng[0]:rng[1] + 1]
                return body
        except urllib.error.HTTPError as e:
            if e.code < 500 or attempt == 2:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if attempt == 2:
                raise
        time.sleep(5 * (attempt + 1))
    raise AssertionError("unreachable")


def builds(name: str, since: str, data: dict | None = None, versions=VERSIONS) -> list[dict]:
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


# Every link is COMPUTED from the build being processed -- nothing names a
# version, a date or a build. Microsoft's symbol server addresses a binary by its
# PE timestamp + image size (from Winbindex) and a PDB by its GUID + age (from
# the binary's own CodeView record); Winbindex addresses its list by file name.
def binary_url(b: dict) -> str:
    return f"{MSDL}/{b['file']}/{b['timestamp']:08X}{b['virtualSize']:X}/{b['file']}"


def pdb_url(pdb: str, guid: str, age: int) -> str:
    return f"{MSDL}/{pdb}/{guid}{age:X}/{pdb}"


def codeview(b: dict) -> tuple[str, str, int]:
    """(pdb name, GUID, age) from the PE's CodeView debug record."""
    url = binary_url(b)
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
            fh.write(_get(pdb_url(pdb, guid, age), timeout=600))
        out = os.path.join(tmp, "out.json.xz")
        # -p names the database. Without it pdbconv falls back to what the PDB
        # says, which for tcpip.pdb is nothing: the table was written as
        # "unknown.pdb", Volatility indexed it under that name, and NetStat
        # could not find a table that was in the pack (2026-10-06, air-gap proof).
        r = subprocess.run([sys.executable, "-m", "volatility3.framework.symbols.windows.pdbconv",
                            "-f", local, "-p", pdb, "-o", out], capture_output=True, text=True, timeout=1800)
        if r.returncode != 0 or not os.path.exists(out):
            raise RuntimeError((r.stderr or r.stdout or "pdbconv failed")[-300:])
        meta = json.load(lzma.open(out))["metadata"]["windows"]["pdb"]
        # All three are what Volatility indexes a table by (pdb|GUID|age): a table
        # it cannot look up is a table the pack does not have.
        if meta["GUID"].upper() != guid or int(meta["age"]) != age or meta.get("database") != pdb:
            raise RuntimeError(f"converted table says {meta.get('database')}/{meta['GUID']}-{meta['age']}, "
                               f"wanted {pdb}/{guid}-{age}")
        shutil.move(out, dest + ".tmp")
        os.replace(dest + ".tmp", dest)
    return rel


def seed(cache: str, pack: str, log=print) -> int:
    """Start from a previous release's intact-windows-kernels.zip: every table in
    it, and the PDB identities it was built from, are reused as converted. The
    release workflow seeds from the last published release, so a release converts
    only the Windows updates published since -- with no schedule and no CI cache
    (a release run cannot restore another tag's cache anyway)."""
    n = 0
    with zipfile.ZipFile(pack) as z:
        for name in z.namelist():
            if name.startswith("windows/") and name.endswith(".json.xz"):
                dest = os.path.join(cache, name)
                if not os.path.exists(dest):
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    with z.open(name) as src, open(dest, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    n += 1
        if "codeview.json" in z.namelist():
            ids_path = os.path.join(cache, "codeview.json")
            try:
                with open(ids_path) as fh:
                    ids = json.load(fh)
            except (OSError, ValueError):
                ids = {}
            ids.update(json.loads(z.read("codeview.json")))
            with open(ids_path, "w") as fh:
                json.dump(ids, fh)
    log(f"kernel pack: seeded {n} table(s) from {pack}")
    return n


def _hms(sec: float) -> str:
    sec = int(sec)
    return f"{sec // 3600}h{sec % 3600 // 60:02d}m" if sec >= 3600 else f"{sec // 60}m{sec % 60:02d}s"


def _bar(done: int, total: int, t0: float, now: float) -> str:
    """[#######-------------] 412/1470  28% · 31m05s · ETA 1h20m -- one line per
    finished item, so a CI log shows where a build is and when it will end."""
    frac = done / total if total else 1.0
    fill = int(20 * frac)
    eta = (now - t0) / done * (total - done) if done else 0
    return (f"[{'#' * fill}{'-' * (20 - fill)}] {done}/{total} {frac:4.0%} · {_hms(now - t0)}"
            + (f" · ETA {_hms(eta)}" if done < total else ""))


def _key(b: dict) -> str:
    return f"{b['file']}:{b['timestamp']}:{b['virtualSize']}"


def identify(todo: list[dict], ids: dict, jobs: int, log=print) -> list[str]:
    """Fill `ids` (build key -> [pdb, GUID, age]) for every build it lacks, with
    range requests to Microsoft's symbol server. A build's identity never
    changes, so a seeded or warm run asks the server nothing."""
    need = [b for b in todo if _key(b) not in ids]
    failed: list[str] = []
    if not need:
        return failed
    log(f"kernel pack: reading the PDB identity of {len(need)} build(s) from the symbol server")
    t0 = time.monotonic()
    # I/O, not CPU: many more threads than cores.
    with cf.ThreadPoolExecutor(max_workers=max(16, jobs)) as ex:
        futs = {ex.submit(codeview, b): b for b in need}
        for n, f in enumerate(cf.as_completed(futs), 1):
            b = futs[f]
            try:
                ids[_key(b)] = list(f.result())
            except Exception as e:                       # noqa: BLE001 -- one bad build, not the pack
                failed.append(f"{b['file']} {b['version']}: identity: {str(e)[:150]}")
            if n % 100 == 0 or n == len(need):
                log(f"  identities {_bar(n, len(need), t0, time.monotonic())} · {len(failed)} failed")
    return failed


def make_plan(cache: str, since: str, jobs: int, data: dict | None = None,
              skip_zip: str | None = None, versions=VERSIONS, log=print):
    """What the pack holds and what is still to convert.

    Returns (tables, work, failed): tables = {rel: {version, released, windows}}
    for every table the pack should carry; work = the [pdb, GUID, age] of each
    one not in the cache yet -- each ONCE, though several builds may share it
    (converting it twice wasted a CPU minute and raced on the same file)."""
    os.makedirs(cache, exist_ok=True)
    todo = [b for name in FILES for b in builds(name, since, (data or {}).get(name), versions)]
    # Tables Volatility's own windows.zip already carries are not shipped twice.
    have = set()
    if skip_zip:
        have = {n for n in zipfile.ZipFile(skip_zip).namelist() if n.endswith((".json.xz", ".json"))}
    log(f"kernel pack: {len(todo)} x64 build(s) of {', '.join(FILES)} "
        f"({', '.join(versions) if versions else 'every Windows version'}), released since {since}"
        + (f"; skipping {len(have)} table(s) in {skip_zip}" if have else ""))
    ids_path = os.path.join(cache, "codeview.json")
    try:
        with open(ids_path) as fh:
            ids = json.load(fh)
    except (OSError, ValueError):
        ids = {}
    failed = identify(todo, ids, jobs, log)
    with open(ids_path + ".tmp", "w") as fh:
        json.dump(ids, fh)
    os.replace(ids_path + ".tmp", ids_path)
    tables, work = {}, []
    for b in todo:
        if _key(b) not in ids:
            continue
        pdb, guid, age = ids[_key(b)]
        rel = f"windows/{pdb}/{guid}-{age}.json.xz"
        if rel in have or rel in tables:
            continue
        tables[rel] = {"version": b["version"], "released": b["released"], "windows": b["windows"]}
        if not os.path.exists(os.path.join(cache, rel)):
            work.append([pdb, guid, age])
    log(f"kernel pack: {len(tables)} table(s) in the pack; {len(tables) - len(work)} already converted, "
        f"{len(work)} to convert")
    return tables, work, failed


def convert_all(work: list, cache: str, jobs: int, log=print) -> list[str]:
    """Convert every [pdb, GUID, age] in `work` into the cache, one progress line
    per table. Returns the failures; one bad PDB never stops the rest."""
    failed: list[str] = []
    if not work:
        return failed
    log(f"kernel pack: converting {len(work)} table(s), {jobs} at a time")
    t0 = time.monotonic()
    with cf.ThreadPoolExecutor(max_workers=jobs) as ex:
        futs = {ex.submit(lambda w: (time.monotonic(), convert(*w, cache), time.monotonic()), w): w for w in work}
        for n, f in enumerate(cf.as_completed(futs), 1):
            pdb, guid, age = futs[f]
            try:
                st, _rel, end = f.result()
                what = f"ok   {pdb}/{guid}-{age} ({end - st:.0f}s)"
            except Exception as e:                       # noqa: BLE001
                failed.append(f"{pdb}/{guid}-{age}: {str(e)[:150]}")
                what = f"FAIL {pdb}/{guid}-{age}: {str(e)[:120]}"
            log(f"  {_bar(n, len(work), t0, time.monotonic())} · {what}")
    log(f"kernel pack: converted {len(work) - len(failed)}/{len(work)} in {_hms(time.monotonic() - t0)}"
        + (f", {len(failed)} failed" if failed else ""))
    return failed


def build(out_dir: str, cache: str, since: str, jobs: int, data: dict | None = None,
          skip_zip: str | None = None, versions=VERSIONS, log=print) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    tables, work, failed = make_plan(cache, since, jobs, data, skip_zip, versions, log)
    failed += convert_all(work, cache, jobs, log)
    tables = {rel: m for rel, m in tables.items() if os.path.exists(os.path.join(cache, rel))}
    if not tables:
        raise SystemExit(f"kernel pack: nothing built ({len(failed)} failure(s); first: {failed[:1]})")
    with open(os.path.join(cache, "codeview.json")) as fh:
        ids = json.load(fh)
    pack = os.path.join(out_dir, "intact-windows-kernels.zip")
    with zipfile.ZipFile(pack + ".tmp", "w", zipfile.ZIP_STORED) as z:   # .xz is already compressed
        for rel in sorted(tables):
            z.write(os.path.join(cache, rel), rel)
        z.writestr("codeview.json", json.dumps(ids, sort_keys=True))
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
    ap.add_argument("--out", help="where intact-windows-kernels.zip is written")
    ap.add_argument("--cache", required=True)
    ap.add_argument("--since", default="2000-01-01",
                    help="only builds released on/after this date (default: every build of a supported version)")
    ap.add_argument("--skip-zip", help="a symbol pack whose tables need not be built again (windows.zip)")
    ap.add_argument("--seed-zip", help="a previous intact-windows-kernels.zip to start from")
    ap.add_argument("--versions", default="",
                    help="Winbindex Windows version keys, comma separated (default: every version)")
    ap.add_argument("--jobs", type=int, default=max(2, (os.cpu_count() or 2)))
    # CI fans the conversion out (volweb-symbols-pack.yml): one job writes the
    # plan, N jobs each convert every Nth table of it, one job builds the zip
    # from the merged tables. A cold build is ~1,470 tables at ~45 s of one CPU
    # each -- ~4 h on one runner, ~40 min on eight.
    ap.add_argument("--plan-out", help="write what is to convert to this file, and stop")
    ap.add_argument("--plan", help="the --plan-out file a --shard converts from")
    ap.add_argument("--shard", help="K/N: convert every Nth table of --plan, starting at K, into --cache")
    a = ap.parse_args(argv)
    cache = os.path.expanduser(a.cache)
    os.makedirs(cache, exist_ok=True)
    if a.seed_zip and os.path.isfile(a.seed_zip):
        seed(cache, a.seed_zip)
    versions = tuple(v for v in a.versions.split(",") if v) or None
    if a.shard:
        k, n = (int(x) for x in a.shard.split("/"))
        with open(a.plan) as fh:
            work = json.load(fh)["convert"][k::n]
        print(f"kernel pack: shard {k + 1}/{n}: {len(work)} table(s)")
        convert_all(work, cache, a.jobs)
        return 0                  # failures are retried by the assembling build
    if a.plan_out:
        _tables, work, failed = make_plan(cache, a.since, a.jobs, skip_zip=a.skip_zip, versions=versions)
        with open(a.plan_out, "w") as fh:
            json.dump({"convert": work, "identity_failures": failed}, fh)
        return 0
    if not a.out:
        ap.error("--out is required to build the pack")
    build(a.out, cache, a.since, a.jobs, skip_zip=a.skip_zip, versions=versions)
    return 0


if __name__ == "__main__":
    sys.exit(main())
