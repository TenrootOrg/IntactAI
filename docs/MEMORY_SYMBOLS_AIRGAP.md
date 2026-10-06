# Windows memory analysis: Volatility symbols, online and air-gapped

Volatility 3 cannot read a Windows memory image without the **ISF** (Intermediate
Symbol File) for that exact kernel build. It ships with **no Windows symbols at
all** — it derives them on demand: find the kernel in the dump, read its PDB GUID,
download `ntkrnlmp.pdb` from `msdl.microsoft.com`, convert it.

On a box with internet that happens by itself the first time a kernel is seen. On
an **air-gapped** box the download fails, and what the operator sees is not an
error about symbols:

```
Symbol file could not be downloaded from remote server
Unsatisfied requirements:
Task VolWeb.SelectiveEngine[…] succeeded in 36.09s: None
```

Volatility constructs **zero plugins**, VolWeb's extraction task ends **SUCCESS**
in ~36 seconds having produced nothing, and every Windows MEMORY run on the
appliance fails. Since 2026-09-22 the backend names this exact cause in the run
log and fails the run in ~40 s instead of waiting out the 30-minute budget, and
it **keeps the dump** (host copy, VolWeb staging, Velociraptor flow) so the retry
costs no re-acquisition.

## Where symbols go

`/home/app/web/media/symbols` inside the VolWeb containers — the shared
`volweb_volweb_media` volume. VolWeb adds it to Volatility's search path
(`volatility_engine/utils.py`: `volatility3.symbols.__path__ += [ … ]`).

Volatility 3 (2.28 in `forensicxlab/volweb-backend:3.16.0`) indexes:

* loose ISFs — `*.json`, `*.json.xz`, `*.json.gz`, at any depth
* **whole `.zip` symbol packs**, read in place — nothing to unpack

You never copy there by hand. Put the files in **`data/volweb-symbols/`** in the
appliance directory and run the installer or an upgrade:
`lib/modules/volweb.sh:seed_volweb_symbols` copies anything new into the volume
(`docker cp`, idempotent), and then **prints how many symbol files the box has**.
A release package that carries a `volweb_symbols/` directory is staged into the
same place by `lib/package.sh`.

The directory is created by a root `docker exec` and then **chowned to `app`**,
unconditionally — VolWeb runs as `app`, and a root-owned `symbols/` means the
appliance can read what shipped but can never add to it. That is invisible from
the outside: runs still start, still finish, and quietly learn nothing.

### `scripts/clean.sh --volumes` and `--all` DESTROY the symbol library

`volweb_volweb_media` is an ordinary named volume, so both flags remove it along
with everything else — and on an air-gapped box the ISFs in it cannot be fetched
again. Before running either, copy them out:

```bash
docker run --rm -v volweb_volweb_media:/m -v "$PWD/data/volweb-symbols:/out" \
    alpine sh -c 'cp -rn /m/symbols/. /out/ 2>/dev/null; true'
```

They are then re-seeded by the next install or upgrade. Upgrades do **not** need
this: no upgrade module removes a volume, and `lib/upgrade/modules/volweb.sh`
counts the library before and after and says so in the report if it shrank.

## Option 1 — one kernel, 230 KB (recommended)

The smallest thing that actually works. You need one ISF per distinct Windows
kernel build you analyse, and the failed run tells you exactly which:

```
The image needs the ISF for ntkrnlmp.pdb 3006AD7DBD884D8EB8F92EC21FFCEE4E2
```

On an **internet-connected** machine with Docker (same image the appliance runs,
so the converter matches):

```bash
PDB=ntkrnlmp.pdb
GUID=3006AD7DBD884D8EB8F92EC21FFCEE4E2      # GUID + age, no separator
docker run --rm -v "$PWD:/out" forensicxlab/volweb-backend:3.16.0 \
    python3 -m volatility3.framework.symbols.windows.pdbconv \
    -p "$PDB" -g "$GUID" -o "/out/${GUID}.json.xz"
```

Carry `<GUID>.json.xz` to the appliance, drop it in `data/volweb-symbols/`, and
re-run the installer (or `seed_volweb_symbols` on its own). Measured: **~230 KB
compressed** per kernel, 2.6 MB of JSON, indexed in under a tenth of a second.

Re-run the memory analysis against the dump you still have — Memory → *Upload
existing dump* — no re-acquisition from the endpoint.

## Option 2 — the full Microsoft pack, 801 MiB

The Volatility Foundation publishes one zip of pre-converted Windows ISFs:

```bash
curl -L -o data/volweb-symbols/windows.zip \
    https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
```

Measured 2026-09-22, from the server and from the zip's own central directory:

| | |
|---|---|
| download size | 839,727,133 bytes = **801 MiB** |
| contents | **3,014** ISFs — ntkrnlmp 1,724 · ntkrpamp 1,027 · ntoskrnl 149 · ntkrnlpa 114 |
| last published | **2019-10-16** |
| first-use indexing cost | ~3,014 files × ~50 ms ≈ **2.5–5 min**, once per container lifetime |

Two things to know before you carry 801 MiB across an air gap:

* **It stops at 2019.** The pack has not been republished since 2019-10-16, so a
  Windows 10 20H2+, Windows 11, or any patched modern kernel is **not in it**.
  It is worth carrying for older estates; it is not a guarantee, and it is not a
  substitute for Option 1 on a current endpoint.
* The index it builds lives in the container's `~/.cache/volatility3`, not in a
  volume, so the 2.5–5 minutes is paid again after any container recreate
  (upgrade, `docker compose up -d --force-recreate`). Loose per-kernel ISFs cost
  effectively nothing to re-index.

**Every release ships it**, in the release's own **`<tag>-volweb_symbols.tar`**
(`volweb_symbols/windows.zip`, its sha256 in the release index), and install and
upgrade put it in VolWeb. Only the
newest copy is kept: a changed pack **replaces** the old one of the same name,
earlier uploads of it (`<12-hex>_windows.zip`) are removed, and an upload through
Settings → *Volatile Memory* replaces it the same way. Per-kernel ISFs (Option 1, and
what the box downloads from Microsoft itself) are never removed — each is a
different kernel, not an older copy. A site can still drop its own pack or ISFs
into `data/volweb-symbols/`.

## Option 3 — the Intact kernel pack, every supported Windows build (shipped)

`windows.zip` stops in 2019: a Windows 10 20H2+ or Windows 11 image is not in it.
Measured on Windows 11 IoT Enterprise LTSC 24H2 (DESKTOP-2175T02): its kernel,
10.0.26100.1742, needs `ntkrnlmp.pdb/953A8DE880B0818C32DA2DEC1D79C2D9-1`, which a
connected box downloads from Microsoft and an air-gapped one cannot get.

So every release also ships **`intact-windows-kernels.zip`**, beside `windows.zip`
in **`<tag>-volweb_symbols.tar`** — a release asset of its own, outside the volweb
module asset (with both packs inside, that one passed GitHub's 2 GiB per-file
limit). Built in CI by `scripts/ci/build_kernel_pack.py` (workflow
`volweb-symbols-pack.yml`, fanned out over 8 runners):

| | |
|---|---|
| what | `ntkrnlmp.pdb` + `tcpip.pdb` tables for **every x64 build of every Windows 10 and 11 version** (1507 → 26H1, LTSC included, out-of-support versions too — organisations run them), and with them Server 2016/2019/2025, which share those kernels. A Windows version released tomorrow is in the next build with no code change |
| not covered | **Server 2022** (build 20348, its own kernel) — Winbindex indexes client Windows only. Windows 7/8.1/Server 2012 R2 only as far as `windows.zip` (2019) |
| how | Winbindex lists the builds; each kernel's PDB identity is read from Microsoft's symbol server; the PDB is converted with Volatility 3.2.28's own `pdbconv` — the same server and converter VolWeb uses, and the same table (checked: identical to the one VolWeb downloaded itself) |
| skips | tables `windows.zip` already has |
| size | ~920 kernels + ~550 tcpip ≈ 610 MB (kernel ~615 KB, tcpip ~106 KB each) |
| fresh | built in every release, as of that day, seeded from the previous release's pack — only what Microsoft published since is converted. No schedule |

Install and upgrade treat it exactly like `windows.zip`: staged, seeded into
`media/symbols`, replaced when it changed, indexed in the background. An upgrade
fetches `<tag>-volweb_symbols.tar` when **any** pack file differs from the box's
(`volweb_symbols.files` in the release index), and only then — whether or not
VolWeb itself moves. Not covered: Server 2022 and post-2019 Windows 7/8.1/Server 2012 R2
updates; upload those per Option 1.

## Check where you stand

The installer and every upgrade print one of:

```
VolWeb Windows symbols: 12 ISF file(s)/pack(s) present — offline memory analysis is covered
```

```
VolWeb has NO Volatility symbols and this is an air-gapped install.
Every Windows memory analysis will fail in ~40s with 'could not get kernel symbols'.
```

To ask directly:

```bash
docker exec intact_volweb_backend sh -c \
  "find /home/app/web/media/symbols -type f \
   \( -name '*.json' -o -name '*.json.xz' -o -name '*.json.gz' -o -name '*.zip' \) | wc -l"
```

## Linux / macOS images

The same directory serves them (`media/symbols/linux/`, `media/symbols/mac/`),
and the same `data/volweb-symbols/` staging applies. There is no symbol server
for those: an ISF must be built from the target kernel's debug package with
`dwarf2json`. Out of scope here — this appliance acquires Windows memory.

## Adding a symbol table from the UI (air-gapped boxes)

Settings → **Volatile Memory** → **Upload** (the tab shows when VolWeb is
installed; the page also lists what the box holds and which Windows the pack
covers). Accepted, and where to get each:

- **A newer pack** — `intact-windows-kernels.zip` out of a newer Intact.AI
  release's `<tag>-volweb_symbols.tar`. Upload the `.zip` as is; Volatility reads
  packs in place. nginx lets this one route take bodies over
  the 500M `/api/` cap (`location = /api/memory/symbols/upload`).
- **One build's table** — its `.pdb` from Microsoft's symbol server, at the link
  the failed analysis prints in its log (converted on the box with `pdbconv -f`,
  named from the table's own metadata); or a ready `.json.xz` / `.json`, e.g. from
  a connected Intact.AI appliance's `media/symbols/windows/<pdb>/`.

`windows.zip` from the Volatility Foundation is not offered: it was last
published in 2019 and every release already carries it.

Missing `ntkrnlmp.pdb` → no plugin output at all; missing `tcpip.pdb` → NetStat
fails and NetScan comes back empty.
