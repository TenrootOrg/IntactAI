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

Nothing in the release package ships this file: it is per-site, it is large, and
it does not cover modern kernels. The staging path is wired so that a site which
*does* want it only has to put it in `data/volweb-symbols/`.

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
