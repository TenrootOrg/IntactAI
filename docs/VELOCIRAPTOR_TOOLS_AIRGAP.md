# Velociraptor tools on an air-gapped appliance

Many Velociraptor artifacts run a third-party **tool** on the endpoint: Hayabusa,
Sigcheck, Bulk Extractor, YARA rule files, and so on. Online, Velociraptor
downloads each tool from its internet URL the first time an artifact needs it.
An air-gapped box has no internet, so any tool that is not already stored on the
Velociraptor server makes its artifact **fail when it runs**.

This page says which tools an air-gapped install already has, and how to add any
others — with `scripts/velo_tools.sh`, or by hand.

## What is already inside, and configured

An air-gapped install (`install.sh --package …`) ships and registers the tools the
**default blueprints** use. They are stored on the Velociraptor server and served
to endpoints from it, so they work with no internet:

| Tool name | File | Used by |
|---|---|---|
| `Autorun_amd64` | `autorunsc64.exe` | `Windows.Sysinternals.Autoruns` |
| `lastactivityview` | `lastactivityview.zip` | `Windows.Nirsoft.LastActivityView` |
| `DetectRaptorLolRMM` | `lolrmm.csv` | `DetectRaptor.Windows.Detection.LolRMM` |
| `VelociraptorWindows`, `VelociraptorWindowsMSI`, `VelociraptorLinux`, `VelociraptorCollector` | the Velociraptor binaries and the offline collector | client installers, offline collectors |

That is **7 tools**, measured on a clean `install.sh --package` install of
`intact-20260903` with only Velociraptor enabled. Every artifact the default
Velociraptor blueprints use is present, and every tool they need is stored, on
64-bit Windows. `Windows.Sysinternals.Autoruns` on **32-bit** Windows needs
`Autorun_386`, which is not included.

## What is not inside

Everything else: **79** more tools that artifacts on the server refer to, stored
by name only and pointing at internet URLs. Among them are Hayabusa, Sigcheck,
FTK Imager, CatScale, Bulk Extractor, ThorZIP, the log4shell scanners, and:

- `FileYaraWindows` / `FileYaraLinux` / `FileYaraMacOS`, the rule files for
  `DetectRaptor.Generic.Detection.YaraFile`;
- `extsentry`, the feed for `DetectRaptor.Generic.Detection.BrowserExtensions`.

No default blueprint uses these. Their artifacts fail on an air-gapped box until
you add the tool yourself. A box that was installed or maintained **with
internet** may already hold some of them.

The package deliberately carries only the default tools (see
`data/tools_inventory.yaml`: `enabled: true` is the default tier). Setting
`options.download_tools: true` in `config.yaml` does **not** put the optional
tools into a package; it only makes an install or maintenance run **with
internet** download them.

## Add the extra tools

`scripts/velo_tools.sh` moves tools onto an air-gapped appliance. It carries no
list of its own: it asks the running server which tools **its own artifacts**
want and hasn't got, so artifacts you import later are covered too, and it
registers any file under any tool name you give it.

### 1. On the appliance — what is missing

```bash
sudo bash scripts/velo_tools.sh list > missing.tsv
```

One row per tool: the exact tool name, its download URL, and the artifacts that
want it. Delete the rows you do not need — you only need the tools for the
artifacts you intend to run.

```
TOOL             URL                                                SHA256 the artifact expects   ARTIFACTS
Autorun_386      https://live.sysinternals.com/tools/autorunsc.exe                                Windows.Sysinternals.Autoruns
Hayabusa-2.14.0  https://github.com/.../hayabusa-2.14.0-win-x64.zip de8abff4f6ed35f2...           Exchange.Windows.EventLogs.Hayabusa.Takajo
```

A row with an empty URL (a vendor installer such as `CrowdStrikeFalconInstaller`)
has no public download; get that file from the vendor and use `add` (below).

**The hash column matters.** Some artifacts pin their tool's sha256 — 18 of the
missing tools on a clean box do, including every Hayabusa version, SharpHound,
Capa and Sigcheck. A file that does not match is registered happily by the
server and then **refused by the endpoint**, mid-collection. So `fetch` checks
what it downloaded, and `add`/`import` refuse a file whose hash does not match:

```
ERROR: hash mismatch for Hayabusa-2.14.0
ERROR:   the artifact expects: de8abff4f6ed35f28e1e2897659e4f7adcca13ef84d2764afa786ca3f60224ec
ERROR:   this file is:         7d94206ac5c5d68cae535916fe92ba86f963e459633233ff8faf6b361a959d90
ERROR:   endpoints would refuse it. Get the pinned version, or re-run with --force.
```

Nothing is copied or registered when that happens. If the URL has moved on to a
newer release, fetch the pinned version instead — or, if you mean to run a
different version, update the artifact's tool definition and use `--force`.

### 2. On a machine WITH internet — download them

Carry `missing.tsv` across, then:

```bash
bash scripts/velo_tools.sh fetch missing.tsv --out ./velo-tools
```

This writes the files plus a `velo_tools.map` (`TOOL<TAB>FILE`) next to them.
The map is what makes each file land under its **real tool name** on the other
side. Check each tool's licence before redistributing it to a customer site.

### 3. Back on the appliance — register them

Carry `./velo-tools` across, then:

```bash
sudo bash scripts/velo_tools.sh import ./velo-tools
sudo bash scripts/velo_tools.sh status
```

`import` copies the files into `data/tools/` and registers each one under its
tool name. It makes **no** network calls, so it works with the cable pulled.
Re-running it is harmless.

### A worked example, start to finish

Adding CatScale (a Linux collection script) to an air-gapped box. Real output.

**On the appliance** — find it and keep just that row:

```bash
$ cd /home/tenroot/intact
$ sudo bash scripts/velo_tools.sh list > missing.tsv
# 79 tool(s) missing
$ grep '^CatScale' missing.tsv > want.tsv
$ cat want.tsv
CatScale   https://raw.githubusercontent.com/FSecureLABS/LinuxCatScale/master/Cat-Scale.sh      Linux.Collection.CatScale
```

**On a machine with internet** — carry `want.tsv` over, download:

```bash
$ bash scripts/velo_tools.sh fetch want.tsv --out ./velo-tools
  fetched CatScale -> Cat-Scale.sh
fetch: 1 downloaded, 0 without a public URL, 0 failed
carry ./velo-tools (files + velo_tools.map) to the appliance, then: velo_tools.sh import ./velo-tools

$ ls velo-tools
Cat-Scale.sh  velo_tools.map
$ cat velo-tools/velo_tools.map
CatScale	Cat-Scale.sh
```

**Back on the appliance** — carry the folder over (USB, share, however), import:

```bash
$ sudo bash scripts/velo_tools.sh import /media/usb/velo-tools
registered CatScale -> Cat-Scale.sh
import: 1 registered, 0 failed
```

That is the whole job. The tool is stored on the server, hashed, and served to
endpoints with no internet:

```bash
$ sudo bash scripts/velo_tools.sh status
Stored on this server (served to endpoints, no internet needed):
  CatScale  <-  Cat-Scale.sh
  ...
  (10 tool(s))
Missing (an artifact wants them, this server has not got them): 76
```

### A folder you put together yourself

If you downloaded the files by hand rather than with `fetch`, the folder has no
`velo_tools.map`, and `import` will not guess names — a wrong name registers
happily and is then never found by any artifact:

```bash
$ sudo bash scripts/velo_tools.sh import /media/usb/my-tools
ERROR: no velo_tools.map in /media/usb/my-tools — add tools one at a time with: velo_tools.sh add <TOOL> <FILE>
```

Either add each file, naming it yourself:

```bash
$ sudo bash scripts/velo_tools.sh add CatScale /media/usb/my-tools/Cat-Scale.sh
$ sudo bash scripts/velo_tools.sh add OurCollector /media/usb/my-tools/our_collector.exe
```

or write the map once — one line per file, name and file separated by a **TAB**
— and import the folder in one go:

```bash
$ printf 'CatScale\tCat-Scale.sh\nOurCollector\tour_collector.exe\n' \
    > /media/usb/my-tools/velo_tools.map
$ sudo bash scripts/velo_tools.sh import /media/usb/my-tools
```

Take the names from the `list` output, character for character. `OurCollector`
above is an in-house tool no artifact has asked for yet — that works too; the
artifact that uses it just has to name the tool the same way.

### One tool, or a file from a vendor

```bash
sudo bash scripts/velo_tools.sh add CrowdStrikeFalconInstaller /media/usb/falcon.exe
```

`add` takes any name and any file — including a tool no artifact has asked for
yet, and your own in-house binaries. **Copy the tool name exactly** as `list`
prints it; it is how the artifact finds the file, and it often carries a version
(`Hayabusa-2.14.0`). Names are restricted to letters, digits and `. _ + @ -`.

### The same thing in raw VQL

`add` runs this. Use it if you prefer to drive Velociraptor yourself — put the
file in `data/tools/` first (it is mounted into the container, read-only, as
`/tools/`):

```bash
V="docker exec intact_velociraptor /velociraptor/velociraptor --api_config /velociraptor/api.config.yaml"
$V query --format jsonl \
  "SELECT inventory_add(tool='Bulk_Extractor_Binary', serve_locally=TRUE, file='/tools/bulk_extractor.exe', filename='bulk_extractor.exe', accessor='file') AS r FROM scope()"
```

Check it:

```bash
$V query --format jsonl \
  "SELECT name, serve_locally, filename, hash FROM inventory() WHERE name = 'Bulk_Extractor_Binary'"
```

Expect `serve_locally` true, your file name, and a `hash`. Then run the
artifact: the endpoint downloads the tool from the appliance.

Use `--api_config`, not `--config /velociraptor/server.config.yaml`. With
`--config`, `query` runs in a separate local process that sees only the 421
built-in artifacts, not the ~400 curated ones the server loads via
`--definitions`, so a missing-tools list built that way is short.

## Notes

- **Where it is stored.** Registering copies the file into Velociraptor's
  datastore, the Docker volume `velociraptor_velociraptor_datastore`, and records
  the tool there. An upgrade keeps that volume and `data/tools/`. Deleting Docker
  volumes (for example `scripts/clean.sh --volumes`) deletes the registrations —
  re-run `velo_tools.sh import data/tools` to put them back.
- **The map.** `add` and `import` record `TOOL<TAB>FILE` in
  `data/tools/velo_tools.map`. `sudo bash scripts/upgrade.sh --velo-refresh`
  replays it, and falls back to the shipped pattern→name mapping in
  `data/tools_inventory.yaml`, so tools are re-registered under their **names**.
  It used to register every file under its *file* name, which no artifact looks
  up. A file it cannot name is reported, not registered under a guessed name;
  two are expected there on a normal box — `Velociraptor-Artifacts-main.zip`
  (an artifact bundle, not a tool) and the macOS client binary (no artifact asks
  for it).
- **Removing a tool.** `docker exec intact_velociraptor /velociraptor/velociraptor
  --config /velociraptor/server.config.yaml tools rm <TOOL_NAME>` (the `tools`
  subcommands need the server config, not `--api_config`). Delete its line from
  `data/tools/velo_tools.map` too, or the next `--velo-refresh` puts it back.
- **A newer artifact can want a newer tool version** under a different name
  (`Hayabusa-2.14.0` → `Hayabusa-3.8.0`). After importing new artifacts, run
  `velo_tools.sh list` again.
- **`options.download_tools: true`** only makes an install or maintenance run
  **with internet** download the optional tier into `data/tools/` (and register
  it). It does not put those tools into a package, and it does nothing on an
  air-gapped box — that is what the steps above are for.
