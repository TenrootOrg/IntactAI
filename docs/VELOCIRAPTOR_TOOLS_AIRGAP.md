# Velociraptor tools on an air-gapped appliance

Many Velociraptor artifacts run a third-party **tool** on the endpoint: Hayabusa,
Sigcheck, Bulk Extractor, YARA rule files, and so on. Online, Velociraptor
downloads each tool from its internet URL the first time an artifact needs it.
An air-gapped box has no internet, so any tool that is not already stored on the
Velociraptor server makes its artifact **fail when it runs**.

`scripts/velo_tools.sh` puts tools on the server. It holds no list of its own —
it asks the running server what its own artifacts want, and it registers any
file under any name you give it.

```bash
cd /home/tenroot/intact

sudo bash scripts/velo_tools.sh list                  # what artifacts want and the box has not got
sudo bash scripts/velo_tools.sh install Takajo-2.5.0  # box has internet: fetch it and register it
sudo bash scripts/velo_tools.sh add OurTool /media/usb/ourtool.exe   # air-gapped, or your own tool
sudo bash scripts/velo_tools.sh status                # what is on the server now
sudo bash scripts/velo_tools.sh selftest              # check the whole thing end to end
```

| Command | What it does | Needs internet |
|---|---|---|
| `list` | tools the installed artifacts ask for and the server does not store, with URL and expected hash | no |
| `install <NAME>…` | looks the URL up from the artifact, downloads, registers | yes |
| `add <NAME> <FILE>` | registers any file under any name | no |
| `import <DIR>` | registers a whole carried folder (uses its `velo_tools.map`) | no |
| `fetch <list.tsv> --out <DIR>` | downloads a carry folder on a connected machine | yes |
| `status` | what the server stores, and how many are still missing | no |
| `test --tool <NAME>` | makes an **endpoint** download the tool, and says PASS/FAIL | no |
| `selftest` | runs the whole chain and checks each step | yes |

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
by name only and pointing at internet URLs — Hayabusa, Sigcheck, FTK Imager,
CatScale, Bulk Extractor, the log4shell scanners, and also:

- `FileYaraWindows` / `FileYaraLinux` / `FileYaraMacOS`, the rule files for
  `DetectRaptor.Generic.Detection.YaraFile`;
- `extsentry`, the feed for `DetectRaptor.Generic.Detection.BrowserExtensions`.

No default blueprint uses these, so a default collection is unaffected — but any
artifact that does use one fails on an air-gapped box until you add the tool. A
box installed or maintained **with internet** may already hold some of them.

The package deliberately carries only the default tools (see
`data/tools_inventory.yaml`: `enabled: true` is the default tier). Setting
`options.download_tools: true` in `config.yaml` does **not** put the optional
tools into a package; it only makes an install or maintenance run **with
internet** download them.

## Adding tools

**The name is the whole point.** An artifact asks for a tool by name —
`Hayabusa-2.14.0`, not `hayabusa-2.14.0-win-x64.zip`. Registering a file under
the wrong name succeeds, reports success, and is never found by anything. Take
names from `list`, column 1, character for character. Names may contain letters,
digits and `. _ + @ -`.

You are not limited to what `list` prints: `add` takes any file under any name,
including a tool of your own that no artifact asks for yet.

### A. The appliance has internet — name the tool

```bash
$ cd /home/tenroot/intact
$ sudo bash scripts/velo_tools.sh install Takajo-2.5.0
Takajo-2.5.0: downloading https://github.com/Yamato-Security/takajo/releases/download/v2.5.0/takajo-2.5.0-win.zip
registered Takajo-2.5.0 -> takajo-2.5.0-win.zip
install: 1 added, 0 failed
```

The URL comes from the artifact that wants the tool, so there is no link to copy
and no file name to guess. Several at once is fine:

```bash
sudo bash scripts/velo_tools.sh install Hayabusa-2.14.0 Takajo-2.5.0 CapaWindows
```

A tool of your own needs no lookup at all:

```bash
$ sudo bash scripts/velo_tools.sh add OurCollector /opt/ours/our_collector.exe
registered OurCollector -> our_collector.exe
```

Your artifact then asks for `OurCollector` and the endpoint gets that file from
the appliance.

### B. Air-gapped — you already have the files

You downloaded the tools on another machine and carried the folder over, say to
`/home/tenroot/my-tools`. `import` will not guess names, so it asks you to name
each file:

```bash
$ sudo bash scripts/velo_tools.sh import /home/tenroot/my-tools
ERROR: no velo_tools.map in /home/tenroot/my-tools — add tools one at a time with: velo_tools.sh add <TOOL> <FILE>
```

Either name each file as you add it:

```bash
$ sudo bash scripts/velo_tools.sh add etl2pcapng /home/tenroot/my-tools/etl2pcapng.zip
registered etl2pcapng -> etl2pcapng.zip
```

or write the folder's map once — one line per file: name, a **TAB**, file name —
and import the whole folder:

```bash
$ printf 'etl2pcapng\tetl2pcapng.zip\nBulk_Extractor_Binary\tbulk_extractor.exe\n' \
    > /home/tenroot/my-tools/velo_tools.map

$ sudo bash scripts/velo_tools.sh import /home/tenroot/my-tools
registered etl2pcapng -> etl2pcapng.zip
registered Bulk_Extractor_Binary -> bulk_extractor.exe
import: 2 registered, 0 failed
```

`import` and `add` make no network calls, so both work with the cable pulled.
Re-running either is harmless.

### C. Let the appliance tell you what to carry

**1. On the appliance**, write the list and cut it down to what you need:

```bash
$ sudo bash scripts/velo_tools.sh list > missing.tsv
# 79 tool(s) missing
$ grep '^CatScale' missing.tsv > want.tsv
```

Columns are: name, URL, the sha256 the artifact expects (often empty), and the
artifacts that want it.

**2. On a machine with internet**, carry `want.tsv` over and download:

```bash
$ bash scripts/velo_tools.sh fetch want.tsv --out ./velo-tools
  fetched CatScale -> Cat-Scale.sh
fetch: 1 downloaded, 0 without a public URL, 0 failed

$ ls velo-tools
Cat-Scale.sh  velo_tools.map
```

`fetch` writes the map for you. Check each tool's licence before redistributing
it to a customer site.

**3. Back on the appliance**, carry the folder over and import it:

```bash
$ sudo bash scripts/velo_tools.sh import /media/usb/velo-tools
registered CatScale -> Cat-Scale.sh
import: 1 registered, 0 failed
```

### A tool with no public download

Some rows in `list` have an empty URL — a vendor installer such as
`CrowdStrikeFalconInstaller`. `install` says so rather than guessing:

```
ERROR: no download URL known for 'CrowdStrikeFalconInstaller'
ERROR:   either no artifact asks for it, or it has no public download (a vendor installer).
ERROR:   Get the file yourself, then: velo_tools.sh add CrowdStrikeFalconInstaller <file>
```

Get the file from the vendor, then add it as in A or B.

## Hashes: why an add can be refused

Some artifacts pin their tool's sha256 — 18 of the missing tools on a clean box
do, including every Hayabusa version, SharpHound, Capa and Sigcheck. A file that
does not match is registered happily by the server and then **refused by the
endpoint**, mid-collection. So `fetch` and `install` check what they downloaded,
and `add`/`import` refuse a mismatch:

```
ERROR: hash mismatch for sigcheck_amd64
ERROR:   the artifact expects: 5d9e06ba65bb4d365e98fbb468f44fa8926f05984bf1a77ec7b1df19c43dc5ef
ERROR:   this file is:         3a081d7ae5a052f5a2fe918c1a9fed11ef7a6686ab2bf51204b5f1f75bf4038e
ERROR:   endpoints would refuse it. Get the pinned version, or re-run with --force.
```

Nothing is copied or registered when that happens.

**Which URLs stay put.** A URL under a release tag —
`.../releases/download/v2.5.0/takajo-2.5.0-win.zip` — is fixed forever, which is
why `Hayabusa-2.14.0` and `Takajo-2.5.0` are the examples here: both were
downloaded on 2026-09-15 and matched the hash their artifact pins. A URL that
always serves "the latest" does not. The Sigcheck mismatch above is real and
current: `https://live.sysinternals.com/tools/sigcheck64.exe` is a newer build
than `Client.Windows.Sigcheck` pins. Either get the pinned build, or update the
artifact's tool definition and use `--force`.

## Checking it works

### The whole chain, one command

```bash
$ cd /home/tenroot/intact
$ sudo bash scripts/velo_tools.sh selftest
1. what the server is missing
   72 tool(s) missing
  PASS  list works
2. install 'Aftermath' by name (download + register)
  PASS  installed Aftermath
3. is it stored on the server?
  PASS  stored as aftermath (06eb4f2f6772…)
4. does the server actually serve those bytes?
  PASS  downloaded from https://192.168.120.11:8000/public/… and the hash matches
5. does an endpoint download it?
  SKIP  no endpoint is enrolled — install a client, then: velo_tools.sh test --tool Aftermath

SUMMARY: 4 pass, 0 fail, 1 skip
```

It picks a missing tool with a public URL, or takes `--tool NAME`. Step 4 is the
one that matters most: it fetches the file back over the **endpoint-facing URL**
and compares the sha256 with what the server recorded. A step it cannot prove is
`SKIP`, never a pass — with no client enrolled, step 5 skips.

### Does an endpoint really get it?

Registering a tool and *serving* it are two different things, and only an
endpoint settles the second. With at least one client enrolled:

```bash
sudo bash scripts/velo_tools.sh test --tool etl2pcapng
```

It collects `Generic.Utils.FetchBinary`, the helper every tool-using artifact
calls internally — so nothing forensic runs and nothing is collected off the
machine. It prints the endpoint, the flow, the flow state and what the endpoint
reported, ending in PASS or FAIL. Add `--client C.xxxx` to choose an endpoint;
otherwise the most recently seen one is used. On failure it prints the command
that shows the flow log.

## The same thing in raw VQL

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

Expect `serve_locally` true, your file name, and a `hash`.

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
- **The map.** `add`, `install` and `import` record `TOOL<TAB>FILE` in
  `data/tools/velo_tools.map`. `sudo bash scripts/upgrade.sh --velo-refresh`
  replays it, and falls back to the shipped pattern→name mapping in
  `data/tools_inventory.yaml`, so tools come back under their **names**. It used
  to register every file under its *file* name, which no artifact looks up. A file
  it cannot name is reported, not registered under a guessed name; two are
  expected on a normal box — `Velociraptor-Artifacts-main.zip` (an artifact
  bundle, not a tool) and the macOS client binary (no artifact asks for it).
- **Removing a tool** takes two steps, and the second is not optional:

  ```bash
  docker exec intact_velociraptor /velociraptor/velociraptor \
      --config /velociraptor/server.config.yaml tools rm <TOOL_NAME>
  docker restart intact_velociraptor
  ```

  The `tools` subcommands need the server config, not `--api_config`. `tools rm`
  exits 0 and the tool is still served until the restart — the running server
  holds the inventory in memory and writes it back. Measured on 2026-09-15: after
  `rm` the entry still had `serve_locally: true` and its hash; after the restart,
  neither. Delete its line from `data/tools/velo_tools.map` and its file from
  `data/tools/` too, or the next `--velo-refresh` puts it straight back.
- **A newer artifact can want a newer tool version** under a different name
  (`Hayabusa-2.14.0` → `Hayabusa-3.9.0`). After importing new artifacts, run
  `velo_tools.sh list` again.
