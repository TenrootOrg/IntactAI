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

**Any file, under any name.** The `list` command is a convenience — it tells you
what the installed artifacts are asking for — but you are not limited to it.
`add` registers whatever file you point it at, under whatever name you give:
a tool from a vendor, a newer build than the artifact expects, a script of your
own that no artifact uses yet. The name is simply what an artifact must ask for
to get that file.

Three ways in, depending on where the files are:

- **A — the appliance itself has internet.** Download and add, on the box, two
  commands.
- **B — you already have the files.** Carry the folder onto the box and register
  them. No internet at any point.
- **C — let the script tell you what is missing**, download it on a machine that
  has internet, and carry that folder over.

### A. The appliance has internet — download and add

```bash
$ cd /home/tenroot/intact
$ bash scripts/velo_tools.sh list | grep Hayabusa
Hayabusa-2.14.0   https://github.com/Yamato-Security/hayabusa/releases/download/v2.14.0/hayabusa-2.14.0-win-x64.zip   de8abff4f6ed35f2...

$ curl -fL -o /tmp/hayabusa.zip https://github.com/Yamato-Security/hayabusa/releases/download/v2.14.0/hayabusa-2.14.0-win-x64.zip
$ sudo bash scripts/velo_tools.sh add Hayabusa-2.14.0 /tmp/hayabusa.zip
registered Hayabusa-2.14.0 -> hayabusa.zip
```

A tool of your own works the same way — there is nothing to look up:

```bash
$ sudo bash scripts/velo_tools.sh add OurCollector /opt/ours/our_collector.exe
```

Your artifact then asks for `OurCollector`, and the endpoint gets that file from
the appliance.


### B. You already have the files — carry the folder in

The common case: you downloaded the tools on your own machine, put them on a
USB stick, and moved the folder onto the appliance. Real output, on a box with
`etl2pcapng.zip` and `bulk_extractor.exe` in `/home/tenroot/my-tools`.

`import` will not guess names. A tool registered under the wrong name — its file
name, say — is accepted by the server and then never found by any artifact, so
the script asks you to name each file instead:

```bash
$ sudo bash scripts/velo_tools.sh import /home/tenroot/my-tools
ERROR: no velo_tools.map in /home/tenroot/my-tools — add tools one at a time with: velo_tools.sh add <TOOL> <FILE>
```

**Either name each file as you add it:**

```bash
$ sudo bash scripts/velo_tools.sh add etl2pcapng /home/tenroot/my-tools/etl2pcapng.zip
registered etl2pcapng -> etl2pcapng.zip
```

**or write the folder's map once and import the whole folder.** One line per
file: the tool name, a **TAB**, the file name.

```bash
$ printf 'etl2pcapng\tetl2pcapng.zip\nBulk_Extractor_Binary\tbulk_extractor.exe\n' \
    > /home/tenroot/my-tools/velo_tools.map

$ sudo bash scripts/velo_tools.sh import /home/tenroot/my-tools
registered etl2pcapng -> etl2pcapng.zip
registered Bulk_Extractor_Binary -> bulk_extractor.exe
import: 2 registered, 0 failed

$ sudo bash scripts/velo_tools.sh status
  ...
  (12 tool(s))
Missing (an artifact wants them, this server has not got them): 74
```

Done — no internet was used, and the tools are now served to endpoints from the
appliance.

**Where do the names come from?** `velo_tools.sh list` prints the exact name each
artifact asks for (see B below). Copy it character for character; it often carries
a version, such as `Hayabusa-2.14.0`. A tool of your own that no artifact uses yet
works the same way — just name it the same in your artifact. Names may contain
letters, digits and `. _ + @ -`.

### C. Let the script find and download them

Use this when the appliance can tell you what it is missing and another machine
has internet.

**1. On the appliance — what is missing**

```bash
sudo bash scripts/velo_tools.sh list > missing.tsv
```

One row per tool: the exact tool name, its download URL, the sha256 the artifact
expects (often empty), and the artifacts that want it. Delete the rows you do not
need — you only need tools for the artifacts you intend to run.

```
TOOL             URL                                                SHA256 the artifact expects   ARTIFACTS
Autorun_386      https://live.sysinternals.com/tools/autorunsc.exe                                Windows.Sysinternals.Autoruns
Hayabusa-2.14.0  https://github.com/.../hayabusa-2.14.0-win-x64.zip de8abff4f6ed35f2...           Exchange.Windows.EventLogs.Hayabusa.Takajo
```

A row with an empty URL (a vendor installer such as `CrowdStrikeFalconInstaller`)
has no public download; get that file from the vendor and add it as in A.

**2. On a machine WITH internet — download them**

```bash
$ bash scripts/velo_tools.sh fetch want.tsv --out ./velo-tools
  fetched CatScale -> Cat-Scale.sh
fetch: 1 downloaded, 0 without a public URL, 0 failed

$ ls velo-tools
Cat-Scale.sh  velo_tools.map
```

`fetch` writes the `velo_tools.map` for you, so the files land under their real
tool names on the other side. Check each tool's licence before redistributing it
to a customer site.

**3. Back on the appliance — import the folder**

```bash
$ sudo bash scripts/velo_tools.sh import /media/usb/velo-tools
registered CatScale -> Cat-Scale.sh
import: 1 registered, 0 failed
```

`import` makes **no** network calls, so it works with the cable pulled, and
re-running it is harmless.

### Hashes: why an add can be refused

Some artifacts pin their tool's sha256 — 18 of the missing tools on a clean box
do, including every Hayabusa version, SharpHound, Capa and Sigcheck. A file that
does not match is registered happily by the server and then **refused by the
endpoint**, mid-collection. So `fetch` checks what it downloaded, and
`add`/`import` refuse a mismatch:

```
ERROR: hash mismatch for Hayabusa-2.14.0
ERROR:   the artifact expects: de8abff4f6ed35f28e1e2897659e4f7adcca13ef84d2764afa786ca3f60224ec
ERROR:   this file is:         7d94206ac5c5d68cae535916fe92ba86f963e459633233ff8faf6b361a959d90
ERROR:   endpoints would refuse it. Get the pinned version, or re-run with --force.
```

Nothing is copied or registered when that happens. If the download URL has moved
on to a newer release, get the pinned version instead — or, if you mean to run a
different version, update the artifact's tool definition and use `--force`.

### Check an endpoint really gets it

Registering a tool and *serving* it are two different things, and only an
endpoint settles the second. With at least one client enrolled:

```bash
$ sudo bash scripts/velo_tools.sh test --tool etl2pcapng
endpoint : C.1234567890abcdef
tool     : etl2pcapng
flow     : F.CV9K2M7QJ4R8T
state    : FINISHED (after 6s)
endpoint reported:
{"Binary":"C:\\Windows\\Temp\\etl2pcapng.zip","Hash":"..."}
PASS — the endpoint downloaded 'etl2pcapng' from this appliance, no internet needed
```

It collects `Generic.Utils.FetchBinary`, the helper every tool-using artifact
calls internally — so nothing forensic runs and nothing is collected off the
machine. Add `--client C.xxxx` to pick an endpoint; without it the most recently
seen one is used. On failure it prints the flow state and the command that shows
the flow log.

### A tool with no public download

Some rows in `list` have an empty URL — a vendor installer such as
`CrowdStrikeFalconInstaller`. Get the file from the vendor, then add it exactly
as in A or B:

```bash
sudo bash scripts/velo_tools.sh add CrowdStrikeFalconInstaller /media/usb/falcon.exe
```

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
- **Removing a tool** takes two steps, and the second is not optional:

  ```bash
  docker exec intact_velociraptor /velociraptor/velociraptor \
      --config /velociraptor/server.config.yaml tools rm <TOOL_NAME>
  docker restart intact_velociraptor
  ```

  The `tools` subcommands need the server config, not `--api_config`. `tools rm`
  exits 0 and the tool is still served until the restart — the running server
  holds the inventory in memory and writes it back. Verified on 2026-09-15:
  after `rm` the tool still had `serve_locally: true` and its hash; after the
  restart, `serve_locally: false` and no hash. Delete its line from
  `data/tools/velo_tools.map` too (and the file from `data/tools/`), or the next
  `--velo-refresh` puts it straight back.
- **A newer artifact can want a newer tool version** under a different name
  (`Hayabusa-2.14.0` → `Hayabusa-3.8.0`). After importing new artifacts, run
  `velo_tools.sh list` again.
- **`options.download_tools: true`** only makes an install or maintenance run
  **with internet** download the optional tier into `data/tools/` (and register
  it). It does not put those tools into a package, and it does nothing on an
  air-gapped box — that is what the steps above are for.
