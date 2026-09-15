# Velociraptor tools on an air-gapped appliance

Many Velociraptor artifacts run a third-party **tool** on the endpoint: Hayabusa,
Sigcheck, Bulk Extractor, YARA rule files, and so on. Online, Velociraptor
downloads each tool from its internet URL the first time an artifact needs it.
An air-gapped box has no internet, so any tool that is not already stored on the
Velociraptor server makes its artifact **fail when it runs**.

`scripts/velo_tools.sh` puts tools on the server. It holds no list of its own —
it asks the running server what its own artifacts want, and it registers any
file under any name you give it.

Every command below is copy-paste ready and was run on a live appliance.

> Run them as the appliance user (the one that owns `/home/tenroot/intact`), not
> with `sudo`. The tools directory belongs to that user, and a `sudo` run leaves
> root-owned files that later runs cannot rewrite. If your `data/tools` is
> already root-owned, use `sudo` for *every* command instead of mixing the two.

| Command | What it does | Needs internet |
|---|---|---|
| `list` | tools the installed artifacts ask for and the server does not store, with URL and expected hash | no |
| `install <NAME>…` | looks the URL up from the artifact, downloads it, registers it | yes |
| `add <NAME> <FILE>` | registers any file under any name | no |
| `import <DIR>` | registers a carried folder (uses its `velo_tools.map`) | no |
| `fetch <list.tsv> --out <DIR>` | builds a carry folder on a connected machine | yes |
| `status` | what the server stores, and how many are still missing | no |
| `test --tool <NAME>` | makes an **endpoint** download the tool, and says PASS/FAIL | no |
| `selftest` | runs the whole chain and checks every step | yes |

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

## See what is missing

```bash
cd /home/tenroot/intact
bash scripts/velo_tools.sh list | head -20
```

Output — name, download URL, the sha256 the artifact expects (often empty), and
the artifacts that want it:

```
# 79 tool(s) missing
# TOOL	URL	SHA256 the artifact expects (empty = any)	ARTIFACTS (delete rows you do not need)
ChopChopGo	https://github.com/M00NLIG7/ChopChopGo/releases/download/v1.0.0-beta-3/ChopChopGo_v1.0.0-beta-3.zip		Linux.LogAnalysis.ChopChopGo
CapaWindows	https://github.com/mandiant/capa/releases/download/v6.1.0/capa-v6.1.0-windows.zip	070923d5ca225ef2…	Windows.Analysis.Capa
CrowdStrikeFalconInstaller			Custom.Windows.CrowdStrike.FalconInstall
```

**Column 1 is the name that matters.** An artifact asks for `Hayabusa-2.14.0`,
not `hayabusa-2.14.0-win-x64.zip`. A file registered under the wrong name is
accepted by the server and then never found by anything. Copy names exactly;
they may contain letters, digits and `. _ + @ -`.

What the server holds right now:

```bash
cd /home/tenroot/intact
bash scripts/velo_tools.sh status
```

## Route A — the appliance has internet

One tool, by name. Nothing else to look up:

```bash
cd /home/tenroot/intact
bash scripts/velo_tools.sh install Takajo-2.5.0
```

```
Takajo-2.5.0: downloading https://github.com/Yamato-Security/takajo/releases/download/v2.5.0/takajo-2.5.0-win.zip
registered Takajo-2.5.0 -> takajo-2.5.0-win.zip
install: 1 added, 0 failed
```

Several at once:

```bash
cd /home/tenroot/intact
bash scripts/velo_tools.sh install Hayabusa-2.14.0 ChopChopGo DHParser
```

```
install: 3 added, 0 failed
```

## Route B — air-gapped, you already have the files

You downloaded the tools elsewhere and carried the folder over. `import` will not
guess names, so it stops and asks you to name each file:

```bash
cd /home/tenroot/intact
bash scripts/velo_tools.sh import /home/tenroot/my-tools
```

```
ERROR: no velo_tools.map in /home/tenroot/my-tools — add tools one at a time with: velo_tools.sh add <TOOL> <FILE>
```

**Either** name each file as you add it:

```bash
cd /home/tenroot/intact
bash scripts/velo_tools.sh add etl2pcapng /home/tenroot/my-tools/etl2pcapng.zip
```

```
registered etl2pcapng -> etl2pcapng.zip
```

**or** write the folder's map once and import the lot. One line per file: the
tool name, a **TAB**, the file name:

```bash
printf 'etl2pcapng\tetl2pcapng.zip\nBulk_Extractor_Binary\tbulk_extractor.exe\n' \
    > /home/tenroot/my-tools/velo_tools.map

cd /home/tenroot/intact
bash scripts/velo_tools.sh import /home/tenroot/my-tools
```

```
registered etl2pcapng -> etl2pcapng.zip
registered Bulk_Extractor_Binary -> bulk_extractor.exe
import: 2 registered, 0 failed
```

`add` and `import` make no network calls, so both work with the cable pulled, and
re-running either is harmless.

A tool of your own works exactly the same — there is nothing to look up:

```bash
cd /home/tenroot/intact
bash scripts/velo_tools.sh add OurCollector /opt/ours/our_collector.exe
```

Your artifact then asks for `OurCollector`, and endpoints get that file from the
appliance.

## Route C — let the appliance tell you what to carry

**1. On the appliance**, write the list and keep only the rows you want:

```bash
cd /home/tenroot/intact
bash scripts/velo_tools.sh list > /tmp/missing.tsv
grep -E '^Trawler|^DocsIndex' /tmp/missing.tsv > /tmp/want.tsv
```

Copy `/tmp/want.tsv` to a machine with internet.

**2. On that machine** (it needs the repo checkout, `curl` and `python3`):

```bash
bash scripts/velo_tools.sh fetch /tmp/want.tsv --out ~/velo-tools
ls ~/velo-tools
```

```
  fetched Trawler -> Trawler.ps1
fetch: 1 downloaded, 0 without a public URL, 0 failed
carry ~/velo-tools (files + velo_tools.map) to the appliance, then: velo_tools.sh import ~/velo-tools

Trawler.ps1  velo_tools.map
```

`fetch` writes the map for you, so each file lands under its real tool name.
Check each tool's licence before redistributing it to a customer site.

**3. Carry `~/velo-tools` to the appliance** (USB, share, `scp`, whatever the
site allows) and import it:

```bash
cd /home/tenroot/intact
bash scripts/velo_tools.sh import /media/usb/velo-tools
```

```
registered Trawler -> Trawler.ps1
import: 1 registered, 0 failed
```

## A tool with no public download

Vendor installers have no URL in `list`. `install` says so rather than guessing:

```bash
cd /home/tenroot/intact
bash scripts/velo_tools.sh install CrowdStrikeFalconInstaller
```

```
ERROR: no download URL known for 'CrowdStrikeFalconInstaller'
ERROR:   either no artifact asks for it, or it has no public download (a vendor installer).
ERROR:   Get the file yourself, then: velo_tools.sh add CrowdStrikeFalconInstaller <file>
```

Get the file from the vendor, then:

```bash
cd /home/tenroot/intact
bash scripts/velo_tools.sh add CrowdStrikeFalconInstaller /media/usb/falcon.exe
```

## Hashes: why an add can be refused

Some artifacts pin their tool's sha256 — 18 of the missing tools on a clean box
do, including every Hayabusa version, SharpHound, Capa and Sigcheck. A file that
does not match is registered happily by the server and then **refused by the
endpoint**, mid-collection. So `install` and `fetch` check what they downloaded,
and `add`/`import` refuse a mismatch:

```bash
cd /home/tenroot/intact
curl -fL -o /tmp/sigcheck64.exe https://live.sysinternals.com/tools/sigcheck64.exe
bash scripts/velo_tools.sh add sigcheck_amd64 /tmp/sigcheck64.exe
```

```
ERROR: hash mismatch for sigcheck_amd64
ERROR:   the artifact expects: 5d9e06ba65bb4d365e98fbb468f44fa8926f05984bf1a77ec7b1df19c43dc5ef
ERROR:   this file is:         3a081d7ae5a052f5a2fe918c1a9fed11ef7a6686ab2bf51204b5f1f75bf4038e
ERROR:   endpoints would refuse it. Get the pinned version, or re-run with --force.
```

Nothing is copied or registered when that happens. That example is real and
current: Microsoft serves a newer Sigcheck than `Client.Windows.Sigcheck` pins.

To register it anyway — only sensible if you also update the artifact's tool
definition, otherwise endpoints reject it:

```bash
cd /home/tenroot/intact
bash scripts/velo_tools.sh add --force sigcheck_amd64 /tmp/sigcheck64.exe
```

**Which URLs stay put.** A URL under a release tag —
`.../releases/download/v2.5.0/takajo-2.5.0-win.zip` — is fixed forever, which is
why `Hayabusa-2.14.0` and `Takajo-2.5.0` are the examples here: both were
downloaded on 2026-09-15 and matched the hash their artifact pins. A URL that
always serves "the latest" does not, which is exactly the Sigcheck case above.

## Check it works

The whole chain, one command. It picks a missing tool, installs it, and verifies
each step:

```bash
cd /home/tenroot/intact
bash scripts/velo_tools.sh selftest
```

```
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

Step 4 is the one that matters most: it fetches the file back over the
**endpoint-facing URL** and compares the sha256 with what the server recorded. A
step it cannot prove is `SKIP`, never a pass. Add `--tool NAME` to test a
specific one.

With at least one endpoint enrolled, prove the last hop too:

```bash
cd /home/tenroot/intact
bash scripts/velo_tools.sh test --tool etl2pcapng
```

It collects `Generic.Utils.FetchBinary`, the helper every tool-using artifact
calls internally — so nothing forensic runs and nothing is collected off the
machine. It prints the endpoint, flow, flow state and what the endpoint reported,
ending in PASS or FAIL, and on failure the command that shows the flow log. Add
`--client C.xxxx` to choose an endpoint; otherwise the most recently seen one is
used.

## Remove a tool

Two steps, and the second is not optional:

```bash
docker exec intact_velociraptor /velociraptor/velociraptor \
    --config /velociraptor/server.config.yaml tools rm Takajo-2.5.0
docker restart intact_velociraptor
```

Then drop it from the map and the tools directory, or the next `--velo-refresh`
puts it straight back:

```bash
cd /home/tenroot/intact
awk -F'\t' '$1 != "Takajo-2.5.0"' data/tools/velo_tools.map > /tmp/m && mv /tmp/m data/tools/velo_tools.map
rm -f data/tools/takajo-2.5.0-win.zip
```

The `tools` subcommands need the server config, not `--api_config`. `tools rm`
exits 0 while the tool is still served: the running server holds the inventory in
memory and writes it back, so the restart is what makes it stick. Measured on
2026-09-15 — after `rm` the entry still had its hash; only after the restart was
the hash gone.

Check it with the `hash` field, not with `serve_locally`:

```bash
docker exec intact_velociraptor /velociraptor/velociraptor \
    --api_config /velociraptor/api.config.yaml query --format jsonl \
    "SELECT name, serve_locally, hash, url FROM inventory() WHERE name = 'sigcheck_amd64'"
```

```
{"name":"sigcheck_amd64","serve_locally":true,"hash":"","filename":"sigcheck64.exe","url":"https://live.sysinternals.com/tools/sigcheck64.exe"}
```

An empty `hash` means the server no longer holds a copy — the tool is back to
"missing", and `list` shows it again. The name and its URL stay, because an
artifact still declares them; that is the inventory entry, not a stored file.

## The same thing in raw VQL

`add` runs this. Use it if you prefer to drive Velociraptor yourself — put the
file in `data/tools/` first (it is mounted into the container, read-only, as
`/tools/`):

```bash
V="docker exec intact_velociraptor /velociraptor/velociraptor --api_config /velociraptor/api.config.yaml"

$V query --format jsonl \
  "SELECT inventory_add(tool='Bulk_Extractor_Binary', serve_locally=TRUE, file='/tools/bulk_extractor.exe', filename='bulk_extractor.exe', accessor='file') AS r FROM scope()"

$V query --format jsonl \
  "SELECT name, serve_locally, filename, hash FROM inventory() WHERE name = 'Bulk_Extractor_Binary'"
```

```
{"name":"Bulk_Extractor_Binary","serve_locally":true,"filename":"bulk_extractor.exe","hash":"1eade5c20c693cf537e9b0e89ecdcb958e573c4ad45c72b25234041461ca53e0"}
```

Use `--api_config`, not `--config /velociraptor/server.config.yaml`. With
`--config`, `query` runs in a separate local process that sees only the 421
built-in artifacts, not the ~400 curated ones the server loads via
`--definitions`, so a missing-tools list built that way is short.

## Notes

- **Where it is stored.** Registering copies the file into Velociraptor's
  datastore, the Docker volume `velociraptor_velociraptor_datastore`, and records
  the tool there. An upgrade keeps that volume and `data/tools/`. Deleting Docker
  volumes (for example `scripts/clean.sh --volumes`) deletes the registrations.
  Put them all back with:

  ```bash
  cd /home/tenroot/intact
  bash scripts/velo_tools.sh import data/tools
  ```

- **The map.** `add`, `install` and `import` record `TOOL<TAB>FILE` in
  `data/tools/velo_tools.map`. `sudo bash scripts/upgrade.sh --velo-refresh`
  replays it, and falls back to the shipped pattern→name mapping in
  `data/tools_inventory.yaml`, so tools come back under their **names**. It used
  to register every file under its *file* name, which no artifact looks up. A file
  it cannot name is reported, not registered under a guessed name; two are
  expected on a normal box — `Velociraptor-Artifacts-main.zip` (an artifact
  bundle, not a tool) and the macOS client binary (no artifact asks for it).
- **A newer artifact can want a newer tool version** under a different name
  (`Hayabusa-2.14.0` → `Hayabusa-3.9.0`). After importing new artifacts, run
  `bash scripts/velo_tools.sh list` again.
