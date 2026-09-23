# Velociraptor tools on an air-gapped appliance

Many Velociraptor artifacts run a third-party **tool** on the endpoint: Hayabusa,
Sigcheck, Bulk Extractor, YARA rule files. Velociraptor downloads each one from
its internet URL the first time an artifact needs it, so on an air-gapped box a
tool the server does not already hold makes its artifact **fail when it runs**.

The fix is always the same: store the file on the Velociraptor server under the
**name the artifact asks for**. `scripts/velo_tools.sh` does that. It keeps no
list of its own — it asks the running server what its artifacts want.

Every command is safe to run again: nothing is downloaded twice, and re-importing
a folder re-registers the same files rather than duplicating them.

> Run it as the appliance user (the one that owns `/home/tenroot/intact`), not
> with `sudo` — a `sudo` run leaves root-owned files later runs cannot rewrite.

| Command | What it does | Needs internet |
|---|---|---|
| `list` | tools the artifacts want and the server has not got, with URL and expected hash | no |
| `fetch <list.tsv> --out <DIR>` | on a connected machine, builds a folder to carry in | yes |
| `import <DIR>` | registers a carried folder (uses its `velo_tools.map`) | no |
| `add <NAME> <FILE>` | registers any file under any name — your own tools included | no |
| `status` | what the server holds, and how many are still missing | no |
| `selftest` / `test --tool <NAME>` | proves the chain, up to an endpoint downloading the tool | `selftest`: yes |
| `install <NAME>…` | on a connected box: takes the URL from the artifact and registers it | yes |

## What ships, and what does not

An air-gapped install (`install.sh --package …`) registers the tools the
**default blueprints** use, so a default collection works with no internet:
`Autorun_amd64`, `lastactivityview`, `DetectRaptorLolRMM`, plus the Velociraptor
binaries and the offline collector — **7 tools**, measured on a clean install of
`intact-20260903`.

Everything else is **not** included: around 79 more tools that other artifacts
refer to — Hayabusa, Sigcheck, FTK Imager, CatScale, Bulk Extractor, the YARA
rule files for `DetectRaptor.Generic.Detection.YaraFile`, and so on. No default
blueprint uses them, so a default collection is unaffected, but any artifact that
does use one fails until you add the tool. 32-bit Windows also needs
`Autorun_386`, which is not included.

## What this box is missing

```bash
cd /home/tenroot/intact
bash scripts/velo_tools.sh list      # name, URL, expected sha256, artifacts
bash scripts/velo_tools.sh status    # what is already stored
```

**Column 1 of `list` is the name that matters.** An artifact asks for
`Hayabusa-2.14.0`, not `hayabusa-2.14.0-win-x64.zip`. A file registered under the
wrong name is accepted by the server and then never found by anything.

## Getting tools onto an air-gapped appliance

**1. On the appliance**, write the list and keep the rows you want:

```bash
cd /home/tenroot/intact
bash scripts/velo_tools.sh list > /tmp/missing.tsv
grep -E '^Hayabusa-2.14.0|^FileYaraWindows' /tmp/missing.tsv > /tmp/want.tsv
```

Use names from **your** list: those two are examples, and a tool this server
already holds is not in `list` at all. `fetch` refuses a list that matched
nothing rather than sending you off with an empty folder.

**2. On a machine with internet** — it needs the repo checkout, `curl` and
`python3`, no Docker — download them into a folder:

```bash
bash scripts/velo_tools.sh fetch /tmp/want.tsv --out ~/velo-tools
```

`fetch` checks each download against the hash its artifact pins and writes
`velo_tools.map`, so every file lands under its real tool name. Check each tool's
licence before carrying it to a customer site.

**3. Carry the folder in** (USB, share, `scp`) and register it:

```bash
cd /home/tenroot/intact
bash scripts/velo_tools.sh import /media/usb/velo-tools
```

`import` makes no network calls. It registers what the map names, and reports any
file in the folder the map does not name — a folder reused between trips keeps
its old map, and a new file dropped into it must not be skipped in silence. A map
line written with spaces instead of a TAB is an error, not a skipped line.

## Your own tools, and vendor binaries

Anything you have as a file — your own collector, a vendor installer with no
public download (CrowdStrike, ESET), a tool you fetched by hand — is registered
by name, with no list to be on and no internet:

```bash
cd /home/tenroot/intact
bash scripts/velo_tools.sh add OurCollector /opt/ours/our_collector.exe
bash scripts/velo_tools.sh add CrowdStrikeFalconInstaller /media/usb/falcon.exe
```

Your artifact then asks for `OurCollector` and endpoints get that file from the
appliance. (`install` refuses a tool with no public URL rather than guessing, and
says to use `add`.)

Registrations are recorded in `data/tools/velo_tools.map`, which
`sudo bash scripts/upgrade.sh --velo-refresh` replays, so a tool of your own
survives an upgrade under its name.

## Hashes: why an add can be refused

Some artifacts pin their tool's sha256 — including every Hayabusa version,
SharpHound, Capa and Sigcheck. A file that does not match is stored happily by
the server and then **refused by the endpoint**, mid-collection, at the customer
site. So `fetch` and `install` check what they downloaded, and `add` / `import`
refuse a mismatch and register nothing.

This is real and current: Microsoft serves a newer Sigcheck than
`Client.Windows.Sigcheck` pins, so adding today's `sigcheck64.exe` is refused.
`--force` registers it anyway, which only makes sense if you also update the
artifact's tool definition.

A URL under a release tag (`…/releases/download/v2.5.0/…`) keeps serving the same
file; a "latest" URL does not — which is exactly the Sigcheck case.

## Check it works

```bash
cd /home/tenroot/intact
bash scripts/velo_tools.sh test --tool etl2pcapng   # air-gapped: the endpoint hop
bash scripts/velo_tools.sh selftest                 # connected box: the whole chain
```

`test --tool` collects `Generic.Utils.FetchBinary`, the helper every tool-using
artifact calls, so nothing forensic runs and nothing is collected off the machine.
It prints the endpoint, flow and result, ending in PASS or FAIL. Add
`--client C.xxxx` to choose an endpoint; otherwise the most recently seen one is
used.

An endpoint that has not been seen for a while is **offline**: the collection
would just queue until it comes back, so the test says SKIP and exits 2 rather
than reporting a failure of the tool. Enrolled-but-stale clients (an imported
dataset, a lab that was shut down) are the usual reason.

`selftest` installs a missing tool and checks each step — the one that matters
most fetches the file back over the **endpoint-facing URL** and compares the
sha256 with what the server recorded. A step it cannot prove is `SKIP`, never a
pass.

## On a connected box

One command per tool, URL and hash taken from the artifact itself. A tool the
server already holds is skipped, so this is cheap to re-run:

```bash
cd /home/tenroot/intact
bash scripts/velo_tools.sh install Hayabusa-2.14.0 Takajo-2.5.0
```

The platform also has a bulk downloader (`options.download_tools: true` in
`config.yaml`, then
`docker exec intact_backend curl -s -X POST http://127.0.0.1:5001/api/maintenance/download-tools`),
which also runs on every install and maintenance run. Prefer `install`: the bulk
path knows only the 26 tools listed in `data/tools_inventory.yaml`, and it does
not check the hash an artifact pins, so a moved URL registers a file endpoints
will refuse.

A release package built on a connected box carries its tools with it, so a site
that already transports packages needs no second transfer: a stock package
carries the default tier, and with `download_tools: true` the optional tier too.
`install.sh --package …` stages and registers them.

## Remove a tool

Two steps, and the restart is not optional — the running server holds the
inventory in memory and writes it back, so without it the tool is still served:

```bash
docker exec intact_velociraptor /velociraptor/velociraptor \
    --config /velociraptor/server.config.yaml tools rm Takajo-2.5.0
docker restart intact_velociraptor

cd /home/tenroot/intact
awk -F'\t' '$1 != "Takajo-2.5.0"' data/tools/velo_tools.map > /tmp/m && mv /tmp/m data/tools/velo_tools.map
rm -f data/tools/takajo-2.5.0-win.zip
```

Drop it from the map and `data/tools/` as well, or the next `--velo-refresh` puts
it straight back. Judge the result by the `hash` field of `inventory()`, not by
`serve_locally`: an empty hash means the server no longer holds a copy.

## Notes

- **Where it is stored.** Registering copies the file into Velociraptor's
  datastore (the Docker volume `velociraptor_velociraptor_datastore`). An upgrade
  keeps that volume and `data/tools/`; deleting Docker volumes (for example
  `scripts/clean.sh --volumes`) deletes the registrations. Put them all back with
  `bash scripts/velo_tools.sh import data/tools`. That names files from
  `velo_tools.map` first and from the shipped `data/tools_inventory.yaml` after,
  so the installer's own tools come back too; anything neither can name is
  reported rather than registered under a guessed name.
- **A newer artifact can want a newer tool version** under a different name
  (`Hayabusa-2.14.0` → `Hayabusa-3.9.0`). After importing artifacts, run `list`
  again.
- **The `tools` subcommands need `--config`** (the server config) while `query`
  needs `--api_config`: with `--config`, `query` sees only the built-in artifacts,
  so a missing-tools list built that way is far too short.

## What has been verified

Every command here was run on a live appliance: `list`, `status`, `install` (one
name, several names, and a re-run that downloads nothing), `add`, `add --force`,
`import` with a map, without a map and with a stale map, `fetch` (including twice
into the same folder), the refusals (no public URL, pinned-hash mismatch, invalid
name), `selftest`, removal (`tools rm` + restart) and the `--velo-refresh` tool
replay. A registered tool was downloaded back over its endpoint-facing URL and the
sha256 matched.

Not yet proven: an **endpoint** downloading a tool (no client was enrolled, so
`selftest` reports that step as SKIP), a full optional-tier bulk download, and
`fetch` run on a separate laptop rather than on the appliance.
