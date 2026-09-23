# Velociraptor tools on an air-gapped appliance

Many artifacts run a third-party **tool** on the endpoint (Hayabusa, Sigcheck,
YARA rule files). Velociraptor downloads each one from the internet the first time
it is needed, so on an air-gapped box a tool the server does not hold makes its
artifact **fail when it runs**. The fix is always to store the file on the server
under the **name the artifact asks for** — `Hayabusa-2.14.0`, not
`hayabusa-2.14.0-win-x64.zip`.

`scripts/velo_tools.sh` does that. It asks the running server what its artifacts
want, so it needs no list of its own, and every command is safe to run twice.

| Command | What it does | Internet |
|---|---|---|
| `list` | tools the artifacts want and the server has not got | no |
| `status` | what the server holds, and how many are missing | no |
| `fetch <list> --out <dir>` | on a connected machine: downloads a folder to carry in | yes |
| `import <dir>` | registers a carried folder | no |
| `add <NAME> <FILE>` | registers any file under any name | no |
| `install <NAME>…` | downloads one tool by name and registers it | yes |
| `test --tool <NAME>` | makes an endpoint download it, PASS/FAIL | no |
| `selftest` | runs the whole chain and checks every step | yes |

**What ships:** an air-gapped install registers the 7 tools the default blueprints
use (Autoruns, LastActivityView, lolrmm, the Velociraptor binaries and collector),
so a default collection works offline. **What does not:** ~79 other tools that
other artifacts refer to; any artifact using one fails until you add it.

## See what is missing

```bash
cd /home/tenroot/intact
bash scripts/velo_tools.sh list
bash scripts/velo_tools.sh status
```

## Carry tools to an air-gapped box

Write the list, keeping the rows you want:

```bash
cd /home/tenroot/intact
bash scripts/velo_tools.sh list > /tmp/missing.tsv
awk -F'\t' 'NR>2 && $2 ~ /releases\/download/ {print; n++} n==5 {exit}' /tmp/missing.tsv > /tmp/want.tsv
cut -f1 /tmp/want.tsv        # what you are about to carry
```

(That filter takes the first five whose URL is a pinned release download. A
vendor's "latest" link often 404s or serves a newer build than the artifact
expects, and `fetch` refuses those — it tells you which and carries the rest.)

Download them where there is internet. `fetch` checks each file against the hash
its artifact pins and writes `velo_tools.map`, so every file lands under its real
tool name:

```bash
cd /home/tenroot/intact     # on another machine: cd to your checkout of this repo
bash scripts/velo_tools.sh fetch /tmp/want.tsv --out ~/velo-tools
```

Carry the folder over and register it. `import` names what the map names and
reports any file it cannot name rather than guessing:

```bash
cd /home/tenroot/intact
bash scripts/velo_tools.sh import ~/velo-tools     # or /media/usb/velo-tools
```

## Your own tools and vendor binaries

Any file, any name, no internet and no list to be on — also the route for a
vendor installer with no public download:

```bash
cd /home/tenroot/intact
bash scripts/velo_tools.sh add OurCollector <path-to>/our_collector.exe
```

Your artifact then asks for `OurCollector` and endpoints get it from the
appliance. Registrations are recorded in `data/tools/velo_tools.map`, which
`sudo bash scripts/upgrade.sh --velo-refresh` replays, so your tool survives an
upgrade under its name.

## Hashes

Some artifacts pin their tool's sha256. A file that does not match is stored
happily by the server and then **refused by the endpoint**, mid-collection — so
`fetch`, `install`, `add` and `import` check it and refuse instead. `--force`
registers anyway, which only makes sense if you also update the artifact.

## Check it works

```bash
cd /home/tenroot/intact
bash scripts/velo_tools.sh test --tool etl2pcapng
bash scripts/velo_tools.sh selftest
```

`test --tool` collects `Generic.Utils.FetchBinary` on an endpoint: nothing
forensic runs, and it ends in PASS or FAIL. An endpoint not seen for a while is
offline, so it says SKIP and exits 2 instead of blaming the tool.

`selftest` installs a missing tool and proves each step, including fetching the
file back over the endpoint-facing URL. A step it cannot prove is SKIP, never a
pass.

## On a connected box

```bash
cd /home/tenroot/intact
bash scripts/velo_tools.sh install Hayabusa-2.14.0 Takajo-2.5.0
```

A tool already stored is skipped. There is also a bulk downloader
(`options.download_tools: true`, then `POST /api/maintenance/download-tools` on
the backend), but prefer `install`: the bulk path knows only the tools listed in
`data/tools_inventory.yaml` and does not check pinned hashes.

## Doing it by hand, in VQL

`velo_tools.sh` wraps these. Put the file in `data/tools/` first — that directory
is mounted into the container read-only as `/tools/`.

```bash
V="docker exec intact_velociraptor /velociraptor/velociraptor --api_config /velociraptor/api.config.yaml"

# register a tool
$V query --format jsonl "SELECT inventory_add(tool='Bulk_Extractor_Binary', serve_locally=TRUE, file='/tools/bulk_extractor.exe', filename='bulk_extractor.exe', accessor='file') AS r FROM scope()"

# what the server holds
$V query --format jsonl "SELECT name, filename, hash, serve_url FROM inventory() WHERE serve_locally AND hash"

# which tools the artifacts want
$V query --format jsonl "SELECT * FROM foreach(row={SELECT name AS Artifact, tools FROM artifact_definitions() WHERE tools}, query={SELECT name AS Tool, url AS Url, expected_hash AS Expected, Artifact FROM foreach(row=tools)})"
```

Use `--api_config`. With `--config server.config.yaml`, `query` starts a second
local Velociraptor: it sees only the built-in artifacts, and anything it writes is
discarded when the running server saves its own copy.

## Remove a tool

The restart is not optional — the running server holds the inventory in memory and
writes it back:

```bash
docker exec intact_velociraptor /velociraptor/velociraptor \
    --config /velociraptor/server.config.yaml tools rm Takajo-2.5.0
docker restart intact_velociraptor

cd /home/tenroot/intact
awk -F'\t' '$1 != "Takajo-2.5.0"' data/tools/velo_tools.map > /tmp/m && mv /tmp/m data/tools/velo_tools.map
rm -f data/tools/takajo-2.5.0-win.zip
```

Drop it from the map and `data/tools/` too, or the next `--velo-refresh` puts it
back. Judge the result by `hash` in `inventory()`, not by `serve_locally`: an empty
hash means the server holds no copy. (`tools rm` needs `--config`, not
`--api_config`.)

## Notes

- Registering copies the file into Velociraptor's datastore volume. An upgrade
  keeps it; deleting Docker volumes (`scripts/clean.sh --volumes`) does not — put
  everything back with `bash scripts/velo_tools.sh import data/tools`.
- A newer artifact can want a newer tool version under a different name
  (`Hayabusa-2.14.0` → `Hayabusa-3.9.0`). After importing artifacts, run `list`
  again.
- Every command here was run on a live appliance, except an endpoint actually
  downloading a tool: the test box has no live client, so that step reports SKIP.
