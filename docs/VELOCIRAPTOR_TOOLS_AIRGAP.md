# Velociraptor tools on an air-gapped appliance

Many Velociraptor artifacts run a third-party **tool** on the endpoint: Hayabusa,
Sigcheck, Bulk Extractor, YARA rule files, and so on. Online, Velociraptor
downloads each tool from its internet URL the first time an artifact needs it.
An air-gapped box has no internet, so any tool that is not already stored on the
Velociraptor server makes its artifact **fail when it runs**.

This page says which tools an air-gapped install already has, and how to add the
rest by hand.

## What is already inside, and configured

An air-gapped install (`install.sh --package …`) ships and registers the tools the
**default blueprints** use. They are stored on the Velociraptor server and served
to endpoints from it, so they work with no internet:

| Tool name | File |
|---|---|
| `Autorun_amd64` | `autorunsc64.exe` |
| `lastactivityview` | `lastactivityview.zip` |
| `DetectRaptorLolRMM` | `lolrmm.csv` |
| `FileYaraWindows` / `FileYaraLinux` / `FileYaraMacOS` | `full_*_file.yar.gz` |
| `extsentry` | `extsentry_feed.json` |
| `VelociraptorWindows`, `VelociraptorWindowsMSI`, `VelociraptorLinux`, `VelociraptorCollector` | the Velociraptor binaries and the offline collector |

Measured on an `intact-20260825` appliance: 12 tools ready offline.

## What is not inside

Everything else. The same appliance had **78** more tools registered by name
only, pointing at internet URLs — Hayabusa, Sigcheck, FTK Imager, CatScale,
Bulk Extractor, ThorZIP, the log4shell scanners, and others. The artifacts that
use them fail on an air-gapped box until you add the tool yourself.

The package deliberately carries only the default tools (see
`data/tools_inventory.yaml`: `enabled: true` is the default tier). Setting
`options.download_tools: true` in `config.yaml` does **not** put the optional
tools into a package; it only makes an install or maintenance run **with
internet** download them.

## Add a tool by hand

All commands run on the appliance, from the Intact folder (the one holding
`install.sh`). `V` is a shortcut for the Velociraptor binary inside its
container:

```bash
V="docker exec intact_velociraptor /velociraptor/velociraptor --config /velociraptor/server.config.yaml"
```

### 1. List the tools that are missing (on the appliance)

```bash
$V query --format jsonl \
  "LET offline <= SELECT name FROM inventory() WHERE serve_locally AND hash" \
  "SELECT * FROM foreach(row={SELECT name AS ArtifactName, tools FROM artifact_definitions() WHERE tools}, query={SELECT name AS Tool, url AS Url, ArtifactName FROM foreach(row=tools) WHERE NOT name IN offline.name}) ORDER BY Tool" \
  > missing_tools.jsonl
```

Each line names a tool, the URL to download it from, and the artifact that needs
it:

```json
{"Tool":"Bulk_Extractor_Binary","Url":"https://github.com/Velocidex/Tools/raw/main/BulkExtractor/bulk_extractor.exe","ArtifactName":"Windows.Forensics.BulkExtractor"}
```

You only need the tools for the artifacts you intend to run. **Copy the `Tool`
value exactly**; it is how the artifact finds the file, and it often carries a
version (`Hayabusa-2.14.0`).

A tool with an empty `Url` (for example a vendor installer such as
`CrowdStrikeFalconInstaller`) has no public download; get the file from the
vendor.

To see every tool the server knows about that is not stored yet, including tools
from imported artifact packs:

```bash
$V query --format jsonl "SELECT name FROM inventory() WHERE NOT serve_locally OR NOT hash"
```

### 2. Download the files (on a machine with internet)

Carry `missing_tools.jsonl` across and download each `Url`. Keep the file name
from the end of the URL. Check the licence of each tool before redistributing it
to a customer site.

### 3. Copy the files onto the appliance

```bash
sudo cp /media/usb/bulk_extractor.exe data/tools/
sudo chmod 644 data/tools/bulk_extractor.exe
```

`data/tools/` is mounted into the Velociraptor container, read-only, as `/tools/`.
The file must be there before you register it.

### 4. Register the tool under its exact name

```bash
$V query --format jsonl \
  "SELECT inventory_add(tool='Bulk_Extractor_Binary', serve_locally=TRUE, file='/tools/bulk_extractor.exe', accessor='file') AS r FROM scope()"
```

- `tool=` is the `Tool` value from step 1, character for character.
- `file=` is the file under `/tools/`.
- `serve_locally=TRUE` makes endpoints fetch it from this server, not the internet.

Running it again with the same file is harmless: the stored copy and its hash stay
the same.

Several tools at once, from a two-column list of `TOOL FILE`:

```bash
while read -r tool file; do
  [[ -z "$tool" || "$tool" == \#* ]] && continue
  $V query --format jsonl \
    "SELECT inventory_add(tool='${tool}', serve_locally=TRUE, file='/tools/${file}', accessor='file') AS r FROM scope()" \
    >/dev/null && echo "registered ${tool}" || echo "FAILED ${tool}"
done < tools_to_register.txt
```

### 5. Check it

```bash
$V tools show Bulk_Extractor_Binary
```

Expect `serve_locally: true`, your file name, and a `hash`:

```
name: Bulk_Extractor_Binary
serve_locally: true
filename: bulk_extractor.exe
hash: <sha256 of the file>
```

Then run the artifact. The endpoint downloads the tool from the appliance.

## Notes

- **Where it is stored.** Step 4 copies the file into Velociraptor's datastore, the
  Docker volume `velociraptor_velociraptor_datastore`, and records the tool there.
  An upgrade keeps that volume and `data/tools/`. Deleting Docker volumes (for
  example `scripts/clean.sh --volumes`) deletes the registrations: repeat step 4.
- **Use the tool name, not the file name.** `sudo bash scripts/upgrade.sh
  --velo-refresh` re-registers every file in `data/tools/`, but under its *file*
  name (`bulk_extractor.exe`), which no artifact looks for. It does not replace
  step 4.
- **A newer artifact can want a newer tool version** under a different name
  (`Hayabusa-2.14.0` → `Hayabusa-3.8.0`). After importing new artifacts, run step 1
  again.
