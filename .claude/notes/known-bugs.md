# Known bugs — triage later

## Velociraptor: legacy version disabled after upgrade/offline-install

**Symptom**
After running an upgrade (or offline install) of the Velociraptor
module, the LEGACY Velociraptor binary support gets disabled —
clients running older Win7 / Server 2008 R2 OSes can no longer be
generated as offline collectors or repacked from the live-client
path.

**Where to start looking**
- `lib/modules.sh:download_legacy_velociraptor_binaries`
  (the install.sh path that fetches velociraptor_legacy=0.7.1 binaries)
- `modules/backend/services/upgrade/velociraptor.py`
  (upgrade_velociraptor_offline + install_velociraptor_offline —
  probably overwrites the staged-binaries directory and wipes the
  legacy binaries put there by install.sh)
- `modules/nginx/html/downloads/velociraptor-v0.7.1-*` paths
  (where install.sh stages the legacy binaries for the
  offline-collector + live-client repack flows)
- `config.yaml: versions.velociraptor_legacy` (currently `'0.7.1'`)

**Likely root cause hypothesis**
upgrade_velociraptor_offline bumps the VELOCIRAPTOR_VERSION and
recreates the container, but the LEGACY binaries (separate pin,
separate filenames like `velociraptor-v0.7.1-linux-amd64`) live in
the same nginx/downloads directory that the upgrade may clean up
or fail to repopulate. install.sh has a dedicated
`download_legacy_velociraptor_binaries` step; the upgrade path
probably doesn't run an equivalent.

**Reported by user** 2026-06-09 session — alongside the
fresh-install Timesketch fixes (see commits 7c27d2a, a093f20, the
in-flight timesketch user-creation patch).

---

## Velociraptor: config-schema mismatch when downgrading on retained volume

**Symptom**
After installing Velociraptor 0.74.3 on a host where 0.76.x
previously ran, the container crash-loops with:

    velociraptor: error: user add: Unable to load config file:
      yaml: unmarshal errors:
        line 223: field compression not found in type proto.DatastoreConfig
        line 242: field security not found in type proto.Config
    Creating admin user: tenroot
    [repeats — restart count climbs]

The 0.76.x entrypoint wrote `server.config.yaml` with newer schema
fields (`Datastore.compression`, top-level `security`) that the
0.74.3 binary's protobuf doesn't recognize. The retained
`velociraptor_data` docker volume carries the old YAML; the 0.74.3
entrypoint's "regenerate if missing" check sees the file exists
and uses it as-is.

**Where to start looking**
- `modules/velociraptor/Dockerfile` and the upstream entrypoint
  script that runs `velociraptor config generate` — check whether
  it has a "regenerate when fields don't match" branch (it
  doesn't, today)
- `modules/backend/services/upgrade/velociraptor.py:install_velociraptor_offline`
  — could add a pre-install step that wipes the volume's
  `server.config.yaml` if the installed version is a downgrade
- `modules/velociraptor/docker-compose.yaml` — volume mount
  `velociraptor_data:/velociraptor` is what persists the config

**Why this isn't blocking for fresh targets**
On a host that's never run Velociraptor before, the volume is
empty, the entrypoint generates a fresh config matching the
binary's schema, and the install works. The bug ONLY appears on
hosts that previously had a newer Velociraptor and are now being
"downgraded" via an offline package targeting an older version.

**Air-gap install code path itself is fine.** The install reports
success because the polling probe (`test -f
/velociraptor/client.config.yaml`) passes — the file exists, just
not in a shape the binary can parse. The probe should also check
container stability (`docker inspect ... .State.Status == running`
and `RestartCount` not climbing) before declaring success.

**Reported by user** 2026-06-09 session — surfaced during the
final air-gap apply test of the 5-module transport package after
the `--pull never` fix (commit 59d6c37).

---

## Detection-content gaps: high-signal actions invisible to Case Analysis

**Symptom**
Attacker techniques, run and COLLECTED on a lab Win11 host, surface no finding in
Case Analysis — not a weighting problem, a missing-detection problem.

- **Defender exclusion / disable (T1562.001).** FIXED (commit 55770240): new
  artifact Custom.Windows.Detection.DefenderExclusions reads the live Defender
  config via WMI; the mapper surfaces an exclusion (medium) / disabled RTP (high).
  Validated end-to-end on the live VM. The notes below are kept for the record.
- **Archive/staging of loot (`Compress-Archive` → zip, T1560.001). RESOLVED
  2026-10-11 (commit 60b29f22).** The evidence IS collected — DetectRaptor's
  "Suspicious Location" MFT rule flags the archive (a high `mft_detection` event),
  but it also fires on benign backups/installers/cloud-sync, so a standalone rule
  floods. Fix: `correlate._staging_archive_findings` promotes a staging-path
  archive to a T1560.001 finding ONLY when another high/coordinated finding hit
  the same host within the hour — co-occurrence is the tight signal the lone MFT
  row (no process lineage) lacks. Validated live: sim-E surfaces; baseline +
  benign stress stay 0. A lone archive stays a quiet timeline event.
- **DLL side-loading (T1574.002).** Still open. Stock Win11 logs no DLL loads
  (needs Sysmon EID 7), and the planted pair isn't in HijackLibs' known-abused
  set — so there is no load event to detect. A fusion rule can't synthesize one;
  the same staging-corroboration trick only helps if the DLL lands in a
  world-writable path (then "Suspicious Location" flags it). True side-load (DLL
  beside a signed exe in its install dir) needs the HijackLibs pair added or
  Sysmon module-load collection — a telemetry/signature fix, not fusion.

**Why it is NOT a fusion/weighting fix (proven 2026-10-08)**
Tried a mapper re-titling heuristic (scan the generic-heuristic rows' scriptblock
for `Add-MpPreference ... -Exclusion`) and REVERTED it, because the collected data
cannot carry the signal reliably:
  1. The PowerShell 4104 event logs the AUTO-GENERATED cmdletization MODULE for
     `root\Microsoft\Windows\Defender\MSFT_MpPreference` (identical for Get-/
     Set-/Add-/Remove-MpPreference), split across ~20 scriptblock chunks — not the
     literal `Add-MpPreference -ExclusionPath "..."` invocation. "Add-MpPreference"
     and "-ExclusionPath" never co-occur matchably, and the module defines Add/Set/
     Remove/Get all, so any match that fires would also fire on a benign READ.
  2. The RELIABLE signal, Microsoft-Windows-Windows Defender/Operational EventID
     5007 ("configuration changed / exclusion added"), is NOT COLLECTED. The
     collection only carries channels: PowerShell/Operational, Security, System,
     Windows PowerShell (verified in the chain01 capture).

**The real fix (collection-time, needs a live run to validate)**
Add the Windows Defender Operational channel (EID 5007/5001/1116...) to the
Velociraptor collection (the agentic QuickWins blueprint / the EVTX artifact), and
a SIGMA/Hayabusa rule mapping 5007 -> T1562.001. Same shape for archive-staging:
needs process-command-line logging (Sysmon EID 1) or a dedicated artifact.

**Archive-staging — live re-test (2026-10-11, VM clock 2026-10-08T15:12).**
Ran `Compress-Archive` of a loot dir to `C:\Users\Public\exfil_stage.zip`, then
collected agentic_quick_wins. Findings on the attack window: none for T1560.001
(the data-collection redirect that preceded it surfaced as "Cmd Stream
Redirection"; the archive step did not). Checked the raw rows:
  1. The `Compress-Archive` INVOCATION is not captured in any matchable form —
     zero PowerShell 4103/4104 rows carry the command line or the destination
     path (same cmdletization-module problem as Defender's Add-MpPreference).
  2. The ARCHIVE FILE itself IS collected: `DetectRaptor.Windows.Detection.MFT`
     has a row for `\\.\C:\Users\Public\exfil_stage.zip` with its create/modify
     timestamps and size. So the fusion graph COULD receive this evidence — the
     gap is detection-content, not collection.
So why still open: any generic rule that turns "a .zip/.rar/.7z in a
world-writable staging path (Public, ProgramData, *\Temp, C:\Temp)" into a
finding would also fire on every benign admin zip (installers, log bundles,
backups) — it fails the `BenignHostStaysQuiet` tightness guarantee
(tests/test_sigma_medium_techniques_surface.py). The MFT row carries NO process
lineage, so it also can't be tied by correlation to the collection/cred-access
activity in the same window (the fusion-side angle that would have avoided the
FP). A tight detection needs process→file provenance (Sysmon EID 1 cmdline +
EID 11 FileCreate, or a dedicated artifact that records the creating process),
which the current collection does not carry. Deliberately NOT adding a loose
content heuristic.

**Reported by** attack-sim campaign (dev-attack-simulation-rules), 2026-10-08;
archive-staging re-characterised 2026-10-11. See memory [[attack-sim-campaign-state]].
