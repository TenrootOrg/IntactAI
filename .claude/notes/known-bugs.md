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
Three attacker techniques, run and COLLECTED on a lab Win11 host, surface no
finding in Case Analysis — not a weighting problem, a missing-detection problem.

- **Defender exclusion via `Add-MpPreference -ExclusionPath` (T1562.001).** The
  command IS collected (PowerShell 4104 scriptblock, in Windows.Hayabusa.Rules +
  DetectRaptor.Windows.Detection.Evtx), but the ONLY detection it trips is the
  generic "Potentially Malicious PwSh" heuristic — which fusion_weighting.yaml
  correctly downweights to low as noise. So the real defense-evasion action is
  suppressed with the noise. No specific SIGMA/Hayabusa rule names it.
- **Archive/staging of loot (`Compress-Archive` → zip, T1560.001).** No
  collection/detection surfaces it.
- **DLL side-loading (T1574.002).** Stock Win11 logs no DLL loads (needs Sysmon
  EID 7), and the planted pair isn't in HijackLibs' known-abused set.

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
needs process-command-line logging (Sysmon EID 1) or a dedicated artifact. These
are collection/detection-content changes, NOT fusion — the fusion graph never
receives the evidence.

**Reported by** attack-sim campaign (dev-attack-simulation-rules), 2026-10-08.
See memory [[attack-sim-campaign-state]].
