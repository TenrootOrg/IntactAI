# Attack-simulation campaign — parked; resume here

Win11 attack chains A–E run against a lab VM to check that fusion catches real
techniques without benign false positives. All code from it is on `main`
(the `dev-attack-simulation-rules` branch was merged and deleted 2026-10-11).
What is left is the open DLL side-loading research below.

## Where / what
- **Code:** on `main` (campaign tip was **ee64054b**). Appliance tree `~/intact`; the running `intact_backend`/`intact_velociraptor` have the
  branch code deployed via `docker cp` + restart (survives restart, NOT a recreate — rebuild
  the image before any reinstall or it reverts to stock intact-20261008).
- **VM:** Win11 `attacked-win11@192.168.120.131`, Velociraptor client `C.51628cbbd6a2ae90`
  (DESKTOP-2175T02). SSH key-auth. VM clock ~3 days behind (paused-overnight); don't touch it.
- **Safety (non-negotiable):** never run anything that can cut the VM's network (firewall/
  adapter/DNS/hosts/reboot/shutdown/stop-velo/disable-account/BCD/wipers) or any atomic with a
  download dependency (VMware NAT). Read each atomic YAML first. One case per scenario.
- **ART staged on VM:** `C:\AtomicRedTeam\{atomics,module,psyaml}` + `C:\SimLab\clean.ps1`;
  host runners in `~/art-stage`. Run chains from a `.ps1` FILE (inline SSH quoting breaks),
  `-ExecutionPolicy Bypass`. Collections: `agentic_quick_wins` (20 artifacts); add top-level
  `"cpu_limit":100` to POST /api/agentic/run for speed (per-run, NOT the code default).
  Score by timestamp (VM retains MFT/Amcache leftovers across tests).

## Done (on `main`)
- Fusion: burst correlation `f7a80207`, activity-window `8754d747`, one-record dedup `7914bae2`.
- Defender tampering detection (live WMI) `55770240` + severity tightening `87889151`.
- Presidio keep-list `191ad774`; masking-log clearer names `606e946b`; **NER FP fix + log-once**
  `e0330c03` (rejects `-flags`/camelCase, keep-list threat words, case-variant dedup).
- **Archive-staging T1560.001 CLOSED** `60b29f22`: `correlate._staging_archive_findings` promotes
  an archive in a world-writable path ONLY when a high/coordinated finding hit the same host
  within the hour. Validated live: sim-E surfaces, baseline+benign stay 0. (`ee64054b` docs.)
- Measured recall across chains A–E: **0 benign false positives**; high-signal techniques
  (persistence, defense-evasion/Defender, cred-access, masquerade, loopback lateral) all caught +
  correlated. Low-by-design misses (correct): discovery/recon, cached-cred enum, share-maps.

## OPEN — where we stopped (DLL side-loading T1574.002)
Goal: a GENERIC, low-volume detection. No fusion rule can help — there's no load event collected.
Searched Velociraptor artifacts; evaluated live on the VM:
- `Windows.Detection.ForwardedImports` — only the forwarder-DLL variant (too specific). Baseline
  6 rows, ALL benign `rpcrt4.dll` → **needs an rpcrt4/system-path exclude** (else ~600/100 machines).
- `Windows.System.UntrustedBinaries` — **noisy, reject**: flags catalog-signed Windows binaries
  (saw 8/9 benign); systemic per-machine FP → ~800–1000 per 100 machines.
- **`Windows.Attack.UnexpectedImagePath` — best candidate**: generic "trusted name from the wrong
  path" (masquerade/side-load cousin), no systemic FP, projected ~0–3 per 100 machines. BUT only
  n=1 and the one hit was OUR leftover `C:\Users\Attacked-WIN11\AppData\Local\Temp\lsass.exe`
  (PID 8376, from the cmd→lsass chain) — **never saw its clean baseline**.
- Memory-based generic injection (`InjectedThreadEx`, `HollowsHunter`, `ReflectedAssemblies`):
  generic but heavy (memory scan) + real benign FPs (JIT/.NET/EDR) — a tuning project, not drop-in.
- `Windows.System.DLLs` = raw inventory (rejected); `Windows.ETW.KernelProcess` = generic image-load
  but continuous-monitor model (not our point-in-time snapshot).

**Next steps when resuming:**
1. Clean the leftover `Temp\lsass.exe` (PID 8376) on the VM and **re-run `UnexpectedImagePath`** to
   get a real clean baseline (expected 0). Only then trust it.
2. Decide: add `UnexpectedImagePath` to the collection + map it into fusion as a T1036 masquerade
   detection (and optionally `ForwardedImports` WITH the exclude).
3. Still-open gap: true general DLL side-load (plain malicious DLL beside a signed exe) needs
   module-load telemetry (Sysmon EID 7 / `Windows.ETW.KernelProcess`) — a collection decision.
- `Windows.Detection.ForwardedImports` baseline flow on VM: `F.DB5LL3JKM7QNE` (6 rows).

## Still-open documented gaps (`.claude/notes/known-bugs.md`)
- T1574.002 DLL side-loading (above).
- (T1560.001 now RESOLVED — see known-bugs.)
