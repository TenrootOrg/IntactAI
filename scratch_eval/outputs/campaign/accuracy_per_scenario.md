# Attack-simulation ACCURACY — per scenario (deterministic)

10 authored PowerShell attack scenarios through the REAL pipeline (map_agentic -> correlate.assemble). Recall = the planted technique surfaced as a finding on the right host.

**Recall 8/10 (80%) · Host-grounded 8/10 · Severity-correct 8/10**

| # | Scenario | ATT&CK | Detected | Host✓ | Sev✓ | Matched finding |
|---|---|---|:--:|:--:|:--:|---|
| 1 | LSASS credential dumping (Mimikatz) | T1003.001 | ✅ | ✅ | ✅ | `sigma: mimikatz lsass credential dumping on wks-eval01 :: wk` |
| 2 | Security event log cleared | T1070.001 | ✅ | ✅ | ✅ | `sigma: security eventlog cleared on wks-eval01 :: wks-eval01` |
| 3 | Kerberoasting via Rubeus | T1558.003 | ✅ | ✅ | ✅ | `sigma: rubeus kerberos ticket request on wks-eval02 :: wks-e` |
| 4 | Windows Defender disabled | T1562.001 | ✅ | ✅ | ✅ | `sigma: windows defender real-time protection disabled on wks` |
| 5 | Encoded PowerShell execution | T1059.001 | ❌ MISS | — | — | `(none)` |
| 6 | Scheduled task persistence | T1053.005 | ❌ MISS | — | — | `(none)` |
| 7 | Process injection (RWX memory, YARA hit) | T1055 | ✅ | ✅ | ✅ | `injected process with c2 — explorer.exe (4820) on wks-eval01` |
| 8 | Cross-host credential reuse (service account) | T1021 | ✅ | ✅ | ✅ | `account 'adatumlab\svc_backup' used across 2 hosts :: wks-ev` |
| 9 | Cobalt Strike named pipe | T1071 | ✅ | ✅ | ✅ | `sigma: cobalt strike named pipe pattern on wks-eval05 :: wks` |
| 10 | Renamed system binary (procdump) | T1036.003 | ✅ | ✅ | ✅ | `sigma: renamed procdump execution on wks-eval04 :: wks-eval0` |
