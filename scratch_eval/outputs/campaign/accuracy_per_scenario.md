# Attack-simulation ACCURACY — per scenario (deterministic)

41 authored PowerShell attack scenarios through the REAL pipeline (map_agentic -> correlate.assemble). Recall = the planted technique surfaced as a finding on the right host.

**Recall 37/41 (90%) · Host-grounded 37/41 · Severity-correct 35/41**

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
| 11 | WMI event consumer persistence | T1546.003 | ✅ | ✅ | ✅ | `sigma: wmi event subscription persistence on wks-eval06 :: w` |
| 12 | DCSync credential replication | T1003.006 | ✅ | ✅ | ✅ | `sigma: dcsync replication rights abuse on wks-eval02 :: wks-` |
| 13 | SharpHound/BloodHound AD collection | T1087.002 | ✅ | ✅ | ✅ | `sigma: sharphound bloodhound collection on wks-eval03 :: wks` |
| 14 | Non-standard outbound RDP | T1021.001 | ✅ | ✅ | ✅ | `sigma: non-standard outbound rdp connection on wks-eval04 ::` |
| 15 | Injected svchost (RWX, no YARA) | T1055.001 | ✅ | ✅ | — | `code injection — svchost.exe (992) on wks-eval06 :: wks-eval` |
| 16 | Kerberos golden ticket | T1558.001 | ✅ | ✅ | ✅ | `sigma: golden ticket kerberos forgery on wks-eval02 :: wks-e` |
| 17 | Ransomware mass file encryption | T1486 | ✅ | ✅ | ✅ | `sigma: ransomware mass file encryption behaviour on wks-eval` |
| 18 | Shadow copy deletion | T1490 | ✅ | ✅ | ✅ | `sigma: volume shadow copy deletion via vssadmin on wks-eval0` |
| 19 | Registry SAM hive dump | T1003.002 | ✅ | ✅ | ✅ | `sigma: registry sam hive dump on wks-eval01 :: wks-eval01` |
| 20 | DLL sideloading | T1574.002 | ✅ | ✅ | ✅ | `sigma: dll sideloading via signed binary on wks-eval03 :: wk` |
| 21 | AMSI bypass | T1562.001 | ✅ | ✅ | ✅ | `sigma: amsi bypass patch in memory on wks-eval03 :: wks-eval` |
| 22 | Data exfiltration via rclone | T1567.002 | ✅ | ✅ | ✅ | `sigma: rclone cloud exfiltration on wks-eval04 :: wks-eval04` |
| 23 | LOLBin download (certutil) | T1105 | ✅ | ✅ | ✅ | `sigma: certutil remote file download on wks-eval05 :: wks-ev` |
| 24 | AD discovery (net group) | T1069.002 | ❌ MISS | — | — | `(none)` |
| 25 | Unauthorized RMM tool (AnyDesk) | T1219 | ❌ MISS | — | — | `(none)` |
| 26 | Attacker script in PowerShell ISE autosave | T1059.001 | ✅ | ✅ | — | `ise autosave: att&ck t1059.001 - encoded download cradle on ` |
| 27 | Anti-forensic wiper in MFT (sdelete) | T1070.004 | ✅ | ✅ | ✅ | `mft: sdelete secure deletion tool on wks-eval07 :: wks-eval0` |
| 28 | BYOVD — vulnerable driver loaded | T1068 | ✅ | ✅ | ✅ | `sigma: vulnerable driver loaded (byovd) on wks-eval06 :: wks` |
| 29 | PsExec remote execution | T1569.002 | ✅ | ✅ | ✅ | `sigma: psexec service installation on wks-eval05 :: wks-eval` |
| 30 | Webshell dropped on IIS | T1505.003 | ✅ | ✅ | ✅ | `sigma: webshell written to web root on wks-eval08 :: wks-eva` |
| 31 | UAC bypass via fodhelper | T1548.002 | ✅ | ✅ | ✅ | `sigma: uac bypass via fodhelper registry hijack on wks-eval0` |
| 32 | AS-REP roasting | T1558.004 | ✅ | ✅ | ✅ | `sigma: as-rep roasting attack on wks-eval02 :: wks-eval02` |
| 33 | C2 beaconing to external IP | T1071.001 | ✅ | ✅ | ✅ | `sigma: c2 beaconing pattern detected on wks-eval01 :: wks-ev` |
| 34 | NTDS.dit extraction | T1003.003 | ✅ | ✅ | ✅ | `sigma: ntds.dit extraction via ntdsutil on wks-eval02 :: wks` |
| 35 | ADCS certificate abuse (ESC1) | T1649 | ✅ | ✅ | ✅ | `sigma: adcs certificate template abuse esc1 on wks-eval02 ::` |
| 36 | Access token impersonation | T1134.001 | ✅ | ✅ | ✅ | `sigma: access token impersonation on wks-eval06 :: wks-eval0` |
| 37 | Data staged in an archive | T1560.001 | ✅ | ✅ | ✅ | `sigma: data staged in password-protected archive on wks-eval` |
| 38 | Keylogging / input capture | T1056.001 | ✅ | ✅ | ✅ | `sigma: keylogger input capture hook on wks-eval03 :: wks-eva` |
| 39 | Firewall rule tampering | T1562.004 | ✅ | ✅ | ✅ | `sigma: windows firewall rule added via netsh on wks-eval05 :` |
| 40 | Service account privilege abuse | T1078.002 | ✅ | ✅ | ✅ | `sigma: service account interactive logon on wks-eval06 :: wk` |
| 41 | USN journal deletion | T1070.009 | ✅ | ✅ | ✅ | `sigma: usn journal deleted via fsutil on wks-eval07 :: wks-e` |
