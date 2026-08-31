"""Ground-truth attack corpus — pure-PowerShell-style scenarios with an ANSWER KEY.

Each scenario authors the Velociraptor telemetry the activity WOULD produce (real
row shapes the mappers consume), so it flows through the REAL detection pipeline
(map_agentic -> correlate.assemble -> derived findings). Because we author it, we
know exactly what should be found — the basis for a recall / precision / grounding
accuracy score. Modelled on Invoke-Adversary / RTA / DetectRaptor techniques.

`expect.find` = substrings that MUST appear in a derived finding on `host`.
`expect.tech` = the ATT&CK id the activity represents (for coverage reporting).
"""

_T = "Windows.Hayabusa.Rules"      # SIGMA detections -> "SIGMA: <Title> on <host>"


def _sigma(host, title, level, ts, n=1):
    return [{"Computer": host, "Title": title, "Level": level, "EventTime": ts}
            for _ in range(n)]


SCENARIOS = [
    # 1 — credential dumping
    {"id": "cred-lsass", "name": "LSASS credential dumping (Mimikatz)",
     "tech": "T1003.001", "host": "WKS-EVAL01",
     "activity": "Invoke-Mimikatz sekurlsa::logonpasswords reading LSASS memory",
     "telemetry": {_T: _sigma("WKS-EVAL01", "Mimikatz LSASS Credential Dumping", "crit",
                              "2026-08-01T09:12:00Z", n=3)},
     "expect": {"find": ["mimikatz"], "sev": "critical"}},
    # 2 — anti-forensics
    {"id": "log-clear", "name": "Security event log cleared",
     "tech": "T1070.001", "host": "WKS-EVAL01",
     "activity": "wevtutil cl Security / Clear-EventLog",
     "telemetry": {_T: _sigma("WKS-EVAL01", "Security Eventlog Cleared", "high",
                              "2026-08-01T09:20:00Z")},
     "expect": {"find": ["eventlog cleared"], "sev": "high"}},
    # 3 — credential access via Kerberos
    {"id": "kerberoast", "name": "Kerberoasting via Rubeus",
     "tech": "T1558.003", "host": "WKS-EVAL02",
     "activity": "Rubeus.exe kerberoast / asktgt",
     "telemetry": {_T: _sigma("WKS-EVAL02", "Rubeus Kerberos Ticket Request", "high",
                              "2026-08-01T09:30:00Z")},
     "expect": {"find": ["rubeus", "kerberos"], "sev": "high"}},
    # 4 — defense evasion
    {"id": "defender-off", "name": "Windows Defender disabled",
     "tech": "T1562.001", "host": "WKS-EVAL02",
     "activity": "Set-MpPreference -DisableRealtimeMonitoring $true",
     "telemetry": {_T: _sigma("WKS-EVAL02", "Windows Defender Real-time Protection Disabled",
                              "high", "2026-08-01T09:35:00Z")},
     "expect": {"find": ["defender"], "sev": "high"}},
    # 5 — execution
    {"id": "enc-ps", "name": "Encoded PowerShell execution",
     "tech": "T1059.001", "host": "WKS-EVAL03",
     "activity": "powershell -enc <base64 downloader>",
     "telemetry": {_T: _sigma("WKS-EVAL03", "Suspicious Encoded PowerShell Command Line",
                              "medium", "2026-08-01T09:40:00Z")},
     "expect": {"find": ["encoded powershell"], "sev": "medium"}},
    # 6 — persistence
    {"id": "sched-task", "name": "Scheduled task persistence",
     "tech": "T1053.005", "host": "WKS-EVAL03",
     "activity": "schtasks /create for a backdoor",
     "telemetry": {_T: _sigma("WKS-EVAL03", "Suspicious Scheduled Task Creation", "medium",
                              "2026-08-01T09:45:00Z")},
     "expect": {"find": ["scheduled task"], "sev": "medium"}},
    # 7 — memory injection (RICHER artifact: malfind -> injected process)
    {"id": "inject", "name": "Process injection (RWX memory, YARA hit)",
     "tech": "T1055", "host": "WKS-EVAL01",
     "activity": "Reflective DLL / shellcode injected into a running process",
     "telemetry": {"Windows.Detection.Malfind": [
         {"Computer": "WKS-EVAL01", "Pid": 4820, "Name": "explorer.exe",
          "Protection": "PAGE_EXECUTE_READWRITE", "CreateTime": "2026-08-01T09:50:00Z",
          "YaraHit": {"Rule": "CobaltStrike_Beacon"}}]},
     "expect": {"find": ["explorer"], "sev": "critical"}},   # injected -> anomaly 100 -> critical
    # 8 — lateral movement / cross-host identity (RICHER: account on 2 hosts)
    {"id": "xhost-acct", "name": "Cross-host credential reuse (service account)",
     "tech": "T1021", "host": "WKS-EVAL04",
     "activity": "adatumlab\\svc_backup authenticates to two hosts (lateral)",
     "telemetry": {"Windows.EventLogs.CondensedAccountUsage": [
         {"Computer": "WKS-EVAL04", "User": "adatumlab\\svc_backup",
          "EventTime": "2026-08-01T09:55:00Z", "LogonType": "3"},
         {"Computer": "WKS-EVAL05", "User": "adatumlab\\svc_backup",
          "EventTime": "2026-08-01T09:56:00Z", "LogonType": "3"}]},
     "expect": {"find": ["svc_backup", "across"], "sev": "high"}},
    # 9 — C2
    {"id": "namedpipe-c2", "name": "Cobalt Strike named pipe",
     "tech": "T1071", "host": "WKS-EVAL05",
     "activity": "Cobalt Strike default named pipe \\\\.\\pipe\\msagent_xx",
     "telemetry": {_T: _sigma("WKS-EVAL05", "Cobalt Strike Named Pipe Pattern", "crit",
                              "2026-08-01T10:00:00Z")},
     "expect": {"find": ["cobalt strike", "pipe"], "sev": "critical"}},
    # 10 — masquerading
    {"id": "binrename", "name": "Renamed system binary (procdump)",
     "tech": "T1036.003", "host": "WKS-EVAL04",
     "activity": "procdump renamed to svchost-helper.exe to dump LSASS",
     "telemetry": {_T: _sigma("WKS-EVAL04", "Renamed ProcDump Execution", "high",
                              "2026-08-01T10:05:00Z")},
     "expect": {"find": ["procdump"], "sev": "high"}},
]


# More techniques, second batch — broaden tactic coverage to find more gaps.
SCENARIOS += [
    {"id": "wmi-persist", "name": "WMI event consumer persistence",
     "tech": "T1546.003", "host": "WKS-EVAL06",
     "activity": "permanent WMI event subscription for persistence",
     "telemetry": {_T: _sigma("WKS-EVAL06", "WMI Event Subscription Persistence", "high",
                              "2026-08-01T10:10:00Z")},
     "expect": {"find": ["wmi"], "sev": "high"}},
    {"id": "dcsync", "name": "DCSync credential replication",
     "tech": "T1003.006", "host": "WKS-EVAL02",
     "activity": "Mimikatz lsadump::dcsync pulling domain hashes",
     "telemetry": {_T: _sigma("WKS-EVAL02", "DCSync Replication Rights Abuse", "crit",
                              "2026-08-01T10:15:00Z")},
     "expect": {"find": ["dcsync"], "sev": "critical"}},
    {"id": "bloodhound", "name": "SharpHound/BloodHound AD collection",
     "tech": "T1087.002", "host": "WKS-EVAL03",
     "activity": "SharpHound.exe -c All domain enumeration",
     "telemetry": {_T: _sigma("WKS-EVAL03", "SharpHound BloodHound Collection", "high",
                              "2026-08-01T10:20:00Z")},
     "expect": {"find": ["bloodhound"], "sev": "high"}},
    {"id": "rdp-lateral", "name": "Non-standard outbound RDP",
     "tech": "T1021.001", "host": "WKS-EVAL04",
     "activity": "outbound RDP to a workstation (lateral movement)",
     "telemetry": {_T: _sigma("WKS-EVAL04", "Non-Standard Outbound RDP Connection", "high",
                              "2026-08-01T10:25:00Z")},
     "expect": {"find": ["rdp"], "sev": "high"}},
    {"id": "malfind-svc", "name": "Injected svchost (RWX, no YARA)",
     "tech": "T1055.001", "host": "WKS-EVAL06",
     "activity": "shellcode injected into svchost.exe (no signature match)",
     "telemetry": {"Windows.Detection.Malfind": [
         {"Computer": "WKS-EVAL06", "Pid": 992, "Name": "svchost.exe",
          "Protection": "PAGE_EXECUTE_READWRITE", "CreateTime": "2026-08-01T10:30:00Z"}]},
     "expect": {"find": ["svchost"], "sev": "critical"}},
]

# Batch 3 — broaden across more tactics (mostly high/critical, a couple medium to
# keep characterizing the finding threshold).
SCENARIOS += [
    {"id": "golden-ticket", "name": "Kerberos golden ticket", "tech": "T1558.001",
     "host": "WKS-EVAL02", "activity": "forged TGT (golden ticket) for domain persistence",
     "telemetry": {_T: _sigma("WKS-EVAL02", "Golden Ticket Kerberos Forgery", "crit",
                              "2026-08-01T10:35:00Z")},
     "expect": {"find": ["golden ticket"], "sev": "critical"}},
    {"id": "ransomware", "name": "Ransomware mass file encryption", "tech": "T1486",
     "host": "WKS-EVAL07", "activity": "mass file rename to .locked + ransom note",
     "telemetry": {_T: _sigma("WKS-EVAL07", "Ransomware Mass File Encryption Behaviour",
                              "crit", "2026-08-01T10:40:00Z")},
     "expect": {"find": ["ransomware"], "sev": "critical"}},
    {"id": "shadowcopy", "name": "Shadow copy deletion", "tech": "T1490",
     "host": "WKS-EVAL07", "activity": "vssadmin delete shadows /all (anti-recovery)",
     "telemetry": {_T: _sigma("WKS-EVAL07", "Volume Shadow Copy Deletion via Vssadmin",
                              "high", "2026-08-01T10:41:00Z")},
     "expect": {"find": ["shadow copy"], "sev": "high"}},
    {"id": "reg-sam", "name": "Registry SAM hive dump", "tech": "T1003.002",
     "host": "WKS-EVAL01", "activity": "reg save HKLM\\SAM for offline hash extraction",
     "telemetry": {_T: _sigma("WKS-EVAL01", "Registry SAM Hive Dump", "high",
                              "2026-08-01T10:42:00Z")},
     "expect": {"find": ["sam"], "sev": "high"}},
    {"id": "dll-sideload", "name": "DLL sideloading", "tech": "T1574.002",
     "host": "WKS-EVAL03", "activity": "signed binary loads an attacker DLL from its dir",
     "telemetry": {_T: _sigma("WKS-EVAL03", "DLL Sideloading via Signed Binary", "high",
                              "2026-08-01T10:43:00Z")},
     "expect": {"find": ["sideload"], "sev": "high"}},
    {"id": "amsi-bypass", "name": "AMSI bypass", "tech": "T1562.001",
     "host": "WKS-EVAL03", "activity": "in-memory AMSI patch to evade script scanning",
     "telemetry": {_T: _sigma("WKS-EVAL03", "AMSI Bypass Patch In Memory", "high",
                              "2026-08-01T10:44:00Z")},
     "expect": {"find": ["amsi"], "sev": "high"}},
    {"id": "exfil-rclone", "name": "Data exfiltration via rclone", "tech": "T1567.002",
     "host": "WKS-EVAL04", "activity": "rclone copy to a cloud bucket (exfil)",
     "telemetry": {_T: _sigma("WKS-EVAL04", "Rclone Cloud Exfiltration", "high",
                              "2026-08-01T10:45:00Z")},
     "expect": {"find": ["rclone"], "sev": "high"}},
    {"id": "certutil-dl", "name": "LOLBin download (certutil)", "tech": "T1105",
     "host": "WKS-EVAL05", "activity": "certutil -urlcache -f http://... payload.exe",
     "telemetry": {_T: _sigma("WKS-EVAL05", "Certutil Remote File Download", "high",
                              "2026-08-01T10:46:00Z")},
     "expect": {"find": ["certutil"], "sev": "high"}},
    # deliberately MEDIUM — discovery recon, to reconfirm the threshold boundary
    {"id": "ad-recon", "name": "AD discovery (net group)", "tech": "T1069.002",
     "host": "WKS-EVAL06", "activity": "net group 'Domain Admins' /domain recon",
     "telemetry": {_T: _sigma("WKS-EVAL06", "Domain Admins Enumeration", "medium",
                              "2026-08-01T10:47:00Z")},
     "expect": {"find": ["domain admins"], "sev": "medium"}},
    {"id": "rmm-abuse", "name": "Unauthorized RMM tool (AnyDesk)", "tech": "T1219",
     "host": "WKS-EVAL05", "activity": "attacker-installed AnyDesk for remote access",
     "telemetry": {_T: _sigma("WKS-EVAL05", "Unauthorized RMM Tool AnyDesk", "medium",
                              "2026-08-01T10:48:00Z")},
     "expect": {"find": ["anydesk"], "sev": "medium"}},
]

# Batch 4 — NON-SIGMA artifact paths, to test derivation variety (each uses a
# different mapper branch, not the Hayabusa/SIGMA passthrough).
SCENARIOS += [
    {"id": "ise-autosave", "name": "Attacker script in PowerShell ISE autosave",
     "tech": "T1059.001", "host": "WKS-EVAL03",
     "activity": "attacker script content recovered from ISE autosave file",
     "telemetry": {"DetectRaptor.Windows.Detection.Powershell.IseAutoSave": [
         {"Computer": "WKS-EVAL03",
          "Detection": {"Name": "ATT&CK T1059.001 - Encoded Download Cradle"},
          "FileInfo": {"OSPath": "C:\\Users\\a\\AppData\\...\\PSISE_autosave.ps1",
                       "Mtime": "2026-08-01T10:50:00Z"}}]},
     "expect": {"find": ["ise autosave"], "sev": "critical"}},
    {"id": "mft-erasing", "name": "Anti-forensic wiper in MFT (sdelete)",
     "tech": "T1070.004", "host": "WKS-EVAL07",
     "activity": "sdelete.exe present in the MFT (secure-delete / anti-forensics)",
     "telemetry": {"DetectRaptor.Windows.Detection.MFT.Erasing.Tools": [
         {"Computer": "WKS-EVAL07", "OSPath": "C:\\Tools\\sdelete64.exe",
          "Detection": {"Name": "SDelete secure deletion tool", "Criticality": "high"},
          "FNTimestamps": {"Created0x30": "2026-08-01T10:52:00Z"}}]},
     "expect": {"find": ["sdelete"], "sev": "high"}},   # MFT detection: characterize its severity
]

# Batch 5 — further tactic breadth.
SCENARIOS += [
    {"id": "byovd", "name": "BYOVD — vulnerable driver loaded", "tech": "T1068",
     "host": "WKS-EVAL06", "activity": "attacker loads a known-vulnerable signed driver",
     "telemetry": {_T: _sigma("WKS-EVAL06", "Vulnerable Driver Loaded (BYOVD)", "crit",
                              "2026-08-01T11:00:00Z")},
     "expect": {"find": ["driver"], "sev": "critical"}},
    {"id": "psexec-lateral", "name": "PsExec remote execution", "tech": "T1569.002",
     "host": "WKS-EVAL05", "activity": "PsExec service created for remote execution",
     "telemetry": {_T: _sigma("WKS-EVAL05", "PsExec Service Installation", "high",
                              "2026-08-01T11:02:00Z")},
     "expect": {"find": ["psexec"], "sev": "high"}},
    {"id": "webshell", "name": "Webshell dropped on IIS", "tech": "T1505.003",
     "host": "WKS-EVAL08", "activity": "aspx webshell written to inetpub",
     "telemetry": {_T: _sigma("WKS-EVAL08", "Webshell Written To Web Root", "crit",
                              "2026-08-01T11:04:00Z")},
     "expect": {"find": ["webshell"], "sev": "critical"}},
    {"id": "uac-bypass", "name": "UAC bypass via fodhelper", "tech": "T1548.002",
     "host": "WKS-EVAL03", "activity": "fodhelper.exe registry hijack for elevation",
     "telemetry": {_T: _sigma("WKS-EVAL03", "UAC Bypass via Fodhelper Registry Hijack",
                              "high", "2026-08-01T11:06:00Z")},
     "expect": {"find": ["uac bypass"], "sev": "high"}},
    {"id": "asrep-roast", "name": "AS-REP roasting", "tech": "T1558.004",
     "host": "WKS-EVAL02", "activity": "AS-REP roasting against accounts without preauth",
     "telemetry": {_T: _sigma("WKS-EVAL02", "AS-REP Roasting Attack", "high",
                              "2026-08-01T11:08:00Z")},
     "expect": {"find": ["as-rep"], "sev": "high"}},
    {"id": "c2-beacon", "name": "C2 beaconing to external IP", "tech": "T1071.001",
     "host": "WKS-EVAL01", "activity": "periodic HTTPS beacon to attacker infrastructure",
     "telemetry": {_T: _sigma("WKS-EVAL01", "C2 Beaconing Pattern Detected", "crit",
                              "2026-08-01T11:10:00Z")},
     "expect": {"find": ["beacon"], "sev": "critical"}},
]

# Batch 6 — tactics not yet represented (collection, staging, token theft, ADCS,
# NTDS, clipboard/keylog, service-account abuse, firewall tampering).
SCENARIOS += [
    {"id": "ntds-dump", "name": "NTDS.dit extraction", "tech": "T1003.003",
     "host": "WKS-EVAL02", "activity": "ntdsutil IFM dump of the AD database",
     "telemetry": {_T: _sigma("WKS-EVAL02", "NTDS.dit Extraction via Ntdsutil", "crit",
                              "2026-08-01T11:12:00Z")},
     "expect": {"find": ["ntds"], "sev": "critical"}},
    {"id": "adcs-abuse", "name": "ADCS certificate abuse (ESC1)", "tech": "T1649",
     "host": "WKS-EVAL02", "activity": "malicious certificate request for impersonation",
     "telemetry": {_T: _sigma("WKS-EVAL02", "ADCS Certificate Template Abuse ESC1", "crit",
                              "2026-08-01T11:14:00Z")},
     "expect": {"find": ["certificate"], "sev": "critical"}},
    {"id": "token-theft", "name": "Access token impersonation", "tech": "T1134.001",
     "host": "WKS-EVAL06", "activity": "token duplication to impersonate SYSTEM",
     "telemetry": {_T: _sigma("WKS-EVAL06", "Access Token Impersonation", "high",
                              "2026-08-01T11:16:00Z")},
     "expect": {"find": ["token"], "sev": "high"}},
    {"id": "staging-archive", "name": "Data staged in an archive", "tech": "T1560.001",
     "host": "WKS-EVAL04", "activity": "7z archive of collected documents for exfil",
     "telemetry": {_T: _sigma("WKS-EVAL04", "Data Staged In Password-Protected Archive",
                              "high", "2026-08-01T11:18:00Z")},
     "expect": {"find": ["archive"], "sev": "high"}},
    {"id": "keylogger", "name": "Keylogging / input capture", "tech": "T1056.001",
     "host": "WKS-EVAL03", "activity": "keyboard hook installed to capture credentials",
     "telemetry": {_T: _sigma("WKS-EVAL03", "Keylogger Input Capture Hook", "high",
                              "2026-08-01T11:20:00Z")},
     "expect": {"find": ["keylog"], "sev": "high"}},
    {"id": "fw-tamper", "name": "Firewall rule tampering", "tech": "T1562.004",
     "host": "WKS-EVAL05", "activity": "netsh advfirewall rule added for C2 egress",
     "telemetry": {_T: _sigma("WKS-EVAL05", "Windows Firewall Rule Added Via Netsh",
                              "high", "2026-08-01T11:22:00Z")},
     "expect": {"find": ["firewall"], "sev": "high"}},
    {"id": "svc-acct-abuse", "name": "Service account privilege abuse", "tech": "T1078.002",
     "host": "WKS-EVAL06", "activity": "domain service account used interactively",
     "telemetry": {_T: _sigma("WKS-EVAL06", "Service Account Interactive Logon", "high",
                              "2026-08-01T11:24:00Z")},
     "expect": {"find": ["service account"], "sev": "high"}},
    {"id": "clear-usnjrnl", "name": "USN journal deletion", "tech": "T1070.009",
     "host": "WKS-EVAL07", "activity": "fsutil usn deletejournal (anti-forensics)",
     "telemetry": {_T: _sigma("WKS-EVAL07", "USN Journal Deleted Via Fsutil", "high",
                              "2026-08-01T11:26:00Z")},
     "expect": {"find": ["usn"], "sev": "high"}},
]

# BENIGN baseline — normal admin/IT activity that should NOT produce attack findings
# (false-positive / precision test). Informational SIGMA + routine processes.
BENIGN = {
    "Windows.Hayabusa.Rules": [
        {"Computer": "WKS-EVAL01", "Title": "User Logon", "Level": "informational",
         "EventTime": "2026-08-01T08:00:00Z"},
        {"Computer": "WKS-EVAL01", "Title": "Windows Update Installed", "Level": "low",
         "EventTime": "2026-08-01T08:05:00Z"},
        {"Computer": "WKS-EVAL02", "Title": "Scheduled Defrag", "Level": "informational",
         "EventTime": "2026-08-01T08:10:00Z"},
    ],
    "Generic.System.Pstree": [
        {"Computer": "WKS-EVAL01", "Pid": 700, "Name": "explorer.exe",
         "CommandLine": "C:\\Windows\\explorer.exe", "CreateTime": "2026-08-01T08:00:00Z"},
        {"Computer": "WKS-EVAL02", "Pid": 812, "Name": "OUTLOOK.EXE",
         "CommandLine": "outlook.exe", "CreateTime": "2026-08-01T08:12:00Z"},
    ],
}


def build_all_telemetry():
    """Merge every scenario's telemetry into one multi-host collection (the combined
    incident) — {artifact: [rows across scenarios]}."""
    merged: dict = {}
    for s in SCENARIOS:
        for art, rows in s["telemetry"].items():
            merged.setdefault(art, []).extend(rows)
    return merged
