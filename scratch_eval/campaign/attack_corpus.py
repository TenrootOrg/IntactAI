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
