"""Fusion correlation + report tests, fixture-driven (no live infra).

Run inside the backend container:
    python3 -m services.fusion.tests.test_fusion          # prints the demo report
    python3 -m pytest services/fusion/tests/test_fusion.py # asserts
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.fusion import correlate, render, llm_sim, keys  # noqa: E402
from services.fusion.mappers import map_memory, map_agentic   # noqa: E402

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
    md = llm_sim.generate_report(g, window=WINDOW, min_severity="low",
                                 initial_access="2026-05-19T08:14:20", case_name="INTRUSION-MAY")
    for section in ("Executive / Risk Overview", "Infrastructural Attack Timeline", "Per-Host Detail"):
        assert section in md, f"missing section: {section}"
    assert "Lateral Movement" in md
    assert "5.100.251.10" in md


def test_chat_grounded():
    g = build()
    a1 = llm_sim.chat(g, "how did they move laterally?", window=WINDOW, min_severity="low")
    assert "administrator" in a1.lower() or "lateral" in a1.lower()
    a2 = llm_sim.chat(g, "what about 5.100.251.10?", window=WINDOW, min_severity="low")
    assert "cross-host" in a2.lower()


def test_ioc_and_mitre_sections():
    g = build()
    md = llm_sim.generate_report(g, window=WINDOW, min_severity="low", case_name="X")
    assert "Key Indicators" in md and "5.100.251.10" in md
    assert "MITRE ATT&CK" in md and "T1071" in md and "T1021" in md


def test_persistence_service_finding():
    payload = {"host": "H", "yara": [], "plugins": {"svcscan": [
        {"Name": "EvilSvc", "State": "SERVICE_RUNNING", "PID": 4444,
         "Binary": "C:\\Users\\x\\AppData\\Local\\Temp\\evil.exe"}]}}
    g = correlate.assemble("c", [map_memory(payload, run_id="m", asset=keys.asset_id("C.x"))], ["m"])
    svc = [f for f in g.findings if "service" in f.title.lower()]
    assert svc and "T1543" in svc[0].mitre


def test_cve_mapper_and_finding():
    from services.fusion.mappers import map_cve
    rows = [{"Hostname": "WS01", "Product": "Acme", "Version": "1.0",
             "CVE": "CVE-2024-1234", "CVSS_Score": 9.8}]
    g = correlate.assemble("c", [map_cve(rows, run_id="cve_1")], ["cve_1"])
    v = [e for e in g.entities.values() if e.type == "vuln"]
    assert v and v[0].severity == "critical"
    assert any(f.title.startswith("Vulnerability") for f in g.findings)
    assert any(r.kind == "has_cve" for r in g.relationships)


def test_chat_more_intents():
    g = build()
    assert "host" in llm_sim.chat(g, "give me a summary", window=WINDOW, min_severity="low").lower()
    assert "WS01" in llm_sim.chat(g, "who is the most affected host?", window=WINDOW, min_severity="low")
    ia = llm_sim.chat(g, "how did they get in?", window=WINDOW, min_severity="low")
    assert "initial-access" in ia.lower() or "earliest" in ia.lower()


def test_host_severity_rollup():
    g = build()
    ws01 = g.entities[keys.asset_id(WS01)]
    assert ws01.severity == "critical", f"WS01 should roll up to critical, got {ws01.severity}"


def test_timesketch_mapper_extracts_iocs():
    from services.fusion.mappers import map_timesketch
    evs = [{"datetime": "2026-06-15T08:00:00", "message": "connection to 5.100.251.10 observed",
            "parser": "winevtx"}]
    g = correlate.assemble("c", [map_timesketch(evs, run_id="ts_1", asset=keys.asset_id("C.x"),
                                                hostname="H")], ["ts_1"])
    assert any(e.type == "event" for e in g.entities.values())
    assert keys.ioc_id("ip", "5.100.251.10") in g.entities


def test_hostname_asset_merges_into_client_id_asset():
    from services.fusion.mappers import map_cve, map_agentic
    DC = "C.dcdcdc"
    agt = map_agentic({"Generic.System.Pstree": [
        {"_client_id": DC, "_hostname": "DC01", "Pid": 1, "Name": "x",
         "CreateTime": "2026-06-15T07:00:00Z"}]}, run_id="a", hostnames={DC: "DC01"})
    cve = map_cve([{"Hostname": "DC01", "CVE": "CVE-2021-26855", "CVSS_Score": 9.8}], run_id="c")
    g = correlate.assemble("c", [agt, cve], ["a", "c"])
    assets = g.by_type("asset")
    assert len(assets) == 1, f"DC01 must be ONE node, got {[a.id for a in assets]}"
    assert keys.asset_id(DC) in g.entities, "canonical client_id asset survives"
    vuln = [e for e in g.entities.values() if e.type == "vuln"][0]
    assert keys.asset_id(DC) in (vuln.attrs.get("_assets") or []), "CVE re-pointed to the real host"


def test_four_module_integration():
    from services.fusion.mappers import map_cve, map_timesketch
    mem = map_memory(MEMORY_PAYLOAD, run_id="m", asset=keys.asset_id(WS01), hostname="WS01")
    agt = map_agentic(AGENTIC_DATA, run_id="a", hostnames=HOSTNAMES)
    cve = map_cve([{"Hostname": "WS01", "CVE": "CVE-2024-0001", "CVSS_Score": 9.0}], run_id="c")
    ts = map_timesketch([{"datetime": "2026-05-19T08:00:00", "message": "beacon to 5.100.251.10",
                          "parser": "evtx"}], run_id="t", asset=keys.asset_id(WS01), hostname="WS01")
    g = correlate.assemble("case", [mem, agt, cve, ts], ["m", "a", "c", "t"])
    srcs = set()
    for e in g.entities.values():
        srcs.update(e.sources)
    assert {"memory", "agentic", "cve", "timesketch"} <= srcs, f"all 4 modules merge, got {srcs}"
    md = llm_sim.generate_report(g, window=WINDOW, min_severity="medium", case_name="FULL")
    assert "Vulnerability" in md or "CVE-2024-0001" in md
    assert "Lateral Movement" in md


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
    md = llm_sim.generate_report(g, min_severity="low", case_name="X")
    assert "Escalation" in md and "WS9" in md
    assert "deep-dive" in llm_sim.chat(g, "what should I investigate next?", min_severity="low").lower()


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
