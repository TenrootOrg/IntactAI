"""Auth / Kerberos — cross-host lateral movement + Golden-Ticket detection.

SYNTHETIC fixtures built from the REAL artifact schemas (column names verbatim from
Windows.EventLogs.CondensedAccountUsage / LogonSessions / Kerberos.GoldenTicketTriage) —
the standalone lab box has no domain auth, so these are schema-accurate, not real capture.
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.fusion import correlate  # noqa: E402
from services.fusion.mappers import map_agentic  # noqa: E402


def test_domain_admin_across_hosts_is_lateral_movement():
    # same domain\administrator logs on to TWO hosts (4624 type 3 + IpAddress) ->
    # global account key collapses -> ONE 'used across N hosts' cross-host finding.
    rows_dc = [{"EventTime": "2026-05-19T09:00:00Z", "Computer": "DC01", "EventID": 4624,
                "DomainName": "CORP", "UserName": "administrator", "LogonType": 3,
                "AuthenticationPackageName": "Kerberos", "IpAddress": "10.0.0.50",
                "_client_id": "C.dc", "_hostname": "DC01"}]
    rows_srv = [{"EventTime": "2026-05-19T09:05:00Z", "Computer": "SRV", "EventID": 4624,
                 "DomainName": "CORP", "UserName": "administrator", "LogonType": 10,
                 "LogonProcessName": "seclogon", "IpAddress": "10.0.0.50",
                 "_client_id": "C.srv", "_hostname": "SRV"}]
    cdc = map_agentic({"Windows.EventLogs.CondensedAccountUsage": rows_dc},
                      run_id="a", hostnames={"C.dc": "DC01"})
    csrv = map_agentic({"Windows.EventLogs.CondensedAccountUsage": rows_srv},
                       run_id="b", hostnames={"C.srv": "SRV"})
    g = correlate.assemble("auth", [cdc, csrv], ["a", "b"])
    lat = [f for f in g.findings if f.kind == "cross_host" and "administrator" in f.title.lower()]
    assert lat, "domain admin on 2 hosts must be a cross-host lateral-movement finding"
    assert "T1021" in lat[0].mitre or "T1078" in lat[0].mitre
    # the enriched edge carries the auth context
    auth_edges = [r for r in g.relationships if r.kind == "authenticated"]
    assert any(r.attrs.get("src_ip") == "10.0.0.50" for r in auth_edges)
    assert any(r.attrs.get("logon_process") == "seclogon" for r in auth_edges)


def test_kerberos_golden_ticket_fires_only_when_suspicious():
    susp = [{"Source": "CACHE", "TicketType": "TGT", "Client": "administrator",
             "Server": "krbtgt/CORP", "EncType": "rc4_hmac", "Suspicious": True,
             "_client_id": "C.dc", "_hostname": "DC01"}]
    benign = [{"Source": "CACHE", "TicketType": "TGS", "Client": "alice", "Server": "cifs/fs01",
               "EncType": "aes256", "Suspicious": False,
               "_client_id": "C.dc", "_hostname": "DC01"}]
    g_s = correlate.assemble("k", [map_agentic({"Windows.Kerberos.GoldenTicketTriage": susp},
                                               run_id="a", hostnames={"C.dc": "DC01"})], ["a"])
    g_b = correlate.assemble("k", [map_agentic({"Windows.Kerberos.GoldenTicketTriage": benign},
                                               run_id="a", hostnames={"C.dc": "DC01"})], ["a"])
    assert any("Kerberos" in f.title for f in g_s.findings), "Suspicious TGT must fire a finding"
    assert any("T1558" in f.mitre for f in g_s.findings)
    assert not any("Kerberos" in f.title for f in g_b.findings), "benign ticket must not fire"


def test_benign_local_logons_stay_silent():
    # local workgroup logons on one host -> account keyed locally, no cross-host, no finding.
    rows = [{"EventTime": "2026-05-19T09:00:00Z", "Computer": "WS", "EventID": 4624,
             "DomainName": "WORKGROUP", "UserName": "user", "LogonType": 2,
             "_client_id": "C.ws", "_hostname": "WS"}]
    g = correlate.assemble("auth", [map_agentic({"Windows.EventLogs.LogonSessions": rows},
                                                run_id="a", hostnames={"C.ws": "WS"})], ["a"])
    from services.fusion import severity as sev
    assert not [f for f in g.findings if sev.at_least(f.severity, "high")], \
        "benign single-host logons must produce no high findings"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    p = f = 0
    for fn in fns:
        try:
            fn(); p += 1; print(f"PASS {fn.__name__}")
        except AssertionError as e:
            f += 1; print(f"FAIL {fn.__name__}: {e}")
    print(f"{p}/{len(fns)} passed")
    sys.exit(1 if f else 0)
