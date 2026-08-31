"""Synthetic fused-graph generator for the report-strategy eval.

Builds a FusionGraph of arbitrary scope shape (N hosts x T-day timeframe x F
findings, with cross-host identities) so we can test the altitude ladder across
the matrix — many/few endpoints x long/short timeframe — without real collections.
Plausible SIGMA-style findings so the LLM has realistic content to reason over.
"""
import random, datetime
from services.fusion.schema import FusionGraph, Entity, Finding

_TECH = [
    ("HackTool - Mimikatz Execution", ["T1003.001"], "high"),
    ("Windows Defender Real-time Protection Disabled", ["T1562.001"], "high"),
    ("Suspicious Encoded PowerShell", ["T1059.001"], "medium"),
    ("Rubeus Kerberos Ticket Request", ["T1558.003"], "high"),
    ("Suspicious Service Installation", ["T1543.003"], "medium"),
    ("Security Event Log Cleared", ["T1070.001"], "high"),
    ("SharpHound / BloodHound Collection", ["T1087.002"], "medium"),
    ("Non-standard Outbound RDP", ["T1021.001"], "medium"),
    ("LSASS Memory Access", ["T1003.001"], "high"),
    ("Cobalt Strike Named Pipe", ["C2-CobaltStrike"], "critical"),
    ("Scheduled Task Persistence", ["T1053.005"], "low"),
    ("WMI Event Consumer Persistence", ["T1546.003"], "medium"),
    ("Renamed System Binary (procdump/adfind)", ["T1036.003"], "medium"),
]
_ROLE = {0: "DC01", 1: "DC02", 2: "CA01", 3: "MECM01"}   # first few hosts are tier-zero


def synth(hosts, span_days, findings, cross_host=None, seed=7):
    rnd = random.Random(seed)
    now = datetime.datetime(2026, 8, 31, tzinfo=datetime.timezone.utc)
    start = now - datetime.timedelta(days=max(1, span_days))

    def at(frac):
        return (start + (now - start) * frac).strftime("%Y-%m-%dT%H:%M:%SZ")

    g = FusionGraph(case_id=f"synth_h{hosts}_d{span_days}_f{findings}")
    names = []
    for i in range(hosts):
        hn = _ROLE.get(i) or f"WKS{i:03d}"
        names.append(hn)
        aid = f"asset:endpoint:C.h{i:04d}"
        g.entities[aid] = Entity(id=aid, type="asset", label=hn, severity="informational",
                                 attrs={"hostname": hn, "_assets": [aid], "modules": ["velociraptor"]})
    A = lambda i: f"asset:endpoint:C.h{i:04d}"

    # a handful of accounts that recur across hosts -> identities + cross-host findings
    naccts = max(1, hosts // 8)
    accts = [f"adatumlab\\svc{j}" for j in range(naccts)]
    for j, a in enumerate(accts):
        seen = rnd.sample(range(hosts), min(hosts, rnd.randint(2, min(6, hosts))))
        eid = f"account:{a}"
        g.entities[eid] = Entity(id=eid, type="account", label=a, severity="medium",
                                 anomaly=10, first_seen=at(rnd.random()),
                                 attrs={"_assets": [A(x) for x in seen]})

    if cross_host is None:
        cross_host = max(1, findings // 12) if hosts > 1 else 0

    for k in range(findings):
        t = at(rnd.random())
        if k < cross_host and hosts > 1:
            acct = rnd.choice(accts)
            hs = rnd.sample(range(hosts), min(hosts, rnd.randint(2, min(6, hosts))))
            g.findings.append(Finding(
                id=f"f_ch_{k}", title=f"Account {acct} used across {len(hs)} hosts",
                severity="high", confidence="high", kind="cross_host",
                summary=(f"The account {acct} authenticated/executed on "
                         f"{', '.join(names[x] for x in hs)} at {t} — consistent with "
                         f"lateral movement using shared credentials."),
                asset_ids=[A(x) for x in hs], entity_ids=[f"account:{acct}"],
                mitre=["T1021", "T1078"], ts=t))
        else:
            tech, mitre, sev = rnd.choice(_TECH)
            hi = rnd.randrange(hosts)
            g.findings.append(Finding(
                id=f"f_{k}", title=f"{tech} on {names[hi]}",
                severity=sev, confidence=rnd.choice(["high", "medium"]),
                summary=f"SIGMA rule '{tech}' matched on {names[hi]} at {t}.",
                asset_ids=[A(hi)], mitre=mitre, ts=t))

    d = {"time_window": {"start": "2016-08-31T00:00:00", "end": "2026-08-31T00:00:00"},
         "min_severity": "informational", "max_entities": 500000}
    return g, d


# The scope matrix: many/few endpoints x long/short timeframe (+ two middles).
MATRIX = {
    "many_long":  (100, 365, 220),   # full org, 1 year   -> expect MACRO
    "many_short": (100, 3, 70),      # full org, 3 days    -> ?
    "few_long":   (3, 365, 45),      # few hosts, 1 year   -> ?
    "few_short":  (3, 7, 14),        # few hosts, 1 week   -> expect FOCUSED
    "mid":        (25, 60, 90),      # mid both            -> ?
}
