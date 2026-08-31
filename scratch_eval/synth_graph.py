"""Synthetic fused-graph generator for the report-strategy eval.

Builds a FusionGraph of arbitrary scope shape (N hosts x T-day timeframe x F
findings, with cross-host identities) so we can test the altitude ladder across
the matrix — many/few endpoints x long/short timeframe — without real collections.
Plausible SIGMA-style findings so the LLM has realistic content to reason over.
"""
import random, datetime
from services.fusion.schema import FusionGraph, Entity, Finding, EvidenceRef

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


_ARTIFACT = "Windows.EventLogs.Evidence"
_CMDS = [
    ("mimikatz.exe sekurlsa::logonpasswords", "b" * 64),
    ("rubeus.exe asktgt /user:svc /ptt", "c" * 64),
    ("powershell -enc SQBFAFgA...", "d" * 64),
    ("wevtutil cl Security", "e" * 64),
    ("cmd.exe /c whoami /all", "f" * 64),
]


def add_events(g, d, *, run_id="synthrun1", per_finding=3, seed=7):
    """Extend a synth graph with EVENT entities (ev_* attrs) + EvidenceRef locators
    on both the events and their findings, and return the matching raw-rows source
    {artifact: [row,...]} so evidence()/pivot() resolve. This is what lets the
    agentic tools run at synthetic scale — synth graphs otherwise have no event
    entities and no evidence refs (report-path only).

    Returns (raw_rows, run_id). Feed raw_rows to evidence() by monkeypatching
    store._agentic_collected_data(run_id) -> raw_rows (see agentic_synthscale.py)."""
    rnd = random.Random(seed)
    rows = []
    g.note_run(run_id)
    for f in g.findings:
        host_ids = f.asset_ids or []
        host_lbl = [g.entities[a].label for a in host_ids if a in g.entities]
        for j in range(per_finding):
            cmd, sha = rnd.choice(_CMDS)
            acct = f"adatumlab\\svc{rnd.randrange(4)}"
            idx = len(rows)
            row = {"EventTime": f.ts, "Computer": (host_lbl[0] if host_lbl else "WKS000"),
                   "User": acct, "CommandLine": cmd, "SHA256": sha,
                   "TargetIP": f"10.0.{rnd.randrange(255)}.{rnd.randrange(255)}"}
            rows.append(row)
            ref = EvidenceRef(module="velociraptor", run_id=run_id,
                              locator=f"{_ARTIFACT}/row={idx}")
            eid = f"event:{f.id}:{j}"
            g.entities[eid] = Entity(
                id=eid, type="event", label=f"{cmd[:24]} on {row['Computer']}",
                severity=f.severity, first_seen=f.ts,
                attrs={"_assets": host_ids, "ev_user": acct, "ev_proc": cmd.split()[0],
                       "ev_cmdline": cmd, "ev_sha256": sha, "ev_tgtip": row["TargetIP"]},
                sources=["velociraptor"], evidence=[ref])
            f.entity_ids = list(f.entity_ids or []) + [eid]
            f.evidence = list(f.evidence or []) + [ref]
    return {_ARTIFACT: rows}, run_id


# The scope matrix: many/few endpoints x long/short timeframe (+ two middles).
MATRIX = {
    "many_long":  (100, 365, 220),   # full org, 1 year   -> expect MACRO
    "many_short": (100, 3, 70),      # full org, 3 days    -> ?
    "few_long":   (3, 365, 45),      # few hosts, 1 year   -> ?
    "few_short":  (3, 7, 14),        # few hosts, 1 week   -> expect FOCUSED
    "mid":        (25, 60, 90),      # mid both            -> ?
}
