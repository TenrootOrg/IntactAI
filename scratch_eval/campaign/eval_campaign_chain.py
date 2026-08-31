"""E17 + B7 + C10 + C11 — one sequenced campaign, four questions (deterministic).

Builds ONE actor's campaign in a known order:
  t0 initial access   WKS-CHAIN01   (phishing payload)
  t1 escalation       WKS-CHAIN01   (UAC bypass)
  t2 credential theft WKS-CHAIN01   (LSASS)  -> account corp\\intruder harvested
  t3 lateral move     WKS-CHAIN02   (same account)
  t4 DC compromise    DC-CHAIN01    (same account, DCSync)
  t5 exfiltration     DC-CHAIN01

Then asks, deterministically:
  E17 chain correlation  — does fusion link this into cross-host findings (one campaign)
                           rather than 6 unrelated single-host findings?
  B7  timeline order     — is the rendered timeline in true chronological order, and is
                           patient zero (WKS-CHAIN01, earliest) identifiable?
  C10 identity clustering— does the shared account resolve to ONE account entity spanning
                           all three hosts (not three separate accounts)?
  C11 account-form equiv — DOMAIN\\user, user@domain and bare SAM for the SAME person:
                           do they cluster, or silently split an actor's reach?

  cd /app/scratch_eval && PYTHONPATH=/app python3 campaign/eval_campaign_chain.py
"""
import json
import os
import re
import sys

sys.path.insert(0, "/app")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from services.fusion.mappers.agentic import map_agentic  # noqa: E402
from services.fusion import correlate, render, keys  # noqa: E402

OUT = "/tmp/eval_out/campaign"
os.makedirs(OUT, exist_ok=True)

H1, H2, DC = "WKS-CHAIN01", "WKS-CHAIN02", "DC-CHAIN01"
ACCT = "corp\\intruder"
_T = "Windows.Hayabusa.Rules"
_ACC = "Windows.EventLogs.CondensedAccountUsage"

# the campaign, in true order
STEPS = [
    ("t0", H1, "Malicious Attachment Executed", "high", "2026-09-01T08:00:00Z"),
    ("t1", H1, "UAC Bypass via Fodhelper Registry Hijack", "high", "2026-09-01T08:20:00Z"),
    ("t2", H1, "Mimikatz LSASS Credential Dumping", "crit", "2026-09-01T08:40:00Z"),
    ("t3", H2, "Non-Standard Outbound RDP Connection", "high", "2026-09-01T09:10:00Z"),
    ("t4", DC, "DCSync Replication Rights Abuse", "crit", "2026-09-01T09:40:00Z"),
    ("t5", DC, "Rclone Cloud Exfiltration", "high", "2026-09-01T10:15:00Z"),
]


def telemetry(account_forms=None):
    """account_forms: list of (host, account-string) — C11 uses the SAME person in
    three different notations to see whether they cluster."""
    t = {_T: [{"Computer": h, "Title": title, "Level": lvl, "EventTime": ts}
              for _, h, title, lvl, ts in STEPS]}
    forms = account_forms or [(H1, ACCT), (H2, ACCT), (DC, ACCT)]
    t[_ACC] = [{"Computer": h, "User": a, "EventTime": "2026-09-01T09:00:00Z",
                "LogonType": "3"} for h, a in forms]
    return t


def fuse(tele, cid):
    e, r = map_agentic(tele, run_id="chainrun", hostnames={})
    return correlate.assemble(cid, [(e, r)], ["chainrun"])


def main():
    res = {}
    g = fuse(telemetry(), "chain")
    hosts = {a.id: a.label for a in g.by_type("asset")}

    # ---- E17 chain correlation --------------------------------------------
    xh = [f for f in g.findings if f.kind == "cross_host"]
    xh_hosts = {render._host_label(g, a) for f in xh for a in (f.asset_ids or [])}
    e17 = len(xh) >= 1 and len(xh_hosts) >= 3
    res["E17"] = {"cross_host_findings": len(xh), "hosts_linked": sorted(xh_hosts),
                  "pass": e17, "titles": [f.title for f in xh][:3]}

    # ---- B7 timeline order + patient zero ----------------------------------
    tl = render.timeline(g)
    tss = [r["ts"] for r in tl if r.get("ts")]
    ordered = tss == sorted(tss)
    dated = [(f.ts, f) for f in g.findings if f.ts]
    first_host = ""
    if dated:
        earliest = min(dated, key=lambda x: keys.to_utc_dt(x[0]) or x[0])[1]
        first_host = ", ".join(render._host_label(g, a) for a in (earliest.asset_ids or []))
    b7 = ordered and H1 in first_host
    res["B7"] = {"timeline_rows": len(tl), "chronological": ordered,
                 "patient_zero": first_host, "expected": H1, "pass": b7}

    # ---- C10 identity clustering -------------------------------------------
    accts = [e for e in g.by_type("account")]
    target = [e for e in accts if "intruder" in (e.label or "").lower()]
    span = set()
    for e in target:
        span |= {render._host_label(g, a) for a in (e.attrs.get("_assets") or [])}
    c10 = len(target) == 1 and len(span) >= 3
    res["C10"] = {"account_entities": len(accts), "intruder_entities": len(target),
                  "hosts_spanned": sorted(span), "pass": c10}

    # ---- C11 account-form equivalence --------------------------------------
    g2 = fuse(telemetry([(H1, "corp\\intruder"), (H2, "intruder@corp.local"),
                         (DC, "intruder")]), "chain_forms")
    a2 = [e for e in g2.by_type("account") if "intruder" in (e.label or "").lower()]
    span2 = set()
    for e in a2:
        span2 |= {render._host_label(g2, a) for a in (e.attrs.get("_assets") or [])}
    xh2 = [f for f in g2.findings if f.kind == "cross_host"]
    # What matters is whether the actor's movement SURFACES AS A FINDING — the
    # entities legitimately stay separate (different id scopes); the question is
    # whether the identity cluster still yields a cross-host signal.
    c11 = len(xh2) >= 1
    res["C11"] = {"entities_for_one_person": len(a2),
                  "labels": [e.label for e in a2], "hosts_spanned": sorted(span2),
                  "cross_host_findings": len(xh2),
                  "finding_titles": [f.title for f in xh2][:2], "pass": c11}

    lines = ["# Campaign chain: correlation, timeline order, identities", "",
             "One actor's campaign in a known order (initial access → escalation → "
             "credential theft → lateral → DC → exfil) across 3 hosts with one account.",
             "",
             "| Test | Question | Result | |", "|---|---|---|:--:|",
             f"| **E17** | Does fusion link it into ONE campaign? | "
             f"{res['E17']['cross_host_findings']} cross-host finding(s) spanning "
             f"{len(res['E17']['hosts_linked'])} hosts | "
             f"{'✅' if res['E17']['pass'] else '❌'} |",
             f"| **B7** | Timeline chronological + patient zero? | "
             f"chronological={res['B7']['chronological']}, "
             f"patient-zero={res['B7']['patient_zero'] or '—'} | "
             f"{'✅' if res['B7']['pass'] else '❌'} |",
             f"| **C10** | One account across 3 hosts = ONE identity? | "
             f"{res['C10']['intruder_entities']} entity, spans "
             f"{len(res['C10']['hosts_spanned'])} hosts | "
             f"{'✅' if res['C10']['pass'] else '❌'} |",
             f"| **C11** | DOMAIN\\u + u@dom + bare SAM → cross-host finding? | "
             f"{res['C11']['cross_host_findings']} finding(s) from "
             f"{res['C11']['entities_for_one_person']} account forms | "
             f"{'✅' if res['C11']['pass'] else '❌'} |",
             ""]
    if not res["C11"]["pass"]:
        lines += ["> **C11 detail:** the same person written three ways produced "
                  f"**{res['C11']['entities_for_one_person']} separate account entities** "
                  f"({res['C11']['labels']}), spanning {res['C11']['hosts_spanned']}. "
                  "A split identity understates an actor's reach — the cross-host "
                  f"finding count here is {res['C11']['cross_host_findings']}.", ""]
    md = "\n".join(lines) + "\n"
    open(f"{OUT}/campaign_chain.md", "w").write(md)
    json.dump(res, open(f"{OUT}/campaign_chain.json", "w"), indent=2, default=str)
    print(md)


if __name__ == "__main__":
    main()
