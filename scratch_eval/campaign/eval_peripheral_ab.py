"""The decisive test for '## Other severe findings': a case with PERIPHERAL hosts.

The 41-scenario corpus cannot test this section. Its 8 hosts are all part of one
story, so a single-story narrative has nothing to leave out — control and fixed both
scored 35.8/37.

The real Default case has a different shape: one dominant host carrying the intrusion
story, plus peripheral hosts whose own high-severity findings belong to no story at
all. That is the condition the section exists for, and it is where the section
surfaced three hosts the narrative had never mentioned.

This builds that shape deliberately: one host with a dense, coherent attack chain, and
N peripheral hosts each with a single unrelated high finding. Scoring asks only one
question — are the PERIPHERAL hosts named at all?

  cd /app/scratch_eval && PYTHONPATH=/app:/app/scratch_eval/campaign \
      python3 campaign/eval_peripheral_ab.py [N]
"""
import json
import os
import sys

sys.path.insert(0, "/app")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from services.fusion import schema, render, llm_sim  # noqa: E402

N = int(sys.argv[1]) if sys.argv[1:] else 10
OUT = "/tmp/eval_out/campaign"
os.makedirs(OUT, exist_ok=True)
ws = __import__("services.fusion.store", fromlist=["x"])._ws()

FIXED = llm_sim.REPORT_SYSTEM_PROMPT_FOCUSED
_i = FIXED.find("## Other severe findings")
_j = FIXED.find("## Do next", _i)
assert _i > 0 and _j > _i
CONTROL = FIXED[:_i] + FIXED[_j:]

# One dominant host: a coherent 8-step intrusion the narrative will want to tell.
STORY = [
    ("Security event log cleared", "high", "2026-08-01T09:00:00Z"),
    ("Encoded PowerShell execution", "high", "2026-08-01T09:01:00Z"),
    ("PowerShell running as SYSTEM", "high", "2026-08-01T09:02:00Z"),
    ("Mimikatz LSASS credential dumping", "critical", "2026-08-01T09:05:00Z"),
    ("Driver loaded from temporary directory", "high", "2026-08-01T09:10:00Z"),
    ("WMI persistence subscription created", "high", "2026-08-01T09:20:00Z"),
    ("Code injection into explorer.exe", "critical", "2026-08-01T09:30:00Z"),
    ("Rclone cloud exfiltration", "high", "2026-08-01T10:00:00Z"),
]
# Peripheral hosts: one unrelated HIGH finding each, part of no story.
PERIPHERAL = [
    ("PERIPH-01", "Advanced IP Scanner downloaded", "2026-08-03T11:00:00Z"),
    ("PERIPH-02", "7-Zip archive utility retrieved", "2026-08-04T12:00:00Z"),
    ("PERIPH-03", "Direct-IP browsing to 20.77.72.232", "2026-08-05T13:00:00Z"),
    ("PERIPH-04", "SharpHound BloodHound collection", "2026-08-06T14:00:00Z"),
    ("PERIPH-05", "UAC bypass via Fodhelper registry hijack", "2026-08-07T15:00:00Z"),
]


def build():
    g = schema.FusionGraph(case_id="periph")
    g.entities["asset:main"] = schema.Entity(id="asset:main", type="asset",
                                             label="MAIN-HOST", severity="critical")
    for i, (title, sv, ts) in enumerate(STORY):
        g.findings.append(schema.Finding(
            id="s%d" % i, title="%s on MAIN-HOST" % title, severity=sv,
            confidence="high", summary="", asset_ids=["asset:main"], ts=ts))
    for i, (host, title, ts) in enumerate(PERIPHERAL):
        hid = "asset:p%d" % i
        g.entities[hid] = schema.Entity(id=hid, type="asset", label=host, severity="high")
        g.findings.append(schema.Finding(
            id="p%d" % i, title="%s on %s" % (title, host), severity="high",
            confidence="medium", summary="", asset_ids=[hid], ts=ts))
    return g


def main():
    g = build()
    alt, why = render._resolve_altitude(g)
    payload = json.dumps(render.distilled(g, max_entities=500, budget_chars=90000,
                                          detail="explicit"), default=str)
    print("case: %d hosts, %d findings (%d story + %d peripheral); altitude=%s (%s)"
          % (len(g.by_type("asset")), len(g.findings), len(STORY), len(PERIPHERAL),
             alt, why), flush=True)

    res = {}
    for arm, system in (("control", CONTROL), ("fixed", FIXED)):
        per_run = []
        for i in range(1, N + 1):
            rid = ws.create_automation_run("periph_ab", "%s%d" % (arm, i))
            try:
                rep = llm_sim._real_llm(system, payload, run_id=rid)
            except Exception as e:  # noqa: BLE001
                rep = "(ERROR %s)" % e
            low = rep.lower()
            named = [h for h, _t, _ts in PERIPHERAL if h.lower() in low]
            per_run.append(len(named))
            open("%s/periph_%s_%d.md" % (OUT, arm, i), "w").write(rep)
            print("[%s %d/%d] %d/%d peripheral hosts named, %dc"
                  % (arm, i, N, len(named), len(PERIPHERAL), len(rep)), flush=True)
        res[arm] = {"per_run": per_run, "mean": sum(per_run) / len(per_run)}

    c, f = res["control"], res["fixed"]
    md = ["# Peripheral-host A/B — the decisive test for '## Other severe findings'", "",
          "One dominant host with a coherent %d-step intrusion, plus %d peripheral hosts "
          "each carrying ONE unrelated high finding. Scored only on whether the "
          "peripheral hosts are named at all. n=%d per arm."
          % (len(STORY), len(PERIPHERAL), N), "",
          "| Arm | Peripheral hosts named | Per-run |", "|---|---|---|",
          "| control (before) | %.1f/%d (%.0f%%) | %s |"
          % (c["mean"], len(PERIPHERAL), 100 * c["mean"] / len(PERIPHERAL),
             ", ".join(map(str, c["per_run"]))),
          "| fixed (after) | %.1f/%d (%.0f%%) | %s |"
          % (f["mean"], len(PERIPHERAL), 100 * f["mean"] / len(PERIPHERAL),
             ", ".join(map(str, f["per_run"])))]
    out = "\n".join(md) + "\n"
    open("%s/peripheral_ab.md" % OUT, "w").write(out)
    json.dump(res, open("%s/peripheral_ab.json" % OUT, "w"), indent=2)
    print()
    print(out)


if __name__ == "__main__":
    main()
