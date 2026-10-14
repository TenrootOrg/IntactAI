"""Score a case's fusion + report against a public dataset's answer key.

    docker cp scripts/dev/groundtruth_eval.py scripts/dev/groundtruth_steps.json intact_backend:/tmp/
    docker exec -w /app intact_backend python3 /tmp/groundtruth_eval.py <dataset> <case_id> [--json]

datasets: szechuan, apt29_day1, apt29_day2, apt29_both (= day1 + day2 steps + combining traps).

Each STEP is a key attack step from the audits (simulations/audit/, 2026-10-14) with a regex that must be
found (a) in the fused findings -- titles, summaries, burst parts and the attrs of the entities they cite --
and (b) in the report text. Each TRAP is a known-false claim the report must NOT make. Read-only: it only
loads the stored graph and report. A step missing from the graph cannot reach the report, so the two columns
say WHERE it is lost: graph=no -> fusion, graph=yes report=no -> the report.

The regexes are deliberately about the FACT (a file name, an IP, a technique word), not about Intact's
wording, so a better narrative scores higher and a reworded one does not break the score.
"""
import json
import os
import re
import sys

sys.path.insert(0, "/app")
from services.fusion import store  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def graph_text(g) -> str:
    out = []
    for f in g.findings:
        out.append(json.dumps(f.to_dict(), default=str))
        for eid in (f.entity_ids or [])[:60]:
            e = g.entities.get(eid)
            if e is not None:
                out.append(json.dumps([e.label, e.attrs], default=str)[:4000])
    return "\n".join(out)


def main():
    ds, cid = sys.argv[1], sys.argv[2]
    spec = json.load(open(os.path.join(HERE, "groundtruth_steps.json")))
    # A combined dataset inherits its parts' STEPS but declares its own TRAPS: "UTICA is involved" is a
    # false claim for Day 1 alone and a true one once Day 2 is in the same case.
    steps = [s for part in spec[ds].get("include", [ds]) for s in spec[part]["steps"]]
    traps = spec[ds].get("traps", [])
    g = store.load_graph(cid)
    gt = graph_text(g)
    rep = (store.get_case(cid) or {}).get("report_md") or ""
    rows, ng, nr = [], 0, 0
    for s in steps:
        rx = re.compile(s["rx"], re.I | re.S)
        in_g = bool(rx.search(gt))
        in_r = bool(re.compile(s.get("report_rx", s["rx"]), re.I | re.S).search(rep))
        ng += in_g
        nr += in_r
        rows.append((s["id"], s["what"], in_g, in_r))
    hits = [(t["id"], t["what"]) for t in traps if re.search(t["rx"], rep, re.I | re.S)]
    if "--json" in sys.argv:
        print(json.dumps({"dataset": ds, "case": cid, "steps": len(steps), "in_graph": ng, "in_report": nr,
                          "traps_hit": [h[0] for h in hits], "rows": rows}))
        return
    print(f"{ds} · {cid} · {len(g.findings)} findings · report {len(rep):,} chars")
    print(f"{'step':<18} {'graph':<6} {'report':<7} what")
    for sid, what, a, b in rows:
        print(f"{sid:<18} {'yes' if a else '-':<6} {'yes' if b else '-':<7} {what}")
    print(f"\nSTEPS  in graph {ng}/{len(steps)}   in report {nr}/{len(steps)}")
    print(f"TRAPS  {len(hits)}/{len(traps)} false claims made" + "".join(f"\n  ! {i}: {w}" for i, w in hits))


if __name__ == "__main__":
    main()
