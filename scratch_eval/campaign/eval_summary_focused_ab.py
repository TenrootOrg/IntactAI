"""Focused-path A/B for the '## Other severe findings' section.

The macro fix measured 68% -> 94%, but eval_summary_accuracy.py FORCES the macro
prompt, so it never exercised the focused path -- which is the one a real case with
a time window / severity floor actually takes, and which is MORE exposed (it commits
to "the single most likely intrusion story").

Both arms run identical code; the control arm strips the section out of the prompt
string at runtime, so nothing but the prompt differs.

  cd /app/scratch_eval && PYTHONPATH=/app:/app/scratch_eval/campaign \
      python3 campaign/eval_summary_focused_ab.py [N]
"""
import json
import os
import sys
from collections import Counter

sys.path.insert(0, "/app")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from services.fusion.mappers.agentic import map_agentic  # noqa: E402
from services.fusion import correlate, render, llm_sim  # noqa: E402
import attack_corpus as corpus  # noqa: E402
from rescore_summaries import SYN  # noqa: E402

N = int(sys.argv[1]) if sys.argv[1:] else 10
OUT = "/tmp/eval_out/campaign"
os.makedirs(OUT, exist_ok=True)
ws = __import__("services.fusion.store", fromlist=["x"])._ws()

FIXED = llm_sim.REPORT_SYSTEM_PROMPT_FOCUSED
_i = FIXED.find("## Other severe findings")
_j = FIXED.find("## Do next", _i)
assert _i > 0 and _j > _i, "section markers not found in FOCUSED prompt"
CONTROL = FIXED[:_i] + FIXED[_j:]          # the prompt exactly as it was before
assert "Other severe findings" not in CONTROL


def fuse():
    tele = corpus.build_all_telemetry()
    e, r = map_agentic(tele, run_id="ab", hostnames={})
    return correlate.assemble("ab", [(e, r)], ["ab"])


def eligible(g):
    texts = [f"{f.title} {' '.join(render._host_label(g, a) for a in (f.asset_ids or []))}".lower()
             for f in g.findings]
    out = []
    for s in corpus.SCENARIOS:
        kws = [k.lower() for k in s["expect"]["find"]]
        if any(all(k in t for k in kws) for t in texts):
            out.append(s)
    return out


def main():
    g = fuse()
    elig = eligible(g)
    alt, why = render._resolve_altitude(g)
    payload = json.dumps(render.distilled(g, max_entities=500, budget_chars=90000,
                                          detail="explicit"), default=str)
    print("case: %d hosts, %d findings; %d eligible plants; natural altitude=%s (%s)"
          % (len(g.by_type("asset")), len(g.findings), len(elig), alt, why), flush=True)

    results = {}
    for arm, system in (("control", CONTROL), ("fixed", FIXED)):
        hits, per_run = Counter(), []
        for i in range(1, N + 1):
            rid = ws.create_automation_run("focus_ab", "%s%d" % (arm, i))
            try:
                rep = llm_sim._real_llm(system, payload, run_id=rid)
            except Exception as e:  # noqa: BLE001
                rep = "(ERROR %s)" % e
            low = rep.lower()
            found = [s["id"] for s in elig
                     if any(k in low for k in
                            (SYN.get(s["id"]) or [k2.lower() for k2 in s["expect"]["find"]]))]
            for sid in found:
                hits[sid] += 1
            per_run.append(len(found))
            open("%s/focus_%s_%d.md" % (OUT, arm, i), "w").write(rep)
            print("[%s %d/%d] %d/%d plants, %dc"
                  % (arm, i, N, len(found), len(elig), len(rep)), flush=True)
        never = [s["id"] for s in elig if hits[s["id"]] == 0]
        results[arm] = {"per_run": per_run, "mean": sum(per_run) / len(per_run),
                        "never": never, "eligible": len(elig)}

    c, f = results["control"], results["fixed"]
    md = ["# Focused-path A/B — '## Other severe findings'", "",
          "Both arms identical except the prompt; the control strips the section at "
          "runtime. n=%d per arm." % N, "",
          "| Arm | Mean coverage | Never surfaced | Per-run |",
          "|---|---|---|---|",
          "| control (before) | %.1f/%d (%.0f%%) | %d | %s |"
          % (c["mean"], c["eligible"], 100 * c["mean"] / c["eligible"], len(c["never"]),
             ", ".join(map(str, c["per_run"]))),
          "| fixed (after) | %.1f/%d (%.0f%%) | %d | %s |"
          % (f["mean"], f["eligible"], 100 * f["mean"] / f["eligible"], len(f["never"]),
             ", ".join(map(str, f["per_run"]))),
          "", "Control blind spots: %s" % (", ".join(c["never"]) or "none"),
          "", "Fixed blind spots: %s" % (", ".join(f["never"]) or "none")]
    out = "\n".join(md) + "\n"
    open("%s/summary_focused_ab.md" % OUT, "w").write(out)
    json.dump(results, open("%s/summary_focused_ab.json" % OUT, "w"), indent=2)
    print()
    print(out)


if __name__ == "__main__":
    main()
