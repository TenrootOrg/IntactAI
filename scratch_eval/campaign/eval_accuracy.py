"""Ground-truth ACCURACY eval — run the attack corpus through the REAL pipeline and
score recall / precision / grounding against the answer key. This measures detection
ACCURACY (did we find what was planted?), which every prior eval skipped.

  cd /app/scratch_eval && PYTHONPATH=/app python3 campaign/eval_accuracy.py per      # per-scenario (deterministic, no model)
  cd /app/scratch_eval && PYTHONPATH=/app python3 campaign/eval_accuracy.py combined  # fuse all -> report + investigate (model)
"""
import json
import os
import re
import sys

sys.path.insert(0, "/app")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from services.fusion.mappers.agentic import map_agentic  # noqa: E402
from services.fusion import correlate, render, store, llm_sim, investigate  # noqa: E402
import attack_corpus as corpus  # noqa: E402

OUT = "/tmp/eval_out/campaign"
os.makedirs(OUT, exist_ok=True)


def _fuse(telemetry, case_id):
    ents, rels = map_agentic(telemetry, run_id="evalrun", hostnames={})
    return correlate.assemble(case_id, [(ents, rels)], ["evalrun"])


def _finding_texts(g):
    return [f"{f.title} :: {' '.join(render._host_label(g, a) for a in (f.asset_ids or []))}"
            .lower() for f in g.findings]


def score_scenario(s):
    g = _fuse(s["telemetry"], s["id"])
    fts = _finding_texts(g)
    host = s["host"].lower()
    kws = [k.lower() for k in s["expect"]["find"]]
    # RECALL: a finding exists whose text contains every keyword AND names the host
    hit = next((t for t in fts if all(k in t for k in kws)), None)
    recalled = hit is not None
    grounded = bool(hit) and host in hit
    # SEVERITY match (grounding of criticality)
    want_sev = s["expect"].get("sev")
    sev_ok = (not want_sev) or any(
        f.severity == want_sev for f in g.findings
        if all(k in f.title.lower() for k in kws))
    return {"id": s["id"], "name": s["name"], "tech": s["tech"],
            "findings": len(g.findings), "recall": recalled,
            "grounded_host": grounded, "severity_ok": sev_ok,
            "matched": hit or "(none)"}


def cmd_per():
    rows = [score_scenario(s) for s in corpus.SCENARIOS]
    rec = sum(r["recall"] for r in rows)
    gnd = sum(r["grounded_host"] for r in rows)
    sev = sum(r["severity_ok"] for r in rows)
    n = len(rows)
    lines = ["# Attack-simulation ACCURACY — per scenario (deterministic)", "",
             f"{n} authored PowerShell attack scenarios through the REAL pipeline "
             "(map_agentic -> correlate.assemble). Recall = the planted technique "
             "surfaced as a finding on the right host.", "",
             f"**Recall {rec}/{n} ({round(100*rec/n)}%) · Host-grounded {gnd}/{n} · "
             f"Severity-correct {sev}/{n}**", "",
             "| # | Scenario | ATT&CK | Detected | Host✓ | Sev✓ | Matched finding |",
             "|---|---|---|:--:|:--:|:--:|---|"]
    for i, r in enumerate(rows, 1):
        lines.append(f"| {i} | {r['name']} | {r['tech']} | "
                     f"{'✅' if r['recall'] else '❌ MISS'} | "
                     f"{'✅' if r['grounded_host'] else '—'} | "
                     f"{'✅' if r['severity_ok'] else '—'} | `{r['matched'][:60]}` |")
    md = "\n".join(lines) + "\n"
    open(f"{OUT}/accuracy_per_scenario.md", "w").write(md)
    json.dump({"rows": rows, "recall": rec, "n": n}, open(f"{OUT}/accuracy_per_scenario.json", "w"),
              indent=2, default=str)
    print(md)


# ---- combined incident: fuse ALL, run the model, score whether it surfaced each plant
_JUDGE = (
    "You are grading a DFIR tool's INCIDENT REPORT for detection ACCURACY against a "
    "known ANSWER KEY of what was actually done. For each planted technique say if the "
    "report clearly surfaces it (mentions the activity on the right host). Then rate "
    "recall_pct (0-100, how many plants surfaced), false_positive_risk (0-100, invented "
    "activity not in the key), grounding (0-100, claims tied to real host/time). STRICT "
    'JSON only: {"per_plant":[{"id":"..","surfaced":true/false}],"recall_pct":n,'
    '"false_positive_risk":n,"grounding":n,"verdict":"one line"}')


def cmd_combined():
    ws = store._ws()
    tele = corpus.build_all_telemetry()
    g = _fuse(tele, "eval_combined")
    print(f"combined case: {len(g.by_type('asset'))} hosts, {len(g.findings)} findings", flush=True)
    # deterministic recall on the combined graph
    fts = _finding_texts(g)
    key = [{"id": s["id"], "kws": [k.lower() for k in s["expect"]["find"]],
            "host": s["host"].lower(), "activity": s["activity"]} for s in corpus.SCENARIOS]
    det = [{"id": k["id"], "surfaced": any(all(w in t for w in k["kws"]) and k["host"] in t
                                           for t in fts)} for k in key]
    det_recall = sum(d["surfaced"] for d in det)
    print(f"deterministic recall on combined graph: {det_recall}/{len(key)}", flush=True)

    # REPORT — generate over the combined case and judge for accuracy vs the key
    payload = render.distilled(g, max_entities=400, budget_chars=60000, detail="summary")
    rid = ws.create_automation_run("acc_report", "combined")
    report = llm_sim._real_llm(llm_sim.REPORT_SYSTEM_PROMPT_MACRO, json.dumps(payload, default=str),
                               run_id=rid)
    answer_key = "\n".join(f"- {s['id']}: {s['activity']} (host {s['host']}, {s['tech']})"
                           for s in corpus.SCENARIOS)
    jrid = ws.create_automation_run("acc_judge", "combined")
    jraw = llm_sim._real_llm(_JUDGE, f"ANSWER KEY (what was actually done):\n{answer_key}\n\n"
                             f"REPORT UNDER TEST:\n{report}", run_id=jrid)
    try:
        verdict = json.loads(jraw[jraw.index("{"): jraw.rindex("}") + 1])
    except Exception:
        verdict = {"error": jraw[:300]}

    lines = ["# Attack-simulation ACCURACY — combined incident (model)", "",
             f"All {len(corpus.SCENARIOS)} scenarios fused into one case "
             f"({len(g.by_type('asset'))} hosts, {len(g.findings)} findings).", "",
             f"**Deterministic finding-level recall: {det_recall}/{len(key)}**", "",
             "## LLM-judged report accuracy (vs answer key)",
             f"- recall_pct: **{verdict.get('recall_pct')}**",
             f"- false_positive_risk: **{verdict.get('false_positive_risk')}**",
             f"- grounding: **{verdict.get('grounding')}**",
             f"- verdict: {verdict.get('verdict','')}", "",
             "| Plant | Surfaced in report? |", "|---|:--:|"]
    perp = {p.get("id"): p.get("surfaced") for p in (verdict.get("per_plant") or [])}
    for s in corpus.SCENARIOS:
        lines.append(f"| {s['id']} ({s['tech']}) | {'✅' if perp.get(s['id']) else '❌'} |")
    md = "\n".join(lines) + "\n"
    open(f"{OUT}/accuracy_combined.md", "w").write(md)
    open(f"{OUT}/accuracy_combined_report.md", "w").write(report)
    print("\n".join(lines[:12]))
    print(f"\nwrote {OUT}/accuracy_combined.md")


if __name__ == "__main__":
    {"per": cmd_per, "combined": cmd_combined}.get(sys.argv[1] if sys.argv[1:] else "per", cmd_per)()
