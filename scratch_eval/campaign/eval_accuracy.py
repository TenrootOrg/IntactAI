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


def cmd_precision():
    """FALSE-POSITIVE test: benign telemetry must NOT produce attack findings."""
    g = _fuse(corpus.BENIGN, "eval_benign")
    finds = [(f.title, f.severity) for f in g.findings]
    # any high/critical finding on benign input is a false positive
    fp = [f for f in g.findings if f.severity in ("high", "critical")]
    lines = ["# Attack-simulation ACCURACY — precision (benign input)", "",
             f"Benign admin/IT telemetry through the real pipeline. "
             f"**{len(g.findings)} finding(s), {len(fp)} high/critical false positive(s).**", "",
             "PASS = no high/critical findings invented from benign activity.", "",
             f"**{'✅ PASS' if not fp else '❌ FAIL'}** — findings: {finds or 'none'}"]
    md = "\n".join(lines) + "\n"
    open(f"{OUT}/accuracy_precision.md", "w").write(md)
    json.dump({"findings": finds, "false_positives": len(fp)},
              open(f"{OUT}/accuracy_precision.json", "w"), indent=2, default=str)
    print(md)


def cmd_noise():
    """RECALL-UNDER-NOISE: bury the attack telemetry in benign volume, confirm every
    finding-eligible plant still surfaces (a detection must survive a noisy host)."""
    tele = corpus.build_all_telemetry()
    for art, rows in corpus.BENIGN.items():        # add benign noise on the same hosts
        tele.setdefault(art, []).extend(rows * 20)  # 20x benign volume
    g = _fuse(tele, "eval_noise")
    fts = _finding_texts(g)
    key = [{"id": s["id"], "kws": [k.lower() for k in s["expect"]["find"]],
            "host": s["host"].lower(), "sev": s["expect"].get("sev")} for s in corpus.SCENARIOS
           if s["expect"].get("sev") in ("high", "critical")]   # finding-eligible only
    rows = [{"id": k["id"], "surfaced": any(all(w in t for w in k["kws"]) and k["host"] in t
                                            for t in fts)} for k in key]
    rec = sum(r["surfaced"] for r in rows)
    lines = ["# Attack-simulation ACCURACY — recall under noise", "",
             f"Attack telemetry + 20× benign volume on the same hosts "
             f"({len(g.findings)} findings total).", "",
             f"**Finding-eligible plants still detected: {rec}/{len(key)}**", "",
             "| Plant | Survived noise? |", "|---|:--:|"]
    for r in rows:
        lines.append(f"| {r['id']} | {'✅' if r['surfaced'] else '❌ LOST'} |")
    md = "\n".join(lines) + "\n"
    open(f"{OUT}/accuracy_noise.md", "w").write(md)
    print(md)


def cmd_incremental():
    """INCREMENTAL INTEGRITY: a real incident arrives over MULTIPLE collections. Fuse
    the corpus as one batch, then as two halves fed incrementally, and assert the
    detections are identical — no lost findings, no duplicates, no severity drift."""
    tele = corpus.build_all_telemetry()
    # one-shot
    one = _fuse(tele, "inc_one")
    # split every artifact's rows in half -> two "collections"
    a_t, b_t = {}, {}
    for art, rows in tele.items():
        mid = max(1, len(rows) // 2)
        a_t[art] = rows[:mid]
        b_t[art] = rows[mid:]
    ea, ra = map_agentic(a_t, run_id="run_a", hostnames={})
    eb, rb = map_agentic(b_t, run_id="run_b", hostnames={})
    seed = correlate.assemble("inc_two", [(ea, ra)], ["run_a"])
    two = correlate.assemble("inc_two", [(eb, rb)], ["run_a", "run_b"], seed=seed)

    def sig(g):
        return sorted(f"{f.title}|{f.severity}" for f in g.findings)
    s1, s2 = sig(one), sig(two)
    only1 = [x for x in s1 if x not in s2]
    only2 = [x for x in s2 if x not in s1]
    dupes = [x for x in set(s2) if s2.count(x) > 1]
    ok = not only1 and not only2 and not dupes
    lines = ["# Incremental collection integrity", "",
             "A real incident arrives over multiple collections. One-shot fuse vs the "
             "same telemetry split into two collections fused incrementally.", "",
             f"- one-shot findings: **{len(s1)}**",
             f"- incremental findings: **{len(s2)}**",
             f"- lost in incremental: **{len(only1)}** {only1[:4] or ''}",
             f"- extra in incremental: **{len(only2)}** {only2[:4] or ''}",
             f"- duplicated: **{len(dupes)}** {dupes[:4] or ''}", "",
             f"**{'✅ PASS — incremental == one-shot' if ok else '❌ FAIL'}**"]
    md = "\n".join(lines) + "\n"
    open(f"{OUT}/accuracy_incremental.md", "w").write(md)
    json.dump({"one": len(s1), "two": len(s2), "lost": only1, "extra": only2,
               "dupes": dupes, "pass": ok},
              open(f"{OUT}/accuracy_incremental.json", "w"), indent=2, default=str)
    print(md)


if __name__ == "__main__":
    {"per": cmd_per, "combined": cmd_combined, "precision": cmd_precision,
     "noise": cmd_noise, "incremental": cmd_incremental}.get(
        sys.argv[1] if sys.argv[1:] else "per", cmd_per)()
