"""Does the summary EVOLVE as the investigation narrows? (operator's stated spec)

"the summary should give visibility about what happens or at least the most possible
option, and change during the chat and timeline changes during the investigation."

So the summary must not be static: as an analyst narrows scope (zoom to a host / window),
the story should sharpen from a broad triage map to a specific theory. This measures that
transition on one case:

  stage 1  FULL scope        -> expect MACRO   (ranked candidate scenarios)
  stage 2  ZOOM to one host  -> expect FOCUSED (one explicit theory)
  stage 3  ZOOM to a window  -> expect FOCUSED, narrower still

Scored deterministically: altitude, scope counts, and whether the narrative actually
changed (not just re-worded).

  cd /app/scratch_eval && PYTHONPATH=/app python3 campaign/eval_summary_evolves.py
"""
import json, os, re, sys, difflib
sys.path.insert(0, "/app")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from services.fusion import render, store, llm_sim  # noqa: E402
import attack_corpus as corpus  # noqa: E402
from services.fusion.mappers.agentic import map_agentic  # noqa: E402
from services.fusion import correlate  # noqa: E402

OUT = "/tmp/eval_out/campaign"
os.makedirs(OUT, exist_ok=True)
ws = store._ws()


def summarise(g, window, tag):
    alt, reason = render._resolve_altitude(g, window=window)
    payload = json.dumps(render.distilled(g, window=window, max_entities=300,
                                          budget_chars=400000, detail="summary"), default=str)
    sysp = (llm_sim.REPORT_SYSTEM_PROMPT_MACRO if alt == "macro"
            else llm_sim.REPORT_SYSTEM_PROMPT_FOCUSED)
    rid = ws.create_automation_run("evolve", tag)
    try:
        rep = llm_sim._real_llm(sysp, payload, run_id=rid)
    except Exception as e:
        rep = f"(ERROR {e})"
    return alt, reason, rep


def main():
    # MACRO-ELIGIBLE case: the base corpus is 8 hosts / 0-day span, which resolves to
    # FOCUSED at every scope, so it could never show the macro->focused transition.
    # Spread it across 30 hosts and 200 days so full scope is genuinely macro.
    import copy, datetime as _d
    base = corpus.build_all_telemetry()
    tele = {}
    for art, rows in base.items():
        out = []
        for h in range(30):
            for k, row in enumerate(rows):
                r2 = copy.deepcopy(row)
                r2["Computer"] = f"FLEET-{h:03d}"
                day = _d.datetime(2026, 2, 1) + _d.timedelta(days=(h * 7 + k) % 200)
                for tk in ("EventTime", "CreateTime"):
                    if tk in r2:
                        r2[tk] = day.strftime("%Y-%m-%dT%H:%M:%SZ")
                out.append(r2)
        tele[art] = out
    e, r = map_agentic(tele, run_id="ev", hostnames={})
    g = correlate.assemble("evolve", [(e, r)], ["ev"])
    hosts = sorted(a.label for a in g.by_type("asset"))
    print(f"case: {len(hosts)} hosts, {len(g.findings)} findings", flush=True)

    stages = []
    # 1 full scope
    alt1, r1, rep1 = summarise(g, None, "full")
    stages.append(("full scope", alt1, r1, rep1))
    print(f"[1/3] full scope -> altitude={alt1} ({r1})", flush=True)
    # 2 narrow WINDOW (one hour of the campaign)
    win = {"start": "2026-02-01T00:00:00", "end": "2026-02-20T00:00:00"}
    alt2, r2, rep2 = summarise(g, win, "window")
    stages.append(("narrow window (19d)", alt2, r2, rep2))
    print(f"[2/3] narrow window -> altitude={alt2} ({r2})", flush=True)
    # 3 even narrower
    win2 = {"start": "2026-02-01T00:00:00", "end": "2026-02-04T00:00:00"}
    alt3, r3, rep3 = summarise(g, win2, "tight")
    stages.append(("tight window (3d)", alt3, r3, rep3))
    print(f"[3/3] tight window -> altitude={alt3} ({r3})", flush=True)

    sim12 = difflib.SequenceMatcher(None, rep1, rep2).ratio()
    sim23 = difflib.SequenceMatcher(None, rep2, rep3).ratio()
    md = ["# Does the summary evolve as the investigation narrows?", "",
          "Operator spec: the summary should convey the most likely story and CHANGE as "
          "chat/timeline narrow during the investigation.", "",
          "| Stage | Scope | Altitude | Summary chars |", "|---|---|---|---|"]
    for name, alt, reason, rep in stages:
        md.append(f"| {name} | {reason} | **{alt}** | {len(rep):,} |")
    md += ["", f"- narrative similarity full→window: **{sim12:.2f}** (lower = it changed)",
           f"- narrative similarity window→tight: **{sim23:.2f}**",
           "",
           f"**Altitude transition: {stages[0][1]} → {stages[1][1]} → {stages[2][1]}**",
           "", "## Read",
           "The summary should move from a ranked triage map (macro) to one explicit "
           "theory (focused) as scope narrows, and the text should genuinely differ — "
           "a high similarity would mean the summary ignored the narrowing."]
    open(f"{OUT}/summary_evolves.md", "w").write("\n".join(md) + "\n")
    json.dump({"stages": [(n, a, r, t[:600]) for n, a, r, t in stages],
               "sim12": sim12, "sim23": sim23},
              open(f"{OUT}/summary_evolves.json", "w"), indent=2, default=str)
    print("\n".join(md[4:12]))


if __name__ == "__main__":
    main()
