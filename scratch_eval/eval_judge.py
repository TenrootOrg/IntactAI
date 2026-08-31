"""Judge + side-by-side artifact for the report-strategy eval.

Reads the saved per-strategy reports for a case, has a principal-DFIR judge score
them (professionalism / altitude-fit / grounding / actionability / efficiency),
and writes a verdict JSON + an HTML page with every report, its cost, and its
scores side by side.
"""
import json, sys, os, glob, html
from services.fusion import llm_sim
from services import workflow_service as ws

OUT = "/tmp/eval_out"

JUDGE_SYSTEM = (
    "You are a PRINCIPAL DFIR reviewer grading candidate incident-analysis reports "
    "to a top-tier IR-consultancy hiring bar: would you ship this to a client? You are "
    "given the CASE SCOPE FACTS and several candidate reports of the SAME case. Score "
    "each report 1-5 (integers) on:\n"
    "- dfir_professionalism: crisp, structured, calibrated, senior — no filler.\n"
    "- altitude_fit: specificity MATCHES the scope. BROAD (many hosts / long span) must "
    "give ranked candidate scenarios/hypotheses with confidence + zoom targets, NOT one "
    "forced campaign story; NARROW (few hosts / short span) must give a single explicit "
    "theory in detail. Penalize a forced single story on broad scope; penalize vagueness "
    "on narrow scope.\n"
    "- grounding: every concrete claim (host/account/hash/time) is cited; no invented "
    "entities/actors/campaigns; no over-confident conclusion the evidence doesn't support.\n"
    "- actionability: clear, prioritized next steps a responder can execute.\n"
    "- efficiency: high signal per length; no padding (a shorter report that says as much "
    "scores HIGHER).\n"
    "Be a harsh grader. Return STRICT JSON only:\n"
    '{"case_altitude":"broad|narrow","scores":[{"strategy":"..","dfir_professionalism":n,'
    '"altitude_fit":n,"grounding":n,"actionability":n,"efficiency":n,"total":n,'
    '"rationale":"one line"}],"winner":"strategy","why":"one line"}'
)


def judge(case_id, facts, reports):
    parts = [f"CASE SCOPE FACTS: {json.dumps(facts)}", ""]
    for strat, md in reports.items():
        parts.append(f"===== CANDIDATE REPORT [{strat}] =====")
        parts.append(md)
        parts.append("")
    user = "\n".join(parts)
    rid = ws.create_automation_run("eval_judge", f"judge:{case_id}")
    raw = llm_sim._real_llm(JUDGE_SYSTEM, user, run_id=rid)
    m = (ws.get_automation_run(rid) or {}).get("llm_metrics") or {}
    verdict = llm_sim._parse_json(raw) if hasattr(llm_sim, "_parse_json") else None
    if verdict is None:
        try:
            s = raw[raw.index("{"): raw.rindex("}") + 1]
            verdict = json.loads(s)
        except Exception:
            verdict = {"error": "unparseable", "raw": raw[:2000]}
    return verdict, m


def html_page(case_id, facts, results, reports, verdict, jm):
    def esc(x):
        return html.escape(str(x))
    score_by = {s["strategy"]: s for s in (verdict.get("scores") or [])} if isinstance(verdict, dict) else {}
    cols = []
    for strat, md in reports.items():
        r = (results.get("reports") or {}).get(strat, {})
        met = r.get("metrics") or {}
        sc = score_by.get(strat, {})
        win = " WINNER" if verdict.get("winner") == strat else ""
        cols.append(f"""
      <div class="col{'' if not win else ' win'}">
        <h2>{esc(strat)}{esc(win)}</h2>
        <div class="meta">out {esc(met.get('output_tokens'))} tok · in {esc(met.get('input_tokens'))} · {esc(len(md)):}c</div>
        <div class="scores">{''.join(f'<span>{esc(k)}: <b>{esc(v)}</b></span>' for k,v in sc.items() if k not in ('strategy','rationale'))}</div>
        <div class="rat">{esc(sc.get('rationale',''))}</div>
        <pre>{esc(md)}</pre>
      </div>""")
    return f"""<!doctype html><meta charset=utf-8><title>eval {esc(case_id)}</title>
<style>body{{font:13px system-ui;margin:0;background:#0d1117;color:#e6edf3}}
header{{padding:12px 16px;border-bottom:1px solid #30363d}}
.wrap{{display:flex;gap:0;align-items:flex-start}}
.col{{flex:1;min-width:0;border-right:1px solid #30363d;padding:12px 16px}}
.col.win{{background:#0f2417}} h2{{margin:.2em 0}}
.meta{{color:#8b949e}} .scores span{{display:inline-block;margin:2px 10px 2px 0;color:#adbac7}}
.rat{{color:#d29922;margin:6px 0;font-style:italic}}
pre{{white-space:pre-wrap;word-wrap:break-word;background:#161b22;padding:10px;border-radius:6px;max-height:70vh;overflow:auto}}</style>
<header><b>{esc(case_id)}</b> — scope {esc(json.dumps(facts))} · judge says altitude=<b>{esc(verdict.get('case_altitude'))}</b>, winner=<b>{esc(verdict.get('winner'))}</b> — {esc(verdict.get('why'))}</header>
<div class=wrap>{''.join(cols)}</div>"""


if __name__ == "__main__":
    case_id = sys.argv[1]
    results = json.load(open(f"{OUT}/results.json")).get(case_id, {})
    facts = results.get("facts", {})
    reports = {}
    for fp in sorted(glob.glob(f"{OUT}/{case_id}__*.md")):
        strat = os.path.basename(fp)[len(case_id) + 2:-3]
        reports[strat] = open(fp).read()
    verdict, jm = judge(case_id, facts, reports)
    json.dump(verdict, open(f"{OUT}/{case_id}__verdict.json", "w"), indent=2)
    open(f"{OUT}/{case_id}__compare.html", "w").write(html_page(case_id, facts, results, reports, verdict, jm))
    print("VERDICT:", json.dumps(verdict, indent=2))
    print(f"\njudge cost: out={jm.get('output_tokens')} in={jm.get('input_tokens')}")
    print(f"wrote {OUT}/{case_id}__verdict.json and __compare.html")
