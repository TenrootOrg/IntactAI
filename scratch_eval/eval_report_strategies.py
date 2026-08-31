"""Report-strategy eval harness (Phase 0).

Runs the Case Analysis report under candidate strategies against REAL fused
graphs, records real token/$ usage per strategy, and dumps the outputs so we can
rank them on DFIR-professionalism, altitude-fit, grounding AND cost. No shipped
code is modified — strategies call the same transport generate_report uses.
"""
import json, sys, os
from services.fusion import store, render, llm_sim, keys
from services import workflow_service as ws

OUT = "/tmp/eval_out"
os.makedirs(OUT, exist_ok=True)

FOCUSED_PROMPT = llm_sim.REPORT_SYSTEM_PROMPT   # today's report prompt (baseline)

# --- draft MACRO prompt: high-level DFIR triage map for broad scope ----------
MACRO_PROMPT = (
    "You are a senior DFIR consultant triaging a BROAD, correlated incident graph — "
    "many hosts and/or a long timeframe, fused across the environment. At this altitude "
    "you do NOT force one intrusion story. You give the lead analyst a high-level map: "
    "the shape of what's in scope, the few candidate scenarios worth pursuing, and "
    "exactly where to zoom in next. Write like a senior consultancy triage note — "
    "concise, high-signal, calibrated. No filler.\n"
    "\n"
    "PAYLOAD (JSON) keys: assets (hosts+severity); findings (summary, hosts[], mitre, ts, "
    "kind — kind=='cross_host' means the SAME activity/account/tooling touched >1 host); "
    "timeline (time-ordered, real timestamps only); top_entities (accounts/processes/IOCs "
    "with anomaly+flags); identities (one identity = one person's accounts across hosts); "
    "host_coverage (each host once: severity, finding_count, first/last activity, role_hint). "
    "scope (host/finding counts + evidence span).\n"
    "\n"
    "Write clean markdown, concise, in this order:\n"
    "\n"
    "## Assessment\n"
    "2-4 sentences: how many hosts over what period, the dominant activity, and whether "
    "this reads as ONE campaign, SEVERAL unrelated issues, or mostly benign/administrative "
    "noise. Business language. Give overall confidence (HIGH/MODERATE/LOW).\n"
    "\n"
    "## Candidate Scenarios\n"
    "The 2-4 most plausible intrusion/abuse scenarios the evidence supports, highest risk "
    "first. For each: a bolded title, then\n"
    "  - **What** — the hypothesis in one line (the story it would be if true).\n"
    "  - **Where/When** — the specific hosts (or host-role cluster) and the time-window it "
    "lives in, from the graph.\n"
    "  - **Evidence** — the findings / cross_host links / identities that suggest it, cited.\n"
    "  - **Confidence** — HIGH/MODERATE/LOW and what drives it.\n"
    "  - **Zoom** — the exact scope to narrow to (which hosts + which time window) to confirm "
    "or kill it.\n"
    "Rank by risk to the organisation, not finding volume. If the evidence genuinely shows "
    "only benign/administrative activity, say so and STOP — never manufacture scenarios.\n"
    "\n"
    "## Suspicious Timeframes & Clusters\n"
    "A short ranked list of the periods and host-clusters that concentrate the risk, each "
    "with why it stands out — the heat-map the analyst zooms into.\n"
    "\n"
    "## What to do first\n"
    "The 3 highest-value next actions: which scenario to zoom into first, which host(s) to "
    "pull deeper (memory / timeline), and the single question that most changes the picture.\n"
    "\n"
    "DISCIPLINE\n"
    "Grade every assessment HIGH/MODERATE/LOW and what drives it. Keep OBSERVATION (in the "
    "graph) separate from INFERENCE (your analysis). Cite hosts, accounts, hashes and "
    "timestamps verbatim; never invent an entity, event, time, actor or campaign not in the "
    "payload. An honest 'undetermined, and here is what's missing' beats a guess. This is a "
    "triage MAP, not the full report — be brief. No preamble. Start at '## Assessment'."
)


# --- S2: macro v2 — same triage map, but fix the judge's two dings on S1:
#     (1) ground aggregate/environment-wide claims in named hosts + cited findings;
#     (2) add a brief "Contain now" so a broad report still gives immediate actions.
MACRO2_PROMPT = MACRO_PROMPT.replace(
    "## What to do first\n"
    "The 3 highest-value next actions: which scenario to zoom into first, which host(s) to "
    "pull deeper (memory / timeline), and the single question that most changes the picture.\n",
    "## Priority actions\n"
    "Two short lists, each item naming the specific host/account:\n"
    "  **Contain now** — the few steps that stop active access or protect tier-zero right "
    "now (isolate a host, disable/rotate a shared account, protect the CA/DCs), each "
    "justified by a cited finding. If nothing warrants immediate containment, say so.\n"
    "  **Investigate next** — the scenario to zoom into first, the host(s) to pull deeper "
    "(memory / timeline), and the single question that most changes the picture.\n",
).replace(
    "An honest 'undetermined, and here is what's missing' beats a guess.",
    "An honest 'undetermined, and here is what's missing' beats a guess. Ground every "
    "aggregate / environment-wide claim in specific hosts + a cited finding and time; never "
    "assert broad reach without naming the evidence.",
)


def scope_facts(graph, d):
    window = d.get("time_window") or None
    msev = d.get("min_severity", "informational")
    assets, findings = render.scope(graph, window=window, min_severity=msev)
    ts = [f.ts for f in findings if f.ts]
    span = None
    if ts:
        lo, hi = keys.to_utc_dt(min(ts)), keys.to_utc_dt(max(ts))
        if lo and hi:
            span = (hi - lo).days
    return {"hosts": len(assets), "findings": len(findings),
            "entities": len(graph.entities), "span_days": span}


def is_macro(f):
    return (f["hosts"] > 12 or f["findings"] > 150 or (f["span_days"] or 0) > 90)


def build_payload(graph, d, detail):
    ent, chars = store._llm_payload_budget(d)
    p = render.distilled(graph, window=d.get("time_window") or None,
                         min_severity=d.get("min_severity", "informational"),
                         max_entities=ent, budget_chars=chars, detail=detail,
                         max_identities=store._llm_identity_budget(d))
    p["scope"] = scope_facts(graph, d)
    return p


def call_and_meter(system, payload, tag):
    rid = ws.create_automation_run("eval_report", f"eval:{tag}")
    ps = json.dumps(payload, default=str)
    try:
        text = llm_sim._real_llm(system, ps, run_id=rid)
    except Exception as e:
        text = f"[ERROR] {e}"
    m = (ws.get_automation_run(rid) or {}).get("llm_metrics") or {}
    return text, m, len(ps)


def run_strategy(name, graph, d, facts):
    macro = is_macro(facts)
    if name == "S0-baseline":
        return call_and_meter(FOCUSED_PROMPT, build_payload(graph, d, "explicit"), name)
    if name == "S1-altitude":
        if macro:
            return call_and_meter(MACRO_PROMPT, build_payload(graph, d, "summary"), name)
        return call_and_meter(FOCUSED_PROMPT, build_payload(graph, d, "explicit"), name)
    if name == "S2-macro2":
        if macro:
            return call_and_meter(MACRO2_PROMPT, build_payload(graph, d, "summary"), name)
        return call_and_meter(FOCUSED_PROMPT, build_payload(graph, d, "explicit"), name)
    raise ValueError(name)


STRATEGIES = ["S0-baseline", "S1-altitude", "S2-macro2"]
GRAPH_DIR = "/app/data/fusion_graphs"


def all_case_facts():
    out = []
    from glob import glob
    for fp in sorted(glob(f"{GRAPH_DIR}/*.json")):
        cid = os.path.basename(fp)[:-5]
        try:
            g = store.load_graph(cid); d = store.get_case(cid) or {}
            f = scope_facts(g, d); f["case"] = cid; f["macro"] = is_macro(f)
            out.append(f)
        except Exception as e:
            out.append({"case": cid, "error": str(e)})
    return out


if __name__ == "__main__":
    if sys.argv[1:2] == ["facts"]:
        for f in all_case_facts():
            print(f"  {f.get('case')}: hosts={f.get('hosts')} findings={f.get('findings')} "
                  f"span_days={f.get('span_days')} entities={f.get('entities')} macro={f.get('macro')}")
        sys.exit(0)

    cases = sys.argv[1:]
    if not cases:
        print("usage: eval_report_strategies.py <case_id> [<case_id>...]  |  facts")
        sys.exit(1)
    only = [s for s in os.environ.get("EVAL_ONLY", "").split(",") if s]
    strategies = only or STRATEGIES
    # merge into any existing results so re-running one strategy keeps the others
    try:
        results = json.load(open(f"{OUT}/results.json"))
    except Exception:
        results = {}
    for cid in cases:
        g = store.load_graph(cid); d = store.get_case(cid) or {}
        facts = scope_facts(g, d)
        print(f"\n=== {cid} | hosts={facts['hosts']} findings={facts['findings']} "
              f"span_days={facts['span_days']} macro={is_macro(facts)} ===")
        results.setdefault(cid, {"facts": facts, "macro": is_macro(facts), "reports": {}})
        results[cid]["facts"] = facts
        results[cid]["macro"] = is_macro(facts)
        for s in strategies:
            text, m, plen = run_strategy(s, g, d, facts)
            results[cid]["reports"][s] = {"metrics": m, "payload_chars": plen, "report_chars": len(text)}
            open(f"{OUT}/{cid}__{s}.md", "w").write(text)
            print(f"  {s:14s} in={m.get('input_tokens')} out={m.get('output_tokens')} "
                  f"${m.get('cost_usd')} | payload={plen}c report={len(text)}c "
                  f"-> {OUT}/{cid}__{s}.md")
    json.dump(results, open(f"{OUT}/results.json", "w"), default=str)
    print(f"\nwrote {OUT}/results.json")
