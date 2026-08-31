"""Agentic investigation loop (#1): the model INVESTIGATES a case by calling
retrieval tools over the fused graph + raw evidence, instead of recalling from one
frozen payload. Text-based ReAct protocol (the model emits a JSON tool call in its
text; we service it and feed the result back), so it works over the existing
single-shot transport — Codex / Claude / OpenAI — with no native tool-use API.

Bounded steps; every step is one _real_llm call, so this is ON-DEMAND (a "dig into
this" / verify action), NOT the default report path — keeps cost controlled. The
whole point: the model cannot fabricate a timestamp/host/hash it had to fetch.
"""
import json
import re

from . import store, render
from . import severity as sev
from . import llm_sim

INVESTIGATE_SYSTEM = (
    "You are a senior DFIR analyst INVESTIGATING a correlated incident graph. You do "
    "NOT have the whole case in front of you — you PULL what you need with tools and "
    "GROUND every claim in what they return. Never assert a host, account, hash, time "
    "or event a tool did not show you.\n"
    "\n"
    "Respond with EXACTLY ONE JSON object, nothing else:\n"
    "  to use a tool -> {\"tool\":\"<name>\",\"args\":{...}}\n"
    "  when finished -> {\"final\":\"<answer as markdown, grounded in tool results>\"}\n"
    "\n"
    "Tools:\n"
    "  list_findings({\"limit\":N})      -> the case's top findings [{id,title,severity,hosts,ts,kind}].\n"
    "  search({\"query\":\"...\"})         -> findings whose title/summary match a keyword.\n"
    "  evidence({\"finding_id\":\"...\"})  -> the RAW rows behind a finding (the ground truth).\n"
    "  clusters({})                    -> suspicious (host-cluster, time-window) hotspots.\n"
    "\n"
    "Investigate efficiently: start from list_findings or clusters, drill into the "
    "decisive ones with evidence, then answer in 3-6 tool calls. In your final answer "
    "state confidence (HIGH/MODERATE/LOW) and keep OBSERVATION (a tool showed it) "
    "separate from INFERENCE (your reasoning)."
)

_MAX_TOOL_RESULT_CHARS = 6000
_MAX_ROW_CHARS = 1500


def _tool(case_id, name, args):
    args = args or {}
    if name == "list_findings":
        g = store.load_graph(case_id)
        fs = sorted(g.findings, key=lambda f: -sev.rank(f.severity))
        lim = min(40, int(args.get("limit") or 20))
        return [{"id": f.id, "title": f.title, "severity": f.severity,
                 "hosts": [render._host_label(g, a) for a in (f.asset_ids or [])][:6],
                 "ts": f.ts, "kind": f.kind} for f in fs[:lim]]
    if name == "search":
        q = str(args.get("query") or "").lower()
        g = store.load_graph(case_id)
        out = []
        for f in g.findings:
            if q and q in (f.title + " " + (f.summary or "")).lower():
                out.append({"id": f.id, "title": f.title, "severity": f.severity, "ts": f.ts})
            if len(out) >= 15:
                break
        return out
    if name == "evidence":
        rows = store.get_evidence_rows(case_id, args.get("finding_id"), max_rows=6)
        return [{"artifact": r["artifact"],
                 "row": json.dumps(r["row"], default=str)[:_MAX_ROW_CHARS]} for r in rows]
    if name == "clusters":
        g = store.load_graph(case_id)
        d = store.get_case(case_id) or {}
        cl = render.zoom_targets(g, window=d.get("time_window") or None,
                                 min_severity=d.get("min_severity") or "informational")
        return [{"title": c["title"], "hosts": c["host_labels"], "window": c["window"],
                 "finding_count": c["finding_count"], "severity": c["severity"],
                 "mitre": c["mitre"]} for c in cl]
    return {"error": f"unknown tool '{name}'"}


def _parse(raw):
    if not raw:
        return None
    try:
        return json.loads(raw.strip())
    except Exception:
        pass
    try:
        s = raw[raw.index("{"): raw.rindex("}") + 1]
        return json.loads(s)
    except Exception:
        return None


def investigate(case_id, question, *, run_id=None, max_steps=6, log=None):
    """Run the bounded ReAct loop. Returns {answer, steps:[{tool,args}], truncated}."""
    _log = log or (lambda m, l="info": None)
    if not store.get_case(case_id):
        return {"answer": "case not found", "steps": []}
    convo = [f"CASE: {case_id}\nQUESTION: {question}\n\n"
             "Begin. Pull what you need with tools, then answer with a single "
             '{"final":"..."} object.']
    steps = []
    for i in range(max_steps):
        raw = llm_sim._real_llm(INVESTIGATE_SYSTEM, "\n\n".join(convo), run_id=run_id)
        obj = _parse(raw)
        if obj is None:
            convo.append("(your last message was not valid JSON — respond with ONE "
                         "JSON object only)")
            continue
        if "final" in obj:
            _log(f"investigation done in {len(steps)} tool call(s)")
            return {"answer": obj.get("final") or "", "steps": steps, "truncated": False}
        tool, targs = obj.get("tool"), obj.get("args") or {}
        _log(f"tool: {tool}({json.dumps(targs)[:80]})")
        result = _tool(case_id, tool, targs)
        steps.append({"tool": tool, "args": targs})
        convo.append(json.dumps({"tool": tool, "args": targs}))
        convo.append(f"TOOL[{tool}] RESULT:\n"
                     + json.dumps(result, default=str)[:_MAX_TOOL_RESULT_CHARS])
    # out of budget -> force a final answer from what was gathered
    convo.append('Step budget reached. Give your {"final":"..."} answer now from '
                 "what the tools have shown you.")
    raw = llm_sim._real_llm(INVESTIGATE_SYSTEM, "\n\n".join(convo), run_id=run_id)
    obj = _parse(raw) or {}
    return {"answer": obj.get("final") or raw, "steps": steps, "truncated": True}
