"""LLM engine for the fusion layer — CURRENTLY SIMULATED.

Per the operator's instruction, the real LLM API call is commented out and
the narration is produced deterministically in-code (acting as the LLM
ourselves). This is viable precisely because the fusion graph already holds
the structured findings + timeline; the LLM's only job is narration, which
here is templating + retrieval.

To switch to a real model: uncomment ``_real_llm`` below, ensure the LLM
config/API key is set, and route ``generate_report`` / ``chat`` through it.
No graph/correlation code changes — only this boundary swaps.
"""

from __future__ import annotations

import json

from . import render, budget, severity as sev
from .correlate import _assets_of, _host_label

SIMULATED = True   # default; per-call mode resolves from frontend_config (see _use_real)


# ---------------------------------------------------------------------------
# Real-LLM boundary — the ONLY place the model API is touched. Default OFF
# (mode='simulated'); flip frontend_config agentic.fusion_llm_mode='real' with an
# API key to enable. Any failure falls back to the deterministic narrator.
# ---------------------------------------------------------------------------
def _agentic_cfg() -> dict:
    try:
        from services.memory.pipeline import _llm_config_from_runtime
        return (_llm_config_from_runtime() or {}).get("agentic", {}) or {}
    except Exception:
        return {}


def _use_real() -> bool:
    cfg = _agentic_cfg()
    if str(cfg.get("fusion_llm_mode", "simulated")).lower() != "real":
        return False
    # need a usable transport: online needs an api_key, offline (ollama) is self-hosted
    if str(cfg.get("llm_mode", "online")).lower() == "offline":
        return True
    return bool((cfg.get("online_llm") or {}).get("api_key"))


def _real_llm(system_prompt: str, user_message: str, *, run_id=None) -> str:
    """Production path. The distilled graph is KB-sized, so this is cheap. Token
    counts land on the run's llm_metrics automatically via call_llm's recorder."""
    from services.agentic.analyzers import call_llm
    from services.memory.pipeline import _llm_config_from_runtime
    return call_llm(user_message, system_prompt, _llm_config_from_runtime(), run_id=run_id)


REPORT_SYSTEM_PROMPT = (
    "You are a senior DFIR consultant. From the provided correlated incident graph "
    "(JSON), write ONLY a concise executive narrative and an attack-story paragraph: "
    "what happened, the most affected hosts, the kill-chain progression, and the lead "
    "finding. Structured fact tables (IOCs, MITRE, per-host detail) are appended "
    "separately, so do NOT re-list them. Cite hosts/accounts verbatim. Invent nothing "
    "not in the graph."
)
CHAT_SYSTEM_PROMPT = (
    "You are a DFIR assistant answering questions about ONE correlated incident "
    "graph (JSON). Answer only from the graph facts provided; cite the host + evidence "
    "source for each claim; never speculate beyond the data."
)

_SIM_TAG = ("\n\n---\n_Narrative by the in-graph narrator (simulated — deterministic). "
            "Set agentic.fusion_llm_mode='real' to use a live model._\n")


def generate_report(graph, *, window=None, min_severity="informational",
                    initial_access=None, case_name="Case", run_id=None) -> str:
    """Case report. Real path = LLM narrative over distilled() + deterministic
    fact tables appended verbatim. Falls back to the deterministic narrator on any
    failure (or when mode='simulated')."""
    if _use_real():
        try:
            payload = render.distilled(graph, window=window, min_severity=min_severity,
                                       max_entities=budget.REPORT_MAX_ENTITIES,
                                       budget_chars=budget.REPORT_BUDGET_CHARS)
            narrative = _real_llm(REPORT_SYSTEM_PROMPT, json.dumps(payload), run_id=run_id)
            facts = render.facts_md(graph, window=window, min_severity=min_severity,
                                    initial_access=initial_access)
            return (f"# Incident Case Report — {case_name}\n\n{narrative}\n\n{facts}"
                    "\n\n---\n_Narrative by live LLM; fact tables deterministic._\n")
        except Exception as e:  # noqa: BLE001 — never let LLM failure break a case
            md = render.report(graph, window=window, min_severity=min_severity,
                               initial_access=initial_access, case_name=case_name)
            return md + (f"\n\n---\n_Live LLM unavailable ({type(e).__name__}); "
                         "deterministic fallback._\n")
    md = render.report(graph, window=window, min_severity=min_severity,
                       initial_access=initial_access, case_name=case_name)
    return md + _SIM_TAG


def chat(graph, question: str, history=None, *, window=None, min_severity="informational",
         run_id=None) -> str:
    """Grounded Q&A. Real path narrates the distilled graph; simulated = deterministic
    retrieval. (Phase 4 swaps the real-path payload for a question-scoped subgraph.)"""
    if _use_real():
        try:
            payload = render.distilled(graph, window=window, min_severity=min_severity,
                                       max_entities=budget.CHAT_MAX_ENTITIES,
                                       budget_chars=budget.CHAT_BUDGET_CHARS)
            turns = "".join(f"{m.get('role')}: {m.get('content')}\n" for m in (history or []))
            return _real_llm(CHAT_SYSTEM_PROMPT,
                             f"{json.dumps(payload)}\n\n{turns}Q: {question}", run_id=run_id)
        except Exception:  # noqa: BLE001 — fall through to deterministic retrieval
            pass
    q = (question or "").lower()
    _, findings = render.scope(graph, window=window, min_severity=min_severity)

    def cite(f):
        srcs = "/".join(f.sources) or "?"
        return f"- **[{f.severity}]** {f.title} — {f.summary}  _(source: {srcs})_"

    # 1) host-focused
    for a in graph.by_type("asset"):
        if a.label and a.label.lower() in q:
            af = [f for f in findings if a.id in f.asset_ids]
            if af:
                return f"On **{a.label}**:\n" + "\n".join(cite(f) for f in af)

    # triage / escalation — which hosts to deep-dive next
    if any(k in q for k in ("escalate", "deep-dive", "deep dive", "what next", "run memory",
                            "run timesketch", "which host", "investigate next", "prioriti")):
        esc = sorted((a for a in graph.by_type("asset") if a.attrs.get("escalate")),
                     key=lambda a: -(a.attrs.get("risk_score") or 0))
        if esc:
            return ("Deep-dive candidates (malicious under broad collection, no memory/"
                    "Timesketch yet — run those next):\n"
                    + "\n".join(f"- **{a.label}** — risk {a.attrs.get('risk_score', 0)}, "
                                f"{a.severity}, seen by [{', '.join(a.attrs.get('modules') or [])}]"
                                for a in esc))
        return ("No escalation candidates — either nothing is high-risk, or the high-risk "
                "hosts already have memory/Timesketch coverage.")

    # summary / overview / who is worst
    if any(k in q for k in ("summary", "overview", "brief", "tl;dr", "what happened")):
        hosts = sorted(graph.by_type("asset"), key=lambda a: -sev.rank(a.severity))
        top = sorted(findings, key=lambda f: -sev.rank(f.severity))[:3]
        return (f"{len(hosts)} host(s); worst: "
                + ", ".join(f"{a.label} ({a.severity})" for a in hosts[:4]) + ".\n"
                + "Top findings:\n" + "\n".join(cite(f) for f in top))
    if any(k in q for k in ("who", "most malicious", "worst", "patient zero", "most affected")):
        hosts = sorted(graph.by_type("asset"), key=lambda a: -sev.rank(a.severity))
        if hosts:
            a = hosts[0]
            af = [f for f in findings if a.id in f.asset_ids]
            return (f"**{a.label}** is the most affected host ({a.severity}, {len(af)} findings) — "
                    f"likely patient zero.\n" + "\n".join(cite(f) for f in af[:4]))
    if any(k in q for k in ("initial access", "get in", "got in", "entry", "first compromise")):
        tl = render.timeline(graph, window=window)
        if tl:
            r = tl[0]
            return (f"Earliest in-window activity: `{r['ts']}` on **{r['host']}** — {r['title']}. "
                    f"That is the most likely initial-access anchor.")
    if any(k in q for k in ("vuln", "cve", "patch", "exposure")):
        vf = [f for f in findings if f.title.lower().startswith("vulnerability")]
        return ("Vulnerabilities:\n" + "\n".join(cite(f) for f in vf)) if vf \
            else "No vulnerabilities (CVE) above threshold in this case."
    if any(k in q for k in ("persist", "service", "autorun", "scheduled task", "stay")):
        pf = [f for f in findings if any(k in f.title.lower() for k in ("service", "persist", "task"))]
        return ("Persistence:\n" + "\n".join(cite(f) for f in pf)) if pf \
            else "No persistence findings above threshold in this case."

    # 2) lateral movement / how did they move / pivot
    if any(k in q for k in ("lateral", "move", "moved", "pivot", "spread", "how did")):
        xh = [f for f in findings if f.kind == "cross_host"]
        if xh:
            return "Cross-host / lateral movement evidence:\n" + "\n".join(cite(f) for f in xh)
        return "No deterministic cross-host (lateral-movement) link surfaced in the graph for this window."

    # 3) timeline / when / first
    if any(k in q for k in ("timeline", "when", "first", "initial", "order", "happen")):
        tl = render.timeline(graph, window=window)
        if tl:
            lines = [f"- `{r['ts'] or '—'}` · {r['host']} · [{r['phase']}] {r['title']}" for r in tl[:20]]
            return "Attack timeline (chronological):\n" + "\n".join(lines)

    # 4) indicator / IP / account lookup
    for e in graph.entities.values():
        if e.type in ("ioc", "account") and e.label and e.label.lower() in q:
            hosts = ", ".join(_host_label(graph, x) for x in _assets_of(e))
            tag = " (CROSS-HOST)" if "cross_host" in e.flags else ""
            return (f"**{e.label}** ({e.type}){tag} seen on: {hosts}. "
                    f"Severity {e.severity}, sources {'/'.join(e.sources)}.")

    # 5) default: top findings
    top = sorted(findings, key=lambda f: -sev.rank(f.severity))[:8]
    if not top:
        return "No findings above the current severity threshold in this window."
    return "Top findings for this case:\n" + "\n".join(cite(f) for f in top)
