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
import re

from . import render, budget, severity as sev
from .correlate import _assets_of, _host_label

# FP-triage intent detection (deterministic, grounded).
_DISP_BENIGN = ("benign", "false positive", "false-positive", "ignore", "expected",
                "legitimate", "sanctioned", "is fine", "is our", "is the", "was the",
                "was our", "backup", "not malicious", "authorized", "authorised", "approved",
                "that's it", "that was it", "known good")
_DISP_MAL = ("confirmed malicious", "is malicious", "real attack", "true positive",
             "actually malicious")
_GENERIC_TITLE_TOK = {"sigma", "host", "suspicious", "activity", "detection", "coordinated",
                      "alert", "process", "service", "indicator", "account", "driver"}


def _disp_attribution(q: str) -> str:
    if "service account" in q:
        return "service_account"
    if "it admin" in q or "sysadmin" in q or " it " in q or "helpdesk" in q or "admin" in q:
        return "it_admin"
    if "employee" in q or "staff" in q or "user" in q:
        return "employee"
    if any(k in q for k in ("backup", "sanctioned", "approved tool", "our tool", "software")):
        return "sanctioned_tool"
    return "other"


def detect_disposition(graph, question: str):
    """If the message attributes activity as benign/IT/etc AND grounds to a real finding or
    entity, return a disposition dict; else None (caller falls back to normal chat). Grounding
    is mandatory — the same anti-hallucination discipline as the analyst pass."""
    q = (question or "").lower()
    verdict = ("malicious" if any(k in q for k in _DISP_MAL)
               else ("benign" if any(k in q for k in _DISP_BENIGN) else None))
    if not verdict:
        return None
    scope = ("environment" if any(k in q for k in ("environment", "everywhere", "always",
                                                   "fleet", "all hosts", "every host"))
             else "case")
    target = label = None
    for f in graph.findings:                       # ground to a finding by a distinctive token
        toks = [w for w in re.findall(r"[a-z0-9]{4,}", f.title.lower())
                if w not in _GENERIC_TITLE_TOK]
        if any(t in q for t in toks):
            target, label = f.id, f.title.split(" on ")[0]
            break
    if not target:                                 # or to an entity by its label
        for e in graph.entities.values():
            if e.type in ("ioc", "account", "process", "service", "module") and e.label \
                    and len(str(e.label)) >= 4 and str(e.label).lower() in q:
                target, label = e.id, e.label
                break
    if not target:
        return None
    return {"target": target, "label": label, "verdict": verdict,
            "attribution": _disp_attribution(q), "scope": scope}

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

# The grounded analyst pass. Anti-hallucination discipline mirrors the agentic HARD
# RULES (FACT vs INFERENCE, cite only what's in the graph). The deterministic findings
# are authoritative; this pass is ADVISORY.
ANALYST_SYSTEM_PROMPT = (
    "You are a senior DFIR analyst reviewing a correlated incident graph (JSON) that "
    "already contains deterministic findings. Do THREE things and return STRICT JSON:\n"
    "1) incident_groups: cluster the EXISTING findings into named campaigns. Each group "
    "cites finding_ids that appear in the graph's findings.\n"
    "2) hypotheses: novel patterns the deterministic rules may have MISSED. Each MUST cite "
    "entity_ids that appear in the graph's top_entities, a confidence (low|medium|high), "
    "and a one-line reason. These are FOR ANALYST VERIFICATION — not confirmed.\n"
    "3) (optional) note operator dispositions you were given.\n"
    "HARD RULES: reference ONLY ids/values present in the provided graph. Do NOT invent "
    "hosts, hashes, accounts, campaign names, or threat actors. If you cannot ground a "
    "hypothesis in a real entity_id, omit it. Distinguish FACT (in the graph) from "
    "INFERENCE (your reasoning). Output JSON only: "
    '{"incident_groups":[{"name","finding_ids","rationale"}],'
    '"hypotheses":[{"title","entity_ids","confidence","reason"}]}'
)

_SIM_TAG = ("\n\n---\n_Narrative by the in-graph narrator (simulated — deterministic). "
            "Set agentic.fusion_llm_mode='real' to use a live model._\n")


def _build_mask_mapping(graph, mask):
    """Populate the anonymizer's mapping from the graph's sensitive entity labels
    (hosts, accounts, IPs), using typed rows so its field-name detection fires. We then
    literal-replace those originals everywhere (payload + report) for consistency."""
    rows = []
    for e in graph.entities.values():
        lbl = (e.label or "").strip()
        if not lbl:
            continue
        if e.type == "asset":
            rows.append({"hostname": lbl})
        elif e.type == "account":
            rows.append({"username": lbl})
        elif e.type in ("netconn", "ioc"):
            rows.append({"ipaddress": lbl})
    if rows:
        try:
            mask.mask_data(rows)
        except Exception:
            pass


def _apply_mask(text, mask):
    """Literal-replace originals→pseudonyms (longest-first) using the anonymizer's
    accumulated mapping, so the LLM input + fact tables + narrative are masked
    consistently. No-op when masking is off."""
    if not mask:
        return text
    mapping = getattr(mask, "mapping", {}) or {}
    for orig in sorted((k for k in mapping if k), key=len, reverse=True):
        text = text.replace(orig, mapping[orig])
    return text


def generate_report(graph, *, window=None, min_severity="informational",
                    initial_access=None, case_name="Case", run_id=None,
                    audience="both", language="en", master_prompt=None, mask=None) -> str:
    """Case report. Real path = LLM narrative over distilled() + deterministic
    fact tables appended verbatim. `audience` (exec/technical/both) + `language`
    tailor the narrative (reusing the engagement directive); `master_prompt` is the
    operator's "remove X / focus Y" steering, prepended as ground truth. `mask` is an
    optional DataAnonymizer — when set, the distilled LLM payload AND the rendered
    markdown are anonymized (customer-facing). Falls back to the deterministic narrator
    on any failure (or when mode='simulated')."""
    if _use_real():
        try:
            payload = render.distilled(graph, window=window, min_severity=min_severity,
                                       max_entities=budget.REPORT_MAX_ENTITIES,
                                       budget_chars=budget.REPORT_BUDGET_CHARS)
            payload_str = json.dumps(payload)
            if mask:                                  # anonymize the LLM input too
                _build_mask_mapping(graph, mask)
                payload_str = _apply_mask(payload_str, mask)
            system = REPORT_SYSTEM_PROMPT
            if (audience and audience != "both") or (language and language != "en"):
                try:                              # reuse engagement audience/language tailoring
                    from services.engagement.templates import audience_language_directive
                    system = system + "\n\n" + audience_language_directive(audience, language)
                except Exception:
                    pass
            if master_prompt:
                system = ("## OPERATOR CONTEXT (from interactive validation) — treat as "
                          "ground truth; apply the removals/focus described:\n"
                          f"{master_prompt.strip()}\n\n---\n\n") + system
            narrative = _real_llm(system, payload_str, run_id=run_id)
            facts = render.facts_md(graph, window=window, min_severity=min_severity,
                                    initial_access=initial_access)
            md = (f"# Incident Case Report — {case_name}\n\n{narrative}\n\n{facts}"
                  "\n\n---\n_Narrative by live LLM; fact tables deterministic._\n")
            return _apply_mask(md, mask)
        except Exception as e:  # noqa: BLE001 — never let LLM failure break a case
            md = render.report(graph, window=window, min_severity=min_severity,
                               initial_access=initial_access, case_name=case_name)
            return _apply_mask(md, mask) + (f"\n\n---\n_Live LLM unavailable "
                                            f"({type(e).__name__}); deterministic fallback._\n")
    md = render.report(graph, window=window, min_severity=min_severity,
                       initial_access=initial_access, case_name=case_name) + _SIM_TAG
    if mask:                                          # populate the mapping, then mask the md
        _build_mask_mapping(graph, mask)
        md = _apply_mask(md, mask)
    return md


def _parse_json(text):
    """Tolerant extraction of the first JSON object from an LLM response."""
    try:
        return json.loads(text)
    except Exception:
        pass
    s, e = text.find("{"), text.rfind("}")
    if 0 <= s < e:
        try:
            return json.loads(text[s:e + 1])
        except Exception:
            return {}
    return {}


def _ground(analysis: dict, graph) -> dict:
    """Deterministic post-filter: drop any cited id not present in the graph; reject a
    hypothesis left citing zero real entities. Grounding is enforced, not trusted."""
    valid_ent = set(graph.entities)
    valid_find = {f.id for f in graph.findings}
    groups = []
    for grp in (analysis.get("incident_groups") or []):
        if not isinstance(grp, dict):
            continue
        cited = [i for i in (grp.get("finding_ids") or []) if i in valid_find]
        removed = [i for i in (grp.get("finding_ids") or []) if i not in valid_find]
        if cited:
            grp = dict(grp); grp["finding_ids"] = cited
            if removed:
                grp["ungrounded_refs_removed"] = removed
            groups.append(grp)
    hyps = []
    for h in (analysis.get("hypotheses") or []):
        if not isinstance(h, dict):
            continue
        cited = [i for i in (h.get("entity_ids") or []) if i in valid_ent]
        removed = [i for i in (h.get("entity_ids") or []) if i not in valid_ent]
        if not cited:
            continue                              # zero real entities = hallucination, drop
        h = dict(h); h["entity_ids"] = cited
        h["status"] = "for_analyst_verification"
        if removed:
            h["ungrounded_refs_removed"] = removed
        hyps.append(h)
    return {"incident_groups": groups, "hypotheses": hyps}


def _simulated_analysis(graph, findings) -> dict:
    """Deterministic analyst output (no model): group findings by host, no hypotheses."""
    by_host: dict = {}
    for f in findings:
        for a in (f.asset_ids or ["?"]):
            by_host.setdefault(a, []).append(f.id)
    groups = [{"name": f"Activity on {_host_label(graph, a)}", "finding_ids": fids,
               "rationale": "deterministic grouping by host (simulated)."}
              for a, fids in by_host.items() if fids]
    return {"incident_groups": groups, "hypotheses": [], "simulated": True}


def analyze(graph, *, window=None, min_severity="informational", run_id=None,
            dispositions=None) -> dict:
    """ADVISORY analyst pass over the distilled graph: incident-grouping + grounded
    hypotheses. Reuses the agentic skills corpus for expertise. Never mutates
    graph.findings. Real path is grounding-gated; simulated path is deterministic."""
    _, findings = render.scope(graph, window=window, min_severity=min_severity)
    if not _use_real():
        return _simulated_analysis(graph, findings)
    try:
        payload = render.distilled(graph, window=window, min_severity=min_severity,
                                   max_entities=budget.REPORT_MAX_ENTITIES,
                                   budget_chars=budget.REPORT_BUDGET_CHARS)
        # select the curated DFIR macro playbook FROM THE GRAPH (reuse agentic skills)
        system = ANALYST_SYSTEM_PROMPT
        try:
            from services.agentic.skills import select_macro_skill, compose_system_prompt
            from services.fusion.render import _sev_tally
            mitre = [m for f in findings for m in (f.mitre or [])]
            arts = sorted({e.attrs.get("artifact") for e in graph.entities.values()
                           if e.attrs.get("artifact")})
            macro = select_macro_skill(aggregated_mitre=mitre,
                                       severity_counts=_sev_tally(findings),
                                       artifact_names=arts)
            if macro:
                system = compose_system_prompt(ANALYST_SYSTEM_PROMPT, [macro])
        except Exception:  # noqa: BLE001 — skills are enrichment, never required
            pass
        user = json.dumps(payload)
        if dispositions:
            user += ("\n\nOPERATOR DISPOSITIONS (already triaged — do not re-flag): "
                     + json.dumps(dispositions))
        raw = _real_llm(system, user, run_id=run_id)
        return _ground(_parse_json(raw), graph)
    except Exception:  # noqa: BLE001 — advisory only; never break a case
        return _simulated_analysis(graph, findings)


CHECKLIST_SYSTEM_PROMPT = (
    "You are a DFIR consultant preparing a CUSTOMER-CONFIRMATION checklist. For each "
    "notable finding in the provided case graph, write ONE plain-language yes/no question "
    "asking the customer to confirm whether the activity is EXPECTED / AUTHORISED (benign) "
    "— e.g. scheduled IT work, a sanctioned tool, a known service account. Every item MUST "
    "cite the exact finding_id from the graph. Return STRICT JSON only: "
    '{"checklist":[{"finding_id":"...","question":"...","suggestion":"benign"}]}'
)


def _checklist_id(finding_id, question):
    import hashlib
    return "chk_" + hashlib.sha1(f"{finding_id}|{question}".encode()).hexdigest()[:12]


def _simulated_checklist(findings) -> list:
    return [{"id": _checklist_id(f.id, f.title), "finding_id": f.id,
             "question": f"Is “{f.title}” expected / authorised activity (benign)?",
             "suggestion": "benign", "status": "pending"} for f in findings]


def generate_disposition_checklist(graph, *, window=None, min_severity="high",
                                   run_id=None) -> list:
    """Customer-confirmation checklist: per high finding, a likely-benign yes/no question
    the customer accepts (=> dispositioned benign) or declines (=> kept). Grounded to real
    finding_ids; deterministic fallback when no real LLM. Never raises."""
    _, findings = render.scope(graph, window=window, min_severity=min_severity)
    high = [f for f in findings if sev.at_least(f.severity, "high")] or findings
    if not _use_real():
        return _simulated_checklist(high)
    try:
        payload = render.distilled(graph, window=window, min_severity=min_severity,
                                   max_entities=budget.REPORT_MAX_ENTITIES,
                                   budget_chars=budget.REPORT_BUDGET_CHARS)
        raw = _real_llm(CHECKLIST_SYSTEM_PROMPT, json.dumps(payload), run_id=run_id)
        data = _parse_json(raw)
        valid = {f.id for f in graph.findings}
        out = []
        for it in (data.get("checklist") or []):
            fid = it.get("finding_id")
            q = (it.get("question") or "").strip()
            if fid in valid and q:                    # grounding: only real findings
                out.append({"id": _checklist_id(fid, q), "finding_id": fid, "question": q,
                            "suggestion": it.get("suggestion", "benign"), "status": "pending"})
        return out or _simulated_checklist(high)
    except Exception:  # noqa: BLE001
        return _simulated_checklist(high)


def chat(graph, question: str, history=None, *, window=None, min_severity="informational",
         run_id=None, dispositions=None) -> str:
    """Grounded Q&A. Real path narrates the distilled graph; simulated = deterministic
    retrieval. Surfaces operator dispositions (what's been triaged as benign/IT)."""
    q0 = (question or "").lower()
    # "what's been marked benign / explained / dispositioned"
    if dispositions and any(k in q0 for k in ("disposition", "marked benign", "what did i mark",
                                              "triaged", "explained", "marked as", "benign list",
                                              "what's benign", "whats benign")):
        lines = [f"- **{x.get('target')}** → {x.get('verdict')} ({x.get('attribution')}"
                 + (f", {x.get('reason')}" if x.get('reason') else "") + f") [{x.get('scope')}]"
                 for x in dispositions]
        return "Operator dispositions on this case:\n" + "\n".join(lines)
    if _use_real():
        try:
            # question-scoped subgraph (not the whole graph) — keeps chat tokens flat
            payload = render.chat_subgraph(graph, question, window=window,
                                           min_severity=min_severity,
                                           max_entities=budget.CHAT_MAX_ENTITIES)
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

    def _n_from(qq, default=5):
        m = re.search(r"\b(\d{1,3})\b", qq)
        return max(1, min(int(m.group(1)), 25)) if m else default

    _RANK_CUES = ("top", "worst", "most", "rank", "list", "biggest", "main", "key")
    _has_rank = any(k in q for k in _RANK_CUES) or bool(re.search(r"\b\d+\b", q))

    # 0a) top-N IDENTITIES / accounts (must precede the generic 'who' branch, which
    #     otherwise answers with a host). Ranks accounts by cross-host spread first.
    if any(k in q for k in ("identit", "account", "user ", "users", "credential", "logon")) \
            and not any(k in q for k in ("host", "machine", "endpoint", "computer")):
        accts = [e for e in graph.entities.values() if e.type == "account"]
        if accts:
            def _akey(e):
                return (1 if "cross_host" in (e.flags or []) else 0,
                        len(_assets_of(e)), sev.rank(e.severity), e.anomaly or 0)
            accts.sort(key=_akey, reverse=True)
            n = _n_from(q)
            lines = []
            for e in accts[:n]:
                hl = [_host_label(graph, x) for x in _assets_of(e)]
                xh = " (cross-host)" if "cross_host" in (e.flags or []) else ""
                lines.append(f"- **{e.label}**{xh} — {e.severity}, on {len(hl)} host(s)"
                             + (f": {', '.join(hl[:8])}" if hl else ""))
            return (f"Top {min(n, len(accts))} identities by cross-host spread + severity:\n"
                    + "\n".join(lines))

    # 0b) top-N HOSTS / machines, ranked by risk (precedes the default findings dump).
    if any(k in q for k in ("host", "machine", "endpoint", "computer", "asset")) and _has_rank:
        hosts = list(graph.by_type("asset"))
        if hosts:
            def _hcount(a):
                return len([f for f in findings if a.id in f.asset_ids])
            hosts.sort(key=lambda a: (a.attrs.get("risk_score") or 0,
                                      sev.rank(a.severity), _hcount(a)), reverse=True)
            n = _n_from(q)
            lines = [f"- **{a.label}** — {a.severity}, risk {a.attrs.get('risk_score', 0)}, "
                     f"{_hcount(a)} finding(s)" for a in hosts[:n]]
            return f"Top {min(n, len(hosts))} hosts by risk:\n" + "\n".join(lines)

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
