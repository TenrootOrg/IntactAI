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


def _chat_full_context() -> bool:
    """ESCAPE HATCH (config `agentic.chat_send_full_context`, default OFF).

    When ON, the case chat SKIPS entity resolution/clarify entirely and sends the
    FULL distilled graph on every message — so no question can ever be 'blocked'
    by a clarify, at the price of much higher token cost per message (the
    question-scoped subgraph is ~20 entities/12k chars; the full graph is up to
    ~60 entities/32k chars and is re-sent every turn). Leave OFF unless an
    operator explicitly wants maximum recall over cost."""
    return bool(_agentic_cfg().get("chat_send_full_context", False))


def _use_real() -> bool:
    cfg = _agentic_cfg()
    if str(cfg.get("fusion_llm_mode", "simulated")).lower() != "real":
        return False
    # need a usable transport: online needs an api_key, offline (ollama) is self-hosted
    if str(cfg.get("llm_mode", "online")).lower() == "offline":
        return True
    return bool((cfg.get("online_llm") or {}).get("api_key"))


def _llm_available() -> bool:
    """A usable LLM transport is configured (online API key OR offline Ollama URL),
    INDEPENDENT of the fusion_llm_mode flag. The case CHAT uses this so that simply
    configuring a model turns it into a real, generic conversation — no extra toggle.
    (The per-fuse report/analyst narrative still respects _use_real for cost control.)"""
    try:
        from services.agentic.analyzers import is_llm_configured
        from services.memory.pipeline import _llm_config_from_runtime
        return bool(is_llm_configured(_llm_config_from_runtime() or {}))
    except Exception:
        return False


def _real_llm(system_prompt: str, user_message: str, *, run_id=None,
              max_output_tokens=None) -> str:
    """Production path. The distilled graph is KB-sized, so this is cheap. Token
    counts land on the run's llm_metrics automatically via call_llm's recorder.
    `max_output_tokens` (the case 'Output token cap') overrides the global
    agentic max_response_tokens for THIS call only — caps output cost per rescan."""
    from services.agentic.analyzers import call_llm
    from services.memory.pipeline import _llm_config_from_runtime
    cfg = _llm_config_from_runtime()
    if max_output_tokens:
        cfg = dict(cfg)
        ag = dict(cfg.get("agentic") or {})
        ag["max_response_tokens"] = int(max_output_tokens)
        cfg["agentic"] = ag
    return call_llm(user_message, system_prompt, cfg, run_id=run_id)


REPORT_SYSTEM_PROMPT = (
    "You are a senior DFIR consultant writing the narrative section of an incident "
    "report for a customer, from the provided correlated incident graph (JSON: hosts, "
    "accounts, processes, IOCs, findings, cross-host links, timeline, and the analyst's "
    "dispositions/validations).\n"
    "Write these sections as clean markdown, in this order:\n"
    "## Executive Summary — 3-5 sentences in plain business language: what happened, "
    "how many hosts, the severity/confidence, and the bottom line for a non-technical "
    "reader.\n"
    "## Incident Overview — scope, the most-affected host(s) and the likely entry "
    "point/initial access, and what the adversary appears to have been after.\n"
    "## Attack Narrative — the kill chain as prose, in order (initial access → "
    "execution → persistence → C2 → lateral movement → impact), naming the hosts, "
    "accounts and times involved at each step.\n"
    "Reflect the analyst's validations: treat findings confirmed real as fact, and do "
    "NOT dwell on ones dispositioned benign / known-to-IT (mention they were cleared).\n"
    "Structured fact tables (timeline, hosts, IOCs, MITRE, recommendations) are appended "
    "by the system AFTER your text — do NOT reproduce them. Be specific and grounded: "
    "cite hosts/accounts/hashes verbatim from the graph; never invent anything not "
    "present. No preamble, start at '## Executive Summary'."
)
CHAT_SYSTEM_PROMPT = (
    "You are a senior DFIR / SOC analyst embedded in this investigation, talking with "
    "another analyst about their environment. The attached correlated incident graph "
    "(JSON: hosts, accounts, processes, IOCs, findings, cross-host links, timeline) is "
    "your evidence about the whole infrastructure.\n"
    "Answer ANY question they ask — overviews, risk ranking, the attack path, lateral "
    "movement, a specific host/account/IP, what's suspicious vs expected, what to do "
    "next. Be direct, conversational and genuinely helpful; synthesise across hosts and "
    "modules to give insight, not just lookups.\n"
    "Ground every CONCRETE claim (a host, account, hash, IP, finding) in the graph and "
    "cite it. You may reason, correlate, prioritise and recommend — just keep OBSERVATION "
    "(in the graph) distinct from INFERENCE (your analysis). Never invent hosts, accounts, "
    "hashes or events that aren't present; if the graph can't answer, say so and suggest "
    "what to collect next.\n"
    "If the payload has `resolved_focus`, the analyst named that specific host/identity — "
    "OPEN your answer by stating which one you're answering on (e.g. \"On DESKTOP-566AT85:\") "
    "so a mis-resolved name is caught, then answer scoped to it."
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
                    audience="both", language="en", master_prompt=None, mask=None,
                    dispositions=None, validations=None, prefer_llm=True,
                    max_entities=None, budget_chars=None, max_output_tokens=None) -> str:
    """Case report. Real path = LLM narrative over distilled() + deterministic
    fact tables appended verbatim. `audience` (exec/technical/both) + `language`
    tailor the narrative (reusing the engagement directive); `master_prompt` is the
    operator's "remove X / focus Y" steering, prepended as ground truth. `mask` is an
    optional DataAnonymizer — when set, the distilled LLM payload AND the rendered
    markdown are anonymized (customer-facing). `max_entities`/`budget_chars` size the
    LLM payload (the case 'LLM payload' knob); None = the default fixed budget. Falls
    back to the deterministic narrator on any failure (or when mode='simulated')."""
    me = max_entities or budget.REPORT_MAX_ENTITIES
    bc = budget_chars or budget.REPORT_BUDGET_CHARS
    # Use a real model only when asked (prefer_llm) AND one is configured. The FIRST
    # scan generates a fast, free, deterministic report (prefer_llm=False); the
    # premium LLM narrative is produced ONLY on an explicit Rescan/Regenerate
    # (regenerate_report passes prefer_llm=True). Keeps tokens fully on-demand.
    if prefer_llm and (_use_real() or _llm_available()):
        try:
            payload = render.distilled(graph, window=window, min_severity=min_severity,
                                       max_entities=me, budget_chars=bc)
            # give the model the analyst's triage so the narrative reflects it
            if dispositions:
                payload["operator_dispositions"] = dispositions
            if validations:
                payload["analyst_validations"] = validations
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
            narrative = _real_llm(system, payload_str, run_id=run_id,
                                  max_output_tokens=max_output_tokens)
            facts = render.facts_md(graph, window=window, min_severity=min_severity,
                                    initial_access=initial_access,
                                    dispositions=dispositions, validations=validations)
            md = (f"# Incident Case Report — {case_name}\n\n{narrative}\n\n{facts}"
                  "\n\n---\n_Narrative by live LLM; fact tables deterministic._\n")
            return _apply_mask(md, mask)
        except Exception as e:  # noqa: BLE001 — never let LLM failure break a case
            md = render.report(graph, window=window, min_severity=min_severity,
                               initial_access=initial_access, case_name=case_name,
                               dispositions=dispositions, validations=validations)
            return _apply_mask(md, mask) + (f"\n\n---\n_Live LLM unavailable "
                                            f"({type(e).__name__}); deterministic fallback._\n")
    md = render.report(graph, window=window, min_severity=min_severity,
                       initial_access=initial_access, case_name=case_name,
                       dispositions=dispositions, validations=validations) + _SIM_TAG
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
            dispositions=None, max_entities=None, budget_chars=None,
            max_output_tokens=None) -> dict:
    """ADVISORY analyst pass over the distilled graph: incident-grouping + grounded
    hypotheses. Reuses the agentic skills corpus for expertise. Never mutates
    graph.findings. Real path is grounding-gated; simulated path is deterministic.
    `max_entities`/`budget_chars` size the LLM payload (the case 'LLM payload' knob)."""
    me = max_entities or budget.REPORT_MAX_ENTITIES
    bc = budget_chars or budget.REPORT_BUDGET_CHARS
    _, findings = render.scope(graph, window=window, min_severity=min_severity)
    if not _use_real():
        return _simulated_analysis(graph, findings)
    try:
        payload = render.distilled(graph, window=window, min_severity=min_severity,
                                   max_entities=me, budget_chars=bc)
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
        raw = _real_llm(system, user, run_id=run_id, max_output_tokens=max_output_tokens)
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
         run_id=None, dispositions=None, validations=None, full_context=None) -> str:
    """Grounded Q&A. Real path narrates the distilled graph; simulated = deterministic
    retrieval. Surfaces operator dispositions (what's been triaged as benign/IT)."""
    # --- entity resolution + safety clarify (BEFORE any LLM call, so an ambiguous
    # or typo'd host name is never silently answered on the wrong machine). The
    # clarify reply reads as the assistant asking back; it costs no LLM tokens.
    # The operator can DISABLE all of this via `chat_send_full_context` (see
    # _chat_full_context) — the escape hatch: never clarifies, always sends the
    # full graph. More expensive (see the warning on the flag).
    from . import resolve as _resolve
    # per-case toggle (Case Analysis → Configuration) wins; else the global default.
    full_ctx = bool(full_context) if full_context is not None else _chat_full_context()
    pinned = []
    if not full_ctx:
        pinned = _resolve.resolve_followup(graph, question, history)
        if pinned is None:
            _res = _resolve.resolve(graph, question)
            _clar = _resolve.clarify_text(_res)
            if _clar:
                return _clar
            pinned = _res["resolved"]
    pin_ids = [e.id for e in pinned]
    focus = [e.label for e in pinned]

    # PRIMARY: whenever a model is configured, this is ONE generic, grounded
    # conversation over the whole infrastructure graph — no prepared intents. Just
    # configuring an LLM (online key or offline Ollama) turns it on; no extra flag.
    if _use_real() or _llm_available():
        try:
            if full_ctx:
                # Bypass: send the FULL distilled graph every turn (pricier).
                payload = render.distilled(graph, window=window, min_severity=min_severity,
                                           max_entities=budget.REPORT_MAX_ENTITIES,
                                           budget_chars=budget.REPORT_BUDGET_CHARS)
            else:
                payload = render.chat_subgraph(graph, question, window=window,
                                               min_severity=min_severity,
                                               max_entities=budget.CHAT_MAX_ENTITIES,
                                               pin_ids=pin_ids, focus_labels=focus)
            if dispositions:
                payload["operator_dispositions"] = dispositions   # so the LLM can answer triage Qs
            if validations:
                payload["analyst_validations"] = validations      # Timeline real/not-real/known
            turns = "".join(f"{m.get('role')}: {m.get('content')}\n" for m in (history or []))
            return _real_llm(CHAT_SYSTEM_PROMPT,
                             f"{json.dumps(payload)}\n\n{turns}Q: {question}", run_id=run_id)
        except Exception:  # noqa: BLE001 — fall through to deterministic retrieval
            pass

    # FALLBACK (no LLM): if the question resolved to a HOST, answer scoped to it
    # deterministically so the pin works even without a model configured. Account/
    # IOC mentions fall through to the existing keyword retrieval below (which has
    # dedicated identity/IOC handling).
    pin_assets = [e for e in pinned if e.id.startswith("asset:")]
    if pin_assets:
        _aids = {e.id for e in pin_assets}
        _, _findings = render.scope(graph, window=window, min_severity=min_severity)
        hits = sorted((f for f in _findings if _aids & set(f.asset_ids)),
                      key=lambda f: -sev.rank(f.severity))
        head = "On " + ", ".join(e.label for e in pin_assets) + ":"
        if not hits:
            return f"{head} no findings in the current window/severity filter."
        lines = [f"- **[{f.severity}]** {f.title} — {f.summary}" for f in hits[:15]]
        return head + "\n" + "\n".join(lines)

    # FALLBACK (no LLM configured): deterministic keyword retrieval over the graph.
    q0 = (question or "").lower()
    # "what's been marked benign / explained / dispositioned"
    if dispositions and any(k in q0 for k in ("disposition", "marked benign", "what did i mark",
                                              "triaged", "explained", "marked as", "benign list",
                                              "what's benign", "whats benign")):
        lines = [f"- **{x.get('target')}** → {x.get('verdict')} ({x.get('attribution')}"
                 + (f", {x.get('reason')}" if x.get('reason') else "") + f") [{x.get('scope')}]"
                 for x in dispositions]
        return "Operator dispositions on this case:\n" + "\n".join(lines)
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
                                      a.attrs.get("risk_intensity") or 0,
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

    # 1b) attack path / kill chain — the cross-host story, chronological + phased
    if any(k in q for k in ("attack path", "path the attack", "path did", "path took",
                            "which path", "kill chain", "kill-chain", "attack took",
                            "how the attack", "attack chain", "the chain", "story",
                            "narrative", "trace the", "across hosts", "across clients",
                            "across the", "multiple clients", "multiple hosts",
                            "from multiple", "full picture", "whole attack", "end to end",
                            "end-to-end", "progression", "sequence of")):
        tl = render.timeline(graph, window=window)
        xh = [f for f in findings if f.kind == "cross_host"]
        if tl:
            lines, last = [], None
            for r in tl[:30]:
                ph = r.get("phase") or ""
                head = f"**{ph}** — " if ph and ph != last else ""
                last = ph or last
                lines.append(f"- `{r['ts'] or '—'}` · {r['host']} · {head}{r['title']}")
            out = ("Attack path (chronological, across the affected hosts):\n"
                   + "\n".join(lines))
            if xh:
                out += ("\n\nCross-host pivots (same account/indicator on >1 host — the "
                        "lateral-movement spine):\n" + "\n".join(cite(f) for f in xh[:8]))
            return out
        if xh:
            return "Cross-host pivots:\n" + "\n".join(cite(f) for f in xh)

    # 2) lateral movement / how did they move / pivot
    if any(k in q for k in ("lateral", "move", "moved", "pivot", "spread", "how did",
                            "traverse", "propagat")):
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

    # 5) default: a brief case framing + top findings (no exact intent matched).
    top = sorted(findings, key=lambda f: -sev.rank(f.severity))[:8]
    if not top:
        return "No findings above the current severity threshold in this window."
    hosts = sorted(graph.by_type("asset"), key=lambda a: -sev.rank(a.severity))
    xh = sum(1 for f in findings if f.kind == "cross_host")
    head = (f"I don't have an exact answer for that (deterministic no-LLM mode — "
            f"configure an LLM for free-form Q&A). For context: {len(hosts)} host(s), "
            f"worst " + ", ".join(f"{a.label} ({a.severity})" for a in hosts[:3])
            + (f", {xh} cross-host finding(s)" if xh else "") + ".\n"
            "Try: \"attack path\", \"top 3 hosts\", \"top identities\", \"lateral movement\", "
            "\"timeline\", or a host/account/IP name.\n\nTop findings:")
    return head + "\n" + "\n".join(cite(f) for f in top)
