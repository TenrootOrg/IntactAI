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

from . import store, render, keys
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
    "  pivot({\"value\":\"<account|host|process|ip>\",\"window\":{\"start\":\"...\",\"end\":\"...\"}}) "
    "-> raw EVENTS mentioning that value across the case (the classic investigative "
    "pivot; window optional, ISO times).\n"
    "\n"
    "Investigate efficiently: start from list_findings or clusters, drill into the "
    "decisive ones with evidence, then answer in 3-6 tool calls. In your final answer "
    "state confidence (HIGH/MODERATE/LOW) and keep OBSERVATION (a tool showed it) "
    "separate from INFERENCE (your reasoning).\n"
    "\n"
    "IF THE QUESTION ASSUMES SOMETHING THE EVIDENCE DOES NOT PROVE (e.g. it asks "
    "whether a tool was used FOR a purpose, and the evidence shows only that the tool "
    "ran): do NOT discard the facts you did establish. ALWAYS report the confirmed "
    "specifics first — the host, the time, the artifact, the exact command — then say "
    "plainly which part of the question the evidence does not support. Lowering your "
    "confidence is not a reason to omit a host or timestamp a tool showed you. An "
    "answer that drops established facts because one premise is unproven is a FAILED "
    "answer."
)

_MAX_TOOL_RESULT_CHARS = 6000
_MAX_ROW_CHARS = 1500
# A model that answers with a {final} before calling any tool has looked at no
# evidence — nudge it back this many times, then FORCE one list_findings so the
# answer is at least grounded (never accept a 0-evidence give-up).
_MIN_STEP_NUDGES = 2


def _role_annot(label):
    """A6: append the hostname's role hint (domain controller / CA / config manager)
    so tier-zero priority SURVIVES masking — the identifier 'ALDC02' is pseudonymized
    to 'Hostname7', but '(domain controller)' is not an identifier and passes through,
    so the model still knows which hosts matter. Role is a naming HINT, not asserted."""
    r = render._host_role(label or "")
    return f"{label} ({r})" if r else label


def _tool(case_id, name, args):
    args = args or {}
    if name == "list_findings":
        g = store.load_graph(case_id)
        fs = sorted(g.findings, key=lambda f: -sev.rank(f.severity))
        lim = min(40, int(args.get("limit") or 20))
        return [{"id": f.id, "title": f.title, "severity": f.severity,
                 "hosts": [_role_annot(render._host_label(g, a))
                           for a in (f.asset_ids or [])][:6],
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
    if name == "pivot":
        # The classic investigative move: every raw event that mentions a value
        # (account, host, process, ip), optionally inside a time window. Grounded
        # straight from the graph's event entities — nothing fetched can be invented.
        val = str(args.get("value") or "").strip().lower()
        if not val:
            return {"error": "pivot needs a value"}
        g = store.load_graph(case_id)
        win = args.get("window") or {}
        lo = keys.to_utc_dt(win.get("start")) if win.get("start") else None
        hi = keys.to_utc_dt(win.get("end")) if win.get("end") else None
        _EV_KEYS = ("ev_user", "ev_proc", "ev_cmdline", "ev_tgtip", "ev_sha256")
        hits = []
        for e in g.entities.values():
            if e.type != "event":
                continue
            a = e.attrs or {}
            labels = [render._host_label(g, x) for x in (a.get("_assets") or [])]
            hay = " ".join(str(x) for x in
                           ([e.label] + labels + [a.get(k) for k in _EV_KEYS]) if x).lower()
            if val not in hay:
                continue
            t = keys.to_utc_dt(e.first_seen or e.last_seen)
            if (lo and t and t < lo) or (hi and t and t > hi):
                continue
            hits.append((t, {"ts": e.first_seen or e.last_seen,
                             "hosts": [_role_annot(x) for x in labels[:3]],
                             **{k: str(a[k])[:300] for k in _EV_KEYS if a.get(k)}}))
        hits.sort(key=lambda x: (x[0] is None, x[0]))
        total = len(hits)
        rows = [h for _, h in hits[:15]]
        return {"total_matches": total, "shown": len(rows), "events": rows}
    if name == "clusters":
        g = store.load_graph(case_id)
        d = store.get_case(case_id) or {}
        cl = render.zoom_targets(g, window=d.get("time_window") or None,
                                 min_severity=d.get("min_severity") or "informational")
        return [{"title": c["title"],
                 "hosts": [_role_annot(lb) for lb in c["host_labels"]],
                 "window": c["window"], "finding_count": c["finding_count"],
                 "severity": c["severity"], "mitre": c["mitre"]} for c in cl]
    return {"error": f"unknown tool '{name}'"}


def _safe_tool(case_id, name, args):
    """_tool, but a crashing tool (a model-supplied bad arg — non-numeric limit,
    malformed pivot window — or a store/render failure) becomes an {"error":...}
    the model can recover from, NOT an exception that 500s the whole request."""
    try:
        return _tool(case_id, name, args)
    except Exception as e:  # noqa: BLE001
        return {"error": f"tool '{name}' failed: {type(e).__name__}: {e}"}


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


def _mask_for_case(d, graph, run_id):
    """Per-case opt-in DataAnonymizer, gated EXACTLY like the report/chat paths
    (store.py builds it the same way from d['masking']). None when masking is off
    or unavailable — every mask helper is a no-op on None.

    Honest limit: the mapping is graph-derived (_build_mask_mapping sweeps the whole
    graph incl. bounded evidence), so a stray identifier appearing ONLY inside a raw
    row is best-effort — the same standard the report's evidence lines accept."""
    mk = (d or {}).get("masking") or {}
    if not mk.get("enabled"):
        return None
    try:
        from services.data_anonymizer import DataAnonymizer
        mask = DataAnonymizer(custom_patterns=mk.get("patterns") or [])
        llm_sim._build_mask_mapping(graph, mask)
        llm_sim._log_mask_audit(run_id, mask)
        return mask
    except Exception:
        return None


def _revert_obj(o, mask):
    """Revert pseudonyms→originals in every STRING of a parsed structure. Never on
    serialized JSON: an original like 'DOMAIN\\user' substituted into a JSON string
    would inject an invalid escape and corrupt the parse."""
    if isinstance(o, str):
        return llm_sim._revert_mask(o, mask)
    if isinstance(o, dict):
        return {k: _revert_obj(v, mask) for k, v in o.items()}
    if isinstance(o, list):
        return [_revert_obj(v, mask) for v in o]
    return o


_MASK_ID_KEYS = {
    "computer": "host", "hostname": "host", "host": "host", "machine": "host",
    "dest_host": "host", "src_host": "host", "workstation": "host", "dnshostname": "host",
    "user": "user", "username": "user", "account": "user", "subjectusername": "user",
    "targetusername": "user", "ev_user": "user", "samaccountname": "user",
    "sourceip": "ip_int", "destinationip": "ip_int", "targetip": "ip_int",
    "ev_tgtip": "ip_int", "ipaddress": "ip_int", "srcip": "ip_int", "dstip": "ip_int",
}


def _enrich_mask_from_result(mask, obj):
    """A8: register identifier-shaped VALUES found in a tool result (raw evidence /
    pivot rows) into the mask BEFORE it is applied — so a hostname/user/ip that lives
    ONLY in a raw row (never promoted to a graph entity, so absent from the
    graph-derived mapping) is still pseudonymized instead of leaking to the model.
    Best-effort; walks nested dicts/lists and parses stringified-JSON row blobs."""
    if not mask:
        return

    def reg(v, cat):
        v = (v or "").strip()
        if v and v not in getattr(mask, "mapping", {}):
            try:
                mask._get_or_create_pseudo(v, cat)
            except Exception:
                pass

    def walk(o, depth=0):
        if depth > 6:
            return
        if isinstance(o, dict):
            for k, v in o.items():
                kl = str(k).lower()
                if isinstance(v, str):
                    if kl in _MASK_ID_KEYS:
                        reg(v, _MASK_ID_KEYS[kl])
                    elif v[:1] == "{":                 # a stringified raw row (evidence())
                        try:
                            walk(json.loads(v), depth + 1)
                        except Exception:
                            pass
                else:
                    walk(v, depth + 1)
        elif isinstance(o, list):
            for x in o:
                walk(x, depth + 1)

    try:
        walk(obj)
    except Exception:
        pass


def investigate(case_id, question, *, run_id=None, max_steps=6, log=None,
                use_mask=True, enable_pivot=True):
    """Run the bounded ReAct loop. Returns {answer, steps:[{tool,args}], truncated}.

    Masking (when the case has it enabled): the model sees ONLY pseudonyms — the
    question and every tool result are _apply_mask'ed before the send, tool ARGS
    come back in pseudonym space and are reverted before execution, and the final
    answer is reverted so the analyst reads real names. Same in-transit-only
    contract as generate_report/chat. `use_mask`/`enable_pivot` exist for the
    v1-vs-v2 eval harness; production callers leave them True."""
    _log = log or (lambda m, l="info": None)
    d = store.get_case(case_id)
    if not d:
        return {"answer": "case not found", "steps": []}
    mask = _mask_for_case(d, store.load_graph(case_id), run_id) if use_mask else None
    system = ((llm_sim._MASK_IDENTITY_LEGEND if mask else "") + INVESTIGATE_SYSTEM)
    if not enable_pivot:
        system = "\n".join(l for l in system.splitlines() if "pivot(" not in l)

    def _m(t):
        return llm_sim._apply_mask(t, mask)

    convo = [_m(f"CASE: {case_id}\nQUESTION: {question}\n\n"
                "Begin. Pull what you need with tools, then answer with a single "
                '{"final":"..."} object.')]
    steps = []
    nudges = 0

    def _ask():
        """One model turn. A transport failure (rejected key / no credit / timeout /
        CLI error) is caught and classified into LLMUnavailable — so investigate
        returns a clean operator message instead of an unhandled 500, matching the
        report/chat paths (A3). Returns (raw, err)."""
        try:
            return llm_sim._real_llm(system, "\n\n".join(convo), run_id=run_id), None
        except Exception as e:  # noqa: BLE001
            return None, llm_sim.LLMUnavailable(llm_sim._classify_llm_error(e))

    def _transport_error(err, truncated):
        _log(f"investigation transport failure: {err}", "error")
        return {"answer": llm_sim.llm_error_message(str(err)), "steps": steps,
                "truncated": truncated, "error": True}

    def _feed(tool, targs, result):
        convo.append(json.dumps({"tool": tool, "args": targs}))
        convo.append(_m(f"TOOL[{tool}] RESULT:\n"
                        + json.dumps(result, default=str)[:_MAX_TOOL_RESULT_CHARS]))

    for i in range(max_steps):
        raw, err = _ask()
        if err is not None:
            return _transport_error(err, False)
        obj = _parse(raw)
        if obj is None:
            convo.append("(your last message was not valid JSON — respond with ONE "
                         "JSON object only)")
            continue
        if "final" in obj:
            if not steps:
                # A1: a {final} before ANY tool call means the model answered from
                # memory without looking. Never accept it. Nudge; if it keeps
                # bailing, force one list_findings so the answer is grounded.
                if nudges < _MIN_STEP_NUDGES:
                    nudges += 1
                    convo.append('You have not called ANY tool yet — you have seen no '
                                 'evidence. Do not answer from memory. Call a tool first '
                                 '(start with {"tool":"list_findings","args":{"limit":20}}) '
                                 'and only answer after inspecting real results.')
                    continue
                forced = _safe_tool(case_id, "list_findings", {"limit": 20})
                _enrich_mask_from_result(mask, forced)   # A8: mask row-only identifiers
                steps.append({"tool": "list_findings", "args": {"limit": 20}})
                _feed("list_findings", {"limit": 20}, forced)
                convo.append('Now answer, grounded ONLY in those findings, with one '
                             '{"final":"..."} object.')
                continue
            _log(f"investigation done in {len(steps)} tool call(s)")
            return {"answer": llm_sim._revert_mask(obj.get("final") or "", mask),
                    "steps": steps, "truncated": False}
        tool, targs = obj.get("tool"), obj.get("args") or {}
        if not enable_pivot and tool == "pivot":
            result = {"error": "unknown tool 'pivot'"}
            real_args = targs
        else:
            real_args = _revert_obj(targs, mask)          # model speaks pseudonyms
            result = _safe_tool(case_id, tool, real_args)  # A2: never raises
        _enrich_mask_from_result(mask, result)            # A8: mask row-only identifiers
        _log(f"tool: {tool}({json.dumps(real_args)[:80]})")
        steps.append({"tool": tool, "args": real_args})   # analyst-facing trace: real
        _feed(tool, targs, result)
    # out of budget -> force a final answer from what was gathered
    convo.append('Step budget reached. Give your {"final":"..."} answer now from '
                 "what the tools have shown you.")
    raw, err = _ask()
    if err is not None:
        return _transport_error(err, True)
    obj = _parse(raw) or {}
    final = obj.get("final")
    if not final:
        # A7b: never surface the raw model text (often a tool-call JSON blob) as the
        # analyst answer. Give a clean insufficient-evidence message; include the raw
        # only if it reads as prose, never a JSON blob.
        looks_prose = bool(raw) and not raw.strip().lstrip("`").startswith("{")
        final = ("The investigation reached its step budget without a conclusive, "
                 "grounded answer" + (f": {raw.strip()[:400]}" if looks_prose else
                 " — re-run the investigation or narrow the question."))
    return {"answer": llm_sim._revert_mask(final, mask),
            "steps": steps, "truncated": True}
