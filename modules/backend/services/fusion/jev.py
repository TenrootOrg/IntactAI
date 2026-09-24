"""Jev — TypeSafe's "System One" model — for small, closed decisions.

Jev does not write text. It takes a `state` (any JSON) plus named questions,
each a yes/no ("noul"), pick-one ("choice") or ordered "score", and returns a
typed answer with probabilities. We reach it through OpenRouter's Decisions
endpoint, with Jev's own OpenRouter key when one is set in Settings, else the
main key while OpenRouter is the chat provider — so a box whose chat runs on
Claude or a Codex subscription can still use it.

EVERYTHING HERE IS A SUGGESTION. Nothing in this module, or in any caller,
sets a disposition, merges an identity or edits a report on Jev's word: the
analyst still clicks. Any failure returns None and the caller carries on
exactly as it does with Jev switched off (the default).

Masked case data leaves the box when this is on — the Settings block says so.
"""
import json
import logging

import requests

from .budget import approx_tokens

log = logging.getLogger(__name__)

URL = "https://openrouter.ai/api/v1/systemone"
USES = ("disposition", "relevance", "grounding", "identity", "chat_intent", "injection")
DEFAULTS = {"enabled": False, "model": "jev-latest", "min_confidence": 0.8,
            # Jev's own OpenRouter key. Empty = use the main key, which only works
            # while OpenRouter is the selected chat provider.
            "api_key": "",
            "uses": {u: True for u in USES}}
# Cloudflare's model card gives a 32k-token context; stay well under it.
MAX_TOKENS = 24000


def _cfg():
    from .llm_sim import _agentic_cfg
    return _agentic_cfg()


def settings(cfg=None) -> dict:
    cfg = _cfg() if cfg is None else cfg
    j = cfg.get("jev") or {}
    out = {**DEFAULTS, **{k: v for k, v in j.items() if k != "uses"}}
    out["uses"] = {**DEFAULTS["uses"], **(j.get("uses") or {})}
    return out


def _key(cfg):
    # Offline mode is the operator saying "nothing leaves this box" — even if an
    # OpenRouter key is still sitting in the online block.
    if str(cfg.get("llm_mode", "online")).lower() != "online":
        return None
    own = (cfg.get("jev") or {}).get("api_key")
    if own:
        return own
    online = cfg.get("online_llm") or {}
    if (online.get("provider") or "").lower() != "openrouter":
        return None
    return online.get("api_key") or None


def enabled(use, cfg=None) -> bool:
    cfg = _cfg() if cfg is None else cfg
    s = settings(cfg)
    return bool(s["enabled"] and s["uses"].get(use) and _key(cfg))


def min_confidence() -> float:
    try:
        return float(settings()["min_confidence"])
    except (TypeError, ValueError):
        return DEFAULTS["min_confidence"]


def ask(state, questions, *, run_id=None, cfg=None):
    """One Decisions call. Returns the `answers` map, or None on any failure."""
    cfg = _cfg() if cfg is None else cfg
    key = _key(cfg)
    if not key or not questions:
        return None
    model = settings(cfg)["model"]
    try:
        r = requests.post(URL, timeout=15,
                          headers={"Authorization": f"Bearer {key}"},
                          json={"model": model, "state": state, "questions": questions})
        if r.status_code != 200:
            log.warning("jev: HTTP %s: %s", r.status_code, r.text[:200])
            return None
        body = r.json()
    except Exception as e:  # noqa: BLE001 — every failure means "no suggestion"
        log.warning("jev: call failed: %s", e)
        return None
    if run_id:
        u = body.get("usage") or {}
        try:
            from services.workflow_service import record_llm_metrics
            record_llm_metrics(run_id, calls=1, input_tokens=u.get("input_tokens") or 0,
                               output_tokens=u.get("output_tokens") or 0,
                               cost_usd=u.get("cost") or 0.0, model=body.get("model") or model)
        except Exception:  # noqa: BLE001
            pass
    return body.get("answers") or None


def pack(items, render, max_tokens=MAX_TOKENS, max_items=50):
    """Greedy chunks of `items` whose rendered size stays under max_tokens."""
    chunk, size = [], 0
    for it in items:
        t = approx_tokens(render(it))
        if chunk and (size + t > max_tokens or len(chunk) >= max_items):
            yield chunk
            chunk, size = [], 0
        chunk.append(it)
        size += t
    if chunk:
        yield chunk


def ask_each(items, render, question, *, context=None, run_id=None, cfg=None):
    """Ask the same `question(i)` about every item, many items per call.

    The state is {"context": context, "items": {"q0": text, ...}}; question
    q<i> is about item q<i>. Returns one answer (or None) per item, in order.
    Stops at the first failed call — the rest come back None.
    """
    out, base = [], approx_tokens(context) if context is not None else 0
    for chunk in pack(items, render, max_tokens=MAX_TOKENS - base):
        keys = [f"q{i}" for i in range(len(chunk))]
        state = {"items": {k: render(it) for k, it in zip(keys, chunk)}}
        if context is not None:
            state["context"] = context
        ans = ask(state, {k: question(k) for k in keys}, run_id=run_id, cfg=cfg)
        if ans is None:
            return out + [None] * (len(items) - len(out))
        out += [ans.get(k) for k in keys]
    return out


def mask_for(details, graph):
    """The case's anonymiser with its mapping built, or None when masking is off."""
    mk = (details or {}).get("masking") or {}
    if not mk.get("enabled"):
        return None
    try:
        from services.data_anonymizer import DataAnonymizer
        from .llm_sim import _build_mask_mapping
        mask = DataAnonymizer(custom_patterns=mk.get("patterns") or [])
        _build_mask_mapping(graph, mask)
        return mask
    except Exception as e:  # noqa: BLE001
        # Masking was asked for and cannot be done: send nothing rather than
        # the real values.
        log.warning("jev: masking unavailable, skipping: %s", e)
        return False


def masked(text, mask):
    if mask is False:       # masking required but broken — never fall through unmasked
        raise RuntimeError("jev: masking required but unavailable")
    from .llm_sim import _apply_mask
    return _apply_mask(text if isinstance(text, str) else json.dumps(text, default=str), mask)


# ---------------------------------------------------------------------------
# Suggested verdict per finding.
#
# The options are named after the Timeline's own verdict states (TL_STATES in
# cases.html), so the chip's click is the existing tlValidate() call — the
# analyst makes the decision; Jev only saves them reading the evidence cold.
# ---------------------------------------------------------------------------
VERDICTS = {
    "true_positive": "Malicious or attacker activity that needs a response.",
    "known": "Expected activity by IT, administrators or sanctioned tools.",
    "false_positive": "A detection error: the rule fired on something harmless.",
}


def finding_state(g, f) -> dict:
    """What Jev sees about one finding. The offline eval uses this same function,
    so it measures exactly what production sends."""
    from .render import _finding_evidence
    hosts = [getattr(g.entities.get(a), "label", None) or a for a in (f.asset_ids or [])]
    return {"title": f.title, "severity": f.severity, "summary": f.summary,
            "detected_by": list(f.sources or []), "hosts": hosts,
            "mitre": list(f.mitre or []), "evidence": _finding_evidence(g, f)}


def _verdict_question(k):
    return {"type": "choice", "criteria": VERDICTS,
            "instructions": f"items.{k} is one finding from a digital-forensics case. "
                            "Classify it from its detection, hosts and evidence."}


def _answer_to_suggestion(ans):
    if not isinstance(ans, dict) or ans.get("choice") not in VERDICTS:
        return None
    label = ans["choice"]
    probs = ans.get("probabilities") or {}
    return {"label": label, "p": float(probs.get(label, 0.0)),
            "confidence": float(ans.get("confidence") or 0.0)}


def suggest_dispositions(case_id, d, g) -> int:
    """Ask about every unreviewed finding whose occurrences changed since the
    last ask. Returns how many findings were asked about."""
    have = d.get("jev_suggestions") or {}
    validated = {v.get("finding_id") for v in (d.get("timeline_validations") or [])}
    todo = [f for f in g.findings
            if f.id not in validated and f.kind != "dispositioned"
            and (have.get(f.id) or {}).get("wm") != f.watermark()]
    if not todo:
        return 0
    mask = mask_for(d, g)
    answers = ask_each(todo, lambda f: masked(finding_state(g, f), mask),
                       _verdict_question, run_id=case_id)
    new = dict(have)
    for f, ans in zip(todo, answers):
        s = _answer_to_suggestion(ans)
        if s:
            new[f.id] = {"wm": f.watermark(), **s}
    live = {f.id for f in g.findings}
    new = {k: v for k, v in new.items() if k in live}      # findings that vanished
    # The notice: findings Jev is sure are malicious and nobody has reviewed.
    # Stored with titles so the case payload can show it without the graph.
    floor = min_confidence()
    title = {f.id: f.title for f in g.findings}
    notice = [{"id": k, "title": title[k]} for k, v in new.items()
              if v.get("label") == "true_positive" and v.get("confidence", 0) >= floor]
    fresh = [n for n in notice if n["id"] in {f.id for f in todo}]
    if new != have or notice != (d.get("jev_notice") or []):
        from .store import _merge_case_details
        _merge_case_details(case_id, {"jev_suggestions": new, "jev_notice": notice})
    if fresh:
        from .store import log_case_event
        log_case_event(case_id, f"Jev · {len(fresh)} finding(s) look malicious — not reviewed yet",
                       "warning", "; ".join(n["title"] for n in fresh)[:500],
                       finding_ids=[n["id"] for n in fresh])
    return len(todo)


def unreviewed_notice(d):
    """The Analysis-tab notice: Jev's confident true-positives still unreviewed.
    [] when Jev is off — the deterministic page shows nothing extra."""
    if not enabled("disposition"):
        return []
    done = {v.get("finding_id") for v in (d.get("timeline_validations") or [])}
    return [n for n in (d.get("jev_notice") or []) if n.get("id") not in done]


def suggestion_for(d_suggestions, fid, wm):
    """The chip for one Timeline row, or None (stale, unsure, or absent)."""
    s = (d_suggestions or {}).get(fid)
    if not s or s.get("wm") != wm or s.get("confidence", 0) < min_confidence():
        return None
    return {"label": s["label"], "p": s["p"]}


# ---------------------------------------------------------------------------
# Identity-match hints: "are these two accounts the same person?" for the pairs
# the deterministic matcher only SUGGESTS (not corroborated, not decided).
# Merge/Dismiss stay the analyst's buttons; this only adds a number beside them.
# ---------------------------------------------------------------------------
def _pending_identity_pairs(d, g):
    from . import identities as idf
    from .store import _identity_decisions
    decisions = _identity_decisions(d)
    fuzzy = idf.analyst_inputs(g, decisions, idf.compute_candidates(g))["fuzzy"]
    return [c for c in fuzzy if not c.get("auto") and not decisions.get(c["id"])]


def _pair_state(c):
    return {"account_a": c.get("a_label"), "seen_on_a": c.get("a_ctx"),
            "account_b": c.get("b_label"), "seen_on_b": c.get("b_ctx"),
            "why_suggested": c.get("reason")}


def _same_person_question(k):
    return {"type": "noul",
            "instructions": f"items.{k} is a pair of user accounts from a forensic case. "
                            "Do both belong to the same real person?",
            "criteria": {"true": "Same person (e.g. jsmith and john.smith@corp).",
                         "false": "Different people who merely have similar names."}}


def suggest_identities(case_id, d, g) -> int:
    # Masking turns both names into unrelated pseudonyms, which destroys the only
    # signal this question has. Skip rather than send noise.
    if (d.get("masking") or {}).get("enabled"):
        return 0
    have = d.get("jev_identity") or {}
    pairs = _pending_identity_pairs(d, g)
    todo = [c for c in pairs if c["id"] not in have]
    if not todo:
        return 0
    answers = ask_each(todo, _pair_state, _same_person_question, run_id=case_id)
    new = dict(have)
    for c, ans in zip(todo, answers):
        if isinstance(ans, dict) and isinstance(ans.get("noul"), (int, float)):
            new[c["id"]] = float(ans["noul"])
    if new != have:
        from .store import _merge_case_details
        _merge_case_details(case_id, {"jev_identity": new})
    return len(todo)


# ---------------------------------------------------------------------------
# Grounding check on a written report: which statements does the evidence the
# model was given NOT support? Flagged beside the report — never removed.
# ---------------------------------------------------------------------------
import re  # noqa: E402

_SENT = re.compile(r"(?<=[.!?])\s+")
MAX_CLAIMS = 40
UNSUPPORTED_BELOW = 0.3


def _claims(narrative):
    out = []
    for line in (narrative or "").splitlines():
        t = line.strip()
        if not t or t.startswith(("#", "|", ">", "```", "_Narrative")):
            continue
        t = re.sub(r"^[-*+]\s+|^\d+\.\s+", "", t).replace("**", "").replace("`", "")
        out += [c.strip() for c in _SENT.split(t) if 40 <= len(c.strip()) <= 400]
    return out[:MAX_CLAIMS]


def _supported_question(k):
    return {"type": "noul",
            "instructions": f"items.{k} is one statement from an incident report. `context` "
                            "is the case evidence the report was written from. Is the "
                            "statement supported by that evidence?",
            "criteria": {"true": "The evidence states or directly implies it.",
                         "false": "The evidence does not contain it, or contradicts it."}}


def unsupported_claims(narrative, masked_payload, mask, *, run_id=None, log_event=None):
    """Statements in `narrative` (real values) that Jev judges unsupported by the
    (already masked) evidence payload. [] when off, skipped or all supported."""
    if not enabled("grounding"):
        return []
    claims = _claims(narrative)
    if not claims:
        return []
    # Truncating the evidence would make every claim about the cut part look
    # unsupported — a false alarm is worse than no check.
    if approx_tokens(masked_payload) > MAX_TOKENS * 3 // 4:
        if log_event:
            log_event("Report · Jev grounding check skipped", "info",
                      f"the evidence (~{approx_tokens(masked_payload):,} tokens) is larger "
                      f"than one Jev call can read")
        return []
    try:
        answers = ask_each(claims, lambda c: masked(c, mask), _supported_question,
                           context=masked_payload, run_id=run_id)
    except Exception as e:  # noqa: BLE001
        log.warning("jev: grounding check failed: %s", e)
        return []
    bad = [c for c, a in zip(claims, answers)
           if isinstance(a, dict) and isinstance(a.get("noul"), (int, float))
           and a["noul"] < UNSUPPORTED_BELOW]
    if log_event:
        log_event("Report · Jev grounding check", "warning" if bad else "info",
                  f"{len(bad)} of {len(claims)} statements not matched to the evidence")
    return bad


# ---------------------------------------------------------------------------
# Chat: does the analyst's message state a verdict? Only the DETECTION — the
# offer it produces still needs the literal "confirm" to apply (the chat says
# so, and a casual "yes" must never suppress a finding).
# ---------------------------------------------------------------------------
CHAT_VERDICTS = {
    "malicious": "The analyst states the activity is malicious or an attack.",
    "benign": "The analyst states the activity is expected, legitimate or harmless.",
    "none": "The message states no verdict (a question, instruction or other remark).",
}


def chat_verdict(question, d, g, run_id=None):
    """'malicious' | 'benign' | 'none' when Jev is sure, else None (use keywords)."""
    from .llm_sim import is_question
    if not enabled("chat_intent") or is_question(question):
        return None
    try:
        mask = mask_for(d, g)
        ans = (ask({"message": masked(question or "", mask)},
                   {"v": {"type": "choice", "criteria": CHAT_VERDICTS,
                          "instructions": "The message is from a security analyst in a "
                                          "case chat. Does it state a verdict?"}},
                   run_id=run_id) or {}).get("v")
    except Exception as e:  # noqa: BLE001
        log.warning("jev: chat verdict skipped: %s", e)
        return None
    if not isinstance(ans, dict) or ans.get("choice") not in CHAT_VERDICTS:
        return None
    if float(ans.get("confidence") or 0) < min_confidence():
        return None
    return ans["choice"]


# ---------------------------------------------------------------------------
# After every fuse, off the fuse lock, one worker per case.
# ---------------------------------------------------------------------------
import threading  # noqa: E402

_workers_lock = threading.Lock()
_running, _again = set(), set()


def after_fuse(case_id) -> None:
    """Called by store.fuse_case once the lock is released. Never raises."""
    try:
        cfg = _cfg()
        if not any(enabled(u, cfg) for u in ("disposition", "identity")):
            return
        with _workers_lock:
            if case_id in _running:
                _again.add(case_id)          # re-run once the current pass ends
                return
            _running.add(case_id)
        threading.Thread(target=_work, args=(case_id,), daemon=True,
                         name=f"jev-{case_id}").start()
    except Exception as e:  # noqa: BLE001
        log.warning("jev: after_fuse(%s) not started: %s", case_id, e)


def _work(case_id):
    try:
        while True:
            try:
                _one_pass(case_id)
            except Exception as e:  # noqa: BLE001 — a suggestion is never worth an error
                log.warning("jev: pass for %s failed: %s", case_id, e)
            with _workers_lock:
                if case_id not in _again:
                    _running.discard(case_id)
                    return
                _again.discard(case_id)
    except BaseException:
        with _workers_lock:
            _running.discard(case_id)
        raise


def _one_pass(case_id):
    from .store import get_case, view_graph
    d = get_case(case_id)
    if not d:
        return
    g = view_graph(case_id, d, scoped=False)
    if enabled("disposition"):
        suggest_dispositions(case_id, d, g)
    if enabled("identity"):
        suggest_identities(case_id, d, g)


# ---------------------------------------------------------------------------
# Relevance: score a case's RAW collected rows (Velociraptor results, cached
# Timesketch events) for "worth an analyst's attention in this case?", and keep
# the top of the list. A System action (Settings → Actions): it can take
# minutes and many calls, so it is started on demand, can be stopped, and
# shows its progress and log there. Cases hold no event store of their own, so
# these rows are the only raw material there is.
# ---------------------------------------------------------------------------
MAX_ROWS = 20000          # a hard ceiling per run — bounded cost, said in the log
KEEP = 200
ROW_CHARS = 500
RELEVANT_FROM = 0.5


def _run_host(det):
    h = det.get("client_name")
    cl = det.get("clients")
    if not h and isinstance(cl, list) and cl and isinstance(cl[0], dict):
        h = cl[0].get("client_name")
    hns = det.get("hostnames")
    if not h and isinstance(hns, list) and hns:
        h = hns[0]
    return h


def _case_rows(case_id, d, log_fn):
    """(run_id, artifact, row_index, text) for every raw row, excluded hosts left out."""
    from . import keys
    from .store import _agentic_collected_data, _members_for_case, _ws
    ws = _ws()
    excluded = {keys.norm_host(h) for h in (d.get("excluded_hosts") or []) if h}
    for rid in _members_for_case(case_id, d):
        run = ws.get_automation_run(rid) or {}
        det = run.get("details") or {}
        host = _run_host(det)
        if host and keys.norm_host(host) in excluded:
            continue
        evs = det.get("timeline_events") or det.get("events")
        data = ({"timesketch": evs} if isinstance(evs, list) and evs
                else _agentic_collected_data(rid, det, log=log_fn))
        for artifact, rows in (data or {}).items():
            if not isinstance(rows, list):
                continue
            for i, row in enumerate(rows):
                text = json.dumps(row, default=str, ensure_ascii=False)[:ROW_CHARS]
                if host:
                    text = f"[{host}] {text}"
                yield rid, artifact, i, text


def _relevant_question(k):
    return {"type": "noul",
            "instructions": f"items.{k} is one raw row collected from a host in a forensic "
                            "case; `context` lists the case's findings. Is this row relevant "
                            "to the investigation — worth an analyst's attention?",
            "criteria": {"true": "It shows attacker activity, or evidence about a finding.",
                         "false": "Routine system noise unrelated to the findings."}}


def score_relevance(case_id, *, run_id, cancel):
    """The System action's body (see case_routes.start_relevance). Returns the
    run's result details; raises on stop/failure after saving what it scored."""
    from datetime import datetime
    from services import workflow_service as ws
    from .store import _merge_case_details, get_case, view_graph

    def say(msg, level="info"):
        ws.add_log_to_run(run_id, msg, level)

    d = get_case(case_id)
    if not d:
        raise RuntimeError("case not found")
    g = view_graph(case_id, d, scoped=False)
    mask = mask_for(d, g)
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    top = sorted(g.findings, key=lambda f: rank.get(f.severity, 4))[:30]
    context = masked({"case_findings": [f.title for f in top]}, mask)

    items = []
    for it in _case_rows(case_id, d, lambda m, lvl="info": say(m, lvl)):
        if len(items) >= MAX_ROWS:
            say(f"More than {MAX_ROWS:,} rows — scoring the first {MAX_ROWS:,} only.", "warning")
            break
        items.append((*it, masked(it[3], mask)))       # masked once, sent as-is
    if not items:
        raise RuntimeError("this case has no collected rows to score")
    say(f"Scoring {len(items):,} collected rows with Jev.")

    scored, done = [], 0

    def save():
        best = sorted((s for s in scored if s["p"] >= RELEVANT_FROM),
                      key=lambda s: -s["p"])[:KEEP]
        _merge_case_details(case_id, {"jev_relevance": {
            "scored_at": datetime.now().isoformat(timespec="seconds"),
            "rows_scored": done, "rows_total": len(items), "rows": best}})
        return best

    for chunk in pack(items, lambda it: it[4],
                      max_tokens=MAX_TOKENS - approx_tokens(context)):
        if cancel.is_set():
            save()
            raise RuntimeError("stopped")
        keys = [f"q{i}" for i in range(len(chunk))]
        ans = ask({"context": context,
                   "items": {k: it[4] for k, it in zip(keys, chunk)}},
                  {k: _relevant_question(k) for k in keys}, run_id=run_id)
        if ans is None:
            save()
            raise RuntimeError(f"Jev stopped answering after {done:,} of {len(items):,} "
                               "rows — the rows scored so far are kept")
        for k, (rid, artifact, i, text, _m) in zip(keys, chunk):
            p = (ans.get(k) or {}).get("noul")
            if isinstance(p, (int, float)):
                scored.append({"run_id": rid, "artifact": artifact, "row": i,
                               "text": text, "p": round(float(p), 3)})
        done += len(chunk)
        ws.update_run_status(run_id, "running", progress=int(done * 100 / len(items)))
    best = save()
    say(f"Done: {done:,} rows scored, {len(best)} kept as relevant (≥{RELEVANT_FROM:.0%}).",
        "success")
    return {"case_id": case_id, "rows_scored": done, "relevant": len(best)}
