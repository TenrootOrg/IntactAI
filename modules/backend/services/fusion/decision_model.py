"""The decision model — small, closed decisions with probabilities, never text.

A decision model does not write text. It takes a `state` (any JSON) plus named
questions, each a yes/no ("noul"), pick-one ("choice") or ordered "score", and
returns a typed answer with probabilities. The operator picks where it runs
(Settings → Agentic → Decision model): OpenRouter (default: TypeSafe's Jev,
`jev-latest`; also every other decision model it serves), OpenAI's Decisions API,
or -- in Offline mode -- a Jev-compatible server on the local network. Each has its own
key; empty uses the AI model's key while that runs on the same provider, so a box
whose chat runs on Claude or a Codex subscription can still use it. (This module was services/fusion/jev.py; the
feature was renamed to the generic "decision model" in 2026-10, when other
vendors began serving the same kind of model.)

EVERYTHING HERE IS A SUGGESTION. Nothing in this module, or in any caller,
sets a disposition, merges an identity or edits a report on the model's word:
the analyst still clicks. Any failure returns None and the caller carries on
exactly as it does with the decision model switched off (the default).

Masked case data leaves the box when this is on — the Settings block says so.
"""
import json
import logging
import threading

import requests

from .budget import approx_tokens

log = logging.getLogger(__name__)

# Where each provider is and how it is spoken to. "jev" is the wire TypeSafe defined
# and OpenRouter (every decision model it serves) and a local server accept; "openai" is OpenAI's own
# Decisions API (different field names, translated below). `cloud` providers are
# off in Offline mode; "local" is the only one allowed there and must resolve to a
# private address. Contracts observed 2026-10-11, see docs/DECISION_MODEL.md.
PROVIDERS = {
    "openrouter": {"url": "https://openrouter.ai/api/v1/systemone", "wire": "jev", "cloud": True,
                   "model": "jev-latest", "timeout": 15, "label": "OpenRouter"},
    "openai": {"url": "https://api.openai.com/v1/decisions", "wire": "openai", "cloud": True,
               "model": "gpt-6-luna", "timeout": 15, "label": "OpenAI"},
    "local": {"url": "", "wire": "jev", "cloud": False, "model": "", "timeout": 60, "label": "Local server"},
}
URL = PROVIDERS["openrouter"]["url"]
# Known models: suggested in Settings, and how much one call may carry. `budget` is
# what pack() fills (our chars/4 estimate); `cut_at` is where a provider silently
# TRUNCATES instead of refusing -- Clef on OpenRouter read the first 16,384 tokens of
# a 50k request and answered from them (2026-10-11), so an answer that used exactly
# that many tokens is treated as "too big" and split, never trusted.
MODELS = [
    {"provider": "openrouter", "model": "jev-latest", "budget": 24000,
     "note": "TypeSafe Jev — the default; ~0.4 s a call"},
    {"provider": "openrouter", "model": "cloudflare/clef", "budget": 12000, "cut_at": 16384,
     "note": "Cloudflare Clef (open weights) — ~1.4 s a call"},
    {"provider": "openrouter", "model": "cloudflare/clef-flash", "budget": 12000, "cut_at": 16384,
     "note": "Cloudflare Clef Flash — cheapest, ~1.2 s a call"},
    {"provider": "openai", "model": "gpt-6-luna", "budget": 24000,
     "note": "OpenAI Decisions API (beta) — needs an OpenAI API key; not yet tested live"},
    # Conformance pass 2026-10-11 (docs/DECISION_MODEL.md): same wire, but limits or
    # answers that differ. `max_questions`: refused 40 questions in one call.
    # `avoid`: wrong too often on obvious cases -- left out of the suggestions
    # (it can still be typed).
    {"provider": "openrouter", "model": "togethercomputer/tev1-4b-experimental", "budget": 12288,
     "max_questions": 32, "note": "Together Tev1 4B (experimental) — at most 32 questions a call"},
    {"provider": "openrouter", "model": "upstage/solar-decide-flash", "budget": 24000,
     "avoid": "21 of 40 obvious cases right", "note": "Upstage Solar Decide Flash"},
    {"provider": "openrouter", "model": "upstage/solar-decide", "budget": 24000,
     "avoid": "27 of 40 obvious cases right, 14 s for 40 questions", "note": "Upstage Solar Decide"},
]
MAX_QUESTIONS = 50             # per call, unless the model says fewer
# OpenRouter lists every decision model it serves under this filter (found
# 2026-10-11: plain /models lists chat models only). "Update catalog" stores it;
# the hand-checked MODELS above win where both name a model (Clef's listed 64k
# context is really a silent 16k cut on OpenRouter's provider).
CATALOG_URL = "https://openrouter.ai/api/v1/models?output_modalities=decisions"
CATALOG_PATH = "/app/data/decision_models.json"
_store = []


def _catalog_store():
    if not _store:
        from services.llm_catalogs.base import CatalogStore
        _store.append(CatalogStore("decision", CATALOG_PATH, CATALOG_URL))
    return _store[0]


def refresh_catalog(cfg=None) -> dict:
    """Fetch OpenRouter's decision models into CATALOG_PATH (kept if the fetch is empty)."""
    cfg = _cfg() if cfg is None else cfg
    key = _key({**cfg, "decision_model": {**(cfg.get("decision_model") or {}), "mode": "online",
                                          "provider": "openrouter"}})
    r = requests.get(CATALOG_URL, timeout=30, allow_redirects=False,
                     headers={"Authorization": f"Bearer {key}"} if key else {})
    r.raise_for_status()
    rows = []
    for m in r.json().get("data") or []:
        mid = m.get("id") or ""
        if not mid or mid.startswith("~"):          # "~typesafe/jev-latest" = our jev-latest alias
            continue
        try:
            price = float((m.get("pricing") or {}).get("prompt") or 0) * 1e6
        except (TypeError, ValueError):
            price = 0.0
        rows.append({"provider": "openrouter", "model": mid, "name": m.get("name") or mid,
                     "context": int(m.get("context_length") or 0), "price_per_m": round(price, 4)})
    return _catalog_store().write(rows)


def catalog() -> list:
    """Known models: the hand-checked MODELS, then whatever the last Update catalog listed."""
    out = list(MODELS)
    have = {(r["provider"], r["model"]) for r in out}
    try:
        listed = _catalog_store().load()
    except Exception:  # noqa: BLE001 -- suggestions only
        listed = []
    for m in listed:
        if (m.get("provider"), m.get("model")) in have:
            continue
        ctx = int(m.get("context") or 0)
        # 3/8 of the listed window: Jev lists 64k and refused our chars/4-estimated
        # batches above ~24k (2026-09). The listing is the vendor's word, not ours.
        budget = min(24000, ctx * 3 // 8) if ctx else UNKNOWN_BUDGET
        note = f"{m.get('name')} — {ctx // 1000}k context, ${m.get('price_per_m', 0):g}/M input" if ctx \
            else f"{m.get('name')} — ${m.get('price_per_m', 0):g}/M input"
        out.append({"provider": m.get("provider"), "model": m.get("model"), "budget": budget, "note": note})
    return out


USES = ("disposition", "relevance", "grounding", "identity", "chat_intent", "injection",
        "chat_confidence", "scopes", "compromise", "report")
DEFAULTS = {"enabled": False,
            # "" = follow the AI model's mode (every box saved before the provider
            # choice existed: an offline box must not start calling a cloud).
            "mode": "", "provider": "openrouter", "model": "jev-latest",
            "url": "",                 # local only
            "context_tokens": 0,       # 0 = the known model's budget, else UNKNOWN_BUDGET
            "min_confidence": 0.8,
            # The decision model's own key. Empty = the AI model's key while that runs
            # on the same provider (OpenRouter, or OpenAI with an API key).
            "api_key": "",
            "uses": {u: True for u in USES}}
MAX_TOKENS = 24000             # Jev's budget, the default
UNKNOWN_BUDGET = 6000          # a local model nobody measured: small and safe
DEFAULT_BY = "openrouter/jev-latest"   # what wrote a cache saved before caches were stamped


def _cfg():
    from .llm_sim import _agentic_cfg
    return _agentic_cfg()


def settings(cfg=None) -> dict:
    cfg = _cfg() if cfg is None else cfg
    j = cfg.get("decision_model") or {}
    out = {**DEFAULTS, **{k: v for k, v in j.items() if k != "uses"}}
    out["uses"] = {**DEFAULTS["uses"], **(j.get("uses") or {})}
    return out


def provider(cfg) -> str:
    s = settings(cfg)
    mode = str(s.get("mode") or cfg.get("llm_mode", "online")).lower()
    if mode != "online":
        return "local"
    p = s.get("provider")
    return p if p in PROVIDERS and PROVIDERS[p]["cloud"] else "openrouter"


def model_name(cfg) -> str:
    s, p = settings(cfg), provider(cfg)
    m = (s.get("model") or "").strip()
    # The model saved for another provider means nothing here (jev-latest is not an
    # OpenAI model): fall back to this provider's own default.
    if m and any(r["model"] == m and r["provider"] != p for r in catalog()):
        m = ""
    return m or PROVIDERS[p]["model"]


def _known(cfg):
    p, m = provider(cfg), model_name(cfg)
    return next((r for r in catalog() if r["provider"] == p and r["model"] == m), {})


def max_questions(cfg=None) -> int:
    cfg = _cfg() if cfg is None else cfg
    return int(_known(cfg).get("max_questions") or MAX_QUESTIONS)


def context_tokens(cfg=None) -> int:
    """How many (estimated) tokens one call may carry for the model in use."""
    cfg = _cfg() if cfg is None else cfg
    try:
        own = int(settings(cfg).get("context_tokens") or 0)
    except (TypeError, ValueError):
        own = 0
    return own if own > 0 else _known(cfg).get("budget") or UNKNOWN_BUDGET


def current_by(cfg=None) -> str:
    """The provider/model a cache was written by -- caches from another one are not shown."""
    cfg = _cfg() if cfg is None else cfg
    return f"{provider(cfg)}/{model_name(cfg)}"


def _key(cfg):
    """The key to send, "" when the provider takes none, None when it cannot be used."""
    p = provider(cfg)
    s = settings(cfg)
    own = s.get("api_key") or ""
    if p == "local":
        return own if (s.get("url") or "").strip() else None
    if own:
        return own
    online = cfg.get("online_llm") or {}
    if str(cfg.get("llm_mode", "online")).lower() == "online" and (online.get("provider") or "").lower() == p:
        return online.get("api_key") or None        # OpenAI *Subscription* is a different provider id
    return None


def _url(cfg) -> str:
    p = provider(cfg)
    return PROVIDERS[p]["url"] or (settings(cfg).get("url") or "").strip()


def enabled(use, cfg=None) -> bool:
    cfg = _cfg() if cfg is None else cfg
    s = settings(cfg)
    return bool(s["enabled"] and s["uses"].get(use) and _key(cfg) is not None)


def why_inactive(cfg=None) -> str:
    """Why no call can be made with these settings ("" when one can), in the operator's words."""
    cfg = _cfg() if cfg is None else cfg
    if _key(cfg) is not None:
        return ""
    p = provider(cfg)
    if p == "local":
        return "Offline mode needs the URL of a decision-model server on your network."
    label = PROVIDERS[p]["label"]
    return f"Needs an {label} API key here (or {label} as the AI model's provider, in Online mode)."


def min_confidence() -> float:
    try:
        return float(settings()["min_confidence"])
    except (TypeError, ValueError):
        return DEFAULTS["min_confidence"]


def cached(d, name, cfg=None) -> dict:
    """A case's decision_<name> cache, or {} when another provider/model wrote it: a
    switch from Jev to Clef must not show Jev's answers as Clef's."""
    by = (d.get("decision_by") or {}).get(name, DEFAULT_BY)
    return (d.get(f"decision_{name}") or {}) if by == current_by(cfg) else {}


def _save(case_id, **caches):
    """Write decision_<name> caches and stamp each with the model that answered."""
    from .store import get_case, _merge_case_details
    by = dict((get_case(case_id) or {}).get("decision_by") or {})   # fresh: another pass may have stamped
    now = current_by()
    by.update({k: now for k in caches})
    _merge_case_details(case_id, {**{f"decision_{k}": v for k, v in caches.items()}, "decision_by": by})


# One failure answers for every decision-model call: the provider is skipped until DOWN_SECONDS
# have passed or its provider / URL / key / model change. On an air-gapped box every feature
# (verdicts, phases, people, report grounding, chat) asked on its own after every fuse and
# report -- 15 rejected calls in one minute -- each one waiting out a timeout or a 401
# that the first had already answered.
DOWN_SECONDS = 600
_down = {"until": 0.0, "fp": None, "why": ""}


def _fp(cfg):
    import hashlib
    return hashlib.sha1(f"{provider(cfg)}|{_url(cfg)}|{model_name(cfg)}|{_key(cfg)}".encode()).hexdigest()[:12]


def retry_now():
    """An operator asked for a live answer (Settings' Test, a Refusion they clicked):
    forget the last failure. The pause is for automatic fuses on an offline box; it
    kept a box that had just come back online silent for ten minutes."""
    _down["until"] = 0.0


def unavailable(cfg=None):
    """Why the decision model is being skipped right now, or "" when it may be called."""
    import time
    cfg = _cfg() if cfg is None else cfg
    if _down["fp"] == _fp(cfg) and time.monotonic() < _down["until"]:
        return _down["why"]
    return ""


def _private_only(url):
    """"" when every address the URL's host resolves to is loopback / private /
    link-local, else why not. A "local" model must not quietly be a cloud one."""
    import ipaddress
    import socket
    from urllib.parse import urlparse
    host = urlparse(url).hostname
    if not host:
        return "the local URL has no host"
    try:
        addrs = {ai[4][0] for ai in socket.getaddrinfo(host, None)}
    except OSError as e:
        return f"the local host {host} does not resolve ({e})"
    # ponytail: resolved here and again by requests -- a DNS-rebinding window. The
    # operator owns this URL; pin the IP in the request if that ever matters.
    bad = [a for a in addrs if not (lambda ip: ip.is_private or ip.is_loopback or ip.is_link_local)(
        ipaddress.ip_address(a.split("%")[0]))]
    return f"the local URL resolves to a public address ({bad[0]})" if bad else ""


# --- wire formats ----------------------------------------------------------------
def _openai_body(model, state, questions):
    """Jev-shaped questions -> OpenAI's: predicate / choice, an ordered array by name."""
    qs = []
    for qid, q in questions.items():
        crit = q.get("criteria") or {}
        if q.get("type") == "noul":
            text = q.get("instructions", "")
            if crit:   # a predicate has no criteria slot: say what true / false mean
                text += " True means: " + str(crit.get("true", "")) + " False means: " + str(crit.get("false", ""))
            qs.append({"type": "predicate", "name": qid, "instructions": text})
        elif q.get("type") == "choice":
            qs.append({"type": "choice", "name": qid, "instructions": q.get("instructions", ""),
                       "choices": [{"value": k, "description": v} for k, v in crit.items()]})
        else:
            raise ValueError(f"question type {q.get('type')!r} is not mapped for OpenAI")
    return {"model": model, "input": json.dumps(state), "questions": qs}


def _openai_answers(body):
    """OpenAI's answers array -> Jev's {qid: answer} map."""
    out = {}
    for a in body.get("answers") or []:
        name = a.get("name")
        if a.get("type") == "predicate":
            out[name] = {"type": "noul", "noul": a.get("probability")}
        elif a.get("type") == "choice":
            out[name] = {"type": "choice", "choice": a.get("choice"), "confidence": a.get("confidence"),
                         "probabilities": {p.get("value"): p.get("probability")
                                           for p in a.get("probabilities") or []}}
    return out


def _cost(body, model):
    u = body.get("usage") or {}
    if u.get("cost") is not None:
        return u["cost"]
    if model.startswith("gpt-6-luna"):          # tokens only; $0.10 per million input (beta price)
        return (u.get("input_tokens") or 0) * 0.10 / 1e6
    return 0.0


def ask(state, questions, *, run_id=None, cfg=None):
    """One Decisions call. Returns the `answers` map, or None on any failure;
    _last.too_big says whether it failed for being too large (per thread: the
    after-fuse pass, a report and the relevance job can call at once)."""
    ans, _last.too_big = _call(state, questions, run_id=run_id, cfg=cfg)
    return ans


_last = threading.local()


def _call(state, questions, *, run_id=None, cfg=None):
    """(answers or None, too_big). too_big = the model called the request too large
    (or silently cut it): the caller splits and retries; it is not an outage."""
    import time
    cfg = _cfg() if cfg is None else cfg
    key = _key(cfg)
    if key is None or not questions:
        return None, False
    p, model, url = provider(cfg), model_name(cfg), _url(cfg)
    row = PROVIDERS[p]
    if unavailable(cfg):                     # failed moments ago: skip, offline, no call
        return None, False

    def _trip(why):
        if not unavailable(cfg):
            log.warning("decision model: %s -- every decision-model call is skipped for %d min (offline) or until "
                        "its settings change", why, DOWN_SECONDS // 60)
        _down.update(until=time.monotonic() + DOWN_SECONDS, fp=_fp(cfg), why=why)
    if not row["cloud"]:
        why = _private_only(url)
        if why:
            _trip(why)
            return None, False
    try:
        body = (_openai_body(model, state, questions) if row["wire"] == "openai"
                else {"model": model, "state": state, "questions": questions})
    except ValueError as e:
        log.warning("decision model: %s", e)
        return None, False
    try:
        # A 5xx is the provider's own hiccup, not an outage: retried ONCE. Seen
        # live: one HTTP 520 on the verdict question left a 285-finding case with
        # no suggestions at all, silently. A connection error, a timeout or a 4xx
        # is still one call -- a dead provider must not cost a dozen.
        # No redirects: a "local" server must not bounce case data elsewhere, and
        # a cloud endpoint that moved should fail loudly, not follow blindly.
        for attempt in (0, 1):
            r = requests.post(url, timeout=row["timeout"], allow_redirects=False,
                              headers={"Authorization": f"Bearer {key}"} if key else {}, json=body)
            if r.status_code < 500 or attempt:
                break
            log.warning("decision model: HTTP %s — retrying once", r.status_code)
            time.sleep(RETRY_SECONDS)
        if r.status_code != 200:
            # The model's own token count is the only exact one; ours is chars/4. A
            # request it calls too large is split and retried by _ask_chunk.
            too_big = r.status_code in (400, 413) and any(
                w in r.text for w in ("max_tokens", "context_length", "too long", "too large",
                                      "questions per request"))   # Tev1: "at most 32 questions per request"
            log.warning("decision model: HTTP %s: %s", r.status_code, r.text[:200])
            if not too_big:                          # too big is ours to split, not an outage
                _trip(f"HTTP {r.status_code}")
            return None, too_big
        body = r.json()
    except Exception as e:  # noqa: BLE001 — every failure means "no suggestion"
        log.warning("decision model: call failed: %s", e)
        _trip(f"unreachable ({type(e).__name__})")
        return None, False
    _down["until"] = 0.0                         # answered: not down
    u = body.get("usage") or {}
    cut = _known(cfg).get("cut_at")
    if cut and (u.get("input_tokens") or 0) >= cut:
        log.warning("decision model: %s read only %s tokens of the request -- split and asked again", model, cut)
        return None, True
    if run_id:
        try:
            from services.workflow_service import record_llm_metrics
            record_llm_metrics(run_id, calls=1, input_tokens=u.get("input_tokens") or 0,
                               output_tokens=u.get("output_tokens") or 0,
                               cost_usd=_cost(body, model), model=body.get("model") or model)
        except Exception:  # noqa: BLE001
            pass
    answers = _openai_answers(body) if row["wire"] == "openai" else body.get("answers")
    return answers or None, False


RETRY_SECONDS = 2              # the pause before the one retry of a 5xx answer


def pack(items, render, max_tokens=None, max_items=None, per_item=0):
    """Greedy chunks of `items` whose rendered size — plus `per_item` tokens for
    the question each item brings — stays under max_tokens."""
    max_tokens = context_tokens() if max_tokens is None else max_tokens
    max_items = max_questions() if max_items is None else max_items
    chunk, size = [], 0
    for it in items:
        t = approx_tokens(render(it)) + per_item
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
    for chunk in pack(items, render, max_tokens=context_tokens(cfg) - base, max_items=max_questions(cfg),
                      per_item=_question_tokens(question)):
        ans = _ask_chunk(chunk, render, question, context, run_id=run_id, cfg=cfg)
        if ans is None:
            return out + [None] * (len(items) - len(out))
        out += ans
    return out


def _question_tokens(question) -> int:
    """What one item's question adds to a request (instructions + criteria)."""
    return approx_tokens(json.dumps(question("q000"))) + 8


def _ask_chunk(chunk, render, question, context=None, *, run_id=None, cfg=None):
    """One answer (or None) per item of `chunk`, or None if the call failed.

    Found live: batches our chars/4 estimate thought fit were refused by Jev as
    max_tokens_exceeded, and every row after them went unanswered (108 of 323).
    A request the model calls too large is split in half and retried, down to single
    items. Any other failure (outage, auth) is NOT retried — it returns None at
    once, so a dead provider costs one call, not a dozen.
    """
    keys = [f"q{i}" for i in range(len(chunk))]
    state = {"items": {k: render(it) for k, it in zip(keys, chunk)}}
    if context is not None:
        state["context"] = context
    ans = ask(state, {k: question(k) for k in keys}, run_id=run_id, cfg=cfg)
    if ans is not None:
        return [ans.get(k) for k in keys]
    if not getattr(_last, "too_big", False) or len(chunk) < 2:
        return None
    mid = len(chunk) // 2
    left = _ask_chunk(chunk[:mid], render, question, context, run_id=run_id, cfg=cfg)
    if left is None:
        return None
    right = _ask_chunk(chunk[mid:], render, question, context, run_id=run_id, cfg=cfg)
    return None if right is None else left + right


def mask_for(details, graph):
    """The case's anonymiser with its mapping built, or None when masking is off."""
    mk = (details or {}).get("masking") or {}
    if not mk.get("enabled"):
        return None
    try:
        from services.data_anonymizer import DataAnonymizer
        from .llm_sim import _build_mask_mapping
        mask = DataAnonymizer(custom_patterns=mk.get("patterns") or [])
        mask._ner = bool(mk.get("ner"))     # optional NER second pass (presidio_masker)
        _build_mask_mapping(graph, mask)
        return mask
    except Exception as e:  # noqa: BLE001
        # Masking was asked for and cannot be done: send nothing rather than
        # the real values.
        log.warning("decision model: masking unavailable, skipping: %s", e)
        return False


def masked(text, mask):
    if mask is False:       # masking required but broken — never fall through unmasked
        raise RuntimeError("decision model: masking required but unavailable")
    from .llm_sim import _apply_mask
    return _apply_mask(text if isinstance(text, str) else json.dumps(text, default=str), mask)


# ---------------------------------------------------------------------------
# Suggested verdict per finding.
#
# The options are named after the Timeline's own verdict states (TL_STATES in
# cases.html), so the chip's click is the existing tlValidate() call — the
# analyst makes the decision; the model only saves them reading the evidence cold.
# ---------------------------------------------------------------------------
VERDICTS = {
    "true_positive": "Malicious or attacker activity that needs a response.",
    "known": "Expected activity by IT, administrators or sanctioned tools.",
    "false_positive": "A detection error: the rule matched something harmless.",
}


def finding_state(g, f) -> dict:
    """What the decision model sees about one finding. The offline eval uses this same function,
    so it measures exactly what production sends."""
    from .render import _finding_evidence
    hosts = [getattr(g.entities.get(a), "label", None) or a for a in (f.asset_ids or [])]
    state = {"title": f.title, "severity": f.severity, "summary": f.summary,
             "detected_by": list(f.sources or []), "hosts": hosts,
             "mitre": list(f.mitre or []), "evidence": _finding_evidence(g, f)}
    # A daily routine is the strongest sign of scheduled, expected activity —
    # without it Jev rated one routine "92% likely true positive" once per day.
    r = getattr(f, "recurring", None)
    if r and r.get("period") == "maintenance":
        state["pattern"] = (f"the same detection about the same object, {r.get('days')} times over "
                            f"{r.get('span_days')} days, only version numbers changing — the "
                            f"pattern of software updating itself")
    elif r:
        weekly = r.get("period") == "weekly"
        state["pattern"] = (f"recurring every {'week' if weekly else 'day'} at about {r.get('tod')} "
                            f"UTC for {r.get('days')} {'weeks' if weekly else 'days'}, the same small "
                            f"number of hits each time")
    return state


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


NOTICE_NAMES = 5          # findings named in the Log's "not reviewed yet" line


def suggest_dispositions(case_id, d, g) -> int:
    """Ask about every unreviewed finding whose occurrences changed since the
    last ask. Returns how many findings were asked about."""
    have = cached(d, "suggestions")
    validated = {v.get("finding_id") for v in (d.get("timeline_validations") or [])}
    from .correlate import _part_ids
    # Reviewed = the row or any of its parts has a verdict (a row judged part by
    # part was still asked about, and still listed as "not reviewed yet").
    todo = [f for f in g.findings
            if not (set(f.ids() + _part_ids(f)) & validated) and f.kind != "dispositioned"
            and (have.get(f.id) or {}).get("wm") != f.watermark()]
    new = dict(have)
    if todo:
        mask = mask_for(d, g)
        answers = ask_each(todo, lambda f: masked(finding_state(g, f), mask),
                           _verdict_question, run_id=case_id)
        for f, ans in zip(todo, answers):
            s = _answer_to_suggestion(ans)
            if s:
                new[f.id] = {"wm": f.watermark(), **s}
        if not any(a is not None for a in answers):
            # Said in the case Log: it used to show only in the backend log, so a
            # Timeline with no suggestion chips looked like "nothing to suggest".
            from .store import log_case_event
            log_case_event(case_id, "Decision model · no verdict suggestions this time", "info",
                           f"The decision model did not answer for {len(todo)} finding(s) (its provider "
                           "returned an error or could not be reached) — they are asked "
                           "about again on the next fuse")
    # No early return when nothing changed: the notice below must still be built
    # (a case suggested before the notice existed, or a changed threshold).
    live = {f.id for f in g.findings}
    new = {k: v for k, v in new.items() if k in live}      # findings that vanished
    # The notice: findings the model is sure are malicious and nobody has reviewed.
    # Stored with titles so the case payload can show it without the graph.
    floor = min_confidence()
    title = {f.id: f.title for f in g.findings}
    alias = {f.id: [a for a in f.ids() if a != f.id] for f in g.findings}
    # The detection name, so the page groups rows by what fired rather than by
    # re-parsing titles (which split "Shared binary: x on 3 hosts" wrongly).
    from .correlate import _detection_name
    det = {f.id: _detection_name(f) for f in g.findings}
    parts = {f.id: _part_ids(f) for f in g.findings if f.parts}
    notice = [{"id": k, "title": title[k], "detection": det[k], "aliases": alias.get(k) or [],
               **({"parts": parts[k]} if parts.get(k) else {})}
              for k, v in new.items()
              if v.get("label") == "true_positive" and v.get("confidence", 0) >= floor]
    fresh = [n for n in notice if n["id"] in {f.id for f in todo}]
    if new != have or notice != (cached(d, "notice") or []):
        _save(case_id, suggestions=new, notice=notice)
    if fresh:
        from .store import log_case_event
        # INFO, not a warning: nothing went wrong -- it says where to look first. As a
        # warning it read as a fault in a run that had none ("I dont wanna see any
        # warnings why is this?").
        # The first few by name, then a count: 98 findings used to print as a
        # 500-character wall of "Defender Alert (Severe) ...; Rubeus ...; Mimikatz ...".
        _names = "; ".join(n["title"] for n in fresh[:NOTICE_NAMES])
        if len(fresh) > NOTICE_NAMES:
            _names += f" … +{len(fresh) - NOTICE_NAMES} more — see the Timeline"
        log_case_event(case_id, f"Decision model · {len(fresh)} finding(s) look malicious — not reviewed yet",
                       "info", _names[:700],
                       finding_ids=[n["id"] for n in fresh])
    return len(todo)


def suggestion_for(d_suggestions, fid, wm):
    """The chip for one Timeline row, or None (stale, unsure, or absent)."""
    s = (d_suggestions or {}).get(fid)
    if not s or s.get("wm") != wm or s.get("confidence", 0) < min_confidence():
        return None
    # Show the number the chip is gated on. It showed the label's probability
    # while gating on the model's confidence, so a "74%" chip appeared under an 80% floor.
    return {"label": s["label"], "p": s.get("confidence", 0)}


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
    have = cached(d, "identity")
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
        _save(case_id, identity=new)
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
    """Statements in `narrative` (real values) that the decision model judges unsupported by the
    (already masked) evidence payload. [] when off, skipped or all supported."""
    if not enabled("grounding"):
        return []
    claims = _claims(narrative)
    if not claims:
        return []
    # Truncating the evidence would make every claim about the cut part look
    # unsupported — a false alarm is worse than no check.
    if approx_tokens(masked_payload) > context_tokens() * 3 // 4:
        if log_event:
            log_event("Report · decision model grounding check skipped", "info",
                      f"the evidence (~{approx_tokens(masked_payload):,} tokens) is larger "
                      f"than one decision-model call can read")
        return []
    try:
        answers = ask_each(claims, lambda c: masked(c, mask), _supported_question,
                           context=masked_payload, run_id=run_id)
    except Exception as e:  # noqa: BLE001
        log.warning("decision model: grounding check failed: %s", e)
        return []
    bad = [c for c, a in zip(claims, answers)
           if isinstance(a, dict) and isinstance(a.get("noul"), (int, float))
           and a["noul"] < UNSUPPORTED_BELOW]
    if log_event:
        log_event("Report · decision model grounding check", "warning" if bad else "info",
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
    """'malicious' | 'benign' | 'none' when the decision model is sure, else None (use keywords)."""
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
        log.warning("decision model: chat verdict skipped: %s", e)
        return None
    if not isinstance(ans, dict) or ans.get("choice") not in CHAT_VERDICTS:
        return None
    if float(ans.get("confidence") or 0) < min_confidence():
        return None
    return ans["choice"]


# ---------------------------------------------------------------------------
# Chat: "how likely is kobi malicious?" — the decision model's estimate for the account or host
# the question names, added under the model's answer. A number with its basis,
# labelled as a second opinion; nothing about the case changes.
# ---------------------------------------------------------------------------
_RISK_WORDS = ("malicious", "compromis", "suspicious", "attacker", "bad actor", "threat actor",
               "intruder", "hacker", "confiden", "likely", "risk", "guilty", "innocent",
               "legit", "clean", "trust", "זדוני", "חשוד", "תוקף", "פרוץ", "נפרץ", "סיכון",
               "בטוח", "לגיטימי")
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def analyst_verdicts(d) -> dict:
    """finding id -> the analyst's verdict ("true_positive" / "false_positive" /
    "known"), from the Timeline and from chat dispositions. Every estimate below
    sends it with each finding and keys its cache on it, so a verdict changes the
    number: a finding the analyst ruled out must not keep pushing it up."""
    from .render import analyst_verdict_map
    return analyst_verdict_map((d or {}).get("dispositions"), (d or {}).get("timeline_validations"))


def _verdict_of(f, verdicts):
    from .render import row_verdict
    return row_verdict(f, verdicts)


def _finding_brief(g, f, verdicts, n_ev):
    from .render import _finding_evidence
    b = {"title": f.title, "severity": f.severity, "detected_by": list(f.sources or []),
         "evidence": _finding_evidence(g, f)[:n_ev]}
    v = _verdict_of(f, verdicts)
    if v:
        b["analyst_verdict"] = v
    return b


_VERDICT_NOTE = (" A finding's `analyst_verdict`, when present, is the analyst's own call: "
                 "true_positive = confirmed malicious; false_positive or known = ruled out, "
                 "do not count it as evidence.")


def _entity_state(g, e, fs, verdicts=None):
    hosts = sorted({getattr(g.entities.get(a), "label", None) or a
                    for f in fs for a in (f.asset_ids or [])})
    return {"entity": e.label, "type": e.type, "hosts": hosts,
            "findings": [_finding_brief(g, f, verdicts or {}, 4)
                         for f in sorted(fs, key=lambda f: _SEV_RANK.get(f.severity, 4))[:15]]}


def entity_estimates(question, d, g, run_id=None) -> str:
    """Markdown to append to a chat answer, or "" (off, not a risk question,
    nothing named, no findings, or the model did not answer)."""
    from .llm_sim import is_question
    q = (question or "").lower()
    if not enabled("chat_confidence") or not is_question(question) \
            or not any(w in q for w in _RISK_WORDS):
        return ""
    try:
        from .resolve import resolve
        r = resolve(g, question)
        # An ambiguous name ("kobi" -> kobia, adatumlab\kobia, kobitst) gets an
        # estimate per candidate that has findings, side by side — the chat model
        # answers about one of them anyway, and the analyst sees which.
        seen, ents = set(), []
        for e in (r.get("resolved") or []) + [c for a in r.get("ambiguous") or []
                                             for c in a.get("candidates") or []]:
            if e.type in ("account", "asset") and e.id not in seen:
                seen.add(e.id)
                ents.append(e)
        pairs = []
        for e in ents:
            if len(pairs) >= 3:
                break
            fs = [f for f in g.findings if e.id in (f.entity_ids or []) or e.id in (f.asset_ids or [])]
            if fs:
                pairs.append((e, fs))
        if not pairs:
            return ""
        mask = mask_for(d, g)
        kind = {"account": "account", "asset": "host"}
        verdicts = analyst_verdicts(d)
        answers = ask_each(pairs, lambda p: masked(_entity_state(g, *p, verdicts), mask), lambda k: {
            "type": "noul",
            "instructions": f"items.{k} is one account or host from a forensic case, with the "
                            "findings that involve it. Is it involved in malicious activity?"
                            + _VERDICT_NOTE,
            "criteria": {"true": "It took part in, or was used for, attacker activity.",
                         "false": "Its activity is explained as normal, or it is only a bystander."}},
            run_id=run_id)
    except Exception as e:  # noqa: BLE001
        log.warning("decision model: entity estimate skipped: %s", e)
        return ""
    lines = []
    for (e, fs), a in zip(pairs, answers):
        p = (a or {}).get("noul") if isinstance(a, dict) else None
        if not isinstance(p, (int, float)):
            continue
        nh = len({h for f in fs for h in (f.asset_ids or [])})
        lines.append(f"- **{e.label}** ({kind.get(e.type, e.type)}): **{round(p * 100)}% (decision model)** likely "
                     f"involved in malicious activity — from {len(fs)} finding"
                     f"{'s' if len(fs) != 1 else ''} on {nh} host{'s' if nh != 1 else ''}")
    if not lines:
        return ""
    return ("\n\n---\n_Decision-model estimate — a fast second opinion from the findings, not a verdict:_\n"
            + "\n".join(lines))


# ---------------------------------------------------------------------------
# Scope cards: for a broad case, "how likely is this window real attacker
# activity?" on each card. Asked after the fuse and cached per exact set of
# findings (+ their occurrences), so the cards themselves load instantly and a
# window whose findings changed shows no stale number.
# ---------------------------------------------------------------------------
def _scope_sig(z, by_id, verdicts=None):
    import hashlib
    verdicts = verdicts or {}
    parts = sorted(f"{fid}:{by_id[fid].watermark()}:{_verdict_of(by_id[fid], verdicts) or ''}"
                   for fid in z.get("finding_ids") or [] if fid in by_id)
    return hashlib.sha1("|".join(parts).encode()).hexdigest()[:16] if parts else None


def _scope_state(z, by_id, g, verdicts=None):
    fs = sorted((by_id[i] for i in z.get("finding_ids") or [] if i in by_id),
                key=lambda f: _SEV_RANK.get(f.severity, 4))[:15]
    return {"window": z.get("window"), "hosts": z.get("host_labels") or [],
            "mitre": z.get("mitre") or [],
            "findings": [_finding_brief(g, f, verdicts or {}, 3) for f in fs]}


def _cards_of_every_scope(case_id, d):
    """[(card, sig)] for the cards of EVERY scope of the case, the active one first,
    each window once. Only the active scope's cards used to be scored -- and every
    other estimate was then dropped as "no longer exists" -- so a fuse run inside a
    narrow scope left the broad view with 1 figure for 10 phases (asd, 2026-10-04).
    Each scope's cards are built on a COPY of the case with that scope selected;
    nothing is written. ponytail: the graph is re-read per scope; fine for a handful."""
    from .store import FULL_SCOPE_ID, _active_scope_id, _scopes, scope_cards
    verdicts = analyst_verdicts(d)
    ids = [_active_scope_id(d)] + [x["id"] for x in _scopes(d)] + [FULL_SCOPE_ID]
    out, seen, g0, g_full = [], set(), None, None
    for sid in dict.fromkeys(ids):
        try:
            _alt, _r, cards, g = scope_cards(case_id, dict(d, active_scope=sid))
        except Exception as e:                            # noqa: BLE001 — one scope, never the rest
            print(f"[DECISION] scope cards for {case_id}/{sid} not built: {e}", flush=True)
            continue
        g0 = g0 or g
        if sid == FULL_SCOPE_ID:
            g_full = g                                    # holds every scope's findings
        by_id = {f.id: f for f in g.findings}
        for z in cards:
            sig = None if z.get("rollup") else _scope_sig(z, by_id, verdicts)
            if sig and sig not in seen:
                seen.add(sig)
                out.append((z, sig, g))
    # The model is told about every card from the whole case's graph: a narrow scope's
    # graph lacks the findings of the broader scopes' cards.
    return out, (g_full or g0)


def suggest_scopes(case_id, d) -> int:
    pairs, g = _cards_of_every_scope(case_id, d)
    verdicts = analyst_verdicts(d)
    have = cached(d, "scopes")
    todo = [(z, sig) for z, sig, _g in pairs if sig not in have]
    if g is not None:
        by_id = {f.id: f for f in g.findings}
    if todo and g is not None:
        mask = mask_for(d, g)
        answers = ask_each(todo, lambda t: masked(_scope_state(t[0], by_id, g, verdicts), mask), lambda k: {
            "type": "noul",
            "instructions": f"items.{k} is one time window of a forensic case: its hosts, "
                            "techniques and findings. Does it show real attacker activity?"
                            + _VERDICT_NOTE,
            "criteria": {"true": "An intrusion or attacker actions happened in this window.",
                         "false": "Benign, administrative or detection noise."}}, run_id=case_id)
        new = dict(have)
        for (z, sig), a in zip(todo, answers):
            if isinstance(a, dict) and isinstance(a.get("noul"), (int, float)):
                new[sig] = round(float(a["noul"]), 3)
    else:
        new = dict(have)
    live = {sig for _z, sig, _g in pairs}
    new = {k: v for k, v in new.items() if k in live}        # windows that no longer exist IN ANY scope
    if new != have:
        _save(case_id, scopes=new)
    return len(todo)


def attach_scope_estimates(cards, d, g):
    """Set card["decision_p"] where a current estimate exists. Nothing when off."""
    if not enabled("scopes"):
        return
    by_id = {f.id: f for f in g.findings}
    verdicts = analyst_verdicts(d)
    est = cached(d, "scopes")
    for z in cards:
        p = est.get(_scope_sig(z, by_id, verdicts)) if not z.get("rollup") else None
        if p is not None:
            z["decision_p"] = p


# ---------------------------------------------------------------------------
# Identities: "is this person compromised?" on each card that has findings,
# beside the analyst's own Compromised / Not compromised switch. Asked after the
# fuse, cached per exact accounts + findings (+ their occurrences), so the tab
# loads instantly and a person whose evidence changed shows no stale number.
# ---------------------------------------------------------------------------
def compromise_sig(account_ids, fs, verdicts=None):
    import hashlib
    if not fs:
        return None
    verdicts = verdicts or {}
    parts = sorted(account_ids or []) + sorted(f"{f.id}:{f.watermark()}:{_verdict_of(f, verdicts) or ''}"
                                               for f in fs)
    return hashlib.sha1("|".join(parts).encode()).hexdigest()[:16]


def compromise_estimate(d, account_ids, fs):
    """The decision model's probability that the person is compromised, or None (off, no findings,
    not asked yet, or the evidence changed since)."""
    if not enabled("compromise"):
        return None
    return cached(d, "compromise").get(compromise_sig(account_ids, fs, analyst_verdicts(d)))


def _person_state(g, card, fs, verdicts=None):
    return {"person": card.get("name"),
            "accounts": [a.get("label") for a in card.get("accounts") or [] if not a.get("disabled")],
            "hosts": card.get("seen_on") or [],
            "account_type": ("built-in" if card.get("builtin") else card.get("account_kind") or "user"),
            "findings": [_finding_brief(g, f, verdicts or {}, 3)
                         for f in sorted(fs, key=lambda f: _SEV_RANK.get(f.severity, 4))[:15]]}


def _compromised_question(k):
    return {"type": "noul",
            "instructions": f"items.{k} is one person from a forensic case: their accounts, the "
                            "hosts they appear on, and the findings on those accounts and on "
                            "what they ran. Is this identity compromised?" + _VERDICT_NOTE,
            "criteria": {"true": "An attacker used these accounts, or the person is the attacker.",
                         "false": "The activity is the person's normal or administrative work, "
                                  "or detection noise."}}


def suggest_compromise(case_id, d) -> int:
    """Every person, in EVERY scope of the case. A person's findings -- and so the
    cache key -- differ per scope; only the active scope's people used to be asked,
    and every other estimate was dropped, so switching scope after a fuse left the
    Identities tab with no figure at all (asd, 2026-10-04: 0 of 19). Each scope is
    read on a copy of the case with that scope selected; nothing is written."""
    from . import identities as idf
    from .store import FULL_SCOPE_ID, _active_scope_id, _scopes, identity_view, view_graph
    have = cached(d, "compromise")
    verdicts = analyst_verdicts(d)
    todo, live, g_full = [], set(), None
    for sid in dict.fromkeys([_active_scope_id(d)] + [x["id"] for x in _scopes(d)] + [FULL_SCOPE_ID]):
        dd = dict(d, active_scope=sid)
        try:
            cards = (identity_view(case_id, dd) or {}).get("identities") or []
            g = view_graph(case_id, dd)                  # the graph the tab reads in that scope
        except Exception as e:                            # noqa: BLE001 — one scope, never the rest
            print(f"[DECISION] identities for {case_id}/{sid} not read: {e}", flush=True)
            continue
        if sid == FULL_SCOPE_ID:
            g_full = g
        for c in cards:
            ids = [a["id"] for a in c.get("accounts") or [] if not a.get("disabled")]
            fs = idf.person_findings(g, ids)
            sig = compromise_sig(ids, fs, verdicts)
            if sig and sig not in live:
                live.add(sig)
                if sig not in have:
                    todo.append((c, fs, sig, g))
    new = {k: v for k, v in have.items() if k in live}      # people whose evidence changed everywhere
    if todo:
        mask = mask_for(d, g_full or todo[0][3])
        answers = ask_each(todo, lambda t: masked(_person_state(t[3], t[0], t[1], verdicts), mask),
                           _compromised_question, run_id=case_id)
        for (c, fs, sig, _g), a in zip(todo, answers):
            if isinstance(a, dict) and isinstance(a.get("noul"), (int, float)):
                new[sig] = round(float(a["noul"]), 3)
    if new != have:
        _save(case_id, compromise=new)
    return len(todo)


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
        if not any(enabled(u, cfg) for u in ("disposition", "identity", "scopes", "compromise")):
            return
        with _workers_lock:
            if case_id in _running:
                _again.add(case_id)          # re-run once the current pass ends
                return
            _running.add(case_id)
        threading.Thread(target=_work, args=(case_id,), daemon=True,
                         name=f"decision-{case_id}").start()
    except Exception as e:  # noqa: BLE001
        log.warning("decision model: after_fuse(%s) not started: %s", case_id, e)


def _work(case_id):
    try:
        while True:
            try:
                _one_pass(case_id)
            except Exception as e:  # noqa: BLE001 — a suggestion is never worth an error
                log.warning("decision model: pass for %s failed: %s", case_id, e)
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
    if enabled("scopes"):
        suggest_scopes(case_id, get_case(case_id) or d)
    if enabled("compromise"):
        suggest_compromise(case_id, get_case(case_id) or d)


# ---------------------------------------------------------------------------
# The report reads the decision model's estimates (use "report"): the report step waits, bounded,
# for the pass above, then gives the report model the per-finding verdict
# suggestions and per-person compromise estimates -- LABELLED as automated
# estimates. They are never verdicts: anything the analyst judged is left out
# here, because the analyst's own verdict already reaches the model and rules.
# Off, unreachable or slow: the report is written without them, as before.
# ---------------------------------------------------------------------------
REPORT_WAIT_SECONDS = 90
_ESTIMATE = {"true_positive": "likely malicious",
             "known": "likely expected or administrative activity",
             "false_positive": "likely a false detection"}
# DATA ONLY. The rule for using these lives in the report's SYSTEM prompt
# (llm_sim.ESTIMATES_RULE). A note carried inside this payload was -- correctly --
# caught by the prompt-injection guard as "text addressed to an AI model": withheld
# on every call and quoted in the report as a possible injection.


def report_wait_seconds() -> float:
    try:
        return max(0.0, float(settings().get("report_wait_seconds", REPORT_WAIT_SECONDS)))
    except (TypeError, ValueError):
        return REPORT_WAIT_SECONDS


def wait_idle(case_id, timeout) -> bool:
    """Wait (at most `timeout` seconds) for the case's after-fuse pass. True when
    none is running any more."""
    import time
    end = time.monotonic() + max(0.0, timeout)
    while True:
        with _workers_lock:
            if case_id not in _running:
                return True
        if time.monotonic() >= end:
            return False
        time.sleep(0.25)


def report_estimates(case_id, d, g) -> dict:
    """{} or {"findings": [...], "identities": [...]} for the report model.
    Only estimates that are still valid for the evidence as it is now, at or above
    the confidence floor, and only where the analyst has not decided."""
    if not enabled("report"):
        return {}
    out = {}
    try:
        if enabled("disposition"):
            from .correlate import _part_ids
            done = {v.get("finding_id") for v in (d.get("timeline_validations") or [])}
            sug = cached(d, "suggestions")
            rows = []
            for f in g.findings:
                if (set(f.ids() + _part_ids(f)) & done) or f.kind == "dispositioned":
                    continue
                s = suggestion_for(sug, f.id, f.watermark())
                if s:
                    rows.append({"finding": f.title, "estimate": _ESTIMATE.get(s["label"], s["label"]),
                                 "confidence": round(float(s["p"]), 2)})
            if rows:
                out["findings"] = sorted(rows, key=lambda r: -r["confidence"])[:60]
        if enabled("compromise"):
            from .store import identity_view
            people = [{"identity": c.get("name"), "compromise_probability": round(float(c["decision_compromise"]), 2)}
                      for c in ((identity_view(case_id) or {}).get("identities") or [])
                      if isinstance(c.get("decision_compromise"), (int, float)) and not c.get("verdict")]
            if people:
                out["identities"] = sorted(people, key=lambda r: -r["compromise_probability"])[:30]
    except Exception as e:  # noqa: BLE001 — an estimate is never worth a failed report
        log.warning("decision model: report estimates for %s skipped: %s", case_id, e)
        return {}
    return out


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
    say(f"Scoring {len(items):,} collected rows with the decision model.")

    scored, done = [], 0

    def save():
        best = sorted((s for s in scored if s["p"] >= RELEVANT_FROM),
                      key=lambda s: -s["p"])[:KEEP]
        _merge_case_details(case_id, {"decision_relevance": {
            "scored_at": datetime.now().isoformat(timespec="seconds"),
            "rows_scored": done, "rows_total": len(items), "rows": best}})
        return best

    for chunk in pack(items, lambda it: it[4],
                      max_tokens=context_tokens() - approx_tokens(context),
                      per_item=_question_tokens(_relevant_question)):
        if cancel.is_set():
            save()
            raise RuntimeError("stopped")
        ans = _ask_chunk(chunk, lambda it: it[4], _relevant_question, context, run_id=run_id)
        if ans is None:
            save()
            raise RuntimeError(f"The decision model stopped answering after {done:,} of {len(items):,} "
                               "rows — the rows scored so far are kept")
        for a, (rid, artifact, i, text, _m) in zip(ans, chunk):
            p = (a or {}).get("noul")
            if isinstance(p, (int, float)):
                scored.append({"run_id": rid, "artifact": artifact, "row": i,
                               "text": text, "p": round(float(p), 3)})
        done += len(chunk)
        ws.update_run_status(run_id, "running", progress=int(done * 100 / len(items)))
    best = save()
    say(f"Done: {done:,} rows scored, {len(best)} kept as relevant (≥{RELEVANT_FROM:.0%}).",
        "success")
    return {"case_id": case_id, "rows_scored": done, "relevant": len(best)}
