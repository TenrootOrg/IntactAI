"""Jev — TypeSafe's "System One" model — for small, closed decisions.

Jev does not write text. It takes a `state` (any JSON) plus named questions,
each a yes/no ("noul"), pick-one ("choice") or ordered "score", and returns a
typed answer with probabilities. We reach it through OpenRouter's Decisions
endpoint with the OpenRouter key the operator already configured, so there is
no second key to manage — and no way to use it with any other provider.

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
USES = ("disposition", "relevance", "grounding", "identity", "chat_intent")
DEFAULTS = {"enabled": False, "model": "jev-latest", "min_confidence": 0.8,
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
