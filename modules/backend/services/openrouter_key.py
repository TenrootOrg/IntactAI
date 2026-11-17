#!/usr/bin/env python3
"""One OpenRouter API key for Case Analysis, the decision model and Timesketch.

2026-11-17, later: the Google AI key too (Agentic's "Google (API)" = Timesketch's
"Google AI Studio"), same rules, under its own secret (KEYS below). Every
function takes the Timesketch provider name ('openrouter', 'google'); the
default keeps the OpenRouter callers as they were. The decision model has no
Google provider, so only Agentic and Timesketch share that one.

2026-11-17: one key, entered once, for all three (the models stay per section).
Wherever it is saved -- Settings -> Agentic (model or decision model) or
Settings -> Timesketch -- it is the key of every OpenRouter user on the box:
  - Case Analysis's OpenRouter copy (online_llm.api_key) follows, an empty one
    included: setting the key turns OpenRouter on for Case Analysis too.
  - The decision model reads it directly (decision_model._key), no copy.
  - Timesketch: an Agentic save rewrites timesketch.conf through the Timesketch
    settings workflow (routes/timesketch_llm_routes.start_shared_key_sync), which
    restarts Timesketch's four processes in parallel and only when the file
    changed. Timesketch's own AI features stay off until a user turns them on.
Earlier rules (kept below for the history): the sharing was one-way and never
filled an empty Agentic key.

QA (2026-11): "enter openrouter api in agentic tab, move to timesketch: you
should enter it again". The two sections kept separate copies -- Agentic in
frontend_config (agentic.online_llm.api_key), Timesketch only inside the
timesketch.conf it renders -- and neither ever looked at the other. The models
stay per section; only the key is shared.

The shared copy lives in the `secrets` table, not frontend_config: that table
never enters export_db()/import_db() and the DB download blanks it, so the key
gets no new way off the box and an import cannot plant one.

The two section copies still exist, because that is what the runtimes read:
online_llm.api_key for Case Analysis (many readers), timesketch.conf for
Timesketch (read at container start). They follow the shared key like this:
  - Agentic Save (provider OpenRouter) sets the shared key. timesketch.conf is
    NOT rewritten: that needs a Timesketch restart, which an Agentic save must
    not cause. GET /api/timesketch/config/llm reports it as pending instead.
  - Timesketch Save (provider OpenRouter) sets the shared key and REPLACES an
    OpenRouter key Agentic already uses (rotation). It never fills an EMPTY
    Agentic key: that would turn Case Analysis's cloud AI on -- case data
    leaving the box, auto-generated reports billing tokens -- from the
    Timesketch tab. GET /api/config shows the shared key there, flagged, and
    the operator's next Agentic Save puts it in force.
  - An emptied field is "remove the key": one key, so it goes from the shared
    copy (and from an Agentic copy, on a Timesketch save) too.
"""

import re

from services.storage.config_store import load_frontend_config, save_frontend_config
from services.storage.secret_store import delete_secret, get_secret, set_secret

# Timesketch provider -> (secrets-table name, Agentic online_llm provider,
# timesketch.conf provider). "<secret>_adopted" is set once the one-time adoption
# in get() has run, so a key the operator later REMOVED is not re-adopted from a
# copy that still holds it (timesketch.conf keeps its key until Timesketch is saved).
KEYS = {
    "openrouter": ("openrouter_api_key", "openrouter", "openrouter"),
    "google":     ("google_api_key",     "gemini",     "aistudio"),
}
SECRET = KEYS["openrouter"][0]


def for_agentic(agentic_provider):
    """The shared key name behind an Agentic online provider, None if it has none."""
    return next((k for k, v in KEYS.items() if v[1] == agentic_provider), None)
# What every GET substitutes for a saved key; anything sent back with this
# prefix means "keep the stored one".
MASK = "••••"
TIMESKETCH_CONF = "/app/config/timesketch/timesketch.conf"


def read_conf_value(content, ts_provider, conf_key):
    """Pull one provider field out of timesketch.conf, '' if absent.

    Find the provider dict, then the key inside it. `[^}]*` keeps the match
    from wandering past the end of that provider's block.
    """
    match = re.search(
        r"'" + re.escape(ts_provider) + r"':\s*\{[^}]*'"
        + re.escape(conf_key) + r"':\s*'([^']*)'",
        content)
    return match.group(1) if match else ""


def conf_key(path=None, provider="openrouter"):
    """The provider's key timesketch.conf holds now ('' if none / no file)."""
    try:
        with open(path or TIMESKETCH_CONF) as f:
            return read_conf_value(f.read(), KEYS[provider][2], "api_key")
    except OSError:
        return ""


def _agentic_online(cfg):
    ag = (cfg or {}).get("agentic")
    on = ag.get("online_llm") if isinstance(ag, dict) else None
    return on if isinstance(on, dict) else {}


def get(provider="openrouter"):
    """The shared key of that provider, '' when there is none.

    The first call on a box that predates sharing adopts whichever section
    already has one. Both differ: Agentic's wins -- it is the copy the backend
    tests and Case Analysis runs on; timesketch.conf is a rendered file.
    Timesketch keeps running on its own key until its section is saved, and
    its GET says the key is pending until then.
    """
    secret, agentic, _ts = KEYS[provider]
    key = get_secret(secret)
    if key or get_secret(secret + "_adopted"):
        return key or ""
    cfg = load_frontend_config() or {}
    on = _agentic_online(cfg)
    key = (on.get("api_key") or "").strip() if on.get("provider") == agentic else ""
    if not key and provider == "openrouter":   # the decision model's own key (OpenRouter is its default)
        dm = ((cfg.get("agentic") or {}).get("decision_model") or {})
        if (dm.get("provider") or "openrouter") == "openrouter":
            key = (dm.get("api_key") or "").strip()
    if key.startswith(MASK):            # never adopt a mask as a key
        key = ""
    key = key or conf_key(provider=provider)
    if key:
        set_secret(secret, key)
    set_secret(secret + "_adopted", "1")
    return key


def save(value, from_timesketch=False, provider="openrouter"):
    """Apply what a Settings form sent as the OpenRouter key; returns the real key.

    Masked -> the stored key, unchanged. Anything else becomes the shared key
    ('' removes it) and every copy follows: Case Analysis's OpenRouter copy (an
    empty one too), and -- unless the Timesketch save itself is writing its
    file (from_timesketch) -- Timesketch.
    """
    secret, agentic, _ts = KEYS[provider]
    current = get(provider)
    if isinstance(value, str) and value.startswith(MASK):
        return current
    value = (value or "").strip() if isinstance(value, str) else ""
    if value == current:
        return current
    if value:
        set_secret(secret, value)
    else:
        delete_secret(secret)
    cfg = load_frontend_config() or {}
    on = _agentic_online(cfg)
    if on.get("provider") == agentic and on.get("api_key") != value:
        on["api_key"] = value
        save_frontend_config({"agentic": cfg["agentic"]})
    if not from_timesketch:
        _sync_timesketch(provider)
    return value


def _sync_timesketch(provider="openrouter"):
    """Carry the key into timesketch.conf (a background settings run). Never fails
    the save that called it: Settings -> Timesketch shows the key as pending then."""
    try:
        from routes.timesketch_llm_routes import start_shared_key_sync
        start_shared_key_sync(provider)
    except Exception as e:                                   # noqa: BLE001
        print(f"[OPENROUTER] could not hand the key to Timesketch: {e}", flush=True)


def mask(key):
    """Same shape GET /api/config uses: bullets plus the last four."""
    if not key:
        return ""
    return MASK * 2 + key[-4:] if len(key) > 4 else MASK * 2
